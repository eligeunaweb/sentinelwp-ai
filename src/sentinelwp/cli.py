"""Read-only, offline heuristic WordPress PHP auditor."""
import argparse
import html
import json
import re
from pathlib import Path

SKIP = {'.git', 'node_modules', 'vendor', '.venv', '__pycache__', 'dist', 'build'}
RULES = [
    ('SWP001', 'high', 'Dynamic PHP execution', re.compile(r'\b(?:eval|assert)\s*\(', re.I), 'Avoid dynamic execution of untrusted input.'),
    ('SWP002', 'medium', 'OS command execution', re.compile(r'\b(?:shell_exec|system|passthru|exec|proc_open|popen)\s*\(', re.I), 'Review whether command execution is required; never pass untrusted input.'),
    ('SWP003', 'medium', 'Unserialization', re.compile(r'\bunserialize\s*\(', re.I), 'Avoid unserializing untrusted input.'),
    ('SWP004', 'medium', 'Direct SQL query', re.compile(r'\$wpdb\s*->\s*query\s*\(', re.I), 'Review parameterization; use $wpdb->prepare for variable values.'),
    ('SWP005', 'high', 'Potential hardcoded credential', re.compile(r"(?i)(?:password|api_key|secret|token)\s*['\"]?\s*(?:=>|=)\s*['\"][^'\"\r\n]{12,}['\"]"), 'Move secrets to environment or secure configuration; verify before remediation.'),
]

def scan(root):
    findings=[]; scanned=0; skipped=0
    for file in sorted(root.rglob('*')):
        if not file.is_file() or any(part in SKIP for part in file.relative_to(root).parts):
            continue
        if file.suffix.lower() not in {'.php', '.inc'}:
            continue
        try:
            if file.stat().st_size > 512 * 1024:
                skipped+=1; continue
            source=file.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            skipped+=1; continue
        scanned+=1
        for line_number,line in enumerate(source.splitlines(),1):
            # Skip single-line comments only; static heuristics may flag strings and multiline comments.
            if line.lstrip().startswith(('//', '#', '*')):
                continue
            for rule,severity,title,pattern,advice in RULES:
                if pattern.search(line):
                    findings.append({'rule':rule,'severity':severity,'title':title,'file':file.relative_to(root).as_posix(),'line':line_number,'recommendation':advice})
    return {'tool':'SentinelWP AI','version':'0.1.1','root':str(root),'files_scanned':scanned,'files_skipped':skipped,'findings':findings,'limitations':'Heuristic source-only checks; false positives and false negatives possible. Does not inspect running WordPress, dependency CVEs, or git history.'}

def render_html(report):
    esc=html.escape
    rows=''.join('<tr>'+''.join('<td>'+esc(str(item[key]))+'</td>' for key in ('severity','rule','title','file','line','recommendation'))+'</tr>' for item in report['findings'])
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SentinelWP AI report</title><style>body{font:1rem/1.5 system-ui;max-width:80rem;margin:auto;padding:1rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #777;padding:.5rem;text-align:left}th{background:#eee}@media(prefers-color-scheme:dark){body{background:#151515;color:#eee}th{background:#333}}.scroll{overflow-x:auto}</style></head><body><main><h1>SentinelWP AI security review</h1><p>Files scanned: '+str(report['files_scanned'])+'; skipped: '+str(report['files_skipped'])+'; findings: '+str(len(report['findings']))+'</p><p>'+esc(report['limitations'])+'</p><div class="scroll"><table><caption>Heuristic findings requiring manual review</caption><thead><tr>'+''.join('<th scope="col">'+v+'</th>' for v in ('Severity','Rule','Description','File','Line','Recommendation'))+'</tr></thead><tbody>'+rows+'</tbody></table></div></main></body></html>'

def main(argv=None):
    parser=argparse.ArgumentParser(description='Offline, read-only WordPress PHP review')
    parser.add_argument('path', nargs='?', default='.', help='Local plugin or WordPress directory')
    parser.add_argument('--format', choices=['text','json','html'], default='text')
    parser.add_argument('--output', help='Write report to file')
    parser.add_argument('--fail-on-high', action='store_true', help='Return 1 if high findings exist')
    args=parser.parse_args(argv)
    root=Path(args.path).expanduser().resolve()
    if not root.is_dir():
        parser.error('path must be an existing directory')
    report=scan(root)
    if args.format=='json':
        result=json.dumps(report,indent=2,ensure_ascii=False)
    elif args.format=='html':
        result=render_html(report)
    else:
        result=f"SentinelWP AI v0.1.1 | scanned {report['files_scanned']} PHP files | {len(report['findings'])} findings\n" + '\n'.join(f"{f['severity'].upper()} {f['rule']} {f['file']}:{f['line']} {f['title']}" for f in report['findings'])+'\n'+report['limitations']
    if args.output:
        Path(args.output).write_text(result,encoding='utf-8')
        print(f"Report written to {args.output}")
    else:
        print(result)
    return int(args.fail_on_high and any(f['severity']=='high' for f in report['findings']))

if __name__=='__main__':
    raise SystemExit(main())
