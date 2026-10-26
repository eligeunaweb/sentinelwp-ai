import json
import tempfile
import unittest
from pathlib import Path
from sentinelwp.cli import scan, main, render_html

class SentinelTests(unittest.TestCase):
    def test_detect_eval(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'bad.php').write_text('<?php eval($input);',encoding='utf-8')
            self.assertIn('SWP001',[f['rule'] for f in scan(Path(d))['findings']])
    def test_safe_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'safe.php').write_text('<?php echo esc_html("hi");',encoding='utf-8')
            self.assertEqual([],scan(Path(d))['findings'])
    def test_skips_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d,'vendor');p.mkdir();(p/'bad.php').write_text('<?php eval($x);')
            self.assertEqual(0,scan(Path(d))['files_scanned'])
    def test_high_exit(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'bad.php').write_text('<?php eval($x);')
            self.assertEqual(1,main([d,'--fail-on-high']))
    def test_json_report(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d,'report.json')
            self.assertEqual(0,main([d,'--format','json','--output',str(out)]))
            self.assertEqual('0.1.1',json.loads(out.read_text())['version'])
    def test_html_escaping(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'test.php').write_text('<?php eval($x);', encoding='utf-8')
            report = scan(Path(d))
            self.assertTrue(report['findings'])
            report['findings'][0]['file'] = '<test>.php'
            self.assertIn('&lt;test&gt;.php', render_html(report))

if __name__=='__main__': unittest.main()
