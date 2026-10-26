# SentinelWP AI 🛡️

**Free, offline-first, read-only WordPress PHP security review CLI.** Initial v0.1.1 release; **AI is optional and not included in this MVP**.

## Install (Windows PowerShell)

Requires Python 3.10+.

```powershell
python -m pip install -e .
sentinelwp --help
sentinelwp "C:\path\to\wordpress\wp-content\plugins\my-plugin" --format html --output audit.html
Start-Process .\audit.html
```

For JSON: `sentinelwp . --format json --output audit.json`. For CI: `sentinelwp . --fail-on-high`.

## What it checks

- `SWP001`: PHP `eval()` / `assert()` calls
- `SWP002`: PHP OS command execution calls
- `SWP003`: `unserialize()` calls
- `SWP004`: `$wpdb->query()` calls requiring manual review
- `SWP005`: selected potential hardcoded credential assignments

Scans `.php` and `.inc` files under the supplied directory, ignoring generated/vendor folders and files over 512 KiB. Findings include file, line, severity, rule, and recommendation. Reports are text, JSON, or semantic HTML. Nothing is uploaded or modified in the inspected project.

**Important:** This is a deliberately limited, heuristic source review, not a full WordPress security audit. Findings can be false positives and serious vulnerabilities may be missed. It does not detect plugin CVEs, verify nonce/capability authorization, inspect running websites, or generate automatic patches. Do not publicly share reports from private code.

## Run tests

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Roadmap

- Context-aware nonce and capability checks with fixture tests
- WordPress coding standards and dependency advisory integration
- Explicit approval for proposed fixes and GitHub pull requests
- Spanish documentation and improved screen-reader validation

## License

MIT. See [LICENSE](LICENSE).


### v0.1.1
Fixed a cross-platform HTML escaping test that previously used a Windows-invalid filename.
