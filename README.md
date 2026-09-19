# portable-path-audit

Find filename portability problems before sharing a directory tree with another
operating system. The tool inspects names and filesystem metadata, without
opening target file contents or making changes.

Requires Python 3.11 or later. There are no runtime dependencies.

## Install from a checkout

```sh
python -m pip install .
portable-path-audit path/to/tree
```

Installation builds a package with setuptools; pip may need to obtain that build
dependency. To run directly without installing anything, set `PYTHONPATH` to the
checkout's `src` directory:

```sh
PYTHONPATH=src python -m portable_path_audit path/to/tree
```

In PowerShell, from the checkout root:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
python -m portable_path_audit path/to/tree
```

## Checks

| Code | Meaning |
| --- | --- |
| `reserved-name` | Windows device basenames `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9`, including extensions and superscript digits ¹, ², ³. |
| `forbidden-character` | A character in `< > : " / \ | ? *` or U+0000–U+001F. |
| `trailing-space-or-period` | A filename ending in an ASCII space or period. |
| `name-collision` | Sibling names that compare equal after NFC normalization, case folding, and NFC normalization again. |
| `component-too-long` | A filename exceeds the UTF-8 byte limit, 255 by default. |
| `path-too-long` | A relative path exceeds the optional Unicode code-point limit. |
| `invalid-unicode` | A filename contains surrogate code points and cannot be encoded as UTF-8. |

The reserved-name check uses the part before the first period, ignoring trailing
ASCII spaces in that part, and compares it without regard to case. For example,
`nul.backup.txt` is reported. Sibling collision checks cover files and directories
together; identical names in different directories do not collide.

```sh
portable-path-audit assets --max-component-bytes 200 --max-path-length 240
portable-path-audit assets --json
portable-path-audit assets --include-git
```

The path limit counts the exact spelling of a relative path, including `/`
separators. For example, `images/a.png` has length 12. The root directory name is
excluded from every check. Component limits count UTF-8 bytes before any
normalization: a non-ASCII character may occupy multiple bytes.

## Exit status and reports

- **0**: all inspected entries passed and no operational errors occurred.
- **1**: one or more portability findings, with no operational errors.
- **2**: invalid command-line input, an invalid root, an incomplete scan, or an
  output failure such as a closed stdout pipe.

By default, findings and the summary go to stdout; operational errors go to
stderr. Paths are JSON-quoted so embedded newlines and other unusual characters
cannot imitate report lines. Directory symlinks, file symlinks, broken symlinks,
and Windows reparse points are skipped. A symlink or reparse point supplied as
the root is rejected. Entries named `.git` are skipped at every depth unless
`--include-git` is supplied.

`--json` writes a single JSON object to stdout, including operational errors.
Argument parsing errors still use stderr and do not emit a JSON object. An empty
directory produces:

```json
{
  "errors": [],
  "exit_code": 0,
  "findings": [],
  "scanned_entries": 0,
  "schema_version": 1,
  "skipped_git_entries": 0,
  "skipped_symlinks": 0
}
```

If writing output fails, the command returns 2 and attempts a short error on
stderr; a complete report may not be available.

Each finding has `code`, `path`, `message`, and `related_paths`. For a collision,
`path` identifies the parent (`.` for the root), and `related_paths` contains all
colliding siblings. Other findings have an empty `related_paths` array.
Operational errors have `path` and `message`. `scanned_entries` counts inspected
files, directories, and other non-skipped entries; the root itself is not counted.
Skipped-directory descendants are neither inspected nor counted.

Reports sort findings by relative path, code, and related paths, and errors by
relative path and message. There are no timestamps or absolute root paths in
reports. JSON's `schema_version` identifies the report structure; scripts should
use codes instead of matching human-readable messages.

## Python API

```python
from portable_path_audit import AuditOptions, audit_tree, check_component

result = audit_tree("assets", options=AuditOptions(max_path_length=240))
for finding in result.findings:
    print(finding.code, finding.path)
raise SystemExit(result.exit_code)
```

`check_component("NUL.txt")` checks a name without creating it on disk, which is
useful when validating proposed filenames. It returns a tuple of findings.
`AuditOptions` rejects nonpositive limits with `ValueError`. All report and
option objects are immutable dataclasses. The API collects filesystem errors in
`result.errors`; a partial result always has exit code 2.

## Limitations

This is a conservative lint check, not a filesystem compatibility guarantee.
Case folding plus NFC does not exactly reproduce every Windows, macOS, Linux,
network filesystem, archive format, or application comparison rule. It can flag
names that coexist on some filesystems. It does not emulate NTFS short-name
aliases, every special device namespace, or destination-specific restrictions.

The UTF-8 byte limit does not model filesystems that measure UTF-16 code units.
The relative path limit does not model Windows `MAX_PATH`, absolute destination
prefixes, or long-path configuration. Choose limits for the destination you
intend to support. No full-path limit is enforced unless one is supplied.

Only directory entries that exist and can be inspected are checked. Excluded
entries can hide additional issues. Audits are not snapshots; avoid concurrently
renaming or replacing entries during a scan. Large directories require memory
proportional to their entry count, and findings are retained until the report is
complete. Unicode behavior follows the database bundled with the running Python
version, so rare character comparisons may differ between Python versions.

## Development

```sh
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for reporting issues and making changes.
Distributed under the [MIT license](LICENSE).
