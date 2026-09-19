"""Command-line interface for portable-path-audit."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from typing import Sequence, TextIO

from . import __version__
from .audit import AuditOptions, audit_tree


def _positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _discard_failed_stream(stream: TextIO) -> None:
    # A failed flush can leave buffered data behind. Redirect the descriptor so
    # interpreter shutdown cannot retry the failed write and replace exit 2 with
    # exit 120. Embedded callers may supply streams without file descriptors.
    try:
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), stream.fileno())
    except (AttributeError, OSError, ValueError):
        pass


def _output_error() -> int:
    _discard_failed_stream(sys.stdout)
    try:
        sys.stderr.write("portable-path-audit: unable to write output.\n")
        sys.stderr.flush()
    except (OSError, UnicodeError, ValueError):
        _discard_failed_stream(sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="portable-path-audit",
        description="Inspect directory entry names for portability problems without reading file contents.",
    )
    parser.add_argument("root", help="directory tree to inspect")
    parser.add_argument("--json", action="store_true", help="write one JSON report to stdout")
    parser.add_argument("--max-component-bytes", type=_positive_integer, default=255, metavar="N", help="UTF-8 byte limit per filename (default: 255)")
    parser.add_argument("--max-path-length", type=_positive_integer, metavar="N", help="limit relative paths to N Unicode code points, including '/' separators")
    parser.add_argument("--include-git", action="store_true", help="inspect entries named .git (skipped by default)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    try:
        try:
            arguments = parser.parse_args(argv)
        except SystemExit:
            # argparse's help/version actions also write buffered output.
            sys.stdout.flush()
            sys.stderr.flush()
            raise
    except (OSError, UnicodeError, ValueError):
        return _output_error()
    report = audit_tree(
        arguments.root,
        options=AuditOptions(
            max_component_bytes=arguments.max_component_bytes,
            max_path_length=arguments.max_path_length,
            include_git=arguments.include_git,
        ),
    )
    try:
        if arguments.json:
            payload = {"schema_version": 1, "exit_code": report.exit_code, **asdict(report)}
            print(json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2))
        else:
            for finding in report.findings:
                print(f"{finding.code}: {json.dumps(finding.path, ensure_ascii=True)}: {finding.message}")
                for path in finding.related_paths:
                    print(f"  {json.dumps(path, ensure_ascii=True)}")
            for error in report.errors:
                print(f"error: {json.dumps(error.path, ensure_ascii=True)}: {error.message}", file=sys.stderr)
            print(
                f"Inspected {report.scanned_entries} entries; {len(report.findings)} findings; "
                f"{len(report.errors)} errors; skipped {report.skipped_symlinks} symlinks/reparse points "
                f"and {report.skipped_git_entries} .git entries."
            )
        sys.stdout.flush()
        sys.stderr.flush()
    except (OSError, UnicodeError, ValueError):
        return _output_error()
    return report.exit_code
