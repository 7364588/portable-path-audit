from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_cli(self, *arguments):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE)
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, "-m", "portable_path_audit", *map(str, arguments)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            check=False,
            timeout=20,
        )

    def test_empty_tree_json_schema_and_clean_status(self):
        process = self.run_cli(self.root, "--json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        self.assertEqual(json.loads(process.stdout), {
            "schema_version": 1, "exit_code": 0, "findings": [], "errors": [],
            "scanned_entries": 0, "skipped_symlinks": 0, "skipped_git_entries": 0,
        })

    def test_findings_status_and_json_are_deterministic(self):
        (self.root / "longname").touch()
        first = self.run_cli(self.root, "--json", "--max-component-bytes", 5)
        second = self.run_cli(self.root, "--json", "--max-component-bytes", 5)
        self.assertEqual(first.returncode, 1)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["findings"][0]["path"], "longname")
        self.assertEqual(payload["findings"][0]["related_paths"], [])
        self.assertNotIn(str(self.root), first.stdout)

    def test_human_output(self):
        (self.root / "longname").touch()
        process = self.run_cli(self.root, "--max-component-bytes", 5)
        self.assertEqual(process.returncode, 1)
        self.assertIn('component-too-long: "longname":', process.stdout)
        self.assertIn("1 findings; 0 errors", process.stdout)
        self.assertEqual(process.stderr, "")

    def test_closed_stdout_pipe_returns_operational_error_for_reports_and_help(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE)
        environment["PYTHONIOENCODING"] = "utf-8"
        for flags in ([], ["--json"], ["--help"], ["--version"]):
            with self.subTest(flags=flags):
                reader, writer = os.pipe()
                os.close(reader)
                try:
                    process = subprocess.run(
                        [sys.executable, "-m", "portable_path_audit", str(self.root), *flags],
                        stdout=writer, stderr=subprocess.PIPE, text=True,
                        encoding="utf-8", env=environment, check=False, timeout=20,
                    )
                finally:
                    os.close(writer)
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertNotIn("Traceback", process.stderr)
                self.assertNotIn("Exception ignored", process.stderr)

    def test_missing_root_has_json_error_and_status_two(self):
        process = self.run_cli(self.root / "missing", "--json")
        self.assertEqual(process.returncode, 2)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["errors"][0]["path"], ".")
        self.assertEqual(payload["exit_code"], 2)
        self.assertEqual(process.stderr, "")

    def test_human_errors_go_to_stderr(self):
        process = self.run_cli(self.root / "missing")
        self.assertEqual(process.returncode, 2)
        self.assertIn('error: ".":', process.stderr)
        self.assertIn("1 errors", process.stdout)

    def test_invalid_limits_are_argument_errors(self):
        for option in ("--max-component-bytes", "--max-path-length"):
            for value in ("0", "-1", "hello"):
                with self.subTest(option=option, value=value):
                    process = self.run_cli(self.root, option, value, "--json")
                    self.assertEqual(process.returncode, 2)
                    self.assertEqual(process.stdout, "")
                    self.assertIn("must be a positive integer", process.stderr)

    def test_relative_path_limit_end_to_end(self):
        (self.root / "dir").mkdir()
        (self.root / "dir" / "file").touch()
        process = self.run_cli(self.root, "--max-path-length", 7, "--json")
        self.assertEqual(process.returncode, 1)
        findings = json.loads(process.stdout)["findings"]
        self.assertEqual([(item["code"], item["path"]) for item in findings], [("path-too-long", "dir/file")])

    def test_include_git_end_to_end(self):
        (self.root / ".git").mkdir()
        (self.root / ".git" / "longname").touch()
        skipped = self.run_cli(self.root, "--max-component-bytes", 5, "--json")
        included = self.run_cli(self.root, "--max-component-bytes", 5, "--include-git", "--json")
        self.assertEqual(skipped.returncode, 0)
        self.assertEqual(included.returncode, 1)
        self.assertEqual(json.loads(included.stdout)["findings"][0]["path"], ".git/longname")

    def test_help_version_and_missing_argument(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0)
        self.assertEqual(version.stdout.strip(), "portable-path-audit 0.1.0")
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == "__main__":
    unittest.main()
