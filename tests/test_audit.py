from __future__ import annotations

import builtins
import errno
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from portable_path_audit import AuditOptions, audit_tree, check_component


class FakeEntry:
    def __init__(self, name: str, *, directory: bool = False, link: bool = False,
                 attributes: int = 0, path: str | None = None, error: OSError | None = None):
        self.name = name
        self.path = name if path is None else path
        self.mode = stat.S_IFLNK if link else (stat.S_IFDIR if directory else stat.S_IFREG)
        self.attributes = attributes
        self.error = error

    def stat(self, *, follow_symlinks: bool):
        if follow_symlinks:
            raise AssertionError("The audit must never request symlink target metadata")
        if self.error:
            raise self.error
        return SimpleNamespace(st_mode=self.mode, st_file_attributes=self.attributes)


class FakeScan:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, *args):
        return False


class ComponentTests(unittest.TestCase):
    def codes(self, name, **kwargs):
        return {item.code for item in check_component(name, **kwargs)}

    def test_all_reserved_device_names_with_extensions_and_case(self):
        names = ["CON", "PRN", "AUX", "NUL"]
        names += [f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"]
        for name in names:
            for suffix in ("", ".txt", ".tar.gz"):
                with self.subTest(name=name, suffix=suffix):
                    self.assertIn("reserved-name", self.codes(name.lower() + suffix))

    def test_reserved_stem_ignores_trailing_spaces(self):
        self.assertIn("reserved-name", self.codes("NUL .txt"))

    def test_near_reserved_names_are_accepted(self):
        for name in ("COM0", "COM10", "LPT10.txt", "NULx.txt", "conifer", ".CON", "hello.COM1"):
            with self.subTest(name=name):
                self.assertEqual(self.codes(name), set())

    def test_every_forbidden_character_and_control(self):
        for character in '<>:"/\\|?*' + "".join(chr(index) for index in range(32)):
            with self.subTest(character=repr(character)):
                self.assertIn("forbidden-character", self.codes("a" + character + "b"))

    def test_control_check_does_not_overreach_to_del(self):
        self.assertNotIn("forbidden-character", self.codes("a\x7fb"))

    def test_trailing_period_or_space(self):
        for name in ("hello.", "hello ", "hello.. "):
            with self.subTest(name=name):
                self.assertIn("trailing-space-or-period", self.codes(name))
        self.assertEqual(self.codes("hello world.txt"), set())

    def test_byte_limit_uses_utf8_and_strict_greater_than(self):
        self.assertEqual(self.codes("éé", max_component_bytes=4), set())
        self.assertIn("component-too-long", self.codes("éé", max_component_bytes=3))
        self.assertIn("component-too-long", self.codes("🙂", max_component_bytes=3))

    def test_surrogate_name_is_a_finding(self):
        self.assertEqual(self.codes("broken\udcff"), {"invalid-unicode"})

    def test_multiple_issues_and_display_path(self):
        findings = check_component("NUL. ", path="folder/NUL. ", max_component_bytes=2)
        self.assertEqual({item.path for item in findings}, {"folder/NUL. "})
        self.assertEqual([item.code for item in findings], ["component-too-long", "reserved-name", "trailing-space-or-period"])

    def test_non_names_are_rejected(self):
        for name in ("", ".", "..", None, 5):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_component(name)

    def test_invalid_limits_are_rejected(self):
        for value in (0, -1, 1.5, "255", True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                check_component("valid", max_component_bytes=value)


class OptionsTests(unittest.TestCase):
    def test_invalid_limits_and_boolean(self):
        for value in (0, -1, 1.5, "255", True):
            for field in ("max_component_bytes", "max_path_length"):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    AuditOptions(**{field: value})
        with self.assertRaises(ValueError):
            AuditOptions(max_component_bytes=None)
        with self.assertRaises(ValueError):
            AuditOptions(include_git=1)


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fake_audit(self, entries, **kwargs):
        with patch("portable_path_audit.audit.os.scandir", return_value=FakeScan(entries)):
            return audit_tree(self.root, **kwargs)

    def test_empty_tree_is_clean(self):
        report = audit_tree(self.root)
        self.assertTrue(report.clean)
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.scanned_entries, 0)

    def test_nested_tree_and_relative_path_threshold(self):
        (self.root / "é").mkdir()
        (self.root / "é" / "ok").touch()
        report = audit_tree(self.root, options=AuditOptions(max_path_length=3))
        self.assertEqual([(item.path, item.code) for item in report.findings], [("é/ok", "path-too-long")])
        self.assertEqual(report.scanned_entries, 2)
        self.assertTrue(audit_tree(self.root, options=AuditOptions(max_path_length=4)).clean)

    def test_component_limit_on_real_entries(self):
        (self.root / "abcdef").touch()
        report = audit_tree(self.root, options=AuditOptions(max_component_bytes=5))
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(report.findings[0].code, "component-too-long")

    def test_git_is_skipped_at_any_depth_and_can_be_included(self):
        (self.root / ".git").mkdir()
        (self.root / ".git" / "longname").touch()
        (self.root / "sub").mkdir()
        (self.root / "sub" / ".git").touch()
        report = audit_tree(self.root, options=AuditOptions(max_component_bytes=4))
        self.assertTrue(report.clean)
        self.assertEqual(report.skipped_git_entries, 2)
        self.assertEqual(report.scanned_entries, 1)
        included = audit_tree(self.root, options=AuditOptions(max_component_bytes=4, include_git=True))
        self.assertEqual(included.skipped_git_entries, 0)
        self.assertEqual(included.scanned_entries, 4)
        self.assertEqual(included.findings[0].path, ".git/longname")

    def test_casefold_and_unicode_normalization_collisions(self):
        report = self.fake_audit([FakeEntry(name) for name in ("A.txt", "a.txt", "café", "cafe\u0301", "Straße", "STRASSE")])
        groups = {item.related_paths for item in report.findings}
        self.assertEqual(groups, {("A.txt", "a.txt"), ("cafe\u0301", "café"), ("STRASSE", "Straße")})
        self.assertTrue(all(item.code == "name-collision" and item.path == "." for item in report.findings))

    def test_directories_and_files_share_collision_namespace(self):
        entries = [FakeEntry("DATA", directory=True, path="child"), FakeEntry("data")]
        def scanner(path):
            return FakeScan(entries if Path(path) == self.root else [])
        with patch("portable_path_audit.audit.os.scandir", side_effect=scanner):
            report = audit_tree(self.root)
        self.assertEqual(report.findings[0].related_paths, ("DATA", "data"))

    def test_names_in_different_directories_do_not_collide(self):
        for parent in ("first", "second"):
            (self.root / parent).mkdir()
            (self.root / parent / "same").touch()
        self.assertTrue(audit_tree(self.root).clean)

    def test_order_does_not_depend_on_scandir_order(self):
        names = ("z.", "nul.txt", "A", "a", "bad?", "x ")
        first = self.fake_audit([FakeEntry(name) for name in names])
        second = self.fake_audit([FakeEntry(name) for name in reversed(names)])
        self.assertEqual(first, second)
        self.assertEqual(first.findings, tuple(sorted(first.findings, key=lambda item: (item.path, item.code, item.related_paths))))

    def test_missing_root_and_regular_file_root_are_errors(self):
        for path in (self.root / "missing", self.root / "file"):
            if path.name == "file":
                path.touch()
            with self.subTest(path=path.name):
                report = audit_tree(path)
                self.assertEqual(report.exit_code, 2)
                self.assertEqual(report.errors[0].path, ".")
                self.assertNotIn(str(self.root), report.errors[0].message)

    def test_scan_error_retains_findings_and_does_not_claim_clean(self):
        (self.root / "good").mkdir()
        (self.root / "good" / "longname").touch()
        (self.root / "blocked").mkdir()
        original_scan = os.scandir
        def scanner(path):
            if Path(path).name == "blocked":
                raise PermissionError(errno.EACCES, "Permission denied", str(path))
            return original_scan(path)
        with patch("portable_path_audit.audit.os.scandir", side_effect=scanner):
            report = audit_tree(self.root, options=AuditOptions(max_component_bytes=7))
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.errors[0].path, "blocked")
        self.assertEqual(report.errors[0].message, "Permission denied")
        self.assertEqual(report.findings[0].path, "good/longname")

    def test_entry_metadata_error_is_reported(self):
        report = self.fake_audit([FakeEntry("gone", error=FileNotFoundError(errno.ENOENT, "No such file")), FakeEntry("okay")])
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.errors[0].path, "gone")
        self.assertEqual(report.scanned_entries, 1)

    def test_link_names_are_skipped_including_collision_members(self):
        report = self.fake_audit([FakeEntry("A"), FakeEntry("a", link=True), FakeEntry("NUL.", link=True)])
        self.assertTrue(report.clean)
        self.assertEqual(report.scanned_entries, 1)
        self.assertEqual(report.skipped_symlinks, 2)

    def test_windows_reparse_points_are_skipped(self):
        with patch("portable_path_audit.audit.stat.FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True):
            report = self.fake_audit([FakeEntry("junction", directory=True, attributes=0x400)])
        self.assertTrue(report.clean)
        self.assertEqual(report.skipped_symlinks, 1)
        self.assertEqual(report.scanned_entries, 0)

    def test_root_link_is_rejected(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        with patch("portable_path_audit.audit.Path.stat", return_value=metadata):
            report = audit_tree(self.root)
        self.assertEqual(report.exit_code, 2)
        self.assertIn("Root must not", report.errors[0].message)

    def test_real_symlink_and_broken_link_when_supported(self):
        (self.root / "target").mkdir()
        try:
            (self.root / "linked").symlink_to(self.root / "target", target_is_directory=True)
            (self.root / "broken").symlink_to(self.root / "missing")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"Symlink creation unavailable: {type(error).__name__}")
        report = audit_tree(self.root)
        self.assertTrue(report.clean)
        self.assertEqual(report.skipped_symlinks, 2)
        self.assertEqual(report.scanned_entries, 1)
        self.assertEqual(audit_tree(self.root / "linked").exit_code, 2)

    def test_target_file_contents_are_never_opened(self):
        (self.root / "content.bin").write_bytes(b"must stay untouched")
        with patch.object(builtins, "open", side_effect=AssertionError("No content reads")), patch.object(Path, "open", side_effect=AssertionError("No content reads")):
            report = audit_tree(self.root)
        self.assertTrue(report.clean)
        self.assertEqual((self.root / "content.bin").read_bytes(), b"must stay untouched")

    def test_deep_tree_does_not_use_python_recursion(self):
        depth = 1100
        def scanner(path):
            index = 0 if Path(path) == self.root else int(Path(path).name)
            return FakeScan([] if index == depth else [FakeEntry("folder", directory=True, path=str(index + 1))])
        with patch("portable_path_audit.audit.os.scandir", side_effect=scanner):
            report = audit_tree(self.root)
        self.assertTrue(report.clean)
        self.assertEqual(report.scanned_entries, depth)


if __name__ == "__main__":
    unittest.main()
