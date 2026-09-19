"""Portable-name checks. No target file contents are opened."""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

_FORBIDDEN = frozenset('<>:"/\\|?*')
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"}
)


@dataclass(frozen=True)
class AuditOptions:
    """Limits apply to descendants, not the supplied root directory name.

    max_path_length counts Unicode code points in a slash-separated relative
    path. It is deliberately not a Windows MAX_PATH or UTF-16 measurement.
    """

    max_component_bytes: int = 255
    max_path_length: int | None = None
    include_git: bool = False

    def __post_init__(self) -> None:
        for name in ("max_component_bytes", "max_path_length"):
            value = getattr(self, name)
            if value is None and name == "max_path_length":
                continue
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.include_git) is not bool:
            raise ValueError("include_git must be a boolean")


@dataclass(frozen=True)
class Finding:
    """A failed check, with paths relative to the supplied root."""

    code: str
    path: str
    message: str
    related_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class OperationalError:
    """A path that could not be inspected. A root error uses '.'."""

    path: str
    message: str


@dataclass(frozen=True)
class AuditResult:
    findings: tuple[Finding, ...] = ()
    errors: tuple[OperationalError, ...] = ()
    scanned_entries: int = 0
    skipped_symlinks: int = 0
    skipped_git_entries: int = 0

    @property
    def exit_code(self) -> int:
        """2 for incomplete scans, otherwise 1 for findings or 0 for clean."""
        return 2 if self.errors else (1 if self.findings else 0)

    @property
    def clean(self) -> bool:
        return self.exit_code == 0


def _collision_key(name: str) -> str:
    # Normalize again because case folding can produce decomposed sequences.
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", name).casefold())


def check_component(
    name: str, *, path: str | None = None, max_component_bytes: int = 255
) -> tuple[Finding, ...]:
    """Check a filename in isolation, including names the host cannot create.

    ``path`` is a display label only. Collision and full-path checks belong to
    :func:`audit_tree`. Empty strings and the special components '.' and '..'
    are rejected because they are not ordinary directory entry names.
    """
    if not isinstance(name, str) or name in ("", ".", ".."):
        raise ValueError("name must be a nonempty ordinary filename")
    if type(max_component_bytes) is not int or max_component_bytes < 1:
        raise ValueError("max_component_bytes must be a positive integer")
    label = name if path is None else path
    findings: list[Finding] = []
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if stem in _RESERVED:
        findings.append(Finding("reserved-name", label, "Windows reserved device filename."))
    if any(character in _FORBIDDEN or ord(character) < 32 for character in name):
        findings.append(
            Finding("forbidden-character", label, "Contains a Windows-forbidden character or U+0000-U+001F control.")
        )
    if name.endswith((" ", ".")):
        findings.append(
            Finding("trailing-space-or-period", label, "Filename ends with a space or period.")
        )
    try:
        byte_length = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        findings.append(
            Finding("invalid-unicode", label, "Filename contains a surrogate and cannot be encoded as UTF-8.")
        )
    else:
        if byte_length > max_component_bytes:
            findings.append(
                Finding(
                    "component-too-long",
                    label,
                    f"UTF-8 component length {byte_length} exceeds {max_component_bytes} bytes.",
                )
            )
    return tuple(sorted(findings, key=lambda item: item.code))


def _is_link(metadata: os.stat_result) -> bool:
    # On Windows, junctions and other reparse points should not lead us outside
    # the requested tree. The attribute is absent on other platforms.
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _error_message(error: OSError | ValueError) -> str:
    # OSError.__str__ may expose an absolute root. Keep messages relative.
    return str(getattr(error, "strerror", None) or type(error).__name__)


def audit_tree(root: str | os.PathLike[str], *, options: AuditOptions | None = None) -> AuditResult:
    """Inspect names and metadata below root without reading file contents.

    Symlinks and Windows reparse points are skipped. Any '.git' entry is skipped
    unless include_git is enabled. Findings and errors use deterministic order.
    An unreadable path produces an error and scanning continues where possible.
    """
    settings = options if options is not None else AuditOptions()
    root_path = Path(root)
    try:
        metadata = root_path.stat(follow_symlinks=False)
    except (OSError, ValueError) as error:
        return AuditResult(errors=(OperationalError(".", _error_message(error)),))
    if _is_link(metadata):
        return AuditResult(errors=(OperationalError(".", "Root must not be a symlink or Windows reparse point."),))
    if not stat.S_ISDIR(metadata.st_mode):
        return AuditResult(errors=(OperationalError(".", "Root is not a directory."),))

    findings: list[Finding] = []
    errors: list[OperationalError] = []
    scanned = skipped_links = skipped_git = 0
    pending: list[tuple[Path, str]] = [(root_path, "")]
    while pending:
        directory, relative_parent = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            errors.append(OperationalError(relative_parent or ".", _error_message(error)))
            continue
        sibling_names: dict[str, list[str]] = {}
        children: list[tuple[Path, str]] = []
        for entry in entries:
            relative = f"{relative_parent}/{entry.name}" if relative_parent else entry.name
            if entry.name == ".git" and not settings.include_git:
                skipped_git += 1
                continue
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                errors.append(OperationalError(relative, _error_message(error)))
                continue
            if _is_link(metadata):
                skipped_links += 1
                continue
            scanned += 1
            findings.extend(
                check_component(entry.name, path=relative, max_component_bytes=settings.max_component_bytes)
            )
            if settings.max_path_length is not None and len(relative) > settings.max_path_length:
                findings.append(
                    Finding(
                        "path-too-long",
                        relative,
                        f"Relative path length {len(relative)} exceeds {settings.max_path_length} code points.",
                    )
                )
            sibling_names.setdefault(_collision_key(entry.name), []).append(relative)
            if stat.S_ISDIR(metadata.st_mode):
                children.append((Path(entry.path), relative))
        for paths in sibling_names.values():
            if len(paths) > 1:
                findings.append(
                    Finding(
                        "name-collision",
                        relative_parent or ".",
                        "Sibling names match after NFC normalization and case folding.",
                        tuple(sorted(paths)),
                    )
                )
        pending.extend(reversed(children))

    return AuditResult(
        findings=tuple(sorted(findings, key=lambda item: (item.path, item.code, item.related_paths))),
        errors=tuple(sorted(errors, key=lambda item: (item.path, item.message))),
        scanned_entries=scanned,
        skipped_symlinks=skipped_links,
        skipped_git_entries=skipped_git,
    )
