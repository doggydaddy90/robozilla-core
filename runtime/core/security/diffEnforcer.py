"""Unified-diff-only write enforcement.

Runtime file mutation must go through this module. It rejects direct overwrite
patterns and only applies validated unified patches.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from errors import PolicyViolationError

_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")
_NO_NEWLINE_MARKER = r"\ No newline at end of file"
_BINARY_MARKERS = ("GIT binary patch", "Binary files ", "literal ", "delta ")


@dataclass(frozen=True)
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[tuple[str, str]]


@dataclass(frozen=True)
class PatchApplyResult:
    target_file: Path
    changed: bool
    dry_run: bool
    bytes_written: int
    content_sha256: str


def _job_flag(job_contract: dict[str, Any] | None, flag_name: str) -> bool:
    if not isinstance(job_contract, dict):
        return False
    spec = job_contract.get("spec")
    if not isinstance(spec, dict):
        return False
    snapshot = spec.get("permissions_snapshot")
    if isinstance(snapshot, dict):
        confirmations = snapshot.get("confirmations")
        if isinstance(confirmations, dict) and bool(confirmations.get(flag_name)):
            return True
    confirmations = spec.get("confirmations")
    if isinstance(confirmations, dict):
        return bool(confirmations.get(flag_name))
    return False


def _normalize_patch_path(value: str) -> str:
    p = value.strip().split("\t", 1)[0].strip()
    if p.startswith("a/") or p.startswith("b/"):
        return p[2:]
    return p


def _parse_diff_headers(lines: list[str]) -> tuple[str, str, int]:
    start = 0
    while start < len(lines) and not lines[start].startswith("--- "):
        start += 1
    if start >= len(lines):
        raise PolicyViolationError("Invalid diff format: missing '---' header")
    if start + 1 >= len(lines) or not lines[start + 1].startswith("+++ "):
        raise PolicyViolationError("Invalid diff format: missing '+++' header")

    old_path = _normalize_patch_path(lines[start][4:])
    new_path = _normalize_patch_path(lines[start + 1][4:])
    return old_path, new_path, start + 2


def _contains_binary_marker(diff_text: str) -> bool:
    return any(marker in diff_text for marker in _BINARY_MARKERS)


def _validate_target_header(target_file: Path, old_path: str, new_path: str) -> None:
    if new_path == "/dev/null":
        raise PolicyViolationError("Patch deletes are not allowed; use safeDelete()")

    expected = target_file.name
    header_target = Path(new_path).name if new_path else ""
    if header_target and header_target != expected:
        raise PolicyViolationError(
            f"Diff target mismatch: patch targets '{new_path}', requested target is '{target_file.name}'"
        )
    if old_path not in ("/dev/null", new_path):
        # Multi-target or rename patches are intentionally denied.
        raise PolicyViolationError("Rename/multi-target patches are not allowed")


def _parse_hunks(lines: list[str], start_index: int) -> list[DiffHunk]:
    hunks: list[DiffHunk] = []
    i = start_index
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue
        if line.startswith(("diff --git ", "index ", "new file mode ", "deleted file mode ")):
            i += 1
            continue
        m = _HUNK_RE.match(line)
        if m is None:
            raise PolicyViolationError(f"Invalid diff format near line: {line}")

        old_start = int(m.group("old_start"))
        old_count = int(m.group("old_count") or "1")
        new_start = int(m.group("new_start"))
        new_count = int(m.group("new_count") or "1")
        i += 1

        hunk_lines: list[tuple[str, str]] = []
        while i < len(lines):
            cur = lines[i]
            if cur.startswith("@@ "):
                break
            if cur.startswith(("--- ", "+++ ")):
                raise PolicyViolationError("Only single-file unified diff patches are allowed")
            if cur == _NO_NEWLINE_MARKER:
                i += 1
                continue
            if not cur:
                raise PolicyViolationError("Malformed hunk line (missing prefix)")
            op = cur[0]
            if op not in (" ", "+", "-"):
                raise PolicyViolationError(f"Malformed hunk line prefix: {op}")
            hunk_lines.append((op, cur[1:]))
            i += 1

        old_seen = sum(1 for op, _ in hunk_lines if op in (" ", "-"))
        new_seen = sum(1 for op, _ in hunk_lines if op in (" ", "+"))
        if old_seen != old_count or new_seen != new_count:
            raise PolicyViolationError("Diff hunk counts do not match header ranges")

        hunks.append(
            DiffHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=hunk_lines,
            )
        )
    if not hunks:
        raise PolicyViolationError("Invalid diff format: no hunks found")
    return hunks


def _load_existing_text(target_file: Path) -> str:
    if not target_file.exists():
        return ""
    raw = target_file.read_bytes()
    if b"\x00" in raw:
        raise PolicyViolationError(f"Binary overwrite is not allowed: {target_file}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyViolationError(f"Non-UTF8 file overwrite is not allowed: {target_file}") from exc


def _apply_hunks(source: str, hunks: list[DiffHunk]) -> str:
    src_lines = source.splitlines()
    out: list[str] = []
    src_index = 0

    for hunk in hunks:
        start = max(hunk.old_start - 1, 0)
        if start < src_index:
            raise PolicyViolationError("Overlapping or out-of-order diff hunks are not allowed")
        out.extend(src_lines[src_index:start])
        src_index = start

        for op, text in hunk.lines:
            if op == " ":
                if src_index >= len(src_lines) or src_lines[src_index] != text:
                    raise PolicyViolationError("Patch context does not match target file contents")
                out.append(text)
                src_index += 1
            elif op == "-":
                if src_index >= len(src_lines) or src_lines[src_index] != text:
                    raise PolicyViolationError("Patch delete line does not match target file contents")
                src_index += 1
            elif op == "+":
                out.append(text)

    out.extend(src_lines[src_index:])
    if not out:
        return ""
    return "\n".join(out) + "\n"


def _atomic_write_text(path: Path, content: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    payload = content.encode("utf-8")
    with tmp_path.open("wb") as f:
        f.write(payload)
    os.replace(tmp_path, path)
    return len(payload)


def applyPatch(
    *,
    diff: str,
    targetFile: Path,
    jobContract: dict[str, Any] | None,
    dryRun: bool = False,
    confirmationFlag: str = "allow_diff_apply",
) -> PatchApplyResult:
    """Validate and apply a unified diff patch to one target file."""
    if not isinstance(diff, str) or not diff.strip():
        raise PolicyViolationError("Diff payload is required")
    if _contains_binary_marker(diff):
        raise PolicyViolationError("Binary patch payloads are not allowed")
    if not _job_flag(jobContract, confirmationFlag):
        raise PolicyViolationError(
            f"JobContract confirmation flag '{confirmationFlag}' is required before applying a patch"
        )

    lines = diff.splitlines()
    old_path, new_path, hunk_start = _parse_diff_headers(lines)
    _validate_target_header(targetFile, old_path, new_path)
    hunks = _parse_hunks(lines, hunk_start)

    source = _load_existing_text(targetFile)
    updated = _apply_hunks(source, hunks)
    if "\x00" in updated:
        raise PolicyViolationError("Binary overwrite is not allowed")

    changed = source != updated
    digest = hashlib.sha256(updated.encode("utf-8")).hexdigest()
    if dryRun or not changed:
        return PatchApplyResult(target_file=targetFile, changed=changed, dry_run=dryRun, bytes_written=0, content_sha256=digest)

    written = _atomic_write_text(targetFile, updated)
    return PatchApplyResult(target_file=targetFile, changed=True, dry_run=False, bytes_written=written, content_sha256=digest)

