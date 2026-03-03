#!/usr/bin/env python3
"""Fail CI when forbidden destructive/shell APIs appear outside approved MCP paths."""

from __future__ import annotations

import re
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("Could not locate repository root")


REPO_ROOT = _find_repo_root(Path(__file__).resolve().parent)
APPROVED_MCP_DIR = (REPO_ROOT / "runtime" / "core" / "mcp").resolve()

SCAN_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".sh",
}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}
FORBIDDEN_PATTERNS = {
    "fs.rm": re.compile(r"\bfs\.rm\b"),
    "rimraf": re.compile(r"\brimraf\b"),
    "child_process.exec": re.compile(r"\bchild_process\.exec\b"),
    "spawn": re.compile(r"\bspawn\s*\("),
}


def is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def iter_files() -> list[Path]:
    out: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        out.append(path)
    return out


def main() -> int:
    violations: list[str] = []
    self_path = Path(__file__).resolve()

    for path in iter_files():
        if path.resolve() == self_path:
            continue
        if APPROVED_MCP_DIR.exists() and is_under(path, APPROVED_MCP_DIR):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for label, pattern in FORBIDDEN_PATTERNS.items():
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                rel = path.relative_to(REPO_ROOT)
                violations.append(f"{rel}:{line}: forbidden token `{label}`")

    if violations:
        print("Forbidden destructive/shell APIs detected outside approved MCP folder:")
        for row in violations:
            print(f" - {row}")
        return 1
    print("No forbidden destructive/shell APIs detected outside approved MCP folder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
