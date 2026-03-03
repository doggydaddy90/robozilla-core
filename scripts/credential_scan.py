from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


DEFAULT_EXCLUDES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
}


SCANNER_SELF_REL_PATH = Path("scripts/credential_scan.py").as_posix()


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)
            \b(
                password|passwd|secret|api[_-]?key|apikey|client_secret|
                access_token|refresh_token|id_token|auth_token
            )\b
            \s*=\s*
            (?P<value>[^#\s][^\r\n]*)
            """
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{16,}\b")),
    ("authorization_header", re.compile(r"(?i)\bauthorization\s*:\s*[^ \t\r\n].+")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("long_base64", re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{65,}={0,2}(?![A-Za-z0-9+/=])")),
    ("connection_string", re.compile(r"(?i)\b(?:mongodb|postgres|mysql|redis|ftp|s3)://[^\s]+")),
    ("url_with_embedded_credentials", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
    ("email_address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("ipv4_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("windows_abs_path", re.compile(r"\b[A-Za-z]:\\[^\s\"']+")),
    ("unix_home_path", re.compile(r"/(?:Users|home)/[^\s\"']+")),
)


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in DEFAULT_EXCLUDES for part in rel_parts):
            continue
        out.append(path)
    return out


def _should_skip_line(kind: str, line: str) -> bool:
    lowered = line.lower()
    if "redacted" in lowered or "placeholder" in lowered or "example" in lowered:
        if kind in {"credential_assignment", "authorization_header", "email_address"}:
            return True

    # Security modules and tests can legitimately contain detection regexes.
    if "re.compile(" in line and kind in {"private_key_block", "bearer_token", "long_base64", "email_address"}:
        return True

    # Permit empty/default env assignments in sample files.
    if kind == "credential_assignment":
        m = PATTERNS[0][1].search(line)
        if m:
            value = m.group("value").strip().strip("'\"")
            if not value:
                return True
            if value.startswith("${") and value.endswith("}"):
                return True
            if value.lower() in {"redacted", "[redacted]", "<redacted>", "placeholder", "changeme", "example"}:
                return True
    return False


def scan(root: Path) -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []
    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        if rel == SCANNER_SELF_REL_PATH:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        except OSError:
            continue

        for lineno, line in enumerate(lines, start=1):
            for kind, pattern in PATTERNS:
                if not pattern.search(line):
                    continue
                if _should_skip_line(kind, line):
                    continue
                findings.append((path, lineno, kind, line.strip()))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan repository for credential and personal artifact indicators.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Repository root.")
    args = parser.parse_args()

    root = args.root.resolve()
    findings = scan(root)
    if not findings:
        print("credential-scan: no suspicious content found")
        return 0

    print("credential-scan: suspicious content detected")
    for path, lineno, kind, line in findings:
        rel = path.relative_to(root).as_posix()
        print(f"{rel}:{lineno}: {kind}: {line}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
