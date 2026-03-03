"""Prompt injection filtering for external content."""

from __future__ import annotations

import re

from errors import PolicyViolationError

_SCRIPT_TAG_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
_INLINE_EVENT_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
_BASE64_BLOB_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{80,}={0,2})\b")
_ENCODED_BYTE_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){12,}")
_DANGEROUS_PHRASES = (
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
)
_SECRET_EXFIL_RE = re.compile(
    r"(send|reveal|show|print)\s+(me\s+)?(your\s+)?(api\s+key|token|private\s+key|environment\s+variables?)",
    re.IGNORECASE,
)


def sanitize_untrusted_content(*, content: str, mode: str = "full") -> str:
    if not isinstance(content, str):
        raise PolicyViolationError("content must be a string")
    level = str(mode).strip().lower()
    if level not in {"light", "full"}:
        raise PolicyViolationError("mode must be 'light' or 'full'")

    candidate = content.strip()
    if not candidate:
        return ""

    if _SECRET_EXFIL_RE.search(candidate):
        raise PolicyViolationError("prompt injection detected: credential exfiltration request")
    if level == "full" and _ENCODED_BYTE_RE.search(candidate):
        raise PolicyViolationError("prompt injection detected: encoded instruction payload")

    cleaned = candidate
    cleaned = _SCRIPT_TAG_RE.sub(" ", cleaned)
    cleaned = _INLINE_EVENT_RE.sub("", cleaned)
    cleaned = _BASE64_BLOB_RE.sub("[REMOVED_B64_BLOB]", cleaned)
    for pattern in _DANGEROUS_PHRASES:
        cleaned = pattern.sub("[REMOVED_INJECTION]", cleaned)

    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned

