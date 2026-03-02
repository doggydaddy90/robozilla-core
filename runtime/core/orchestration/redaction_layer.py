"""PII redaction/rejection layer for normalized-document ingestion."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Iterable

from errors import PolicyViolationError

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_RES = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
)
WALLET_RES = (
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
)
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b\.?",
    re.IGNORECASE,
)
NAME_RE = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b")

REDACTIONS = {
    "email": "[REDACTED_EMAIL]",
    "phone": "[REDACTED_PHONE]",
    "api_key": "[REDACTED_API_KEY]",
    "wallet_address": "[REDACTED_WALLET]",
    "street_address": "[REDACTED_ADDRESS]",
    "ssn": "[REDACTED_SSN]",
    "private_name": "[REDACTED_NAME]",
}
NAME_CONTEXT_KEYS = {"name", "full_name", "contact_name", "person_name", "author_name", "customer_name"}
DEFAULT_PUBLIC_FIGURES = {
    "barack obama",
    "elon musk",
    "taylor swift",
    "bill gates",
    "warren buffett",
    "satya nadella",
}


@dataclass(frozen=True)
class PiiFinding:
    pii_type: str
    path: str
    value: str


def sanitize_for_ingestion(
    *,
    normalized_document: dict[str, Any],
    org_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reject or redact PII before ingestion.

    - If org policy disallows PII ingestion: deny when any PII is present.
    - Else: return a redacted copy.
    """
    if not isinstance(normalized_document, dict):
        raise PolicyViolationError("normalized_document must be an object")

    findings = detect_pii(normalized_document=normalized_document, org_policy=org_policy)
    if findings and not _allow_pii_ingestion(org_policy):
        types = sorted({f.pii_type for f in findings})
        raise PolicyViolationError(f"PII detected while allow_pii_ingestion=false: {types}")

    if not findings:
        return copy.deepcopy(normalized_document)
    return redact_document(normalized_document=normalized_document, org_policy=org_policy)


def detect_pii(*, normalized_document: dict[str, Any], org_policy: dict[str, Any] | None) -> list[PiiFinding]:
    if not isinstance(normalized_document, dict):
        raise PolicyViolationError("normalized_document must be an object")
    public_figures = _public_figure_whitelist(org_policy)
    findings: list[PiiFinding] = []
    for path, key, value in _iter_strings(normalized_document):
        findings.extend(_findings_for_text(value=value, path=path, key=key, public_figures=public_figures))
    return findings


def redact_document(*, normalized_document: dict[str, Any], org_policy: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(normalized_document, dict):
        raise PolicyViolationError("normalized_document must be an object")
    public_figures = _public_figure_whitelist(org_policy)
    out = copy.deepcopy(normalized_document)
    _redact_in_place(out, key="", public_figures=public_figures)
    return out


def _redact_in_place(node: Any, *, key: str, public_figures: set[str]) -> Any:
    if isinstance(node, dict):
        for k, v in list(node.items()):
            k_str = str(k)
            node[k] = _redact_in_place(v, key=k_str, public_figures=public_figures)
        return node
    if isinstance(node, list):
        for idx, item in enumerate(list(node)):
            node[idx] = _redact_in_place(item, key=key, public_figures=public_figures)
        return node
    if not isinstance(node, str):
        return node

    redacted = node
    redacted = EMAIL_RE.sub(REDACTIONS["email"], redacted)
    redacted = PHONE_RE.sub(REDACTIONS["phone"], redacted)
    redacted = SSN_RE.sub(REDACTIONS["ssn"], redacted)
    for api_re in API_KEY_RES:
        redacted = api_re.sub(REDACTIONS["api_key"], redacted)
    for wallet_re in WALLET_RES:
        redacted = wallet_re.sub(REDACTIONS["wallet_address"], redacted)
    redacted = ADDRESS_RE.sub(REDACTIONS["street_address"], redacted)

    if _is_name_context(key):
        candidates = {m.group(1).strip() for m in NAME_RE.finditer(redacted)}
        for candidate in sorted(candidates):
            if candidate.lower() not in public_figures:
                redacted = redacted.replace(candidate, REDACTIONS["private_name"])
    return redacted


def _iter_strings(node: Any, *, path: str = "$", key: str = "") -> Iterable[tuple[str, str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            k_str = str(k)
            yield from _iter_strings(v, path=f"{path}.{k_str}", key=k_str)
        return
    if isinstance(node, list):
        for idx, item in enumerate(node):
            yield from _iter_strings(item, path=f"{path}[{idx}]", key=key)
        return
    if isinstance(node, str):
        yield (path, key, node)


def _findings_for_text(*, value: str, path: str, key: str, public_figures: set[str]) -> list[PiiFinding]:
    out: list[PiiFinding] = []
    for m in EMAIL_RE.finditer(value):
        out.append(PiiFinding("email", path, m.group(0)))
    for m in PHONE_RE.finditer(value):
        out.append(PiiFinding("phone", path, m.group(0)))
    for m in SSN_RE.finditer(value):
        out.append(PiiFinding("ssn", path, m.group(0)))
    for api_re in API_KEY_RES:
        for m in api_re.finditer(value):
            out.append(PiiFinding("api_key", path, m.group(0)))
    for wallet_re in WALLET_RES:
        for m in wallet_re.finditer(value):
            out.append(PiiFinding("wallet_address", path, m.group(0)))
    for m in ADDRESS_RE.finditer(value):
        out.append(PiiFinding("street_address", path, m.group(0)))

    if _is_name_context(key):
        for m in NAME_RE.finditer(value):
            name = m.group(1).strip()
            if name.lower() in public_figures:
                continue
            out.append(PiiFinding("private_name", path, name))

    return out


def _is_name_context(key: str) -> bool:
    return key.strip().lower() in NAME_CONTEXT_KEYS


def _allow_pii_ingestion(org_policy: dict[str, Any] | None) -> bool:
    if not isinstance(org_policy, dict):
        return False

    direct = org_policy.get("allow_pii_ingestion")
    if isinstance(direct, bool):
        return direct

    spec = org_policy.get("spec")
    if isinstance(spec, dict):
        risk = spec.get("permissions")
        if isinstance(risk, dict):
            limits = risk.get("risk_limits")
            if isinstance(limits, dict) and isinstance(limits.get("allow_pii"), bool):
                return bool(limits.get("allow_pii"))
    return False


def _public_figure_whitelist(org_policy: dict[str, Any] | None) -> set[str]:
    out = set(DEFAULT_PUBLIC_FIGURES)
    if not isinstance(org_policy, dict):
        return out
    sources = [
        org_policy.get("public_figure_whitelist"),
        ((org_policy.get("spec") or {}).get("knowledge_policy") if isinstance(org_policy.get("spec"), dict) else None),
    ]
    for src in sources:
        values = src.get("public_figure_whitelist") if isinstance(src, dict) else src
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                out.add(value.strip().lower())
    return out
