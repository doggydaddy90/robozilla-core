"""Ingest normalized research documents into RAG storage via diff-only writes."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from audit.auditLog import AuditLog
from errors import PolicyViolationError
from security.pathGuard import get_project_root, resolve_path, safeRead, safeWrite

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def ingest_document(
    *,
    normalized_document: dict[str, Any],
    job_contract: dict[str, Any],
    audit_log: AuditLog | None = None,
    actor: str = "runtime.core.skills.rag_ingest_document",
) -> dict[str, Any]:
    _validate_normalized_document(normalized_document)
    _validate_intent_alignment(normalized_document=normalized_document, job_contract=job_contract)

    document_id = str(normalized_document["document_id"])
    topic_hash = str(normalized_document["topic_hash"])
    version = int(normalized_document["version"])

    relative_path = Path("rag") / topic_hash / f"{document_id}.json"
    resolved = resolve_path(relative_path, operation="write", require_exists=False)

    canonical = json.dumps(normalized_document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    previous_text = safeRead(resolved, actor=actor) if resolved.exists() else ""
    patch = _build_unified_diff(
        old_text=previous_text,
        new_text=canonical,
        rel_path=str(relative_path).replace("\\", "/"),
    )

    changed = False
    if patch:
        result = safeWrite(
            target_path=resolved,
            diff=patch,
            job_contract=job_contract,
            actor=actor,
            confirmation_flag="allow_diff_apply",
        )
        changed = bool(result.changed)

    log = audit_log or AuditLog(get_project_root() / "runtime" / "state" / "runtime_audit.sqlite")
    log.append(
        actor=actor,
        action="rag.ingest_document",
        target=str(relative_path).replace("\\", "/"),
        details={"document_id": document_id, "version": version, "changed": changed},
    )

    return {
        "status": "ingested",
        "path": str(relative_path).replace("\\", "/"),
        "document_id": document_id,
        "version": version,
    }


def _validate_normalized_document(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise PolicyViolationError("normalized_document must be an object")

    required = ("document_id", "topic_hash", "source_hash", "version", "content_blocks")
    for field in required:
        if field not in doc:
            raise PolicyViolationError(f"normalized_document missing required field: {field}")

    for hash_field in ("document_id", "topic_hash", "source_hash"):
        value = str(doc.get(hash_field, ""))
        if not _HASH_RE.fullmatch(value):
            raise PolicyViolationError(f"{hash_field} must be a 64-char lowercase hex sha256")

    version = doc.get("version")
    if not isinstance(version, int) or version < 1:
        raise PolicyViolationError("version must be an integer >= 1")

    blocks = doc.get("content_blocks")
    if not isinstance(blocks, list) or not blocks:
        raise PolicyViolationError("content_blocks must be a non-empty array")
    for idx, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise PolicyViolationError(f"content_blocks[{idx}] must be an object")
        if "fact_text" not in block:
            raise PolicyViolationError(f"content_blocks[{idx}] missing fact_text")
        text = block.get("fact_text")
        if not isinstance(text, str) or not text.strip():
            raise PolicyViolationError(f"content_blocks[{idx}].fact_text must be a non-empty string")


def _build_unified_diff(*, old_text: str, new_text: str, rel_path: str) -> str:
    if old_text == new_text:
        return ""

    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    from_path = rel_path if old_text else "/dev/null"
    to_path = rel_path

    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=from_path,
            tofile=to_path,
            lineterm="",
        )
    )
    if not diff_lines:
        return ""
    return "\n".join(diff_lines) + "\n"


def _validate_intent_alignment(*, normalized_document: dict[str, Any], job_contract: dict[str, Any]) -> None:
    spec = job_contract.get("spec")
    if not isinstance(spec, dict):
        raise PolicyViolationError("job_contract.spec is required")
    envelope = spec.get("intent_envelope")
    if not isinstance(envelope, dict):
        raise PolicyViolationError("job_contract.spec.intent_envelope is required")

    original_prompt = envelope.get("original_prompt")
    intent_hash = envelope.get("intent_hash")
    if not isinstance(original_prompt, str) or not original_prompt:
        raise PolicyViolationError("IntentEnvelope.original_prompt must be a non-empty string")
    if not isinstance(intent_hash, str):
        raise PolicyViolationError("IntentEnvelope.intent_hash is required")

    computed_intent_hash = hashlib.sha256(original_prompt.encode("utf-8")).hexdigest()
    if computed_intent_hash != intent_hash:
        raise PolicyViolationError("IntentEnvelope.intent_hash does not match original_prompt")

    expected_topic_hash = hashlib.sha256(original_prompt.strip().lower().encode("utf-8")).hexdigest()
    topic_hash = str(normalized_document.get("topic_hash", ""))
    if topic_hash != expected_topic_hash:
        raise PolicyViolationError("normalized_document.topic_hash is not aligned with IntentEnvelope.original_prompt")
