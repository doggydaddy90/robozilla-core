from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from errors import PolicyViolationError

_POLICY_PATH = Path(__file__).with_name("search_operator_policy.yaml")
_TOKEN_PATTERN = re.compile(
    r'"[^"]*"|\(|\)|\bAND\b|\bOR\b|\bNOT\b|AROUND\(\d+\)|filetype:[^\s()]+|site:[^\s()]+|[^\s()]+',
    re.IGNORECASE,
)
_CONFIRMATION_INTENT_PATTERN = re.compile(
    r"\b(prove|confirm|validate|demonstrate|show)\b|\b(evidence|proof)\s+that\b",
    re.IGNORECASE,
)
_BALANCING_INTENT_PATTERN = re.compile(
    r"\b(disprove|counter|opposing|alternative|both sides|pros and cons|limitations|risk|uncertainty|falsify)\b",
    re.IGNORECASE,
)


def build_boolean_query(*, engine: str, query: str, tier: str) -> dict[str, Any]:
    tier_norm = _normalize_tier(tier)
    engine_norm = _normalize_engine(engine)
    if not isinstance(query, str) or not query.strip():
        raise PolicyViolationError("query must be a non-empty string")

    policy = _load_policy()
    if _is_confirmation_bias(query):
        raise PolicyViolationError("confirmation-bias query detected")

    tokens = _tokenize(query)
    normalized_tokens = _normalize_tokens(tokens)
    grouping_depth = _validate_boolean_sequence_and_grouping(tokens=normalized_tokens, tier=tier_norm, policy=policy)
    operators_used = _extract_operators(tokens=normalized_tokens, max_grouping_depth=grouping_depth)

    _enforce_tier_operator_legality(tier=tier_norm, operators_used=operators_used, policy=policy)
    _enforce_engine_capability(engine=engine_norm, operators_used=operators_used, policy=policy)

    return {
        "engine": engine_norm,
        "query": _format_query(normalized_tokens),
        "operators_used": operators_used,
        "tier": tier_norm,
    }


def _normalize_tier(tier: str) -> str:
    value = str(tier).strip().lower()
    if value not in {"fast", "high", "deep"}:
        raise PolicyViolationError("tier must be one of: fast|high|deep")
    return value


def _normalize_engine(engine: str) -> str:
    value = str(engine).strip().lower()
    if not value:
        raise PolicyViolationError("engine must be a non-empty string")
    return value


@lru_cache(maxsize=1)
def _load_policy() -> dict[str, Any]:
    try:
        raw = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyViolationError(f"failed to load search operator policy: {_POLICY_PATH}") from exc
    if not isinstance(raw, dict):
        raise PolicyViolationError("search operator policy root must be an object")
    return raw


def _is_confirmation_bias(query: str) -> bool:
    q = query.strip()
    if not _CONFIRMATION_INTENT_PATTERN.search(q):
        return False
    return _BALANCING_INTENT_PATTERN.search(q) is None


def _tokenize(query: str) -> list[str]:
    tokens = [match.group(0).strip() for match in _TOKEN_PATTERN.finditer(query) if match.group(0).strip()]
    if not tokens:
        raise PolicyViolationError("query tokenization produced no tokens")
    return tokens


def _normalize_tokens(tokens: list[str]) -> list[str]:
    out: list[str] = []
    for token in tokens:
        upper = token.upper()
        if upper in {"AND", "OR", "NOT"}:
            out.append(upper)
            continue

        around = re.fullmatch(r"AROUND\((\d+)\)", token, flags=re.IGNORECASE)
        if around is not None:
            out.append(f"AROUND({around.group(1)})")
            continue

        lower = token.lower()
        if lower.startswith("filetype:"):
            out.append(f"filetype:{lower.split(':', 1)[1]}")
            continue
        if lower.startswith("site:"):
            out.append(f"site:{lower.split(':', 1)[1]}")
            continue

        out.append(token)
    return out


def _validate_boolean_sequence_and_grouping(*, tokens: list[str], tier: str, policy: dict[str, Any]) -> int:
    max_depth_by_tier = _get_grouping_depth_policy(policy)
    max_allowed_depth = int(max_depth_by_tier.get(tier, 1))
    depth = 0
    max_depth = 0
    expect_operand = True

    for token in tokens:
        kind = _token_kind(token)

        if expect_operand:
            if kind in {"operand", "lparen", "unary"}:
                if kind == "operand":
                    expect_operand = False
                elif kind == "lparen":
                    depth += 1
                    max_depth = max(max_depth, depth)
                    if depth > max_allowed_depth:
                        raise PolicyViolationError(f"{tier} tier disallows nesting depth > {max_allowed_depth}")
                # unary keeps expect_operand=True
            else:
                raise PolicyViolationError("invalid boolean sequence: expected operand")
        else:
            if kind in {"binary", "rparen"}:
                if kind == "binary":
                    expect_operand = True
                else:
                    depth -= 1
                    if depth < 0:
                        raise PolicyViolationError("unbalanced grouping: too many closing parentheses")
            else:
                raise PolicyViolationError("invalid boolean sequence: expected operator or ')'")

        if token == "(":
            if not expect_operand:
                # Covered above by sequence rule, but keep explicit for clarity.
                raise PolicyViolationError("invalid grouping before '('")
        elif token == ")":
            if expect_operand:
                raise PolicyViolationError("empty grouping or dangling operator before ')'")

    if depth != 0:
        raise PolicyViolationError("unbalanced grouping: missing closing parenthesis")
    if expect_operand:
        raise PolicyViolationError("query cannot end with an operator")
    return max_depth


def _token_kind(token: str) -> str:
    if token == "(":
        return "lparen"
    if token == ")":
        return "rparen"
    if token == "NOT":
        return "unary"
    if token in {"AND", "OR"} or token.startswith("AROUND("):
        return "binary"
    return "operand"


def _extract_operators(*, tokens: list[str], max_grouping_depth: int) -> list[str]:
    used: set[str] = set()
    for token in tokens:
        if token in {"AND", "OR", "NOT"}:
            used.add(token)
            continue
        if token.startswith("AROUND("):
            used.add("AROUND")
            continue
        lower = token.lower()
        if lower.startswith("filetype:"):
            used.add("FILETYPE")
        elif lower.startswith("site:"):
            used.add("SITE")
        elif token.startswith('"') and token.endswith('"') and len(token) >= 2:
            used.add("PHRASE")
        elif token in {"(", ")"}:
            used.add("GROUP")

    if max_grouping_depth > 1:
        used.add("GROUP_NESTED")
    return sorted(used)


def _enforce_tier_operator_legality(*, tier: str, operators_used: list[str], policy: dict[str, Any]) -> None:
    tiers = policy.get("tiers")
    if not isinstance(tiers, dict):
        raise PolicyViolationError("invalid search policy: missing tiers")
    tier_cfg = tiers.get(tier)
    if not isinstance(tier_cfg, dict):
        raise PolicyViolationError(f"invalid search policy: missing tier config '{tier}'")
    allowed = tier_cfg.get("allowed_operators")
    if not isinstance(allowed, list):
        raise PolicyViolationError(f"invalid search policy: tier '{tier}' missing allowed_operators")
    allowed_set = {str(item).strip().upper() for item in allowed}

    disallowed = [op for op in operators_used if op not in allowed_set]
    if disallowed:
        raise PolicyViolationError(f"{tier} tier disallows operators: {', '.join(disallowed)}")


def _enforce_engine_capability(*, engine: str, operators_used: list[str], policy: dict[str, Any]) -> None:
    engines = policy.get("engines")
    if not isinstance(engines, dict):
        raise PolicyViolationError("invalid search policy: missing engines")
    engine_cfg = engines.get(engine)
    if not isinstance(engine_cfg, dict):
        raise PolicyViolationError(f"unknown search engine '{engine}'")
    supported = engine_cfg.get("supported_operators")
    if not isinstance(supported, list):
        raise PolicyViolationError(f"invalid search policy: engine '{engine}' missing supported_operators")
    supported_set = {str(item).strip().upper() for item in supported}

    unsupported = [op for op in operators_used if op not in supported_set]
    if unsupported:
        raise PolicyViolationError(
            f"engine '{engine}' does not support operators: {', '.join(unsupported)}"
        )


def _get_grouping_depth_policy(policy: dict[str, Any]) -> dict[str, int]:
    grouping = policy.get("grouping")
    if not isinstance(grouping, dict):
        return {"fast": 1, "high": 1, "deep": 8}
    max_depth = grouping.get("max_depth")
    if not isinstance(max_depth, dict):
        return {"fast": 1, "high": 1, "deep": 8}

    out: dict[str, int] = {}
    for tier in ("fast", "high", "deep"):
        raw = max_depth.get(tier, 1 if tier != "deep" else 8)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 1 if tier != "deep" else 8
        out[tier] = max(value, 1)
    return out


def _format_query(tokens: list[str]) -> str:
    text = " ".join(tokens)
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r"\s+\)", ")", text)
    return text.strip()
