"""Endpoint allowlist checks for outbound tool requests."""

from __future__ import annotations

from urllib.parse import urlparse

from errors import PolicyViolationError


def enforce_endpoint_allowlist(*, request_url: str, allowed_endpoints: list[str]) -> str:
    if not isinstance(request_url, str) or not request_url.strip():
        raise PolicyViolationError("request_url must be a non-empty string")
    if not isinstance(allowed_endpoints, list) or not allowed_endpoints:
        raise PolicyViolationError("allowed_endpoints must be a non-empty list")

    parsed_request = _parse_url(request_url)
    for allowed in allowed_endpoints:
        if not isinstance(allowed, str) or not allowed.strip():
            continue
        if "*" in allowed:
            raise PolicyViolationError("wildcard domains are forbidden in allowed_endpoints")
        parsed_allowed = _parse_url(allowed)
        if parsed_request.scheme != parsed_allowed.scheme:
            continue
        if parsed_request.hostname != parsed_allowed.hostname:
            continue
        if _normalized_port(parsed_request) != _normalized_port(parsed_allowed):
            continue
        allowed_path = (parsed_allowed.path or "/").rstrip("/")
        request_path = (parsed_request.path or "/").rstrip("/")
        if allowed_path and allowed_path != "/" and not request_path.startswith(allowed_path):
            continue
        return allowed

    raise PolicyViolationError(f"endpoint not in allowlist: {request_url}")


def _parse_url(url: str):
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise PolicyViolationError(f"unsupported endpoint scheme: {url}")
    if not parsed.hostname:
        raise PolicyViolationError(f"invalid endpoint URL: {url}")
    return parsed


def _normalized_port(parsed) -> int:
    if parsed.port is not None:
        return int(parsed.port)
    return 443 if parsed.scheme == "https" else 80

