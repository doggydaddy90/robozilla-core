"""Logging helpers.

The runtime uses Python logging with a JSON formatter for auditability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Common structured extras (when provided).
        for k in ("job_id", "org_id", "evaluation_id", "artifact_id", "event", "code"):
            v = getattr(record, k, None)
            if v is not None:
                base[k] = v

        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(base, ensure_ascii=True, sort_keys=True)

