"""Scheduler (intentionally minimal in build mode).

The constitutional contracts require deterministic, bounded execution. In build
mode we do not auto-execute agents, so the scheduler is disabled by default.

This module exists to keep the runtime modular:
- API submits jobs
- Scheduler selects runnable jobs
- Executor performs bounded work under JobContract

Future work (deferred):
- A polling scheduler that picks up `created` jobs and runs them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from config.settings import SchedulerConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Scheduler:
    config: SchedulerConfig

    def run_forever(self) -> None:
        if not self.config.enabled:
            logger.info("scheduler_disabled", extra={"event": "scheduler_disabled"})
            return
        # Intentionally deferred: no background execution in build mode.
        raise NotImplementedError("Scheduler is not implemented in build mode")

