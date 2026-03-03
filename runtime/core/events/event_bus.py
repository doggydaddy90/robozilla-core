"""Synchronous in-process event bus."""

from __future__ import annotations

from typing import Callable

from errors import PolicyViolationError
from events.runtime_event import RuntimeEvent

RuntimeEventHandler = Callable[[RuntimeEvent], None]


class EventBus:
    """Minimal synchronous pub/sub for kernel events."""

    __slots__ = ("_subscribers",)

    def __init__(self) -> None:
        self._subscribers: list[RuntimeEventHandler] = []

    def subscribe(self, handler: RuntimeEventHandler) -> None:
        if not callable(handler):
            raise PolicyViolationError("EventBus.subscribe handler must be callable")
        self._subscribers.append(handler)

    def emit(self, event: RuntimeEvent) -> None:
        if not isinstance(event, RuntimeEvent):
            raise PolicyViolationError("EventBus.emit requires RuntimeEvent")
        for handler in tuple(self._subscribers):
            handler(event)

    def subscriber_count(self) -> int:
        return len(self._subscribers)

