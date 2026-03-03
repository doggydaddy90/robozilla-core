from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from events.event_bus import EventBus
from events.runtime_event import RuntimeEvent


class EventBusTests(unittest.TestCase):
    def test_emit_dispatches_to_subscriber(self) -> None:
        bus = EventBus()
        seen: list[RuntimeEvent] = []
        bus.subscribe(seen.append)

        event = RuntimeEvent(
            event_type="module_spawn",
            module_name="test.module",
            metadata={"unsafe": object()},
        )
        bus.emit(event)

        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].event_type, "module_spawn")
        self.assertEqual(seen[0].module_name, "test.module")
        self.assertIsInstance(seen[0].metadata.get("unsafe"), str)


if __name__ == "__main__":
    unittest.main()

