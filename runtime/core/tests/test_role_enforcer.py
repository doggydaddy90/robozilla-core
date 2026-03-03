from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from security.role_enforcer import REDACTED_SECRET, enforce_role_data_access


def _fake_api_key() -> str:
    return "sk-" + ("FAKE" * 8)


class RoleEnforcerTests(unittest.TestCase):
    def test_admin_can_retrieve_phone_number(self) -> None:
        value = enforce_role_data_access(role="admin", field_name="phone", value="+1-415-555-1212")
        self.assertEqual(value, "+1-415-555-1212")

    def test_admin_cannot_retrieve_api_key(self) -> None:
        value = enforce_role_data_access(
            role="admin",
            field_name="api_key",
            value=_fake_api_key(),
            channel="chat",
        )
        self.assertEqual(value, REDACTED_SECRET)

    def test_non_admin_cannot_retrieve_ssn(self) -> None:
        with self.assertRaises(PolicyViolationError):
            enforce_role_data_access(role="viewer", field_name="ssn", value="123-45-6789")


if __name__ == "__main__":
    unittest.main()
