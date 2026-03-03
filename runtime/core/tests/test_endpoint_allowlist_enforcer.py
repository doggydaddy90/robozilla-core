from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from security.endpoint_allowlist_enforcer import enforce_endpoint_allowlist


class EndpointAllowlistEnforcerTests(unittest.TestCase):
    def test_valid_endpoint_allowed(self) -> None:
        matched = enforce_endpoint_allowlist(
            request_url="https://api.perplexity.ai/search?q=test",
            allowed_endpoints=["https://api.perplexity.ai/search"],
        )
        self.assertEqual(matched, "https://api.perplexity.ai/search")

    def test_unknown_endpoint_denied(self) -> None:
        with self.assertRaises(PolicyViolationError):
            enforce_endpoint_allowlist(
                request_url="https://evil.example.com/steal",
                allowed_endpoints=["https://api.perplexity.ai/search"],
            )


if __name__ == "__main__":
    unittest.main()

