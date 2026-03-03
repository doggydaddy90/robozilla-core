from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from capability.capability_registry import CapabilityDefinition, CapabilityRegistry, default_kernel_capability_registry


class CapabilityRegistryHashTests(unittest.TestCase):
    def test_hash_is_deterministic_for_same_definitions(self) -> None:
        base = default_kernel_capability_registry()
        reversed_registry = CapabilityRegistry(definitions=tuple(reversed(base.all())))
        self.assertEqual(base.deterministic_hash(), reversed_registry.deterministic_hash())

    def test_hash_changes_when_definition_changes(self) -> None:
        base = default_kernel_capability_registry()
        modified = CapabilityRegistry(
            definitions=(
                *base.all()[:-1],
                CapabilityDefinition(
                    name=base.all()[-1].name,
                    side_effect_class=base.all()[-1].side_effect_class,
                    risk_tier=base.all()[-1].risk_tier,
                    strictness_min=0.9,
                ),
            )
        )
        self.assertNotEqual(base.deterministic_hash(), modified.deterministic_hash())


if __name__ == "__main__":
    unittest.main()

