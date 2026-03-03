from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from governance.strictness_adapter import derive_strictness_profile


class StrictnessAdapterTests(unittest.TestCase):
    def test_strictness_1_increases_caution(self) -> None:
        low = derive_strictness_profile(system_strictness=0.3)
        high = derive_strictness_profile(system_strictness=1.0)
        self.assertLess(high.risk_deny_threshold, low.risk_deny_threshold)
        self.assertGreater(high.deep_trigger_aggressiveness, low.deep_trigger_aggressiveness)
        self.assertLess(high.entropy_tolerance, low.entropy_tolerance)

    def test_strictness_03_reduces_escalation_frequency(self) -> None:
        strict = derive_strictness_profile(system_strictness=1.0)
        relaxed = derive_strictness_profile(system_strictness=0.3)
        self.assertLess(relaxed.deep_trigger_aggressiveness, strict.deep_trigger_aggressiveness)
        self.assertLess(relaxed.minority_escalation_sensitivity, strict.minority_escalation_sensitivity)

    def test_core_invariants_unchanged_all_levels(self) -> None:
        for level in (0.0, 0.3, 0.75, 1.0):
            profile = derive_strictness_profile(system_strictness=level)
            self.assertGreaterEqual(profile.atomic_threshold_floor, 0.7)
            self.assertTrue(profile.pii_redaction_enabled)
            self.assertTrue(profile.capability_enforcer_required)
            self.assertTrue(profile.diff_only_mutation_required)
            self.assertTrue(profile.endpoint_allowlist_required)
            self.assertTrue(profile.credential_exposure_forbidden)


if __name__ == "__main__":
    unittest.main()

