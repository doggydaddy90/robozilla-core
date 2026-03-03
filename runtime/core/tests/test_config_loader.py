from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

import yaml

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from config.config_loader import ConfigLoader
from errors import PolicyViolationError
from security.pathGuard import set_project_root


class ConfigLoaderTests(unittest.TestCase):
    def test_load_returns_immutable_kernel_config(self) -> None:
        try:
            set_project_root(CORE_DIR, freeze=False)
        except PolicyViolationError as exc:
            self.skipTest(f"unable to set test project root: {exc}")

        with tempfile.TemporaryDirectory(dir=str(CORE_DIR)) as tmp:
            root = Path(tmp)
            runtime_path = root / "runtime.yaml"
            limits_path = root / "limits.yaml"

            runtime_path.write_text(
                yaml.safe_dump(
                    {
                        "runtime": {
                            "role": "dev",
                            "strict_validation": True,
                            "fail_closed": True,
                            "compliance_enabled": False,
                            "container_mode_enabled": False,
                            "extended_audit": False,
                        },
                        "service": {"host": "127.0.0.1", "port": 8080},
                        "registry": {
                            "schemas_dir": "./schemas",
                            "orgs_dir": "./orgs",
                            "agent_definitions_dir": "./agents/definitions",
                            "skill_contracts_dir": "./skills/contracts",
                        },
                        "storage": {"driver": "sqlite", "sqlite": {"path": "./state/runtime.sqlite"}},
                        "scheduler": {"enabled": False, "poll_interval_seconds": 10},
                    }
                ),
                encoding="utf-8",
            )
            limits_path.write_text(
                yaml.safe_dump(
                    {
                        "job_contract": {
                            "max_iterations_upper_bound": 10,
                            "max_runtime_seconds_upper_bound": 120,
                            "max_cost_upper_bound": {"currency": "USD", "max_cost": 12.0},
                            "max_expires_in_seconds_upper_bound": 600,
                        },
                        "registry": {"require_known_org": True},
                    }
                ),
                encoding="utf-8",
            )

            cfg = ConfigLoader(
                environ={
                    "ROBOZILLA_RUNTIME_CONFIG": str(runtime_path),
                    "ROBOZILLA_LIMITS_CONFIG": str(limits_path),
                    "ROBOZILLA_LOGGING_CONFIG": str(root / "logging.yaml"),
                }
            ).load()

            self.assertFalse(cfg.runtime.flags.compliance_enabled)
            self.assertFalse(cfg.runtime.flags.container_mode_enabled)
            self.assertFalse(cfg.runtime.flags.extended_audit)
            with self.assertRaises(FrozenInstanceError):
                cfg.runtime = cfg.runtime  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
