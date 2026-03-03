from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from api.main import app, kernel_info
from capability.capability_registry import default_kernel_capability_registry
from config.config_loader import KernelConfig
from config.settings import LimitsConfig, RegistryConfig, RuntimeConfig, RuntimeFlags, SchedulerConfig, ServiceConfig, StorageConfig


def _kernel_config() -> KernelConfig:
    runtime = RuntimeConfig(
        flags=RuntimeFlags(
            role="dev",
            strict_validation=True,
            fail_closed=True,
            compliance_enabled=False,
            container_mode_enabled=False,
            extended_audit=False,
        ),
        service=ServiceConfig(host="127.0.0.1", port=8080),
        registry=RegistryConfig(
            schemas_dir=Path("schemas"),
            orgs_dir=Path("orgs"),
            agent_definitions_dir=Path("agents/definitions"),
            skill_contracts_dir=Path("skills/contracts"),
        ),
        storage=StorageConfig(driver="sqlite", sqlite_path=Path("state/runtime.sqlite")),
        scheduler=SchedulerConfig(enabled=False, poll_interval_seconds=10),
        config_dir=Path("config"),
    )
    limits = LimitsConfig(
        max_iterations_upper_bound=10,
        max_runtime_seconds_upper_bound=120,
        max_cost_upper_bound_currency="USD",
        max_cost_upper_bound=10.0,
        max_expires_in_seconds_upper_bound=600,
        require_known_org=True,
    )
    return KernelConfig(
        runtime=runtime,
        limits=limits,
        runtime_config_path=Path("config/runtime.yaml"),
        logging_config_path=Path("config/logging.yaml"),
        limits_config_path=Path("config/limits.yaml"),
    )


class KernelInfoTests(unittest.TestCase):
    def test_kernel_info_endpoint_returns_expected_structure(self) -> None:
        app.state.components = SimpleNamespace(
            config=_kernel_config(),
            capability_registry=default_kernel_capability_registry(),
            isolation_mode="inprocess",
        )
        payload = kernel_info()
        self.assertEqual(set(payload.keys()), {"kernel_version", "isolation_mode", "feature_flags", "capability_registry_hash"})
        self.assertIn(payload["isolation_mode"], ("inprocess", "subprocess"))
        self.assertIsInstance(payload["feature_flags"], dict)
        self.assertIn("compliance_enabled", payload["feature_flags"])
        self.assertIn("container_mode_enabled", payload["feature_flags"])
        self.assertIn("extended_audit", payload["feature_flags"])
        self.assertEqual(len(str(payload["capability_registry_hash"])), 64)


if __name__ == "__main__":
    unittest.main()

