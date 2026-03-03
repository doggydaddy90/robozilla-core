from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from api.isolation import (
    enforce_route_isolation,
    is_roland_strict_mode_enabled,
    mutation_route_allowed,
    run_startup_isolation_check,
)
from errors import PolicyViolationError
import security.pathGuard as path_guard


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> None:
        self.rows.append(
            {
                "actor": actor,
                "action": action,
                "target": target,
                "details": details or {},
            }
        )


class RolandIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "cfg").mkdir(parents=True, exist_ok=True)
        (self.root / "state").mkdir(parents=True, exist_ok=True)
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)

    def tearDown(self) -> None:
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        self._tmp.cleanup()

    def test_strict_mode_defaults_true(self) -> None:
        self.assertTrue(is_roland_strict_mode_enabled({}))
        self.assertFalse(is_roland_strict_mode_enabled({"ROLAND_STRICT_MODE": "false"}))

    def test_mutation_routes_blocked_outside_roland(self) -> None:
        self.assertFalse(mutation_route_allowed(path="/jobs", method="POST", strict_mode=True))
        self.assertTrue(mutation_route_allowed(path="/roland/query", method="POST", strict_mode=True))
        self.assertTrue(mutation_route_allowed(path="/jobs", method="GET", strict_mode=True))
        with self.assertRaises(PolicyViolationError):
            enforce_route_isolation(path="/artifacts", method="POST", strict_mode=True)

    def test_startup_isolation_check_logs_and_fails_closed_outside_root(self) -> None:
        cfg = self.root / "cfg" / "runtime.yaml"
        cfg.write_text("runtime: {}\n", encoding="utf-8")
        outside = Path(self.root.anchor) if self.root.anchor else Path("/")
        audit = _AuditSink()

        details = run_startup_isolation_check(
            project_root=self.root,
            required_paths=[cfg, self.root / "state" / "db.sqlite"],
            strict_mode=True,
            audit_log=audit,
        )
        self.assertEqual(details["checked_count"], 2)
        self.assertEqual(audit.rows[-1]["action"], "roland.isolation_check")

        with self.assertRaises(PolicyViolationError):
            run_startup_isolation_check(
                project_root=self.root,
                required_paths=[outside / "outside.sqlite"],
                strict_mode=True,
                audit_log=audit,
            )

    def test_loader_uses_env_and_path_guard_for_skill_contracts_dir(self) -> None:
        loader_path = CORE_DIR / "registry" / "loader.py"
        text = loader_path.read_text(encoding="utf-8")
        self.assertIn("SKILL_CONTRACTS_DIR_ENV", text)
        self.assertIn("ROBOZILLA_SKILL_CONTRACTS_DIR", text)
        self.assertIn("resolve_path(", text)
        self.assertNotIn("/repo/skills/contracts", text)

    def test_entrypoint_has_no_hardcoded_mount_paths(self) -> None:
        entrypoint = CORE_DIR / "entrypoint.sh"
        text = entrypoint.read_text(encoding="utf-8")
        forbidden = ["/repo", "/app", "/data", "/tmp"]
        for token in forbidden:
            self.assertNotIn(token, text)

    def test_main_gates_legacy_mutation_routes(self) -> None:
        main_py = (CORE_DIR / "api" / "main.py").read_text(encoding="utf-8")
        required = [
            '_enforce_legacy_mutation_route("/jobs", "POST")',
            '_enforce_legacy_mutation_route("/jobs/{job_id}/run", "POST")',
            '_enforce_legacy_mutation_route("/jobs/{job_id}/stop", "POST")',
            '_enforce_legacy_mutation_route("/artifacts", "POST")',
            '_enforce_legacy_mutation_route("/evaluations", "POST")',
        ]
        for needle in required:
            self.assertIn(needle, main_py)


if __name__ == "__main__":
    unittest.main()
