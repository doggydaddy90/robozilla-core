from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = CORE_DIR.parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from audit.auditLog import AuditLog
from errors import PolicyViolationError
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest
from security.pathGuard import safeDelete, safeWrite
import security.pathGuard as path_guard


def _job_with_confirmations(**flags: bool) -> dict[str, object]:
    return {"spec": {"permissions_snapshot": {"confirmations": dict(flags)}}}


def _allowed_job_contract(*, invariant: bool = True) -> dict[str, object]:
    return {
        "metadata": {"job_id": "stress-job"},
        "spec": {
            "status": {"state": "running"},
            "invariants": {"no_side_effects_without_active_job_contract": invariant},
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["skill.allowed"],
                    "allowed_skill_categories": ["ops"],
                },
                "mcp": {
                    "allowed": [
                        {
                            "mcp_id": "mcp.safe",
                            "ref": "mcp://safe",
                            "allowed_scopes": ["read", "write"],
                        }
                    ]
                },
            },
        },
    }


def _allowed_skill_contract(*, category: str = "ops") -> dict[str, object]:
    return {"spec": {"classification": {"category_id": category}}}


class _MemoryAuditSink:
    def __init__(self) -> None:
        self.entries: list[dict[str, object]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.entries.append(
            {
                "actor": actor,
                "action": action,
                "target": target,
                "details": details or {},
            }
        )


class _BaseStressTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)

        self.audit_path = self.root / "runtime" / "state" / "audit.sqlite"
        self.audit = AuditLog(self.audit_path)
        path_guard.set_audit_logger(self.audit)

    def tearDown(self) -> None:
        path_guard.set_audit_logger(None)
        self._tmp.cleanup()

    def _count_action(self, action: str) -> int:
        conn = sqlite3.connect(str(self.audit_path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM audit_entries WHERE action = ?;", (action,)).fetchone()
            return int(row[0]) if row is not None else 0
        finally:
            conn.close()


class FilesystemRootGuardStressTests(_BaseStressTest):
    def test_root_guard_attacks_are_denied_and_logged(self) -> None:
        denied_before = self._count_action("attempt.denied")

        outside_dir = tempfile.TemporaryDirectory()
        outside_path = Path(outside_dir.name) / "outside.txt"

        in_root = self.root / "runtime" / "tmp" / "in_root.txt"
        in_root.parent.mkdir(parents=True, exist_ok=True)
        in_root.write_text("keep", encoding="utf-8")

        recursive_target = self.root / "other" / "delete-tree"
        recursive_target.mkdir(parents=True, exist_ok=True)
        (recursive_target / "x.txt").write_text("x", encoding="utf-8")

        diff_payload = "\n".join(
            [
                "--- a/in_root.txt",
                "+++ b/in_root.txt",
                "@@ -1,1 +1,1 @@",
                "-keep",
                "+changed",
                "",
            ]
        )

        try:
            with self.assertRaises(PolicyViolationError):
                safeWrite(
                    target_path=Path("C:/"),
                    diff=diff_payload,
                    job_contract=_job_with_confirmations(allow_diff_apply=True),
                    dry_run=True,
                )

            with self.assertRaises(PolicyViolationError):
                safeWrite(
                    target_path="../outside.txt",
                    diff=diff_payload,
                    job_contract=_job_with_confirmations(allow_diff_apply=True),
                    dry_run=True,
                )

            with self.assertRaises(PolicyViolationError):
                safeWrite(
                    target_path=outside_path,
                    diff=diff_payload,
                    job_contract=_job_with_confirmations(allow_diff_apply=True),
                    dry_run=True,
                )

            with self.assertRaises(PolicyViolationError):
                safeDelete(
                    target_path=self.root,
                    job_contract=_job_with_confirmations(allow_delete=True),
                )

            with self.assertRaises(PolicyViolationError):
                safeDelete(
                    target_path=recursive_target,
                    job_contract=_job_with_confirmations(allow_delete=True, allow_recursive_delete=True),
                    recursive=True,
                )

            with self.assertRaises(PolicyViolationError):
                safeDelete(
                    target_path="*.py",
                    job_contract=_job_with_confirmations(allow_delete=True),
                )

            with self.assertRaises(PolicyViolationError):
                safeDelete(
                    target_path=in_root,
                    job_contract=_job_with_confirmations(),
                )
        finally:
            outside_dir.cleanup()

        denied_after = self._count_action("attempt.denied")
        self.assertEqual(denied_after - denied_before, 7)
        self.assertTrue(self.root.exists())
        self.assertTrue(recursive_target.exists())
        self.assertTrue(in_root.exists())
        self.assertEqual(in_root.read_text(encoding="utf-8"), "keep")


class DiffEnforcerStressTests(_BaseStressTest):
    def setUp(self) -> None:
        super().setUp()
        self.target = self.root / "runtime" / "tmp" / "diff" / "target.txt"
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text("line1\nline2\n", encoding="utf-8")

    def _assert_denied_with_no_write(
        self,
        *,
        diff_payload: str,
        job_contract: dict[str, object] | None = None,
        target: Path | None = None,
    ) -> None:
        selected_target = target or self.target
        before_content = selected_target.read_text(encoding="utf-8")
        denied_before = self._count_action("attempt.denied")

        with self.assertRaises(PolicyViolationError):
            safeWrite(
                target_path=selected_target,
                diff=diff_payload,
                job_contract=job_contract if job_contract is not None else _job_with_confirmations(allow_diff_apply=True),
            )

        denied_after = self._count_action("attempt.denied")
        self.assertEqual(denied_after - denied_before, 1)
        self.assertEqual(selected_target.read_text(encoding="utf-8"), before_content)
        self.assertFalse(selected_target.with_name(f".{selected_target.name}.tmp").exists())

    def test_binary_patch_payload_is_denied(self) -> None:
        self._assert_denied_with_no_write(diff_payload="GIT binary patch\nliteral 5")

    def test_rename_patch_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/old_name.txt",
                "+++ b/new_name.txt",
                "@@ -1,2 +1,2 @@",
                "-line1",
                "+line1-new",
                " line2",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload)

    def test_multi_target_patch_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/target.txt",
                "+++ b/target.txt",
                "@@ -1,2 +1,2 @@",
                "-line1",
                "+line1-updated",
                " line2",
                "--- a/another.txt",
                "+++ b/another.txt",
                "@@ -1,1 +1,1 @@",
                "-x",
                "+y",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload)

    def test_hunk_count_mismatch_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/target.txt",
                "+++ b/target.txt",
                "@@ -1,3 +1,3 @@",
                "-line1",
                "+line1-updated",
                " line2",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload)

    def test_context_mismatch_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/target.txt",
                "+++ b/target.txt",
                "@@ -1,2 +1,2 @@",
                "-not-present",
                "+line1-updated",
                " line2",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload)

    def test_patch_without_confirmation_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/target.txt",
                "+++ b/target.txt",
                "@@ -1,2 +1,2 @@",
                "-line1",
                "+line1-updated",
                " line2",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload, job_contract=_job_with_confirmations())

    def test_same_filename_different_directory_patch_is_denied(self) -> None:
        diff_payload = "\n".join(
            [
                "--- a/other-place/target.txt",
                "+++ b/other-place/target.txt",
                "@@ -1,2 +1,2 @@",
                "-line1",
                "+line1-updated",
                " line2",
                "",
            ]
        )
        self._assert_denied_with_no_write(diff_payload=diff_payload)


class CapabilityEnforcerStressTests(unittest.TestCase):
    def test_unauthorized_capabilities_are_denied_and_logged(self) -> None:
        audit = _MemoryAuditSink()
        enforcer = CapabilityEnforcer(audit_log=audit)
        job = _allowed_job_contract()
        skill = _allowed_skill_contract()

        attempts = [
            CapabilityRequest(
                actor="stress",
                job_contract=None,
                skill_contract=skill,
                skill_id="skill.allowed",
                requested_side_effects=False,
                requested_channel="none",
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=job,
                skill_contract=None,
                skill_id="skill.allowed",
                requested_side_effects=False,
                requested_channel="none",
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=job,
                skill_contract=_allowed_skill_contract(category="unknown"),
                skill_id="skill.forbidden",
                requested_side_effects=False,
                requested_channel="none",
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=_allowed_job_contract(invariant=False),
                skill_contract=skill,
                skill_id="skill.allowed",
                requested_side_effects=True,
                requested_channel="none",
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=job,
                skill_contract=skill,
                skill_id="skill.allowed",
                requested_side_effects=False,
                requested_channel="fs",
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=job,
                skill_contract=skill,
                skill_id="skill.allowed",
                requested_side_effects=False,
                requested_channel="shell",
                requested_mcp_id=None,
            ),
            CapabilityRequest(
                actor="stress",
                job_contract=job,
                skill_contract=skill,
                skill_id="skill.allowed",
                requested_side_effects=False,
                requested_channel="mcp",
                requested_mcp_id="mcp.safe",
                requested_mcp_scopes=["admin"],
            ),
        ]

        for req in attempts:
            with self.assertRaises(PolicyViolationError):
                enforcer.enforceCapability(req)

        denied_count = sum(1 for row in audit.entries if row["action"] == "attempt.denied")
        allowed_count = sum(1 for row in audit.entries if row["action"] == "capability.allowed")
        self.assertEqual(denied_count, len(attempts))
        self.assertEqual(allowed_count, 0)


class AuditLogTamperStressTests(_BaseStressTest):
    def test_update_and_delete_are_blocked_by_triggers(self) -> None:
        self.audit.append(actor="stress", action="append", target="entry-1", details={})

        conn = sqlite3.connect(str(self.audit_path))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_entries SET actor = 'tamper' WHERE id = 1;")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_entries WHERE id = 1;")
        finally:
            conn.close()

    def test_direct_db_file_modification_is_detected_when_feasible(self) -> None:
        self.audit.append(actor="stress", action="append", target="entry-1", details={})
        self.audit.append(actor="stress", action="append", target="entry-2", details={})

        conn = sqlite3.connect(str(self.audit_path))
        try:
            row = conn.execute("SELECT hash FROM audit_entries WHERE id = 1;").fetchone()
            self.assertIsNotNone(row)
            expected_hash = str(row[0])
        finally:
            conn.close()

        blob = self.audit_path.read_bytes()
        marker = expected_hash.encode("ascii")
        if marker not in blob:
            self.skipTest("Could not locate hash bytes in sqlite file to perform direct mutation")
        tampered = blob.replace(marker, b"f" * 64, 1)
        self.audit_path.write_bytes(tampered)

        result = self.audit.verifyAuditChain()
        self.assertFalse(result.valid)

    def test_out_of_order_insert_is_detected(self) -> None:
        first = self.audit.append(actor="stress", action="append", target="entry-1", details={})

        conn = sqlite3.connect(str(self.audit_path))
        try:
            conn.execute(
                """
                INSERT INTO audit_entries(id, timestamp, actor, action, target, details_json, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (10, first["timestamp"], "tamper", "append", "entry-10", "{}", first["hash"], "c" * 64),
            )
            conn.commit()
        finally:
            conn.close()

        result = self.audit.verifyAuditChain()
        self.assertFalse(result.valid)
        self.assertTrue(any("id sequence break" in err for err in result.errors))

    def test_broken_hash_chain_is_detected(self) -> None:
        first = self.audit.append(actor="stress", action="append", target="entry-1", details={})

        conn = sqlite3.connect(str(self.audit_path))
        try:
            conn.execute(
                """
                INSERT INTO audit_entries(id, timestamp, actor, action, target, details_json, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (2, first["timestamp"], "tamper", "append", "entry-2", "{}", "not-real-prev", "d" * 64),
            )
            conn.commit()
        finally:
            conn.close()

        result = self.audit.verifyAuditChain()
        self.assertFalse(result.valid)
        self.assertTrue(any(("prev_hash mismatch" in err) or ("hash mismatch" in err) for err in result.errors))


class CifForbiddenOpsScannerStressTests(unittest.TestCase):
    def test_scanner_flags_temp_file_and_file_is_cleaned_up(self) -> None:
        scanner = REPO_ROOT / "tools" / "ci" / "check_forbidden_ops.py"
        self.assertTrue(scanner.exists())

        temp_file = REPO_ROOT / "runtime" / "core" / "tests" / "stress_tests" / "_tmp_forbidden_scan.py"
        token_a = "fs" + ".rm"
        token_b = "rim" + "raf"
        token_c = "child_process" + "." + "exec"
        token_d = "sp" + "awn"
        payload = "\n".join(
            [
                f"{token_a}",
                f"{token_b}",
                f"{token_c}",
                f"{token_d}(",
                "",
            ]
        )
        temp_file.write_text(payload, encoding="utf-8")
        try:
            run = subprocess.run(
                [sys.executable, str(scanner)],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run.returncode, 1)
            self.assertIn(str(temp_file.relative_to(REPO_ROOT)).replace("\\", "/"), run.stdout.replace("\\", "/"))
        finally:
            if temp_file.exists():
                temp_file.unlink()

        self.assertFalse(temp_file.exists())


class ConcurrencyStressTests(_BaseStressTest):
    def test_parallel_denials_and_audit_appends_are_stable(self) -> None:
        write_target = self.root / "runtime" / "tmp" / "parallel" / "target.txt"
        write_target.parent.mkdir(parents=True, exist_ok=True)
        write_target.write_text("base\n", encoding="utf-8")

        bad_diff = "\n".join(
            [
                "--- a/target.txt",
                "+++ b/target.txt",
                "@@ -1,2 +1,2 @@",
                "-base",
                "+new",
                "",
            ]
        )

        delete_targets = []
        delete_root = self.root / "runtime" / "tmp" / "parallel-delete"
        delete_root.mkdir(parents=True, exist_ok=True)
        for i in range(10):
            candidate = delete_root / f"candidate-{i}.txt"
            candidate.write_text("stay", encoding="utf-8")
            delete_targets.append(candidate)

        def write_attack(i: int) -> bool:
            try:
                safeWrite(
                    target_path=write_target,
                    diff=bad_diff,
                    job_contract=_job_with_confirmations(allow_diff_apply=True),
                    actor=f"writer-{i}",
                )
            except PolicyViolationError:
                return True
            return False

        def delete_attack(path: Path) -> bool:
            try:
                safeDelete(
                    target_path=path,
                    job_contract=_job_with_confirmations(),
                    actor="deleter",
                )
            except PolicyViolationError:
                return True
            return False

        def append_audit(i: int) -> None:
            self.audit.append(
                actor=f"audit-{i}",
                action="stress.append",
                target=f"parallel-{i}",
                details={"index": i},
            )

        with ThreadPoolExecutor(max_workers=10) as pool:
            write_results = list(pool.map(write_attack, range(10)))
        self.assertTrue(all(write_results))
        self.assertEqual(write_target.read_text(encoding="utf-8"), "base\n")

        with ThreadPoolExecutor(max_workers=10) as pool:
            delete_results = list(pool.map(delete_attack, delete_targets))
        self.assertTrue(all(delete_results))
        self.assertTrue(all(path.exists() for path in delete_targets))

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(append_audit, range(10)))

        verify = self.audit.verifyAuditChain()
        self.assertTrue(verify.valid, msg=f"audit chain errors: {verify.errors}")
        self.assertEqual(self._count_action("attempt.denied"), 20)
        self.assertEqual(self._count_action("stress.append"), 10)


if __name__ == "__main__":
    unittest.main()
