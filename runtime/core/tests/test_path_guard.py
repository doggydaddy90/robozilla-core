from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from security.pathGuard import safeDelete, safeRead, safeWrite
import security.pathGuard as path_guard


def _job_with_confirmations(**flags: bool) -> dict[str, object]:
    return {
        "spec": {
            "permissions_snapshot": {
                "confirmations": dict(flags),
            }
        }
    }


class PathGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # Reset mutable globals for isolated tests.
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)
        path_guard.set_audit_logger(None)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_safe_read_blocks_path_traversal(self) -> None:
        with self.assertRaises(PolicyViolationError):
            safeRead("../outside.txt")

    def test_safe_write_applies_diff_patch(self) -> None:
        target = self.root / "runtime" / "tmp" / "sample.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("line1\nline2\n", encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/sample.txt",
                "+++ b/sample.txt",
                "@@ -1,2 +1,2 @@",
                "-line1",
                "+line1-updated",
                " line2",
                "",
            ]
        )
        job = _job_with_confirmations(allow_diff_apply=True)
        res = safeWrite(target_path=target, diff=diff, job_contract=job)

        self.assertTrue(res.changed)
        self.assertEqual(target.read_text(encoding="utf-8"), "line1-updated\nline2\n")

    def test_safe_write_requires_confirmation(self) -> None:
        target = self.root / "runtime" / "tmp" / "sample.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("a\n", encoding="utf-8")
        diff = "\n".join(["--- a/sample.txt", "+++ b/sample.txt", "@@ -1,1 +1,1 @@", "-a", "+b", ""])
        with self.assertRaises(PolicyViolationError):
            safeWrite(target_path=target, diff=diff, job_contract=_job_with_confirmations())

    def test_safe_delete_requires_confirmation(self) -> None:
        target = self.root / "runtime" / "tmp" / "delete_me.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")

        with self.assertRaises(PolicyViolationError):
            safeDelete(target_path=target, job_contract=_job_with_confirmations())

        safeDelete(target_path=target, job_contract=_job_with_confirmations(allow_delete=True))
        self.assertFalse(target.exists())

    def test_recursive_delete_only_allowed_under_runtime_tmp_or_build(self) -> None:
        allowed = self.root / "runtime" / "tmp" / "job-artifacts"
        allowed.mkdir(parents=True, exist_ok=True)
        (allowed / "data.txt").write_text("ok", encoding="utf-8")

        disallowed = self.root / "other" / "job-artifacts"
        disallowed.mkdir(parents=True, exist_ok=True)
        (disallowed / "data.txt").write_text("no", encoding="utf-8")

        job = _job_with_confirmations(allow_delete=True, allow_recursive_delete=True)
        safeDelete(target_path=allowed, job_contract=job, recursive=True)
        self.assertFalse(allowed.exists())

        with self.assertRaises(PolicyViolationError):
            safeDelete(target_path=disallowed, job_contract=job, recursive=True)

    def test_root_level_delete_is_blocked(self) -> None:
        top = self.root / "top.txt"
        top.write_text("x", encoding="utf-8")
        with self.assertRaises(PolicyViolationError):
            safeDelete(target_path=top, job_contract=_job_with_confirmations(allow_delete=True))


if __name__ == "__main__":
    unittest.main()
