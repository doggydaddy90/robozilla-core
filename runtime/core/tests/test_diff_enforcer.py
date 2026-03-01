from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from security.diffEnforcer import applyPatch


def _job(confirm: bool) -> dict[str, object]:
    return {"spec": {"permissions_snapshot": {"confirmations": {"allow_diff_apply": confirm}}}}


class DiffEnforcerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_apply_patch_updates_file(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("a\nb\n", encoding="utf-8")
        diff = "\n".join(
            [
                "--- a/sample.txt",
                "+++ b/sample.txt",
                "@@ -1,2 +1,2 @@",
                "-a",
                "+updated",
                " b",
                "",
            ]
        )
        res = applyPatch(diff=diff, targetFile=target, jobContract=_job(confirm=True))
        self.assertTrue(res.changed)
        self.assertGreater(res.bytes_written, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "updated\nb\n")

    def test_dry_run_does_not_write(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("x\n", encoding="utf-8")
        diff = "\n".join(["--- a/sample.txt", "+++ b/sample.txt", "@@ -1,1 +1,1 @@", "-x", "+y", ""])
        res = applyPatch(diff=diff, targetFile=target, jobContract=_job(confirm=True), dryRun=True)
        self.assertTrue(res.changed)
        self.assertEqual(target.read_text(encoding="utf-8"), "x\n")

    def test_missing_confirmation_is_rejected(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("x\n", encoding="utf-8")
        diff = "\n".join(["--- a/sample.txt", "+++ b/sample.txt", "@@ -1,1 +1,1 @@", "-x", "+y", ""])
        with self.assertRaises(PolicyViolationError):
            applyPatch(diff=diff, targetFile=target, jobContract=_job(confirm=False))

    def test_binary_overwrite_is_rejected(self) -> None:
        target = self.root / "sample.txt"
        target.write_bytes(b"\x00\x01\x02")
        diff = "\n".join(["--- a/sample.txt", "+++ b/sample.txt", "@@ -1,1 +1,1 @@", "-x", "+y", ""])
        with self.assertRaises(PolicyViolationError):
            applyPatch(diff=diff, targetFile=target, jobContract=_job(confirm=True))

    def test_invalid_diff_is_rejected(self) -> None:
        target = self.root / "sample.txt"
        target.write_text("x\n", encoding="utf-8")
        with self.assertRaises(PolicyViolationError):
            applyPatch(diff="not-a-diff", targetFile=target, jobContract=_job(confirm=True))


if __name__ == "__main__":
    unittest.main()
