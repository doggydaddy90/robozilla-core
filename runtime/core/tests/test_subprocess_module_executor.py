from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from execution.module_executor import SubprocessModuleExecutor


def _write_worker(path: Path, *, body: str) -> None:
    source = "\n".join(
        [
            "import json",
            "import os",
            "import sys",
            "request = json.loads(sys.stdin.read())",
            "module = request.get('module')",
            "payload = request.get('payload', {})",
            body,
        ]
    )
    path.write_text(source, encoding="utf-8")


class SubprocessModuleExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.sandbox = self.root / "sandbox"
        self.worker = self.root / "worker.py"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _executor(self, *, timeout_seconds: float = 30.0, env_whitelist: tuple[str, ...] | None = None) -> SubprocessModuleExecutor:
        return SubprocessModuleExecutor(
            command_resolver={"test.module": [sys.executable, str(self.worker)]},
            sandbox_dir=self.sandbox,
            timeout_seconds=timeout_seconds,
            max_io_bytes=16_384,
            allow_unsupported_platform=True,
            env_whitelist=env_whitelist or ("PATH", "TEMP", "TMP"),
            memory_soft_limit_bytes=64 * 1024 * 1024,
            cpu_time_limit_seconds=2,
        )

    def test_module_timeout_kills_process(self) -> None:
        _write_worker(
            self.worker,
            body="\n".join(
                [
                    "import time",
                    "time.sleep(2.0)",
                    "sys.stdout.write(json.dumps({'status': 'ok', 'result': {'done': True}}))",
                ]
            ),
        )
        executor = self._executor(timeout_seconds=0.2)
        with self.assertRaises(PolicyViolationError):
            executor.execute_module("test.module", {"x": 1})

    def test_module_output_schema_violation_is_rejected(self) -> None:
        _write_worker(
            self.worker,
            body="sys.stdout.write(json.dumps({'status': 'ok', 'result': 'not-an-object'}))",
        )
        executor = self._executor()
        with self.assertRaises(PolicyViolationError):
            executor.execute_module("test.module", {"x": 1})

    def test_restricted_secret_env_var_is_not_passed(self) -> None:
        _write_worker(
            self.worker,
            body="\n".join(
                [
                    "out = {",
                    "  'secret': os.environ.get('UNUM_SECRET_TOKEN', ''),",
                    "  'http_proxy': os.environ.get('HTTP_PROXY', ''),",
                    "}",
                    "sys.stdout.write(json.dumps({'status': 'ok', 'result': out}))",
                ]
            ),
        )
        os.environ["UNUM_SECRET_TOKEN"] = "TOP_SECRET_123"
        os.environ["HTTP_PROXY"] = "http://proxy.local:3128"
        try:
            executor = self._executor(env_whitelist=("PATH", "UNUM_SECRET_TOKEN", "HTTP_PROXY"))
            out = executor.execute_module("test.module", {"x": 1})
        finally:
            os.environ.pop("UNUM_SECRET_TOKEN", None)
            os.environ.pop("HTTP_PROXY", None)

        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("secret"), "")
        self.assertEqual(out.get("http_proxy"), "")


if __name__ == "__main__":
    unittest.main()

