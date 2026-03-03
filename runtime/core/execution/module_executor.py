"""Kernel execution boundary for module invocations.

This abstraction keeps module execution behind a narrow interface so callers
cannot bypass kernel-owned enforcement gates.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

ModuleRunner = Callable[[str, dict[str, Any]], Any]


class BaseModuleExecutor(ABC):
    """Execution interface used by orchestration/runtime modules."""

    @abstractmethod
    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        """Execute one module with a structured payload."""


class SubprocessModuleExecutor(BaseModuleExecutor):
    """Default module executor.

    In current build mode this delegates to the injected kernel runner. The
    actual runner can be MCP-backed while keeping orchestration code decoupled
    from transport details.
    """

    def __init__(self, *, module_runner: ModuleRunner):
        if not callable(module_runner):
            raise TypeError("module_runner must be callable")
        self._module_runner = module_runner

    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        return self._module_runner(module_name, payload)


class ContainerModuleExecutor(BaseModuleExecutor):
    """Future container-based execution boundary (intentionally not implemented)."""

    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        raise NotImplementedError("Container module executor is not implemented in build mode")

