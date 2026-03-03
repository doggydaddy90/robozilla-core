"""Kernel metadata response model."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from typing import Any

from capability.capability_registry import CapabilityRegistry
from config.config_loader import KernelConfig

_VERSION_PACKAGE_CANDIDATES = ("unum-secure-runtime", "robozilla-core")
_DEFAULT_KERNEL_VERSION = "0.1.0"


@dataclass(frozen=True)
class KernelInfo:
    kernel_version: str
    isolation_mode: str
    feature_flags: dict[str, bool]
    capability_registry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kernel_version": self.kernel_version,
            "isolation_mode": self.isolation_mode,
            "feature_flags": dict(self.feature_flags),
            "capability_registry_hash": self.capability_registry_hash,
        }


def build_kernel_info(
    *,
    config: KernelConfig,
    capability_registry: CapabilityRegistry,
    isolation_mode: str,
) -> KernelInfo:
    mode = str(isolation_mode).strip().lower()
    if mode not in {"inprocess", "subprocess"}:
        mode = "inprocess"

    flags = config.runtime.flags
    feature_flags = {
        "compliance_enabled": bool(flags.compliance_enabled),
        "container_mode_enabled": bool(flags.container_mode_enabled),
        "extended_audit": bool(flags.extended_audit),
    }
    return KernelInfo(
        kernel_version=read_kernel_version(),
        isolation_mode=mode,
        feature_flags=feature_flags,
        capability_registry_hash=capability_registry.deterministic_hash(),
    )


def read_kernel_version() -> str:
    for package_name in _VERSION_PACKAGE_CANDIDATES:
        try:
            return importlib_metadata.version(package_name)
        except importlib_metadata.PackageNotFoundError:
            continue
    return _DEFAULT_KERNEL_VERSION

