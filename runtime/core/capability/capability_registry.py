"""Kernel-owned immutable capability registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Iterable

from errors import PolicyViolationError


@dataclass(frozen=True)
class CapabilityDefinition:
    name: str
    side_effect_class: str
    risk_tier: str
    strictness_min: float


class CapabilityRegistry:
    """Read-only capability definitions after initialization."""

    __slots__ = ("_definitions", "_ordered")

    def __init__(self, *, definitions: Iterable[CapabilityDefinition]):
        by_name: dict[str, CapabilityDefinition] = {}
        ordered: list[CapabilityDefinition] = []
        for item in definitions:
            if not isinstance(item, CapabilityDefinition):
                raise PolicyViolationError("CapabilityRegistry definitions must be CapabilityDefinition entries")
            name = item.name.strip()
            if not name:
                raise PolicyViolationError("CapabilityDefinition.name must be non-empty")
            if name in by_name:
                raise PolicyViolationError(f"Duplicate capability definition: {name}")
            strictness_min = float(item.strictness_min)
            if strictness_min < 0.0 or strictness_min > 1.0:
                raise PolicyViolationError(f"Capability strictness_min out of bounds [0,1]: {name}")
            normalized = CapabilityDefinition(
                name=name,
                side_effect_class=item.side_effect_class.strip(),
                risk_tier=item.risk_tier.strip(),
                strictness_min=round(strictness_min, 4),
            )
            by_name[name] = normalized
            ordered.append(normalized)
        self._definitions = MappingProxyType(by_name)
        self._ordered = tuple(ordered)

    def get(self, name: str) -> CapabilityDefinition:
        key = str(name).strip()
        out = self._definitions.get(key)
        if out is None:
            raise PolicyViolationError(f"Unknown capability definition: {name}")
        return out

    def all(self) -> tuple[CapabilityDefinition, ...]:
        return self._ordered

    def __contains__(self, name: str) -> bool:
        return str(name).strip() in self._definitions

    def __len__(self) -> int:
        return len(self._ordered)

    def deterministic_hash(self) -> str:
        rows = []
        for item in sorted(self._ordered, key=lambda x: x.name):
            rows.append(
                {
                    "name": item.name,
                    "side_effect_class": item.side_effect_class,
                    "risk_tier": item.risk_tier,
                    "strictness_min": item.strictness_min,
                }
            )
        payload = json.dumps(rows, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def default_kernel_capability_registry() -> CapabilityRegistry:
    return CapabilityRegistry(
        definitions=(
            CapabilityDefinition(
                name="roland_interface",
                side_effect_class="read_only",
                risk_tier="low",
                strictness_min=0.0,
            ),
            CapabilityDefinition(
                name="research_router",
                side_effect_class="external_lookup",
                risk_tier="medium",
                strictness_min=0.6,
            ),
            CapabilityDefinition(
                name="perplexity_confidence_adapter",
                side_effect_class="external_lookup",
                risk_tier="medium",
                strictness_min=0.6,
            ),
            CapabilityDefinition(
                name="autonomous_loop_controller",
                side_effect_class="tool_orchestration",
                risk_tier="high",
                strictness_min=0.75,
            ),
        )
    )
