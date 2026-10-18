"""
base.py - Base abstractions and data structures for patching operations.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PatchRule:
    """Represents an exact-byte or string replacement rule."""
    name: str
    target: bytes
    replacement: bytes
    description: str = ""

    def __post_init__(self):
        if len(self.target) != len(self.replacement):
            raise ValueError(
                f"Binary patch rule '{self.name}' must have identical length: "
                f"{len(self.target)} != {len(self.replacement)}"
            )


@dataclass
class PatchResult:
    """Outcome of applying or reverting a patch."""
    success: bool
    modified_count: int
    message: str
    details: Dict[str, Any] = None


class BasePatcher(abc.ABC):
    """Abstract base class for all patching components."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Patcher component name."""
        pass

    @abc.abstractmethod
    def inspect(self, target: Path) -> Dict[str, Any]:
        """Inspects target file/environment patch state."""
        pass

    @abc.abstractmethod
    def apply(self, target: Path) -> PatchResult:
        """Applies patch to target."""
        pass

    @abc.abstractmethod
    def revert(self, target: Path) -> PatchResult:
        """Reverts patch from target."""
        pass
