"""
base.py - Abstract lifecycle component for Antigravity Unlocker server services.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceStatus:
    name: str
    is_running: bool
    listen_addresses: str
    details: Optional[str] = None


class BaseServerService(abc.ABC):
    """Abstract base class establishing lifecycle contract for all server services."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable service name."""
        pass

    @abc.abstractmethod
    async def start(self) -> None:
        """Asynchronously binds sockets and starts serving requests."""
        pass

    @abc.abstractmethod
    async def stop(self) -> None:
        """Gracefully stops serving, cancels background tasks and closes sockets."""
        pass

    @abc.abstractmethod
    def get_status(self) -> ServiceStatus:
        """Returns the current operational status of the service."""
        pass
