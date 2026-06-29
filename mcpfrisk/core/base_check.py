"""Basis-Interface für alle Sicherheitschecks.

Jeder Check ist eine eigenständige Klasse mit einer run()-Methode.
Das macht es trivial, neue Checks hinzuzufügen, ohne bestehenden Code
anzufassen (Open/Closed Principle) -- wichtig, wenn die Check-Liste
mit der Zeit auf 17+ wächst.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from mcpfrisk.core.models import Finding


class BaseCheck(ABC):
    """Abstrakte Basis für statische (Code-) Checks."""

    check_id: str = "BASE"
    name: str = "Unnamed Check"
    description: str = ""
    requires_running_server: bool = False  # True = dynamischer Check

    @abstractmethod
    def run(self, target_path: Path) -> list[Finding]:
        """Führt den Check aus und gibt eine Liste von Findings zurück."""
        raise NotImplementedError

    def applies_to(self, target_path: Path) -> bool:
        """Optionaler Vorfilter: soll dieser Check überhaupt laufen?

        Default: ja. Checks können das überschreiben, z.B. um sich
        selbst zu deaktivieren, wenn keine .py/.ts-Dateien gefunden werden.
        """
        return True


class BaseDynamicCheck(BaseCheck):
    """Basis für Checks, die einen laufenden MCP-Server brauchen
    (z.B. Auth-Boundary-Test, Schema-Fuzzing). Diese verbinden sich
    über stdio oder HTTP zum Server statt Quellcode zu lesen.
    """

    requires_running_server = True

    @abstractmethod
    def run_against_server(self, connection) -> list[Finding]:
        raise NotImplementedError

    def run(self, target_path: Path) -> list[Finding]:
        # Dynamische Checks werden über den DynamicRunner aufgerufen,
        # nicht direkt über run(). Das hier ist nur ein Fallback.
        raise RuntimeError(
            f"{self.check_id} ist ein dynamischer Check und braucht "
            "eine Server-Verbindung -- nutze run_against_server()."
        )
