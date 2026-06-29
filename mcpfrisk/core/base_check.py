"""Basis-Interface für alle Sicherheitschecks.

Jeder Check ist eine eigenständige Klasse mit einer run()-Methode.
Das macht es trivial, neue Checks hinzuzufügen, ohne bestehenden Code
anzufassen (Open/Closed Principle) -- wichtig, wenn die Check-Liste
mit der Zeit auf 17+ wächst.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from mcpfrisk.core.models import BoundaryOutcome, Finding, Severity

if TYPE_CHECKING:
    from mcpfrisk.core.dynamic_runner import DynamicSession
    from mcpfrisk.core.models import BoundaryResult


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
    über HTTP (bzw. künftig stdio) zum Server statt Quellcode zu lesen
    und werden über den DynamicRunner ausgeführt, nicht über run().
    """

    requires_running_server = True
    severity: Severity = Severity.HIGH

    @abstractmethod
    def run_against_server(self, session: "DynamicSession") -> "BoundaryResult":
        """Probt den laufenden Server über `session` und liefert ein
        BoundaryResult. Darf bei Server-Fehlverhalten NICHT werfen --
        ein Crash/Timeout/Transportfehler wird als INCONCLUSIVE gemeldet."""
        raise NotImplementedError

    def to_finding(self, result: "BoundaryResult") -> Finding | None:
        """Default-Mapping BoundaryResult -> Finding.

        Nur ein NOT_ENFORCED-Ergebnis erzeugt ein Finding; ENFORCED und
        INCONCLUSIVE liefern keins. Checks können das für genauere Texte
        überschreiben.
        """
        if result.outcome != BoundaryOutcome.NOT_ENFORCED:
            return None
        probe = result.failing_probe()
        observed = probe.observed if probe else ""
        location = f"{probe.operation} @ {result.target}" if probe else result.target
        return Finding(
            check_id=self.check_id,
            severity=self.severity,
            title=f"{self.name}: boundary not enforced",
            description=(
                f"Der Server beantwortete eine Anfrage ({location}) ohne sie "
                "abzulehnen, obwohl ein Zugriffsschutz erwartet wird."
            ),
            snippet=observed,
        )

    def run(self, target_path: Path) -> list[Finding]:
        # Dynamische Checks laufen über den DynamicRunner, nicht über run().
        raise RuntimeError(
            f"{self.check_id} ist ein dynamischer Check und braucht "
            "eine Server-Verbindung -- nutze run_against_server()."
        )
