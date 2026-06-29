"""Zentrale Registry aller Checks.

Neue Checks werden hier registriert -- ein Import + ein Listeneintrag.
Das hält core/runner.py komplett unverändert, wenn das Tool von 4 auf
17 Checks wächst.
"""
from __future__ import annotations

from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.checks.hardcoded_secrets import HardcodedSecretsCheck
from mcpfrisk.checks.path_traversal import PathTraversalCheck
from mcpfrisk.checks.tool_poisoning import ToolDescriptionPoisoningCheck
from mcpfrisk.core.base_check import BaseCheck

# Statische Checks: laufen direkt gegen den Quellcode, kein Server nötig.
STATIC_CHECKS: list[type[BaseCheck]] = [
    CommandInjectionCheck,
    PathTraversalCheck,
    HardcodedSecretsCheck,
    ToolDescriptionPoisoningCheck,
]

# Platzhalter für Tier-2-Checks (dynamisch, brauchen laufenden Server).
# Sobald implementiert: hier eintragen, in core/dynamic_runner.py verdrahten.
DYNAMIC_CHECKS: list[type[BaseCheck]] = [
    # AuthBoundaryCheck,
    # RbacCrossTenantCheck,
    # SchemaFuzzingCheck,
    # SsrfCheck,
    # ErrorLeakageCheck,
]


def get_all_static_checks() -> list[BaseCheck]:
    return [check_cls() for check_cls in STATIC_CHECKS]
