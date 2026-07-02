"""Zentrale Registry aller Checks.

Neue Checks werden hier registriert -- ein Import + ein Listeneintrag.
Das hält core/runner.py komplett unverändert, wenn das Tool von 4 auf
17 Checks wächst.
"""
from __future__ import annotations

from mcpfrisk.checks.auth_boundary import AuthBoundaryCheck
from mcpfrisk.checks.command_injection import CommandInjectionCheck
from mcpfrisk.checks.hardcoded_secrets import HardcodedSecretsCheck
from mcpfrisk.checks.path_traversal import PathTraversalCheck
from mcpfrisk.checks.rbac_cross_tenant import RbacCrossTenantCheck
from mcpfrisk.checks.ssrf_check import SsrfCheck
from mcpfrisk.checks.tool_poisoning import ToolDescriptionPoisoningCheck
from mcpfrisk.core.base_check import BaseCheck, BaseDynamicCheck

# Statische Checks: laufen direkt gegen den Quellcode, kein Server nötig.
STATIC_CHECKS: list[type[BaseCheck]] = [
    CommandInjectionCheck,
    PathTraversalCheck,
    HardcodedSecretsCheck,
    ToolDescriptionPoisoningCheck,
]

# Tier-2-Checks (dynamisch, brauchen laufenden Server), ausgeführt via
# core/dynamic_runner.py. Neue dynamische Checks: hier eintragen.
DYNAMIC_CHECKS: list[type[BaseDynamicCheck]] = [
    AuthBoundaryCheck,
    SsrfCheck,
    RbacCrossTenantCheck,
    # SchemaFuzzingCheck,
    # ErrorLeakageCheck,
]


def get_all_static_checks() -> list[BaseCheck]:
    return [check_cls() for check_cls in STATIC_CHECKS]


def get_all_dynamic_checks() -> list[BaseDynamicCheck]:
    return [check_cls() for check_cls in DYNAMIC_CHECKS]
