"""Contract-Test für das geteilte Dynamic-Check-Helfer-Modul (Feature 013).

Sichert (a) das Verhalten der konsolidierten Helfer und (b) dass die vier
`call()`-basierten Tier-2-Checks die Symbole nicht mehr SELBST definieren,
sondern aus dem gemeinsamen Modul beziehen (ein Ort der Wahrheit -> kein
stiller Drift zwischen den Checks).
"""
from __future__ import annotations

import importlib

import pytest

from mcpfrisk.checks import _dynamic_helpers as dh


class TestSharedHelperBehaviour:
    def test_is_read_tool_classifies_read_and_mutate(self):
        assert dh.is_read_tool("get_item") is True
        assert dh.is_read_tool("list_orders") is True
        assert dh.is_read_tool("delete_item") is False
        assert dh.is_read_tool("create_user") is False
        # mutierender Hint gewinnt auch bei gemischtem Namen (konservativ).
        assert dh.is_read_tool("get_and_delete") is False

    def test_tool_properties_and_required_read_input_schema(self):
        tool = {
            "name": "x",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "q": {"type": "string"}},
                "required": ["id"],
            },
        }
        assert set(dh.tool_properties(tool)) == {"id", "q"}
        assert dh.tool_required(tool) == {"id"}

    def test_tool_helpers_tolerate_missing_or_malformed_schema(self):
        assert dh.tool_properties({}) == {}
        assert dh.tool_required({}) == set()
        assert dh.tool_properties({"inputSchema": "nope"}) == {}
        assert dh.tool_required({"inputSchema": {"required": "nope"}}) == set()

    def test_find_leak_matches_markers_and_ignores_clean_text(self):
        assert dh.find_leak("Traceback (most recent call last):") is not None
        assert dh.find_leak('File "server.py", line 42') is not None
        assert dh.find_leak("sqlite3.OperationalError: no such table") is not None
        assert dh.find_leak("KeyError") is not None
        assert dh.find_leak("everything is fine, item returned") is None

    def test_find_leak_flags_real_filesystem_paths(self):
        # Echte geleakte Dateisystem-Pfade bleiben ein Leak-Marker.
        assert dh.find_leak("open failed: /etc/passwd") is not None
        assert dh.find_leak("at /home/deploy/app/server.py") is not None
        assert dh.find_leak("could not load /opt/service/config.yaml") is not None
        assert dh.find_leak("no such file /var/log/app.log") is not None

    def test_find_leak_ignores_url_routes(self):
        # Harmlose URL-Routen in Fehlermeldungen sind KEIN Interna-Leak (FP-Fix,
        # Review 2026-07): kein System-Root, keine Datei-Endung.
        assert dh.find_leak("resource not found at /api/v1/users") is None
        assert dh.find_leak("unknown route /products/123/reviews") is None
        assert dh.find_leak("GET /health returned 200") is None

    def test_truncate_respects_limit(self):
        assert dh.truncate("short", limit=200) == "short"
        long = "A" * 300
        out = dh.truncate(long, limit=200)
        assert len(out) == 201 and out.endswith("…")


class TestChecksDoNotRedefineSharedSymbols:
    """Die vier Checks dürfen die konsolidierten Symbole nicht mehr als eigene
    Modul-Attribute führen -- sonst wäre die Konsolidierung wirkungslos
    (Drift-Risiko bliebe)."""

    @pytest.mark.parametrize(
        "modname",
        [
            "mcpfrisk.checks.schema_fuzzing",
            "mcpfrisk.checks.error_leakage",
            "mcpfrisk.checks.rbac_cross_tenant",
            "mcpfrisk.checks.rate_limiting",
        ],
    )
    def test_no_local_hint_or_leak_duplicates(self, modname):
        mod = importlib.import_module(modname)
        # Keine eigene Kopie der Tool-Hints / Leak-Marker mehr.
        assert not hasattr(mod, "_READ_HINTS")
        assert not hasattr(mod, "_MUTATE_HINTS")
        assert not hasattr(mod, "_LEAK_PATTERNS")
        assert not hasattr(mod, "_find_leak")

    def test_schema_fuzzing_and_error_leakage_share_one_leak_source(self):
        # Beide müssen dieselbe find_leak-Funktion verwenden (Identität), nicht
        # zwei divergierbare Kopien.
        from mcpfrisk.checks import error_leakage, schema_fuzzing

        assert schema_fuzzing.find_leak is dh.find_leak
        assert error_leakage.find_leak is dh.find_leak
