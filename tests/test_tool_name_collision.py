"""Tests für den TOOL_NAME_COLLISION-Check (Feature 011).

Constitution-aligned:
- Prinzip VI: paired vulnerable + clean Fixtures, Python UND JS/TS.
- Prinzip V: Finding nennt beide konkreten Fundstellen (Datei:Zeile).
- Prinzip III: klar verschiedene Namen / gemeinsames Wort → kein FP;
  konservative Near-Duplicate-Heuristik.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.tool_name_collision import ToolNameCollisionCheck
from mcpfrisk.core.models import Severity
from mcpfrisk.core.sourcetree import jsts_available

FIXTURES = Path(__file__).parent / "fixtures"
JSTS = FIXTURES / "jsts"

requires_jsts = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _run(tmp_path: Path, *sources: Path):
    for src in sources:
        (tmp_path / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return ToolNameCollisionCheck().run(tmp_path)


class TestExactDuplicatePython:
    def test_exact_duplicate_is_flagged_medium(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "collision_vuln.py")
        exact = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(exact) == 1
        f = exact[0]
        assert f.check_id == "TOOL_NAME_COLLISION"
        assert f.cwe_ref == "CWE-706"
        # Beide Fundstellen (Zeilen 15 und 21 der Fixture) müssen im Beleg stehen.
        assert "get_item" in (f.description + (f.snippet or ""))
        blob = f.description + (f.snippet or "")
        assert blob.count("collision_vuln.py") >= 2 or blob.count(":") >= 2

    def test_clean_python_has_no_findings(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "collision_clean.py")
        assert findings == []


class TestNearDuplicatePython:
    def test_near_duplicate_is_flagged_low(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "collision_vuln.py")
        low = [f for f in findings if f.severity == Severity.LOW]
        # send_mail vs sendMail ist das Near-Duplicate-Paar.
        assert len(low) >= 1
        assert any("send" in (f.description + (f.snippet or "")).lower() for f in low)

    def test_shared_word_distinct_names_are_clean(self, tmp_path):
        # list_users / create_user / delete_order teilen Wörter, sind aber
        # klar verschieden -> kein Near-Duplicate-Finding.
        findings = _run(tmp_path, FIXTURES / "collision_clean.py")
        assert findings == []


class TestDegradation:
    def test_no_tools_no_findings(self, tmp_path):
        (tmp_path / "plain.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
        assert ToolNameCollisionCheck().run(tmp_path) == []

    def test_each_collision_pair_reported_once(self, tmp_path):
        # Drei exakte Vorkommen desselben Namens -> EIN Finding (nicht drei
        # paarweise), das alle Fundstellen nennt.
        (tmp_path / "triple.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def dup(a): return a\n"
            "@mcp.tool()\n"
            "def dup(a): return a\n"
            "@mcp.tool()\n"
            "def dup(a): return a\n",
            encoding="utf-8",
        )
        findings = ToolNameCollisionCheck().run(tmp_path)
        exact = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(exact) == 1


class TestExactDuplicateJsTs:
    @requires_jsts
    def test_exact_duplicate_is_flagged(self, tmp_path):
        findings = _run(tmp_path, JSTS / "collision_vuln.ts")
        exact = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(exact) == 1
        assert "get_item" in (exact[0].description + (exact[0].snippet or ""))

    @requires_jsts
    def test_near_duplicate_is_flagged(self, tmp_path):
        # get_item vs get_items (Plural) -> Near-Duplicate (LOW).
        findings = _run(tmp_path, JSTS / "collision_vuln.ts")
        low = [f for f in findings if f.severity == Severity.LOW]
        assert len(low) >= 1

    @requires_jsts
    def test_clean_jsts_has_no_findings(self, tmp_path):
        findings = _run(tmp_path, JSTS / "collision_clean.ts")
        assert findings == []


class TestLowLevelSdkHandlersAreNotTools:
    """Regression (externer Benchmark 2026-07): die Low-Level-MCP-SDK-Handler
    @server.list_tools()/@server.call_tool() sind KEINE Tool-Definitionen -- sie
    enthalten nur zufällig den Substring 'tool'. Der frühere Substring-Match
    flaggte sie (und ihre gleichnamigen Vorkommen über mehrere Server hinweg)
    fälschlich als Tool-Namens-Kollision."""

    def test_list_call_tool_handlers_do_not_collide(self, tmp_path):
        src = (
            "from mcp.server import Server\n"
            "server = Server('x')\n"
            "@server.list_tools()\n"
            "async def list_tools():\n"
            "    return []\n"
            "@server.call_tool()\n"
            "async def call_tool(name, arguments):\n"
            "    return []\n"
        )
        (tmp_path / "a.py").write_text(src, encoding="utf-8")
        (tmp_path / "b.py").write_text(src, encoding="utf-8")  # zweiter Server, gleiche Handler
        assert ToolNameCollisionCheck().run(tmp_path) == []

    def test_real_fastmcp_tool_still_detected(self, tmp_path):
        # Gegenprobe: echte @mcp.tool()-Duplikate werden weiterhin erkannt.
        (tmp_path / "s.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def dup(a): return a\n"
            "@mcp.tool()\n"
            "def dup(a): return a\n",
            encoding="utf-8",
        )
        findings = ToolNameCollisionCheck().run(tmp_path)
        assert any(f.severity == Severity.MEDIUM for f in findings)


class TestExistingFixturesStayCollisionFree:
    """Regression: die bestehenden vulnerable/clean-Server dürfen KEINE
    TOOL_NAME_COLLISION-Findings erzeugen (sie haben keine Kollisionen)."""

    def test_shared_vulnerable_server_has_no_collision(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "vulnerable_server.py")
        assert findings == []

    def test_shared_clean_server_has_no_collision(self, tmp_path):
        findings = _run(tmp_path, FIXTURES / "clean_server.py")
        assert findings == []
