"""Tests für den SCHEMA_DOCSTRING_MISMATCH-Check (Feature 016).

Constitution-aligned:
- Prinzip I: Tests zuerst (rot) — Port-Erweiterung + Check.
- Prinzip VI: paired vulnerable + clean Fixtures, Python UND JS/TS.
- Prinzip V: Finding nennt Tool + konkreten Parameter-Namen.
- Prinzip III: doppeltes Signal (sensibel UND undokumentiert); nicht-sensible /
  framework-injizierte Parameter nie geflaggt; token-tolerantes "erwähnt".
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.schema_docstring_mismatch import SchemaDocstringMismatchCheck
from mcpfrisk.core.models import Severity
from mcpfrisk.core.sourcetree import analyze, jsts_available

FIXTURES = Path(__file__).parent / "fixtures"
JSTS = FIXTURES / "jsts"

requires_jsts = pytest.mark.skipif(
    not jsts_available(), reason="jsts-Extra (tree-sitter) nicht installiert"
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _run(tmp_path: Path, *sources: Path):
    for src in sources:
        (tmp_path / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return SchemaDocstringMismatchCheck().run(tmp_path)


# --------------------------------------------------------------------------
# Port-Erweiterung: ToolDefinition.parameters
# --------------------------------------------------------------------------


class TestPortParameters:
    def test_python_tool_exposes_signature_params(self, tmp_path):
        src = _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def get_weather(city: str, api_key: str) -> str:\n"
            "    '''Return the weather.'''\n"
            "    return city\n",
        )
        model = analyze(src)
        tool = model.tool_definitions()[0]
        assert tool.parameters == ["city", "api_key"]

    def test_python_filters_injected_params(self, tmp_path):
        src = _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "from fastmcp import Context\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def do(self, ctx: Context, token: str) -> str:\n"
            "    '''Do a thing.'''\n"
            "    return token\n",
        )
        model = analyze(src)
        tool = model.tool_definitions()[0]
        assert "self" not in tool.parameters
        assert "ctx" not in tool.parameters
        assert tool.parameters == ["token"]

    @requires_jsts
    def test_jsts_tool_exposes_schema_keys(self, tmp_path):
        src = _write(
            tmp_path,
            "srv.ts",
            'import { z } from "zod";\n'
            'server.tool("fetch_page", "Fetch a web page for the given url.",\n'
            "  { url: z.string(), session_token: z.string() },\n"
            "  async (args) => ({ content: [] }));\n",
        )
        model = analyze(src)
        tool = model.tool_definitions()[0]
        assert "url" in tool.parameters
        assert "session_token" in tool.parameters


# --------------------------------------------------------------------------
# US1 — Python
# --------------------------------------------------------------------------


class TestPython:
    def test_sensitive_undocumented_param_is_flagged_high(self, tmp_path):
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def get_weather(city: str, api_key: str) -> str:\n"
            "    '''Return the weather for a city.'''\n"
            "    return city\n",
        )
        findings = SchemaDocstringMismatchCheck().run(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "SCHEMA_DOCSTRING_MISMATCH"
        assert f.severity == Severity.HIGH
        assert f.cwe_ref == "CWE-213"
        assert "get_weather" in (f.description + (f.snippet or ""))
        assert "api_key" in (f.description + (f.snippet or ""))

    def test_documented_sensitive_param_is_clean(self, tmp_path):
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def authenticate(api_key: str) -> str:\n"
            "    '''Authenticate using the provided api_key.'''\n"
            "    return 'ok'\n",
        )
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []

    def test_documented_with_spaced_wording_is_clean(self, tmp_path):
        # "API key" (mit Leerzeichen) dokumentiert api_key ebenso.
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def authenticate(api_key: str) -> str:\n"
            "    '''Authenticate with the given API key.'''\n"
            "    return 'ok'\n",
        )
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []

    def test_only_nonsensitive_params_is_clean(self, tmp_path):
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def search(query: str, limit: int, offset: int) -> str:\n"
            "    '''Search items.'''\n"
            "    return query\n",
        )
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []

    def test_empty_description_with_sensitive_param_is_flagged(self, tmp_path):
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def grab(ssh_key: str) -> str:\n"
            "    return ssh_key\n",
        )
        findings = SchemaDocstringMismatchCheck().run(tmp_path)
        assert len(findings) == 1
        assert "ssh_key" in (findings[0].description + (findings[0].snippet or ""))


# --------------------------------------------------------------------------
# US3 — Degradation
# --------------------------------------------------------------------------


class TestDegradation:
    def test_no_tools_no_findings(self, tmp_path):
        _write(tmp_path, "plain.py", "def helper():\n    return 1\n")
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []

    def test_unparsable_file_is_skipped(self, tmp_path):
        _write(tmp_path, "broken.py", "@mcp.tool(\ndef oops(token: str:\n")
        # kein Crash, kein Finding
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []

    def test_injected_context_param_never_flagged(self, tmp_path):
        _write(
            tmp_path,
            "srv.py",
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def do(ctx, context, city: str) -> str:\n"
            "    '''Do it.'''\n"
            "    return city\n",
        )
        assert SchemaDocstringMismatchCheck().run(tmp_path) == []


# --------------------------------------------------------------------------
# US2 — JS/TS
# --------------------------------------------------------------------------


class TestJsTs:
    @requires_jsts
    def test_positional_schema_sensitive_param_flagged(self, tmp_path):
        findings = _run(tmp_path, JSTS / "schema_mismatch_vuln.ts")
        highs = [f for f in findings if f.severity == Severity.HIGH]
        assert len(highs) >= 1
        blob = " ".join(f.description + (f.snippet or "") for f in highs)
        assert "session_token" in blob or "api_key" in blob

    @requires_jsts
    def test_clean_jsts_has_no_findings(self, tmp_path):
        assert _run(tmp_path, JSTS / "schema_mismatch_clean.ts") == []


# --------------------------------------------------------------------------
# Regression: bestehende paired Server bleiben befundfrei
# --------------------------------------------------------------------------


class TestExistingFixturesStayClean:
    def test_vulnerable_server_has_no_schema_finding(self, tmp_path):
        # vulnerable_server.py hat keine sensibel benannten Parameter.
        assert _run(tmp_path, FIXTURES / "vulnerable_server.py") == []

    def test_clean_server_has_no_schema_finding(self, tmp_path):
        assert _run(tmp_path, FIXTURES / "clean_server.py") == []
