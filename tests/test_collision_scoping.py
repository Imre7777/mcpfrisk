"""Feature 026: TOOL_NAME_COLLISION Datei-Scoping.

Tool-Shadowing setzt DENSELBEN Server (dieselbe FastMCP()/Server()-Instanz)
voraus. Real-World-Befund (python-sdk, mcp-atlassian, 2026-07): jede Quelldatei
ist typischerweise ein eigenständiger Server mit eigener Instanz --
Doku-Tutorials (tutorial001.py ... tutorial008.py) und getrennte Beispielserver
teilen zwar Verzeichnisse, aber nie den Namensraum; mcp-atlassian nutzt getrennte
Sub-Server (confluence_mcp/jira_mcp), die beim Mounten geprefixt werden. Der
frühere globale Vergleich meldete all das fälschlich (~83 FP auf den SDKs).
Gewertet wird daher nur INNERHALB einer Datei.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.checks.tool_name_collision import ToolNameCollisionCheck
from mcpfrisk.core.models import Severity

_TOOL = (
    "from fastmcp import FastMCP\n"
    "mcp = FastMCP('x')\n"
    "@mcp.tool()\n"
    "def {name}(a): return a\n"
)


def _write(p: Path, name: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_TOOL.format(name=name), encoding="utf-8")


def _run(tmp_path: Path) -> list:
    return ToolNameCollisionCheck().run(tmp_path)


class TestSeparateServersDoNotCollide:
    def test_same_name_in_separate_dirs_is_clean(self, tmp_path):
        _write(tmp_path / "examples" / "server_a" / "main.py", "echo")
        _write(tmp_path / "examples" / "server_b" / "main.py", "echo")
        assert _run(tmp_path) == []

    def test_same_name_in_separate_files_same_dir_is_clean(self, tmp_path):
        # Der python-sdk-Fall: tutorial001.py / tutorial002.py im selben
        # Verzeichnis, jeweils eigener Server -> KEINE Kollision.
        _write(tmp_path / "docs" / "tutorial001.py", "add_note")
        _write(tmp_path / "docs" / "tutorial002.py", "add_note")
        assert _run(tmp_path) == []

    def test_near_duplicate_across_files_is_clean(self, tmp_path):
        _write(tmp_path / "a.py", "get_item")
        _write(tmp_path / "b.py", "get_items")
        assert _run(tmp_path) == []

    def test_sub_servers_own_instances_are_clean(self, tmp_path):
        # Der mcp-atlassian-Fall: zwei Sub-Server mit eigener Instanz, gleicher
        # Tool-Name -> beim Mounten geprefixt, keine echte Kollision.
        (tmp_path / "confluence.py").write_text(
            "from fastmcp import FastMCP\n"
            "confluence_mcp = FastMCP('c')\n"
            "@confluence_mcp.tool()\n"
            "def search(q): return q\n",
            encoding="utf-8",
        )
        (tmp_path / "jira.py").write_text(
            "from fastmcp import FastMCP\n"
            "jira_mcp = FastMCP('j')\n"
            "@jira_mcp.tool()\n"
            "def search(q): return q\n",
            encoding="utf-8",
        )
        assert _run(tmp_path) == []

    def test_many_example_servers_same_toolset_are_clean(self, tmp_path):
        for i in range(6):
            _write(tmp_path / "examples" / f"tutorial00{i}.py", "echo")
        assert _run(tmp_path) == []


class TestSameFileStillFlagged:
    def test_duplicate_in_single_file_still_flagged(self, tmp_path):
        (tmp_path / "srv.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def echo(a): return a\n"
            "@mcp.tool()\n"
            "def echo(a): return a\n",
            encoding="utf-8",
        )
        exact = [f for f in _run(tmp_path) if f.severity == Severity.MEDIUM]
        assert len(exact) == 1
        # Der Beleg nennt "derselben Datei", nicht mehr Verzeichnis.
        assert "Datei" in exact[0].description

    def test_near_duplicate_in_single_file_still_flagged(self, tmp_path):
        (tmp_path / "srv.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def get_item(a): return a\n"
            "@mcp.tool()\n"
            "def get_items(a): return a\n",
            encoding="utf-8",
        )
        low = [f for f in _run(tmp_path) if f.severity == Severity.LOW]
        assert len(low) >= 1


class TestMixedScopes:
    def test_only_the_real_in_file_collision_is_reported(self, tmp_path):
        # server_a/srv.py hat ein echtes Duplikat IN EINER Datei -> genau ein
        # Finding. server_b/server_c teilen den Namen, sind aber getrennte
        # Dateien/Server -> ignoriert.
        (tmp_path / "server_a").mkdir()
        (tmp_path / "server_a" / "srv.py").write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def echo(a): return a\n"
            "@mcp.tool()\n"
            "def echo(a): return a\n",
            encoding="utf-8",
        )
        _write(tmp_path / "server_b" / "srv.py", "echo")
        _write(tmp_path / "server_c" / "srv.py", "echo")
        exact = [f for f in _run(tmp_path) if f.severity == Severity.MEDIUM]
        assert len(exact) == 1
        assert "server_a" in (exact[0].snippet or "") + exact[0].description
