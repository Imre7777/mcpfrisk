"""Feature 030: Performance-Regressionstest (Budget gegen katastrophale Regression).

Auf einem großen Monorepo (python-sdk, 815 Dateien) lief der Scan früher >90s in
einen Timeout -- v.a. PATH_TRAVERSAL/CMD_INJECTION mit ihrer Cross-Function-
Analyse. Nach den Excludes (022) und dem Datei-Scoping (026) ist das entschärft;
dieser Test verhindert einen Rückfall.

BEWUSST großzügig und NICHT flaky (ROADMAP 3.4): es ist KEIN Mikro-Benchmark. Das
Budget hat ~8x Puffer über der lokalen Messung (300 realistische Server-Dateien
in ~5s) und trippt nur bei einer *katastrophalen* Regression -- Hang, O(n^2) über
die Dateien, oder ein vielfacher Per-Datei-Blowup.
"""
from __future__ import annotations

import time

from mcpfrisk.core.runner import run_static_scan

# Ein moderat realistischer Server: eigene Instanz, Helfer, Cross-Function-Fluss
# (open + subprocess mit shell=True + urlopen) -- damit die AST-/Taint-schweren
# Checks tatsächlich Arbeit leisten, nicht nur leere Dateien zählen.
_TEMPLATE = """from fastmcp import FastMCP
import subprocess, os, urllib.request
mcp = FastMCP('srv{i}')

def _helper_{i}(x):
    return os.path.join('/data', x)

@mcp.tool()
def run_cmd_{i}(name: str):
    p = _helper_{i}(name)
    with open(p) as f:
        d = f.read()
    return subprocess.run('ls ' + name, shell=True)

@mcp.tool()
def fetch_{i}(url: str):
    return urllib.request.urlopen(url).read()
"""

_N_FILES = 300
_BUDGET_SECONDS = 40.0  # lokal ~5s -> ~8x Puffer; nur Katastrophen trippen das.


def test_large_tree_scans_within_budget(tmp_path):
    for i in range(_N_FILES):
        (tmp_path / f"s{i}.py").write_text(_TEMPLATE.format(i=i), encoding="utf-8")

    start = time.perf_counter()
    result = run_static_scan(tmp_path)
    elapsed = time.perf_counter() - start

    # Die Checks müssen tatsächlich gelaufen sein (sonst wäre "schnell" wertlos):
    # der shell=True-String-Concat erzeugt CMD_INJECTION-Findings.
    assert result.findings, "Erwartete Findings aus dem synthetischen Baum -- Scan lief evtl. leer?"
    assert elapsed < _BUDGET_SECONDS, (
        f"Scan von {_N_FILES} Dateien dauerte {elapsed:.1f}s "
        f"(Budget {_BUDGET_SECONDS:.0f}s) -- mögliche Performance-Regression."
    )
