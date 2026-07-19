"""Reproduzierbarer Real-World-Korpus: scannt echte, populäre MCP-Server bei
FEST GEPINNTEN Commit-SHAs und misst das Finding-Rauschen auf produktivem Code.

Zweck (ehrlich abgegrenzt): Das gelabelte Korpus (`benchmark/corpus/`) misst
Precision/Recall gegen bekannte Ground-Truth. DIESER Korpus ergänzt das um die
Frage „wie viel Rauschen erzeugt McpFrisk auf echten, seriösen Servern?" -- ein
Präzisions-/Praxissignal, KEIN gelabelter Recall-Test (die wahren Schwachstellen
dieser Repos sind nicht annotiert).

Reproduzierbarkeit: jeder Eintrag ist auf einen konkreten Commit-SHA gepinnt und
wird per Shallow-Fetch geholt. Gescannt wird der *ausgelieferte Servercode* --
Test-/Beispiel-/Doku-Bäume werden über `--exclude` ausgenommen (so würde ein
Nutzer sein Repo real prüfen; die Ausschlüsse stehen transparent unten).

Aufruf:
    python -m benchmark.realworld_corpus                 # ganzer Manifest
    python -m benchmark.realworld_corpus --only context7,tavily-mcp
    python -m benchmark.realworld_corpus --timeout 180 --keep

Schreibt benchmark/REALWORLD.md + benchmark/realworld.json (mit Provenance).
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))

# SHAs aufgelöst via `git ls-remote <url> HEAD` am 2026-07-15. Zum Aktualisieren
# neu auflösen und den Commit im Manifest ersetzen (der Korpus bleibt dadurch
# jederzeit exakt reproduzierbar).
MANIFEST: list[dict[str, str]] = [
    {"name": "context7", "lang": "ts", "sha": "23843e9ce62908896cf2dcd32cc5c03c05047416",
     "url": "https://github.com/upstash/context7"},
    {"name": "mcp-atlassian", "lang": "py", "sha": "b60c564ce4c8b88edc78a7c34d2e9693ea893e16",
     "url": "https://github.com/sooperset/mcp-atlassian"},
    {"name": "firecrawl-mcp", "lang": "ts", "sha": "3eb1115b1f2883ff2fb74e61b5c4acf5a9ac0fb0",
     "url": "https://github.com/mendableai/firecrawl-mcp-server"},
    {"name": "tavily-mcp", "lang": "ts", "sha": "259bfd205de90d74a131e9d2b29cb69ebe11feb7",
     "url": "https://github.com/tavily-ai/tavily-mcp"},
    {"name": "qdrant-mcp", "lang": "py", "sha": "f1a4d04e4f91c4d3e2b7c63d5283f3f4338fd2e5",
     "url": "https://github.com/qdrant/mcp-server-qdrant"},
    {"name": "chroma-mcp", "lang": "py", "sha": "98ff67589bdcc31b730a5415ff9529433f949077",
     "url": "https://github.com/chroma-core/chroma-mcp"},
    {"name": "playwright-mcp", "lang": "ts", "sha": "55679f5f3d4b4f3e2534ec0ce2fc5683ba2eaf3f",
     "url": "https://github.com/microsoft/playwright-mcp"},
    {"name": "mcp-playwright", "lang": "ts", "sha": "2349c2891e7c499c8c07b7d78c7f3fb4c797a1da",
     "url": "https://github.com/executeautomation/mcp-playwright"},
    {"name": "figma-mcp", "lang": "ts", "sha": "c083d65c7e002923e7cb98f4e3bdafb105e90f6d",
     "url": "https://github.com/GLips/Figma-Context-MCP"},
    {"name": "elastic-mcp", "lang": "ts", "sha": "9e64b842f22269eb214793e1a4885128dc4a8fd8",
     "url": "https://github.com/elastic/mcp-server-elasticsearch"},
    {"name": "llamacloud-mcp", "lang": "py", "sha": "ebc66ba1c0b772cc3eced4db170c3e7eb9679f1e",
     "url": "https://github.com/run-llama/llamacloud-mcp"},
    {"name": "python-sdk", "lang": "py", "sha": "3a6f2996cdd8358957479791e8b26198c07d6a75",
     "url": "https://github.com/modelcontextprotocol/python-sdk"},
    {"name": "typescript-sdk", "lang": "ts", "sha": "f60dff0674954ab516739f21ad9905349c8e9249",
     "url": "https://github.com/modelcontextprotocol/typescript-sdk"},
    {"name": "servers", "lang": "mixed", "sha": "d31124c982401739917fd817c2a59db344529c16",
     "url": "https://github.com/modelcontextprotocol/servers"},
]

# Test-/Beispiel-/Doku-Bäume: nicht der ausgelieferte Servercode. Ausgeschlossen,
# damit das Signal die PRODUKTIONS-Präzision misst (Nutzer scannt sein Server-
# Paket, nicht seine Test-Suite). Transparent im Report vermerkt.
EXCLUDES = (
    "tests", "test", "__tests__", "e2e", "examples", "example",
    "docs", "docs_src", "sample", "samples", "fixtures",
)


def _git(cwd: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout
    )


def clone_pinned(entry: dict, dest: Path, timeout: int) -> bool:
    """Holt genau den gepinnten Commit per Shallow-Fetch (kein voller History-Clone)."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        _git(dest, "init", "-q", timeout=30)
        _git(dest, "remote", "add", "origin", entry["url"], timeout=30)
        fetched = _git(dest, "fetch", "--depth", "1", "origin", entry["sha"], timeout=timeout)
        if fetched.returncode != 0:
            return False
        return _git(dest, "checkout", "-q", "FETCH_HEAD", timeout=60).returncode == 0
    except subprocess.SubprocessError:
        return False


def scan_repo(path: Path, timeout: int) -> dict:
    """Scannt via `python -m mcpfrisk scan --json` (nutzt den Modul-Entrypoint).
    Liefert Status + Findings-Zähler pro check_id."""
    out = path / "__mcpfrisk_report.json"
    cmd = [sys.executable, "-m", "mcpfrisk", "scan", "--json", str(out), str(path)]
    for pat in EXCLUDES:
        cmd += ["--exclude", pat]
    try:
        # stdout/stderr verwerfen: wir werten NUR die JSON-Datei aus. (text=True
        # würde auf Windows cp1252-Dekodierfehler an McpFrisks UTF-8-Report werfen.)
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "total": None, "by_check": {}}
    except OSError as exc:
        return {"status": f"error:{exc}", "total": None, "by_check": {}}
    if not out.exists():
        return {"status": "no-output", "total": 0, "by_check": {}}
    data = json.loads(out.read_text(encoding="utf-8", errors="replace"))
    findings = data.get("findings", [])
    by_check = Counter(f.get("check_id", "?") for f in findings)
    return {"status": "ok", "total": len(findings), "by_check": dict(by_check)}


def _mcpfrisk_version() -> str:
    try:
        from importlib.metadata import version
        return version("mcpfrisk")
    except Exception:
        return "unknown"


def provenance() -> dict:
    def g(*a: str) -> str:
        try:
            r = _git(REPO_ROOT, *a, timeout=15)
            return r.stdout.strip() if r.returncode == 0 else "unknown"
        except subprocess.SubprocessError:
            return "unknown"
    # Nur Quellcode-Änderungen zählen als "dirty" (Report-Artefakte ignorieren).
    dirty = bool(g("status", "--porcelain", "--", "mcpfrisk", "benchmark/realworld_corpus.py"))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": g("rev-parse", "HEAD"),
        "git_commit_short": g("rev-parse", "--short", "HEAD"),
        "git_working_tree_clean_relevant": not dirty,
        "mcpfrisk_version": _mcpfrisk_version(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "excludes": list(EXCLUDES),
    }


def run(only: set[str] | None, workdir: Path, timeout: int, keep: bool) -> dict:
    entries = [e for e in MANIFEST if only is None or e["name"] in only]
    results: list[dict] = []
    for e in entries:
        dest = workdir / e["name"]
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        print(f"[{e['name']}] clone @ {e['sha'][:10]} ...", flush=True)
        if not clone_pinned(e, dest, timeout):
            results.append({**_meta(e), "status": "clone-failed", "total": None, "by_check": {}})
            continue
        print(f"[{e['name']}] scan ...", flush=True)
        scan = scan_repo(dest, timeout)
        results.append({**_meta(e), **scan})
        print(f"[{e['name']}] {scan['status']}: total={scan['total']} {scan['by_check']}", flush=True)
        if not keep:
            shutil.rmtree(dest, ignore_errors=True)
    return {"provenance": provenance(), "results": results}


def _meta(e: dict) -> dict:
    return {"name": e["name"], "lang": e["lang"], "url": e["url"], "sha": e["sha"]}


def write_reports(report: dict) -> None:
    (HERE / "realworld.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    prov = report["provenance"]
    rows = report["results"]
    scanned = [r for r in rows if r["status"] == "ok"]
    agg: Counter = Counter()
    for r in scanned:
        agg.update(r["by_check"])
    lines = [
        "# Real-World-Korpus -- Finding-Rauschen auf echten MCP-Servern",
        "",
        "> Reproduzierbar via `python -m benchmark.realworld_corpus`. Jeder Server",
        "> ist auf einen Commit-SHA gepinnt. Gescannt wird der ausgelieferte",
        f"> Servercode; ausgeschlossen: `{', '.join(prov['excludes'])}`.",
        "",
        "**Abgrenzung (ehrlich):** Dies misst *Präzision/Rauschen auf echtem Code*,",
        "NICHT gelabelten Recall -- die wahren Schwachstellen dieser Repos sind nicht",
        "annotiert. Der gelabelte Recall/Precision-Test steht in `RESULTS.md`.",
        "",
        "## Provenance",
        f"- generated_at: `{prov['generated_at']}`",
        f"- mcpfrisk: `{prov['git_commit_short']}` (version `{prov['mcpfrisk_version']}`)",
        f"- working tree clean (relevant): `{prov['git_working_tree_clean_relevant']}`",
        f"- python `{prov['python']}` -- {prov['platform']}",
        "",
        "## Ergebnisse pro Server",
        "",
        "| Server | Lang | Commit | Status | Findings gesamt | Top-Checks |",
        "|---|---|---|---|---:|---|",
    ]
    for r in rows:
        top = ", ".join(f"{k}:{v}" for k, v in sorted(r["by_check"].items(), key=lambda x: -x[1])[:4])
        total = "-" if r["total"] is None else str(r["total"])
        lines.append(
            f"| {r['name']} | {r['lang']} | `{r['sha'][:10]}` | {r['status']} | {total} | {top or '-'} |"
        )
    lines += [
        "",
        f"## Aggregat über {len(scanned)} erfolgreich gescannte Server",
        "",
        "| Check | Findings |",
        "|---|---:|",
    ]
    for k, v in sorted(agg.items(), key=lambda x: -x[1]):
        lines.append(f"| {k} | {v} |")
    lines.append("")
    (HERE / "REALWORLD.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Real-World-MCP-Server-Korpus (gepinnt).")
    p.add_argument("--only", type=str, default=None, help="Kommagetrennte Server-Namen.")
    p.add_argument("--timeout", type=int, default=240, help="Sekunden pro Clone/Scan.")
    p.add_argument("--workdir", type=Path, default=None, help="Arbeitsverzeichnis (Default: temp).")
    p.add_argument("--keep", action="store_true", help="Geklonte Repos behalten (nicht löschen).")
    args = p.parse_args(argv)
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="mcpfrisk-realworld-"))
    workdir.mkdir(parents=True, exist_ok=True)
    report = run(only, workdir, args.timeout, args.keep)
    write_reports(report)
    print(f"\nGeschrieben: {HERE / 'REALWORLD.md'} + realworld.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
