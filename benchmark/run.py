"""Benchmark-Orchestrator: läuft McpFrisk (und, falls installiert, Wettbewerber)
über das gelabelte Korpus und erzeugt einen reproduzierbaren Report.

Aufruf:  python -m benchmark.run           (aus dem Repo-Root)
     bzw. python benchmark/run.py

Schreibt benchmark/RESULTS.md + benchmark/results.json und gibt den Report auf
stdout aus. Methodik + Ehrlichkeits-Hinweise: siehe benchmark/README.md.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))  # Repo-Root importierbar machen

from benchmark import metrics as M  # noqa: E402
from benchmark.scanners import ALL_SCANNERS  # noqa: E402

CORPUS = HERE / "corpus"


def _jsts_available() -> bool:
    try:
        from mcpfrisk.core.sourcetree import jsts_available
        return jsts_available()
    except Exception:
        return False


def _git(*args: str) -> str:
    try:
        out = subprocess.run(
            ["git", *args], cwd=str(HERE.parent), capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _mcpfrisk_version() -> str:
    try:
        from importlib.metadata import version
        return version("mcpfrisk")
    except Exception:
        return "unknown"


def provenance() -> dict:
    """Herkunftsdaten, damit ein Ergebnis JEDERZEIT auf seinen exakten Code-Stand
    zurückführbar ist: Git-Commit + ob der Working-Tree beim Lauf sauber war
    (sonst ist der Commit-Hash keine vollständige Reproduktions-Referenz),
    Zeitpunkt, McpFrisk-Version und Umgebung."""
    # Die generierten Report-Artefakte selbst vom Clean-Check ausnehmen -- sonst
    # meldete jeder Lauf "dirty", nur weil er RESULTS.md/results.json neu schreibt.
    # Der Flag soll den CODE-/Korpus-Stand widerspiegeln.
    dirty = bool(_git(
        "status", "--porcelain", "--", ".",
        ":(exclude)benchmark/RESULTS.md", ":(exclude)benchmark/results.json",
    ))
    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git("rev-parse", "HEAD") or "unknown",
        "git_commit_short": _git("rev-parse", "--short", "HEAD") or "unknown",
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        "git_working_tree_clean": not dirty,
        "mcpfrisk_version": _mcpfrisk_version(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "jsts_available": _jsts_available(),
    }


def load_corpus() -> list[dict]:
    samples: list[dict] = []
    for d in sorted(CORPUS.iterdir()):
        if not d.is_dir():
            continue
        meta = json.loads((d / "expected.json").read_text(encoding="utf-8"))
        samples.append({
            "name": d.name,
            "dir": d,
            "description": meta.get("description", ""),
            "expected": {e["check_id"] for e in meta.get("expected", [])},
            "requires_jsts": bool(meta.get("requires_jsts", False)),
            "is_vuln": bool(meta.get("expected")),
        })
    return samples


def _fmt(x: float) -> str:
    return f"{x * 100:4.0f}%"


def _bar(m: M.Metrics) -> str:
    return f"{_fmt(m.precision)} / {_fmt(m.recall)} / {m.f1:.2f}"


def run() -> dict:
    samples = load_corpus()
    jsts = _jsts_available()

    # --- McpFrisk: per-check + per-sample --------------------------------
    mcpfrisk = next(s for s in ALL_SCANNERS if s.name == "McpFrisk")
    evals: list[M.SampleEval] = []
    per_sample_rows: list[dict] = []

    for s in samples:
        skipped = s["requires_jsts"] and not jsts
        out = None if skipped else mcpfrisk.scan(s["dir"])
        found = set(out.findings) if out else set()
        if not skipped:
            evals.append(M.SampleEval.build(s["name"], s["expected"], found))
        per_sample_rows.append({
            "sample": s["name"],
            "kind": "vuln" if s["is_vuln"] else "clean",
            "expected": sorted(s["expected"]),
            "mcpfrisk_found": sorted(found),
            "mcpfrisk_skipped": skipped,
        })

    overall = M.aggregate(evals)
    per_check = M.per_check(evals)

    # --- Cross-Tool: Sample-Detection (tool-agnostisch) ------------------
    tool_summaries: dict[str, dict] = {}
    for scanner in ALL_SCANNERS:
        if not scanner.available():
            tool_summaries[scanner.name] = {"available": False}
            continue
        vuln_hit = vuln_total = clean_ok = clean_total = 0
        errors = 0
        for s in samples:
            if scanner.name == "McpFrisk" and s["requires_jsts"] and not jsts:
                continue
            out = scanner.scan(s["dir"])
            if not out.ok:
                errors += 1
                continue
            if s["is_vuln"]:
                vuln_total += 1
                vuln_hit += int(out.flagged)
            else:
                clean_total += 1
                clean_ok += int(not out.flagged)
        tool_summaries[scanner.name] = {
            "available": True,
            "vuln_detected": vuln_hit, "vuln_total": vuln_total,
            "clean_passed": clean_ok, "clean_total": clean_total,
            "errors": errors,
        }

    return {
        "provenance": provenance(),
        "scanners_available": {sc.name: sc.available() for sc in ALL_SCANNERS},
        "jsts_available": jsts,
        "overall": {"tp": overall.tp, "fp": overall.fp, "fn": overall.fn,
                    "precision": overall.precision, "recall": overall.recall, "f1": overall.f1},
        "per_check": {cid: {"tp": m.tp, "fp": m.fp, "fn": m.fn,
                            "precision": m.precision, "recall": m.recall, "f1": m.f1}
                      for cid, m in sorted(per_check.items())},
        "per_sample": per_sample_rows,
        "cross_tool": tool_summaries,
        "per_check_obj": per_check,
        "overall_obj": overall,
    }


class ScanRow:  # (Reserviert für spätere Erweiterung; hält run() typstabil.)
    pass


def to_markdown(res: dict) -> str:
    lines: list[str] = []
    lines.append("# McpFrisk Benchmark — Results\n")
    lines.append(
        "> Auto-generated by `benchmark/run.py`. Methodology & honesty caveats: "
        "[`README.md`](./README.md). Metrics are **precision / recall / F1** on a "
        "labeled corpus of MCP-server samples (one planted issue per vuln sample).\n"
    )

    # Provenienz: macht dieses Ergebnis JEDERZEIT auf seinen Ursprung
    # zurückführbar (welcher Commit, sauberer Tree?, wann, welche Umgebung).
    p = res["provenance"]
    clean = "clean" if p["git_working_tree_clean"] else "DIRTY (uncommitted changes at run time)"
    lines.append("## Provenance\n")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Generated (UTC) | {p['generated_at_utc']} |")
    lines.append(f"| Git commit | `{p['git_commit_short']}` ({p['git_branch']}) |")
    lines.append(f"| Working tree | {clean} |")
    lines.append(f"| McpFrisk version | {p['mcpfrisk_version']} |")
    lines.append(f"| Python | {p['python_version']} · {p['platform']} |")
    lines.append(f"| `jsts` extra | {'available' if p['jsts_available'] else 'not installed'} |")
    avail = ", ".join(n for n, a in res["scanners_available"].items() if a) or "—"
    lines.append(f"| Scanners available | {avail} |")
    lines.append(
        "\n> Reproduce: check out the commit above (with a clean tree), "
        "`pip install -e \".[dev,jsts]\"`, then `python -m benchmark.run`.\n"
    )
    if not res["jsts_available"]:
        lines.append("> ⚠️ `jsts` extra not installed — JS/TS samples were skipped for McpFrisk.\n")

    o = res["overall_obj"]
    lines.append("## McpFrisk — overall (per check_id, across all samples)\n")
    lines.append(f"- **Precision:** {_fmt(o.precision)}  •  **Recall:** {_fmt(o.recall)}  •  **F1:** {o.f1:.2f}")
    lines.append(f"- TP {o.tp} · FP {o.fp} · FN {o.fn}\n")

    lines.append("## McpFrisk — per check\n")
    lines.append("| Check | Precision | Recall | F1 | TP | FP | FN |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for cid, m in sorted(res["per_check_obj"].items()):
        lines.append(f"| `{cid}` | {_fmt(m.precision)} | {_fmt(m.recall)} | {m.f1:.2f} | {m.tp} | {m.fp} | {m.fn} |")
    lines.append("")

    lines.append("## Cross-tool — sample detection (tool-agnostic)\n")
    lines.append(
        "Fair comparison: did the tool flag **any** issue on a vulnerable sample "
        "(detection) and stay **silent** on a clean sample (no false alarm)?\n"
    )
    lines.append("| Tool | Vuln detected | Clean passed | Status |")
    lines.append("|---|---:|---:|---|")
    for name, summ in res["cross_tool"].items():
        if not summ.get("available"):
            lines.append(f"| {name} | — | — | not installed (skipped) |")
            continue
        vd = f"{summ['vuln_detected']}/{summ['vuln_total']}"
        cp = f"{summ['clean_passed']}/{summ['clean_total']}"
        status = "ok" if summ.get("errors", 0) == 0 else f"{summ['errors']} scan error(s)"
        lines.append(f"| {name} | {vd} | {cp} | {status} |")
    lines.append("")

    lines.append("## Per-sample detail (McpFrisk)\n")
    lines.append("| Sample | Kind | Expected | McpFrisk found |")
    lines.append("|---|---|---|---|")
    for r in res["per_sample"]:
        exp = ", ".join(r["expected"]) or "—"
        found = ("_skipped (jsts)_" if r["mcpfrisk_skipped"]
                 else (", ".join(r["mcpfrisk_found"]) or "—"))
        lines.append(f"| `{r['sample']}` | {r['kind']} | {exp} | {found} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    res = run()
    md = to_markdown(res)
    (HERE / "RESULTS.md").write_text(md, encoding="utf-8")
    json_out = {k: v for k, v in res.items() if k not in ("per_check_obj", "overall_obj")}
    (HERE / "results.json").write_text(json.dumps(json_out, indent=2) + "\n", encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
