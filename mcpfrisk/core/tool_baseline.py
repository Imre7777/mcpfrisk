"""Tool-Beschreibungs-Baseline für die Rug-Pull-/Drift-Erkennung (Feature 015).

Ein Rug-Pull-Angriff ändert eine Tool-Beschreibung STILL, nachdem sie einmal
freigegeben/reviewt wurde (CVE-2025-54136). Die MCP-Spec kennt kein Pinning und
keine Notification bei Änderung -- die praktische Abwehr ist, die reviewten
Beschreibungen als Baseline ins Repo zu pinnen und jede spätere Abweichung in CI
zu flaggen (wie eine Snapshot-/Lockfile).

Dieses Modul ist check-agnostisch (kein `BaseCheck`): es liefert Snapshot,
Load/Write und Diff -- genutzt vom `TOOL_DESCRIPTION_DRIFT`-Check UND vom
CLI-`--write-tools-baseline`-Flag (eine Quelle der Wahrheit für den Pfad).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.sourcetree import analyze

BASELINE_FILENAME = ".mcpfrisk-tools.json"


def baseline_path(target_path: Path) -> Path:
    """Der konventionelle Baseline-Pfad zum Scan-Ziel: bei einem Verzeichnis
    darin, bei einer Einzeldatei daneben."""
    base = target_path.parent if target_path.is_file() else target_path
    return base / BASELINE_FILENAME


def _normalize(text: str) -> str:
    """Whitespace-normalisiert, damit reine Reformatierung keine Drift ist."""
    return " ".join(text.split())


def hash_description(description: str) -> str:
    """Stabiler, whitespace-normalisierter Hash einer Tool-Beschreibung.
    Öffentlich, damit der Check dieselbe Normalisierung wie der Snapshot nutzt
    (eine Quelle der Wahrheit -- kein Drift zwischen Pin und Prüfung)."""
    return hashlib.sha256(_normalize(description).encode("utf-8")).hexdigest()[:16]


def snapshot(target_path: Path) -> dict[str, str]:
    """Bildet je Tool-Name den Hash seiner (normalisierten) Beschreibung über
    alle Quelldateien (Python + JS/TS) via `tool_definitions()`."""
    out: dict[str, str] = {}
    for file_path in iter_source_files(target_path):
        model = analyze(file_path)
        if model is None or not model.ok:
            continue
        for tool in model.tool_definitions():
            if isinstance(tool.name, str) and tool.name:
                out[tool.name] = hash_description(tool.description or "")
    return out


def load(path: Path) -> dict[str, str]:
    """Lädt die gepinnte Tool-Hash-Map. Fehlt die Datei oder ist sie nicht
    parsebar, wird das wie eine leere/nicht-vorhandene Baseline behandelt
    (kein Crash) -- der aufrufende Check wertet das als 'kein Pin'."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    tools = data.get("tools") if isinstance(data, dict) else None
    return {k: v for k, v in tools.items() if isinstance(k, str) and isinstance(v, str)} \
        if isinstance(tools, dict) else {}


def write(path: Path, snap: dict[str, str]) -> None:
    """Schreibt einen Tool-Snapshot als Baseline (zum Review-Commit)."""
    data = {"version": 1, "tools": dict(sorted(snap.items()))}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def diff(baseline: dict[str, str], current: dict[str, str]) -> tuple[list[str], list[str]]:
    """Liefert (changed, new): Tools mit abweichendem Hash und Tools, die im
    aktuellen Stand, aber nicht in der Baseline sind. Entfernte Tools werden
    bewusst nicht gemeldet (kein Rug-Pull)."""
    changed = sorted(
        name for name, h in current.items()
        if name in baseline and baseline[name] != h
    )
    new = sorted(name for name in current if name not in baseline)
    return changed, new
