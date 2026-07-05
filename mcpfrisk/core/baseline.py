"""Baseline-/Diff-Scanning: vergleicht Findings gegen eine gespeicherte
Baseline, damit ein CI-Gate nur NEUE Findings blockierend behandelt.

Hintergrund (siehe specs/010-ci-integration/spec.md): ein CI-Gate, das bei
jedem Lauf ALLE historischen Findings erneut zeigt, ist für Teams mit
bestehendem Code in der Praxis unbrauchbar -- das ist der Punkt, an dem ein
Scanner ignoriert oder deaktiviert wird. Die Baseline-Datei wird typischerweise
ins Repo eingecheckt (wie eine Allowlist), nicht extern verwaltet.

Der Fingerprint ist bewusst grob genug, um über kosmetische Änderungen (Snippet-
Formatierung) hinweg stabil zu bleiben, aber fein genug, um verschiedene
Findings zu unterscheiden -- und nutzt einen relativen statt absoluten Pfad,
damit eine Baseline über Maschinen/CI-Runner hinweg portabel bleibt (Prinzip:
kein Fingerprint darf nur auf der Maschine gültig sein, auf der er erzeugt wurde).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcpfrisk.core.models import Finding


def _relative_path(file_path: Path | None, target_path: Path | None) -> str:
    if file_path is None:
        return ""
    if target_path is None:
        return str(file_path)
    try:
        return str(file_path.resolve().relative_to(target_path.resolve()))
    except (ValueError, OSError):
        return str(file_path)


def fingerprint(finding: Finding, target_path: Path | None = None) -> str:
    """Stabiler Fingerabdruck eines Findings für Baseline-Vergleiche.

    check_id + Datei (relativ zum Scan-Ziel) + Zeile + Titel identifizieren
    praktisch immer denselben Befund. Der exakte Snippet-Text fließt bewusst
    NICHT ein -- kleine Formatierungsänderungen dürfen den Fingerprint nicht
    kippen."""
    parts = [
        finding.check_id,
        _relative_path(finding.file_path, target_path),
        str(finding.line_number) if finding.line_number is not None else "",
        finding.title,
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def load_baseline(path: Path) -> set[str]:
    """Lädt die Fingerprint-Menge einer Baseline-Datei.

    Fehlt die Datei oder ist sie nicht parsebar, wird das wie eine leere
    Baseline behandelt (alle Findings gelten dann als neu) -- niemals ein
    Fehler/Crash (Prinzip III)."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return set()
    fps = data.get("fingerprints") if isinstance(data, dict) else None
    return set(fps) if isinstance(fps, list) else set()


def write_baseline(
    path: Path, findings: list[Finding], target_path: Path | None = None
) -> None:
    """Schreibt die Fingerprints der aktuellen Findings als neue Baseline."""
    fps = sorted({fingerprint(f, target_path) for f in findings})
    data = {"version": 1, "fingerprints": fps}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def split_new_vs_known(
    findings: list[Finding], baseline: set[str], target_path: Path | None = None
) -> tuple[list[Finding], list[Finding]]:
    """Teilt Findings in (neu, bereits in der Baseline bekannt) auf.

    Nur "neu" darf gegen `--fail-on` blockieren; "bekannt" bleibt sichtbar,
    verschwindet aber nie kommentarlos (Prinzip III)."""
    new: list[Finding] = []
    known: list[Finding] = []
    for f in findings:
        if fingerprint(f, target_path) in baseline:
            known.append(f)
        else:
            new.append(f)
    return new, known
