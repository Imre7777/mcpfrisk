# Implementation Plan: Collision-Scoping

**Feature**: 026-collision-scoping | **Constitution-Check**: bestanden
(Präzisions-Fix, Prinzip III; nur `tool_name_collision.py` berührt, Plugin-
Isolation gewahrt; Zero-Dep).

## Änderung in `checks/tool_name_collision.py`

`run()` gruppiert die gesammelten Occurrences nach `occ.file` (Datei-Scope, nach
Real-World-Verifikation gewählt — Verzeichnis war zu grob) und ruft
`_exact_findings` + `_near_duplicate_findings` **pro Datei-Gruppe** statt global:

```python
def run(self, target_path):
    occurrences = self._collect_occurrences(target_path)
    by_scope: dict[Path, list[_Occurrence]] = {}
    for occ in occurrences:
        by_scope.setdefault(occ.file, []).append(occ)
    findings = []
    for scope_occs in by_scope.values():   # Einfüge-Reihenfolge = sortierte Dateien
        if len(scope_occs) < 2:
            continue
        findings.extend(self._exact_findings(scope_occs))
        findings.extend(self._near_duplicate_findings(scope_occs))
    return findings
```

`_collect_occurrences`, `_exact_findings`, `_near_duplicate_findings` bleiben
unverändert (sie arbeiten schon auf einer Occurrence-Liste — jetzt eben pro
Scope). Determinismus: `iter_source_files` liefert sortierte Dateien →
`by_scope`-Einfügereihenfolge und Gruppeninhalte sind stabil.

Finding-Text (`_exact_finding`/`_near_finding`): den Hinweis von „nur DIESER
Server" auf „innerhalb desselben Verzeichnisses (Modul)" schärfen.

## Verifikation
- Neue rote Tests (getrennte Dateien → kein Finding; dieselbe Datei → weiterhin).
- Bestehende Suite bleibt grün (bestehende Collision-Tests nutzen Ein-Datei- bzw.
  Handler-Fixtures).
- Real-World-Gegencheck (SDK-Monorepos): python-sdk 53→cross-file 0 (Rest 25 sind
  same-file in `test_*.py` → Sache von `--exclude`); mcp-atlassian 6→cross-file 0
  (Rest 3 LOW-Near-Dups in echten Server-Dateien). Cross-file-FP-Flut = 0.
