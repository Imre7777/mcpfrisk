# Feature Specification: UTF-8 JSON-Reports

**Feature Branch**: `027-utf8-json-report`

**Created**: 2026-07-15

**Status**: Fertig. Kleiner Korrektheits-/Portabilitäts-Fix, entdeckt bei der
Real-World-Analyse zu Feature 026 (Byte 0xfc im JSON-Report = 'ü' in cp1252).

## Kontext / Motivation

`write_json_report` und `write_dynamic_json_report` (`core/report.py`) schrieben
via `output_path.write_text(json.dumps(..., ensure_ascii=False))` — **ohne**
`encoding="utf-8"`. `write_text` nimmt dann die Plattform-Default-Kodierung; auf
**Windows** ist das cp1252. Mit `ensure_ascii=False` bleiben nicht-ASCII-Zeichen
(die deutschen Finding-Texte: ü/ä/ö) echte Zeichen und werden als **cp1252-Bytes**
geschrieben — der Report ist dann **kein gültiges UTF-8**. Jeder Standard-JSON-
Consumer (der UTF-8 erwartet) verschluckt sich daran bzw. dekodiert falsch.

Gegenprobe: SARIF (`core/sarif.py`), Baseline (`core/baseline.py`) und
Tool-Baseline schrieben bereits korrekt mit `encoding="utf-8"` — nur die beiden
JSON-Report-Writer waren betroffen.

## Fix
`encoding="utf-8"` an beide `write_text`-Aufrufe (Zeilen 128 + 141).

## Akzeptanz
- Regressionstest: ein Report mit nicht-ASCII-Finding-Text ist als UTF-8 lesbar
  und roundtrippt; die Bytes enthalten `0xC3 0xBC` (UTF-8 'ü'), nicht das
  cp1252-Einzelbyte `0xFC`. (Vor dem Fix auf Windows rot.)
- Volle Suite grün, ruff clean.
