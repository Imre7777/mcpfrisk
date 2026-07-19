"""Feature 027: JSON-Reports müssen UTF-8 sein.

`write_json_report` nutzte `write_text(..., ensure_ascii=False)` OHNE
`encoding="utf-8"`. Auf Windows ist die Default-Kodierung cp1252 -- die
deutschen Finding-Texte (ü/ä/ö) landeten damit als cp1252-Bytes statt UTF-8, und
ein Standard-UTF-8-Consumer (jedes normale JSON-Tool) verschluckt sich daran.
Real aufgefallen bei der Real-World-Analyse (Byte 0xfc = 'ü' in cp1252).
Gegenprobe: SARIF/Baseline schrieben bereits korrekt mit encoding='utf-8'.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.core.models import Finding, ScanResult, Severity
from mcpfrisk.core.report import write_json_report


def _result(tmp_path: Path) -> ScanResult:
    r = ScanResult(target_path=tmp_path)
    r.add([
        Finding(
            check_id="CMD_INJECTION",
            severity=Severity.HIGH,
            title="Überschattung möglich",  # bewusst nicht-ASCII (ü)
            description="Prüfung ergab: Trennzeichen-Ähnlichkeit (ö, ä, ü).",
            file_path=tmp_path / "srv.py",
            line_number=1,
        )
    ])
    return r


def test_json_report_is_utf8_and_roundtrips(tmp_path):
    out = tmp_path / "report.json"
    write_json_report(_result(tmp_path), out)
    # MUSS als UTF-8 lesbar sein (der Bug: auf Windows war es cp1252).
    text = out.read_text(encoding="utf-8")
    data = json.loads(text)
    blob = json.dumps(data, ensure_ascii=False)
    assert "Überschattung" in blob
    assert "ö, ä, ü" in blob


def test_json_report_bytes_decode_as_utf8(tmp_path):
    out = tmp_path / "report.json"
    write_json_report(_result(tmp_path), out)
    raw = out.read_bytes()
    # 'ü' als UTF-8 ist 0xC3 0xBC; als cp1252 wäre es das Einzelbyte 0xFC.
    assert b"\xc3\xbc" in raw
    assert b"\xfc" not in raw
    # und der reine UTF-8-Decode darf nicht werfen
    raw.decode("utf-8")
