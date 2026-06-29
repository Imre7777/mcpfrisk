"""US2 (FP-Hardening): HARDCODED_SECRETS wird für Code-Dateien AST-gescoped.

Ein key-förmiges Token in einem Kommentar (häufig: "altes Secret rotieren,
war sk-ant-...") darf KEIN Finding auslösen -- es ist kein String-Literal im
ausgeführten Code. Die zeilenbasierte Heuristik konnte das nicht unterscheiden.
Für Nicht-Code-Dateien (JSON/ENV/YAML) bleibt der Zeilen-Scan als Fallback.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcpfrisk.checks.hardcoded_secrets import HardcodedSecretsCheck
from mcpfrisk.core.sourcetree import jsts_available

# Plausibles, aber fiktives Anthropic-Key-Format (>=20 Zeichen nach sk-ant-).
FAKE_KEY = "sk-ant-abcdef0123456789ABCDEFxyz"


def _run(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return HardcodedSecretsCheck().run(tmp_path)


def test_python_key_in_inline_comment_is_not_flagged(tmp_path):
    findings = _run(tmp_path, "x.py", f"x = 1  # TODO: altes Secret {FAKE_KEY} rotieren\n")
    assert findings == []


def test_python_real_assignment_is_still_flagged(tmp_path):
    findings = _run(tmp_path, "x.py", f'API_KEY = "{FAKE_KEY}"\n')
    assert len(findings) >= 1
    assert findings[0].severity.value == "critical"


def test_json_secret_still_detected_via_fallback(tmp_path):
    findings = _run(tmp_path, "config.json", f'{{"apiKey": "{FAKE_KEY}"}}\n')
    assert len(findings) >= 1


@pytest.mark.skipif(not jsts_available(), reason="jsts-Extra nicht installiert")
def test_ts_key_in_comment_is_not_flagged(tmp_path):
    findings = _run(tmp_path, "x.ts", f"const x = 1; // alter Key war {FAKE_KEY}\n")
    assert findings == []


@pytest.mark.skipif(not jsts_available(), reason="jsts-Extra nicht installiert")
def test_ts_real_assignment_is_still_flagged(tmp_path):
    findings = _run(tmp_path, "x.ts", f'const API_KEY = "{FAKE_KEY}";\n')
    assert len(findings) >= 1
