"""SARIF-2.1.0-Export für ScanResult (GitHub Code Scanning).

Reine Serialisierung, keine neue Erkennungslogik (siehe
specs/010-ci-integration/spec.md). Deckt bewusst nur ab, was GitHub Code
Scanning tatsächlich braucht -- kein Vollständigkeitsanspruch gegen die volle
SARIF-Spezifikation. Bewusst nur für `scan` (Tier 1) gedacht: SARIF ist auf
Datei+Zeile im Repo ausgelegt, die Tier-2-Findings (dynamische Checks) fehlen
strukturell -- der Writer bleibt trotzdem defensiv gegenüber Findings ohne
Datei/Zeile, statt zu crashen (Prinzip III).
"""
from __future__ import annotations

import json
from pathlib import Path

from mcpfrisk.core.models import Finding, ScanResult, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
_TOOL_NAME = "mcpfrisk"
_TOOL_URI = "https://github.com/Imre7777/mcpfrisk"
_TOOL_VERSION = "0.1.0"

# SARIF kennt nur error/warning/note/none -- CRITICAL und HIGH teilen sich
# "error" (beide sind für ein CI-Gate gleich dringend), MEDIUM wird "warning",
# LOW/INFO werden "note" (sichtbar, aber nicht alarmierend).
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _relative_uri(file_path: Path | None, target_path: Path | None) -> str | None:
    if file_path is None:
        return None
    if target_path is None:
        return file_path.as_posix()
    try:
        return file_path.resolve().relative_to(target_path.resolve()).as_posix()
    except (ValueError, OSError):
        return file_path.as_posix()


def _rule(check_id: str, sample: Finding) -> dict:
    return {
        "id": check_id,
        "shortDescription": {"text": sample.title},
        "helpUri": (sample.references[0] if sample.references else _TOOL_URI),
        "properties": {"tags": ["security"], **({"cwe": sample.cwe_ref} if sample.cwe_ref else {})},
    }


def _result(finding: Finding, target_path: Path | None) -> dict:
    entry: dict = {
        "ruleId": finding.check_id,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.description},
    }
    uri = _relative_uri(finding.file_path, target_path)
    if uri is not None:
        location: dict = {"artifactLocation": {"uri": uri}}
        if finding.line_number is not None:
            location["region"] = {"startLine": finding.line_number}
        entry["locations"] = [{"physicalLocation": location}]
    return entry


def _build_sarif(result: ScanResult) -> dict:
    findings = result.sorted_findings()
    rules: dict[str, dict] = {}
    for f in findings:
        rules.setdefault(f.check_id, _rule(f.check_id, f))

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "version": _TOOL_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f, result.target_path) for f in findings],
            }
        ],
    }


def write_sarif_report(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(json.dumps(_build_sarif(result), indent=2, ensure_ascii=False), encoding="utf-8")
