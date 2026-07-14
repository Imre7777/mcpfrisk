"""HARDCODED_SECRETS: Findet eingebettete Credentials im Quellcode.

OWASP MCP01: Credentials, die nicht dorthin gehören -- hardcoded API-Keys
in Server-Konfigurationen, langlebige Tokens ohne Rotation, Secrets in
Tool-Beschreibungen oder Debug-Logs.

Bewusst simpel gehalten (Regex auf bekannte Key-Formate + Entropie-Check
für generische Strings), weil es dafür bereits exzellente dedizierte Tools
gibt (gitleaks, trufflehog, detect-secrets). Sentinel deckt hier nur die
offensichtlichsten Fälle ab und verweist bei Bedarf auf die spezialisierten
Tools -- kein Sinn, das Rad neu zu erfinden.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import SOURCE_GLOBS, is_excluded, rglob_or_file
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import SourceModel, analyze, jsts_available

# Nicht-Code-Dateien, die nur zeilenbasiert (nie AST-gescoped) geprüft werden.
_NON_CODE_GLOBS = ("*.json", "*.env", "*.yaml", "*.yml")

# Code-Dateien, die AST-gescoped statt zeilenbasiert geprüft werden (sofern der
# Parser verfügbar ist). Für alles andere (JSON/ENV/YAML, oder JS/TS ohne das
# jsts-Extra) bleibt der Zeilen-Scan als Fallback.
_AST_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}

# Bekannte Key-Formate mit hoher Präzision (wenig False Positives).
# Reihenfolge UND die "(?!ant-)"-Ausschlüsse in der OpenAI-Regex sind bewusst:
# "sk-ant-..." (Anthropic) matchte zuvor auch die generische OpenAI-Alternative
# "sk-<20+ Zeichen>", wodurch Anthropic-Keys fälschlich als "OpenAI API Key"
# gemeldet wurden (Regex-Reihenfolge-Bug). Anthropic wird jetzt zuerst geprüft
# UND die OpenAI-Regex schließt das "ant-"-Präfix explizit aus -- robust
# unabhängig von der Dict-Iterationsreihenfolge.
KNOWN_KEY_PATTERNS = {
    "Anthropic API Key": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
    "OpenAI API Key": re.compile(
        r"sk-(?!ant-)[a-zA-Z0-9_-]{2,}-[a-zA-Z0-9]{20,}|sk-(?!ant-)[a-zA-Z0-9]{20,}"
    ),
    # AKIA (langlebiger IAM-User-Key), ASIA (STS-Temporary-Credentials),
    # ABIA (AWS-STS-Service-Bearer-Token), ACCA (Context-spezifische Credentials).
    "AWS Access Key": re.compile(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}"),
    "GitHub Fine-Grained PAT": re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "Generic Bearer Token in Code": re.compile(
        r"(?i)(authorization|bearer)[\"'\s:=]+[a-zA-Z0-9_\-\.]{20,}"
    ),
    "Private Key Block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# Variablennamen, die auf Secrets hindeuten -- wenn hier ein Literal
# zugewiesen wird (statt os.environ.get(...)), ist das verdächtig.
SUSPICIOUS_VAR_NAMES = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|token|credential|access[_-]?key)\b"
)

# Offensichtliche Platzhalter / Test-Dummys: ein Treffer, dessen Wert so etwas
# enthält, ist KEIN echtes Secret (Test-Fixtures wie "not-a-valid-key",
# "Bearer expired-access-token", "your-token-here"). Ohne diesen Filter meldete
# der Check Test-Code als CRITICAL -- der peinlichste False-Positive-Typ
# (Real-World-Validierung 2026-07, z.B. modelcontextprotocol/typescript-sdk).
_PLACEHOLDER_RE = re.compile(
    r"(?i)(not[-_ ]?(a[-_ ]?)?(real|valid)|invalid|expired|example|sample|"
    r"dummy|fake|placeholder|redacted|change[-_ ]?me|your[-_ ]|"
    r"xxxx+|<[a-z0-9._-]+>|test[-_ ]?(token|key|secret|value|pem|cred|jwt)|"
    r"foo(bar)?|lorem|\bhere\b|\.\.\.)"
)


def _is_placeholder(text: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(text))
ENV_LOOKUP_HINTS = ("os.environ", "os.getenv", "process.env", "dotenv")


class HardcodedSecretsCheck(BaseCheck):
    check_id = "HARDCODED_SECRETS"
    name = "Hardcoded Secrets"
    description = (
        "Sucht nach API-Keys, Tokens und Credentials, die direkt im "
        "Quellcode statt in Umgebungsvariablen/Secret-Stores liegen."
    )

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        # SOURCE_GLOBS deckt auch .jsx/.mjs/.cjs/.mts/.cts/.tsx ab (Bug: diese
        # Erweiterungen wurden bisher NIE gescannt, weil eine eigene, engere
        # Liste statt der gemeinsamen fs.SOURCE_GLOBS verwendet wurde).
        extensions = SOURCE_GLOBS + _NON_CODE_GLOBS
        seen_files = set()

        for ext in extensions:
            for file_path in rglob_or_file(target_path, ext):
                if self._is_excluded(file_path, target_path) or file_path in seen_files:
                    continue
                seen_files.add(file_path)

                # Code-Dateien AST-gescoped prüfen (Secrets nur in echten
                # String-Literalen, nicht in Kommentaren) -- sonst Zeilen-Scan.
                suffix = file_path.suffix.lower()
                if suffix in _AST_SUFFIXES and (suffix == ".py" or jsts_available()):
                    model = analyze(file_path)
                    if model is not None and model.ok:
                        findings.extend(self._scan_model(model))
                        continue

                findings.extend(self._scan_file(file_path))

        return findings

    def _scan_model(self, model: SourceModel) -> list[Finding]:
        """AST-gescopter Scan: bekannte Key-Formate nur in String-Literalen,
        verdächtige Credential-Zuweisungen nur über echte Assignments."""
        findings: list[Finding] = []
        flagged_lines: set[int] = set()

        for literal in model.string_literals():
            if _is_placeholder(literal.value):
                continue  # Test-Dummy/Platzhalter -> kein echtes Secret
            for key_type, pattern in KNOWN_KEY_PATTERNS.items():
                if pattern.search(literal.value):
                    findings.append(
                        self._known_key_finding(
                            model.path, literal.line, literal.snippet, key_type
                        )
                    )
                    flagged_lines.add(literal.line)
                    break

        for assign in model.assignments():
            if assign.value is None or assign.value_is_env_lookup:
                continue
            if assign.line in flagged_lines:
                continue  # bereits als bekanntes Key-Format gemeldet
            if not SUSPICIOUS_VAR_NAMES.search(assign.target_name):
                continue
            if any(p.search(assign.value.value) for p in KNOWN_KEY_PATTERNS.values()):
                continue  # würde sonst doppelt zum String-Literal-Treffer zählen
            if self._looks_like_secret(assign.value.value):
                findings.append(
                    self._suspicious_assignment_finding(
                        model.path, assign.line, assign.value.snippet
                    )
                )
        return findings

    def _known_key_finding(
        self, file_path: Path, line: int, snippet: str, key_type: str
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.CRITICAL,
            title=f"Mögliches Secret im Code: {key_type}",
            description=(
                f"Ein String, der dem Format von '{key_type}' entspricht, wurde "
                "direkt im Quellcode gefunden."
            ),
            file_path=file_path,
            line_number=line,
            snippet=self._redact(snippet),
            owasp_mcp_ref="MCP01",
            cwe_ref="CWE-798",
            remediation=(
                "Secret sofort rotieren (es ist in der Git-History vermutlich "
                "bereits dauerhaft sichtbar). Künftig über Umgebungsvariablen/"
                "Secret-Manager laden, z.B. os.environ['API_KEY']."
            ),
            references=["https://owasp.org/www-project-mcp-top-10/"],
        )

    def _suspicious_assignment_finding(
        self, file_path: Path, line: int, snippet: str
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title="Verdächtige Credential-Zuweisung als Literal",
            description=(
                "Eine Variable mit sicherheitsrelevantem Namen "
                "(key/secret/token/password) wird ein String-Literal mit hoher "
                "Entropie zugewiesen, statt aus einer Umgebungsvariable geladen "
                "zu werden."
            ),
            file_path=file_path,
            line_number=line,
            snippet=self._redact(snippet),
            owasp_mcp_ref="MCP01",
            cwe_ref="CWE-798",
            remediation=(
                "Aus os.environ/process.env oder einem Secret-Manager laden "
                "statt hartzukodieren."
            ),
        )

    @staticmethod
    def _is_excluded(path: Path, root: Path) -> bool:
        # .env.example / .env.sample sind Templates, keine echten Secrets
        if path.name in (".env.example", ".env.sample", ".env.template"):
            return True
        return is_excluded(path, root)

    def _scan_file(self, file_path: Path) -> list[Finding]:
        findings = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except UnicodeDecodeError:
            return findings

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue  # Kommentarzeilen seltener relevant, reduziert Noise

            if _is_placeholder(line):
                continue  # Test-Dummy/Platzhalter -> kein echtes Secret

            # 1. Bekannte Key-Formate
            for key_type, pattern in KNOWN_KEY_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=Severity.CRITICAL,
                            title=f"Mögliches Secret im Code: {key_type}",
                            description=(
                                f"Ein String, der dem Format von '{key_type}' "
                                "entspricht, wurde direkt im Quellcode gefunden."
                            ),
                            file_path=file_path,
                            line_number=i,
                            snippet=self._redact(line),
                            owasp_mcp_ref="MCP01",
                            cwe_ref="CWE-798",
                            remediation=(
                                "Secret sofort rotieren (es ist im Git-History "
                                "vermutlich bereits dauerhaft sichtbar). Künftig "
                                "über Umgebungsvariablen/Secret-Manager laden, "
                                "z.B. os.environ['API_KEY']."
                            ),
                            references=["https://owasp.org/www-project-mcp-top-10/"],
                        )
                    )
                    continue  # nicht doppelt über Entropie-Heuristik prüfen

            # 2. Verdächtiger Variablenname + direktes String-Literal
            if SUSPICIOUS_VAR_NAMES.search(line) and "=" in line:
                if any(hint in line for hint in ENV_LOOKUP_HINTS):
                    continue  # wird korrekt aus Env geladen
                literal_match = re.search(r"=\s*[\"']([^\"']{8,})[\"']", line)
                if literal_match and self._looks_like_secret(literal_match.group(1)):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=Severity.HIGH,
                            title="Verdächtige Credential-Zuweisung als Literal",
                            description=(
                                "Eine Variable mit sicherheitsrelevantem Namen "
                                "(key/secret/token/password) wird ein "
                                "String-Literal mit hoher Entropie zugewiesen, "
                                "statt aus einer Umgebungsvariable geladen zu "
                                "werden."
                            ),
                            file_path=file_path,
                            line_number=i,
                            snippet=self._redact(line),
                            owasp_mcp_ref="MCP01",
                            cwe_ref="CWE-798",
                            remediation=(
                                "Aus os.environ/process.env oder einem "
                                "Secret-Manager laden statt hartzukodieren."
                            ),
                        )
                    )
        return findings

    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        """Einfache Shannon-Entropie-Heuristik: zufällige Tokens haben
        hohe Entropie, normale Wörter/Platzhalter ("changeme", "TODO") nicht."""
        if value.lower() in {"changeme", "your-api-key-here", "todo", "xxx", "placeholder"}:
            return False
        if len(value) < 8:
            return False
        entropy = HardcodedSecretsCheck._shannon_entropy(value)
        return entropy > 3.2  # empirischer Schwellenwert für zufällige Tokens

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) for c in set(s)}
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _redact(line: str) -> str:
        """Zeigt die Zeile, aber maskiert das eigentliche Secret teilweise,
        damit der Report selbst kein neues Leak wird."""
        return re.sub(
            r"([\"'][a-zA-Z0-9_\-]{6})[a-zA-Z0-9_\-]{4,}([a-zA-Z0-9_\-]{4}[\"'])",
            r"\1***REDACTED***\2",
            line.strip(),
        )
