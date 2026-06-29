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
from mcpfrisk.core.fs import rglob_or_file
from mcpfrisk.core.models import Finding, Severity

# Bekannte Key-Formate mit hoher Präzision (wenig False Positives)
KNOWN_KEY_PATTERNS = {
    "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9_-]{2,}-[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{20,}"),
    "Anthropic API Key": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}"),
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
        extensions = ("*.py", "*.js", "*.ts", "*.json", "*.env", "*.yaml", "*.yml")
        seen_files = set()

        for ext in extensions:
            for file_path in rglob_or_file(target_path, ext):
                if self._is_excluded(file_path) or file_path in seen_files:
                    continue
                seen_files.add(file_path)
                findings.extend(self._scan_file(file_path))

        return findings

    @staticmethod
    def _is_excluded(path: Path) -> bool:
        excluded = {"node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".git"}
        # .env.example / .env.sample sind Templates, keine echten Secrets
        if path.name in (".env.example", ".env.sample", ".env.template"):
            return True
        return any(part in excluded for part in path.parts)

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
