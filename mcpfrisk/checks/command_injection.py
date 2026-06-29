"""CMD_INJECTION: Erkennt unsicheren Einsatz von Shell-/Subprocess-Aufrufen.

Hintergrund: Exec/Shell-Injection ist mit ~43% die häufigste CVE-Kategorie
im MCP-Ökosystem (Stand 2026). Die meisten MCP-Server sind dünne Wrapper
um CLI-Tools -- die Versuchung, exec()/subprocess.run() mit
String-Interpolation aus User-Input zu füttern, ist groß.

Dieser Check ist bewusst regex/AST-basiert und *nicht* perfekt --
False Positives sind in Ordnung, False Negatives sind das Problem,
das wir minimieren wollen (Security-Scanner-Grundsatz: lieber zu
vorsichtig als zu nachlässig).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.models import Finding, Severity

# Python: Funktionen, die bei String-Eingabe eine Shell aufmachen
PY_DANGEROUS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",      # nur gefährlich wenn shell=True oder str statt list
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "commands.getoutput",  # legacy
}

# JS/TS: Äquivalente
JS_DANGEROUS_PATTERNS = [
    re.compile(r"exec(?:Async)?\s*\(\s*[`\"'].*\$\{"),     # exec(`cmd ${input}`)
    re.compile(r"execSync\s*\("),
    re.compile(r"child_process\.exec\b(?!File)"),           # exec(), nicht execFile()
    re.compile(r"spawn\s*\(\s*[`\"']/bin/(sh|bash)"),
]


class CommandInjectionCheck(BaseCheck):
    check_id = "CMD_INJECTION"
    name = "Command/Shell Injection"
    description = (
        "Sucht nach Shell-Ausführung mit potenziell unsanitiertem "
        "User-Input (häufigste MCP-CVE-Kategorie)."
    )

    def applies_to(self, target_path: Path) -> bool:
        return any(target_path.rglob("*.py")) or any(
            target_path.rglob("*.[jt]s")
        )

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for py_file in target_path.rglob("*.py"):
            if self._is_excluded(py_file):
                continue
            findings.extend(self._scan_python_file(py_file))

        for js_file in list(target_path.rglob("*.js")) + list(
            target_path.rglob("*.ts")
        ):
            if self._is_excluded(js_file):
                continue
            findings.extend(self._scan_js_file(js_file))

        return findings

    @staticmethod
    def _is_excluded(path: Path) -> bool:
        excluded_dirs = {"node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
        return any(part in excluded_dirs for part in path.parts)

    def _scan_python_file(self, file_path: Path) -> list[Finding]:
        findings = []
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._get_call_name(node)
            if call_name not in PY_DANGEROUS_CALLS:
                continue

            risk_level, reason = self._assess_python_call(node, call_name)
            if risk_level is None:
                continue  # z.B. subprocess.run(["ls", "-la"]) mit Liste -> sicher

            snippet = self._get_snippet(source, node.lineno)
            findings.append(
                Finding(
                    check_id=self.check_id,
                    severity=risk_level,
                    title=f"Potenzielle Command Injection via {call_name}()",
                    description=reason,
                    file_path=file_path,
                    line_number=node.lineno,
                    snippet=snippet,
                    owasp_mcp_ref="MCP05",  # Command Injection
                    cwe_ref="CWE-78",
                    remediation=(
                        "Verwende eine Argument-Liste statt String-Interpolation "
                        "(z.B. subprocess.run(['cmd', arg]) statt shell=True mit "
                        "f-strings). Validiere Input gegen eine Allowlist, "
                        "bevor er in einen Systemaufruf fließt."
                    ),
                    references=[
                        "https://owasp.org/www-project-mcp-top-10/",
                        "https://cwe.mitre.org/data/definitions/78.html",
                    ],
                )
            )
        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extrahiert z.B. 'subprocess.run' aus einem Call-Node."""
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name):
            return func.id
        return None

    def _assess_python_call(
        self, node: ast.Call, call_name: str
    ) -> tuple[Severity | None, str]:
        """Bewertet, ob ein konkreter Call riskant aussieht.

        Heuristik:
        - shell=True + nicht-konstanter String-Arg -> CRITICAL
        - String-Arg (statt Liste) ohne shell=True -> MEDIUM (still riskant je Plattform)
        - Liste als erstes Arg, kein shell=True -> kein Finding
        """
        has_shell_true = any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )

        if not node.args:
            return None, ""

        first_arg = node.args[0]
        first_arg_is_list = isinstance(first_arg, (ast.List, ast.Tuple))
        first_arg_is_constant_str = (
            isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)
        )

        if first_arg_is_list and not has_shell_true:
            return None, ""  # sicherer Standardfall

        if has_shell_true:
            if first_arg_is_constant_str:
                # Konstanter String, aber evtl. mit f-string/format gebaut wäre
                # bereits als JoinedStr erkannt worden -- hier ist es ein reiner
                # String-Literal ohne Interpolation, also geringeres Risiko.
                return (
                    Severity.MEDIUM,
                    f"{call_name} mit shell=True und Konstante -- prüfen, ob "
                    "der String wirklich nie aus User-Input zusammengesetzt wird.",
                )
            return (
                Severity.CRITICAL,
                f"{call_name} mit shell=True und nicht-konstantem Befehl "
                "(z.B. f-string, .format(), String-Konkatenation). "
                "Das ist der dominante Pattern hinter MCP-RCE-CVEs.",
            )

        if isinstance(first_arg, ast.JoinedStr):  # f-string ohne shell=True
            return (
                Severity.HIGH,
                f"{call_name} erhält einen f-string als Befehl. Auch ohne "
                "shell=True können einzelne Argumente injiziert werden, wenn "
                "sie nicht als separate Listenelemente übergeben werden.",
            )

        return None, ""

    def _scan_js_file(self, file_path: Path) -> list[Finding]:
        findings = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except UnicodeDecodeError:
            return findings

        for i, line in enumerate(lines, start=1):
            for pattern in JS_DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=Severity.HIGH,
                            title="Potenzielle Command Injection (JS/TS)",
                            description=(
                                "exec()/execSync() mit Template-Literal oder "
                                "Shell-Aufruf gefunden. child_process.execFile() "
                                "mit Argument-Array ist die sichere Alternative."
                            ),
                            file_path=file_path,
                            line_number=i,
                            snippet=line.strip(),
                            owasp_mcp_ref="MCP05",
                            cwe_ref="CWE-78",
                            remediation=(
                                "Nutze child_process.execFile(cmd, [args]) statt "
                                "exec(`${cmd}`). Niemals Nutzereingaben direkt in "
                                "Shell-Strings interpolieren."
                            ),
                            references=[
                                "https://owasp.org/www-project-mcp-top-10/"
                            ],
                        )
                    )
        return findings

    @staticmethod
    def _get_snippet(source: str, lineno: int) -> str:
        lines = source.splitlines()
        if 0 < lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""
