"""CMD_INJECTION: Erkennt unsicheren Einsatz von Shell-/Subprocess-Aufrufen.

Hintergrund: Exec/Shell-Injection ist mit ~43% die häufigste CVE-Kategorie
im MCP-Ökosystem (Stand 2026). Die meisten MCP-Server sind dünne Wrapper
um CLI-Tools -- die Versuchung, exec()/subprocess.run() mit
String-Interpolation aus User-Input zu füttern, ist groß.

Architektur: Der Check ist ein Use-Case über dem sprach-agnostischen
SourceModel-Port (core/sourcetree). Er fragt `call_sites()` ab und bewertet
deren Argumente -- für Python UND JS/TS über denselben Pfad. Den Parser
(ast bzw. tree-sitter) sieht er nie. Fehlt das `jsts`-Extra, fällt der Check
für JS/TS auf die bisherige Zeilen-Regex zurück, damit der Basis-Install
seine Abdeckung behält.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import (
    CallSite,
    SourceLanguage,
    SourceModel,
    analyze,
    jsts_available,
)

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

# JS/TS: gefährliche Aufrufe per letztem Namenssegment (exec, execSync, spawn,
# spawnSync). execFile/execFileSync sind die sicheren Varianten und bewusst NICHT
# enthalten.
JS_DANGEROUS_SEGMENTS = {"exec", "execSync", "spawn", "spawnSync"}

# Fallback (nur wenn das jsts-Extra fehlt): die bisherigen Zeilen-Regexe.
JS_DANGEROUS_PATTERNS = [
    re.compile(r"exec(?:Async)?\s*\(\s*[`\"'].*\$\{"),
    re.compile(r"execSync\s*\("),
    re.compile(r"child_process\.exec\b(?!File)"),
    re.compile(r"spawn\s*\(\s*[`\"']/bin/(sh|bash)"),
]

# Shell-Interpreter-Namen: als erstes Argument/args[0] einer "sicheren"
# Argument-Liste geben sie trotzdem eine Shell frei ("sh -c <string>" ist
# äquivalent zu shell=True), unabhängig vom shell=-Kwarg bzw. davon, dass
# execFile/spawn(args-array) sonst als sicher gilt.
_SHELL_INTERPRETER_NAMES = {
    "sh", "bash", "zsh", "dash", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
}


class CommandInjectionCheck(BaseCheck):
    check_id = "CMD_INJECTION"
    name = "Command/Shell Injection"
    description = (
        "Sucht nach Shell-Ausführung mit potenziell unsanitiertem "
        "User-Input (häufigste MCP-CVE-Kategorie)."
    )

    def applies_to(self, target_path: Path) -> bool:
        return bool(iter_source_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in iter_source_files(target_path):
            if file_path.suffix.lower() != ".py" and not jsts_available():
                findings.extend(self._scan_js_regex(file_path))
                continue
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            findings.extend(self._scan_model(model))
        return findings

    def _scan_model(self, model: SourceModel) -> list[Finding]:
        findings: list[Finding] = []
        for call in model.call_sites():
            if not self._is_dangerous(model.language, call.callee):
                continue
            severity, reason = self._assess(model.language, call)
            if severity is None:
                continue
            findings.append(self._make_finding(model, call, severity, reason))
        return findings

    @staticmethod
    def _is_dangerous(language: SourceLanguage, callee: str) -> bool:
        if not callee:
            return False
        if language is SourceLanguage.PYTHON:
            return callee in PY_DANGEROUS_CALLS
        return callee.rsplit(".", 1)[-1] in JS_DANGEROUS_SEGMENTS

    def _assess(
        self, language: SourceLanguage, call: CallSite
    ) -> tuple[Severity | None, str]:
        """Sprach-bewusste Risiko-Policy über den einheitlichen Argument-Flags.

        Gemeinsam beiden Sprachen: ein Array/Listen-Literal als erstes Argument
        ist die sichere Form, Interpolation (f-string/Template-Literal/Konkat)
        ist die gefährliche. Sprach-spezifisch ist nur, *wie* die Shell
        aktiviert wird (Python: ``shell=True``; JS: exec() öffnet implizit eine
        Shell). Das Parsing ist identisch -- nur die Bewertung kennt die Sprache.
        """
        if not call.args:
            return None, ""
        first = call.args[0]

        if language is SourceLanguage.PYTHON:
            shell = call.keywords.get("shell")
            shell_true = shell is not None and shell.is_truthy_constant
            if first.is_array:
                # "sh -c <tainted>" (bzw. bash/cmd/powershell) öffnet eine Shell
                # durch den Interpreter selbst -- unabhängig von shell=True.
                if self._is_shell_c_array(first.array_items):
                    return (
                        Severity.CRITICAL,
                        f"{call.callee} übergibt eine Argument-Liste, deren erstes "
                        "Element ein Shell-Interpreter ist (sh/bash/cmd/...) und ein "
                        "späteres Element nicht konstant ist -- 'sh -c <tainted>' ist "
                        "unabhängig von shell=True eine vollständige Command "
                        "Injection, weil der Interpreter selbst die Shell öffnet.",
                    )
                if not shell_true:
                    return None, ""
                if self._array_has_interpolated_element(first.array_items):
                    # shell=True + Liste: Python führt args[0] als Shell-Befehlsstring
                    # aus (Rest als zusätzliche Shell-Argumente) -- eine Interpolation
                    # in einem Element ist daher derselbe direkte RCE-Pfad wie ein
                    # interpolierter String ohne Liste.
                    return (
                        Severity.CRITICAL,
                        f"{call.callee} übergibt ein Argument-Listen-Element mit "
                        "Interpolation (f-string/.format()/Konkatenation) bei aktivem "
                        "shell=True. Bei shell=True wird args[0] als Shell-"
                        "Befehlsstring ausgeführt -- eine Interpolation darin ist "
                        "vollständige Command Injection.",
                    )
                # Array-Befehl + shell=True, aber kein interpoliertes Element: kein
                # direkter Injection-Pfad. shell=True ist hier redundant/irreführend.
                # Laut Severity-Rubrik (Prinzip V) ein Best-Practice-Verstoß = MEDIUM,
                # NICHT CRITICAL. Der Befund wird weiterhin gemeldet (Prinzip III).
                return (
                    Severity.MEDIUM,
                    f"{call.callee} übergibt eine Argument-Liste, setzt aber "
                    "redundant shell=True. Das ist kein interpolierter Befehl "
                    "(kein direkter RCE-Pfad), sollte aber bereinigt werden -- "
                    "shell=True entfernen, damit kein versehentlicher Shell-"
                    "Kontext entsteht.",
                )
            if shell_true:
                if first.is_constant_string:
                    return (
                        Severity.MEDIUM,
                        f"{call.callee} mit shell=True und Konstante -- prüfen, ob "
                        "der String wirklich nie aus User-Input zusammengesetzt wird.",
                    )
                return (
                    Severity.CRITICAL,
                    f"{call.callee} mit shell=True und nicht-konstantem Befehl "
                    "(f-string, .format(), String-Konkatenation). Das ist der "
                    "dominante Pattern hinter MCP-RCE-CVEs.",
                )
            if first.has_interpolation:
                return (
                    Severity.HIGH,
                    f"{call.callee} erhält einen interpolierten String als Befehl. "
                    "Auch ohne shell=True können Argumente injiziert werden, wenn "
                    "sie nicht als separate Listenelemente übergeben werden.",
                )
            return None, ""

        # JS/TS: exec()/execSync()/spawn() öffnen eine Shell, execFile() nicht.
        if first.is_constant_string:
            # spawn("sh", ["-c", tainted]) / spawn("bash", [...]) -- der
            # Interpreter-Name als args[0] öffnet die Shell, das eigentliche
            # gefährliche Element steckt im zweiten (Array-)Argument.
            interpreter = self._shell_literal(first.text)
            second = call.args[1] if len(call.args) > 1 else None
            if (
                interpreter is not None
                and second is not None
                and second.is_array
                and self._array_has_tainted_element(second.array_items)
            ):
                return (
                    Severity.CRITICAL,
                    f"{call.callee}('{interpreter}', [...]) ruft den Shell-"
                    f"Interpreter '{interpreter}' mit einem Argument-Array auf, das "
                    "ein nicht-konstantes Element enthält (klassisches "
                    "'sh -c <tainted>'-Muster) -- vollständige Command Injection, "
                    "unabhängig davon, dass ein Array-Argument sonst als sicher gilt.",
                )
            return None, ""
        if first.is_array:
            return None, ""
        if first.has_interpolation:
            return (
                Severity.HIGH,
                f"{call.callee}() mit Template-Literal/String-Konkatenation als "
                "Befehl. child_process.execFile(cmd, [args]) ist die sichere Form.",
            )
        if first.referenced_names:
            return (
                Severity.HIGH,
                f"{call.callee}() erhält eine Variable als Shell-Befehl. Wenn sie "
                "(teilweise) aus Eingaben stammt, ist das Command Injection.",
            )
        return None, ""

    @staticmethod
    def _shell_literal(text: str) -> str | None:
        """Erkennt, ob ein konstantes String-Argument ein Shell-Interpreter-Name
        ist (auch pfad-qualifiziert, z.B. '/bin/sh'). None, wenn nicht."""
        literal = text.strip().strip("'\"`")
        name = literal.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return name if name.lower() in _SHELL_INTERPRETER_NAMES else None

    @classmethod
    def _is_shell_c_array(cls, items: list) -> bool:
        """True, wenn das erste Array-Element ein Shell-Interpreter-Name ist
        UND ein späteres Element nicht konstant (also potenziell tainted) ist --
        das 'sh -c <tainted>'-Muster, das eine Shell unabhängig von shell=True
        öffnet."""
        if not items or not items[0].is_constant_string:
            return False
        if cls._shell_literal(items[0].text) is None:
            return False
        return cls._array_has_tainted_element(items[1:])

    @staticmethod
    def _array_has_interpolated_element(items: list) -> bool:
        return any(it.has_interpolation for it in items)

    @staticmethod
    def _array_has_tainted_element(items: list) -> bool:
        return any(not it.is_constant_string for it in items)

    def _make_finding(
        self, model: SourceModel, call: CallSite, severity: Severity, reason: str
    ) -> Finding:
        is_python = model.language is SourceLanguage.PYTHON
        if is_python:
            remediation = (
                "Verwende eine Argument-Liste statt String-Interpolation "
                "(z.B. subprocess.run(['cmd', arg]) statt shell=True mit "
                "f-strings). Validiere Input gegen eine Allowlist, bevor er in "
                "einen Systemaufruf fließt."
            )
        else:
            remediation = (
                "Nutze child_process.execFile(cmd, [args]) statt exec(`${cmd}`). "
                "Niemals Nutzereingaben direkt in Shell-Strings interpolieren."
            )
        title = (
            f"Potenzielle Command Injection via {call.callee}()"
            if is_python
            else "Potenzielle Command Injection (JS/TS)"
        )
        return Finding(
            check_id=self.check_id,
            severity=severity,
            title=title,
            description=reason,
            file_path=model.path,
            line_number=call.line,
            snippet=call.snippet,
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-78",
            remediation=remediation,
            references=[
                "https://owasp.org/www-project-mcp-top-10/",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
        )

    def _scan_js_regex(self, file_path: Path) -> list[Finding]:
        """Fallback ohne das jsts-Extra: die bisherige Zeilen-Heuristik."""
        findings: list[Finding] = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return findings
        for i, line in enumerate(lines, start=1):
            if any(p.search(line) for p in JS_DANGEROUS_PATTERNS):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title="Potenzielle Command Injection (JS/TS)",
                        description=(
                            "exec()/execSync() mit Template-Literal oder Shell-Aufruf "
                            "gefunden (Regex-Fallback ohne jsts-Extra)."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=line.strip(),
                        owasp_mcp_ref="MCP05",
                        cwe_ref="CWE-78",
                        remediation=(
                            "Nutze child_process.execFile(cmd, [args]) statt "
                            "exec(`${cmd}`). Für volle AST-Genauigkeit: "
                            "pip install mcpfrisk[jsts]."
                        ),
                        references=["https://owasp.org/www-project-mcp-top-10/"],
                    )
                )
        return findings
