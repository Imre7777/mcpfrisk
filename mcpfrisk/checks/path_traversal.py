"""PATH_TRAVERSAL: Erkennt unsichere Dateipfad-Konstruktion.

Hintergrund: 82% der untersuchten MCP-Implementierungen sind laut
Sicherheitsforschung für Path Traversal anfällig (Stand 2026). Selbst
Anthropics eigener Filesystem-MCP-Server und mcp-server-git waren
betroffen (CVE-2025-68145, path validation bypass).

Typisches Muster: ein Tool nimmt einen "filename"-Parameter vom Modell
entgegen und baut daraus einen Pfad, ohne zu prüfen, ob das Ergebnis
innerhalb eines erlaubten Basisverzeichnisses bleibt. "../../etc/passwd"
oder absolute Pfade umgehen dann jede Einschränkung.

Architektur: Use-Case über dem SourceModel-Port. Der Check fragt
`functions()` ab, verfolgt Taint über `body_assignments` (RHS-Bezeichner)
von einem pfad-artigen Parameter zu einer Zwischenvariable und prüft, ob ein
datei-öffnender Aufruf (`body_calls`) diese tainted-Namen ohne sichtbare
Normalisierung verwendet -- identisch für Python und JS/TS.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import iter_source_files
from mcpfrisk.core.models import Finding, Severity
from mcpfrisk.core.sourcetree import FunctionDef, SourceLanguage, SourceModel, analyze

PY_FILE_OPEN_CALLS = {"open", "os.open", "io.open"}
# JS/TS: datei-öffnende Aufrufe per letztem Namenssegment (fs.readFileSync,
# readFile, createReadStream, openSync, ...).
JS_FILE_OPEN_SEGMENTS = {
    "readFile", "readFileSync",
    "writeFile", "writeFileSync",
    "appendFile", "appendFileSync",
    "createReadStream", "createWriteStream",
    "open", "openSync",
}

PATH_PARAM_KEYWORDS = ("path", "file", "filename", "filepath", "dir", "folder")

SAFE_VALIDATION_HINTS = (
    "realpath",
    "resolve(",
    "is_relative_to",
    "commonpath",
    "abspath",
    "normalize(",   # JS: path.normalize(...)
    "startsWith(",  # JS: full.startsWith(BASE)
    "relative(",    # JS: path.relative(...)
)


class PathTraversalCheck(BaseCheck):
    check_id = "PATH_TRAVERSAL"
    name = "Path Traversal"
    description = (
        "Sucht nach Dateipfad-Konstruktion aus Tool-Parametern ohne "
        "erkennbare Sandboxing-/Normalisierungs-Prüfung."
    )

    def applies_to(self, target_path: Path) -> bool:
        return bool(iter_source_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in iter_source_files(target_path):
            model = analyze(file_path)
            if model is None or not model.ok:
                continue
            for func in model.functions():
                findings.extend(self._scan_function(model, func))
        return findings

    def _scan_function(self, model: SourceModel, func: FunctionDef) -> list[Finding]:
        path_like = {
            p for p in func.params
            if any(kw in p.lower() for kw in PATH_PARAM_KEYWORDS)
        }
        if not path_like:
            return []

        code_only = self._strip_comments(func.body_text)
        has_validation = any(hint in code_only for hint in SAFE_VALIDATION_HINTS)

        # Einfaches Taint-Tracking: Variablen, die (transitiv) aus einem
        # pfad-artigen Parameter gebaut werden, gelten als tainted.
        tainted = set(path_like)
        for assign in func.body_assignments:
            if assign.referenced_names & tainted:
                tainted.add(assign.target_name)

        findings: list[Finding] = []
        for call in func.body_calls:
            if not self._is_file_open(model.language, call.callee):
                continue
            uses_tainted = any(arg.referenced_names & tainted for arg in call.args)
            if uses_tainted and not has_validation:
                findings.append(
                    self._make_finding(model, call.line, call.snippet, func.name, path_like)
                )
        return findings

    @staticmethod
    def _is_file_open(language: SourceLanguage, callee: str) -> bool:
        if not callee:
            return False
        if language is SourceLanguage.PYTHON:
            return callee in PY_FILE_OPEN_CALLS
        return callee.rsplit(".", 1)[-1] in JS_FILE_OPEN_SEGMENTS

    @staticmethod
    def _strip_comments(code: str) -> str:
        """Entfernt Zeilenkommentare (# ... und // ...), damit Validierungs-
        Hinweise in Kommentaren (z.B. 'kein realpath-Check hier!') nicht
        fälschlich als vorhandene Validierung gewertet werden. Bewusst simpel."""
        lines = []
        for line in code.splitlines():
            for marker in ("#", "//"):
                if marker in line:
                    line = line.split(marker, 1)[0]
            lines.append(line)
        return "\n".join(lines)

    def _make_finding(
        self,
        model: SourceModel,
        lineno: int,
        snippet: str,
        func_name: str,
        params: set[str],
    ) -> Finding:
        param_list = ", ".join(sorted(params))
        is_python = model.language is SourceLanguage.PYTHON
        remediation = (
            "Normalisiere den Pfad mit Path(base_dir).joinpath(user_path)."
            "resolve() und prüfe anschließend mit .is_relative_to(base_dir), "
            "dass das Ergebnis innerhalb des erlaubten Verzeichnisses bleibt. "
            "Lehne '..' und absolute Pfade explizit ab."
            if is_python
            else
            "Löse den Pfad mit path.resolve(base, userPath) auf und prüfe mit "
            "result.startsWith(base), dass er im erlaubten Verzeichnis bleibt. "
            "Lehne '..' und absolute Pfade explizit ab."
        )
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title=f"Mögliche Path Traversal in Tool-Funktion '{func_name}'",
            description=(
                f"Die Funktion '{func_name}' nimmt einen dateipfad-artigen "
                f"Parameter ({param_list}) entgegen und übergibt ihn an eine "
                "Datei-öffnende Funktion. Es wurde keine erkennbare "
                "Pfad-Normalisierung/Sandboxing-Prüfung (z.B. realpath, "
                "is_relative_to, resolve, startsWith) im Funktionskörper gefunden."
            ),
            file_path=model.path,
            line_number=lineno,
            snippet=snippet,
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-22",
            remediation=remediation,
            references=[
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
