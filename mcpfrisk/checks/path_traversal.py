"""PATH_TRAVERSAL: Erkennt unsichere Dateipfad-Konstruktion.

Hintergrund: 82% der untersuchten MCP-Implementierungen sind laut
Sicherheitsforschung für Path Traversal anfällig (Stand 2026). Selbst
Anthropics eigener Filesystem-MCP-Server und mcp-server-git waren
betroffen (CVE-2025-68145, path validation bypass).

Typisches Muster: ein Tool nimmt einen "filename"-Parameter vom Modell
entgegen und baut daraus einen Pfad, ohne zu prüfen, ob das Ergebnis
innerhalb eines erlaubten Basisverzeichnisses bleibt. "../../etc/passwd"
oder absolute Pfade umgehen dann jede Einschränkung.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import rglob_or_file
from mcpfrisk.core.models import Finding, Severity

PY_FILE_OPEN_CALLS = {"open", "os.open", "io.open"}
PY_PATH_JOIN_CALLS = {"os.path.join", "Path"}  # Path(base) / user_input

SAFE_VALIDATION_HINTS = (
    "realpath",
    "resolve(",
    "is_relative_to",
    "commonpath",
    "abspath",
)


class PathTraversalCheck(BaseCheck):
    check_id = "PATH_TRAVERSAL"
    name = "Path Traversal"
    description = (
        "Sucht nach Dateipfad-Konstruktion aus Tool-Parametern ohne "
        "erkennbare Sandboxing-/Normalisierungs-Prüfung."
    )

    def applies_to(self, target_path: Path) -> bool:
        return any(rglob_or_file(target_path, "*.py"))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for py_file in rglob_or_file(target_path, "*.py"):
            if self._is_excluded(py_file):
                continue
            findings.extend(self._scan_file(py_file))
        return findings

    @staticmethod
    def _is_excluded(path: Path) -> bool:
        excluded = {"node_modules", ".venv", "venv", "__pycache__"}
        return any(part in excluded for part in path.parts)

    def _scan_file(self, file_path: Path) -> list[Finding]:
        findings = []
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            return findings

        # Funktionsdefinitionen finden, die wie MCP-Tools aussehen
        # (haben einen Parameter, der nach Dateipfad klingt) UND
        # darin file-öffnende Calls ohne sichtbare Validierung enthalten.
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            path_like_params = self._find_path_like_params(func_node)
            if not path_like_params:
                continue

            func_source = ast.get_source_segment(source, func_node) or ""
            code_only = self._strip_comments(func_source)
            has_validation = any(
                hint in code_only for hint in SAFE_VALIDATION_HINTS
            )

            # Einfaches Taint-Tracking: verfolge, welche Variablennamen
            # (transitiv) von einem path-artigen Parameter abstammen.
            # Beispiel: path = os.path.join(base, filename) -> 'path' wird
            # als "tainted" markiert, weil 'filename' in der Zuweisung
            # vorkommt. Das ist bewusst simpel (kein vollständiges
            # Dataflow-Graph), deckt aber den häufigsten Fall ab: eine
            # Zwischenvariable, die direkt aus dem Parameter gebaut wird.
            tainted_names = set(path_like_params)
            for assign_node in ast.walk(func_node):
                if isinstance(assign_node, ast.Assign):
                    rhs_names = {
                        n.id for n in ast.walk(assign_node.value)
                        if isinstance(n, ast.Name)
                    }
                    if rhs_names & tainted_names:
                        for target in assign_node.targets:
                            if isinstance(target, ast.Name):
                                tainted_names.add(target.id)

            for node in ast.walk(func_node):
                if not isinstance(node, ast.Call):
                    continue
                call_name = self._get_call_name(node)

                if call_name in PY_FILE_OPEN_CALLS:
                    uses_param = self._uses_any_name(node, tainted_names)
                    if uses_param and not has_validation:
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                source,
                                func_node.name,
                                path_like_params,
                            )
                        )
        return findings

    @staticmethod
    def _strip_comments(code: str) -> str:
        """Entfernt Zeilenkommentare (# ...), damit Validierungs-Hinweise
        in Kommentaren (z.B. 'kein realpath-Check hier!') nicht fälschlich
        als vorhandene Validierung gewertet werden. Bewusst simpel -- ignoriert
        '#' innerhalb von String-Literalen, was in der Praxis selten relevant
        ist für diesen Anwendungsfall."""
        lines = []
        for line in code.splitlines():
            if "#" in line:
                line = line.split("#", 1)[0]
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def _find_path_like_params(
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        """Findet Parameter, deren Name auf einen Dateipfad hindeutet."""
        path_keywords = ("path", "file", "filename", "filepath", "dir", "folder")
        return {
            arg.arg
            for arg in func_node.args.args
            if any(kw in arg.arg.lower() for kw in path_keywords)
        }

    @staticmethod
    def _uses_any_name(node: ast.Call, names: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in names:
                return True
        return False

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        if isinstance(func, ast.Name):
            return func.id
        return None

    def _make_finding(
        self,
        file_path: Path,
        lineno: int,
        source: str,
        func_name: str,
        params: set[str],
    ) -> Finding:
        lines = source.splitlines()
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
        param_list = ", ".join(sorted(params))
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title=f"Mögliche Path Traversal in Tool-Funktion '{func_name}'",
            description=(
                f"Die Funktion '{func_name}' nimmt einen dateipfad-artigen "
                f"Parameter ({param_list}) entgegen und übergibt ihn an eine "
                "Datei-öffnende Funktion. Es wurde keine erkennbare "
                "Pfad-Normalisierung/Sandboxing-Prüfung (z.B. realpath, "
                "is_relative_to, resolve) im Funktionskörper gefunden."
            ),
            file_path=file_path,
            line_number=lineno,
            snippet=snippet,
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-22",
            remediation=(
                "Normalisiere den Pfad mit Path(base_dir).joinpath(user_path)."
                "resolve() und prüfe anschließend mit .is_relative_to(base_dir), "
                "dass das Ergebnis innerhalb des erlaubten Verzeichnisses bleibt. "
                "Lehne '..' und absolute Pfade explizit ab."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
