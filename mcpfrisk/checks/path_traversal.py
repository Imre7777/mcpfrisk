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
from mcpfrisk.core.sourcetree import (
    CallSite,
    FunctionDef,
    SourceLanguage,
    SourceModel,
    analyze,
)

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
            functions = model.functions()
            # Triage-Kontext (US3): Funktionen im selben Modul, deren Körper eine
            # erkennbare Pfad-Validierung enthält. Das Taint-Tracking ist bewusst
            # intra-prozedural -- validiert ein Server in einer SEPARATEN Funktion
            # (z.B. validatePath()), sieht der Check das nicht und meldet (korrekt
            # nach Prinzip III) trotzdem. Statt zu unterdrücken, hängen wir einen
            # Hinweis an, damit der Reviewer einen wahrscheinlichen FP schnell einordnet.
            module_validators = self._module_validators(functions)

            # Pass 1: intra-prozedural (unverändertes Verhalten).
            intra: list[Finding] = []
            for func in functions:
                intra.extend(self._scan_function(model, func, module_validators))
            findings.extend(intra)

            # Pass 2: Cross-Function-Taint eine Ebene tief (Feature 012). Ein
            # pfad-artiger Parameter, der an einen im selben Modul definierten
            # Helper weitergereicht wird, dessen Körper ihn ungeprüft öffnet --
            # der intra-Pass sieht das nicht (Quelle und Sink in verschiedenen
            # Funktionen). Dedup gegen bereits (intra) gemeldete Sinks.
            flagged_sinks = {(model.path, f.line_number) for f in intra}
            findings.extend(self._scan_cross_function(model, functions, flagged_sinks))
        return findings

    def _module_validators(self, functions: list[FunctionDef]) -> list[str]:
        """Namen der Funktionen, deren (kommentar-bereinigter) Körper einen
        Validierungs-Hinweis enthält. Kommentar-Stripping verhindert, dass ein
        Hinweis-Wort in einem Kommentar fälschlich als 'Validierung existiert' zählt."""
        names: list[str] = []
        for f in functions:
            code_only = self._strip_comments(f.body_text)
            if any(hint in code_only for hint in SAFE_VALIDATION_HINTS):
                names.append(f.name)
        return names

    def _scan_function(
        self,
        model: SourceModel,
        func: FunctionDef,
        module_validators: list[str] | None = None,
    ) -> list[Finding]:
        path_like = self._path_like_params(func)
        if not path_like:
            return []

        has_validation = self._has_validation(func)
        tainted = self._tainted_set(func, path_like)

        # Validierungsfunktionen im Modul, die NICHT diese Funktion selbst sind.
        external_validators = [
            v for v in (module_validators or []) if v != func.name
        ]

        findings: list[Finding] = []
        for call in func.body_calls:
            if not self._is_file_open(model.language, call.callee):
                continue
            uses_tainted = any(arg.referenced_names & tainted for arg in call.args)
            if uses_tainted and not has_validation:
                findings.append(
                    self._make_finding(
                        model, call.line, call.snippet, func.name, path_like,
                        external_validators,
                    )
                )
        return findings

    @staticmethod
    def _path_like_params(func: FunctionDef) -> set[str]:
        return {
            p for p in func.params
            if any(kw in p.lower() for kw in PATH_PARAM_KEYWORDS)
        }

    def _has_validation(self, func: FunctionDef) -> bool:
        code_only = self._strip_comments(func.body_text)
        return any(hint in code_only for hint in SAFE_VALIDATION_HINTS)

    @staticmethod
    def _tainted_set(func: FunctionDef, seed: set[str]) -> set[str]:
        """Menge der Namen, die (transitiv, ein Vorwärts-Pass in Quelltext-
        Reihenfolge) aus `seed` gebaut werden. `seed` sind die anfänglich
        getainteten Parameter -- intra: die pfad-artigen; cross: die per Helfer-
        Aufruf propagierten."""
        tainted = set(seed)
        for assign in func.body_assignments:
            if assign.referenced_names & tainted:
                tainted.add(assign.target_name)
        return tainted

    # -- Cross-Function-Taint (Feature 012) --------------------------------
    def _scan_cross_function(
        self,
        model: SourceModel,
        functions: list[FunctionDef],
        flagged_sinks: set,
    ) -> list[Finding]:
        """Verfolgt Taint EINE Funktionsgrenze weit: ein pfad-artiger Parameter
        einer Funktion F, der (positional oder per Keyword) an einen im selben
        Modul definierten Helfer H weitergereicht wird, dessen Körper ihn
        ungeprüft an einen Datei-Sink gibt. Keine Transitivität (F→H→G) in v1."""
        func_map: dict[str, FunctionDef] = {}
        for f in functions:
            if f.name:
                func_map[f.name] = f  # bei Namensgleichheit gewinnt die letzte Definition

        findings: list[Finding] = []
        for entry in functions:
            path_like = self._path_like_params(entry)
            if not path_like:
                continue  # nur von einer echten Quelle (pfad-artiger Param) aus
            entry_tainted = self._tainted_set(entry, path_like)
            for call in entry.body_calls:
                helper = func_map.get(call.callee)
                if helper is None or helper is entry:
                    continue
                seed = self._bind_tainted_params(call, helper, entry_tainted)
                if not seed:
                    continue
                if self._has_validation(helper):
                    continue  # Helfer validiert selbst -> kein FP
                helper_tainted = self._tainted_set(helper, seed)
                for sink in helper.body_calls:
                    if not self._is_file_open(model.language, sink.callee):
                        continue
                    if not any(arg.referenced_names & helper_tainted for arg in sink.args):
                        continue
                    key = (model.path, sink.line)
                    if key in flagged_sinks:
                        continue  # intra hat diesen Sink schon gemeldet
                    flagged_sinks.add(key)
                    findings.append(
                        self._make_cross_finding(model, sink, entry, helper, seed)
                    )
        return findings

    @staticmethod
    def _bind_tainted_params(
        call: CallSite, helper: FunctionDef, caller_tainted: set[str]
    ) -> set[str]:
        """Bindet getaintete Aufruf-Argumente an die Parameter-Namen des Helfers
        (positional per Position, keyword per Name)."""
        seed: set[str] = set()
        for i, arg in enumerate(call.args):
            if arg.referenced_names & caller_tainted and i < len(helper.params):
                seed.add(helper.params[i])
        for kw_name, arg in call.keywords.items():
            if arg.referenced_names & caller_tainted and kw_name in helper.params:
                seed.add(kw_name)
        return seed

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
        external_validators: list[str] | None = None,
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
        description = (
            f"Die Funktion '{func_name}' nimmt einen dateipfad-artigen "
            f"Parameter ({param_list}) entgegen und übergibt ihn an eine "
            "Datei-öffnende Funktion. Es wurde keine erkennbare "
            "Pfad-Normalisierung/Sandboxing-Prüfung (z.B. realpath, "
            "is_relative_to, resolve, startsWith) im Funktionskörper gefunden."
        )
        # Konfidenz-Kalibrierung: Definiert das Modul eine separate Validierungs-
        # funktion, die diese Funktion selbst nicht aufruft, ist ein FP deutlich
        # wahrscheinlicher (das intra-prozedurale Tracking sieht die Validierung
        # nur nicht) -> MEDIUM statt HIGH. Das UNTERDRÜCKT nichts (FP-über-FN
        # bleibt: das Finding erscheint, blockiert bei --fail-on medium, trägt den
        # Triage-Hinweis) -- es signalisiert nur ehrlich die geringere Konfidenz.
        # Ohne einen solchen Modul-Validierer bleibt es HIGH.
        severity = Severity.HIGH
        if external_validators:
            severity = Severity.MEDIUM
            vlist = ", ".join(f"'{v}'" for v in sorted(set(external_validators)))
            description += (
                f" Triage-Hinweis: Dieses Modul definiert separate "
                f"Validierungsfunktion(en) ({vlist}). Falls der Pfad bereits dort "
                "geprüft wird, BEVOR er hierher gelangt, ist dies wahrscheinlich ein "
                "False Positive -- bitte verifizieren. Deshalb MEDIUM statt HIGH "
                "(das intra-prozedurale Taint-Tracking sieht funktionsübergreifende "
                "Validierung nicht)."
            )
        return Finding(
            check_id=self.check_id,
            severity=severity,
            title=f"Mögliche Path Traversal in Tool-Funktion '{func_name}'",
            description=description,
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

    def _make_cross_finding(
        self,
        model: SourceModel,
        sink: CallSite,
        entry: FunctionDef,
        helper: FunctionDef,
        seed: set[str],
    ) -> Finding:
        is_python = model.language is SourceLanguage.PYTHON
        remediation = (
            "Normalisiere den Pfad mit Path(base_dir).joinpath(user_path)."
            "resolve() und prüfe mit .is_relative_to(base_dir) -- am besten im "
            "Helfer, der die Datei tatsächlich öffnet. Lehne '..' und absolute "
            "Pfade explizit ab."
            if is_python
            else
            "Löse den Pfad mit path.resolve(base, userPath) auf und prüfe mit "
            "result.startsWith(base) -- am besten im Helfer, der die Datei "
            "tatsächlich öffnet. Lehne '..' und absolute Pfade explizit ab."
        )
        seed_list = ", ".join(sorted(seed))
        entry_params = ", ".join(sorted(self._path_like_params(entry)))
        description = (
            f"Der dateipfad-artige Parameter ({entry_params}) der Funktion "
            f"'{entry.name}' wird an den Helfer '{helper.name}' weitergereicht "
            f"(Parameter {seed_list}) und dort ohne erkennbare Validierung an eine "
            "Datei-öffnende Funktion gegeben. Der Fluss läuft über eine "
            "Funktionsgrenze -- die intra-prozedurale Prüfung allein würde ihn "
            "übersehen. (Cross-Function-Taint, eine Ebene tief; tiefere Ketten "
            "oder Helfer aus anderen Modulen deckt diese Version nicht ab.)"
        )
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title=(
                f"Mögliche Path Traversal über Helfer '{helper.name}' "
                f"(aus '{entry.name}')"
            ),
            description=description,
            file_path=model.path,
            line_number=sink.line,
            snippet=sink.snippet,
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-22",
            remediation=remediation,
            references=[
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
