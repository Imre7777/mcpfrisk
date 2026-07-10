"""Sprach-agnostischer SourceModel-Port + Domänen-Wertobjekte.

Das ist die Domänen-Schicht der Code-Analyse (Clean Architecture): Die Checks
(Use-Cases) fragen ausschließlich gegen diesen Port -- sie sehen niemals `ast`
oder `tree_sitter`. Zwei Infrastruktur-Adapter implementieren den Port:
`python_ast.PythonSourceModel` (stdlib `ast`) und `treesitter.JsTsSourceModel`
(tree-sitter für JS/TS/TSX).

Die Wertobjekte sind bewusst die *Domänensprache der statischen Analyse*, so wie
die vier bestehenden Checks sie brauchen (Call-Inspektion, Taint über Parameter,
Tool-Beschreibungen, String-/Secret-Literale) -- nicht ein 1:1-Abbild irgendeines
konkreten Syntaxbaums. Siehe specs/002-jsts-ast-coverage/data-model.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Snippet-Obergrenze: lang genug, um einen mehrzeiligen Aufruf vollständig zu
# zeigen, kurz genug, um den Report nicht zu fluten (Prinzip V: verwertbarer Beleg).
_SNIPPET_MAX_LEN = 200


def condense_snippet(text: str, max_len: int = _SNIPPET_MAX_LEN) -> str:
    """Macht aus einem (potenziell mehrzeiligen) Quelltext ein kompaktes,
    einzeiliges Snippet: alle Whitespace-Folgen werden zu einem Leerzeichen,
    bei Überlänge wird mit ``…`` gekürzt. Sprach-agnostisch, von beiden Adaptern
    genutzt, damit ein über mehrere Zeilen umgebrochener Aufruf als vollständiger
    Beleg sichtbar bleibt statt nur als erste physische Zeile."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= max_len:
        return collapsed
    return collapsed[: max_len - 1].rstrip() + "…"


class SourceLanguage(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"   # .js/.mjs/.cjs/.jsx (javascript-Grammatik, inkl. JSX)
    TYPESCRIPT = "typescript"   # .ts/.mts/.cts
    TSX = "tsx"                 # .tsx


@dataclass
class Argument:
    """Normalisierte Sicht auf ein Aufruf-Argument -- Checks fragen *Absicht*,
    nicht Syntax (z.B. ``is_array`` statt 'ist es eine ast.List ODER ein
    tree-sitter array-Node')."""

    text: str = ""
    is_array: bool = False              # Listen-/Array-Literal -> die sichere Arg-Listen-Form
    is_constant_string: bool = False    # reines String-Literal ohne Interpolation
    has_interpolation: bool = False     # f-string/.format()/Konkat ⇄ Template-Literal mit ${...}
    is_truthy_constant: bool = False    # löst die `shell=True`-artige Flag auf
    referenced_names: set[str] = field(default_factory=set)
    array_items: list["Argument"] = field(default_factory=list)  # nur befüllt, wenn is_array


@dataclass
class CallSite:
    callee: str                          # gepunkteter Name: subprocess.run, exec, child_process.exec
    line: int
    snippet: str
    args: list[Argument] = field(default_factory=list)
    keywords: dict[str, Argument] = field(default_factory=dict)


@dataclass
class FunctionDef:
    name: str
    line: int
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    body_calls: list[CallSite] = field(default_factory=list)
    body_assignments: list["Assignment"] = field(default_factory=list)
    body_text: str = ""


@dataclass
class ToolDefinition:
    name: str
    description: str
    line: int
    # Deklarierte, modell-befüllbare Parameter-Namen des Tools -- bei Python die
    # Funktionssignatur (framework-injizierte wie ctx ausgefiltert), bei JS/TS
    # die Top-Level-Keys des inputSchema-/Zod-Objekts. Additiv (Default []),
    # damit bestehende ToolDefinition(name, description, line)-Aufrufe unverändert
    # gültig bleiben (Feature 016).
    parameters: list[str] = field(default_factory=list)


@dataclass
class StringLiteral:
    value: str
    line: int
    snippet: str


@dataclass
class Assignment:
    target_name: str
    line: int
    value: StringLiteral | None = None
    value_is_env_lookup: bool = False
    referenced_names: set[str] = field(default_factory=set)  # Bezeichner in der RHS (für Taint)


class SourceModel:
    """Port: eine geparste Quelldatei, abgefragt über sprach-neutrale Methoden.

    Die Default-Implementierungen liefern leere Listen -- so ist ein
    nicht-parsebares Modell (``ok=False``) gefahrlos abfragbar, ohne dass ein
    Check einen Sonderfall behandeln muss (Prinzip III: nie crashen, nie still
    'clean' melden).
    """

    path: Path
    language: SourceLanguage
    ok: bool = False

    def call_sites(self) -> list[CallSite]:
        return []

    def functions(self) -> list[FunctionDef]:
        return []

    def tool_definitions(self) -> list[ToolDefinition]:
        return []

    def string_literals(self) -> list[StringLiteral]:
        return []

    def assignments(self) -> list[Assignment]:
        return []


class UnparsedModel(SourceModel):
    """Datei, deren Sprache unterstützt wird, die aber nicht geparst werden konnte
    (Syntaxfehler in Python, oder JS/TS ohne installiertes `jsts`-Extra).

    ``ok`` ist False -- der Aufrufer behandelt sie als 'nicht analysierbar /
    übersprungen', NIEMALS als 'sauber'."""

    def __init__(self, path: Path, language: SourceLanguage) -> None:
        self.path = path
        self.language = language
        self.ok = False
