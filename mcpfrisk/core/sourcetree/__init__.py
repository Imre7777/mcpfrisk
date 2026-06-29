"""core/sourcetree -- die sprach-agnostische Quellcode-Analyse-Schicht.

Öffentliche Oberfläche für die Checks (Use-Cases). Ein Check ruft
``analyze(path)`` und stellt domänennahe Fragen an das zurückgegebene
``SourceModel`` (``call_sites()``, ``tool_definitions()`` ...). Welcher Parser
(stdlib ``ast`` für Python, tree-sitter für JS/TS) dahintersteckt, bleibt
hinter dem Port verborgen -- so liegt die gesamte Parser-Infrastruktur an
genau einer Stelle (Prinzipien II und IV).
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core.sourcetree import python_ast, treesitter
from mcpfrisk.core.sourcetree.model import (
    Argument,
    Assignment,
    CallSite,
    FunctionDef,
    SourceLanguage,
    SourceModel,
    StringLiteral,
    ToolDefinition,
    UnparsedModel,
)

__all__ = [
    "analyze",
    "jsts_available",
    "detect_language",
    "SourceModel",
    "SourceLanguage",
    "CallSite",
    "Argument",
    "FunctionDef",
    "ToolDefinition",
    "StringLiteral",
    "Assignment",
]

_EXTENSION_LANGUAGE = {
    ".py": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".mjs": SourceLanguage.JAVASCRIPT,
    ".cjs": SourceLanguage.JAVASCRIPT,
    ".jsx": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.TYPESCRIPT,
    ".mts": SourceLanguage.TYPESCRIPT,
    ".cts": SourceLanguage.TYPESCRIPT,
    ".tsx": SourceLanguage.TSX,
}


def detect_language(path: Path) -> SourceLanguage | None:
    return _EXTENSION_LANGUAGE.get(Path(path).suffix.lower())


def jsts_available() -> bool:
    """True, wenn das `jsts`-Extra (tree-sitter + Grammatiken) importierbar ist."""
    return treesitter.available()


def analyze(path: Path) -> SourceModel | None:
    """Parst ``path`` in ein sprach-neutrales SourceModel.

    - Nicht unterstützte Dateitypen -> ``None``.
    - Sprache unterstützt, aber Parser fehlt (JS/TS ohne `jsts`-Extra) ->
      ``UnparsedModel(ok=False)`` -- übersprungen, NIE als 'clean' gewertet.
    - Wirft nie bei fehlerhaftem Input.
    """
    path = Path(path)
    language = detect_language(path)
    if language is None:
        return None
    if language is SourceLanguage.PYTHON:
        return python_ast.parse_file(path)
    if not treesitter.available():
        return UnparsedModel(path, language)
    return treesitter.parse_file(path, language)
