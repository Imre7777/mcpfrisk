"""PythonAstAdapter: implementiert den SourceModel-Port über die stdlib `ast`.

Verhaltensgleich zu der bisherigen inline-`ast`-Nutzung in den Checks: eine
Datei mit SyntaxError wird zu ``UnparsedModel(ok=False)``, der Rest des Scans
läuft weiter.
"""
from __future__ import annotations

import ast
from pathlib import Path

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
    condense_snippet,
)

_ENV_HINTS = ("os.environ", "os.getenv", "getenv(", "process.env", "dotenv")


def _iter_dfs(node: ast.AST):
    """Preorder-Tiefensuche in Quellcode-/Ausführungsreihenfolge -- anders als
    `ast.walk()` (breadth-first: alle Knoten einer Ebene vor der nächsten).
    Für Taint-Tracking über body_assignments wichtig: eine Zuweisung in einem
    verschachtelten Block (z.B. innerhalb `if`) muss VOR einer nachfolgenden
    Zuweisung auf Modulebene erscheinen, wenn sie im Quelltext zuerst steht --
    `ast.walk()` liefert das in falscher Reihenfolge (Bug: verschachtelte
    Zuweisung wurde nicht als Taint-Quelle erkannt)."""
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_dfs(child)


def parse_file(path: Path) -> SourceModel:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return UnparsedModel(path, SourceLanguage.PYTHON)
    return PythonSourceModel(path, text, tree)


class PythonSourceModel(SourceModel):
    def __init__(self, path: Path, text: str, tree: ast.AST) -> None:
        self.path = path
        self.language = SourceLanguage.PYTHON
        self.ok = True
        self._text = text
        self._tree = tree
        self._lines = text.splitlines()
        self._import_aliases = self._build_import_aliases()

    # -- helpers -----------------------------------------------------------

    def _build_import_aliases(self) -> dict[str, str]:
        """Bildet 'lokaler Name -> voll-qualifizierter Name' für Import-Aliase,
        damit z.B. `import subprocess as sp; sp.run(...)` oder
        `from subprocess import run; run(...)` denselben Callee-Namen liefern
        wie `subprocess.run(...)` -- sonst umgeht jeder Alias/Direct-Import
        die dangerous-call-Erkennung in command_injection.py/path_traversal.py
        vollständig (Bug: Import-Alias-Bypass)."""
        aliases: dict[str, str] = {}
        for node in ast.walk(self._tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    if local != alias.name:
                        aliases[local] = alias.name  # "sp" -> "subprocess"
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local = alias.asname or alias.name
                    aliases[local] = f"{node.module}.{alias.name}"  # "run" -> "subprocess.run"
        return aliases

    def _resolve_alias(self, dotted: str) -> str:
        if not dotted:
            return dotted
        if dotted in self._import_aliases:
            return self._import_aliases[dotted]
        head, sep, rest = dotted.partition(".")
        target = self._import_aliases.get(head)
        if sep and target is not None and "." not in target:
            return f"{target}.{rest}"
        return dotted

    def _snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()
        return ""

    @staticmethod
    def _callee_name(func: ast.AST) -> str:
        """Gepunkteter Name eines Call-Ziels: subprocess.run, child_process.exec, open."""
        if isinstance(func, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        if isinstance(func, ast.Name):
            return func.id
        return ""

    def _segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self._text, node) or ""

    def _arg(self, node: ast.AST) -> Argument:
        a = Argument(text=self._segment(node))
        a.referenced_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        if isinstance(node, (ast.List, ast.Tuple)):
            a.is_array = True
            a.array_items = [self._arg(el) for el in node.elts]
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                a.is_constant_string = True
            if node.value is True:
                a.is_truthy_constant = True
        elif isinstance(node, ast.JoinedStr):  # f-string
            a.has_interpolation = True
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # String-Konkatenation, die einen Namen enthält -> interpolationsartig
            if a.referenced_names:
                a.has_interpolation = True
        elif isinstance(node, ast.Call) and self._callee_name(node.func).endswith(".format"):
            a.has_interpolation = True
        return a

    def _call_snippet(self, node: ast.AST) -> str:
        """Vollständiger Aufruf als kompaktes Snippet (mehrzeilen-fest). Fällt auf
        die physische Startzeile zurück, falls kein Quell-Segment ermittelbar ist."""
        seg = self._segment(node)
        if seg:
            return condense_snippet(seg)
        return self._snippet(getattr(node, "lineno", 0))

    def _call(self, node: ast.Call) -> CallSite:
        args = [self._arg(a) for a in node.args]
        keywords = {kw.arg: self._arg(kw.value) for kw in node.keywords if kw.arg}
        return CallSite(
            callee=self._resolve_alias(self._callee_name(node.func)),
            line=node.lineno,
            snippet=self._call_snippet(node),
            args=args,
            keywords=keywords,
        )

    def _assignments_from(self, node: ast.AST) -> list[Assignment]:
        targets: list[str] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        if not targets or value is None:
            return []
        lit = None
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            lit = StringLiteral(value.value, node.lineno, self._snippet(node.lineno))
        seg = self._segment(value)
        is_env = any(h in seg for h in _ENV_HINTS)
        refs = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
        return [Assignment(name, node.lineno, lit, is_env, set(refs)) for name in targets]

    # -- port queries ------------------------------------------------------

    def call_sites(self) -> list[CallSite]:
        return [self._call(n) for n in ast.walk(self._tree) if isinstance(n, ast.Call)]

    def functions(self) -> list[FunctionDef]:
        out: list[FunctionDef] = []
        for node in ast.walk(self._tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [a.arg for a in node.args.args]
            decorators: list[str] = []
            for d in node.decorator_list:
                name = self._callee_name(d.func) if isinstance(d, ast.Call) else self._callee_name(d)
                if name:
                    decorators.append(name)
            body_calls = [self._call(n) for n in _iter_dfs(node) if isinstance(n, ast.Call)]
            body_assignments: list[Assignment] = []
            for n in _iter_dfs(node):
                if isinstance(n, (ast.Assign, ast.AnnAssign)):
                    body_assignments.extend(self._assignments_from(n))
            out.append(
                FunctionDef(
                    name=node.name,
                    line=node.lineno,
                    params=params,
                    decorators=decorators,
                    body_calls=body_calls,
                    body_assignments=body_assignments,
                    body_text=self._segment(node),
                )
            )
        return out

    def tool_definitions(self) -> list[ToolDefinition]:
        out: list[ToolDefinition] = []
        for node in ast.walk(self._tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._looks_like_tool(node):
                continue
            # Ein Tool kann seine ans Modell gehende Beschreibung über den
            # Docstring ODER über ein @mcp.tool(description="...")-Kwarg
            # bekommen (beides sind dokumentierte MCP-SDK-Formen) -- beide
            # Quellen zusammenführen, damit ein Angriffsmuster in KEINER von
            # beiden unentdeckt bleibt (Bug: description-Kwarg wurde ignoriert).
            parts = [ast.get_docstring(node), self._decorator_description(node)]
            description = " ".join(p for p in parts if p)
            out.append(ToolDefinition(node.name, description, node.lineno))
        return out

    @staticmethod
    def _looks_like_tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any("tool" in ast.dump(d).lower() for d in node.decorator_list)

    @staticmethod
    def _decorator_description(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        """Liest description="..." aus einem Decorator-Aufruf wie
        @mcp.tool(description="..."), falls vorhanden."""
        for d in node.decorator_list:
            if not isinstance(d, ast.Call):
                continue
            for kw in d.keywords:
                if (
                    kw.arg == "description"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    return kw.value.value
        return None

    def string_literals(self) -> list[StringLiteral]:
        out: list[StringLiteral] = []
        for node in ast.walk(self._tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                line = getattr(node, "lineno", 0)
                out.append(StringLiteral(node.value, line, self._snippet(line)))
        return out

    def assignments(self) -> list[Assignment]:
        out: list[Assignment] = []
        for node in ast.walk(self._tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                out.extend(self._assignments_from(node))
        return out
