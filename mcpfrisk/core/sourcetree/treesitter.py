"""TreeSitterAdapter: implementiert den SourceModel-Port für JS/TS/TSX.

tree-sitter ist fehlertolerant (Prinzip: lieber ein partieller Baum als ein
Crash), liefert vorkompilierte Wheels und deckt TS/TSX/JSX ab. Der Import
erfolgt *lazy* (erst beim ersten echten Parse), damit der Basis-Install ohne
das `jsts`-Extra weder beim Import des Pakets noch beim Python-only-Scan
scheitert -- fehlt das Extra, meldet ``available()`` False und der Aufrufer
überspringt JS/TS-Dateien sauber.
"""
from __future__ import annotations

import functools
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

_ENV_HINTS = ("process.env", "import.meta.env", "dotenv")
_FUNC_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
}
_STRING_TYPES = {"string", "template_string"}


@functools.lru_cache(maxsize=1)
def _languages():
    """Lädt die Grammatiken einmalig. Gibt None zurück, wenn das `jsts`-Extra fehlt."""
    try:
        from tree_sitter import Language
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts

        return {
            SourceLanguage.JAVASCRIPT: Language(tsjs.language()),
            SourceLanguage.TYPESCRIPT: Language(tsts.language_typescript()),
            SourceLanguage.TSX: Language(tsts.language_tsx()),
        }
    except Exception:
        return None


def available() -> bool:
    return _languages() is not None


def parse_file(path: Path, language: SourceLanguage) -> SourceModel:
    langs = _languages()
    if langs is None:
        return UnparsedModel(path, language)
    from tree_sitter import Parser

    data = path.read_bytes()
    parser = Parser(langs[language])
    tree = parser.parse(data)
    return JsTsSourceModel(path, language, data, tree)


class JsTsSourceModel(SourceModel):
    def __init__(self, path: Path, language: SourceLanguage, data: bytes, tree) -> None:
        self.path = path
        self.language = language
        self.ok = True
        self._data = data
        self._root = tree.root_node
        self._lines = data.decode("utf-8", "replace").splitlines()
        self._import_aliases = self._build_import_aliases()

    # -- helpers -----------------------------------------------------------

    def _build_import_aliases(self) -> dict[str, str]:
        """Bildet 'lokaler Name -> Original-Name' für benannte Import-Aliase
        (`import { exec as run } from "child_process"`), damit der lokale Alias
        `run` bei der Gefährlichkeits-Prüfung als `exec` erkannt wird -- sonst
        umgeht jeder Import-Alias die dangerous-segment-Erkennung vollständig
        (Bug: Import-Alias-Bypass)."""
        aliases: dict[str, str] = {}
        for n in self._walk():
            if n.type != "import_specifier":
                continue
            name_node = n.child_by_field_name("name")
            alias_node = n.child_by_field_name("alias")
            if name_node is None or alias_node is None:
                continue
            aliases[self._text(alias_node)] = self._text(name_node)
        return aliases

    def _text(self, node) -> str:
        return self._data[node.start_byte:node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _line(node) -> int:
        return node.start_point[0] + 1

    def _snippet(self, node) -> str:
        ln = self._line(node)
        if 0 < ln <= len(self._lines):
            return self._lines[ln - 1].strip()
        return self._text(node)[:200]

    def _walk(self, start=None):
        stack = [start or self._root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.named_children))

    def _member_name(self, node) -> str:
        if node is None:
            return ""
        if node.type == "identifier":
            return self._import_aliases.get(self._text(node), self._text(node))
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            base = self._member_name(obj)
            pn = self._text(prop) if prop else ""
            return f"{base}.{pn}" if base else pn
        if node.type == "subscript_expression":
            # Computed member access mit String-Literal-Index (cp["exec"]) auf
            # eine reguläre member_expression abbilden -- ein nicht-literaler
            # Index (cp[dynamicKey]) bleibt statisch nicht auflösbar.
            obj = node.child_by_field_name("object")
            idx = node.child_by_field_name("index")
            base = self._member_name(obj)
            if idx is not None and idx.type in _STRING_TYPES:
                prop = self._string_value(idx)
                return f"{base}.{prop}" if base else prop
            return self._text(node)
        return self._text(node)

    def _identifiers(self, node) -> set[str]:
        out: set[str] = set()
        stack = [node]
        while stack:
            x = stack.pop()
            if x.type == "identifier":
                out.add(self._text(x))
            stack.extend(x.named_children)
        return out

    def _string_value(self, node) -> str:
        frags = [self._text(c) for c in node.named_children if c.type == "string_fragment"]
        if frags:
            return "".join(frags)
        t = self._text(node)
        # Anführungszeichen / Backticks entfernen
        return t[1:-1] if len(t) >= 2 and t[0] in "\"'`" else t

    def _arg(self, node) -> Argument:
        a = Argument(text=self._text(node))
        a.referenced_names = self._identifiers(node)
        t = node.type
        if t == "array":
            a.is_array = True
            a.array_items = [self._arg(el) for el in node.named_children]
        elif t == "string":
            a.is_constant_string = True
        elif t == "template_string":
            if any(c.type == "template_substitution" for c in node.named_children):
                a.has_interpolation = True
            else:
                a.is_constant_string = True
        elif t == "true":
            a.is_truthy_constant = True
        elif t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self._text(op) == "+" and a.referenced_names:
                a.has_interpolation = True
        return a

    def _call(self, node) -> CallSite:
        callee = self._member_name(node.child_by_field_name("function"))
        argnode = node.child_by_field_name("arguments")
        args = [self._arg(a) for a in argnode.named_children] if argnode else []
        return CallSite(
            callee=callee,
            line=self._line(node),
            snippet=condense_snippet(self._text(node)),
            args=args,
        )

    def _assignment_from(self, node) -> Assignment | None:
        if node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            target = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
        else:
            return None
        if target is None:
            return None
        lit = None
        if value is not None and value.type in _STRING_TYPES:
            lit = StringLiteral(self._string_value(value), self._line(node), self._snippet(node))
        seg = self._text(value) if value is not None else ""
        refs = self._identifiers(value) if value is not None else set()
        return Assignment(
            target_name=self._text(target),
            line=self._line(node),
            value=lit,
            value_is_env_lookup=any(h in seg for h in _ENV_HINTS),
            referenced_names=refs,
        )

    def _params(self, node) -> list[str]:
        names: list[str] = []
        p = node.child_by_field_name("parameters")
        if p is not None:
            for c in p.named_children:
                ident = self._first_identifier(c)
                if ident:
                    names.append(ident)
        else:
            single = node.child_by_field_name("parameter")
            if single is not None:
                ident = self._first_identifier(single)
                if ident:
                    names.append(ident)
        return names

    def _first_identifier(self, node):
        if node.type == "identifier":
            return self._text(node)
        for c in node.named_children:
            r = self._first_identifier(c)
            if r:
                return r
        return None

    # -- port queries ------------------------------------------------------

    def call_sites(self) -> list[CallSite]:
        return [self._call(n) for n in self._walk() if n.type == "call_expression"]

    def functions(self) -> list[FunctionDef]:
        out: list[FunctionDef] = []
        for n in self._walk():
            if n.type not in _FUNC_TYPES:
                continue
            nm = n.child_by_field_name("name")
            name = self._text(nm) if nm else ""
            body = n.child_by_field_name("body")
            body_calls = []
            body_assignments = []
            if body is not None:
                for x in self._walk(body):
                    if x.type == "call_expression":
                        body_calls.append(self._call(x))
                    elif x.type in ("variable_declarator", "assignment_expression"):
                        a = self._assignment_from(x)
                        if a is not None:
                            body_assignments.append(a)
            out.append(
                FunctionDef(
                    name=name,
                    line=self._line(n),
                    params=self._params(n),
                    decorators=[],
                    body_calls=body_calls,
                    body_assignments=body_assignments,
                    body_text=self._text(body) if body is not None else "",
                )
            )
        return out

    def tool_definitions(self) -> list[ToolDefinition]:
        out: list[ToolDefinition] = []
        for n in self._walk():
            if n.type != "call_expression":
                continue
            callee = self._member_name(n.child_by_field_name("function"))
            if not (callee == "tool" or callee.endswith(".tool") or callee.endswith(".registerTool")):
                continue
            name, description = self._tool_meta(n)
            out.append(ToolDefinition(name, description, self._line(n)))
        return out

    def _tool_meta(self, node) -> tuple[str, str]:
        argnode = node.child_by_field_name("arguments")
        name = ""
        strings: list[str] = []
        if argnode is not None:
            for a in argnode.named_children:
                if a.type in _STRING_TYPES:
                    val = self._string_value(a)
                    if not name and a.type == "string":
                        name = val
                    strings.append(val)
                elif a.type == "object":
                    for key in ("description", "name"):
                        v = self._object_prop(a, key)
                        if v is not None:
                            if key == "name" and not name:
                                name = v
                            else:
                                strings.append(v)
        return name, " ".join(strings)

    def _object_prop(self, obj, key: str):
        for pair in obj.named_children:
            if pair.type != "pair":
                continue
            k = pair.child_by_field_name("key")
            v = pair.child_by_field_name("value")
            if k is not None and v is not None and self._text(k).strip("\"'") == key:
                if v.type in _STRING_TYPES:
                    return self._string_value(v)
                return self._text(v)
        return None

    def string_literals(self) -> list[StringLiteral]:
        out: list[StringLiteral] = []
        for n in self._walk():
            if n.type in _STRING_TYPES:
                out.append(StringLiteral(self._string_value(n), self._line(n), self._snippet(n)))
        return out

    def assignments(self) -> list[Assignment]:
        out: list[Assignment] = []
        for n in self._walk():
            if n.type in ("variable_declarator", "assignment_expression"):
                a = self._assignment_from(n)
                if a is not None:
                    out.append(a)
        return out
