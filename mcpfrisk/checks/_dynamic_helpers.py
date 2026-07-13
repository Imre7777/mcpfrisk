"""Geteilte, check-agnostische Helfer für die call()-basierten Tier-2-Checks.

Dies ist KEIN Check (kein `BaseCheck`/`BaseDynamicCheck`) und importiert KEINEN
Check -- ein reines Utility-Modul, genau wie `_ssrf_callback.py`. Die vier
dynamischen Checks SCHEMA_FUZZING, ERROR_LEAKAGE, RBAC_CROSS_TENANT und
RATE_LIMITING teilen sich Tool-Klassifikation, Schema-Zugriff und (schema_fuzzing
/error_leakage) die Leak-Marker. Vor Feature 013 war das in jedem Check
byte-identisch dupliziert -- ein latentes Drift-Risiko: eine Verbesserung an
einer Stelle (z.B. ein neuer Go-/Rust-Panic-Marker) wäre nicht automatisch für
die anderen gegolten und hätte einen asymmetrischen False Negative erzeugt, den
kein Test fängt. Hier gibt es jetzt EINEN Ort der Wahrheit.

Plugin-Isolation (Prinzip II) bleibt gewahrt: die Checks *nutzen* diese Utility,
sie *hängen* nicht voneinander ab -- ein Check bleibt in Isolation reviewbar
und entfernbar.
"""
from __future__ import annotations

import re

# Tool-Klassifikation: nur lesend klassifizierte Tools werden geprobt/belastet;
# mutierende (MUTATE_HINTS) niemals -- konservativ, damit der Check keine Daten
# verändert (Read-only-Garantie aller vier Checks).
READ_HINTS = ("get", "list", "read", "fetch", "search", "view", "show", "find", "query", "describe")
MUTATE_HINTS = (
    "create", "update", "delete", "write", "set", "remove", "patch", "put",
    "add", "insert", "modify", "drop", "revoke", "grant", "upload",
)

# Obergrenze für einen secret-bereinigten Beleg-Ausschnitt.
EVIDENCE_MAX = 200

# Konservative Leak-Marker -- eindeutig genug, um FP-arm zu bleiben (Prinzip III):
# rohe Tracebacks, Exception-Klassennamen, absolute Pfade, SQL-Fehlertexte.
_EXCEPTION_CLASS_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]*(?:Error|Exception)\b")
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)")
_PY_FRAME_RE = re.compile(r'File "[^"]+", line \d+')
_JS_FRAME_RE = re.compile(r"at (?:Object\.<anonymous>|[\w.$]+ \()")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\s\"'\\]+\\)+[^\s\"'\\]+")
# Absoluter Dateisystem-Pfad als Leak-Marker -- bewusst NICHT jeder `/a/b`-Pfad
# (das flaggte harmlose URL-Routen wie `/api/v1/users` in Fehlermeldungen als
# vermeintliches Interna-Leak -> FP, Review 2026-07). Nur ein Pfad unter einem
# bekannten System-/App-Root ODER einer, der auf eine Quell-/Config-Dateiendung
# endet, gilt als geleakter interner Pfad (Traceback-Frames deckt _PY_FRAME_RE
# ohnehin separat ab).
_UNIX_PATH_RE = re.compile(
    r"/(?:etc|usr|var|home|root|tmp|opt|bin|sbin|lib|lib64|proc|sys|mnt|srv|dev|"
    r"boot|run|private|Users|Applications|Library|System|app|code|workspace)/[\w.\-/]+"
    r"|/(?:[\w.\-]+/)+[\w.\-]+\."
    r"(?:py|pyc|js|mjs|cjs|jsx|ts|tsx|rb|go|java|php|rs|cpp|hpp|cs|sh|bash|"
    r"conf|cfg|ini|ya?ml|toml|log|sql|sqlite3?|db|pem|key)\b"
)
_SQL_ERROR_RE = re.compile(
    r"SQLSTATE\[|ORA-\d{5}|sqlite3\.\w*Error|You have an error in your SQL syntax"
)
LEAK_PATTERNS = (
    _TRACEBACK_RE, _PY_FRAME_RE, _JS_FRAME_RE, _WIN_PATH_RE, _UNIX_PATH_RE,
    _SQL_ERROR_RE, _EXCEPTION_CLASS_RE,
)


def is_read_tool(name: str) -> bool:
    """True für lesend klassifizierte Tool-Namen. Ein mutierender Hint gewinnt
    immer (konservativ: nie ein potenziell mutierendes Tool proben)."""
    n = name.lower()
    if any(h in n for h in MUTATE_HINTS):
        return False
    return any(h in n for h in READ_HINTS)


def tool_properties(tool: dict) -> dict:
    """Das `properties`-Objekt des Tool-`inputSchema` (leeres dict, wenn fehlend
    oder malformt)."""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def tool_required(tool: dict) -> set[str]:
    """Die Menge der Pflicht-Parameter des Tool-`inputSchema` (leer, wenn
    fehlend oder malformt)."""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    req = schema.get("required") if isinstance(schema, dict) else None
    return set(req) if isinstance(req, list) else set()


def find_leak(text: str) -> str | None:
    """Erster Leak-Marker-Treffer in `text` (Traceback/Exception/absoluter
    Pfad/SQL-Fehler) als gematchter Ausschnitt, sonst None."""
    for pattern in LEAK_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def truncate(text: str, limit: int = EVIDENCE_MAX) -> str:
    """Kürzt einen Beleg-Ausschnitt auf `limit` Zeichen (mit …-Suffix)."""
    return text if len(text) <= limit else text[:limit] + "…"
