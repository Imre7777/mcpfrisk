"""TYPOSQUAT (Tier 1, statisch): erkennt Dependency-Namen in Manifesten, die einem
bekannten populären MCP-Paket verwechselbar ähnlich -- aber nicht identisch --
sind (Typosquatting / Dependency-Confusion).

Hintergrund (Research-Pass 2026-07-12, siehe specs/018-typosquat-check):
Typosquatting ist eine der meistgenutzten Supply-Chain-Angriffsklassen auf
npm/PyPI -- ein bösartiges Paket unter einem Namen, der sich nur um ein Zeichen
oder eine Vertauschung von einem populären Paket unterscheidet. Das MCP-
Ökosystem hat wenige, sehr populäre Kern-Pakete (`@modelcontextprotocol/*`,
`mcp`, `fastmcp`), die attraktive Squatting-Ziele sind.

FP-Disziplin (Prinzip III -- Typosquat-Checks sind notorisch FP-anfällig):
Kandidaten werden NUR gegen eine kleine, kuratierte Allowlist bekannter MCP-
Pakete verglichen (npm ⟷ npm, PyPI ⟷ PyPI), nie gegen das ganze Ökosystem.
Geflaggt wird nur, wenn ein Kandidat (a) nicht exakt in der Allowlist steht UND
(b) in Damerau-Levenshtein-Distanz ≤ 1 zu einem Allowlist-Eintrag liegt. Ein
beliebiges Projekt-Paket (`express`, `requests`) ist zu keinem MCP-Kernpaket nah
und wird nie geflaggt. OWASP MCP04 (Supply Chain), CWE-829.

Der Distanz-Helfer liegt im geteilten Nicht-Check-Modul `_name_similarity.py`
(kein Check-zu-Check-Import, Constitution II).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from mcpfrisk.checks._name_similarity import damerau_le_1
from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import is_excluded, rglob_or_file
from mcpfrisk.core.models import Finding, Severity

_MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml")
# Namen unter dieser Länge werden nicht verglichen -- Distanz 1 ist bei sehr
# kurzen Namen fast immer erfüllt (FP-Quelle). Das kurze Kernpaket `mcp` ist
# daher bewusst kein Vergleichsziel.
_MIN_LEN = 5

# --- Kuratierte Allowlists (Prinzip VII: das MCP-Ökosystem verschiebt sich
# schnell -- diese Listen periodisch gegen die offiziellen Registries auffrischen;
# bewusst KLEIN gehalten, damit sie wartbar bleiben und die FP-Fläche winzig ist).
# npm-Namen lowercase; PyPI-Namen PEP-503-normalisiert (siehe _norm_pypi).
_KNOWN_NPM = frozenset({
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/inspector",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-google-drive",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
})
_KNOWN_PYPI = frozenset({
    "fastmcp",
    "modelcontextprotocol",
    "mcp-server-git",
    "mcp-server-fetch",
    "mcp-server-time",
    "mcp-server-sqlite",
    "mcp-server-fetch-python",
})

_NAME_HEAD = re.compile(r"^\s*([A-Za-z0-9._@/-]+)")


def _norm_npm(name: str) -> str:
    return name.strip().lower()


def _norm_pypi(name: str) -> str:
    """PEP-503-Normalisierung: lowercase, Läufe von `._-` zu einem `-`."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _pkg_head(requirement: str) -> str | None:
    """Extrahiert den Paketnamen aus einem PEP-508-/requirements-Eintrag
    (`name[extra]>=1.0` -> `name`). Extras/Version/Marker werden abgetrennt."""
    m = re.match(r"^([A-Za-z0-9._-]+)", requirement.strip())
    return m.group(1) if m else None


def _from_package_json(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            out.update(k for k in deps if isinstance(k, str) and k)
    return out


def _from_requirements(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # Kommentar / Option (-r, --index-url, -e) überspringen
        head = _pkg_head(line)
        if head:
            out.add(head)
    return out


def _from_pyproject(text: str) -> set[str]:
    try:
        import tomllib  # stdlib ab Python 3.11
    except ImportError:
        return set()  # 3.10: pyproject sauber überspringen (kein Crash)
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    out: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        for dep in project.get("dependencies") or []:
            if isinstance(dep, str):
                head = _pkg_head(dep)
                if head:
                    out.add(head)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                for dep in group or []:
                    if isinstance(dep, str):
                        head = _pkg_head(dep)
                        if head:
                            out.add(head)
    # Poetry-Stil
    poetry = (data.get("tool") or {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        pdeps = poetry.get("dependencies")
        if isinstance(pdeps, dict):
            out.update(k for k in pdeps if isinstance(k, str) and k.lower() != "python")
    return out


class TyposquatCheck(BaseCheck):
    check_id = "TYPOSQUAT"
    name = "Dependency Typosquatting"
    description = (
        "Prüft Dependency-Manifeste (package.json/requirements.txt/pyproject.toml) "
        "auf Paketnamen, die einem bekannten populären MCP-Paket verwechselbar "
        "ähnlich -- aber nicht identisch -- sind (Typosquatting)."
    )

    def _manifests(self, target_path: Path) -> list[Path]:
        seen: set[Path] = set()
        for pattern in _MANIFESTS:
            for path in rglob_or_file(target_path, pattern):
                if is_excluded(path, target_path):
                    continue
                seen.add(path)
        return sorted(seen)

    def applies_to(self, target_path: Path) -> bool:
        return bool(self._manifests(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for manifest in self._manifests(target_path):
            text = _read(manifest)
            if manifest.name == "package.json":
                candidates = ((c, _norm_npm, _KNOWN_NPM, "npm") for c in _from_package_json(text))
            elif manifest.name == "requirements.txt":
                candidates = ((c, _norm_pypi, _KNOWN_PYPI, "PyPI") for c in _from_requirements(text))
            else:  # pyproject.toml
                candidates = ((c, _norm_pypi, _KNOWN_PYPI, "PyPI") for c in _from_pyproject(text))
            for raw, norm, known, ecosystem in candidates:
                match = self._nearest_known(norm(raw), known)
                if match is None:
                    continue
                key = (str(manifest), raw)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(manifest, raw, match, ecosystem))
        return findings

    @staticmethod
    def _nearest_known(name: str, known: frozenset[str]) -> str | None:
        """Das ähnliche bekannte Paket, falls `name` ein Beinahe-Treffer ist:
        nicht exakt bekannt, Mindestlänge erfüllt, Damerau-Distanz ≤ 1 zu einem
        Allowlist-Eintrag. Sonst None."""
        if len(name) < _MIN_LEN or name in known:
            return None
        for candidate_known in known:
            if len(candidate_known) < _MIN_LEN:
                continue
            if damerau_le_1(name, candidate_known):
                return candidate_known
        return None

    def _finding(self, manifest: Path, raw: str, known: str, ecosystem: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.MEDIUM,
            title=f"Mögliches Typosquat-Paket '{raw}'",
            description=(
                f"Die {ecosystem}-Dependency '{raw}' ist dem bekannten MCP-Paket "
                f"'{known}' verwechselbar ähnlich (Namensdistanz 1), aber nicht "
                "identisch. Das ist das typische Muster von Typosquatting: ein "
                "bösartiges Paket unter einem Namen, der sich nur um ein Zeichen "
                "oder eine Vertauschung vom Original unterscheidet -- ein "
                "Tippfehler beim Install zieht dann das Angreifer-Paket samt "
                "dessen Code/Install-Skripten ins Projekt."
            ),
            file_path=manifest,
            line_number=None,
            snippet=f"'{raw}' ~ '{known}'  ({manifest.name})",
            owasp_mcp_ref="MCP04",
            cwe_ref="CWE-829",
            remediation=(
                f"Den Paketnamen prüfen: ist '{known}' gemeint? Wenn ja, exakt "
                "diesen Namen verwenden und gepinnt (mit Integritäts-Hash/Lockfile) "
                f"installieren. Wenn '{raw}' bewusst eine andere, legitime "
                "Dependency ist, kann der Befund ignoriert werden. Nie ein Paket "
                "installieren, dessen Name nur knapp neben einem bekannten liegt, "
                "ohne den Herausgeber zu verifizieren."
            ),
            references=[
                "https://owasp.org/www-project-mcp-top-10/",
                "https://cwe.mitre.org/data/definitions/829.html",
            ],
        )
