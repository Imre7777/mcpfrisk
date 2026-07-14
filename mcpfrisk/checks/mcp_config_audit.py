"""MCP_CONFIG_AUDIT (Tier 1, statisch): prüft MCP-Client-/Projekt-Konfigurations-
dateien (claude_desktop_config.json, mcp.json, .mcp.json, .cursor/mcp.json, …)
auf riskante Server-Anbindungen.

Hintergrund (Research-Pass 2026-07-05, siehe specs/014-mcp-config-audit):
Die MCP-Config ist ein real ausgenutzter Angriffsvektor -- CVE-2025-59536
(RCE über in die Config eingecheckte Start-Kommandos), CVE-2026-21852
(`enableAllProjectMcpServers` leakt Quellcode / exfiltriert Keys), und ein
Ökosystem-Audit 2026 fand 79% Klartext-Credentials, 40% ohne Auth, 43%
command-injection-anfällig -- vieles davon manifestiert sich direkt in der
Config. Alle anderen McpFrisk-Checks lesen Server-QUELLCODE; dieser liest die
Config, über die Server gestartet und angebunden werden -- eine Coverage-Lücke,
die der direkte Konkurrent agent-audit abdeckt, McpFrisk bisher nicht.

Fünf Befund-Klassen (jede mit eigener Severity/CWE/OWASP-Ref):
- PLAINTEXT_SECRET  -- hartkodiertes Credential in env/headers (HIGH, CWE-798, MCP01)
- INJECTION_COMMAND -- Shell-Interpreter mit -c bzw. curl|sh-Pipe (HIGH, CWE-78, MCP05)
- UNPINNED_PACKAGE  -- ungepinntes npx/uvx/pip-Paket (MEDIUM, CWE-829, MCP04)
- AUTO_APPROVE_FLAG -- enableAllProjectMcpServers/autoApprove/… (MEDIUM, CWE-862, MCP07)
- REMOTE_NO_AUTH    -- remote url-Server ohne Auth-Header (LOW, CWE-306, MCP07)

Bewusst KEIN Import aus hardcoded_secrets.py (Prinzip II: keine Check-zu-Check-
Abhängigkeit) -- die Secret-Heuristik ist config-lokal und minimal.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

from mcpfrisk.core.base_check import BaseCheck
from mcpfrisk.core.fs import is_excluded, rglob_or_file
from mcpfrisk.core.models import Finding, Severity

# Bekannte MCP-Config-Dateinamen (starkes Signal). Zusätzlich wird JEDE *.json
# mit Top-Level-`mcpServers`/`servers` als Config behandelt (Struktur-Signal).
_KNOWN_CONFIG_NAMES = frozenset({
    "claude_desktop_config.json", "mcp.json", ".mcp.json",
    ".claude.json", "claude.json",
})
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# Config-lokale Secret-Heuristik (KEIN Import aus hardcoded_secrets.py).
_KNOWN_KEY_PREFIXES = re.compile(
    r"^(?:sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|AKIA|ASIA|ABIA|ACCA|xox[baprs]-)"
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_CREDENTIAL_KEY_NAME = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|credential|access[_-]?key|"
    r"auth|bearer|private[_-]?key)\b"
)
# Wert ist eine Referenz/Platzhalter, kein echtes Secret -> nie Finding.
_REFERENCE_VALUE = re.compile(r"^\s*(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%)\s*$")
_PLACEHOLDER_VALUES = frozenset({
    "", "changeme", "change-me", "your-api-key", "your-api-key-here", "todo",
    "xxx", "placeholder", "example", "none", "null",
})
_MIN_SECRET_LEN = 16
_ENTROPY_THRESHOLD = 3.2

# Shell-Interpreter, die als `command` mit `-c` eine Shell öffnen.
_SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh",
})
# Paket-Runner, deren Paket-Argument gepinnt sein sollte.
_PACKAGE_RUNNERS = frozenset({"npx", "bunx", "uvx", "pnpm", "pipx", "pip", "pip3"})
_PIPE_TO_SHELL = re.compile(r"(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b")

# Auto-Approve-/Enable-All-Flags (Top-Level oder pro Server).
_AUTO_APPROVE_KEYS = ("enableAllProjectMcpServers", "autoApprove", "alwaysAllow", "yolo")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_reference_or_placeholder(value: str) -> bool:
    if _REFERENCE_VALUE.match(value):
        return True
    return value.strip().lower() in _PLACEHOLDER_VALUES


def _looks_like_secret(key: str, value: str) -> bool:
    if not isinstance(value, str) or _is_reference_or_placeholder(value):
        return False
    # Für "Authorization"-Header den "Bearer "-Präfix abtrennen.
    candidate = value
    if value.lower().startswith("bearer "):
        candidate = value[len("bearer "):].strip()
        if _is_reference_or_placeholder(candidate):
            return False
    if _KNOWN_KEY_PREFIXES.search(candidate):
        return True
    if _CREDENTIAL_KEY_NAME.search(key) and len(candidate) >= _MIN_SECRET_LEN:
        return _shannon_entropy(candidate) > _ENTROPY_THRESHOLD
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***REDACTED***"
    return f"{value[:4]}***REDACTED***{value[-2:]}"


def _basename(command: str) -> str:
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _is_pinned(runner: str, pkg: str) -> bool:
    """True, wenn das Paket-Argument eine Version festnagelt."""
    if runner in ("pip", "pip3", "pipx"):
        return "==" in pkg or "@" in pkg.split("#egg=")[0][1:]  # x==1.2.3
    # npx/bunx/uvx/pnpm: gepinnt = ein @version NACH dem Paketnamen.
    # "@scope/name@1.2.3" -> pinned; "@scope/name" -> unpinned; "name@1.2.3" -> pinned.
    core = pkg[1:] if pkg.startswith("@") else pkg  # führendes Scope-@ ignorieren
    if "@" not in core:
        return False
    version = core.rsplit("@", 1)[1]
    return bool(version) and version.lower() != "latest"


class McpConfigAuditCheck(BaseCheck):
    check_id = "MCP_CONFIG_AUDIT"
    name = "MCP Client/Project Config Audit"
    description = (
        "Prüft MCP-Konfigurationsdateien (mcp.json / claude_desktop_config.json / "
        "…) auf hartkodierte Secrets, command-injection-anfällige oder ungepinnte "
        "Server-Starts, zu breite Auto-Approve-Flags und remote Server ohne Auth."
    )

    def applies_to(self, target_path: Path) -> bool:
        return any(True for _ in self._config_files(target_path))

    def run(self, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path, data in self._config_files(target_path):
            findings.extend(self._audit_config(path, data))
        return findings

    # -- discovery ---------------------------------------------------------
    def _config_files(self, target_path: Path):
        """Yield (path, parsed_data) für jede erkannte MCP-Config (Name ODER
        Struktur). Malformte/nicht-MCP-JSON werden übersprungen."""
        seen: set[Path] = set()
        for path in rglob_or_file(target_path, "*.json"):
            if path in seen:
                continue
            seen.add(path)
            if is_excluded(path, target_path):
                continue
            if any(suf in path.name.lower() for suf in _TEMPLATE_SUFFIXES):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            is_known = path.name in _KNOWN_CONFIG_NAMES
            has_servers = isinstance(data.get("mcpServers"), dict) or isinstance(data.get("servers"), dict)
            if is_known or has_servers:
                if has_servers:  # nur wirklich verwertbare Configs auditieren
                    yield path, data

    @staticmethod
    def _servers(data: dict) -> dict:
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = data.get("servers")
        return servers if isinstance(servers, dict) else {}

    # -- auditing ----------------------------------------------------------
    def _audit_config(self, path: Path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        # Top-Level Auto-Approve-/Enable-All-Flags.
        findings.extend(self._auto_approve_findings(path, data, scope="config"))

        for name, cfg in self._servers(data).items():
            if not isinstance(cfg, dict):
                continue
            findings.extend(self._secret_findings(path, name, cfg))
            findings.extend(self._command_findings(path, name, cfg))
            findings.extend(self._auto_approve_findings(path, cfg, scope=f"mcpServers.{name}"))
            findings.extend(self._remote_auth_findings(path, name, cfg))
        return findings

    def _secret_findings(self, path: Path, name: str, cfg: dict) -> list[Finding]:
        out: list[Finding] = []
        for block in ("env", "headers"):
            values = cfg.get(block)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if not isinstance(value, str) or not _looks_like_secret(str(key), value):
                    continue
                out.append(Finding(
                    check_id=self.check_id,
                    severity=Severity.HIGH,
                    title=f"Hartkodiertes Credential in MCP-Config ('{name}'.{block}.{key})",
                    description=(
                        f"Der Server '{name}' trägt in seinem '{block}'-Block ein "
                        f"hartkodiertes Credential ({key}={_redact(value)}) statt es aus "
                        "der Host-Umgebung zu referenzieren. Gelangt die Config ins "
                        "Versionskontrollsystem, ist das Secret dauerhaft geleakt."
                    ),
                    file_path=path,
                    line_number=None,
                    snippet=f"mcpServers.{name}.{block}.{key} = {_redact(value)}",
                    owasp_mcp_ref="MCP01",
                    cwe_ref="CWE-798",
                    remediation=(
                        "Credential aus der Config entfernen und über eine Umgebungs-"
                        "variablen-Referenz laden (z.B. \"API_KEY\": \"${API_KEY}\") "
                        "bzw. einen Secret-Manager. Das exponierte Secret rotieren."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/798.html",
                                "https://owasp.org/www-project-mcp-top-10/"],
                ))
        return out

    def _command_findings(self, path: Path, name: str, cfg: dict) -> list[Finding]:
        command = cfg.get("command")
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        str_args = [a for a in args if isinstance(a, str)]
        out: list[Finding] = []
        if not isinstance(command, str) or not command:
            return out
        base = _basename(command)

        # (a) Shell-Interpreter mit -c.
        if base in _SHELL_INTERPRETERS and any(a == "-c" or a == "/c" for a in str_args):
            out.append(self._injection_finding(path, name, command, str_args,
                "Der Server wird über einen Shell-Interpreter mit '-c' gestartet -- "
                "der übergebene Befehl wird als Shell-String ausgeführt. Wird die "
                "Config manipuliert, ist das direkte Code-Ausführung beim Client-Start."))
            return out

        # (b) curl|wget ... | sh in irgendeinem Argument.
        if any(_PIPE_TO_SHELL.search(a) for a in str_args):
            out.append(self._injection_finding(path, name, command, str_args,
                "Ein Startargument lädt ein Skript herunter und pipet es in eine Shell "
                "(curl|wget … | sh) -- ungeprüfte Remote-Code-Ausführung beim Client-Start."))
            return out

        # (c) ungepinntes Paket bei einem Runner.
        if base in _PACKAGE_RUNNERS:
            pkg = self._package_arg(base, str_args)
            if pkg is not None and not _is_pinned(base, pkg):
                out.append(Finding(
                    check_id=self.check_id,
                    severity=Severity.MEDIUM,
                    title=f"Ungepinntes MCP-Server-Paket ('{name}': {base} {pkg})",
                    description=(
                        f"Der Server '{name}' wird über '{base}' mit dem UNGEPINNTEN "
                        f"Paket '{pkg}' gestartet. Ohne Versions-Pin zieht jeder Start die "
                        "jeweils neueste Version -- ein kompromittiertes Update (Rug-Pull/"
                        "Supply-Chain) wird ungeprüft ausgeführt."
                    ),
                    file_path=path,
                    line_number=None,
                    snippet=f"mcpServers.{name}: {command} {' '.join(str_args)}",
                    owasp_mcp_ref="MCP04",
                    cwe_ref="CWE-829",
                    remediation=(
                        f"Das Paket auf eine geprüfte Version festnageln (z.B. "
                        f"'{pkg}@1.2.3' bzw. '{pkg}==1.2.3') und Updates bewusst nachziehen."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/829.html",
                                "https://owasp.org/www-project-mcp-top-10/"],
                ))
        return out

    @staticmethod
    def _package_arg(runner: str, args: list[str]) -> str | None:
        """Das Paket-Argument nach den Flags (npx -y <pkg>, pipx run <pkg>, …)."""
        skip_next = False
        subcmds = {"run", "install", "exec", "dlx"}
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a in ("-p", "--package"):
                skip_next = True
                continue
            if a.startswith("-"):
                continue
            if a in subcmds:
                continue
            return a
        return None

    def _injection_finding(self, path: Path, name: str, command: str,
                           args: list[str], detail: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=Severity.HIGH,
            title=f"Command-Injection-anfälliger MCP-Server-Start ('{name}')",
            description=f"Server '{name}': {detail}",
            file_path=path,
            line_number=None,
            snippet=f"mcpServers.{name}: {command} {' '.join(args)}",
            owasp_mcp_ref="MCP05",
            cwe_ref="CWE-78",
            remediation=(
                "Den Server ohne Shell-Umweg starten: das Programm direkt als "
                "'command' mit einer festen Argument-Liste angeben (keine 'sh -c'-"
                "Verkettung, keine 'curl | sh'-Pipe)."
            ),
            references=["https://cwe.mitre.org/data/definitions/78.html",
                        "https://owasp.org/www-project-mcp-top-10/"],
        )

    def _auto_approve_findings(self, path: Path, obj: dict, scope: str) -> list[Finding]:
        out: list[Finding] = []
        for key in _AUTO_APPROVE_KEYS:
            if key not in obj:
                continue
            val = obj[key]
            # Nur ein aktiv gesetztes Flag melden (True bzw. nicht-leere Liste).
            if val is True or (isinstance(val, list) and val) or val == "true":
                out.append(Finding(
                    check_id=self.check_id,
                    severity=Severity.MEDIUM,
                    title=f"Zu breites Auto-Approve-Flag in MCP-Config ('{key}')",
                    description=(
                        f"Das Flag '{key}' ({scope}) lässt MCP-Server bzw. Tool-Aufrufe "
                        "ohne menschliche Bestätigung laufen. Ein untergeschobener oder "
                        "geänderter Server wird so ungeprüft ausgeführt "
                        "(CVE-2026-21852-Klasse)."
                    ),
                    file_path=path,
                    line_number=None,
                    snippet=f"{scope}.{key} = {json.dumps(val, ensure_ascii=False)}",
                    owasp_mcp_ref="MCP07",
                    cwe_ref="CWE-862",
                    remediation=(
                        "Auto-Approve/Enable-All abschalten und Tool-Aufrufe bzw. neue "
                        "Projekt-Server bewusst einzeln freigeben (Human-in-the-Loop)."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/862.html",
                                "https://owasp.org/www-project-mcp-top-10/"],
                ))
        return out

    def _remote_auth_findings(self, path: Path, name: str, cfg: dict) -> list[Finding]:
        url = cfg.get("url")
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            return []
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        has_auth = any(
            k.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token")
            or "auth" in k.lower() or "token" in k.lower() or "api-key" in k.lower()
            for k in headers
        )
        if has_auth:
            return []
        return [Finding(
            check_id=self.check_id,
            severity=Severity.LOW,
            title=f"Remote MCP-Server ohne Auth-Header ('{name}')",
            description=(
                f"Der remote Server '{name}' ({url}) wird ohne erkennbaren "
                "Auth-Header angebunden. Falls der Endpunkt Authentifizierung "
                "erwartet/erfordert, fehlt sie hier -- bitte verifizieren."
            ),
            file_path=path,
            line_number=None,
            snippet=f"mcpServers.{name}.url = {url} (keine Auth-Header)",
            owasp_mcp_ref="MCP07",
            cwe_ref="CWE-306",
            remediation=(
                "Für remote MCP-Endpunkte einen Auth-Header setzen (z.B. "
                "\"headers\": {\"Authorization\": \"Bearer ${TOKEN}\"}) und das "
                "Token aus der Umgebung referenzieren."
            ),
            references=["https://cwe.mitre.org/data/definitions/306.html",
                        "https://owasp.org/www-project-mcp-top-10/"],
        )]
