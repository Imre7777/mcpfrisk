# Feature Specification: DEPENDENCY_SCAN (Tier 1, statisch, tool-gestützt)

**Feature Branch**: `019-dependency-scan`

**Created**: 2026-07-12

**Status**: Design entschieden — in Implementierung. Phase 3 (Tier 3, Supply-
Chain) des "Top-Produkt zuerst"-Plans. Bewusst ein **Wrapper**, kein Nachbau.

**Input**: Die Dependency-Manifeste/Lockfiles eines MCP-Servers, die bekannte
verwundbare Paketversionen (CVEs) enthalten — erkannt durch **Delegation an
`osv-scanner`**, dessen JSON-Output McpFrisk in seine einheitliche Finding-/
SARIF-/Baseline-Pipeline übersetzt.

## Kontext / Motivation

**Sicherheits-Recherche + Design-Prinzip (Prinzip VII + Design-Prinzip 3, Stand
2026-07-12):** McpFrisks eigenes Design-Prinzip ist explizit *„Don't reinvent
existing good tools. For dependency scanning there is osv-scanner/Snyk … McpFrisk
wraps these rather than duplicating them."* Bekannte verwundbare Dependencies
sind ein realer Angriffsvektor auch bei MCP-Servern (die Server sind normale
npm/PyPI-Projekte). Statt eine eigene CVE-Datenbank zu bauen (fehleranfällig,
wartungsintensiv, immer veraltet), delegiert McpFrisk an **`osv-scanner`** (Google
OSV, multi-Ökosystem: npm + PyPI + mehr, stabiles JSON-Schema, ein
selbst-enthaltenes Binary) und **vereinheitlicht** dessen Ergebnisse mit den
MCP-spezifischen Findings — EIN CI-Gate, EIN Report, EIN Exit-Code, dieselbe
Baseline-/SARIF-Mechanik.

**Zero-Dep-Kern bleibt gewahrt (Prinzip IV):** `osv-scanner` ist **kein** Teil
des Basis-Installs. Der Check erkennt das Binary über den PATH; **fehlt es, ist
der Check sauber „skipped"** (kein Crash, kein stiller „clean"). Wer Dependency-
Scanning will, installiert `osv-scanner` separat (dokumentiert). So bleibt der
Basis-Install dependency-frei.

**OWASP/CWE-Mapping:** OWASP **MCP04** (Supply Chain / verwundbare Dependency);
die konkrete Referenz pro Finding ist die **CVE-/GHSA-/OSV-ID** aus osv-scanner
(kein eigenes CWE-Mapping — die Advisory trägt ihre eigenen Referenzen).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Verwundbare Dependency wird gemeldet (Priority: P1)

Als MCP-Server-Autor:in möchte ich in demselben CI-Gate wie meine MCP-spezifischen
Checks gewarnt werden, wenn eine Dependency eine bekannte Schwachstelle (CVE) hat.

**Why this priority**: der Kern-Zweck; ein einheitliches Gate statt zweier
getrennter Tools.

**Independent Test**: Ein injizierter Tool-Runner liefert einen osv-scanner-
JSON-Report mit einer verwundbaren `requests 2.19.0` (CVE-2018-18074) →
1 Finding (Severity aus der Advisory abgeleitet), das Paket + Version + CVE-/OSV-
ID + Fix-Version nennt. Ein „keine Schwachstellen"-Report → 0 Findings.

**Acceptance Scenarios**:

1. **Given** ein osv-scanner-Report mit ≥ 1 Vulnerability, **When** der Check die
   Ausgabe übersetzt, **Then** je (Paket, Version, Vuln-ID) ein Finding (MCP04)
   mit abgeleiteter Severity + Advisory-Referenzen + Fix-Hinweis.
2. **Given** ein Report ohne Vulnerabilities, **When** der Check läuft, **Then**
   0 Findings (echt sauber).

---

### User Story 2 — Severity-Ableitung (Priority: P2)

Als Reviewer:in möchte ich, dass die Advisory-Severity sinnvoll auf McpFrisks
Skala abgebildet wird (CVSS/Label), damit `--fail-on` funktioniert.

**Independent Test**: CVSS-Score 9.8 → CRITICAL; 7.5 → HIGH; 5.0 → MEDIUM;
2.0 → LOW; unbekannt → MEDIUM (konservativer Default).

**Acceptance Scenarios**:

1. **Given** eine Vulnerability mit CVSS/Label-Severity, **When** übersetzt wird,
   **Then** die Finding-Severity entspricht der Abbildungstabelle.

---

### User Story 3 — Sichere Degradation (Priority: P3)

Als Nutzer:in möchte ich, dass ein fehlendes Tool / ein Tool-Fehler / malformter
Output nie einen Crash oder einen falschen „clean" erzeugt.

**Acceptance Scenarios**:

1. **Given** `osv-scanner` ist nicht installiert, **When** gescannt wird, **Then**
   ist der Check „skipped" (`applies_to` False) — transparent, kein Finding.
2. **Given** das Tool bricht ab / liefert kein JSON, **When** der Check läuft,
   **Then** ein einzelnes **INFO**-Finding „Dependency-Scan nicht abschließbar"
   (transparent, kein Crash, kein stiller Pass) und KEINE Vuln-Findings.
3. **Given** ein Manifest ist vorhanden, aber `osv-scanner` fehlt, **When**
   gescannt wird, **Then** „skipped" (nicht „run").

---

### Edge Cases

- **Exit-Code 1 = Vulns gefunden** (osv-scanner-Konvention), NICHT ein Fehler —
  der JSON-Output auf stdout wird trotzdem geparst. Nur andere Exit-Codes gelten
  als Tool-Fehler.
- **Read-only**: der Wrapper ruft `osv-scanner` nur lesend auf; keine Netz-/
  Datei-Mutation durch McpFrisk selbst (osv-scanner fragt seine DB an — das ist
  gewollt und dokumentiert).
- **Kein Manifest im Ziel**: `applies_to` False (skip), auch wenn das Tool da ist.
- **Dedup**: dieselbe (Paket, Version, Vuln-ID) über mehrere Lockfiles → ein
  Finding.
- **PACKAGE_PROVENANCE** (npm-Provenance/Signatur) ist bewusst **out of scope**
  dieses Features (netzwerk-/registry-lastig) und ein eigenes späteres Feature.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS `osv-scanner` (falls im PATH) als Subprozess gegen
  das Ziel aufrufen und dessen JSON-Report parsen. Der Tool-Runner MUSS für Tests
  injizierbar sein (DI) — die Übersetzungs-Logik ist ohne installiertes Tool und
  ohne Netz testbar.
- **FR-002**: Je Vulnerability (pro Paket/Version) MUSS ein Finding erzeugt
  werden mit Paketname, Version, Vuln-ID (bevorzugt CVE-Alias, sonst OSV/GHSA-ID),
  Kurzbeschreibung, abgeleiteter Severity, Advisory-Referenzen und — falls
  bekannt — der Fix-Version. `owasp_mcp_ref="MCP04"`.
- **FR-003**: Die Severity MUSS aus CVSS-Score (≥9 CRITICAL, ≥7 HIGH, ≥4 MEDIUM,
  sonst LOW) bzw. aus einem Severity-Label abgeleitet werden; unbekannt → MEDIUM.
- **FR-004**: `applies_to` = ein von osv-scanner verstehbares Manifest/Lockfile
  im Ziel vorhanden UND `osv-scanner` verfügbar; sonst „skipped".
- **FR-005**: Exit-Code 1 (Vulns) ist kein Fehler; nur andere Exit-Codes/Timeout/
  fehlendes JSON gelten als Tool-Fehler → ein einzelnes INFO-Finding
  (transparent), nie ein Crash, nie ein stiller „clean". `run()` wirft nie.
- **FR-006**: stdlib-only im Basis-Install (`subprocess`, `shutil`, `json`);
  KEINE Check-zu-Check-Abhängigkeit; `osv-scanner` ist eine externe, optionale
  Laufzeit-Voraussetzung, kein Python-Dependency.

### Key Entities

- **ToolRunner** (Port): `available() -> bool`, `scan(target) -> (stdout, ok)` —
  injizierbar; Default-Impl = osv-scanner-Subprozess.
- **OSV-Report**: `results[].packages[]{package{name,version,ecosystem},
  vulnerabilities[]{id,aliases,summary,severity,references}, groups[]{max_severity}}`.

## Success Criteria *(mandatory)*

- **SC-001**: Ein osv-Report mit Vuln → passendes Finding (Paket+Version+ID+Fix);
  ohne Vuln → 0.
- **SC-002**: Severity-Ableitung entspricht der Tabelle; unbekannt → MEDIUM.
- **SC-003**: Tool fehlt → skipped; Tool-Fehler/malformt → INFO, kein Crash, kein
  stiller Pass.
- **SC-004**: Keine Regression; Integrationstest unverändert (ohne Tool/Manifest
  „skipped"); Basis-Install dependency-frei; Plugin-Isolation gewahrt.

## Assumptions

- `osv-scanner` wird vom Nutzer separat installiert (dokumentiert); McpFrisk bündelt
  es nicht (Zero-Dep-Kern).
- Out of scope (v1): (a) **PACKAGE_PROVENANCE** (npm-Provenance/Sigstore-Signatur
  — Registry-/Netz-lastig, eigenes Feature); (b) ein `pip-audit`-Zweitadapter
  (osv-scanner deckt PyPI mit ab); (c) Auto-Fix/Upgrade; (d) das Bündeln einer
  eigenen Offline-CVE-DB.
