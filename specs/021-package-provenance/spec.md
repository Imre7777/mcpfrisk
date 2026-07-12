# Feature Specification: PACKAGE_PROVENANCE (Tier 1, statisch, tool-gestützt)

**Feature Branch**: `021-package-provenance`

**Created**: 2026-07-12

**Status**: Design entschieden — in Implementierung. Der aus 019 herausgelöste
letzte Supply-Chain-Baustein vor dem Benchmark. Wie DEPENDENCY_SCAN ein
**Wrapper** um ein bestehendes Tool.

**Input**: Die npm-Dependencies eines MCP-Servers, deren Registry-**Signatur**
fehlt oder **ungültig** ist (Integritäts-/Tampering-Signal) — erkannt durch
Delegation an **`npm audit signatures`**.

## Kontext / Motivation

**Sicherheits-Recherche (Prinzip VII, Stand 2026-07-12):** Die npm-Registry
signiert seit 2022 Paket-Artefakte kryptografisch; zusätzlich gibt es
**Provenance-Attestationen** (Sigstore) für Pakete, die aus einem
nachvollziehbaren CI-Build stammen. `npm audit signatures` verifiziert die
Registry-Signaturen der installierten Dependencies gegen die Registry und meldet
Pakete mit **ungültiger** (manipulierter) oder **fehlender** Signatur. Eine
ungültige Signatur ist ein starkes Integritäts-/Tampering-Signal (das Artefakt
weicht von dem ab, was die Registry signiert hat).

**Bewusste FP-Entscheidung (Prinzip III):** McpFrisk flaggt **NICHT** die bloß
**fehlende Provenance-Attestation** — Provenance-Adoption ist noch gering, die
meisten legitimen Pakete haben (noch) keine Attestation; das zu melden wäre
reines Rauschen. Geflaggt werden nur die belastbaren Signale: **ungültige
Signatur** (HIGH, Tampering) und **fehlende Registry-Signatur** (LOW, notabel,
aber selten kritisch).

**Wie McpFrisk das nutzt:** Wie DEPENDENCY_SCAN — Delegation an das bestehende
Tool, Vereinheitlichung im gemeinsamen Report/Exit-Code/Baseline/SARIF. Zero-Dep-
Kern (Prinzip IV): `npm` wird über den PATH erkannt; fehlt es (oder fehlt eine
Lockfile), ist der Check sauber „skipped".

**OWASP/CWE-Mapping:** OWASP **MCP04** (Supply Chain); CWE: **CWE-347** (Improper
Verification of Cryptographic Signature).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Ungültige Signatur (Priority: P1)

Als MCP-Server-Autor:in möchte ich gewarnt werden, wenn eine Dependency eine
**ungültige** Registry-Signatur hat (das Artefakt wurde manipuliert / weicht von
dem ab, was die Registry signiert hat).

**Independent Test**: Ein injizierter Runner liefert `npm audit signatures`-JSON
mit einem `invalid`-Eintrag `foo@1.0.0` → 1 Finding (HIGH, CWE-347), das Paket +
Version nennt. Ein „alles gültig"-Report → 0.

**Acceptance Scenarios**:

1. **Given** ein Report mit ≥ 1 ungültiger Signatur, **When** der Check
   übersetzt, **Then** je Paket ein HIGH-Finding (MCP04/CWE-347).
2. **Given** ein Report ohne Beanstandungen, **When** der Check läuft, **Then** 0.

---

### User Story 2 — Fehlende Signatur (Priority: P2)

Als Reviewer:in möchte ich sehen, wenn eine Dependency gar keine Registry-
Signatur trägt (schwächeres, aber notables Signal).

**Independent Test**: `missing`-Eintrag `bar@2.0.0` → 1 Finding (LOW).

**Acceptance Scenarios**:

1. **Given** ein `missing`-Eintrag, **When** der Check läuft, **Then** 1
   LOW-Finding.

---

### User Story 3 — Sichere Degradation (Priority: P3)

Als Nutzer:in möchte ich, dass fehlendes `npm` / kein Lockfile / Tool-Fehler /
malformter Output nie einen Crash oder falschen „clean" erzeugt.

**Acceptance Scenarios**:

1. **Given** `npm` nicht installiert ODER keine Lockfile, **When** gescannt wird,
   **Then** „skipped" (`applies_to` False).
2. **Given** das Tool bricht ab / liefert kein JSON, **When** der Check läuft,
   **Then** 1 **INFO**-Finding (transparent), kein Crash, keine Signatur-Findings.

---

### Edge Cases

- **Fehlende Provenance-Attestation wird NICHT geflaggt** (bewusst, FP-Vermeidung).
- **Exit-Code ≠ 0 bei Beanstandungen** (npm-Konvention) ist kein Fehler — der
  JSON-Output wird geparst. Nur andere Fehler → INFO.
- **Read-only**: reiner lesender Tool-Aufruf; keine Mutation durch McpFrisk.
- **Dedup**: dasselbe (Paket, Version, Klasse) → ein Finding.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Der Check MUSS `npm audit signatures` (falls `npm` im PATH) gegen
  das Ziel aufrufen und dessen JSON parsen. Der Tool-Runner MUSS injizierbar sein
  (DI) — die Übersetzungs-Logik ist offline testbar.
- **FR-002**: `invalid`-Einträge → HIGH (MCP04/CWE-347) mit Paket+Version+Grund;
  `missing`-Einträge → LOW. `run()` wirft nie.
- **FR-003**: Fehlende Provenance-Attestation erzeugt KEIN Finding.
- **FR-004**: `applies_to` = `npm` verfügbar UND eine npm-Lockfile
  (`package-lock.json`/`npm-shrinkwrap.json`) vorhanden; sonst „skipped".
- **FR-005**: Tool-Fehler/kein-JSON → 1 INFO-Finding (transparent), nie Crash,
  nie stiller „clean".
- **FR-006**: Basis-Install stdlib-only (`subprocess`/`shutil`/`json`); `npm` ist
  optionale externe Laufzeit-Voraussetzung; KEINE Check-zu-Check-Abhängigkeit.

### Key Entities

- **ToolRunner** (Port): `available()`, `scan(target) -> (stdout, ok)` —
  injizierbar; Default = `npm audit signatures --json`.
- **Signatur-Report**: `{"invalid":[{name,version,...}], "missing":[{name,version}]}`
  (defensiv geparst).

## Success Criteria *(mandatory)*

- **SC-001**: ungültige Signatur → HIGH; fehlende → LOW; sauberer Report → 0.
- **SC-002**: `npm`/Lockfile fehlt → skipped; Tool-Fehler/malformt → INFO, kein
  Crash.
- **SC-003**: fehlende Provenance allein → nie ein Finding (FP-Disziplin).
- **SC-004**: keine Regression; Integrationstest unverändert (gated); Basis-
  Install dependency-frei; Plugin-Isolation gewahrt.

## Assumptions

- `npm` wird vom Nutzer separat installiert; McpFrisk bündelt es nicht.
- Die exakte `npm audit signatures --json`-Ausgabe variiert zwischen npm-
  Versionen; das Parsing ist defensiv (fehlende Felder → best-effort), und ein
  nicht-parsebarer Output degradiert zu INFO (kein Crash). Die getestete
  Übersetzungs-Logik nutzt das dokumentierte `invalid`/`missing`-Schema.
- Out of scope (v1): (a) direkter npm-Registry-API-Abgleich ohne npm-CLI; (b)
  PyPI-/andere-Ökosystem-Signaturen; (c) das Erzwingen/Prüfen von Provenance-
  Attestationen (bewusst nicht geflaggt).
