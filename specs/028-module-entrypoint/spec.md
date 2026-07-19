# Feature Specification: `python -m mcpfrisk`

**Feature Branch**: `028-module-entrypoint`

**Created**: 2026-07-15

**Status**: Fertig. ROADMAP Phase 0.3 (P2, trivial).

## Kontext / Motivation

Es gab nur `mcpfrisk/cli.py` mit dem `if __name__ == "__main__"`-Guard, also lief
nur `python -m mcpfrisk.cli`. Der Paketaufruf `python -m mcpfrisk` — die
erwartete, konventionelle Form — brach mit `No module named mcpfrisk.__main__`
ab. Ein `mcpfrisk/__main__.py`, das an `cli.main()` delegiert, behebt das.

## Fix
- `mcpfrisk/__main__.py`: `from mcpfrisk.cli import main; sys.exit(main())`.
- README: „Runnable without installing" von `python3 -m mcpfrisk.cli` auf
  `python3 -m mcpfrisk` umgestellt (die jetzt funktionierende Konvention).

## Akzeptanz
- `python -m mcpfrisk --version` → Exit 0, gibt die Version aus.
- `python -m mcpfrisk scan <nicht-existent>` → Exit 2 (konsistent zur CLI).
- Volle Suite grün, ruff clean.
