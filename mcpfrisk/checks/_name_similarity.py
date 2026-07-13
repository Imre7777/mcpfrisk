"""Geteilter Nicht-Check-Helfer: Namens-Ähnlichkeit über Edit-Distanz.

Kein Check -- ein reines Hilfsmodul (Präzedenz: `_dynamic_helpers.py`,
`_ssrf_callback.py`), damit die Plugin-Isolation (Constitution II) gewahrt bleibt
und Checks nicht voneinander importieren müssen. Aktuell von TYPOSQUAT (018)
genutzt.

`damerau_le_1` beantwortet die eng gefasste Frage „ist die Damerau-Levenshtein-
Distanz höchstens 1?" (eine Ersetzung/Einfügung/Löschung ODER eine Vertauschung
zweier benachbarter Zeichen) -- der Sweet-Spot für Typosquatting-Erkennung.
`levenshtein_le_1` ist die Variante ohne Vertauschung (von TOOL_NAME_COLLISION
für Near-Duplicate-Namen genutzt). Für die reine ≤1-Frage genügt jeweils ein
linearer Vergleich statt der vollen DP-Matrix.
"""
from __future__ import annotations


def levenshtein_le_1(a: str, b: str) -> bool:
    """True, wenn die Levenshtein-Distanz zwischen a und b höchstens 1 ist
    (0 = gleich, 1 = eine Ersetzung/Einfügung/Löschung)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:  # genau eine Substitution erlaubt
        return sum(x != y for x, y in zip(a, b, strict=False)) == 1
    # Längen unterscheiden sich um 1 -> genau eine Einfügung/Löschung erlaubt.
    shorter, longer = (a, b) if la < lb else (b, a)
    i = j = 0
    edited = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
        else:
            if edited:
                return False
            edited = True
            j += 1  # ein Zeichen in `longer` überspringen (= Einfügung)
    return True


def damerau_le_1(a: str, b: str) -> bool:
    """True bei Damerau-Levenshtein-Distanz ≤ 1: Distanz 0/1 nach Levenshtein
    ODER genau eine Vertauschung zweier benachbarter Zeichen (`ab` -> `ba`).

    Die Adjazenz-Vertauschung ist ein klassischer Tippfehler (`fastmcp` ->
    `fatsmcp`), den reine Levenshtein-≤1 als Distanz 2 verfehlt."""
    if levenshtein_le_1(a, b):
        return True
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 2:
            i, k = diffs
            if k == i + 1 and a[i] == b[k] and a[k] == b[i]:
                return True
    return False
