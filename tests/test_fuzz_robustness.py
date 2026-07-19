"""Feature 029: Property-/Fuzz-Tests -- Zero-Crash-Garantie bei beliebigem Input.

Ein Security-Tool darf an keinem Eingabe-Müll crashen (ein Crash ist ein
still-übersehener Scan -> Prinzip III). Diese Tests werfen adversarialen Input
(fies-unicode, Steuerzeichen, Riesenlängen, kaputte Syntax, Binärmüll, wilde
Glob-Muster) gegen die zentralen Eingabepfade und verlangen: **nie eine
Exception**, immer ein wohldefiniertes Ergebnis.

Bewusst stdlib-basiert (fester Seed -> deterministisch), statt eine externe
hypothesis-Abhängigkeit einzuführen -- passend zum Zero-Dep-Ethos; die Zero-
Crash-Garantie ist damit vollständig erreichbar. Steuer-/unsichtbare Zeichen
stehen als \\x/\\u-Escapes im Vorrat, damit die Testdatei selbst sauber bleibt.
"""
from __future__ import annotations

import random
import string
from pathlib import Path

import pytest

from mcpfrisk.core.fs import (
    exclude_context,
    is_excluded,
    iter_source_files,
    load_ignore_patterns,
)
from mcpfrisk.core.runner import run_static_scan
from mcpfrisk.core.sourcetree import analyze, jsts_available

SEED = 20260715
N = 400

# Zeichenvorrat mit vielen "gefährlichen" Symbolen + Unicode + Steuerzeichen
# (letztere als Escapes: NUL, ESC, Zero-width-Space, RTL-Override).
_ALPHABET = (
    string.ascii_letters
    + string.digits
    + " \t\n/\\.:*?![]{}()<>|$#@%^&+=~`'\"-_,;"
    + "üäößÜÄÖé"
    + "\U0001F600→"
    + "\x00\x1b​‮"
)


def _rand_str(rng: random.Random, max_len: int = 60) -> str:
    n = rng.randint(0, max_len)
    return "".join(rng.choice(_ALPHABET) for _ in range(n))


def _cases(rng: random.Random, n: int = N):
    # Feste Härtefälle zuerst, dann zufällige.
    fixed = [
        "", " ", "\x00", "\n", "..", "../" * 50, "/" * 100, "\\" * 100,
        "*", "**", "?", "[", "]", "{a,b}", "!x", "a/**/b", "C:\\x\\y",
        "ü" * 200, "\U0001F600" * 50, "​​", "a" * 5000, ".mcpfriskignore",
    ]
    yield from fixed
    for _ in range(n):
        yield _rand_str(rng)


class TestIsExcludedNeverCrashes:
    def test_is_excluded_on_adversarial_input(self):
        rng = random.Random(SEED)
        root = Path("some/root")
        for s in _cases(rng):
            pat = _rand_str(rng, 30)
            result = is_excluded(Path(s), root, extra=(pat,))
            assert isinstance(result, bool)

    def test_is_excluded_with_context_patterns(self):
        rng = random.Random(SEED + 1)
        for s in _cases(rng, 200):
            with exclude_context((_rand_str(rng, 20), _rand_str(rng, 20))):
                assert isinstance(is_excluded(Path(s), Path("."), extra=()), bool)


class TestIgnoreParserNeverCrashes:
    def test_load_ignore_patterns_on_garbage_file(self, tmp_path):
        rng = random.Random(SEED + 2)
        for _ in range(120):
            body = "\n".join(_rand_str(rng, 40) for _ in range(rng.randint(0, 8)))
            (tmp_path / ".mcpfriskignore").write_text(body, encoding="utf-8")
            pats = load_ignore_patterns(tmp_path)
            assert isinstance(pats, tuple)
            # Muster werden auch tatsächlich benutzt -> darf ebenfalls nicht werfen.
            assert isinstance(is_excluded(tmp_path / "x.py", tmp_path), bool)


@pytest.mark.filterwarnings("ignore::SyntaxWarning")
class TestAnalyzeNeverCrashes:
    """`analyze()` muss bei kaputter/wüster Quelle sauber None bzw. ok=False
    liefern -- niemals werfen (der Parser-Adapter kapselt ast/tree-sitter).

    (Müll-Quelltext löst in ast.parse harmlose SyntaxWarnings aus -- die sind
    erwartet und werden hier unterdrückt, das Verhalten bleibt korrekt.)"""

    def _probe(self, tmp_path: Path, suffix: str, rng: random.Random, n: int):
        for i in range(n):
            content = _rand_str(rng, 300)
            f = tmp_path / f"f{i}{suffix}"
            f.write_text(content, encoding="utf-8")
            model = analyze(f)  # darf NIE werfen
            assert model is None or isinstance(model.ok, bool)

    def test_python_source_garbage(self, tmp_path):
        self._probe(tmp_path, ".py", random.Random(SEED + 3), 150)

    def test_python_raw_bytes_garbage(self, tmp_path):
        rng = random.Random(SEED + 4)
        for i in range(60):
            f = tmp_path / f"b{i}.py"
            f.write_bytes(bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 200))))
            model = analyze(f)
            assert model is None or isinstance(model.ok, bool)

    @pytest.mark.skipif(not jsts_available(), reason="jsts-Extra nicht installiert")
    def test_typescript_source_garbage(self, tmp_path):
        self._probe(tmp_path, ".ts", random.Random(SEED + 5), 120)

    @pytest.mark.skipif(not jsts_available(), reason="jsts-Extra nicht installiert")
    def test_javascript_source_garbage(self, tmp_path):
        self._probe(tmp_path, ".js", random.Random(SEED + 6), 120)


class TestFullScanNeverCrashes:
    """Integration: ein ganzes Verzeichnis voll Müll-Dateien scannen -> alle
    Checks laufen durch, keine Exception, ein wohldefiniertes ScanResult."""

    def test_run_static_scan_on_garbage_tree(self, tmp_path):
        rng = random.Random(SEED + 7)
        for i in range(40):
            suffix = rng.choice([".py", ".ts", ".js", ".json", ".txt"])
            (tmp_path / f"f{i}{suffix}").write_text(_rand_str(rng, 400), encoding="utf-8")
        result = run_static_scan(tmp_path)
        assert result is not None
        assert isinstance(result.findings, list)
        assert isinstance(iter_source_files(tmp_path), list)
