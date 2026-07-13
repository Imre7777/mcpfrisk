"""Precision/Recall/F1-Berechnung für den Benchmark.

Reine Logik, ohne McpFrisk-Import -- daher isoliert testbar. Die Zuordnung
geschieht auf der Ebene (Sample, check_id): pro Sample zählen wir, welche
erwarteten Checks gefunden wurden (TP), welche fehlten (FN) und welche
unerwartet feuerten (FP). So misst der Benchmark sowohl Detection-Rate (Recall)
als auch Rauschen (Precision).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SampleEval:
    name: str
    expected: set[str]           # erwartete check_ids (Ground-Truth)
    found: set[str]              # tatsächlich gefeuerte check_ids
    true_positives: set[str] = field(default_factory=set)
    false_negatives: set[str] = field(default_factory=set)
    false_positives: set[str] = field(default_factory=set)

    @classmethod
    def build(cls, name: str, expected: set[str], found: set[str]) -> "SampleEval":
        return cls(
            name=name,
            expected=set(expected),
            found=set(found),
            true_positives=expected & found,
            false_negatives=expected - found,
            false_positives=found - expected,
        )

    @property
    def perfect(self) -> bool:
        return not self.false_negatives and not self.false_positives


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, tp: int = 0, fp: int = 0, fn: int = 0) -> None:
        self.tp += tp
        self.fp += fp
        self.fn += fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return 1.0 if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return 1.0 if denom == 0 else self.tp / denom

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)


def aggregate(evals: list[SampleEval]) -> Metrics:
    m = Metrics()
    for e in evals:
        m.add(tp=len(e.true_positives), fp=len(e.false_positives), fn=len(e.false_negatives))
    return m


def per_check(evals: list[SampleEval]) -> dict[str, Metrics]:
    """Metriken je check_id über alle Samples hinweg."""
    out: dict[str, Metrics] = {}
    for e in evals:
        for cid in e.true_positives:
            out.setdefault(cid, Metrics()).add(tp=1)
        for cid in e.false_negatives:
            out.setdefault(cid, Metrics()).add(fn=1)
        for cid in e.false_positives:
            out.setdefault(cid, Metrics()).add(fp=1)
    return out
