"""Tests für das Benchmark-Harness (Feature: Phase-5 Benchmark).

- Metrik-Logik (rein, deterministisch).
- Regressionsschutz: McpFrisk erkennt JEDES verwundbare Sample und bleibt auf
  JEDEM sauberen Sample still (0 FP, 0 FN) -- so schlägt ein neuer False Positive
  oder ein kaputter Check sofort hier auf.
"""
from __future__ import annotations

from benchmark import metrics as M
from benchmark.run import run


class TestMetrics:
    def test_sample_eval_partitions(self):
        e = M.SampleEval.build("s", expected={"A", "B"}, found={"B", "C"})
        assert e.true_positives == {"B"}
        assert e.false_negatives == {"A"}
        assert e.false_positives == {"C"}
        assert not e.perfect

    def test_clean_sample_any_finding_is_fp(self):
        e = M.SampleEval.build("clean", expected=set(), found={"X"})
        assert e.false_positives == {"X"}
        assert e.true_positives == set() and e.false_negatives == set()

    def test_precision_recall_f1(self):
        m = M.Metrics(tp=8, fp=2, fn=0)
        assert abs(m.precision - 0.8) < 1e-9
        assert m.recall == 1.0
        assert abs(m.f1 - (2 * 0.8 * 1.0 / 1.8)) < 1e-9

    def test_empty_metrics_are_perfect_by_convention(self):
        m = M.Metrics()
        assert m.precision == 1.0 and m.recall == 1.0

    def test_aggregate_and_per_check(self):
        evals = [
            M.SampleEval.build("a", {"CMD"}, {"CMD"}),          # TP
            M.SampleEval.build("b", {"PATH"}, set()),           # FN
            M.SampleEval.build("c", set(), {"CMD"}),            # FP (clean)
        ]
        agg = M.aggregate(evals)
        assert (agg.tp, agg.fn, agg.fp) == (1, 1, 1)
        pc = M.per_check(evals)
        assert pc["CMD"].tp == 1 and pc["CMD"].fp == 1
        assert pc["PATH"].fn == 1


class TestBenchmarkRegression:
    def test_mcpfrisk_detects_all_vuln_and_stays_clean(self):
        res = run()
        summ = res["cross_tool"]["McpFrisk"]
        # Jedes verwundbare Sample erkannt, jedes saubere Sample still.
        assert summ["vuln_detected"] == summ["vuln_total"] > 0
        assert summ["clean_passed"] == summ["clean_total"] > 0

    def test_mcpfrisk_has_no_false_positives_or_negatives(self):
        res = run()
        assert res["overall"]["fp"] == 0, res["per_sample"]
        assert res["overall"]["fn"] == 0, res["per_sample"]
