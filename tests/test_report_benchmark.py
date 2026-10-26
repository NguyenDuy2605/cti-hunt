"""Metric checks prevent a convincing-looking but incorrect OCR score."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("ocr_benchmark", Path(__file__).parents[1] / "scripts/benchmark_report_ocr.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_edit_metrics_count_insertions_and_preserve_case():
    m = benchmark.metrics("A B", "a B C")
    assert m["character_edits"] == 3 and m["cer"] == 1
    assert m["word_edits"] == 2 and m["wer"] == 1
    assert benchmark.metrics("A  B\nC", "A B C")["cer"] == 0


def test_technical_exact_does_not_normalize_or_repair_strings():
    m = benchmark.metrics("cmd.exe -x 1", "cmd.exe  -x l", ["cmd.exe -x 1"])
    assert not m["technical_exact"][0]["found_verbatim"]
    assert not benchmark.metrics("192.0.2.10", "192.0.2.100", ["192.0.2.10"])["technical_exact"][0]["found_verbatim"]
    assert benchmark.metrics("Tool cmd.exe", "Tool | cmd.exe", ["cmd.exe"])["technical_exact"][0]["found_verbatim"]


@pytest.mark.parametrize("hypothesis,valid", [("A B C", True), ("A C B", False), ("A B", False)])
def test_reading_order_requires_every_anchor(hypothesis, valid):
    assert benchmark.metrics("A B C", hypothesis, anchors=["A", "B", "C"])["anchor_order_ok"] is valid
