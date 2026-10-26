"""H2: local cost estimates on synthetic requests, without API or budget access."""
import pytest

from cti_hunt.llm import budget, providers
from cti_hunt import config
from cti_hunt.stages import s2_report

_CAN_STIX = pytest.mark.skipif(not (config.ROOT / "data" / "attack" / "enterprise-attack-19.2.json").exists(),
                               reason="chưa có file STIX v19.2 trong data/attack")


REQUESTS = [{"system": "a", "user": "", "schema": {}},
            {"system": "", "user": "b", "schema": {}}]


@pytest.mark.parametrize("model,typical,reserve", [
    ("claude-sonnet-5", "0.104008", "0.641034"),
    ("claude-opus-5-5", "0.208016", "1.282068"),
])
def test_cost_rounds_input_per_batch_and_uses_versioned_rates(model, typical, reserve, monkeypatch):
    monkeypatch.setattr(providers, "from_config", lambda *a: pytest.fail("API client created"))
    monkeypatch.setattr(budget.Ledger, "db", lambda *a: pytest.fail("ledger accessed"))
    result = s2_report.estimate_cost(REQUESTS, {"model": model, "max_output_tokens": 32000})
    # Each batch is 3 characters, rounded up to 2 tokens (4 total, not 3).
    assert result["input_tokens"] == 4 and result["reserved_input_tokens"] == 517
    assert result["output_tokens"] == 10400 and result["rate_version"] == budget.RATE_VERSION
    assert result["typical_usd"] == typical and result["reserve_usd"] == reserve
    assert not result["warnings"]


def test_unknown_model_has_no_fabricated_price():
    assert s2_report.estimate_cost(REQUESTS, {"model": "unknown"}) is None
    assert s2_report.estimate_cost(REQUESTS, {}) is None


@pytest.mark.parametrize("batches,warn", [(50, False), (51, True)])
def test_long_report_warning_starts_above_50_batches(batches, warn):
    result = s2_report.estimate_cost([REQUESTS[0]] * batches, {"model": "claude-sonnet-5"})
    assert bool(result["warnings"]) is warn
    if warn:
        assert "51 lô" in result["warnings"][0] and "--segments" in result["warnings"][0]


def test_typical_output_respects_a_smaller_configured_cap_and_empty_plan_costs_zero():
    result = s2_report.estimate_cost(REQUESTS, {"model": "claude-sonnet-5", "max_output_tokens": 1000})
    assert result["output_tokens"] == 2000 and result["typical_usd"] == "0.020008"
    empty = s2_report.estimate_cost([], {"model": "claude-sonnet-5", "max_output_tokens": 32000})
    assert empty["typical_usd"] == empty["reserve_usd"] == "0.000000"


@_CAN_STIX
def test_streamlit_long_report_shows_cost_and_warning_before_any_extraction(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from cti_hunt import config
    from cti_hunt.stages import s1_ingest
    root = tmp_path / "ui"
    bundle = root / "data/reports/moi/LONG"
    source = tmp_path / "source.html"
    source.write_text("<article>" + "".join(
        f"<p>The actor used WMI to execute a remote process. Paragraph {n}.</p>" for n in range(204)
    ) + "</article>", encoding="utf-8")
    s1_ingest.ingest(str(source), "LONG", bundle)
    app_path = config.ROOT / "app/streamlit_app.py"
    monkeypatch.setattr(config, "ROOT", root)
    monkeypatch.setattr(providers, "from_config", lambda *a: pytest.fail("API client created"))
    monkeypatch.setattr(budget.Ledger, "db", lambda *a: pytest.fail("ledger accessed"))
    at = AppTest.from_file(str(app_path), default_timeout=30).run()
    assert not at.exception
    assert any("Ước tính khâu ②" in info.value and "51 lô" in info.value for info in at.info)
    assert any("Report dài (51 lô)" in warning.value and "--segments" in warning.value for warning in at.warning)
    assert not (bundle / "extractions").exists()
