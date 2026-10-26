"""No network or real model: source binding, worksheet semantics and handoff gates."""
import importlib.util
import json

import pytest

from cti_hunt import config, report_review
from cti_hunt.llm.budget import Ledger
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s1_ingest as S1, s2_ioc, s2_report as S2


@pytest.fixture
def case(tmp_path):
    source = tmp_path / "input.html"
    source.write_text('<article><h1>Report</h1><p>The actor used WMI to execute a process.</p>'
                      '<p>&lt;script&gt;untrusted()&lt;/script&gt;</p></article>', encoding="utf-8")
    bundle = tmp_path / "bundle"
    manifest = S1.ingest(str(source), "NEW", bundle)
    stix = tmp_path / "attack.json"
    S1.write_json(stix, {"objects": [
        {"type": "attack-pattern", "id": "attack-pattern--wmi", "name": "WMI",
         "description": "WMI executes a process", "external_references": [
             {"source_name": "mitre-attack", "external_id": "T1047"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]}]})
    reference = tmp_path / "reference.json"
    S1.write_json(reference, {**{k: manifest[k] for k in ("report_id", "source_sha256", "segments_sha256")},
        "status": "assistant_draft", "checks": [{"check_id": "B1", "description": "WMI process",
            "segment_ids": ["NEW-0002"], "technique_ids": ["T1047"]}]})
    return bundle, stix, reference


def extraction(case, out, send=False):
    bundle, stix, _ = case
    client = MockClient(responses=[{"items": [{"segment_id": "NEW-0002", "technique_id": "T1047",
        "tactic": "execution", "quote": "The actor used WMI to execute a process.",
        "behavior_description": "Execute process via WMI", "rationale": "WMI explicitly executes a process"}]}])
    S2.run(bundle, stix, config.ROOT / "prompts/report_extract_v1.md", {"provider": "mock", "model": "test"},
           out, s2_ioc.load_rules(config.ROOT / "configs/ioc_rules.yaml"), send=send, llm=client)
    return out


def test_preview_is_not_empty_success_and_reference_stays_out_of_prompt(case, tmp_path):
    run = extraction(case, tmp_path / "run")
    before = (run / "requests.json").read_bytes()
    packet = report_review.prepare(case[0], run, tmp_path / "review", case[2])
    assert packet["semantic_status"] == "not_run" and packet["contract_a_sha256"] is None
    assert packet["predictions"] == []
    assert packet["reference"]["checks"][0]["review_verdict"] == "not_run"
    assert (run / "requests.json").read_bytes() == before
    assert "assistant_draft" not in before.decode()
    assert "<script>" not in (tmp_path / "review/review.html").read_text(encoding="utf-8")


def test_complete_matches_are_candidates_never_automatic_true_positives(case, tmp_path):
    run = extraction(case, tmp_path / "run", send=True)
    packet = report_review.prepare(case[0], run, tmp_path / "review", case[2])
    assert packet["semantic_status"] == "pending"
    assert packet["predictions"][0]["semantic_verdict"] == "pending"
    assert packet["reference"]["checks"][0]["candidate_predictions"] == ["P0001"]
    assert all(s["parsing_verdict"] == "pending" for s in packet["segments"])
    assert not any(k in packet for k in ("precision", "recall", "TP", "FN"))


@pytest.mark.parametrize("tamper", ["contract", "requests", "reference", "bundle_binding"])
def test_mixed_or_modified_artifacts_fail_before_writing_review(case, tmp_path, tamper):
    run = extraction(case, tmp_path / "run", send=True)
    if tamper == "contract":
        with (run / "contract_a.json").open("a", encoding="utf-8") as f:
            f.write(" ")
    elif tamper == "requests":
        S1.write_json(run / "requests.json", [])
    elif tamper == "reference":
        ref = json.loads(case[2].read_text(encoding="utf-8"))
        ref["source_sha256"] = "different"
        S1.write_json(case[2], ref)
    else:
        meta = json.loads((run / "meta.json").read_text(encoding="utf-8"))
        meta["bundle_manifest_sha256"] = "different"
        S1.write_json(run / "meta.json", meta)
    with pytest.raises(ValueError):
        report_review.prepare(case[0], run, tmp_path / "review", case[2])
    assert not (tmp_path / "review").exists()


def test_failed_extraction_does_not_publish_stale_contract_or_missing_behavior(case, tmp_path):
    run = extraction(case, tmp_path / "run", send=True)
    meta = json.loads((run / "meta.json").read_text(encoding="utf-8"))
    meta["status"] = "failed"
    S1.write_json(run / "meta.json", meta)
    packet = report_review.prepare(case[0], run, tmp_path / "review", case[2])
    assert not packet["predictions"] and packet["semantic_status"] == "not_run"


def test_review_never_overwrites_completed_worksheet(case, tmp_path):
    run = extraction(case, tmp_path / "run")
    out = tmp_path / "review"
    report_review.prepare(case[0], run, out)
    with pytest.raises(ValueError, match="đã tồn tại"):
        report_review.prepare(case[0], run, out)


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location("thu_report_moi", config.ROOT / "scripts/thu_report_moi.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_api_preflight_missing_key_and_insufficient_reserve_do_not_change_ledger(runner, tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "budget.sqlite")
    ledger.init("0.35")
    cfg = {"provider": "anthropic", "model": "claude-sonnet-5", "max_output_tokens": 32000,
           "budget_ledger": str(ledger.path), "api_key_env": "TEST_REPORT_KEY"}
    monkeypatch.delenv("TEST_REPORT_KEY", raising=False)
    before = ledger.status()
    with pytest.raises(ValueError, match="TEST_REPORT_KEY"):
        runner.api_preflight(cfg)
    assert ledger.status() == before
    ledger.set_limit("0.20")
    monkeypatch.setenv("TEST_REPORT_KEY", "dummy-for-test-only")
    before = ledger.status()
    with pytest.raises(ValueError, match="dự phòng"):
        runner.api_preflight(cfg)
    assert ledger.status() == before


def test_handoff_refuses_preview_contract_without_calling_agent(runner, case, tmp_path, monkeypatch):
    out = tmp_path / "case"
    out.mkdir()
    extraction(case, out / "extraction")
    S1.write_json(out / "case.json", {
        "bundle_manifest_sha256": S1.digest((case[0] / "manifest.json").read_bytes()),
        "reference": None, "reference_sha256": None})
    calls = []
    monkeypatch.setattr(runner.cli, "main", lambda args: calls.append(args) or 0)
    assert runner.main(["handoff", "--bundle", str(case[0]), "--out", str(out)]) == 1
    assert calls == [] and not (out / "handoff_preview").exists()


def test_runner_refuses_changed_reference_before_any_api(runner, case, tmp_path, monkeypatch):
    out = tmp_path / "case"
    out.mkdir()
    S1.write_json(out / "case.json", {
        "bundle_manifest_sha256": S1.digest((case[0] / "manifest.json").read_bytes()),
        "reference": str(case[2]), "reference_sha256": "old-hash"})
    calls = []
    monkeypatch.setattr(runner, "api_preflight", lambda cfg: calls.append("api"))
    assert runner.main(["extract", "--send", "--bundle", str(case[0]), "--out", str(out)]) == 1
    assert calls == []


@pytest.mark.parametrize("send", [False, True])
def test_complete_handoff_uses_extracted_contract_and_never_approves(runner, case, tmp_path, monkeypatch, send):
    out = tmp_path / "case"
    out.mkdir()
    extraction(case, out / "extraction", send=True)
    S1.write_json(out / "case.json", {
        "bundle_manifest_sha256": S1.digest((case[0] / "manifest.json").read_bytes()),
        "reference": str(case[2]), "reference_sha256": S1.digest(case[2].read_bytes())})
    calls, preflight = [], []
    monkeypatch.setattr(runner.cli, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(runner, "api_preflight", lambda cfg: preflight.append(True))
    args = ["handoff", "--bundle", str(case[0]), "--out", str(out)]
    assert runner.main(args + (["--send"] if send else [])) == 0
    assert calls[0][0] == "report-coverage"
    agent = calls[1]
    assert agent[:2] == ["agent", "start"]
    assert agent[agent.index("--contract-a") + 1] == str(out / "extraction/contract_a.json")
    assert ("--dry-run" in agent) is not send
    assert str(case[2]) not in agent and not any("approve" in arg for cmd in calls for arg in cmd)
    assert preflight == ([True] if send else [])
