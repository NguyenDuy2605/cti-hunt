"""Công cụ OTRF graph: hai cổng người duyệt trên fixture, không mạng/nhãn thật."""
import importlib.util
import json
from pathlib import Path
import socket
import sys

import pytest
import yaml


@pytest.fixture(autouse=True)
def without_breadth_gate(monkeypatch):
    """Runner/script đã chạy xong, ghim hành vi cũ; cổng độ rộng/biến thể (phiếu rule v3, 15/10) kiểm ở test_duyet_rule_do_rong.py."""
    from cti_hunt import config as _config
    original = _config.agent_config
    def cfg_without(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_do_rong', None)
        return cfg
    monkeypatch.setattr(_config, 'agent_config', cfg_without)

from cti_hunt import approval, config, filter_approval as F, integrity
from cti_hunt.agent import dev_data, session
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import providers


@pytest.fixture
def script(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    name = "thu_graph_duyet_loc_otrf_test"
    spec = importlib.util.spec_from_file_location(name, config.ROOT / "scripts/thu_graph_duyet_loc_otrf.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def trial(script, monkeypatch, work, tmp_path):
    # Chỉ fixture tổng hợp: không dùng đầu vào thật hay quyết định người duyệt thật.
    contract = tmp_path / "contract.json"
    ca = ContractA(report_id="DEV-WMIEXEC", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", confidence=0.9,
        behavior_description="Synthetic WMI execution",
        source_span=SourceSpan(segment_id="TU-001", text="Synthetic WMI execution."))])
    contract.write_text(ca.model_dump_json(), encoding="utf-8")
    ledger = config.ROOT / "data/dev/api_budget.sqlite"
    fake_ledger = tmp_path / "synthetic-ledger"
    fake_ledger.write_bytes(b"synthetic immutable ledger; no real budget reads")
    original_snapshot = script._snapshot

    def fixture_snapshot(paths):
        return {str(Path(p).resolve()): original_snapshot([fake_ledger if Path(p).resolve() == ledger else p])
                [str((fake_ledger if Path(p).resolve() == ledger else Path(p)).resolve())] for p in paths}

    monkeypatch.setattr(script, "_snapshot", fixture_snapshot)
    paths = [contract, work / "events.parquet", Path(script.__file__), ledger]
    checks = {"rows": 9, "kind": "synthetic_fixture_only"}
    monkeypatch.setattr(script, "_inputs", lambda root: (contract, work, checks, script._snapshot(paths)))
    monkeypatch.setattr(script, "_run_path", lambda out, root: Path(out).resolve())
    monkeypatch.setattr(session, "git_state", lambda root: {"commit": None, "co_thay_doi_chua_commit": False})
    monkeypatch.setattr(dev_data, "check_manifest", lambda *args: None)
    return tmp_path / "trial"


def test_mock_wrapper_crosses_both_real_graph_gates_only_after_fixture_reviews(script, trial):
    first = script.run("start", trial)
    assert first["review_kind"] == "hypothesis" and first["mock_calls"] == ["LLMHypothesisBatch"]
    rd = Path(first["review_dir"])
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding="utf-8"))
    assert not form["nguoi_duyet"] and all(not r["quyet_dinh"] for r in form["gia_thuyet"])
    assert script.run("probe-pending", trial)["pending_resume_blocked"]
    assert not (rd / approval.APPROVED_FILE).exists()
    approval.save_decisions(rd, "synthetic fixture reviewer",
                            {form["gia_thuyet"][0]["id"]: {"quyet_dinh": "approved", "ly_do": "fixture only"}},
                            integrity.sha256_file(rd / approval.REVIEW_FILE))
    second = script.run("resume", trial)
    assert second["review_kind"] == "filter" and second["mock_calls"] == ["LLMRule"]
    frd = Path(second["review_dir"])
    filters = F.load_form(frd)
    assert len(filters["muc_loc"]) == 2 and not filters["nguoi_duyet"]
    manifest_sha = integrity.sha256_file(frd / F.MANIFEST)
    assert script.run("inspect", trial)["review_kind"] == "filter"
    assert script.run("probe-pending", trial)["pending_resume_blocked"]
    assert integrity.sha256_file(frd / F.MANIFEST) == manifest_sha
    assert not (frd / F.EFFECTIVE).exists() and not (rd / "agent_execute.json").exists()
    F.save_decisions(frd, "synthetic fixture reviewer",
                     {r["id"]: {"quyet_dinh": "rejected", "ly_do": "fixture mock has no benign evidence"}
                      for r in filters["muc_loc"]}, integrity.sha256_file(frd / F.FORM))
    final = script.run("resume", trial)
    assert final["trang_thai"] == "xong" and final["mock_calls"] == []
    proof = json.loads(Path(final["verification"]).read_text(encoding="utf-8"))
    verified = proof["completed_verification"]
    assert verified["unique_events"] == 1 and verified["cases"][0]["effective_filters"] == []
    assert verified["cases"][0]["stages"][-1]["hits"] == 1
    rec = json.loads((trial / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert rec["observations"][0]["sample"] == [] and len(rec["rarity_summary"]["top"]) == 1
    assert [h["decision"]["action"] for h in rec["history"]] == ["hunt", "stop"]
    assert proof["human_forms_written"] is False and proof["original_inputs_unchanged"]
    assert verified["receipts_audited"][0]["receipt_sha256"] == integrity.sha256_file(frd / "execution_receipt.json")
    with pytest.raises(ValueError, match="không đang chờ"):
        script.run("resume", trial)


@pytest.mark.parametrize("target", ["marker", "run_meta"])
def test_trial_tampering_blocks_before_any_mock_call(script, trial, monkeypatch, target):
    script.run("start", trial)
    path = trial / (script.MARKER if target == "marker" else session.META_FILE)
    data = json.loads(path.read_text(encoding="utf-8"))
    if target == "marker":
        data["immutable_inputs_sha256"][str(Path(script.__file__).resolve())] = "0" * 64
    else:
        data["phien_ban"] = "v1"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(script, "mock_only", lambda calls: pytest.fail("tampering must stop before clients"))
    with pytest.raises(ValueError):
        script.run("resume", trial)
    assert not (trial / "round_01" / approval.APPROVED_FILE).exists()


def test_mock_context_blocks_clients_and_socket_connections(script):
    calls = []
    with script.mock_only(calls):
        assert isinstance(providers.from_config({"provider": "anthropic"}), script.WMIMock)
        for constructor in (providers.AnthropicClient, providers.OpenAICompatibleClient):
            with pytest.raises(RuntimeError, match="cấm client API"):
                constructor({})
        with socket.socket() as sock:
            for connect in (sock.connect, sock.connect_ex):
                with pytest.raises(RuntimeError, match="kết nối mạng"):
                    connect(("127.0.0.1", 1))
        with pytest.raises(RuntimeError, match="kết nối mạng"):
            socket.create_connection(("127.0.0.1", 1))
    assert calls == []


@pytest.mark.parametrize("relative", ["data/dev", "data/work/trial", "runs/trial", "data/labels/trial"])
def test_trial_path_refuses_root_and_non_development_locations(script, relative):
    with pytest.raises(ValueError, match="data/dev"):
        script._run_path(config.ROOT / relative, config.ROOT)


def test_start_refuses_dirty_commit_before_data_reads(script, trial, monkeypatch):
    monkeypatch.setattr(session, "git_state", lambda root: {"co_thay_doi_chua_commit": True})
    monkeypatch.setattr(script, "_inputs", lambda root: pytest.fail("dirty start must stop before input reads"))
    with pytest.raises(ValueError, match="commit"):
        script.run("start", trial)
    assert not trial.exists()
