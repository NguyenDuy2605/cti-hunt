"""Nhánh lọc approved trên graph v2 bằng mock: fixture tổng hợp, không mạng/nhãn/OTRF thật."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml

from cti_hunt import approval, config, filter_approval as F, integrity
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.agent import dev_data, session
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.data.ingest import ingest
from cti_hunt.data.store import connect

SEC = "security"
NAME = "\\Microsoft\\Windows\\UpdateOrchestrator\\AC Power {}"


def _content(command, arguments):
    lines = ['&lt;?xml version="1.0" encoding="UTF-16"?&gt;', "&lt;Task&gt;", '  &lt;Actions Context="Author"&gt;',
             "    &lt;Exec&gt;", f"      &lt;Command&gt;{command}&lt;/Command&gt;",
             f"      &lt;Arguments&gt;{arguments}&lt;/Arguments&gt;", "    &lt;/Exec&gt;", "  &lt;/Actions&gt;",
             "&lt;/Task&gt;"]
    return "\r\n".join(lines)


USO = "%systemroot%\\system32\\usoclient.exe"


def _ev(rec, host, sid, name, content=None):
    e = {"Hostname": host, "Channel": "Security", "EventID": 4698, "RecordNumber": rec,
         "EventTime": f"2020-09-21 18:01:{rec:02d}", "SubjectUserSid": sid, "SubjectUserName": "x", "TaskName": name}
    if content is not None:
        e["TaskContent"] = content
    return e


W6, W5 = "WORKSTATION6.theshire.local", "WORKSTATION5.theshire.local"
EVENTS = [
    _ev(1, W6, "S-1-5-18", NAME.format("Download"), _content(USO, "StartDownload")),
    _ev(2, W6, "S-1-5-18", NAME.format("Install"), _content(USO, "StartInstall")),
    _ev(3, W5, "S-1-5-21-1-2-3-1104", "\\FixtureTask", _content("C:\\fixture\\other.exe", "-a")),
    # Mồi: cùng tên/máy/SID nhưng lệnh khác -> phải còn lại.
    _ev(4, W6, "S-1-5-18", NAME.format("Download"), _content("C:\\fixture\\other.exe", "StartDownload")),
    # Mồi: cùng nội dung nhưng máy khác -> phải còn lại.
    _ev(5, W5, "S-1-5-18", NAME.format("Download"), _content(USO, "StartDownload")),
    # Mồi: thiếu TaskContent -> mục lọc NULL, không được loại.
    _ev(6, W6, "S-1-5-18", NAME.format("Download")),
]


def _key(rec):
    host = "WORKSTATION6" if EVENTS[rec - 1]["Hostname"] == W6 else "WORKSTATION5"
    return [host, SEC, rec]


@pytest.fixture
def work(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text("\n".join(json.dumps(e) for e in EVENTS) + "\n", encoding="utf-8")
    w = tmp_path / "work"
    ingest(raw, w, sysmon_channel="microsoft-windows-sysmon/operational",
           time_cfg={"sysmon_field": "UtcTime", "other_field": "EventTime", "other_offset_hours": 4},
           event_key=["ev_host", "ev_channel", "ev_rec"], expected_rows=len(EVENTS))
    return w


def _load(monkeypatch, name, file):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(name, config.ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def script(monkeypatch):
    return _load(monkeypatch, "thu_graph_loc_approved_otrf_test", "thu_graph_loc_approved_otrf.py")


@pytest.fixture
def trial(script, monkeypatch, work, tmp_path):
    # Chỉ fixture tổng hợp: không dùng đầu vào thật hay quyết định người duyệt thật.
    contract = tmp_path / "contract.json"
    ca = ContractA(report_id="DEV-SCHTASKS", ttps=[TTP(
        tactic="Persistence", technique_id="T1053.005", confidence=0.9,
        behavior_description="Synthetic scheduled task creation",
        source_span=SourceSpan(segment_id="TU-001", text="Synthetic scheduled task creation."))])
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
    checks = {"rows": len(EVENTS), "kind": "synthetic_fixture_only"}
    monkeypatch.setattr(script, "_inputs", lambda root: (contract, work, checks, script._snapshot(paths)))
    monkeypatch.setattr(script, "_run_path", lambda out, root: Path(out).resolve())
    monkeypatch.setattr(session, "git_state", lambda root: {"commit": None, "co_thay_doi_chua_commit": False})
    monkeypatch.setattr(dev_data, "check_manifest", lambda *args: None)
    # Script này kiểm nhánh lọc approved từ trước cổng giữ/bỏ rule (09/10); fixture tắt cổng như lúc viết script.
    load_agent_config = config.agent_config
    def without_rule_gate(*args, **kwargs):
        cfg = load_agent_config(*args, **kwargs)
        cfg.pop("duyet_rule_doi_chieu", None)
        return cfg
    monkeypatch.setattr(config, "agent_config", without_rule_gate)
    return tmp_path / "trial"


def _to_filter_gate(script, trial):
    first = script.run("start", trial)
    assert first["review_kind"] == "hypothesis" and first["mock_calls"] == ["LLMHypothesisBatch"]
    rd = Path(first["review_dir"])
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding="utf-8"))
    assert not form["nguoi_duyet"] and all(not r["quyet_dinh"] for r in form["gia_thuyet"])
    approval.save_decisions(rd, "synthetic fixture reviewer",
                            {form["gia_thuyet"][0]["id"]: {"quyet_dinh": "approved", "ly_do": "fixture only"}},
                            integrity.sha256_file(rd / approval.REVIEW_FILE))
    second = script.run("resume", trial)
    assert second["review_kind"] == "filter" and second["mock_calls"] == ["LLMRule"]
    frd = Path(second["review_dir"])
    form = F.load_form(frd)
    assert [r["id"].rsplit("__", 1)[1] for r in form["muc_loc"]] == ["S-01", "S-02"]
    assert not form["nguoi_duyet"] and all(not r[k] for r in form["muc_loc"] for k in F.HUMAN_FIELDS)
    preview, = F._read(frd / "preview.json")
    assert (preview["candidates"], [f["matched"] for f in preview["filters"]], preview["union_removed"]) == (6, [1, 1], 2)
    assert script.run("probe-pending", trial)["pending_resume_blocked"]
    return frd, form


def _approve(row, hours=24):
    until = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"quyet_dinh": "approved", "ly_do": "fixture only", "can_cu": "fixture evidence only",
            "nguoi_chiu_trach_nhiem": "synthetic fixture owner", "hieu_luc_den_utc": until}


@pytest.mark.parametrize("decisions,final", [
    (("approved", "approved"), [3, 4, 5, 6]),
    (("approved", "rejected"), [2, 3, 4, 5, 6]),
])
def test_approved_filters_remove_only_their_full_key_sets(script, trial, decisions, final):
    frd, form = _to_filter_gate(script, trial)
    choices = {r["id"]: (_approve(r) if d == "approved" else {"quyet_dinh": "rejected", "ly_do": "fixture"})
               for r, d in zip(form["muc_loc"], decisions)}
    F.save_decisions(frd, "synthetic fixture reviewer", choices, integrity.sha256_file(frd / F.FORM))
    form_sha = integrity.sha256_file(frd / F.FORM)
    done = script.run("resume", trial)
    assert done["trang_thai"] == "xong" and done["mock_calls"] == []
    proof = json.loads(Path(done["verification"]).read_text(encoding="utf-8"))
    case, = proof["completed_verification"]["cases"]
    assert case["candidates"] == 6 and case["union_all_proposed"] == 2
    assert [p["keys"] for p in case["proposed_filters"]] == [[_key(1)], [_key(2)]]
    assert case["approved_filters"] == [f"S-0{i + 1}" for i, d in enumerate(decisions) if d == "approved"]
    assert case["final_keys"] == sorted(_key(r) for r in final) and case["removed_by_approved"] == 6 - len(final)
    review, = proof["completed_verification"]["reviews_audited"]
    assert review["form_sha256"] == form_sha and review["receipt_sha256"] == integrity.sha256_file(frd / "execution_receipt.json")
    md = (trial / "hunt_record.md").read_text(encoding="utf-8")
    assert "fixture evidence only" in md and "synthetic fixture owner" in md
    with pytest.raises(ValueError, match="không đang chờ"):
        script.run("resume", trial)


def test_expired_approval_blocks_execution_without_effective_artifacts(script, trial, monkeypatch):
    frd, form = _to_filter_gate(script, trial)
    F.save_decisions(frd, "synthetic fixture reviewer", {r["id"]: _approve(r, hours=1) for r in form["muc_loc"]},
                     integrity.sha256_file(frd / F.FORM))
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    monkeypatch.setattr(F, "utcnow", lambda: later)
    with pytest.raises(F.FilterReviewError, match="hết hạn"):
        script.run("resume", trial)
    assert not (frd / F.EFFECTIVE).exists() and not (frd / "approval_log.json").exists()


def test_mock_rule_filters_are_single_line_and_tampering_stops_before_clients(script, trial, monkeypatch):
    det = yaml.safe_load(script.MOCK_RULE)["detection"]
    values = [v for k, block in det.items() if k.startswith("filter_") for v in block.values()]
    assert all("\r" not in str(v) and "\n" not in str(v) for v in values)
    script.run("start", trial)
    marker = trial / script.MARKER
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["immutable_inputs_sha256"][str(Path(script.__file__).resolve())] = "0" * 64
    marker.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(script, "mock_only", lambda calls: pytest.fail("tampering must stop before clients"))
    with pytest.raises(ValueError):
        script.run("resume", trial)


def test_preflight_key_sets_and_output_location(monkeypatch, work, tmp_path):
    pre = _load(monkeypatch, "chuan_bi_loc_approved_otrf_test", "chuan_bi_loc_approved_otrf.py")
    con = connect(work)
    try:
        catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset")["logsource_catalog"]))
        sets = pre.key_sets(con, pre.mock_spec(con, catalog))
    finally:
        con.close()
    assert sets["candidates"] == 6 and [f["matched"] for f in sets["filters"]] == [1, 1]
    assert sets["union"] == 2 and [list(k) for k in sets["remaining_keys_if_all_approved"]] == sorted(_key(r) for r in (3, 4, 5, 6))
    for out in (config.ROOT / "data/dev", config.ROOT / "data/work/x", tmp_path / "x"):
        with pytest.raises(ValueError, match="data/dev"):
            pre.run(out)
