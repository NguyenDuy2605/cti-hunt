"""Lượt fixture bị ngắt ở ⑤ (lỗi mạng sau khi đã duyệt): dựng hunt record không gọi API, không sửa checkpoint,
không ghi đè. Từ mốc v2, mô hình từ chối không còn làm vỡ lượt; lỗi mạng và lỗi sau khi gửi vẫn làm vỡ."""
import json
import runpy

import pytest
import yaml

from cti_hunt import approval
from cti_hunt.agent import session
from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.integrity import sha256_file
from cti_hunt.llm import providers

G = runpy.run_path(str(ROOT / "scripts" / "ghi_record_luot_ngat.py"))
SYS = "microsoft-windows-sysmon/operational"


class BrokenRules:
    """④ trả một giả thuyết; ⑤ gặp lỗi mạng, lượt dừng ở node execute."""
    model_id = "mock"

    def __init__(self):
        self.calls = []

    def complete_json(self, system, user, json_schema, log=None):
        self.calls.append(json_schema.get("title"))
        if json_schema.get("title") == "LLMRule":
            raise providers.TransportError("mất kết nối tới API")
        return {"items": [{"ttp_refs": [0], "behavior": "Tiến trình con lạ của nhóm thực thi từ xa",
                           "scope": "mọi máy", "timeframe": "toàn bộ log", "data_source": SYS, "event_ids": [1],
                           "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}]}

    def describe(self):
        return {"model": self.model_id}


def test_interrupted_run_gets_a_record_without_api_or_touching_the_checkpoint(work, tmp_path, monkeypatch):
    ca = tmp_path / "contract_a_TU.json"
    ca.write_text(ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi từ xa, mô tả tự soạn",
        source_span=SourceSpan(segment_id="TU-001", text="Câu tự soạn."), confidence=0.9)]).model_dump_json(),
        encoding="utf-8")
    llm = BrokenRules()
    monkeypatch.setattr(providers, "from_config", lambda cfg: llm)
    run = tmp_path / "luot"
    assert session.start("pipeline", ca, work, run, dataset_kind="fixture", dataset_id="TU")["trang_thai"] == "cho_duyet"
    with pytest.raises(session.SessionError, match="đang chờ phiếu"):          # chưa ngắt: dùng resume bình thường
        G["record_interrupted"](run, "thử")
    form_path = run / "round_01" / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "tester"
    for g in form["gia_thuyet"]:
        g["quyet_dinh"] = "approved"
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    with pytest.raises(providers.TransportError):
        session.resume(run)
    assert session.inspect(run)["pending_nodes"] == ["execute"]
    before, calls = sha256_file(run / session.CHECKPOINT_FILE), len(llm.calls)

    with pytest.raises(session.SessionError, match="lý do"):
        G["record_interrupted"](run, "  ")
    incident = G["record_interrupted"](run, "Mất kết nối ở lời gọi ⑤ đầu tiên của vòng 1.")
    assert len(llm.calls) == calls and sha256_file(run / session.CHECKPOINT_FILE) == before
    assert incident["gia_thuyet_da_duyet_chua_thuc_thi"] == [
        {"vong": "round_01", "hypothesis_id": "TU-H01", "co_rule_hop_le": False}]
    assert incident["node_dang_cho"] == ["execute"] and incident["so_hunt_da_thuc_thi"] == 0

    md = (run / "hunt_record.md").read_text(encoding="utf-8")
    assert [line for line in md.splitlines() if line.startswith("## ")] == [
        "## Learn", "## Observe", "## Check", "## Keep"]                         # giữ bố cục D13
    tail = md.split("### Sự cố: lượt dừng giữa chừng")[1]
    assert "- round_01: TU-H01 (chưa có rule)" in tail and "không phải kết quả 0 sự kiện" in tail and "buoc" not in md
    assert "(D11)" not in tail                       # lý do sự cố do người chạy ghi; không gán sẵn quy tắc
    assert json.loads((run / "su_co.json").read_text(encoding="utf-8"))["khong_goi_api"] is True
    assert (run / "agent_dev_record.json").exists()
    with pytest.raises(session.SessionError, match="đã tồn tại"):
        G["record_interrupted"](run, "lần hai")


def test_v2_run_checks_the_milestone_of_its_own_version(tmp_path, monkeypatch):
    # 05/10 (SY_01 tuyến B): công cụ từng so mốc v1 cho lượt v2 nên từ chối đóng lượt dù lượt khớp mốc v2.
    record_interrupted = G["record_interrupted"]
    g = record_interrupted.__globals__
    run = tmp_path / "luot"
    run.mkdir()
    (run / session.META_FILE).write_text(json.dumps({"mode": "pipeline", "phien_ban": "v2",
                                                     "moc_co_dinh": {"sha256": "abc"}}), encoding="utf-8")
    (run / "hunt_record.md").write_text("đã có", encoding="utf-8")
    calls = []
    monkeypatch.setattr(g["session"], "_check_unchanged", lambda meta, root: None)
    monkeypatch.setattr(g["moc"], "verify", lambda mode, root, **kw: calls.append((mode, kw)) or {"sha256": "abc"})
    with pytest.raises(session.SessionError, match="đã tồn tại"):       # qua kiểm mốc, dừng ở bước không ghi đè
        record_interrupted(run, "lý do")
    assert calls == [("pipeline", {"version": "v2"})]
