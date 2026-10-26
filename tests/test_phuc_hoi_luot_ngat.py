"""R2 (09/10): lượt phát triển dừng ngoài cổng duyệt vì lỗi mạng được chạy lại đúng node đang dở; lỗi khác, lượt
đánh giá, cổng duyệt và sổ còn yêu cầu chưa rõ chi phí thì từ chối. Fixture tổng hợp, mô hình giả, không gọi mạng."""
from types import SimpleNamespace

import pytest

from cti_hunt.agent import session
from cti_hunt.agent.graph import AgentGuardError
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import budget, providers

SYS = "microsoft-windows-sysmon/operational"
ITEMS = {"items": [{"ttp_refs": [0], "behavior": "Tiến trình con lạ của nhóm thực thi từ xa", "scope": "mọi máy",
                    "timeframe": "toàn bộ log", "data_source": SYS, "event_ids": [1],
                    "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}]}


class Flaky:
    """Mô hình giả: lỗi theo kịch bản cho planner (`plan_failures`) hoặc ④ (`hyp_failures`), sau đó trả lời hợp lệ."""
    model_id = "mock"

    def __init__(self, plan_failures=(), hyp_failures=()):
        self.plan_failures, self.hyp_failures = list(plan_failures), list(hyp_failures)
        self.plan_calls = self.hyp_calls = 0

    def complete_json(self, system, user, json_schema, log=None):
        if json_schema.get("title") == "_PlannerOutput":
            self.plan_calls += 1
            if self.plan_failures:
                raise self.plan_failures.pop(0)
            return {"action": "hunt", "ttp_refs": [0], "pivot_targets": [], "tra_hunt_memory": None,
                    "doc_hunt_record": None, "reason": "thử TTP duy nhất"}
        self.hyp_calls += 1
        if self.hyp_failures:
            raise self.hyp_failures.pop(0)
        return ITEMS

    def describe(self):
        return {"model": self.model_id}


def _contract(tmp_path):
    path = tmp_path / "contract_a_TU.json"
    path.write_text(ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi từ xa, mô tả tự soạn",
        source_span=SourceSpan(segment_id="TU-001", text="Câu tự soạn."), confidence=0.9)]).model_dump_json(),
        encoding="utf-8")
    return path


def _interrupted(work, tmp_path, monkeypatch, mode, llm, error_type):
    monkeypatch.setattr(providers, "from_config", lambda cfg: llm)
    run = tmp_path / "luot"
    with pytest.raises(error_type):
        session.start(mode, _contract(tmp_path), work, run, dataset_kind="fixture", dataset_id="TU")
    return run


def test_network_error_at_the_planner_is_recovered_at_the_same_node(work, tmp_path, monkeypatch):
    llm = Flaky(plan_failures=[providers.TransportError("TLS handshake timed out")])
    run = _interrupted(work, tmp_path, monkeypatch, "agent", llm, providers.TransportError)
    status = session.inspect(run)
    assert status["trang_thai"] == "chua_hoan_tat" and status["pending_nodes"] == ["plan"]
    assert status["phuc_hoi_duoc"] is True and status["loi"][0].startswith("TransportError(")
    log = (run / "agent_plan_requests.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(log) == 1 and '"error_type": "TransportError"' in log[0]

    out = session.recover(run)
    assert out["trang_thai"] == "cho_duyet" and (run / "round_01" / "duyet.yaml").exists()
    assert (llm.plan_calls, llm.hyp_calls) == (2, 1)       # gọi lại đúng node bị ngắt, một lần
    log = (run / "agent_plan_requests.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(log) == 2 and '"error_type": null' in log[1]   # dòng lỗi cũ giữ nguyên, thêm dòng mới
    assert session.inspect(run)["trang_thai"] == "cho_duyet"
    with pytest.raises(session.SessionError, match="không bị ngắt ngoài cổng duyệt"):
        session.recover(run)                                # đang chờ phiếu: dùng resume, không phục hồi


def test_network_error_after_round_files_exist_is_not_recovered(work, tmp_path, monkeypatch):
    llm = Flaky(hyp_failures=[providers.TransportError("mất phản hồi ở ④")])
    run = _interrupted(work, tmp_path, monkeypatch, "pipeline", llm, providers.TransportError)
    status = session.inspect(run)
    assert status["pending_nodes"] == ["propose"] and status["phuc_hoi_duoc"] is False
    assert "chống ghi đè" in status["ly_do_khong_phuc_hoi"]
    with pytest.raises(session.SessionError, match="chống ghi đè"):
        session.recover(run)
    assert llm.hyp_calls == 1


def test_non_network_error_is_not_recovered(work, tmp_path, monkeypatch):
    llm = Flaky(plan_failures=[RuntimeError("lỗi khác")])
    run = _interrupted(work, tmp_path, monkeypatch, "agent", llm, RuntimeError)
    status = session.inspect(run)
    assert status["phuc_hoi_duoc"] is False and "không phải lỗi mạng" in status["ly_do_khong_phuc_hoi"]
    with pytest.raises(session.SessionError, match="không phải lỗi mạng"):
        session.recover(run)
    assert llm.plan_calls == 1


def test_pending_unknown_cost_blocks_recovery_before_any_call(work, tmp_path, monkeypatch):
    llm = Flaky(plan_failures=[providers.TransportError("mất phản hồi")])
    run = _interrupted(work, tmp_path, monkeypatch, "agent", llm, providers.TransportError)
    ledger = budget.Ledger(tmp_path / "budget.sqlite")
    ledger.init("1")
    ledger.reserve("claude-sonnet-5", 1000)                # yêu cầu chưa rõ chi phí, chờ đối soát Console
    llm.budget_ledger = str(ledger.path)
    with pytest.raises(budget.BudgetError, match="chưa rõ chi phí"):
        session.recover(run)
    assert llm.plan_calls == 1 and session.inspect(run)["trang_thai"] == "chua_hoan_tat"


@pytest.mark.parametrize("kind,nodes,errors,ok,why", [
    ("otrf_dev", ("plan",), ["TransportError('x')"], True, ""),
    ("fixture", ("plan",), [providers.TransportError("x")], True, ""),
    ("otrf_dev", ("prepare_rules",), ["TransportError('x')"], False, "chống ghi đè"),
    ("otrf_dev", ("plan",), ["TransportError('x')", "AgentGuardError('y')"], False, "không phải lỗi mạng"),
    ("otrf_dev", ("plan",), [AgentGuardError("planner chọn thực thể không đủ điều kiện")], False, "không phải lỗi mạng"),
    ("otrf_dev", ("plan",), [], False, "không ghi lỗi"),
    ("danh_gia", ("plan",), ["TransportError('x')"], False, "quy tắc sự cố"),
])
def test_recovery_decision(kind, nodes, errors, ok, why):
    snap = SimpleNamespace(next=nodes,
                           tasks=[SimpleNamespace(error=e) for e in errors] + [SimpleNamespace(error=None)])
    info = session._interruption({"dataset": {"kind": kind}}, snap)
    assert info["phuc_hoi_duoc"] is ok and why in info["ly_do_khong_phuc_hoi"]
    assert len(info["loi"]) == len(errors)
