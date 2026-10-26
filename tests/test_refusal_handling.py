"""Phương án B: mô hình từ chối ở ④/⑤/pivot/planner là thất bại của lời gọi đó, không gọi lại,
không đổi mô hình; lượt đi tiếp và vẫn có hunt record. Mô hình và công cụ giả; không gọi API, không đọc nhãn."""
import copy
import json

from cti_hunt.agent.graph import LLMPlanner, PipelinePlanner, build_graph
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.llm.budget import BudgetExhausted
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import RefusalError
from cti_hunt.stages import s3_telemetry, s5_rule, s8_pivot

SYS = "microsoft-windows-sysmon/operational"
AGENT = load_cfg("agent")
LS = duckdb_sigma.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
RULE_PROMPT = load_sections(ROOT / AGENT["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
CFG = {"max_rounds": 20, "max_total_independent_hypotheses": 10, "max_hypotheses_per_round": 2,
       "max_pivot_depth": 2, "triage": {"max_pivots_per_round": 3, "max_queries_total": 20}}
CA = ContractA(report_id="TU", ttps=[TTP(
    tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi qua WMI",
    source_span=SourceSpan(segment_id="TU-001", text="Mô tả tự soạn về WMI."), confidence=0.9)])
REFUSED = "mô hình từ chối vì bộ phân loại an toàn (loại 'cyber')"


def _hyp(hid, **changes):
    data = {"hypothesis_id": hid, "behavior": f"Tiến trình con của WMI {hid}", "scope": "mọi máy",
            "timeframe": "toàn bộ log", "evidence": Evidence(data_source=SYS, event_ids=[1],
                                                       key_fields=["ParentImage", "Image"]),
            "linked_ttps": ["T1047"], "source_spans": [CA.ttps[0].source_span], "status": "approved"}
    return ContractB(**{**data, **changes})


class Scripted:
    model_id = "synthetic"

    def __init__(self, *outputs):
        self.outputs, self.calls = list(outputs), 0

    def complete_json(self, system, user, schema, log=None):
        self.calls += 1
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            if log is not None and isinstance(out, RefusalError):
                log({"stop_reason": "refusal", "input_tokens": 10, "output_tokens": 0})
            raise out
        return out


def test_refused_rule_is_recorded_once_and_the_request_is_kept(tmp_path):
    llm = Scripted(RefusalError(REFUSED))
    r = s5_rule.generate_rule(_hyp("TU-H01"), llm, RULE_PROMPT, LS, 2, run_dir=tmp_path)
    assert llm.calls == 1                                            # không gọi lại, không sửa
    assert (r["hop_le"], r["so_lan_sua"], r["rule_yaml"], r["hunt_specs"]) == (False, 0, None, [])
    attempt = r["lan_thu"][0]
    assert attempt["loai"] == "tu_choi" and attempt["loi"][0]["kind"] == "mo_hinh_tu_choi"
    assert attempt["api_events"][0]["stop_reason"] == "refusal"
    assert s5_rule.budget_exhausted(r) == ""                        # lô vẫn chạy giả thuyết kế tiếp
    logged = json.loads((tmp_path / "khau5_requests.jsonl").read_text(encoding="utf-8"))
    assert logged["tu_choi"] == REFUSED and logged["raw"] is None and "TU-H01" in logged["user"]


def test_refusal_during_repair_keeps_the_paid_attempt():
    llm = Scripted({"rule_yaml": "title: [", "note": "hỏng"}, RefusalError(REFUSED))
    r = s5_rule.generate_rule(_hyp("TU-H01"), llm, RULE_PROMPT, LS, 2)
    assert llm.calls == 2 and [a["loai"] for a in r["lan_thu"]] == ["sinh", "tu_choi"]
    assert r["lan_thu"][0]["rule_yaml"] == "title: [" and not r["hop_le"]


def test_pivot_skips_only_the_refused_entity(tmp_path):
    telemetry = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
    selected = [{"loai": "may", "gia_tri": host, "pivot_depth": 1, "tu_gia_thuyet": ["TU-H01"]}
                for host in ("A", "B", "C")]
    plan = {"selected": selected, "triage": {"pivot": {"de_xuat": selected}}, "source_depth": 0}
    item = {"ttp_refs": [0], "behavior": "Tiến trình con của WMI trên máy được chọn", "scope": "máy được chọn",
            "timeframe": "toàn bộ khoảng thời gian của log", "data_source": SYS, "event_ids": [1],
            "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}
    out = s8_pivot.generate_round(CA, telemetry, [_hyp("TU-H01")], plan,
                                  Scripted({"items": [item]}, RefusalError(REFUSED), {"items": [item]}),
                                  load_sections(ROOT / AGENT["prompt_khau4_pivot"]), copy.deepcopy(AGENT),
                                  run_dir=tmp_path)
    assert [h.pivot_value for h in out["hypotheses"]] == ["A", "C"]
    refused = [d for d in out["log"]["chi_tiet"] if "ly_do_bo" in d]
    assert [(d["gia_tri"], "từ chối" in d["ly_do_bo"]) for d in refused] == [("B", True)]
    lines = [json.loads(x) for x in (tmp_path / "pivot_requests.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(x["pivot"]["gia_tri"], x.get("tu_choi")) for x in lines] == [("A", None), ("B", REFUSED), ("C", None)]


class Tools:
    def __init__(self):
        self.proposals = 0

    def propose(self, state, decision, run_dir):
        self.proposals += 1
        if self.proposals == 1:
            raise RefusalError(REFUSED)
        return [_hyp(f"TU-H{i}", status="pending_review") for i in (1, 2)]

    def execute(self, state, approved):
        return {}

    def record(self, state):
        return "record"


def test_refused_hunt_round_is_logged_and_the_run_continues(tmp_path):
    out = build_graph(PipelinePlanner(), Tools(), CFG, tmp_path).invoke(
        {"report_id": "TU", "remaining_refs": [0, 1, 2], "history": [], "generated_ids": []},
        {"configurable": {"thread_id": "tu-choi-4"}})
    first, second = out["history"]
    assert first["decision"]["ttp_refs"] == [0, 1] and first["mo_hinh_tu_choi"] == REFUSED
    assert first["generated_ids"] == [] and not out.get("budget_exhausted")
    assert second["decision"]["ttp_refs"] == [2] and "__interrupt__" in out   # vòng sau vẫn sinh và chờ duyệt


def test_refused_planner_call_stops_cleanly(tmp_path):
    prompt = {"sections": {"SYSTEM": "tổng hợp", "USER": "{context}"}}
    decision = LLMPlanner(Scripted(RefusalError(REFUSED)), prompt, tmp_path)({})
    assert decision["action"] == "stop" and "từ chối" in decision["reason"]


def test_budget_exhaustion_still_stops_the_run(tmp_path):
    class Broke(Tools):
        def propose(self, state, decision, run_dir):
            raise BudgetExhausted("Không đủ ngân sách")
    out = build_graph(PipelinePlanner(), Broke(), CFG, tmp_path).invoke(
        {"report_id": "TU", "remaining_refs": [0, 1, 2], "history": [], "generated_ids": []},
        {"configurable": {"thread_id": "het-tien"}})
    assert out["record"] == "record" and out["history"][-1]["decision"]["action"] == "stop"
