"""Đề xuất v2 phương án B: ràng buộc đếm / vắng mặt / mốc neo do mã thực thi trên tập ứng viên.

Dữ liệu tổng hợp ở conftest (không nhãn). Chưa có ④ sinh `rang_buoc`: giả thuyết ở đây dựng tay để kiểm cơ chế.
"""
import json

import pytest
import yaml

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractB, RangBuoc
from cti_hunt.data.store import connect
from cti_hunt.hunt.observe import run_unlabeled, unlabeled_result
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import execution_semantics as ES, s5_rule as S5, s9_record

LS = A.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
SYSMON = "microsoft-windows-sysmon/operational"
P5 = {"sections": {"SYSTEM": "s", "USER": "{hypothesis}\n{logsources}", "REPAIR": "{rule_yaml}{issues}{logsources}"}}
EXE_RULE = """title: Process image
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
"""
ANCHOR = {"scope": {"channel": SYSMON, "event_ids": [1]}, "candidates": "ParentImage ILIKE '%wmiprvse.exe'", "filters": []}


def _hyp(rang_buoc=None, **kw) -> ContractB:
    data = {"hypothesis_id": "SYN-H01", "behavior": "Tiến trình tổng hợp", "scope": "máy fixture", "timeframe": "toàn bộ",
            "evidence": {"data_source": SYSMON, "event_ids": [1], "key_fields": ["Image"]},
            "linked_ttps": ["T1059"], "status": "approved", **kw}
    if rang_buoc:
        data["rang_buoc"] = rang_buoc
    return ContractB(**data)


def _spec(channel=SYSMON, eids=(1,), candidates="Image IS NOT NULL"):
    return {"id": "SYN-H01__x", "scope": {"channel": channel, "event_ids": list(eids)}, "candidates": candidates,
            "filters": []}


def _final(con, spec):
    return sorted(con.execute(f"SELECT ev_host, ev_rec FROM events WHERE ev_channel = '{spec['scope']['channel']}' "
                              f"AND ev_eid IN ({', '.join(map(str, spec['scope']['event_ids']))}) "
                              f"AND ({spec['candidates']})").fetchall())


def _cols(con):
    return {r[0] for r in con.execute("DESCRIBE events").fetchall()}


# ---------- hợp đồng và rào ngữ nghĩa ----------

def test_hypothesis_without_constraint_serializes_exactly_as_before():
    """Phiếu ◆ và gói duyệt lọc cũ băm theo JSON giả thuyết: không ràng buộc thì không thêm khóa."""
    h = _hyp()
    assert "rang_buoc" not in h.model_dump() and "rang_buoc" not in h.model_dump(mode="json")
    with_rb = _hyp({"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 60, "cung": ["ev_host"]}})
    assert ContractB.model_validate(json.loads(json.dumps(with_rb.model_dump(mode="json")))) == with_rb


def test_constraint_model_rejects_unsafe_or_empty_input():
    with pytest.raises(ValueError):
        RangBuoc()
    with pytest.raises(ValueError):
        RangBuoc(dem_khac_nhau={"truong": 'x" OR 1=1', "theo": ["ev_host"], "cua_so_giay": 60, "toi_thieu": 2})
    with pytest.raises(ValueError):
        RangBuoc(dem_khac_nhau={"truong": "Image", "theo": ["ev_host"], "cua_so_giay": 60, "toi_thieu": 1})


def test_guard_blocks_until_a_parameterised_constraint_covers_the_operation():
    prose = {"behavior": "Một tiến trình kết nối tới nhiều địa chỉ IP bên ngoài, không qua phân giải DNS"}
    ops = {i["operation"] for i in ES.issues(_hyp(**prose))}
    assert ops == {"distinct_count", "absence"}
    rb = {"dem_khac_nhau": {"truong": "DestinationIp", "theo": ["ev_host", "Image"], "cua_so_giay": 600, "toi_thieu": 6}}
    assert {i["operation"] for i in ES.issues(_hyp(rb, **prose))} == {"absence"}
    rb["vang_mat"] = {"channel": SYSMON, "event_ids": [22], "khop": [{"ung_vien": "Image", "nguon": "Image"}],
                      "truoc_giay": 300}
    assert ES.issues(_hyp(rb, **prose)) == []
    timed = _hyp(behavior="Tạo tệp trong vòng 30 phút sau lệnh PowerShell")
    assert {i["operation"] for i in ES.issues(timed)} == {"relative_time"}
    neo = {"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 1800, "cung": ["ev_host"]}}
    assert ES.issues(_hyp(neo, behavior=timed.behavior)) == []


# ---------- thực thi trên events ----------

def test_distinct_count_keeps_only_groups_reaching_the_threshold(work):
    con = connect(work)
    rb = {"dem_khac_nhau": {"truong": "Image", "theo": ["ev_host", "ParentImage"], "cua_so_giay": 60, "toi_thieu": 2}}
    spec = ES.bind_constraints(_spec(), _hyp(rb), _cols(con))
    assert _final(con, spec) == [("UTICA", 11), ("UTICA", 12)]        # svchost + sppsvc cùng cha services.exe
    assert spec["rang_buoc"]["candidates_goc"] == "Image IS NOT NULL"
    obs = run_unlabeled(con, spec)
    assert (obs["stages"][1]["hits"], obs["truoc_rang_buoc"]) == (2, 5)


def test_absence_keeps_events_without_matching_prior_event(work):
    con = connect(work)
    rb = {"vang_mat": {"channel": SYSMON, "event_ids": [1], "khop": [{"ung_vien": "ev_host", "nguon": "ev_host"}],
                       "truoc_giay": 1}}
    spec = ES.bind_constraints(_spec("security", (4688,), "NewProcessName IS NOT NULL"), _hyp(rb), _cols(con))
    # 4688 #20 lúc 08:00:00 không có Sysmon 1 trong 1 giây trước; #21 lúc 08:00:02 có (08:00:01.2).
    assert _final(con, spec) == [("UTICA", 20)]


def test_anchor_keeps_events_shortly_after_anchor_on_same_host(work):
    con = connect(work)
    rb = {"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 51, "cung": ["ev_host"]}}
    spec = ES.bind_constraints(_spec(), _hyp(rb), _cols(con), {"H-NEO": ES.anchor_sql([ANCHOR])})
    # Neo: UTICA 07:59:09.928. #11 sau 50,2 giây: giữ; #12 sau 51,3 giây và chính sự kiện neo: không; NEWYORK không neo.
    assert _final(con, spec) == [("UTICA", 11)]
    assert spec["rang_buoc"]["neo_sql"] == ES.anchor_sql([ANCHOR])


def test_constraint_errors_are_reported_not_dropped(work):
    con = connect(work)
    with pytest.raises(ES.ConstraintError) as e:
        ES.bind_constraints(_spec(), _hyp({"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 5,
                                                      "cung": ["ev_host"]}}), _cols(con))
    assert e.value.kind == "thieu_moc_neo"
    with pytest.raises(ES.ConstraintError) as e:
        ES.bind_constraints(_spec(), _hyp({"dem_khac_nhau": {"truong": "TruongKhongCo", "theo": ["ev_host"],
                                                             "cua_so_giay": 5, "toi_thieu": 2}}), _cols(con))
    assert e.value.kind == "rang_buoc_loi"


def test_spec_without_constraint_is_unchanged(work):
    spec = _spec()
    assert ES.bind_constraints(spec, _hyp(), None) is spec


# ---------- khâu ⑤, graph, cổng lọc, Splunk, ◆, ⑨ ----------

def test_rule_generation_binds_constraint_after_static_checks(work):
    con = connect(work)
    rb = {"dem_khac_nhau": {"truong": "Image", "theo": ["ev_host", "ParentImage"], "cua_so_giay": 60, "toi_thieu": 2}}
    r = S5.generate_rule(_hyp(rb), MockClient(responses=[{"rule_yaml": EXE_RULE}]), P5, LS, 2, _cols(con), con)
    assert r["hop_le"] and len(r["hunt_specs"]) == 1
    spec = r["hunt_specs"][0]
    assert spec["rang_buoc"]["dieu_kien"] == rb and _final(con, spec) == [("UTICA", 11), ("UTICA", 12)]


def test_missing_anchor_skips_model_call(work):
    con = connect(work)
    llm = MockClient(responses=[{"rule_yaml": EXE_RULE}])
    r = S5.generate_rule(_hyp({"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 60, "cung": ["ev_host"]}}),
                         llm, P5, LS, 2, _cols(con), con)
    assert llm.calls == [] and not r["hop_le"]
    assert [i["kind"] for i in r["lan_thu"][0]["loi"]] == ["thieu_moc_neo"]


def test_graph_resolves_anchor_only_from_executed_hunts(tmp_path):
    from cti_hunt.agent.stage_tools import StageTools
    path = tmp_path / "H-NEO__a.yaml"
    path.write_text(yaml.safe_dump({"id": "H-NEO__a", "hypothesis_id": "H-NEO", **ANCHOR}), encoding="utf-8")
    h = _hyp({"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 60, "cung": ["ev_host"]}})
    state = {"executed_specs": [{"path": str(path), "hypothesis_id": "H-NEO", "pivot_depth": 0}]}
    assert StageTools._anchors(state, [h]) == {"H-NEO": ES.anchor_sql([ANCHOR])}
    assert StageTools._anchors({"executed_specs": []}, [h]) == {}
    assert StageTools._anchors(state, [_hyp()]) == {}


def test_filter_gate_revalidates_anchor_draft(work):
    from cti_hunt import filter_approval as F
    con = connect(work)
    anchors = {"H-NEO": ES.anchor_sql([ANCHOR])}
    h = _hyp({"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 51, "cung": ["ev_host"]}})
    issues, specs = S5.validate_rule(EXE_RULE, h, LS, _cols(con), con, filter_policy=F.POLICY, anchors=anchors)
    assert issues == [] and specs[0]["sigma_context"]["binding"]["rang_buoc"]
    F._validate_draft(con, specs[0])                 # không ném lỗi: tái lập được chỉ từ dữ liệu đã lưu trong draft


def test_splunk_comparison_refuses_constraint_specs():
    from cti_hunt.eval import splunk_compare
    with pytest.raises(ValueError, match="rang_buoc"):
        splunk_compare.plans_effective({"rang_buoc": {"candidates_goc": "x"}}, None, "idx", "", "")


def test_review_form_shows_constraint_only_when_present(tmp_path):
    rb = {"moc_neo": {"gia_thuyet": "H-NEO", "trong_vong_giay": 60, "cung": ["ev_host"]}}
    form_path = approval.write_review([_hyp(rb), _hyp(hypothesis_id="SYN-H02")], tmp_path)
    rows = yaml.safe_load(form_path.read_text(encoding="utf-8"))["gia_thuyet"]
    assert rows[0]["rang_buoc"] == rb and "rang_buoc" not in rows[1]


def test_record_states_constraint_and_counts(work):
    con = connect(work)
    rb = {"dem_khac_nhau": {"truong": "Image", "theo": ["ev_host"], "cua_so_giay": 60, "toi_thieu": 2}}
    spec = ES.bind_constraints({**_spec(), "hypothesis_id": "SYN-H01"}, _hyp(rb), _cols(con))
    res = unlabeled_result(con, spec)
    assert res["rang_buoc"]["ung_vien_truoc_rang_buoc"] == 5
    text = s9_record._constraint_text(res["rang_buoc"]["dieu_kien"])
    assert "≥ 2 giá trị Image khác nhau cùng ev_host trong ±60 giây" in text
