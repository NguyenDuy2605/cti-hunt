"""Vòng ⑧ → ④ → ◆ → ⑤ trên sự kiện tự tạo, không có bảng nhãn."""
import copy
import json

import duckdb
import pytest
import yaml

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s3_telemetry, s5_rule, s8_pivot, s8_triage, s9_record

SYS = "microsoft-windows-sysmon/operational"
CFG = load_cfg("agent")
TELEMETRY = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
LS = duckdb_sigma.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
PROMPT = load_sections(ROOT / CFG["prompt_khau4_pivot"])
RULE = (ROOT / "hunts" / "sigma" / "H-03.yml").read_text(encoding="utf-8")


@pytest.fixture
def con():
    c = duckdb.connect()
    c.execute("SET default_collation='nocase'")
    c.execute("""CREATE TABLE events (
        ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec INTEGER, ev_ts TIMESTAMP,
        ParentImage VARCHAR, Image VARCHAR, CommandLine VARCHAR, "User" VARCHAR)""")
    c.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        ("A", SYS, 1, 1, "2020-01-01 00:00:00", "C:\\WmiPrvSE.exe", "C:\\powershell.exe", "whoami", "D\\alice"),
        ("A", SYS, 1, 2, "2020-01-01 00:00:02", "C:\\WmiPrvSE.exe", "C:\\cmd.exe", "net user", "D\\alice"),
        ("B", SYS, 1, 3, "2020-01-01 00:00:04", "C:\\WmiPrvSE.exe", "C:\\powershell.exe", "", "D\\bob"),
    ])
    return c


CA = ContractA(report_id="TU", ttps=[TTP(
    tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi qua WMI",
    source_span=SourceSpan(segment_id="TU-001", text="Mô tả tự soạn về WMI."), confidence=0.9)])


def _hyp(hid, **changes):
    data = {"hypothesis_id": hid, "behavior": f"Hành vi {hid}", "scope": "mọi máy",
            "timeframe": "toàn bộ log", "evidence": Evidence(data_source=SYS, event_ids=[1],
                                                       key_fields=["ParentImage", "Image", "User"]),
            "linked_ttps": ["T1047"], "source_spans": [CA.ttps[0].source_span], "status": "approved"}
    return ContractB(**{**data, **changes})


SPECS = [
    {"id": "H1", "hypothesis_id": "TU-H01", "scope": {"channel": SYS, "event_ids": [1]},
     "candidates": "ParentImage ILIKE '%WmiPrvSE.exe'", "filters": []},
    {"id": "H2", "hypothesis_id": "TU-H02", "scope": {"channel": SYS, "event_ids": [1]},
     "candidates": "ev_host = 'A' AND Image ILIKE '%powershell.exe'", "filters": []},
]


def _cfg(**triage_changes):
    cfg = copy.deepcopy(CFG)
    cfg["triage"].update(triage_changes)
    return cfg


def _response():
    return {"items": [{"ttp_refs": [0], "behavior": "Tiến trình con khác qua WMI cần kiểm tra",
                       "scope": "máy được chọn", "timeframe": "toàn bộ log",
                       "data_source": SYS, "event_ids": [1], "key_fields": ["ParentImage", "Image"],
                       "extra_techniques": [], "priority": "cao"}]}


def test_pivot_round_requires_review_and_binds_host_in_query(con, tmp_path):
    cfg = _cfg(max_pivots_per_round=1)
    base = [_hyp("TU-H01"), _hyp("TU-H02")]
    plan = s8_pivot.plan_round(con, SPECS, base, cfg)
    assert [(p["loai"], p["gia_tri"], p["pivot_depth"]) for p in plan["selected"]] == [("may", "A", 1)]
    assert "buoc" not in json.dumps(plan)

    llm = MockClient(responses=[_response()])
    generated = s8_pivot.generate_round(CA, TELEMETRY, base, plan, llm, PROMPT, cfg, run_dir=tmp_path)
    assert generated["log"]["so_gia_thuyet"] == 1
    h = generated["hypotheses"][0]
    assert (h.hypothesis_id, h.origin, h.pivot_depth, h.pivot_kind, h.pivot_value, h.status) == (
        "TU-H03", "pivot", 1, "may", "A", "pending_review")
    assert h.source_spans == [CA.ttps[0].source_span]
    assert "buoc" not in llm.calls[0][1]

    approval.write_review([h], tmp_path)
    with pytest.raises(approval.NotApprovedError):
        s5_rule.generate_rule(h, MockClient(), load_sections(ROOT / CFG["prompt_khau5"], ("SYSTEM", "USER", "REPAIR")),
                              LS, 0)
    form_path = tmp_path / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "người vận hành"
    form["gia_thuyet"][0]["quyet_dinh"] = "approved"
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    approval.apply_review(tmp_path)
    approved = approval.load_hypotheses(tmp_path / approval.APPROVED_FILE)[0]
    issues, specs = s5_rule.validate_rule(RULE, approved, LS,
                                          columns={r[0] for r in con.execute("DESCRIBE events").fetchall()}, con=con)
    assert issues == [] and len(specs) == 1
    assert specs[0]["scope"]["hosts"] == ["A"]
    rows = s8_triage.final_rows(con, specs[0], {r[0] for r in con.execute("DESCRIBE events").fetchall()})
    assert {r["ev_host"] for r in rows} == {"A"}


def test_account_pivot_filters_normalized_account(con):
    h = _hyp("TU-H03", origin="pivot", pivot_depth=1, pivot_kind="tai_khoan", pivot_value="alice")
    spec = {"id": "P", "scope": {"channel": SYS, "event_ids": [1]}, "candidates": "TRUE", "filters": []}
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    bound = s8_pivot.bind_spec(spec, h, cols)
    rows = s8_triage.final_rows(con, bound, cols)
    assert {r["ev_rec"] for r in rows} == {1, 2}
    assert spec["candidates"] == "TRUE"  # không sửa spec gốc
    with pytest.raises(s8_pivot.PivotError, match="tài khoản"):
        s8_pivot.bind_spec(spec, h, {"Image"})


ACCOUNT_RULE = """title: Pivot account fixture
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\\\\WmiPrvSE.exe'
    User: alice
  filter_system:
    User: SYSTEM
  condition: selection and not filter_system
"""


def test_account_pivot_rule_must_not_bind_the_account_itself(con):
    # 08/10 (đánh giá v2 mới): ⑤ viết `User: dschrute` trong khi log ghi `DMEVALS\\dschrute` → 0 kết quả; mã đã tự
    # ràng buộc tài khoản (bỏ miền) nên rule không được tự đặt điều kiện tài khoản ở khối sinh ứng viên.
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    h = _hyp("TU-H03", origin="pivot", pivot_depth=1, pivot_kind="tai_khoan", pivot_value="alice")
    issues, specs = s5_rule.validate_rule(ACCOUNT_RULE, h, LS, columns=cols, con=con)
    assert [i.kind for i in issues] == [s5_rule.PIVOT_ACCOUNT_KIND] and specs == []
    assert "selection.User" in issues[0].message and "filter_system" not in issues[0].message
    assert "\\" not in issues[0].message.split("'")[1]          # chỉ nêu giá trị pivot, không số kết quả
    fixed = ACCOUNT_RULE.replace("    User: alice\n", "")
    issues, specs = s5_rule.validate_rule(fixed, h, LS, columns=cols, con=con)
    assert issues == [] and len(specs) == 1
    assert {r["ev_rec"] for r in s8_triage.final_rows(con, specs[0], cols)} == {1, 2}   # mã khớp D\alice
    # Không áp cho giả thuyết gốc hay pivot theo máy: điều kiện User ở đó là của giả thuyết.
    for other in (_hyp("TU-H01"), _hyp("TU-H04", origin="pivot", pivot_depth=1, pivot_kind="may", pivot_value="A")):
        assert s5_rule.validate_rule(ACCOUNT_RULE, other, LS, columns=cols, con=con)[0] == []


def test_history_and_query_caps_cannot_be_skipped(con):
    cfg = _cfg(min_hypotheses=1, max_pivots_per_round=1, max_queries_total=1)
    base = [_hyp("TU-H01"), _hyp("TU-H02")]
    first = s8_pivot.plan_round(con, SPECS, base, cfg)
    assert len(first["selected"]) == 1
    pivot = _hyp("TU-H03", origin="pivot", pivot_depth=1, pivot_kind="may", pivot_value="A")
    current = [{**SPECS[0], "id": "H3", "hypothesis_id": "TU-H03"}]
    with pytest.raises(s8_pivot.PivotError, match="nhật ký"):
        s8_pivot.plan_round(con, current, base + [pivot], cfg)
    history = [{"source_depth": 0, "selected": first["selected"], "generated_ids": ["TU-H03"]}]
    second = s8_pivot.plan_round(con, current, base + [pivot], cfg, history)
    assert second["selected"] == [] and "trần số truy vấn" in second["triage"]["pivot"]["ly_do_dung"]
    with pytest.raises(s8_pivot.PivotError, match="truy được"):
        s8_pivot.plan_round(con, current, base + [pivot], cfg,
                            [{**history[0], "generated_ids": ["TU-H99"]}])


def test_depth_two_stops_and_record_shows_pivot_chain(con):
    cfg = _cfg(min_hypotheses=1, max_pivots_per_round=1)
    base = [_hyp("TU-H01"), _hyp("TU-H02")]
    first = s8_pivot.plan_round(con, SPECS, base, cfg)
    p1 = _hyp("TU-H03", origin="pivot", pivot_depth=1, pivot_kind="may", pivot_value="A")
    h1 = [{**SPECS[0], "id": "P1", "hypothesis_id": "TU-H03"}]
    log1 = {"source_depth": 0, "selected": first["selected"], "generated_ids": ["TU-H03"]}
    second = s8_pivot.plan_round(con, h1, base + [p1], cfg, [log1])
    assert second["selected"] and second["selected"][0]["pivot_depth"] == 2
    p2 = _hyp("TU-H04", origin="pivot", pivot_depth=2,
              pivot_kind=second["selected"][0]["loai"], pivot_value=second["selected"][0]["gia_tri"])
    h2 = [{**SPECS[0], "id": "P2", "hypothesis_id": "TU-H04"}]
    log2 = {"source_depth": 1, "selected": second["selected"], "generated_ids": ["TU-H04"]}
    third = s8_pivot.plan_round(con, h2, base + [p1, p2], cfg, [log1, log2])
    assert third["selected"] == []
    assert "trần độ sâu" in third["triage"]["pivot"]["ly_do_dung"]

    md = s9_record.render(CA, TELEMETRY, base + [p1, p2], [], pivot_log=[
        {**first["triage"]["nhat_ky_vong"], "selected": first["selected"]},
        {**second["triage"]["nhat_ky_vong"], "selected": second["selected"]},
        {**third["triage"]["nhat_ky_vong"], "selected": third["selected"]},
    ])
    assert "Thực thể pivot" in md and "may=A" in md
    assert "TU-H04 | approved | pivot |" in md
    assert "trần độ sâu" in md


def test_pivot_prompt_uses_profile_line_without_event_counts(con, tmp_path):
    """M2 cho ④ pivot: ghi chú nguồn log trong prompt có dòng hồ sơ nhưng không có số sự kiện."""
    import re
    profile = s3_telemetry.build_profile(con, TELEMETRY, "TU")
    eff = s3_telemetry.apply_profile(TELEMETRY, profile)
    base = [_hyp("TU-H01"), _hyp("TU-H02")]
    plan = s8_pivot.plan_round(con, SPECS, base, _cfg(max_pivots_per_round=1))
    llm = MockClient(responses=[_response()])
    s8_pivot.generate_round(CA, eff, base, plan, llm, PROMPT, _cfg(max_pivots_per_round=1), run_dir=tmp_path)
    user = llm.calls[0][1]
    assert profile["kenh"][SYS] == 3
    assert "Bộ dữ liệu đang chạy: có thu thập " + SYS in user
    assert '"Hostname"' not in user  # G0(b): cột vắng trong nguồn fixture không vào key_fields của pivot
    assert "không thu thập microsoft-windows-wmi-activity/operational (bỏ nguồn này)" in user
    notes = re.findall(r'"telemetry_note": "([^"]*)"', user)
    assert notes and not any(re.search(r"\d[\d.,]*\s*sự kiện|=\s*\d", n) for n in notes)
