"""⑤ v2: không gọi sửa rule khi lỗi thiếu trường nằm trên nguồn log không có sự kiện nào.

Dữ liệu tổng hợp ở conftest có Sysmon 1 nhưng không có Sysmon 19 (cột EventNamespace/Name/Query vắng hẳn).
"""
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractB
from cti_hunt.data.store import connect
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s5_rule as S5

LS = A.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
P5 = load_sections(ROOT / agent_config("v2")["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
SYSMON = "microsoft-windows-sysmon/operational"

WMI_FILTER = """title: WMI event filter
logsource: {product: windows, category: wmi_event}
detection:
  selection:
    EventID: 19
    EventNamespace|contains: 'subscription'
  condition: selection
"""
PROC_BAD_FIELD = """title: Process with missing field
logsource: {product: windows, category: process_creation}
detection:
  selection:
    TruongKhongCo|endswith: '.exe'
  condition: selection
"""


def _hyp(eid: int, fields: list[str]) -> ContractB:
    return ContractB(hypothesis_id="SYN-H01", behavior="Hành vi tổng hợp", scope="máy fixture", timeframe="toàn bộ",
                     evidence={"data_source": SYSMON, "event_ids": [eid], "key_fields": fields},
                     linked_ttps=["T1546.003"], status="approved")


def _cols(con):
    return {r[0] for r in con.execute("DESCRIBE events").fetchall()}


def test_empty_source_missing_field_stops_before_repair(work):
    con = connect(work)
    llm = MockClient(responses=[{"rule_yaml": WMI_FILTER}] * 3)
    r = S5.generate_rule(_hyp(19, ["EventNamespace", "Query"]), llm, P5, LS, 2, _cols(con), con,
                         stop_repair_on_empty_source=True)
    assert len(llm.calls) == 1                                  # chỉ lần sinh, không lời gọi sửa nào
    assert (r["hop_le"], r["hop_le_lan_dau"], r["so_lan_sua"], r["hunt_specs"]) == (False, False, 0, [])
    assert [a["loai"] for a in r["lan_thu"]] == ["sinh", "dung_sua"]
    assert r["lan_thu"][-1]["api_events"] == []
    assert [i["kind"] for i in r["lan_thu"][-1]["loi"]] == [S5.EMPTY_SOURCE_KIND, "truong_khong_co"]
    assert S5.summarize([r])["loi_lan_dau_theo_loai"] == {"truong_khong_co": 1}


def test_without_flag_repair_loop_is_unchanged(work):
    """v1 (tuyến A) không bật cờ: vẫn sửa đủ trần như trước."""
    con = connect(work)
    llm = MockClient(responses=[{"rule_yaml": WMI_FILTER}] * 3)
    r = S5.generate_rule(_hyp(19, ["EventNamespace", "Query"]), llm, P5, LS, 2, _cols(con), con)
    assert (len(llm.calls), r["so_lan_sua"]) == (3, 2)
    assert all(a["loai"] != "dung_sua" for a in r["lan_thu"])


def test_source_with_events_still_repairs_missing_field(work):
    """Nguồn có sự kiện: mô hình có thể đổi sang trường có thật, nên vẫn cho sửa."""
    con = connect(work)
    good = PROC_BAD_FIELD.replace("TruongKhongCo", "Image")
    llm = MockClient(responses=[{"rule_yaml": PROC_BAD_FIELD}, {"rule_yaml": good}])
    r = S5.generate_rule(_hyp(1, ["Image"]), llm, P5, LS, 2, _cols(con), con, stop_repair_on_empty_source=True)
    assert (len(llm.calls), r["hop_le"], r["so_lan_sua"]) == (2, True, 1)
    assert "[truong_khong_co]" in llm.calls[1][1]


def test_other_errors_on_empty_source_still_repair(work):
    con = connect(work)
    bad = WMI_FILTER.replace("EventNamespace|contains", "EventNamespace|containss")
    llm = MockClient(responses=[{"rule_yaml": bad}, {"rule_yaml": WMI_FILTER}])
    r = S5.generate_rule(_hyp(19, ["EventNamespace"]), llm, P5, LS, 2, _cols(con), con,
                         stop_repair_on_empty_source=True)
    assert len(llm.calls) == 2                                  # sigma_loi vẫn được sửa
    assert [i["kind"] for i in r["lan_thu"][0]["loi"]] == ["sigma_loi"]
    assert r["lan_thu"][-1]["loai"] == "dung_sua"               # lỗi thiếu trường sau đó mới dừng


def test_flag_only_in_v2_config():
    assert agent_config("v2").get("dung_sua_khi_nguon_rong") is True
    assert "dung_sua_khi_nguon_rong" not in agent_config("v1")
