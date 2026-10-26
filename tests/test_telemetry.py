"""Khâu ③ — tra bảng nguồn log."""
import pytest
import yaml

from cti_hunt.attack.catalog import AttackCatalog
from cti_hunt.config import ROOT, load as load_cfg, resolve
from cti_hunt.stages import s3_telemetry

CATALOG = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")


def test_shipped_catalog_is_valid_and_covers_scope():
    scope = {"T1047", "T1021.006", "T1569.002", "T1546.003", "T1547.001", "T1550.003", "T1136.001"}
    assert scope <= set(CATALOG)
    assert {e["status"] for e in CATALOG.values()} <= set(s3_telemetry.STATUSES)


def test_not_huntable_is_a_real_answer():
    assert s3_telemetry.map_technique("T1021.004", CATALOG)["status"] == "not_huntable"


def test_unknown_technique_falls_back_to_parent_then_not_huntable():
    assert s3_telemetry.map_technique("T1047", CATALOG)["status"] == "huntable"
    assert s3_telemetry.map_technique("T1047.999", CATALOG)["status"] == "huntable"      # cha T1059… có mục con
    r = s3_telemetry.map_technique("T9999.999", CATALOG)
    assert r["status"] == "not_huntable"


@pytest.mark.parametrize("bad", [
    {"techniques": {"T1": {"status": "co_the"}}},
    {"techniques": {"T1": {"status": "huntable", "sources": [{"channel": "x"}]}}},   # thiếu event_ids
])
def test_invalid_catalog_rejected(tmp_path, bad):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        s3_telemetry.load_catalog(p)


def test_every_technique_id_exists_in_attack_v19():
    stix = resolve(load_cfg("reports")["attack"]["stix_path"])
    if not stix.exists():
        pytest.skip("chưa có file STIX v19.2 trong data/attack")
    cat = AttackCatalog.from_stix(stix)
    bad = [t for t in CATALOG if cat.resolve(t).status != "ok"]
    assert bad == []


# ---------- ghi chú đi vào prompt khâu ④ và hunt record: không mang thông tin suy từ nhãn ----------

def test_step_ids_in_notes_are_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"techniques": {"T1": {"status": "huntable", "ghi_chu": "đúng sự kiện của bước 15.A"}}},
                                allow_unicode=True), encoding="utf-8")
    with pytest.raises(ValueError, match="mã bước"):
        s3_telemetry.load_catalog(p)


def test_route_a_catalog_is_the_generator_baseline():
    """N2 §4: tuyến A dùng đúng 18 mục D17; bộ sinh v2 dùng cùng 18 mục làm lớp ghi đè."""
    assert (ROOT / "configs" / "telemetry_catalog.yaml").read_bytes() == \
        (ROOT / "configs" / "telemetry_baseline.yaml").read_bytes()


def test_catalog_v2_keeps_route_a_entries():
    v2 = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog_v2.yaml")
    assert {t: v2[t] for t in CATALOG} == CATALOG


@pytest.mark.parametrize("name", ["telemetry_catalog.yaml", "telemetry_catalog_v2.yaml", "telemetry_catalog_v2_1.yaml",
                                  "telemetry_catalog_v2_2.yaml", "logsource_catalog.yaml"])
def test_shipped_catalogs_carry_no_label_derived_text(name):
    text = (ROOT / "configs" / name).read_text(encoding="utf-8")
    assert not s3_telemetry.STEP_ID.search(text)
    assert "implant" not in text.lower()


def test_model_input_of_khau4_has_no_step_ids():
    from cti_hunt.contracts import ContractA, SourceSpan, TTP
    from cti_hunt.stages import s4_hypothesis
    ca = ContractA(report_id="TU", ttps=[TTP(tactic="x", technique_id=t, source_span=SourceSpan(), confidence=0.5)
                                         for t in CATALOG])
    rendered = s4_hypothesis.render_inputs(s4_hypothesis.select_inputs(ca, CATALOG)[0])
    assert not s3_telemetry.STEP_ID.search(rendered) and "implant" not in rendered.lower()


# ---------- khâu ③ ↔ khâu ⑤: mọi nguồn log giả thuyết được dùng phải có logsource Sigma ----------

KNOWN_GAPS = {"microsoft-windows-terminalservices-remoteconnectionmanager/operational"}   # SigmaHQ không có logsource


@pytest.mark.parametrize("name", ["telemetry_catalog.yaml", "telemetry_catalog_v2.yaml", "telemetry_catalog_v2_1.yaml",
                                  "telemetry_catalog_v2_2.yaml"])
def test_every_telemetry_source_has_a_sigma_logsource(name):
    from itertools import combinations
    from cti_hunt.adapters import duckdb_sigma
    from cti_hunt.contracts import ContractB, Evidence
    from cti_hunt.stages.s5_rule import logsources_for
    ls = duckdb_sigma.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
    missing = []
    for tid, entry in s3_telemetry.load_catalog(ROOT / "configs" / name).items():
        for src in entry.get("sources") or []:
            if src["channel"] in KNOWN_GAPS or entry.get("status") != "huntable":
                continue
            eids = src["event_ids"]
            for sub in (list(c) for k in range(1, len(eids) + 1) for c in combinations(eids, k)):
                h = ContractB(hypothesis_id="X", behavior="b", scope="s", timeframe="t", linked_ttps=[tid],
                              evidence=Evidence(data_source=src["channel"], event_ids=sub,
                                                key_fields=src["key_fields"][:1]))
                if not logsources_for(h, ls):
                    missing.append((tid, src["channel"], sub))
    assert missing == []


# ---------- danh mục chung + hồ sơ theo bộ dữ liệu ----------

import json
import re

from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.data.store import connect
from cti_hunt.stages import s4_hypothesis, s9_record

SYSMON = "microsoft-windows-sysmon/operational"
WMI = "microsoft-windows-wmi-activity/operational"
BITS = "microsoft-windows-bits-client/operational"


def _src(channel, eids, keys, required):
    return {"channel": channel, "event_ids": eids, "key_fields": keys, "truong_bat_buoc": required}


# Fixture conftest: kênh sysmon (EID 1 có ParentImage, Image — không có CommandLine), system, security (4688),
# powershell/operational (4104 có ScriptBlockText). Không có WMI-Activity, BITS.
FIX_CATALOG = {
    "T1": {"status": "huntable", "sources": [_src(WMI, [5861], ["Message", "Hostname"], ["Message"])]},
    "T2": {"status": "huntable", "ghi_chu": "Ghi chú chung.", "sources": [
        _src(SYSMON, [1], ["ParentImage", "Image", "CommandLine", "Hostname"], ["Image"]),
        _src(BITS, [306], ["Message", "Hostname"], ["Message"])]},
    "T3": {"status": "partial", "ly_do_partial": "Chỉ thấy lúc cài.", "sources": [
        _src("security", [4697], ["ServiceName", "Hostname"], ["ServiceName"])]},
    "T4": {"status": "huntable", "sources": [
        _src("security", [4688], ["NewProcessName", "ScriptBlockText", "Hostname"], ["ScriptBlockText"])]},
}


def _catalog_file(tmp_path, techniques):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"techniques": techniques}, allow_unicode=True), encoding="utf-8")
    return p


def _ok_source():
    return [_src(SYSMON, [1], ["Image", "Hostname"], ["Image"])]


@pytest.mark.parametrize("key,text", [
    ("ghi_chu", "4697 = 18, không có System 7045."),
    ("ghi_chu", "Phía nguồn qua PS 4104 (716 sự kiện)."),
    ("ghi_chu", "4697 chỉ 18 lần ghi."),
    ("ghi_chu", "System 7045 KHÔNG có trong tập dữ liệu."),
    ("ly_do_partial", "Không có WinRM Operational (v3 §3.4)."),
    ("ly_do_partial", "Bộ dữ liệu này không có log BITS."),
])
def test_general_catalog_rejects_counts_dataset_claims_and_report_refs(tmp_path, key, text):
    entry = {"status": "partial", "ly_do_partial": "Lý do chung.", "sources": _ok_source(), key: text}
    with pytest.raises(ValueError, match="phần chung"):
        s3_telemetry.load_catalog(_catalog_file(tmp_path, {"T1": entry}))


@pytest.mark.parametrize("entry,match", [
    ({"status": "partial", "sources": _ok_source()}, "ly_do_partial"),
    ({"status": "partial", "ly_do_partial": "  ", "sources": _ok_source()}, "ly_do_partial"),
    ({"status": "huntable", "sources": [{"channel": SYSMON, "event_ids": [1], "key_fields": ["Image"]}]},
     "truong_bat_buoc"),
    ({"status": "huntable", "sources": [_src(SYSMON, [1], ["Image"], ["CommandLine"])]}, "truong_bat_buoc"),
])
def test_partial_needs_reason_and_every_source_declares_required_fields(tmp_path, entry, match):
    with pytest.raises(ValueError, match=match):
        s3_telemetry.load_catalog(_catalog_file(tmp_path, {"T1": entry}))


def test_shipped_catalog_is_general_and_has_the_added_sources():
    text = (ROOT / "configs" / "telemetry_catalog.yaml").read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "v3" not in body and "tập dữ liệu" not in body and not re.search(r"\d[\d.,]*\s*sự kiện", body)
    assert all(e.get("ly_do_partial") for e in CATALOG.values() if e["status"] == "partial")
    srcs = {tid: [(s["channel"], s["event_ids"]) for s in e.get("sources") or []] for tid, e in CATALOG.items()}
    assert ("system", [7045]) in srcs["T1569.002"] and ("system", [7045]) in srcs["T1543.003"]
    assert ("security", [4699, 4700]) in srcs["T1053.005"]


def test_profile_drops_source_only_for_absent_channel_or_missing_required_field(work):
    p = s3_telemetry.build_profile(connect(work), FIX_CATALOG, "TU-fixture")
    rows = {tid: e["nguon"] for tid, e in p["ky_thuat"].items()}
    # Kênh vắng -> bỏ nguồn; kỹ thuật chỉ có nguồn đó -> not_huntable.
    assert (rows["T1"][0]["giu"], rows["T1"][0]["ly_do_bo"]) == (False, "kenh_khong_thu_thap")
    assert p["ky_thuat"]["T1"]["trang_thai"] == "not_huntable"
    # Một nguồn vắng, một nguồn còn: giữ trạng thái. Trường khóa không bắt buộc (CommandLine) thiếu thì chỉ ghi lại.
    assert [r["giu"] for r in rows["T2"]] == [True, False] and p["ky_thuat"]["T2"]["trang_thai"] == "huntable"
    assert rows["T2"][0]["truong_khong_co_gia_tri"] == ["CommandLine"] and rows["T2"][0]["so_su_kien"] == 5
    # Kênh đã thu thập nhưng mã sự kiện chưa có sự kiện nào: vẫn giữ (M1), chưa kiểm được trường.
    t3 = rows["T3"][0]
    assert (t3["giu"], t3["kenh_thu_thap"], t3["so_su_kien"], t3["da_kiem_truong"]) == (True, True, 0, False)
    assert p["ky_thuat"]["T3"]["trang_thai"] == "partial"
    # Nguồn có sự kiện mà trường bắt buộc không có giá trị ở sự kiện nào (cột có, nhưng thuộc kênh khác): bỏ.
    assert (rows["T4"][0]["giu"], rows["T4"][0]["ly_do_bo"]) == (False, "thieu_truong_bat_buoc")
    assert p["ky_thuat"]["T4"]["trang_thai"] == "not_huntable"
    assert p["dataset_id"] == "TU-fixture" and p["kenh"][SYSMON] == 5 and p["kenh"][WMI] == 0
    # Xác định: cùng events + cùng danh mục thì cùng SHA256.
    assert s3_telemetry.profile_sha256(p) == s3_telemetry.profile_sha256(
        s3_telemetry.build_profile(connect(work), FIX_CATALOG, "TU-fixture"))


def test_effective_catalog_keeps_order_and_rejects_profile_of_another_catalog(work):
    p = s3_telemetry.build_profile(connect(work), FIX_CATALOG, "TU")
    eff = s3_telemetry.apply_profile(FIX_CATALOG, p)
    assert [s["channel"] for s in eff["T2"]["sources"]] == [SYSMON] and eff["T1"]["sources"] == []
    assert eff["T3"]["ghi_chu"].startswith("Chỉ thấy lúc cài. Bộ dữ liệu đang chạy: có thu thập security")
    assert "không thu thập " + WMI in eff["T1"]["ly_do"]
    other = {k: v for k, v in FIX_CATALOG.items() if k != "T4"}
    with pytest.raises(ValueError, match="danh mục khác"):
        s3_telemetry.apply_profile(other, p)
    moved = {**FIX_CATALOG, "T2": {**FIX_CATALOG["T2"], "sources": FIX_CATALOG["T2"]["sources"][::-1]}}
    with pytest.raises(ValueError, match="lập lại hồ sơ"):
        s3_telemetry.apply_profile(moved, p)


def _eids(entry):
    return {str(x) for s in entry.get("sources") or [] for x in s["event_ids"]}


def test_prompt_khau4_carries_profile_line_without_event_counts(work):
    """M2: dòng hồ sơ chỉ nói kênh có/không thu thập và trường khóa không có giá trị; số đếm chỉ ở JSON hồ sơ."""
    p = s3_telemetry.build_profile(connect(work), CATALOG, "TU")
    eff = s3_telemetry.apply_profile(CATALOG, p)
    assert any(r["so_su_kien"] > 0 for e in p["ky_thuat"].values() for r in e["nguon"])   # số có trong JSON
    ca = ContractA(report_id="TU", ttps=[TTP(tactic="x", technique_id=t, source_span=SourceSpan(), confidence=0.5)
                                         for t in CATALOG])
    rows = json.loads(s4_hypothesis.render_inputs(s4_hypothesis.select_inputs(ca, eff)[0]))
    assert len(rows) == sum(1 for e in CATALOG.values() if e["status"] != "not_huntable")
    for row in rows:
        entry = CATALOG[row["technique_id"]]
        general = " ".join(x for x in (entry.get("ly_do_partial", "") if entry["status"] == "partial" else "",
                                       entry.get("ghi_chu", "")) if x)
        note = row["telemetry_note"]
        assert note.startswith(general) and "Bộ dữ liệu đang chạy:" in note
        line = note[len(general):]
        assert set(re.findall(r"\d+", line)) <= _eids(entry), (row["technique_id"], line)
    text = json.dumps(rows, ensure_ascii=False)
    assert not re.search(r"\d[\d.,]*\s*sự kiện|=\s*\d", text)


def test_hunt_record_uses_the_same_profile(work):
    p = s3_telemetry.build_profile(connect(work), FIX_CATALOG, "TU")
    eff = s3_telemetry.apply_profile(FIX_CATALOG, p)
    ca = ContractA(report_id="TU", ttps=[TTP(tactic="x", technique_id=t, technique_name=f"Tên {t}",
                                             source_span=SourceSpan(), confidence=0.5) for t in ("T1", "T2", "T3")])
    md = s9_record.render(ca, eff, [], [])
    cov = [line for line in md.split("### Bảng độ phủ")[1].splitlines() if line.startswith("| T")]
    assert any(line.startswith("| T2 | Tên T2 | huntable | " + SYSMON + " [1] |") for line in cov)
    assert all(BITS not in line.split(" | ")[3] for line in cov)          # nguồn bị bỏ không còn trong cột nguồn
    keep = md.split("## Keep")[1]
    assert "| **T1** | Tên T1 | not_huntable | Không nguồn nào của kỹ thuật dùng được" in keep
    assert "| **T3** | Tên T3 | partial | Chỉ thấy lúc cài." in keep


def test_apt29_profile_keeps_every_source_and_status():
    """Tập đánh giá (không nhãn, chỉ đếm theo kênh/mã sự kiện/trường): M1 không bỏ nguồn nào, trạng thái giữ nguyên."""
    work_dir = resolve(load_cfg("dataset")["work_dir"])
    if not (work_dir / "events.parquet").exists():
        pytest.skip("chưa có data/work/events.parquet")
    p = s3_telemetry.build_profile(connect(work_dir), CATALOG, "apt29_day2")
    assert [(t, r["channel"], r["event_ids"]) for t, e in p["ky_thuat"].items() for r in e["nguon"] if not r["giu"] and t in ["T1047", "T1021.006", "T1021.002", "T1021.001", "T1021.003", "T1569.002", "T1550.003", "T1078", "T1021.004", "T1546.003", "T1547.001", "T1053.005", "T1543.003", "T1136.001", "T1112", "T1059.001", "T1218.011", "T1105"]] == []
    assert all(e["trang_thai"] == e["trang_thai_danh_muc"] for t, e in p["ky_thuat"].items() if t in ["T1047", "T1021.006", "T1021.002", "T1021.001", "T1021.003", "T1569.002", "T1550.003", "T1078", "T1021.004", "T1546.003", "T1547.001", "T1053.005", "T1543.003", "T1136.001", "T1112", "T1059.001", "T1218.011", "T1105"])


# ---------- 07/10: danh mục v2.1 = v2 + ProcessGuid ở nguồn Sysmon có trường đó ----------

def test_catalog_v2_1_is_exactly_v2_plus_process_guid():
    import importlib.util
    spec = importlib.util.spec_from_file_location("tao_v2_1", ROOT / "scripts" / "tao_danh_muc_v2_1.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert (ROOT / "configs" / "telemetry_catalog_v2_1.yaml").read_bytes() == script.render(ROOT)
    v2 = yaml.safe_load((ROOT / "configs" / "telemetry_catalog_v2.yaml").read_text(encoding="utf-8"))["techniques"]
    v21 = yaml.safe_load((ROOT / "configs" / "telemetry_catalog_v2_1.yaml").read_text(encoding="utf-8"))["techniques"]
    assert list(v2) == list(v21)
    added = 0
    for tid, entry in v2.items():
        new = v21[tid]
        assert {k: v for k, v in new.items() if k != "sources"} == {k: v for k, v in entry.items() if k != "sources"}
        assert len(new["sources"]) == len(entry["sources"])
        for old_src, new_src in zip(entry["sources"], new["sources"]):
            extra = new_src["key_fields"][len(old_src["key_fields"]):]
            assert {k: v for k, v in new_src.items() if k != "key_fields"} == \
                {k: v for k, v in old_src.items() if k != "key_fields"}
            assert new_src["key_fields"][:len(old_src["key_fields"])] == old_src["key_fields"]
            guid_source = old_src["channel"] == s3_telemetry.SYSMON and \
                set(old_src["event_ids"]) <= s3_telemetry.PROCESS_GUID_EIDS
            assert extra == (["ProcessGuid"] if guid_source else [])
            added += bool(extra)
    assert added == 854


def test_v2_pointer_uses_catalog_v2_2_and_route_a_is_unchanged():
    from cti_hunt import config
    assert config.telemetry_catalog("v2").name == "telemetry_catalog_v2_2.yaml"   # 09/10: v2.1 → v2.2 (B4)
    assert config.telemetry_catalog("v1").name == "telemetry_catalog.yaml"
    v21 = s3_telemetry.load_catalog(config.telemetry_catalog("v2"))
    sources = {(tuple(s["event_ids"]), "ProcessGuid" in s["key_fields"])
               for e in v21.values() for s in e.get("sources") or [] if s["channel"] == s3_telemetry.SYSMON}
    assert {((1,), True), ((3,), True), ((11,), True), ((22,), True), ((10,), False)} <= sources
    assert ((10,), True) not in sources and ((19, 20, 21), True) not in sources
    assert not any("ProcessGuid" in (s.get("key_fields") or []) for e in CATALOG.values() for s in e.get("sources") or [])


# ---------- 09/10: danh mục v2.2 = v2.1 + bốn sửa B4 có căn cứ không nhãn ----------

def test_catalog_v2_2_is_exactly_v2_1_plus_the_four_b4_edits():
    import importlib.util
    spec = importlib.util.spec_from_file_location("tao_v2_2", ROOT / "scripts" / "tao_danh_muc_v2_2.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert (ROOT / "configs" / "telemetry_catalog_v2_2.yaml").read_bytes() == script.render(ROOT)
    v21 = yaml.safe_load((ROOT / "configs" / "telemetry_catalog_v2_1.yaml").read_text(encoding="utf-8"))
    v22 = yaml.safe_load((ROOT / "configs" / "telemetry_catalog_v2_2.yaml").read_text(encoding="utf-8"))
    assert (v21["phien_ban"], v22["phien_ban"]) == ("1.3", "1.4") and list(v21["techniques"]) == list(v22["techniques"])
    changed = sorted(t for t in v21["techniques"] if v21["techniques"][t] != v22["techniques"][t])
    assert changed == ["T1012", "T1047", "T1070", "T1546.012"]
    sysmon = s3_telemetry.SYSMON

    def eids(t):
        return [(s["channel"], s["event_ids"]) for s in v22["techniques"][t]["sources"]]

    assert eids("T1546.012") == [(sysmon, [1]), (sysmon, [10]), (sysmon, [12]), (sysmon, [13])]
    assert v22["techniques"]["T1546.012"]["sources"][-1]["key_fields"] == ["Image", "TargetObject", "Details",
                                                                           "ProcessGuid"]
    assert eids("T1070") == [(sysmon, [12]), (sysmon, [13]), (sysmon, [14])]
    assert v22["techniques"]["T1070"]["sources"][0]["truong_bat_buoc"] == ["Image"]   # EventType không bắt buộc
    assert (sysmon, [13]) not in eids("T1012") and (sysmon, [14]) not in eids("T1012")
    assert v22["techniques"]["T1012"]["status"] == "huntable" and (sysmon, [1]) in eids("T1012")
    assert v22["techniques"]["T1047"]["sources"] == v21["techniques"]["T1047"]["sources"]   # chỉ đổi ghi chú
    assert v22["techniques"]["T1047"]["ghi_chu"].startswith(v21["techniques"]["T1047"]["ghi_chu"])
    for t in changed:                      # trạng thái và lý do partial giữ nguyên
        for key in ("status", "ly_do_partial"):
            assert v22["techniques"][t].get(key) == v21["techniques"][t].get(key)
    for t, entry in v21["techniques"].items():
        if t not in changed:
            assert v22["techniques"][t] == entry
    assert s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog_v2_2.yaml")


def test_process_guid_is_dropped_by_the_profile_where_empty():
    import duckdb
    con = duckdb.connect()
    con.execute("CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, "
                "Image VARCHAR, ProcessGuid VARCHAR)")
    con.execute("INSERT INTO events VALUES ('H', 'microsoft-windows-sysmon/operational', 1, 1, 'a.exe', '')")
    cat = {"T1059": {"status": "huntable", "sources": [
        {"channel": s3_telemetry.SYSMON, "event_ids": [1], "key_fields": ["Image", "ProcessGuid"],
         "truong_bat_buoc": ["Image"]}]}}
    eff = s3_telemetry.apply_profile(cat, s3_telemetry.build_profile(con, cat, "fixture"))
    assert eff["T1059"]["sources"][0]["key_fields"] == ["Image"] and eff["T1059"]["status"] == "huntable"
