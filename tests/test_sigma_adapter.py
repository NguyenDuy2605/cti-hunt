"""Adapter Sigma -> DuckDB. Kiểm các chỗ dễ sai: hoa thường, ánh xạ trường, nguồn log thiếu trường."""
from pathlib import Path

import pytest

from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.config import ROOT
from cti_hunt.hunt import runner

CATALOG = A.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")

RULE = """
title: {title}
logsource:
  product: windows
  category: {category}
detection:
  selection:
{selection}
  condition: selection
tags:
  - attack.t1047
"""


def rule_file(tmp_path, selection, category="process_creation", title="R"):
    p = tmp_path / "r.yml"
    p.write_text(RULE.format(title=title, category=category, selection=selection), encoding="utf-8")
    return p


def test_shipped_h03_compiles_to_one_hunt_per_source():
    hunts, skipped = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)
    assert [h.source for h in hunts] == ["sysmon_1", "security_4688"] and skipped == []
    assert hunts[0].linked_ttps == ["T1021.006", "T1047", "T1569.002"]
    assert "ILIKE" in hunts[0].candidates and "LIKE '" not in hunts[0].candidates.replace("ILIKE", "")
    # Security 4688 dùng tên trường khác
    assert "ParentProcessName" in hunts[1].candidates and "ParentImage" not in hunts[1].candidates
    for h in hunts:
        runner.validate(h.to_hunt_spec())          # luôn có scope.channel; mục lọc đủ 5 trường
    # filter_known_good tách khỏi ứng viên thành mục lọc, cùng ánh xạ trường theo nguồn
    assert "Image ILIKE" not in hunts[0].candidates.replace("ParentImage", "")
    assert [f["id"] for f in hunts[0].filters] == ["S-01"] and "Image ILIKE" in hunts[0].filters[0]["where"]
    assert "NewProcessName" in hunts[1].filters[0]["where"]


def test_runs_like_handwritten_hunt(con_labeled):
    con, _ = con_labeled
    hunts, _ = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)
    res = runner.run(con, hunts[0].to_hunt_spec(), [], [])
    cand, after = res["giai_doan"]
    # ứng viên = riêng `selection`: 4 con của WmiPrvSE/wsmprovhost/services, 2 của kẻ tấn công
    assert (cand["hits"], cand["attacker_events"], cand["fp"]) == (4, 2, 2)
    # khối filter_known_good thành mục lọc S-01: loại svchost, không loại nhầm
    assert (after["stage"], after["hits"], after["fp"]) == ("sau_S-01", 3, 1)
    assert (after["removed"], after["removed_attacker"]) == (1, 0)
    assert res["mau_so_fpr"]["su_kien_trong_pham_vi"] == 5
    assert res["muc_loc"][0]["nguon"] == "sigma_rule"


def test_branch_a_and_b_agree_stage_by_stage(con_labeled):
    """Cùng một rule, nhánh A (viết tay) và nhánh B (qua adapter) phải cho cùng số ở MỌI giai đoạn."""
    con, _ = con_labeled
    spec = runner.load_spec(ROOT / "hunts" / "manual" / "H-03.yaml")
    # F-02 là lọc riêng của nhánh A (không có trong rule Sigma) -> so từng giai đoạn tới F-01
    spec = dict(spec, filters=[f for f in spec["filters"] if f["id"] == "F-01"])
    manual = runner.run(con, spec, [], [])
    hunts, _ = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)
    auto = runner.run(con, hunts[0].to_hunt_spec(), [], [])
    pick = lambda r: [(g["hits"], g["attacker_events"], g["fp"], g["removed"]) for g in r["giai_doan"]]
    assert pick(manual) == pick(auto)


@pytest.mark.parametrize("selection", [
    "    ParentImage|endswith: '\\\\WMIPRVSE.EXE'",          # endswith -> ILIKE
    "    ParentImage|contains: 'WBEM'",                       # contains -> ILIKE
])
def test_matching_is_case_insensitive(con_labeled, tmp_path, selection):
    con, _ = con_labeled
    hunts, _ = A.compile_rule(rule_file(tmp_path, selection), CATALOG)
    res = runner.run(con, hunts[0].to_hunt_spec(), [], [])
    assert res["giai_doan"][0]["hits"] == 1


def test_plain_equality_is_case_insensitive_via_collation(con_labeled, tmp_path):
    con, _ = con_labeled
    hunts, _ = A.compile_rule(rule_file(tmp_path, "    Image: 'C:\\\\USERS\\\\MSCOTT\\\\M.EXE'"), CATALOG)
    res = runner.run(con, hunts[0].to_hunt_spec(), [], [])
    assert res["giai_doan"][0]["hits"] == 1


def test_percent_in_value_is_not_a_wildcard(con_labeled, tmp_path):
    con, _ = con_labeled
    hunts, _ = A.compile_rule(rule_file(tmp_path, "    Image|contains: '%APPDATA%'"), CATALOG)
    assert runner.run(con, hunts[0].to_hunt_spec(), [], [])["giai_doan"][0]["hits"] == 0


def test_source_without_field_is_skipped_with_reason(tmp_path):
    hunts, skipped = A.compile_rule(rule_file(tmp_path, "    ParentCommandLine|contains: 'wsmprovhost'"), CATALOG)
    assert [h.source for h in hunts] == ["sysmon_1"]
    assert len(skipped) == 1 and "ParentCommandLine" in skipped[0].ly_do


def test_logsource_not_in_dataset(tmp_path):
    hunts, skipped = A.compile_rule(rule_file(tmp_path, "    ImageLoaded: 'x'", category="driver_load"), CATALOG)
    assert hunts == [] and "driver_load" in skipped[0].ly_do


def test_unknown_column_is_static_check_failure(tmp_path):
    hunts, skipped = A.compile_rule(rule_file(tmp_path, "    KhongCoTruongNay: 'x'"), CATALOG,
                                    available_columns={"Image", "ParentImage"})
    assert hunts == [] and all("không có trong dữ liệu" in s.ly_do for s in skipped)


@pytest.mark.parametrize("cond, cand, filters", [
    ("selection", "selection", []),
    ("selection and not filter_known_good", "selection", ["filter_known_good"]),
    ("sel and not f1 and not f2", "sel", ["f1", "f2"]),
    ("(sel and not f)", "sel", ["f"]),
    ("sel and not 1 of filter_*", "sel", ["1 of filter_*"]),
    ("sel and not (f1 or f2)", "sel", ["(f1 or f2)"]),
    ("sel1 and sel2 and not f", "sel1 and sel2", ["f"]),
    ("(a or b) and not f", "(a or b)", ["f"]),
    ("Selection AND NOT Filter", "Selection", ["Filter"]),
])
def test_split_condition(cond, cand, filters):
    r = A.split_condition(cond)
    assert (r.candidates, r.filters, r.ghi_chu) == (cand, filters, "")


@pytest.mark.parametrize("cond", ["sel or other and not f", "not f"])
def test_split_condition_leaves_unsplittable_whole(cond):
    r = A.split_condition(cond)
    assert (r.candidates, r.filters) == (cond, []) and r.ghi_chu


TWO_FILTERS = """
title: Hai khoi loc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: ['\\WmiPrvSE.exe', '\\wsmprovhost.exe', '\\services.exe']
  filter_svc:
    Image|endswith: '\\svchost.exe'
  filter_spp:
    Image|endswith: '\\sppsvc.exe'
  condition: selection and not 1 of filter_*
"""


def test_split_gives_same_final_set_as_whole_condition(con_labeled, tmp_path):
    """Tách không được đổi kết quả cuối khi các trường không NULL."""
    from sigma.collection import SigmaCollection
    from cti_hunt.eval import exec_accuracy as ea
    con, _ = con_labeled
    p = tmp_path / "r.yml"
    p.write_text(TWO_FILTERS, encoding="utf-8")
    h = A.compile_rule(p, CATALOG)[0][0]
    assert len(h.filters) == 1 and h.filters[0]["mo_ta"].startswith("khối `1 of filter_*`")
    spec = h.to_hunt_spec()
    whole = A.DuckDBBackend().convert_rule(SigmaCollection.from_yaml(TWO_FILTERS).rules[0])[0]
    base = f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {runner._scope_where(spec['scope'])}"
    expected = set(con.execute(f"{base} AND ({whole})").fetchall())
    got = ea.result_keys(con, spec)
    assert got["cuoi"] == expected and len(got["ung_vien"]) == 4 and len(expected) == 2


def test_null_field_kept_like_sigma_not_dropped_like_sql():
    """Khác biệt có chủ ý: Image NULL -> Sigma coi filter không khớp nên giữ; `AND NOT` của SQL thì loại."""
    import duckdb
    from cti_hunt.eval import exec_accuracy as ea
    con = duckdb.connect()
    con.execute("""CREATE TABLE events AS SELECT * FROM (VALUES
        ('UTICA', 'microsoft-windows-sysmon/operational', 1, 1, TIMESTAMP '2020-05-02 08:00:00',
         'C:\\Windows\\System32\\services.exe', NULL::VARCHAR)
        ) t(ev_host, ev_channel, ev_eid, ev_rec, ev_ts, ParentImage, Image)""")
    h = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)[0][0]
    whole = f"({h.candidates}) AND NOT ({h.filters[0]['where']})"
    assert con.execute(f"SELECT count(*) FROM events WHERE {whole}").fetchone()[0] == 0
    assert len(ea.result_keys(con, h.to_hunt_spec())["cuoi"]) == 1


@pytest.mark.parametrize("selection, hits", [
    ("    ParentImage|re: '(wsmprovhost|WmiPrvSE)\\.exe$'", 2),    # nhóm lựa chọn, neo cuối chuỗi
    ("    Image|re: '\\\\m\\.exe$'", 1),                        # tìm kiếm, không cần khớp toàn chuỗi
    ("    Image|re: 'M\\.EXE$'", 0),                                # |re phân biệt hoa thường...
    ("    Image|re|i: 'M\\.EXE$'", 1),                              # ...trừ khi có |i
    ("    Image|re: \"o'brien\"", 0),                               # nháy đơn không làm vỡ SQL
])
def test_regex_runs_on_duckdb(con_labeled, tmp_path, selection, hits):
    con, _ = con_labeled
    hunts, _ = A.compile_rule(rule_file(tmp_path, selection), CATALOG)
    assert "REGEXP" not in hunts[0].candidates
    assert runner.run(con, hunts[0].to_hunt_spec(), [], [])["giai_doan"][0]["hits"] == hits


def test_numeric_compare_on_varchar_columns():
    """Trường gốc là VARCHAR: |gt phải so theo số ('10' > 9), không lỗi và không so theo chữ ('10' < '9')."""
    import duckdb
    con = duckdb.connect()
    con.execute("CREATE TABLE t AS SELECT * FROM (VALUES ('5'), ('10'), ('abc'), (NULL)) v(LogonType)")
    rule = ("title: t\nlogsource: {product: windows, category: process_creation}\ndetection:\n"
            "  selection:\n    LogonType|gt: 9\n  condition: selection\n")
    where = A.compile_text(rule, CATALOG)[0][0].candidates
    assert con.execute(f"SELECT LogonType FROM t WHERE {where}").fetchall() == [("10",)]


def test_bulk_check_classifies_rules(tmp_path):
    from cti_hunt.adapters import sigma_check as SC
    d = tmp_path / "rules"
    d.mkdir()
    ok = "title: a\nlogsource: {product: windows, category: process_creation}\ndetection:\n  s:\n    Image|re: 'a'\n  condition: s\n"
    (d / "ok.yml").write_text(ok, encoding="utf-8")
    (d / "ngoai.yml").write_text(ok.replace("process_creation", "driver_load"), encoding="utf-8")
    (d / "kw.yml").write_text(ok.replace("  s:\n    Image|re: 'a'", "  s:\n    - 'mimikatz'"), encoding="utf-8")
    (d / "hong.yml").write_text(ok.replace("|re", "|khongco"), encoding="utf-8")
    res = SC.check_dir(d, CATALOG)
    assert res["nhom"] == {"ok": 1, "ngoai_danh_muc": 1, "loi_backend": 1, "loi_sigma": 1}
    assert res["rule_ok"] == ["ok.yml"]
