"""Khâu ⑧ phần xác định: gom nhóm, tương quan chéo, đề xuất pivot — không nhìn nhãn, ngưỡng và trần do mã quyết."""
import copy
import json

import duckdb
import pytest

from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.hunt import runner
from cti_hunt.stages import s8_triage as T

SYS, SEC = "microsoft-windows-sysmon/operational", "security"
CFG = load_cfg("agent")


def cfg(**kw):
    c = copy.deepcopy(CFG)
    c["triage"].update(kw)
    return c


@pytest.fixture
def con():
    """Chỉ có bảng `events` — KHÔNG có view `labeled`: khâu ⑧ phải chạy được mà không cần nhãn."""
    c = duckdb.connect()
    c.execute("SET default_collation='nocase'")
    c.execute("""CREATE TABLE events AS SELECT ev_host, ev_channel, ev_eid, ev_rec, CAST(ev_ts AS TIMESTAMP) ev_ts,
                 Image, "User", SubjectUserName FROM (VALUES
      ('NEWYORK',  'microsoft-windows-sysmon/operational', 1, 1, '2020-05-02 08:04:00', 'C:\\Users\\mscott\\m.exe', 'DMEVALS\\mscott', NULL),
      ('SCRANTON', 'microsoft-windows-sysmon/operational', 1, 2, '2020-05-02 08:20:00', 'C:\\Windows\\System32\\net.exe', 'DMEVALS\\kmalone', NULL),
      ('UTICA',    'microsoft-windows-sysmon/operational', 1, 3, '2020-05-02 08:00:00', 'C:\\Windows\\System32\\svchost.exe', 'NT AUTHORITY\\SYSTEM', NULL),
      ('UTICA',    'microsoft-windows-sysmon/operational', 1, 4, '2020-05-02 07:59:00', 'C:\\x\\powershell.exe', 'DMEVALS\\dschrute', NULL),
      ('NEWYORK',  'security', 4688, 10, '2020-05-02 08:05:00', NULL, NULL, 'mscott'),
      ('UTICA',    'security', 4688, 11, '2020-05-02 08:01:00', NULL, NULL, 'UTICA$'),
      ('UTICA',    'security', 4688, 12, '2020-05-02 08:40:00', NULL, NULL, 'SYSTEM')
    ) v(ev_host, ev_channel, ev_eid, ev_rec, ev_ts, Image, "User", SubjectUserName)""")
    return c


SPECS = [
    {"id": "A__sysmon_1", "hypothesis_id": "TU-H01", "scope": {"channel": SYS, "event_ids": [1]},
     "candidates": "Image ILIKE '%.exe'", "filters": [{"id": "S-01", "where": "Image ILIKE '%svchost.exe'"}]},
    {"id": "B__security_4688", "hypothesis_id": "TU-H02", "scope": {"channel": SEC, "event_ids": [4688]},
     "candidates": "TRUE", "filters": []},
]


def test_correlation_normalizes_accounts_applies_filters_and_ranks(con):
    tr = T.triage(con, SPECS, cfg(max_pivots_per_round=2))
    multi = [(e["loai"], e["gia_tri"], e["so_gia_thuyet"], e["so_su_kien"]) for e in tr["thuc_the"]
             if e["so_gia_thuyet"] >= 2]
    # DMEVALS\mscott (Sysmon) và mscott (Security) là một tài khoản; UTICA chỉ 3 sự kiện vì svchost bị S-01 loại
    assert multi == [("may", "NEWYORK", 2, 2), ("tai_khoan", "mscott", 2, 2), ("may", "UTICA", 2, 3)]
    assert [h["so_su_kien"] for h in tr["hunts"]] == [3, 3]
    assert {e["gia_tri"] for e in tr["loai_tru"]} == {"system", "utica$"}       # hiện kèm lý do, không bỏ âm thầm
    p = tr["pivot"]
    assert [(x["loai"], x["gia_tri"], x["pivot_depth"]) for x in p["de_xuat"]] == [("may", "NEWYORK", 1),
                                                                                  ("tai_khoan", "mscott", 1)]
    assert all(x["status"] == "pending_review" for x in p["de_xuat"])
    assert {x["gia_tri"] for x in p["ung_vien_du_dieu_kien"]} == {"NEWYORK", "mscott", "UTICA"}
    assert p["chua_xet"] == [{"loai": "may", "gia_tri": "UTICA"}] and "mỗi vòng" in p["ly_do_dung"]
    assert "buoc" not in json.dumps(tr, default=str)


def test_time_clusters_stay_within_one_host(con):
    tr = T.triage(con, SPECS, cfg())
    got = [(c["may"], c["gia_thuyet"], c["so_su_kien"]) for c in tr["cum_thoi_gian"]]
    # UTICA 07:59 (H01) + 08:01 (H02) là một cụm; 08:40 tách riêng và chỉ 1 giả thuyết nên không hiện.
    # NEWYORK 08:04 + 08:05 là một cụm. SCRANTON không bao giờ được nối với máy khác.
    assert sorted(got) == [("NEWYORK", ["TU-H01", "TU-H02"], 2), ("UTICA", ["TU-H01", "TU-H02"], 2)]


def test_depth_query_caps_and_already_pivoted(con):
    tr = T.triage(con, SPECS, cfg(), pivot_depth=CFG["max_pivot_depth"])
    assert tr["pivot"]["de_xuat"] == [] and "trần độ sâu" in tr["pivot"]["ly_do_dung"]
    assert len(tr["pivot"]["chua_xet"]) == 3
    tr = T.triage(con, SPECS, cfg(max_queries_total=5), queries_used=4)
    assert len(tr["pivot"]["de_xuat"]) == 1 and "trần số truy vấn" in tr["pivot"]["ly_do_dung"]
    tr = T.triage(con, SPECS, cfg(), already_pivoted={("may", "NEWYORK")})
    assert [x["gia_tri"] for x in tr["pivot"]["da_pivot_truoc"]] == ["NEWYORK"]
    assert "NEWYORK" not in [x["gia_tri"] for x in tr["pivot"]["de_xuat"]]
    tr = T.triage(con, SPECS[:1], cfg())
    assert tr["pivot"]["ly_do_dung"] == "không còn thực thể vượt ngưỡng"


def test_from_runner_results_into_hunt_record(con_labeled):
    """Nối với runner thật (fixture chung) và hunt record: dùng truy vấn đã chạy, không dùng ket_qua_cuoi."""
    from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
    from cti_hunt.stages import s3_telemetry, s7_rarity, s9_record as S9
    c, _ = con_labeled
    CA = ContractA(report_id="TU", ttps=[TTP(tactic="Lateral Movement", technique_id="T1047", confidence=0.9,
                                              source_span=SourceSpan(text="tự soạn", segment_id="TU-001"))])
    TELEMETRY = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
    ev = Evidence(data_source=SYS, event_ids=[1], key_fields=["ParentImage", "Image"])
    hyp = lambda hid, prio: ContractB(hypothesis_id=hid, behavior="b", scope="s", timeframe="t", evidence=ev,
                                      linked_ttps=["T1047"], priority=prio, status="approved")
    spec = runner.load_spec(ROOT / "hunts" / "manual" / "H-03.yaml") | {"hypothesis_id": "TU-H01"}
    spec["filters"] = [f for f in spec["filters"] if f["id"] == "F-01"]   # fixture không có CommandLine/User
    other = dict(spec, id="all_exe", hypothesis_id="TU-H02", candidates="lower(Image) LIKE '%.exe'", filters=[])
    results = [runner.run(c, s, [], []) for s in (spec, other)]
    tr = T.triage(c, [T.spec_from_result(r) for r in results], cfg())
    hosts2 = sorted(e["gia_tri"] for e in tr["thuc_the"] if e["so_gia_thuyet"] == 2)
    assert hosts2 and all(h.upper().startswith(("UTICA", "NEWYORK")) for h in hosts2)
    hyps = [hyp("TU-H01", "cao"), hyp("TU-H02", "thap")]
    rarity = s7_rarity.score(c, [spec, other])
    md = S9.render(CA, TELEMETRY, hyps, results, triage=tr, rarity=rarity)
    assert "Cụm thời gian" in md and "Điểm độ hiếm:** cao nhất" in md
    assert "chờ duyệt" in md and "buoc" not in md and "14.B" not in md
    mismatched = {**rarity, "su_kien": [{**x, "hunt_sha256": "other"} for x in rarity["su_kien"]]}
    md_old = S9.render(CA, TELEMETRY, hyps, results, rarity=mismatched)
    assert S9.MISSING_7 in md_old
    old_version = {**rarity, "tham_so": {**rarity["tham_so"], "version": "khau7_cu"}}
    assert S9.MISSING_7 in S9.render(CA, TELEMETRY, hyps, results, rarity=old_version)
    with pytest.raises(ValueError, match="truy_van"):
        T.spec_from_result({"hunt": {"id": "cu"}, "giai_doan": []})
