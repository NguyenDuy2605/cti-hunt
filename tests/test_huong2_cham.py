"""Chấm hướng 2 (giao thức `docs/METHODOLOGY.md`) trên dữ liệu tổng hợp: phạm vi nhãn L1, báo nhầm chỉ trong E, khớp ngoài
phạm vi, khớp chéo, FPR theo hunt, cổng độ rộng, đối chứng toàn bộ, phép đo phụ L2, bỏ bộ và dùng lại tập khớp."""
import importlib.util
import json
import sys
import types

import duckdb
import pytest
import yaml

from cti_hunt import config

SYS = "microsoft-windows-sysmon/operational"
COT = ("ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, ev_ts TIMESTAMP, Image VARCHAR, "
       "ParentImage VARCHAR, TargetObject VARCHAR, NewProcessName VARCHAR, ParentProcessName VARCHAR")

# (bộ, kỹ thuật, [(kênh, mã, rec, Image, ParentImage, TargetObject, NewProcessName, ParentProcessName)])
BO = {
    "ad.T1059.001.a": ("T1059.001", [
        (SYS, 1, 1, r"C:\w\powershell.exe", r"C:\w\WmiPrvSE.exe", None, None, None),    # tấn công
        (SYS, 1, 2, r"C:\w\notepad.exe", r"C:\w\explorer.exe", None, None, None),       # nền
        (SYS, 1, 3, r"C:\w\powershell.exe", r"C:\w\explorer.exe", None, None, None),    # bình thường
        ("security", 4688, 10, None, None, None, r"C:\w\powershell.exe", r"C:\w\WmiPrvSE.exe")]),
    "ad.T1112.b": ("T1112", [
        (SYS, 13, 1, None, None, r"HKLM\soft\evil\x", None, None),                     # tấn công
        (SYS, 13, 2, None, None, r"HKLM\soft\good", None, None),
        (SYS, 13, 3, None, None, r"HKLM\soft\other", None, None)]),                    # nền
    "ad.T1059.001.c": ("T1059.001", [                                                    # ngoài L1: không có nhãn
        (SYS, 1, 1, r"C:\w\powershell.exe", r"C:\w\explorer.exe", None, None, None)]),
    "ad.T1027.d": ("T1027", [
        (SYS, 1, 1, r"C:\w\powershell.exe", r"C:\w\WmiPrvSE.exe", None, None, None),    # tấn công, kỹ thuật khác
        (SYS, 1, 2, r"C:\w\cmd.exe", r"C:\w\explorer.exe", None, None, None)]),
}
TAN_CONG = [("ad.T1059.001.a", SYS, 1), ("ad.T1112.b", SYS, 1), ("ad.T1027.d", SYS, 1)]
NEN = [("ad.T1059.001.a", SYS, 2), ("ad.T1112.b", SYS, 3)]
L1 = ["ad.T1059.001.a", "ad.T1112.b", "ad.T1027.d"]

SIGMA = {
    "ps_high.yml": r"""title: Synthetic PowerShell from non-explorer
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
logsource: {product: windows, category: process_creation}
references: [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md]
detection:
  selection:
    Image|endswith: '\powershell.exe'
  filter_explorer:
    ParentImage|endswith: '\explorer.exe'
  condition: selection and not filter_explorer
tags: [attack.execution, attack.t1059.001]
""",
    "reg_medium.yml": r"""title: Synthetic registry evil
id: 22222222-2222-2222-2222-222222222222
status: stable
level: medium
logsource: {product: windows, category: registry_set}
detection:
  selection:
    TargetObject|contains: '\evil\'
  condition: selection
tags: [attack.t1112]
""",
    "notepad_high.yml": r"""title: Synthetic notepad, technique without dataset
id: 33333333-3333-3333-3333-333333333333
status: stable
level: high
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\notepad.exe'
  condition: selection
tags: [attack.t1003]
""",
}

HE_THONG = {
    "T1059.001": [{"id": "AD-T1059-001-H01", "scope": {"channel": SYS, "event_ids": [1]},
                   "candidates": "lower(Image) LIKE '%powershell.exe'",
                   "filters": [{"id": "f", "where": "lower(ParentImage) LIKE '%explorer.exe'"}]}],
    "T1112": [{"id": "AD-T1112-H01", "scope": {"channel": "security", "event_ids": [4698]}, "candidates": "TRUE"},
              {"id": "AD-T1112-H02", "scope": {"channel": SYS, "event_ids": [13]},
               "candidates": "lower(TargetObject) LIKE '%good%'"}],
}


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("huong2_cham_test", config.ROOT / "scripts/huong2_cham.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "huong2_cham_test", mod)
    spec.loader.exec_module(mod)

    class Cat:                                   # mã ATT&CK giữ nguyên, không cần tệp STIX
        @classmethod
        def from_stix(cls, path):
            return cls()

        def resolve(self, k):
            return types.SimpleNamespace(final=k)
    monkeypatch.setattr(mod, "AttackCatalog", Cat)
    return mod


def _keys(rows):
    return [(b, "H", ch, rec) for b, ch, rec in rows]


@pytest.fixture
def du_lieu(tmp_path):
    pq = tmp_path / "parquet"
    con = duckdb.connect()
    tom_tat = {}
    for i, (bo, (kt, evs)) in enumerate(BO.items()):
        d = pq / bo
        d.mkdir(parents=True)
        con.execute(f"CREATE OR REPLACE TABLE t ({COT})")
        for ch, eid, rec, *f in evs:
            con.execute("INSERT INTO t VALUES ('H', ?, ?, ?, TIMESTAMP '2024-01-01 00:00:00', ?, ?, ?, ?, ?)", [ch, eid, rec, *f])
        con.execute(f"COPY t TO '{(d / 'events.parquet').as_posix()}' (FORMAT parquet)")
        tom_tat[f"tep{i}"] = {"trang_thai": "ok", "ma_bo": bo, "ky_thuat": [kt]}
    (pq / "tom_tat_nap.json").write_text(json.dumps(tom_tat), encoding="utf-8")
    for ten, rows in (("nhan.parquet", TAN_CONG), ("nen.parquet", NEN)):
        con.execute("CREATE OR REPLACE TABLE n (bo VARCHAR, ev_host VARCHAR, ev_channel VARCHAR, ev_rec BIGINT)")
        for r in _keys(rows):
            con.execute("INSERT INTO n VALUES (?, ?, ?, ?)", list(r))
        con.execute(f"COPY n TO '{(tmp_path / ten).as_posix()}' (FORMAT parquet)")
    (tmp_path / "pham_vi.json").write_text(json.dumps({"bo": [{"bo": b} for b in L1]}), encoding="utf-8")
    sinh = tmp_path / "sinh"
    for kt, specs in HE_THONG.items():
        d = sinh / "ky_thuat" / kt / "hunts"
        d.mkdir(parents=True)
        for s in specs:
            (d / f"{s['id']}.yaml").write_text(yaml.safe_dump(s, allow_unicode=True), encoding="utf-8")
    sig = tmp_path / "sigmahq" / "rules" / "windows"
    sig.mkdir(parents=True)
    for ten, text in SIGMA.items():
        (sig / ten).write_text(text, encoding="utf-8")
    return tmp_path


def _chay(m, p, *extra, out="out"):
    args = ["--parquet", str(p / "parquet"), "--sinh-rule", str(p / "sinh"), "--nhan", str(p / "nhan.parquet"),
            "--pham-vi", str(p / "pham_vi.json"), "--sigmahq", str(p / "sigmahq"), "--db", str(p / "chung.duckdb"),
            "--out", str(p / out), *extra]
    assert m.main(args) == 0
    return json.loads((p / out / "ket_qua.json").read_text(encoding="utf-8"))


def test_chi_so_chinh_chi_tinh_trong_pham_vi_nhan(m, du_lieu):
    kq = _chay(m, du_lieu, "--nen", str(du_lieu / "nen.parquet"), "--doi-chung-toan-bo")
    assert (kq["so_bo_L1"], kq["so_ky_thuat_T"], kq["so_su_kien_A"], kq["so_su_kien_E"]) == (3, 3, 3, 8)
    c = kq["cach"]
    # SigmaHQ mức cao: khối lọc của rule bỏ powershell do explorer chạy; d1 là tấn công của bộ T1027 (khớp chéo);
    # sự kiện Security nằm ngoài E nên chỉ là khớp ngoài phạm vi, không phải báo nhầm.
    assert (c["sigmahq_cao"]["bat_duoc"], c["sigmahq_cao"]["do_phu"], c["sigmahq_cao"]["bao_nham"]) == (1, 1, 0)
    assert c["sigmahq_cao"]["khop_ngoai_pham_vi_nhan"] == 1
    assert c["sigmahq_cao"]["khop_cheo_tan_cong"] == {"cap": 1, "su_kien": 1}
    assert c["sigmahq_cao"]["precision"] == 1.0
    assert c["sigmahq_moi_muc"]["bat_duoc"] == 2                      # rule medium bắt T1112
    # Hệ thống: mục lọc mô hình đề xuất không áp; bộ ngoài L1 không tính báo nhầm; hunt Security không có FPR.
    h = c["he_thong"]
    assert (h["bat_duoc"], h["do_phu"], h["bao_nham"], h["khop_ngoai_pham_vi_nhan"]) == (1, 2, 2, 1)
    assert h["precision"] == 0.5
    assert h["fpr_theo_hunt"] == {"so_hunt_tinh": 2, "trung_vi": 0.5, "lon_nhat": 0.5, "so_hunt_tren_1pct": 2}
    assert list(kq["he_thong_hunt_bi_danh_dau_rong"]) == ["AD-T1059-001-H01"]     # giữ 4/6 Sysmon 1
    assert c["he_thong_bo_rong"]["bat_duoc"] == 0
    assert c["lai"]["bat_duoc"] == 1
    # Đối chứng: mọi rule mức cao, không xét tag — bắt cả T1027 nhờ rule của T1059.001, và báo nhầm notepad.
    tb = c["sigmahq_cao_toan_bo"]
    assert (tb["bat_duoc"], tb["bao_nham"], tb["khop_cheo_tan_cong"]) == (2, 1, None)
    assert kq["so_cap"]["he_thong_vs_sigmahq_cao"] == {"chi_thu_nhat": 0, "chi_thu_hai": 0, "p": 1.0}
    assert [d["ky_thuat"] for d in kq["doi_dau"]] == ["T1059.001"]
    assert kq["tham_chieu_atomic"]["sigmahq_cao"] == {"so_rule": 1, "co_tham_chieu_atomic": 1}


def test_phep_do_phu_L2_va_dung_lai_tap_khop(m, du_lieu):
    kq = _chay(m, du_lieu, "--nen", str(du_lieu / "nen.parquet"))
    assert kq["so_hunt_chay_moi"] > 0
    l2 = kq["phu_L2"]
    # Hunt hệ thống của T1112 khớp b2 (không thuộc nền) nên "khớp được" — đúng là phép đo yếu, không phải recall.
    assert l2["tren_ky_thuat_he_thong"] == {"T1059.001": {"he_thong": 1, "sigmahq_cao": 1, "sigmahq_moi_muc": 1},
                                            "T1112": {"he_thong": 1, "sigmahq_cao": 0, "sigmahq_moi_muc": 1}}
    assert l2["cach"]["he_thong"] == {"co_hunt": 2, "khop_duoc": 2, "khop_cheo_su_kien": 1}
    kq2 = _chay(m, du_lieu, out="out2")
    assert kq2["so_hunt_chay_moi"] == 0                               # cùng tệp DuckDB: không chạy lại hunt
    assert kq2["cach"] == {k: v for k, v in kq["cach"].items()}


def test_bo_loai_bo_khoi_pham_vi_va_kiem_bam(m, du_lieu):
    (du_lieu / "bo_loai.json").write_text(json.dumps({"bo": ["ad.T1027.d"]}), encoding="utf-8")
    kq = _chay(m, du_lieu, "--bo-loai", str(du_lieu / "bo_loai.json"))
    assert (kq["so_bo_L1"], kq["so_ky_thuat_T"], kq["so_su_kien_A"]) == (2, 2, 2)
    assert kq["cach"]["sigmahq_cao"]["khop_ngoai_pham_vi_nhan"] == 2     # d1 nay ngoài phạm vi, cùng sự kiện Security
    with pytest.raises(SystemExit):
        _chay(m, du_lieu, "--sha-nhan", "0" * 64, out="out3")
    (du_lieu / "bo_la.json").write_text(json.dumps({"bo": ["ad.T1059.001.c"]}), encoding="utf-8")
    with pytest.raises(SystemExit):                                   # bộ ngoài L1 không bỏ được
        _chay(m, du_lieu, "--bo-loai", str(du_lieu / "bo_la.json"), out="out4")


def test_bo_sung_danh_muc_chi_them_category_moi(m, tmp_path):
    root = tmp_path / "sigmahq"
    (root / "rules" / "windows").mkdir(parents=True)
    (root / "rules" / "windows" / "crt.yml").write_text(r"""title: Synthetic remote thread
id: 44444444-4444-4444-4444-444444444444
status: test
level: high
logsource: {product: windows, category: create_remote_thread}
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
  condition: selection
tags: [attack.t1055]
""", encoding="utf-8")
    cols = {"ev_host", "ev_channel", "ev_eid", "ev_rec", "TargetImage", "SourceImage", "Hostname"}
    cao, _, bo = m.specs_sigmahq({"T1055": None}, cols, root)
    assert cao == {} and "create_remote_thread" in bo[0]["ly_do"]
    them = config.ROOT / "eval/inputs/huong2/bo_sung_danh_muc_cham.yaml"
    dm = m.danh_muc_cham(them, tmp_path)
    cao, _, _ = m.specs_sigmahq({"T1055": None}, cols, root, dm)
    assert [s["scope"]["event_ids"] for s in cao["T1055"]] == [[8]]
    trung = tmp_path / "trung.yaml"
    trung.write_text("process_creation: []\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        m.danh_muc_cham(trung, tmp_path)


def test_phep_bang_cua_sigma_khong_phan_biet_hoa_thuong(m, tmp_path):
    """Adapter dịch phép bằng của Sigma thành '=' và dựa vào default_collation='nocase' (như store.connect). Tệp DuckDB của
    script chấm phải đặt chế độ đó, không thì rule bằng tuyệt đối bị đếm thiếu khi log viết khác kiểu chữ (lỗi 19/10)."""
    pq = tmp_path / "parquet" / "ad.T1059.001.a"
    pq.mkdir(parents=True)
    con = duckdb.connect()
    con.execute(f"CREATE TABLE t ({COT})")
    con.execute("INSERT INTO t VALUES ('H', ?, 1, 1, TIMESTAMP '2024-01-01 00:00:00', ?, NULL, NULL, NULL, NULL)",
                [SYS, r"C:\W\POWERSHELL.EXE"])
    con.execute(f"COPY t TO '{(pq / 'events.parquet').as_posix()}' (FORMAT parquet)")
    db = m.mo_csdl(tmp_path / "parquet", tmp_path / "e.duckdb")
    spec = {"id": "h", "scope": {"channel": SYS, "event_ids": [1]}, "candidates": r"Image = 'C:\w\powershell.exe'"}
    m.chay_hunts(db, [spec])
    assert db.execute("SELECT count(*) FROM khop WHERE hunt = 'h'").fetchone()[0] == 1


def test_nhan_ngoai_kenh_sysmon_bi_tu_choi(m, du_lieu):
    con = duckdb.connect()
    con.execute("CREATE TABLE n (bo VARCHAR, ev_host VARCHAR, ev_channel VARCHAR, ev_rec BIGINT)")
    con.execute("INSERT INTO n VALUES ('ad.T1059.001.a', 'H', 'security', 10)")
    con.execute(f"COPY n TO '{(du_lieu / 'nhan.parquet').as_posix()}' (FORMAT parquet)")
    with pytest.raises(SystemExit):
        _chay(m, du_lieu)
