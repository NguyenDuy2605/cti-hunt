"""Chấm mở rộng hướng 2 trên dữ liệu tổng hợp: chọn rule SigmaHQ theo kỹ thuật cha/con, và chấm trên tập con kỹ thuật với hai
lượt hệ thống trùng mã hunt (giao thức `docs/METHODOLOGY.md` §6, `30_…`)."""
import importlib.util
import json
import sys
import types

import duckdb
import pytest
import yaml

from cti_hunt import config

SYS = "microsoft-windows-sysmon/operational"
COT = "ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, ev_ts TIMESTAMP, Image VARCHAR, TargetObject VARCHAR"

# bộ → (kỹ thuật, [(mã sự kiện, rec, Image, TargetObject)]); rec 1 của mỗi bộ là tấn công.
BO = {
    "ad.T1059.001.a": ("T1059.001", [(1, 1, r"C:\w\powershell.exe", None), (1, 2, r"C:\w\notepad.exe", None)]),
    "ad.T1218.b": ("T1218", [(1, 1, r"C:\w\rundll32.exe", None), (1, 2, r"C:\w\calc.exe", None)]),
    "ad.T1112.c": ("T1112", [(13, 1, None, r"HKLM\soft\evil\x"), (13, 2, None, r"HKLM\soft\good")]),
}

SIGMA = {   # không rule mức cao nào mang đúng tag của bộ: chỉ chọn mở rộng mới thấy
    "ps_cha.yml": ("t1059", "high", "process_creation", "Image|endswith: '\\powershell.exe'"),
    "rundll_con.yml": ("t1218.011", "high", "process_creation", "Image|endswith: '\\rundll32.exe'"),
    "reg_dung_tag.yml": ("t1112", "medium", "registry_set", "TargetObject|contains: '\\evil\\'"),
    "anh_em.yml": ("t1059.003", "high", "process_creation", "Image|endswith: '\\notepad.exe'"),
}


def _rule(ten, tag, level, cat, sel):
    return (f"title: {ten}\nid: {sorted(SIGMA).index(ten):08d}-0000-0000-0000-000000000000\nstatus: test\nlevel: {level}\n"
            f"logsource: {{product: windows, category: {cat}}}\ndetection:\n  selection:\n    {sel}\n"
            f"  condition: selection\ntags: [attack.{tag}]\n")


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("huong2_cham_mo_rong_test", config.ROOT / "scripts/huong2_cham_mo_rong.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "huong2_cham_mo_rong_test", mod)
    spec.loader.exec_module(mod)

    class Cat:
        @classmethod
        def from_stix(cls, path):
            return cls()

        def resolve(self, k):
            return types.SimpleNamespace(final=k)
    monkeypatch.setattr(mod.hc, "AttackCatalog", Cat)
    return mod


@pytest.fixture
def p(tmp_path):
    pq = tmp_path / "parquet"
    con = duckdb.connect()
    tom_tat = {}
    for i, (bo, (kt, evs)) in enumerate(BO.items()):
        (pq / bo).mkdir(parents=True)
        con.execute(f"CREATE OR REPLACE TABLE t ({COT})")
        for eid, rec, img, tgt in evs:
            con.execute("INSERT INTO t VALUES ('H', ?, ?, ?, TIMESTAMP '2024-01-01', ?, ?)", [SYS, eid, rec, img, tgt])
        con.execute(f"COPY t TO '{(pq / bo / 'events.parquet').as_posix()}' (FORMAT parquet)")
        tom_tat[f"tep{i}"] = {"trang_thai": "ok", "ma_bo": bo, "ky_thuat": [kt]}
    (pq / "tom_tat_nap.json").write_text(json.dumps(tom_tat), encoding="utf-8")
    con.execute("CREATE OR REPLACE TABLE n (bo VARCHAR, ev_host VARCHAR, ev_channel VARCHAR, ev_rec BIGINT)")
    for bo in BO:
        con.execute("INSERT INTO n VALUES (?, 'H', ?, 1)", [bo, SYS])
    con.execute(f"COPY n TO '{(tmp_path / 'nhan.parquet').as_posix()}' (FORMAT parquet)")
    (tmp_path / "pham_vi.json").write_text(json.dumps({"bo": [{"bo": b} for b in BO]}), encoding="utf-8")
    sig = tmp_path / "sigmahq" / "rules" / "windows"
    sig.mkdir(parents=True)
    for ten, args in SIGMA.items():
        (sig / ten).write_text(_rule(ten, *args), encoding="utf-8")
    for luot, cand in (("a", "lower(TargetObject) LIKE '%evil%'"), ("b", "lower(TargetObject) LIKE '%khong_co%'")):
        d = tmp_path / luot / "ky_thuat" / "T1112" / "hunts"
        d.mkdir(parents=True)
        spec = {"id": "AD-T1112-H01", "scope": {"channel": SYS, "event_ids": [13]}, "candidates": cand}
        (d / "AD-T1112-H01.yaml").write_text(yaml.safe_dump(spec), encoding="utf-8")
    (tmp_path / "tap.json").write_text(json.dumps({"mau": ["T1112", "T1059.001"]}), encoding="utf-8")
    return tmp_path


def _chung(p, out):
    return ["--parquet", str(p / "parquet"), "--nhan", str(p / "nhan.parquet"), "--pham-vi", str(p / "pham_vi.json"),
            "--sigmahq", str(p / "sigmahq"), "--db", str(p / "chung.duckdb"), "--out", str(p / out)]


def test_khop_tag(m):
    ids = {"t1218.011"}
    assert not m.khop_tag({"t1218"}, ids, "chinh_xac") and m.khop_tag({"t1218"}, ids, "cha")
    assert not m.khop_tag({"t1218.010"}, ids, "cha_con")                 # anh em không được chọn
    assert m.khop_tag({"t1059.001"}, {"t1059"}, "con") and not m.khop_tag({"t1059.001"}, {"t1059"}, "cha")
    assert m.khop_tag({"t1112"}, {"t1112"}, "chinh_xac")


def test_cha_con_chon_them_rule_dung_huong(m, p):
    assert m.main(["cha-con", *_chung(p, "cc")]) == 0
    kq = json.loads((p / "cc" / "ket_qua.json").read_text(encoding="utf-8"))
    bat = {c: v["bat_duoc"] for c, v in kq["cach"].items()}
    assert (bat["sigmahq_cao_chinh_xac"], bat["sigmahq_cao_cha"], bat["sigmahq_cao_con"], bat["sigmahq_cao_cha_con"]) \
        == (0, 1, 1, 2)
    assert (bat["sigmahq_moi_muc_chinh_xac"], bat["sigmahq_moi_muc_cha_con"]) == (1, 3)
    assert kq["ky_thuat_them_so_voi_chinh_xac"]["cao_cha"] == ["T1059.001"]
    assert kq["ky_thuat_them_so_voi_chinh_xac"]["cao_con"] == ["T1218"]
    assert kq["so_rule_duoc_chon"]["cha_con"] == {"cao": 2, "moi_muc": 3}     # rule anh em (t1059.003) không vào
    assert kq["trong_mau"] is True


def test_tap_con_va_hai_luot_trung_ma_hunt(m, p):
    args = ["tap-con", "--tap", str(p / "tap.json"), "--khoa", "mau", "--he-thong", f"a={p / 'a'}",
            "--he-thong", f"b={p / 'b'}", *_chung(p, "tc")]
    assert m.main(args) == 0
    kq = json.loads((p / "tc" / "ket_qua.json").read_text(encoding="utf-8"))
    assert kq["so_ky_thuat_T"] == 2 and kq["tap_con"] == ["T1059.001", "T1112"]
    c = kq["cach"]
    assert (c["he_a"]["bat_duoc"], c["he_b"]["bat_duoc"], c["sigmahq_moi_muc"]["bat_duoc"]) == (1, 0, 1)
    assert kq["so_cap"]["he_a_vs_he_b"]["chi_thu_nhat"] == 1
    assert kq["doi_dau"]["he_a_vs_sigmahq_cao"]["so_ky_thuat"] == 0          # không rule cao đúng tag trong S
    assert kq["hunt_khop_0_o_moi_bo"] == {"a": {"so_hunt": 1, "khop_0": 0}, "b": {"so_hunt": 1, "khop_0": 1}}
    db = duckdb.connect(str(p / "chung.duckdb"))
    assert sorted(h for (h,) in db.execute("SELECT hunt FROM hunt_info WHERE hunt LIKE '%T1112-H01'").fetchall()) \
        == ["a__AD-T1112-H01", "b__AD-T1112-H01"]
