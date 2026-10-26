"""F-02 của H-03 (nhánh A): hợp lệ theo v3 §4.3 và khớp đúng mẫu đã chốt, không rộng hơn."""
import duckdb

from cti_hunt.config import ROOT
from cti_hunt.hunt import runner

SPEC = runner.load_spec(ROOT / "hunts" / "manual" / "H-03.yaml")
F02 = {f["id"]: f for f in SPEC["filters"] if f["id"].startswith("F-02")}
TI = r"C:\Windows\servicing\TrustedInstaller.exe"
SPP = r"C:\Windows\System32\sppsvc.exe"
SVC = r"C:\Windows\System32\services.exe"


def _con(rows):
    con = duckdb.connect()
    con.execute('CREATE TABLE t (k INT, "ParentImage" VARCHAR, "Image" VARCHAR, "CommandLine" VARCHAR, "User" VARCHAR)')
    con.executemany("INSERT INTO t VALUES (?,?,?,?,?)", rows)
    return con


def _hit(con, fid):
    return sorted(r[0] for r in con.execute(f"SELECT k FROM t WHERE ({F02[fid]['where']})").fetchall())


def test_f02_has_two_patterns_with_required_fields_and_no_parent():
    assert sorted(F02) == ["F-02a", "F-02b"]
    for f in F02.values():
        assert f["nguoi_chiu_trach_nhiem"] == "Duy" and f["het_han"] == "het_de_tai"
        assert "parentimage" not in f["where"].lower()          # v3 §4.3: mẫu theo tiến trình con


def test_f02_matches_exact_child_cmd_and_account_only():
    con = _con([
        (1, SVC, TI, r"C:\windows\servicing\TrustedInstaller.exe", r"NT AUTHORITY\SYSTEM"),
        (2, SVC, SPP, r"C:\windows\system32\sppsvc.exe", r"NT AUTHORITY\NETWORK SERVICE"),
        (3, SVC, SPP, r"C:\windows\system32\sppsvc.exe ", r"NT AUTHORITY\NETWORK SERVICE"),   # khoảng trắng cuối
        (10, SVC, r"C:\Users\Public\TrustedInstaller.exe", r"C:\Users\Public\TrustedInstaller.exe", r"NT AUTHORITY\SYSTEM"),
        (11, SVC, TI, r"C:\windows\servicing\TrustedInstaller.exe -x", r"NT AUTHORITY\SYSTEM"),
        (12, SVC, SPP, r"C:\windows\system32\sppsvc.exe", r"DMEVALS\someone"),
        (13, SVC, r"C:\Windows\System32\m.exe", r"C:\Windows\System32\m.exe", r"NT AUTHORITY\SYSTEM"),
    ])
    assert _hit(con, "F-02a") == [1]
    assert _hit(con, "F-02b") == [2, 3]
