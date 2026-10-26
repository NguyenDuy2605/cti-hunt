"""Câu hỏi 3, rule không bao giờ khớp (`docs/METHODOLOGY.md` §1): đếm trên ba nhóm log tổng hợp, không nhãn."""
import importlib.util
import json
import sys
import types

import duckdb
import pytest
import yaml

from cti_hunt import config

SYS = "microsoft-windows-sysmon/operational"


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("do_rule_khong_khop_test", config.ROOT / "scripts/do_rule_khong_khop.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "do_rule_khong_khop_test", mod)
    spec.loader.exec_module(mod)
    return mod


def _parquet(path, rows):
    path.mkdir(parents=True)
    con = duckdb.connect()
    con.execute("CREATE TABLE t (ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, Image VARCHAR)")
    for r in rows:
        con.execute("INSERT INTO t VALUES ('H', ?, ?, ?, ?)", list(r))
    con.execute(f"COPY t TO '{(path / 'events.parquet').as_posix()}' (FORMAT parquet)")


def test_dem_khong_bao_gio_khop_tren_ba_nhom(m, tmp_path, monkeypatch):
    _parquet(tmp_path / "work", [(SYS, 1, 1, r"C:\X\CMD.EXE")])
    _parquet(tmp_path / "dev" / "x", [(SYS, 3, 1, None)])
    db = tmp_path / "attack.duckdb"
    con = duckdb.connect(str(db))
    con.execute("CREATE TABLE events AS SELECT 'H' AS ev_host, ? AS ev_channel, 1 AS ev_eid, 1 AS ev_rec, "
                "'c:\\y\\notepad.exe' AS Image", [SYS])
    con.close()
    paths = {"data/work": tmp_path / "work", "data/dev/x": tmp_path / "dev" / "x"}
    monkeypatch.setattr(m, "config", types.SimpleNamespace(resolve=lambda p: paths[p]))
    sc = {"channel": SYS, "event_ids": [1]}
    monkeypatch.setattr(m.base, "DATASETS", {"x": set()})
    monkeypatch.setattr(m.base, "load_rules", lambda: [
        {"id": "a1", "scope": sc, "candidates": r"Image = 'c:\x\cmd.exe'"},       # khớp APT29 nhờ so không phân biệt hoa thường
        {"id": "a2", "scope": sc, "candidates": "Image = 'khong_co'"},           # không bao giờ khớp
        {"id": "a3", "scope": sc, "candidates": "CotKhongCo = 'a'"},           # lỗi ở mọi bộ: không chạy được
        {"id": "trung", "scope": sc, "candidates": r"Image = 'c:\x\cmd.exe'"},  # hai hunt khác lượt trùng mã: không gộp
        {"id": "trung", "scope": sc, "candidates": "Image = 'khong_co_nua'"}])
    sinh = tmp_path / "sinh" / "ky_thuat" / "T1" / "hunts"
    sinh.mkdir(parents=True)
    (sinh / "b1.yaml").write_text(yaml.safe_dump({"id": "b1", "scope": sc, "candidates": "Image ILIKE '%notepad.exe'"}),
                                  encoding="utf-8")
    assert m.main(["--tap", f"b={tmp_path / 'sinh'}", "--attack-db", str(db), "--out", str(tmp_path / "out")]) == 0
    kq = json.loads((tmp_path / "out" / "ket_qua.json").read_text(encoding="utf-8"))["tap"]
    a, b = kq["A_claude_v3"], kq["b"]
    assert (a["so_hunt"], a["chay_duoc"], a["khong_chay_duoc"], a["khong_bao_gio_khop"]) == (5, 4, 1, 2)
    assert a["hunt_khong_bao_gio_khop"] == ["a2", "trung"] and (a["khop_0_tren_nhom_goc"], a["chay_duoc_tren_nhom_goc"]) == (2, 4)
    assert (b["khong_bao_gio_khop"], b["nhom_goc"], b["khop_0_tren_nhom_goc"]) == (0, "attack_data", 0)
