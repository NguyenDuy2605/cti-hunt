"""So sánh lượt sinh rule hướng 2 (giao thức `docs/METHODOLOGY.md` §4) trên hai lượt tổng hợp, không nhãn."""
import importlib.util
import json
import sys

import pytest
import yaml

from cti_hunt import config


@pytest.fixture
def m(monkeypatch):
    spec = importlib.util.spec_from_file_location("so_sanh_sinh_rule_test", config.ROOT / "scripts/so_sanh_sinh_rule.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "so_sanh_sinh_rule_test", mod)
    spec.loader.exec_module(mod)
    return mod


def _kt(root, goc, luc, khau4, hyps, khau5, hunts=()):
    d = root / "ky_thuat" / goc
    d.mkdir(parents=True)
    trang_thai = "xong" if khau4 is not None else "khong_san_duoc: danh mục ③ không có nguồn"
    (d / "ket_qua.json").write_text(json.dumps({"goc": goc, "trang_thai": trang_thai, "khau4": khau4,
                                                "gia_thuyet": [{"hypothesis_id": h} for h in hyps], "khau5": khau5}),
                                    encoding="utf-8")
    (d / "xong.json").write_text(json.dumps({"luc": luc}), encoding="utf-8")
    if hunts:
        (d / "hunts").mkdir()
        for h in hunts:
            (d / "hunts" / f"{h}.yaml").write_text(yaml.safe_dump({"id": h}), encoding="utf-8")


def _cham(root, khop):
    root.mkdir(parents=True)
    with open(root / "theo_hunt.csv", "w", encoding="utf-8") as f:
        f.write("hunt,cach,khop\n" + "".join(f"{h},he_thong;he_thong_bo_rong,{n}\n" for h, n in khop.items()))


def test_tong_hop_va_so_cap(m, tmp_path):
    a = tmp_path / "a"
    k4 = {"so_muc_tho": 2, "ma_sua": {"khong_neo_ttp": 1, "rang_buoc_thieu_may": 1}, "token": {"input_tokens": 10, "output_tokens": 2}}
    _kt(a, "T1", "2026-10-17 10:00:00", k4, ["H1"],
        [{"hypothesis_id": "H1", "hop_le": True, "hop_le_lan_dau": False, "token": {"input_tokens": 5, "output_tokens": 1}}],
        ["H1__x__sysmon_1"])
    _kt(a, "T2", "2026-10-17 10:01:00", {"so_muc_tho": 1, "ma_sua": {}}, ["H2"],
        [{"hypothesis_id": "H2", "hop_le": False, "dau_ra_hong": "hết num_predict trước khi xong JSON"}])
    _kt(a, "T3", "2026-10-17 11:00:00", None, [], [])                                 # sau quãng nghỉ 59 phút
    _cham(tmp_path / "cham_a", {"H1__x__sysmon_1": 0})
    b = tmp_path / "b"
    _kt(b, "T1", "2026-10-17 12:00:00", {"so_muc_tho": 1, "ma_sua": {}}, ["G1"],
        [{"hypothesis_id": "G1", "hop_le": True, "hop_le_lan_dau": True}], ["G1__y__sysmon_1"])
    _kt(b, "T2", "2026-10-17 12:02:00", {"so_muc_tho": 1, "ma_sua": {}}, ["G2"],
        [{"hypothesis_id": "G2", "hop_le": False, "loi_cuoi": [{"kind": "yaml_loi", "message": "x"}]}])
    _kt(b, "T3", "2026-10-17 12:03:00", None, [], [])
    _cham(tmp_path / "cham_b", {"G1__y__sysmon_1": 7})
    out = tmp_path / "kq.json"
    assert m.main(["--luot", f"a={a},{tmp_path / 'cham_a'}", "--luot", f"b={b},{tmp_path / 'cham_b'}", "--out", str(out)]) == 0
    kq = json.loads(out.read_text(encoding="utf-8"))
    la, lb = kq["luot"]["a"], kq["luot"]["b"]
    assert (la["khau4_goi"], la["gia_thuyet"], la["muc_tho"], la["khau4_muc_bi_loai"]) == (2, 2, 3, 1)
    assert la["khau4_ma_loi"] == {"khong_neo_ttp": 1, "rang_buoc_thieu_may": 1}     # 2 mã lỗi, 1 mục bị loại
    assert (la["rule_hop_le"], la["rule_hop_le_sau_sua"], la["rule_hop_le_khop_0"]) == (1, 1, 1)
    assert la["khau5_khong_hop_le_theo_loai"] == {"het_num_predict": 1}
    assert lb["khau5_khong_hop_le_theo_loai"] == {"yaml_loi": 1} and lb.get("rule_hop_le_khop_0", 0) == 0
    assert (la["phut_giua_xong_dau_va_xong_cuoi"], la["phut_nghi_dai_nhat"], la["phut_chay_uoc_tinh"]) == (60.0, 59.0, 1.0)
    assert (la["ky_thuat_co_rule_khop_duoc"], lb["ky_thuat_co_rule_khop_duoc"]) == (0, 1)
    sc = kq["so_cap"]["a_vs_b__rule_khop_duoc"]
    assert (sc["so_ky_thuat"], sc["chi_thu_nhat"], sc["chi_thu_hai"], sc["ca_hai"]) == (2, 0, 1, 0)   # T3 không chạy
    assert kq["so_cap"]["a_vs_b__rule_hop_le"]["ca_hai"] == 1
