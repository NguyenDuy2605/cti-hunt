"""scripts/tong_hop_chi_so_khau.py: chỉ số theo khâu từ lượt đã lưu, trên cây thư mục tự dựng (không dữ liệu thật)."""
import importlib.util
import json
import os
from datetime import datetime, timedelta

import pytest

from cti_hunt import config

T0 = datetime(2026, 10, 8, 9, 0, 0)


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("tong_hop_chi_so_khau_test",
                                                  config.ROOT / "scripts/tong_hop_chi_so_khau.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _put(path, data, at):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False), encoding="utf-8")
    t = (T0 + timedelta(seconds=at)).timestamp()
    os.utime(path, (t, t))


def _run(root, tuyen="tuyen_B_v3", mode="agent", rid="SY_01"):
    run = root / tuyen / mode / rid
    _put(run / "run_meta.json", {"bat_dau": T0.isoformat(timespec="seconds")}, 2)
    return run


def test_times_tach_cho_duyet_va_bo_cong_khong_muc(mod, tmp_path):
    run = _run(tmp_path)
    r1 = run / "round_01"
    _put(r1 / "request.json", {}, 10)
    _put(r1 / "hypotheses.json", [], 60)
    _put(r1 / "approval_log.json", {"dem": {}}, 180)
    _put(r1 / "filter_review/r01/manifest.json", {}, 200)
    _put(r1 / "filter_review/r01/approval_log.json", {"kind": "reviewed_filters", "quyet_dinh": []}, 260)
    r2 = run / "round_02"
    _put(r2 / "hypotheses.json", [], 270)
    _put(r2 / "approval_log.json", {"dem": {}}, 280)
    _put(r2 / "filter_review/r01/manifest.json", {}, 285)
    _put(r2 / "filter_review/r01/approval_log.json", {"kind": "no_filters", "quyet_dinh": []}, 286)
    _put(run / "hunt_record.md", "x", 300)
    _put(run / "checkpoint.sqlite", "x", 9000)          # không phải tệp làm việc
    t = mod.times(run)
    assert t["toan_trinh_giay"] == 300
    assert t["cho_duyet_giay"] == 120 + 60 + 10          # phiếu lọc no_filters không tính chờ
    assert t["may_giay"] == 300 - 190
    assert t["toi_gia_thuyet_dau_giay"] == 60
    assert (t["so_lan_cho_gia_thuyet"], t["so_lan_cho_loc"]) == (2, 1)
    assert t["ket_thuc_theo"] == "hunt_record.md"
    assert t["khoang_may_lon_nhat_giay"] == 50           # 10 → 60, không có chờ duyệt


def test_times_luot_ngat_tinh_den_tep_lam_viec_cuoi(mod, tmp_path):
    run = _run(tmp_path)
    _put(run / "round_01/hypotheses.json", [], 60)
    _put(run / "round_01/approval_log.json", {"dem": {}}, 100)
    _put(run / "round_01/khau5_requests.jsonl", "", 400)
    _put(run / "su_co.json", {"gia_thuyet_da_duyet_chua_thuc_thi": []}, 10_000)
    _put(run / "hunt_record.md", "x", 10_000)
    t = mod.times(run)
    assert t["toan_trinh_giay"] == 400 and t["ket_thuc_theo"] == "tep_lam_viec_cuoi_truoc_su_co"


def test_khau4_tach_loi_cau_truc_trung_va_lo_sai(mod, tmp_path):
    run = _run(tmp_path)
    _put(run / "round_01/agent_proposal.json", {"khau4": {
        "so_muc_tho": 5, "so_gia_thuyet": 3,
        "ma_sua": {"ma_su_kien_ngoai_danh_muc": 1, "trung_gia_thuyet": 1, "truong_ngoai_danh_muc": 2}}}, 10)
    _put(run / "round_01/approval_log.json", {"dem": {"approved": 2, "rejected": 1, "pending_review": 0},
                                             "quyet_dinh": {
        "H01": {"quyet_dinh": "approved", "ly_do": ""},
        "H02": {"quyet_dinh": "approved", "ly_do": ""},
        "H03": {"quyet_dinh": "rejected", "ly_do": "thieu_thanh_phan, khong_bam_nguon: không có điều kiện"}}}, 20)
    _put(run / "round_02/agent_proposal.json", {"khau4": {"so_pivot": 2, "so_gia_thuyet": 0, "chi_tiet": [
        {"loai": "may", "gia_tri": "A", "so_muc_tho": 0, "so_gia_thuyet": 0,
         "ma_sua": {"dau_ra_sai_luoc_do": 1, "ttp_ref_la": 0}},
        {"loai": "may", "gia_tri": "B", "ly_do_bo": "mô hình từ chối"}]}}, 30)
    _put(run / "round_03/request.json", {}, 40)        # vòng đứt trước khi có đề xuất
    k = mod.khau4(run)
    assert (k["so_lo"], k["so_lo_sai_luoc_do"], k["so_lo_bo_truoc_dau_ra"]) == (2, 1, 1)
    assert (k["so_muc_tho"], k["so_muc_du_thanh_phan"], k["so_gia_thuyet_giu"]) == (5, 4, 3)
    assert k["sua_tren_muc_giu"] == {"truong_ngoai_danh_muc": 2}
    assert k["so_vong_khong_co_de_xuat"] == 1
    assert k["duyet"] == {"approved": 2, "rejected": 1, "pending_review": 0}
    assert k["tu_choi_theo_ma"] == {"thieu_thanh_phan": 1, "khong_bam_nguon": 1}


def test_khau5_phan_loai_va_luot_ngat(mod, tmp_path):
    run = _run(tmp_path)
    rules = [
        {"hypothesis_id": "H01", "hop_le": True, "so_lan_sua": 0, "loi": []},
        {"hypothesis_id": "H02", "hop_le": True, "so_lan_sua": 2, "loi": []},
        {"hypothesis_id": "H03", "hop_le": False, "so_lan_sua": 0, "loi": [{"kind": "khong_co_logsource"}]},
        {"hypothesis_id": "H04", "hop_le": False, "so_lan_sua": 0, "loi": [{"kind": "mo_hinh_tu_choi"}]},
        {"hypothesis_id": "H05", "hop_le": False, "so_lan_sua": 0,
         "loi": [{"kind": "nguon_khong_co_su_kien"}, {"kind": "truong_khong_co"}]},
        {"hypothesis_id": "H06", "hop_le": False, "so_lan_sua": 2, "loi": [{"kind": "sql_loi"}]},
    ]
    _put(run / "round_01/agent_execute.json", {"rules": rules, "observations": []}, 10)
    _put(run / "round_02/khau5_requests.jsonl",
         "\n".join(json.dumps({"hypothesis_id": "H07", "lan": n}) for n in (0, 1)) + "\n", 20)
    _put(run / "su_co.json", {"gia_thuyet_da_duyet_chua_thuc_thi": [
        {"vong": "round_02", "hypothesis_id": "H07", "co_rule_hop_le": True},
        {"vong": "round_02", "hypothesis_id": "H08", "co_rule_hop_le": False},
        {"vong": "round_01", "hypothesis_id": "H09"}]}, 30)     # vòng đã có nhật ký ⑤: không đếm lại
    k = mod.khau5(run)
    assert k["tong"] == 8
    assert (k["hop_le_lan_dau"], k["hop_le_sau_sua"]) == (1, 2)
    assert (k["khong_goi_mo_hinh"], k["mo_hinh_tu_choi"], k["dung_sua_nguon_rong"], k["loi_tinh_con_lai"]) == (1, 1, 1, 1)
    assert (k["luot_ngat"], k["luot_ngat_chua_co_rule"]) == (2, 1)
    assert (k["so_rule_co_sua"], k["so_lan_sua"]) == (3, 5)


def test_khau5_doc_manifest_khi_chua_thuc_thi(mod, tmp_path):
    run = _run(tmp_path)
    _put(run / "round_01/filter_review/r01/manifest.json", {"context": {"rule_log": [
        {"hypothesis_id": "H01", "hop_le": True, "so_lan_sua": 1, "lan_thu": [{"loi": [{"kind": "x"}]}, {"loi": []}]}]}},
         10)
    k = mod.khau5(run)
    assert (k["tong"], k["hop_le_sau_sua"], k["nguon"]) == (1, 1, {"manifest.json": 1})


def test_loc_co_cong_va_khong_cong(mod, tmp_path):
    gate = _run(tmp_path)
    rv = gate / "round_01/filter_review"
    _put(rv / "r01/preview.json", [
        {"hunt_id": "A", "candidates": 10, "filters": [{"id": "S-01", "matched": 10}, {"id": "S-02", "matched": 0}]},
        {"hunt_id": "B", "candidates": 0, "filters": [{"id": "S-01", "matched": 0}]}], 10)
    _put(rv / "r01/approval_log.json", {"kind": "reviewed_filters", "quyet_dinh": [
        {"id": "A__S-01", "quyet_dinh": "pending_review", "ly_do": ""},
        {"id": "A__S-02", "quyet_dinh": "rejected", "ly_do": "pham_vi_qua_rong, thieu_can_cu_lanh_tinh: x"},
        {"id": "B__S-01", "quyet_dinh": "rejected", "ly_do": "lý do tự do"}]}, 20)
    _put(rv / "r02/preview.json", [{"hunt_id": "A", "candidates": 10, "filters": [{"id": "S-01", "matched": 10}]}], 30)
    _put(rv / "r02/approval_log.json", {"kind": "reviewed_filters", "quyet_dinh": [
        {"id": "A__S-01", "quyet_dinh": "approved", "ly_do": ""}]}, 40)
    g = mod.loc(gate)
    assert g["co_cong_duyet"] and g["so_muc"] == 3
    assert g["theo_quyet_dinh"] == {"approved": 1, "rejected": 2}         # bản r02 thay quyết định r01
    assert g["theo_nhom_ty_le"]["100%"] == 1 and g["ap_dung_theo_nhom"]["100%"] == 1
    assert g["theo_nhom_ty_le"]["0"] == 1 and g["theo_nhom_ty_le"]["khong_co_ung_vien"] == 1
    assert g["tu_choi_theo_ma"] == {"pham_vi_qua_rong": 1, "thieu_can_cu_lanh_tinh": 1}
    assert g["tu_choi_khong_ma"] == 1

    old = _run(tmp_path, "tuyen_A", "pipeline", "MS_01")
    _put(old / "round_01/agent_execute.json", {"rules": [], "observations": [
        {"hunt_id": "H", "stages": [{"stage": "pham_vi", "hits": 50}, {"stage": "ung_vien", "hits": 20},
                                    {"stage": "sau_S-01", "hits": 15}, {"stage": "sau_S-02", "hits": 0}]}]}, 10)
    o = mod.loc(old)
    assert not o["co_cong_duyet"]
    assert {m["id"]: (m["loai"], m["nhom"]) for m in o["muc"]} == {"H__S-01": (5, "<50%"), "H__S-02": (15, "50–<90%")}
    assert o["theo_quyet_dinh"] == {"ap_tu_dong": 2}


def test_nhom_ty_le(mod):
    assert [mod.nhom_ty_le(x, 10) for x in (0, 4, 5, 9, 10)] == ["0", "<50%", "50–<90%", "90–<100%", "100%"]
    assert mod.nhom_ty_le(0, 0) == "khong_co_ung_vien"


def test_main_phan_loai_phu_luc_va_ghi_tep(mod, tmp_path):
    root = tmp_path / "eval"
    for tuyen, mode, rid in (("tuyen_B_v3", "agent", "SY_03"), ("tuyen_B_v3", "agent", "SY_04"),
                             ("tuyen_A", "pipeline", "PS_01")):
        run = _run(root, tuyen, mode, rid)
        _put(run / "round_01/hypotheses.json", [], 30)
        _put(run / "hunt_record.md", "x", 90)
    out = tmp_path / "out"
    assert mod.main(["--root", str(root), "--out", str(out)]) == 0
    data = json.loads((out / "chi_so_khau.json").read_text(encoding="utf-8"))
    tinh = {(r["tuyen"], r["id"]): r["tinh"] for r in data["luot"]}
    assert tinh == {("tuyen_A", "PS_01"): True, ("tuyen_B_v3", "SY_03"): False, ("tuyen_B_v3", "SY_04"): True}
    assert data["nhom"]["tuyen_B_v3/agent"]["luot"] == ["SY_04"]                # nhóm chỉ gồm lượt được tính
    assert "phụ lục" in (out / "chi_so_khau.md").read_text(encoding="utf-8")
    assert mod.main(["--root", str(root), "--out", str(tmp_path / "labels" / "x")]) == 2


def test_script_khong_tham_chieu_nhan(mod):
    src = (config.ROOT / "scripts/tong_hop_chi_so_khau.py").read_text(encoding="utf-8")
    for bad in ("nhan_v1", "attack_labels", "labeled", "su_kien_tan_cong", "runs/"):
        assert bad not in src
