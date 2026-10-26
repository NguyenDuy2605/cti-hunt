"""Bộ chấm trích TTP của mô hình mở (giao thức `docs/METHODOLOGY.md`): kiểm cách tính trên dữ liệu tổng hợp, không cần dữ liệu thật."""
import importlib.util
import sys
from types import SimpleNamespace

import pytest

from cti_hunt import config


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("do_ttp_mo_hinh_mo_test", config.ROOT / "scripts/do_ttp_mo_hinh_mo.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "do_ttp_mo_hinh_mo_test", mod)
    spec.loader.exec_module(mod)
    return mod


class _Cat:
    """Như AttackCatalog.resolve: T9999 thu hồi sang T1059; T8888 ngừng dùng (không có mã thay thế)."""
    ok = {"T1059", "T1059.001", "T1003", "T1003.001", "T1105"}

    def resolve(self, tid):
        final = {"T9999": "T1059"}.get(tid, tid)
        if final not in self.ok:
            return SimpleNamespace(final=None, status="deprecated")
        return SimpleNamespace(final=final, status="ok")


def test_precision_theo_report_bo_report_khong_neu_ma(m):
    gold = {"R1": {"A", "B"}, "R2": {"A"}, "R3": {"A", "B"}, "R4": {"A"}}
    preds = {"x": {"R1": {"A", "B"}, "R2": {"A", "C"}, "R3": set(), "R4": {"A"}},
             "y": {"R1": {"A", "C", "D"}, "R2": {"A"}, "R3": {"A"}, "R4": {"A"}}}
    r = m.so_precision(gold, preds, "x", "y", ["R1", "R2", "R3", "R4"])
    # R1: 1 > 1/3 hơn; R2: 1/2 < 1 kém; R3 bỏ (x không nêu mã); R4: bằng.
    assert (r["report_a_hon"], r["report_a_kem"], r["report_bang"], r["report_bo_qua"]) == (1, 1, 1, ["R3"])
    assert r["dau_p"] == pytest.approx(1.0)


def test_phep_so_recall_theo_report_va_tren_muc(m):
    gold = {"R1": {"A", "B", "C"}, "R2": {"A", "B"}}
    preds = {"mo_hinh_mo": {"R1": {"A", "B"}, "R2": {"A"}}, "bm25_top1": {"R1": {"A"}, "R2": {"A", "B"}}}
    r = m.phep_so(gold, preds, ["bm25_top1"], ["R1", "R2"])["bm25_top1"]["recall"]
    assert (r["report_a_hon"], r["report_a_kem"], r["report_bang"]) == (1, 1, 0)
    assert (r["muc_chi_a_dung"], r["muc_chi_b_dung"]) == (1, 1)


def test_tong_hop_mau_so_chi_tinh_report_dang_xet(m):
    rows = [{"report": "R1", "ky_thuat": "A", "x": 1}, {"report": "R2", "ky_thuat": "A", "x": 0}]
    s = m.tong_hop(rows, {"x": {"R1": {"A", "Z"}, "R2": {"Q"}}}, ["x"], ["R1"])
    assert s["recall"]["x"]["tren"] == 1 and s["recall"]["x"]["dung"] == 1
    assert s["precision_can_duoi"]["x"]["tren"] == 2


def test_dau_ra_tho_va_ly_do_cong_lam_mat(m):
    audit = [
        {"status": "accepted", "technique_id": "T1059.001", "final_technique_id": "T1059.001"},
        {"status": "rejected", "technique_id": "T1003.001", "reason": "Câu trích không nguyên văn"},
        {"status": "rejected", "technique_id": "T1003", "reason": "Tactic sai"},
        {"status": "rejected", "technique_id": "T9999", "reason": "Thiếu lý do"},  # thu hồi → T1059, đã có
        {"status": "rejected", "technique_id": "T8888", "reason": "Ngừng dùng"},  # không tính
        {"status": "rejected", "reason": "Sai lược đồ"},  # không có mã, không tính
    ]
    tho, ly_do = m.ma_tho(audit, _Cat())
    assert tho == {"T1059.001", "T1003.001", "T1003", "T1059"}
    res = m.phan_tich_tho({"R1": {"T1003.001", "T1105"}}, {"R1": {"T1059.001"}}, {"R1": audit}, _Cat())
    assert res["ma"]["muc_dap_an_cong_lam_mat"] == 1
    assert res["ma"]["chi_tiet_mat"][0]["ly_do"] == ["Câu trích không nguyên văn"]
    # Mức cha: T1003 mất, mang lý do của cả hai mục bị loại cùng cha.
    assert res["cha"]["chi_tiet_mat"] == [{"report": "R1", "ky_thuat": "T1003",
                                           "ly_do": ["Câu trích không nguyên văn", "Tactic sai"]}]
    assert res["cha"]["recall"]["tho"]["dung"] == 1 and res["cha"]["recall"]["sau_cong"]["dung"] == 0


def test_dau_ra_tho_dung_khi_sau_cong_khong_nam_trong_tho(m):
    audit = [{"status": "accepted", "technique_id": "T1059", "final_technique_id": "T1059"}]
    with pytest.raises(SystemExit):
        m.phan_tich_tho({"R1": {"T1059"}}, {"R1": {"T1105"}}, {"R1": audit}, _Cat())


@pytest.mark.parametrize("desc, sau", [
    ("Ai. (2024, March 7). Bài.", False), ("Ai. (2024, November 4). Bài.", True), ("Ai. (2021, January). Bài.", False),
    ("Ai. (2022). Bài.", False), ("Ai. (2025). Bài.", True), ("Ai. (2024, September 19). Bài.", False),
    ("Ai. (2024, September 20). Bài.", True), ("Ai. (2024). Bài.", None), ("Ai. (2024, September). Bài.", None),
    ("Không có ngày", None)])
def test_ngay_dang_so_voi_moc_phat_hanh(m, desc, sau):
    assert m.ngay_dang(desc)[1] is sau


def test_nhom_nam_khac_giao_thuc_thi_dung(m, monkeypatch):
    monkeypatch.setattr(m, "NHOM_SAU", ("RM-X",))
    entries = [{"ma": "RM-X", "source_name": "a"}, {"ma": "RM-Y", "source_name": "b"}]
    ung = [{"source_name": "a", "description": "(2025, May 1)"}, {"source_name": "b", "description": "(2025, May 2)"}]
    with pytest.raises(SystemExit):
        m.kiem_nhom_nam(entries, ung)
    ung[1]["description"] = "(2023, May 2)"
    assert m.kiem_nhom_nam(entries, ung)["RM-X"][1] is True
