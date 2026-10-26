"""Sinh rule hướng 2 bằng Claude (giao thức `docs/METHODOLOGY.md`): chọn mẫu, kiểm yêu cầu ④ trùng gói, trần gói, cách
xử lý từ chối/đầu ra hỏng/hết trần/lỗi mạng và chạy lại. Client giả, không gọi API, không cần dữ liệu log."""
import importlib.util
import json
import sys
import types
from decimal import Decimal

import pytest

from cti_hunt import config
from cti_hunt.llm import budget, providers


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("huong2_sinh_rule_claude_test",
                                                  config.ROOT / "scripts/huong2_sinh_rule_claude.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "huong2_sinh_rule_claude_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_chon_mau_co_dinh_theo_hat_giong_va_chi_lay_trong_khung(m):
    khung = [f"T{1000 + i}" for i in range(55)]
    a = m.chon_mau(list(reversed(khung)))
    assert a == m.chon_mau(khung)                        # không phụ thuộc thứ tự đưa vào
    assert len(a) == 25 and len(set(a)) == 25 and set(a) <= set(khung)
    assert m.chon_mau(khung, hat_giong=1) != a
    assert m.chon_mau(khung[:10]) == m.chon_mau(khung[:10], so=10)   # khung nhỏ hơn mẫu: lấy hết


class Inner:
    model_id = "claude-sonnet-5"

    def __init__(self):
        self.goi = []

    def build_payload(self, system, user, schema):
        return {"model": self.model_id, "system": system, "messages": [{"role": "user", "content": user}]}

    def complete_json(self, system, user, schema, log=None):
        self.goi.append(user)
        if log is not None:
            log({"input_tokens": 1000, "output_tokens": 100})
        return {"ok": True}


def test_client_goi_chan_truoc_khi_gui(m):
    inner = Inner()
    chi = {"v": Decimal("0")}
    c = m.ClientGoi(inner, lambda: chi["v"], Decimal("1.00"))
    dung = m.sha_payload(inner.build_payload("s", "u", {}))
    c.mong_doi = "0" * 64
    with pytest.raises(m.SaiYeuCau):
        c.complete_json("s", "u", {})
    assert inner.goi == [] and c.mong_doi is None
    c.mong_doi = dung
    assert c.complete_json("s", "u", {}) == {"ok": True}
    assert c.complete_json("s", "u2", {}) == {"ok": True}      # lời gọi ⑤ sau ④: không kiểm gói
    chi["v"] = Decimal("0.61")                                   # 0,61 + 0,40 > 1,00
    with pytest.raises(budget.BudgetExhausted):
        c.complete_json("s", "u3", {})
    assert inner.goi == ["u", "u2"] and c.so_loi_goi == 2
    assert len(c.su_kien) == 2 and m.chi_phi_usd(c.su_kien) == pytest.approx(2 * (1000 * 2 + 100 * 10) / 1e6)


class H:
    def __init__(self, hid):
        self.hypothesis_id = hid

    def model_dump_json(self):
        return json.dumps({"hypothesis_id": self.hypothesis_id})


def _bc(m, tmp_path, kich_ban, chi=None):
    """Bối cảnh chạy với ④/⑤ giả theo ``kich_ban`` {goc: hành vi ④}; ⑤ trả rule hợp lệ có một hunt."""
    chi = chi or {"v": Decimal("0")}
    goi_4, goi_5 = [], []

    def tao_gia_thuyet(it, tdir):
        goi_4.append(it["goc"])
        hv = kich_ban[it["goc"]]
        if isinstance(hv, Exception):
            raise hv
        chi["v"] += Decimal("0.15")
        return [H(f"{it['goc']}-H{i}") for i in range(hv)], {"api_events": [{"input_tokens": 1000, "output_tokens": 100}]}

    def tao_rule(h, tdir):
        goi_5.append(h.hypothesis_id)
        if h.hypothesis_id.endswith("NGAT"):
            raise providers.TransportError("mất mạng")
        return {"hypothesis_id": h.hypothesis_id, "hop_le": True, "hop_le_lan_dau": True, "so_lan_sua": 0,
                "rule_yaml": "title: x\n", "hunt_specs": [{"id": f"{h.hypothesis_id}-hunt"}],
                "lan_thu": [{"loi": [], "api_events": [{"input_tokens": 3000, "output_tokens": 800}]}], "token": {}}

    client = types.SimpleNamespace(mong_doi=None, su_kien=[])
    bc = m.BoiCanh(out=tmp_path, client=client, tran=Decimal("1.00"), da_chi=lambda: chi["v"],
                   tao_gia_thuyet=tao_gia_thuyet, tao_rule=tao_rule, yeu_cau={g: "x" for g in kich_ban}, ghi=lambda x: None)
    return bc, goi_4, goi_5, chi


def _mau(*goc):
    return [{"goc": g, "thu_tu": i, "hien_hanh": g} for i, g in enumerate(goc)]


def test_tu_choi_va_dau_ra_hong_tinh_la_xong_khong_goi_lai(m, tmp_path):
    kich_ban = {"T1": 2, "T2": providers.RefusalError("từ chối"), "T3": providers.BadOutputError("hỏng"), "T4": 0}
    bc, goi_4, goi_5, _ = _bc(m, tmp_path, kich_ban)
    kq = m.chay_vong(_mau("T1", "T2", "T3", "T4"), bc)
    assert kq["ly_do_dung"] == "het_mau" and kq["ky_thuat_xong"] == ["T1", "T2", "T3", "T4"]
    assert goi_4 == ["T1", "T2", "T3", "T4"] and goi_5 == ["T1-H0", "T1-H1"]
    t2 = json.loads((tmp_path / "ky_thuat" / "T2" / "ket_qua.json").read_text(encoding="utf-8"))
    assert "tu_choi" in t2["khau4"] and t2["gia_thuyet"] == []
    assert sorted(p.name for p in (tmp_path / "ky_thuat" / "T1" / "hunts").iterdir()) == ["T1-H0-hunt.yaml", "T1-H1-hunt.yaml"]
    # Chạy lại: kỹ thuật đã xong không gọi lại.
    kq2 = m.chay_vong(_mau("T1", "T2", "T3", "T4"), bc)
    assert goi_4 == ["T1", "T2", "T3", "T4"] and kq2["ky_thuat_xong"] == kq["ky_thuat_xong"]


def test_tran_goi_dung_truoc_ky_thuat_moi(m, tmp_path):
    bc, goi_4, _, chi = _bc(m, tmp_path, {"T1": 1, "T2": 1, "T3": 1})
    chi["v"] = Decimal("0.20")       # sau T1: 0,35; còn 0,65 < 0,70 nên không bắt đầu T2
    kq = m.chay_vong(_mau("T1", "T2", "T3"), bc)
    assert (kq["ly_do_dung"], kq["ky_thuat_xong"], goi_4) == ("tran_goi", ["T1"], ["T1"])


def test_het_ngan_sach_giua_ky_thuat_khong_tinh_la_xong(m, tmp_path):
    bc, goi_4, _, _ = _bc(m, tmp_path, {"T1": 1, "T2": budget.BudgetExhausted("hết sổ"), "T3": 1})
    kq = m.chay_vong(_mau("T1", "T2", "T3"), bc)
    assert (kq["ly_do_dung"], kq["ky_thuat_xong"], goi_4) == ("tran_goi", ["T1"], ["T1", "T2"])
    assert not (tmp_path / "ky_thuat" / "T2" / "xong.json").exists()
    # Lần sau (người vận hành nâng trần): T2 dở dang được cất sang _bi_ngat/ rồi chạy lại từ đầu.
    bc2, goi_4b, _, _ = _bc(m, tmp_path, {"T1": 1, "T2": 1, "T3": 1})
    kq2 = m.chay_vong(_mau("T1", "T2", "T3"), bc2)
    assert goi_4b == ["T2", "T3"] and kq2["ky_thuat_xong"] == ["T1", "T2", "T3"]
    assert len(kq2["bi_ngat_lan_nay"]) == 1 and "T2__" in kq2["bi_ngat_lan_nay"][0]
    assert (tmp_path / "_bi_ngat").exists()


def test_loi_mang_de_ky_thuat_do_dang_va_lan_sau_chay_lai(m, tmp_path):
    bc, goi_4, goi_5, _ = _bc(m, tmp_path, {"T1": 1, "T2": 1})
    bc.tao_gia_thuyet, goc = (lambda it, tdir: ([H(f"{it['goc']}-NGAT")], {})), bc.tao_gia_thuyet
    with pytest.raises(providers.TransportError):
        m.chay_vong(_mau("T1", "T2"), bc)
    assert (tmp_path / "ky_thuat" / "T1" / "bat_dau.json").exists()
    assert not (tmp_path / "ky_thuat" / "T1" / "xong.json").exists()
    bc.tao_gia_thuyet = goc
    kq = m.chay_vong(_mau("T1", "T2"), bc)
    assert kq["ky_thuat_xong"] == ["T1", "T2"] and len(kq["bi_ngat_lan_nay"]) == 1


def test_kiem_goi_chi_so_bam_khong_so_duong_dan(m, monkeypatch):
    goi = {"bam": {"dau_vao": ["a/b.json", "x1"], "script": "s1", "cau_hinh": {"c": "h"}}}
    monkeypatch.setattr(m, "dau_vao_bam", lambda a, h: {"dau_vao": [r"D:\r\a\b.json", "x1"], "script": "s1",
                                                         "cau_hinh": {"c": "h"}})
    assert m.kiem_goi(goi, None, None) == []
    monkeypatch.setattr(m, "dau_vao_bam", lambda a, h: {"dau_vao": ["a/b.json", "x2"], "script": "s1",
                                                         "cau_hinh": {"c": "h2"}})
    assert m.kiem_goi(goi, None, None) == ["dau_vao", "cau_hinh"]


def test_du_toan_tu_lich_su(m):
    ls = {"khau4": [{"ky_tu": 30000, "vao": 12000, "ra": 9000, "so_ttp": 10, "so_gt": 3},
                    {"ky_tu": 20000, "vao": 8000, "ra": 2000, "so_ttp": 2, "so_gt": 1}],
          "khau5": [[(3000, 1000)], [(3000, 1000)]]}
    dt = m.du_toan({"T1": {"ky_tu": 30000, "so_ttp": 10}}, ls, lan=50)
    assert dt["nhom_cua_ky_thuat"] == {"T1": "8-10"}
    # Nhóm 8-10 chỉ có một lời gọi ④: 30.000 ký tự × 0,4 = 12.000 vào × 2 + 9.000 ra × 10 = 0,114 USD;
    # ⑤: 3 giả thuyết × 0,016 = 0,048 USD. Lịch sử một phần tử nên mọi lần mô phỏng như nhau.
    assert dt["tong_usd"]["trung_vi"] == dt["tong_usd"]["p90"] == pytest.approx(0.162, abs=1e-3)
    dt2 = m.du_toan({"T1": {"ky_tu": 30000, "so_ttp": 10}, "T2": {"ky_tu": 20000, "so_ttp": 2}}, ls, lan=50)
    assert dt2["tong_usd"]["trung_vi"] == pytest.approx(0.162 + (20000 * 0.4 * 2 + 2000 * 10) / 1e6 + 0.016, abs=1e-3)
