"""Sinh rule hướng 2: thứ tự chạy khi có danh sách ưu tiên (giao thức `docs/METHODOLOGY.md`)."""
import importlib.util
import sys

import pytest

from cti_hunt import config


@pytest.fixture
def m(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("huong2_sinh_rule_test", config.ROOT / "scripts/huong2_sinh_rule.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "huong2_sinh_rule_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_uu_tien_chay_truoc_va_giu_thu_tu_da_tron(m):
    items = [{"goc": g} for g in ("T5", "T1", "T4", "T2", "T3")]
    assert [x["goc"] for x in m.xep_thu_tu(items, ["T2", "T4", "T9"])] == ["T4", "T2", "T5", "T1", "T3"]
    assert m.xep_thu_tu(items, None) == items
    assert sorted(x["goc"] for x in m.xep_thu_tu(items, ["T1"])) == sorted(x["goc"] for x in items)   # không mất, không lặp


def test_loi_500_chi_tinh_la_hong_voi_ky_thuat_duoc_chi_dinh(m):
    from cti_hunt.llm import providers
    e500 = providers.TransportError("Ollama cục bộ lỗi: HTTP Error 500: Internal Server Error")
    r5 = m.r5_loi_500("T1547.009", "H07", e500, ["T1547.009"])
    assert r5["hop_le"] is False and r5["dau_ra_hong"].startswith("loi_ollama_500_lap_lai") and r5["hunt_specs"] == []
    with pytest.raises(providers.TransportError):        # kỹ thuật khác: vẫn dừng như giao thức 09 §3
        m.r5_loi_500("T1059.001", "H01", e500, ["T1547.009"])
    with pytest.raises(providers.TransportError):        # mất kết nối, không phải 500: vẫn dừng
        m.r5_loi_500("T1547.009", "H07", providers.TransportError("Ollama cục bộ lỗi: <urlopen error refused>"), ["T1547.009"])
    with pytest.raises(providers.TransportError):        # không chỉ định gì: hành vi cũ
        m.r5_loi_500("T1547.009", "H07", e500, None)
