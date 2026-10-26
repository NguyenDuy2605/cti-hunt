"""Gói demo lượt v2 chạy thật: chỉ nhận nhánh từ chối có lý do; kiểm trên lượt thật nếu có (chỉ đọc, không API)."""
import importlib.util
import socket
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("chuan_bi_demo_v2_that", SCRIPTS / "chuan_bi_demo_v2_that.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


@pytest.mark.parametrize("rows, msg", [
    ([], "Không có mục lọc"),
    ([{"id": "a", "quyet_dinh": "approved", "ly_do": "x"}], "không phải rejected"),
    ([{"id": "a", "quyet_dinh": "rejected", "ly_do": "  "}], "không phải rejected"),
    ([{"id": "a", "quyet_dinh": "", "ly_do": ""}], "không phải rejected"),
])
def test_only_rejected_with_reason(rows, msg):
    with pytest.raises(ValueError, match=msg):
        B.check_rejected(rows)
    B.check_rejected([{"id": "a", "quyet_dinh": "rejected", "ly_do": "thieu_can_cu_lanh_tinh"}])


@pytest.mark.skipif(not (B.ROOT / B.REAL_RUN / "su_co.json").exists(), reason="chưa có lượt v2 thật trên máy này")
def test_real_run_evidence_reads_only(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Dựng bằng chứng demo không được kết nối mạng")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    ev = B.Evidence()
    real = B.real_run_evidence(ev, B.ROOT / B.REAL_RUN)
    ev.unchanged()
    assert [r["quyet_dinh"] for r in real["cong_loc"]["muc_loc"]] == ["rejected"] * 3
    assert [v["dem"]["approved"] for v in real["vong"]] == [7, 8]
    assert [v["da_thuc_thi"] for v in real["vong"]] == [True, False]
    assert real["chi_phi"]["loi_goi"] == 15 and real["chi_phi"]["usd"] == "0.513196"
    assert all("CommandLine" not in s for k in real["vong"][0]["ket_qua"] for s in k["mau"])
    assert all(p.startswith(B.REAL_RUN + "/") or p == "data/dev/api_budget.sqlite" for p in ev.hashes)
