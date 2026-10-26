"""Không nhãn, không API (15/10): đo bộ rút IOC và tập IOC mạnh trên 3 report chưa từng dùng, mã đóng băng.

Giao thức: `docs/METHODOLOGY.md`. Dùng nguyên các hàm chấm của `scripts/do_ioc_tac_gia.py`, chỉ đổi
danh sách report và ranh giới mục IOC (xem bằng mắt sau khi tải, trước khi chạy bộ rút); không quét log.

    .venv/Scripts/python.exe -X utf8 scripts/do_ioc_report_chua_thay.py --out <thư mục ra>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_ioc_tac_gia as T  # noqa: E402

NGOAI = "../workspace/ioc_15-10/report_moi"
T.REPORTS = {
    "PureHVNC / PureRAT (Check Point Research)": (f"{NGOAI}/IOC-CT-01", "IOC-CT-01-0266", "IOC-CT-01-0280"),
    "Follow the Smoke (SentinelLabs)": (f"{NGOAI}/IOC-CT-02", "IOC-CT-02-0159", "IOC-CT-02-0204"),
    "TA584 (Proofpoint)": (f"{NGOAI}/IOC-CT-03", "IOC-CT-03-0153", "IOC-CT-03-0164"),
}
T.EXCLUDE = {}
# Đáp án đọc theo ý tác giả khi tác giả che sai chuẩn: Proofpoint ghi `ssd[.}png` (ngoặc vuông mở, ngoặc nhọn đóng). Chỉ áp cho
# đáp án; bộ rút của hệ thống giữ nguyên bảng dạng che, nên nếu nó không đọc được thì tính là bỏ sót.
T.DEFANG = T.DEFANG + [(r"\[\.\}", ".")]

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--khong-quet-log" not in args:
        args.append("--khong-quet-log")
    sys.exit(T.main(args))
