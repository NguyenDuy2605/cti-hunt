"""Không nhãn, không API (15/10): quét IOC của 11 report chưa thấy (đợt 1 + đợt 2) trên 8 bộ log — câu 2 mở rộng từ 8 lên 19
report. Giữ nguyên đáp án, danh sách bỏ tay và cách đo của hai script đợt 1/đợt 2; Sekoia và ThreatDown đọc từ bundle dựng lại sau
khi sửa bộ đọc `<br>` (15/10), vì bản cũ làm mất 8 tên miền.

Hai phần quét giống `do_ioc_tac_gia.py`: (a) IOC của tác giả, so chuỗi trên mọi trường văn bản; (b) chính khâu quét IOC của hệ
thống (`s2_ioc_sweep`) trên IOC bộ rút lấy được, chỉ IOC mạnh và cả IOC yếu.

    .venv/Scripts/python.exe -X utf8 scripts/do_ioc_quet_log_report_moi.py --out <thư mục ra>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_ioc_tac_gia as T  # noqa: E402
import do_ioc_report_chua_thay  # noqa: E402,F401  (đặt REPORTS đợt 1, bảng dạng che cho đáp án)

DOT1_REPORTS, DOT1_EXCLUDE = dict(T.REPORTS), dict(T.EXCLUDE)
import do_ioc_report_chua_thay_dot2  # noqa: E402,F401  (đặt REPORTS, EXCLUDE đợt 2, đáp án Sekoia/ThreatDown từ HTML gốc)

SAU_SUA_BR = "../workspace/ioc_15-10/report_moi_sau_sua_br"
dot2 = {}
for name, (d, start, end) in T.REPORTS.items():
    rid = Path(d).name
    if rid in ("IOC-CT-08", "IOC-CT-09"):
        d = f"{SAU_SUA_BR}/{rid}"
    dot2[name] = (d, start, end)
T.REPORTS = {**DOT1_REPORTS, **dot2}
T.EXCLUDE = {**DOT1_EXCLUDE, **T.EXCLUDE}

if __name__ == "__main__":
    sys.exit(T.main([a for a in sys.argv[1:] if a != "--khong-quet-log"]))
