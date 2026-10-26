"""Khâu ① cho tập đánh giá: xuất các đoạn trong sheet DoanVan thành JSONL.

Với 3 report đánh giá, việc tách đoạn đã làm trong file gán nhãn, và đó đúng là văn bản hệ thống
đọc (HuongDan, mục 1). Dùng chung một bản tách đoạn thì so với bộ nhãn tham chiếu theo ma_doan được.
Bóc PDF/HTML tự động cho report mới là việc sau (report ngoài tập đánh giá, tuần 6).

Xuất văn bản không sinh nhãn, nên không cần cổng đóng băng.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..labels import reports


def export(xlsx: Path, out: Path, only: set[str] | None = None) -> dict[str, int]:
    segs = [s for s in reports.load(xlsx)["segments"] if only is None or s.report in only]
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for s in segs:
            d = asdict(s)
            d.pop("da_xem"), d.pop("anh_hanh_vi")          # cột của người gán nhãn, không phải đầu vào
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    counts: dict[str, int] = {}
    for s in segs:
        counts[s.report] = counts.get(s.report, 0) + 1
    return counts
