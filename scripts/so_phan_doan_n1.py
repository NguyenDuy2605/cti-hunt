"""So phân đoạn tự động (N1) với phân đoạn cũ của một report theo bốn chỉ số N1 §5.1. Chỉ đọc văn bản report, không nhãn.

- Độ phủ văn bản: tỷ lệ ký tự của đoạn cũ có chữ (không tính ảnh) xuất hiện trong toàn văn bản mới, so sau khi bỏ mọi
  khoảng trắng (lệch chỉ ở dấu cách quanh dấu câu/liên kết không tính là mất chữ).
- Văn bản thừa: tỷ lệ ký tự của đoạn mới không có trong bản cũ (cùng cách so) và không có đoạn cũ nào giống ≥ ngưỡng.
- Khớp đoạn: tỷ lệ đoạn cũ có một đoạn mới giống ≥ ngưỡng (difflib ratio trên văn bản đã gộp khoảng trắng).
- Khớp loại: trong các đoạn khớp, tỷ lệ cùng loại.

    .venv/Scripts/python.exe -X utf8 scripts/so_phan_doan_n1.py --cu data/reports/segments.jsonl --report MS --moi <thư mục ingest-report>/segments.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

IMAGE = "ảnh"


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text or "")).strip()


def bare(text: str) -> str:
    return re.sub(r"\s+", "", text)


def best_match(text: str, pool: list[tuple[dict, str]]) -> tuple[float, dict | None]:
    score, hit = 0.0, None
    for row, other in pool:
        sm = SequenceMatcher(None, text, other, autojunk=False)
        if sm.real_quick_ratio() <= score or sm.quick_ratio() <= score:
            continue
        s = sm.ratio()
        if s > score:
            score, hit = s, row
    return score, hit


def compare(old: list[dict], new: list[dict], threshold: float = 0.9) -> dict:
    old_txt = [(r, norm(r["van_ban"])) for r in old if r["loai"] != IMAGE and norm(r["van_ban"])]
    new_txt = [(r, norm(r["van_ban"])) for r in new if r["loai"] != IMAGE and norm(r["van_ban"])]
    all_new = bare(" ".join(t for _, t in new_txt))
    all_old = bare(" ".join(t for _, t in old_txt))
    old_chars = sum(len(t) for _, t in old_txt)
    new_chars = sum(len(t) for _, t in new_txt)
    covered = sum(len(t) for _, t in old_txt if bare(t) in all_new)
    matched, same_type, unmatched, type_diff = 0, 0, [], []
    for row, text in old_txt:
        score, hit = best_match(text, new_txt)
        if score >= threshold:
            matched += 1
            same_type += hit["loai"] == row["loai"]
            if hit["loai"] != row["loai"]:
                type_diff.append({"ma_doan": row["ma_doan"], "loai_cu": row["loai"], "loai_moi": hit["loai"],
                                  "dau": text[:80]})
        else:
            unmatched.append({"ma_doan": row["ma_doan"], "loai": row["loai"], "giong_nhat": round(score, 3),
                              "dau": text[:80]})
    extra = [{"ma_doan": row["ma_doan"], "loai": row["loai"], "ky_tu": len(text), "dau": text[:80]}
             for row, text in new_txt
             if bare(text) not in all_old and best_match(text, old_txt)[0] < threshold]
    extra_chars = sum(e["ky_tu"] for e in extra)

    def ratio(a, b):
        return round(a / b, 4) if b else None
    return {"doan_cu_co_chu": len(old_txt), "doan_moi_co_chu": len(new_txt),
            "anh_cu": sum(r["loai"] == IMAGE for r in old), "anh_moi": sum(r["loai"] == IMAGE for r in new),
            "loai_cu": dict(Counter(r["loai"] for r in old)), "loai_moi": dict(Counter(r["loai"] for r in new)),
            "do_phu_van_ban": ratio(covered, old_chars), "van_ban_thua": ratio(extra_chars, new_chars),
            "ky_tu_thua": extra_chars, "ky_tu_moi": new_chars,
            "khop_doan": [matched, len(old_txt)], "khop_loai": [same_type, matched],
            "doan_cu_khong_khop": unmatched, "doan_moi_thua": extra, "khop_khac_loai": type_diff}


def load(path: Path, report: str | None = None) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if report is None or r["report"] == report]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cu", type=Path, required=True, help="segments.jsonl cũ (3 report đánh giá)")
    parser.add_argument("--report", required=True, help="mã report trong tệp cũ: MS, PS, SY")
    parser.add_argument("--moi", type=Path, required=True, help="segments.jsonl của ingest-report")
    parser.add_argument("--nguong", type=float, default=0.9)
    args = parser.parse_args(argv)
    result = {"report": args.report, **compare(load(args.cu, args.report), load(args.moi), args.nguong)}
    print(json.dumps(result, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
