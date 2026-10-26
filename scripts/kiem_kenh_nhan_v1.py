"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không ghi gì, chỉ in số đếm gộp.

Trả lời một câu: bộ nhãn nhan_v1 có gán nhãn cho kênh WMI-Activity hay không. Cần để diễn giải 3 "FP" của hunt
WMI-Activity 5861 trong đo có nhãn 08/10 (docs/METHODOLOGY.md).
In: số dòng nhãn theo kênh; với kênh có chữ "wmi": số dòng theo (kênh, mã sự kiện, bước). Không in từng sự kiện.

    python -X utf8 scripts/kiem_kenh_nhan_v1.py
"""
import csv
from collections import Counter
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "data/labels/nhan_v1/su_kien_tan_cong.csv"

with open(PATH, encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

print(f"Tổng dòng nhãn: {len(rows)}")
print("\nSố dòng theo kênh:")
for channel, n in Counter(r["channel"] for r in rows).most_common():
    print(f"  {n:>7}  {channel}")

wmi = Counter((r["channel"], r.get("event_id") or "-", r["buoc"]) for r in rows if "wmi" in r["channel"].lower())
print("\nKênh có chữ 'wmi' (kênh, mã sự kiện, bước):")
if not wmi:
    print("  KHÔNG CÓ dòng nhãn nào thuộc kênh WMI-Activity")
for (channel, eid, step), n in sorted(wmi.items()):
    print(f"  {n:>5}  {channel} · EID {eid} · bước {step}")
