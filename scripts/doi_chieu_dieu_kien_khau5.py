"""Đối chiếu giá trị điều kiện của rule ⑤ với giả thuyết đã duyệt cùng vòng (B3, 09/10). Chỉ đọc, không gọi API.

Duyệt mọi thư mục vòng có `hypotheses_da_duyet.json` dưới các đường dẫn đưa vào, ghép rule `rules_draft/` hoặc `rules/`
theo tên tệp = mã giả thuyết, in mỗi rule một dòng JSON và dòng tổng. Mục liệt kê là để người xem, không chứng minh
rule sai; rule không có mục không chứng minh giữ đủ điều kiện. Không dùng cho thư mục lượt đánh giá khi thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/doi_chieu_dieu_kien_khau5.py <thư mục lượt hoặc gói> [...]
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from cti_hunt import approval, demo


def rows(base: Path):
    for round_dir in sorted({p.parent for p in base.rglob(approval.APPROVED_FILE)}):
        for sub in ("rules_draft", "rules"):
            for rule in sorted((round_dir / sub).glob("*.yml")):
                items = demo.rule_grounding(rule)
                if items is not None:
                    # "thieu" (H6, 12/10): chuỗi của giả thuyết không thấy trong điều kiện rule; cũng chỉ để người xem.
                    yield {"vong": round_dir.relative_to(base).as_posix(), "rule": f"{sub}/{rule.name}", "muc": items,
                           "thieu": demo.rule_missing(rule) or []}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    total, kinds, missing = 0, Counter(), Counter()
    for base in args.paths:
        for row in rows(base):
            total += 1
            kinds.update(i["kind"] for i in row["muc"])
            missing.update(m["loai"] for m in row["thieu"])
            print(json.dumps({"goc": base.as_posix(), **row}, ensure_ascii=False))
    print(json.dumps({"so_rule": total, "so_muc_theo_loai": dict(kinds), "so_chuoi_thieu_theo_loai": dict(missing)},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
