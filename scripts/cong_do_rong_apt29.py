"""Hunt nào của 12 lượt được tính (bản tổng quát, APT29 day 2) bị cổng độ rộng (15/10) đánh dấu — chỉ đếm, không nhãn.

Ghi danh sách id hunt bị đánh dấu ra JSON để người thực hiện đo có nhãn ở cửa sổ riêng ("bỏ mọi hunt bị đánh dấu" so với số đã
công bố). Không đọc nhãn, không gọi API.

    .venv/Scripts/python.exe -X utf8 scripts/cong_do_rong_apt29.py --out <thư mục ngoài data/>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    con = connect(config.resolve("data/work"))
    out = {}
    for run in base.COUNTED:
        rec = json.loads((config.resolve(f"{base.EVAL}/{run}") / "agent_dev_record.json").read_text(encoding="utf-8"))
        specs = [yaml.safe_load(Path(i["path"]).read_text(encoding="utf-8")) for i in rec.get("executed_specs") or []]
        wide = _breadth(con, specs)
        out[run] = {"so_hunt": len(specs), "bi_danh_dau": wide}
        print(f"{run:18s} {len(specs):3d} hunt · đánh dấu {len(wide)}: "
              + "; ".join(f"{k.split('__')[0]} {v['ty_le']:.0%} ({v['giu']}/{v['pham_vi']})" for k, v in wide.items()))
    p = Path(a.out)
    p.mkdir(parents=True, exist_ok=True)
    (p / "hunt_bi_cong_do_rong_danh_dau_apt29.json").write_text(json.dumps(out, ensure_ascii=False, indent=1),
                                                               encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
