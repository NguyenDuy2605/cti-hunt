"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Tách khâu làm mất từng bước trong scope cho nhánh A và 12 lượt tuyến A, bằng số sự kiện tấn công theo bước ở ba giai đoạn:
- ngoai_pham_vi: không hunt nào có sự kiện của bước trong phạm vi (nguồn log, mã sự kiện, máy, thời gian của hunt);
- khong_khop_dieu_kien: bước có trong phạm vi ≥ 1 hunt nhưng không vào tập ứng viên của hunt nào;
- bi_loc: bước có trong ứng viên ≥ 1 hunt nhưng không còn ở giai đoạn cuối của hunt nào;
- bat_duoc: bước còn ở giai đoạn cuối của ≥ 1 hunt.

Ứng viên/lọc/cuối lấy từ đúng `runner.run` của lệnh `hunt`; chỉ thêm một truy vấn đếm theo bước ở phạm vi. Đầu ra chỉ
gồm số đếm và mã hunt, không có dòng sự kiện. Chỉ dùng cho báo cáo; không dùng chọn TTP, rule, prompt hay chỉnh thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/phan_tich_buoc_bo_sot.py --out runs/phan_tich_buoc_bo_sot_01
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cti_hunt import config
from cti_hunt.hunt import runner
from cti_hunt.labels.ground_truth import Step

ROOT = config.ROOT
EVAL = "data/eval/apt29_day2/tuyen_A"
BRANCH_A = "hunts/manual/H-03.yaml"
KHAU = {"bat_duoc": "B", "bi_loc": "L", "khong_khop_dieu_kien": "R", "ngoai_pham_vi": "P"}


def inscope(steps: list[Step]) -> list[str]:
    """Bước trong scope theo ground truth, cùng quy tắc với `step_recall`."""
    return [s.substep for s in steps if s.scope == "trong"]


def analyze_hunt(con, spec: dict, steps: list[Step], independent: list[str], wanted: list[str]) -> dict:
    res = runner.run(con, spec, steps, independent)
    where = runner._scope_where(spec["scope"])
    scope = dict(con.execute(f"SELECT buoc, count(*) FROM labeled WHERE {where} AND buoc IS NOT NULL "
                             "GROUP BY buoc").fetchall())
    stages = res["giai_doan"]
    removed: dict[str, int] = {}
    for st in stages[1:]:
        for b, n in st["removed_attacker_steps"].items():
            removed[b] = removed.get(b, 0) + n

    def pick(counts: dict) -> dict:
        return {b: int(counts[b]) for b in wanted if counts.get(b)}
    sc = spec["scope"]
    return {"hunt_id": spec["id"],
            "nguon": {"channel": sc["channel"], "event_ids": sc["event_ids"], "hosts": sc.get("hosts") or []},
            "pham_vi": pick(scope), "ung_vien": pick(stages[0]["steps"]), "cuoi": pick(stages[-1]["steps"]),
            "loai_nham": pick(removed)}


def classify(hunts: list[dict], step: str) -> str:
    for key, label in (("cuoi", "bat_duoc"), ("ung_vien", "bi_loc"), ("pham_vi", "khong_khop_dieu_kien")):
        if any(h[key].get(step) for h in hunts):
            return label
    return "ngoai_pham_vi"


def summarize(hunts: list[dict], wanted: list[str]) -> dict:
    return {step: {"khau": classify(hunts, step),
                   "hunt_trong_pham_vi": [h["hunt_id"] for h in hunts if h["pham_vi"].get(step)],
                   "hunt_co_ung_vien": [h["hunt_id"] for h in hunts if h["ung_vien"].get(step)],
                   "hunt_con_cuoi": [h["hunt_id"] for h in hunts if h["cuoi"].get(step)]}
            for step in wanted}


def runs(root: Path = ROOT):
    """(tên, report, đường dẫn hunt đã thực thi) cho nhánh A và 12 lượt; đọc đúng `executed_specs` của từng lượt."""
    yield "Nhánh A (H-03)", "-", [root / BRANCH_A]
    for mode in ("pipeline", "agent"):
        for report in ("SY", "MS", "PS"):
            for i in range(1, 2 if mode == "pipeline" else 4):
                folder = root / EVAL / mode / f"{report}_{i:02d}"
                record = json.loads((folder / "agent_dev_record.json").read_text(encoding="utf-8"))
                yield f"{mode} {report}_{i:02d}", report, [Path(r["path"]) for r in record["executed_specs"]]


def markdown(rows: list[dict], wanted: list[str]) -> str:
    lines = ["# Bước bỏ sót theo khâu — CÓ NHÃN, chỉ dùng cho báo cáo", "",
             "B = bắt được · L = bị lọc · R = trong phạm vi nhưng không khớp điều kiện ứng viên · "
             "P = ngoài phạm vi của mọi hunt", "",
             "| Cách chạy | Hunt | " + " | ".join(wanted) + " |", "|---|---:|" + "---|" * len(wanted)]
    for r in rows:
        lines.append(f"| {r['ten']} | {r['so_hunt']} | "
                     + " | ".join(KHAU[r["buoc"][s]["khau"]] for s in wanted) + " |")
    lines += ["", "## Bước trong phạm vi nhưng không khớp điều kiện (R): hunt có bước trong phạm vi", ""]
    for r in rows:
        for s in wanted:
            if r["buoc"][s]["khau"] == "khong_khop_dieu_kien":
                lines.append(f"- {r['ten']} · {s}: " + ", ".join(r["buoc"][s]["hunt_trong_pham_vi"]))
    return "\n".join(lines) + "\n"


def check_out(out: Path, root: Path = ROOT) -> Path:
    out = out.resolve()
    if not out.is_relative_to((root / "runs").resolve()) or out.exists():
        raise ValueError("--out phải là thư mục mới trong runs/ (đầu ra có nhãn không nằm trong data/dev hay docs)")
    return out


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    out = check_out(parser.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    con = connect(config.resolve(ds["work_dir"]))
    try:
        summary = _labels_ready(con, ds)
        if summary["problems"]:
            raise SystemExit("Nhãn chưa join sạch, không tính: " + "; ".join(map(str, summary["problems"])))
        lv = ds["labels_v1"]
        steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
        independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
        wanted = inscope(steps)
        rows = []
        for name, report, paths in runs():
            hunts = [analyze_hunt(con, runner.load_spec(p, con=con), steps, independent, wanted) for p in paths]
            rows.append({"ten": name, "report": report, "so_hunt": len(hunts),
                         "buoc": summarize(hunts, wanted), "hunt": hunts})
    finally:
        con.close()
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "buoc_trong_scope": wanted, "cach_chay": rows}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = markdown(rows, wanted)
    (out / "tom_tat.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
