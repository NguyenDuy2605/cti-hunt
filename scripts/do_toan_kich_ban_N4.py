"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

N4 §2.1: TP recall theo bước trên **toàn kịch bản** APT29 day 2 cho nhánh A và 12 lượt tuyến A đã chạy. Bảng 5 bước
Living-off-the-Land giữ là bảng chính; bảng này là bảng thêm. Giả thuyết tuyến A chỉ nhắm kỹ thuật Living-off-the-Land,
nên recall trên bước khác phản ánh phạm vi đã chọn.

Dùng lại đúng danh sách hunt đã thực thi và `runner.run` của `phan_tich_buoc_bo_sot.py`. Một bước "bắt được" khi còn sự
kiện của bước ở giai đoạn cuối của ít nhất một hunt. Mẫu số đã chốt (`docs/METHODOLOGY.md` §3): tuyệt
đối (mọi bước ground truth), có log, có mô tả, có mô tả và có log — mô tả theo report của cách chạy (report của lượt;
MS+SY cho dòng ghép; cả 3 report cho nhánh A). Khung nhãn không có bước con (13, 19) báo riêng, không vào mẫu số.

Đầu ra chỉ gồm số đếm và mã bước. Chỉ dùng cho báo cáo.

    .venv/Scripts/python.exe -X utf8 scripts/do_toan_kich_ban_N4.py --out runs/n4_toan_kich_ban_01
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from phan_tich_buoc_bo_sot import analyze_hunt, check_out, runs  # noqa: E402

DESCRIBED = ("co", "mot_phan")
DENOMS = (("tuyet_doi", "Tuyệt đối"), ("co_log", "Có log"), ("co_mo_ta", "Có mô tả"),
          ("co_mo_ta_va_co_log", "Có mô tả và log"))


def denominators(steps, steps_with_log: set[str], reports: list[str] | None) -> dict[str, list[str]]:
    described = [s.substep for s in steps if s.combined(reports) in DESCRIBED]
    return {"tuyet_doi": [s.substep for s in steps],
            "co_log": [s.substep for s in steps if s.substep in steps_with_log],
            "co_mo_ta": described,
            "co_mo_ta_va_co_log": [b for b in described if b in steps_with_log]}


def score(detected: set[str], denoms: dict[str, list[str]], frames: list[str]) -> dict:
    out = {k: {"phat_hien": sorted(b for b in v if b in detected), "mau_so": len(v)} for k, v in denoms.items()}
    out["khung"] = {f: f in detected for f in frames}
    return out


def detected_steps(hunts: list[dict]) -> set[str]:
    return {b for h in hunts for b, n in h["cuoi"].items() if n}


def rows_from(per_run: list[dict], steps, steps_with_log: set[str], frames: list[str], independent: list[str]) -> list[dict]:
    """Một dòng mỗi cách chạy (mô tả theo report của nó), thêm dòng ghép MS+SY theo lượt tương ứng như báo cáo đã công bố."""
    out = []
    for r in per_run:
        reports = None if r["report"] == "-" else [r["report"]]
        out.append({"ten": r["ten"], "mo_ta_theo": "3 report" if reports is None else r["report"],
                    "phat_hien": sorted(r["phat_hien"]),
                    **score(r["phat_hien"], denominators(steps, steps_with_log, reports), frames)})
    by_name = {r["ten"]: r for r in per_run}
    pairs = [("pipeline MS+SY", "pipeline SY_01", "pipeline MS_01")]
    pairs += [(f"agent MS+SY lượt {i}", f"agent SY_{i:02d}", f"agent MS_{i:02d}") for i in (1, 2, 3)]
    for name, a, b in pairs:
        if a in by_name and b in by_name:
            got = by_name[a]["phat_hien"] | by_name[b]["phat_hien"]
            out.append({"ten": name, "mo_ta_theo": "+".join(independent), "phat_hien": sorted(got),
                        **score(got, denominators(steps, steps_with_log, independent), frames)})
    return out


def markdown(rows: list[dict], frames: list[str]) -> str:
    head = ["Cách chạy", "Mô tả theo"] + [label for _, label in DENOMS] + [f"Khung {f}" for f in frames] + ["Bước bắt được"]
    lines = ["# TP recall theo bước, toàn kịch bản APT29 day 2 — CÓ NHÃN, chỉ dùng cho báo cáo", "",
             "Bảng thêm; bảng 5 bước giữ là bảng chính. Giả thuyết tuyến A chỉ nhắm Living-off-the-Land.", "",
             "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        cells = [r["ten"], r["mo_ta_theo"]] + [f"{len(r[k]['phat_hien'])}/{r[k]['mau_so']}" for k, _ in DENOMS]
        cells += ["có" if r["khung"][f] else "không" for f in frames] + [", ".join(r["phat_hien"]) or "-"]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    from cti_hunt import config
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.hunt import runner
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
        with_log = {r[0] for r in con.execute("SELECT DISTINCT l.buoc FROM attack_labels l "
                                              "JOIN events e USING (ev_host, ev_channel, ev_rec)").fetchall()}
        ids = {s.substep for s in steps}
        frames = sorted(b for b in with_log if b and b not in ids)
        wanted = [s.substep for s in steps] + frames
        per_run = []
        for name, report, paths in runs():
            hunts = [analyze_hunt(con, runner.load_spec(p, con=con), steps, independent, wanted) for p in paths]
            per_run.append({"ten": name, "report": report, "so_hunt": len(hunts), "phat_hien": detected_steps(hunts)})
    finally:
        con.close()
    rows = rows_from(per_run, steps, with_log, frames, independent)
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "khung_khong_co_buoc_con": frames, "cach_chay": rows}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = markdown(rows, frames)
    (out / "tom_tat.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
