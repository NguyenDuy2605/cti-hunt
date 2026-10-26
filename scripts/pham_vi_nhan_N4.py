"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). N4 câu 1: đối chiếu 24 bước ground truth
Scenario 2 với nhãn sự kiện nhan_v1, để chốt mẫu số khi đo toàn kịch bản (N4 §2.1).

Chỉ in số đếm theo bước (không in sự kiện), không ghi gì vào data/, không gọi API. Kết quả chỉ dùng chốt mẫu số đánh
giá; không dùng để soạn prompt, chọn TTP hay chỉnh rule.

    .\\.venv\\Scripts\\python.exe -X utf8 scripts\\pham_vi_nhan_N4.py [--out <tệp JSON ngoài repo>]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DESCRIBED = ("co", "mot_phan")          # mức "có mô tả" như bảng 5 bước của v3: rõ + một phần


def summarize(con, steps, independent: list[str]) -> dict:
    """Bảng theo bước từ bảng `attack_labels` (đã attach) và view `events`."""
    labeled = dict(con.execute("SELECT buoc, count(*) FROM attack_labels GROUP BY 1").fetchall())
    joined = dict(con.execute("SELECT l.buoc, count(*) FROM attack_labels l "
                              "JOIN events e USING (ev_host, ev_channel, ev_rec) GROUP BY 1").fetchall())
    sources = con.execute("SELECT l.buoc, e.ev_channel, e.ev_eid, count(*) FROM attack_labels l "
                          "JOIN events e USING (ev_host, ev_channel, ev_rec) GROUP BY 1, 2, 3").fetchall()
    rows = []
    for s in steps:
        top = sorted(((n, ch, eid) for b, ch, eid, n in sources if b == s.substep), key=lambda x: (-x[0], x[1], x[2]))
        rows.append({"buoc": s.substep, "pham_vi": s.scope, "mo_ta_3_report": s.combined(),
                     "mo_ta_ms_sy": s.combined(independent), "su_kien_nhan": labeled.get(s.substep, 0),
                     "su_kien_khop_log": joined.get(s.substep, 0),
                     "nguon_chinh": [f"{ch} EID {eid}: {n}" for n, ch, eid in top[:3]]})
    ids = {s.substep for s in steps}

    def count(pred):
        return [r["buoc"] for r in rows if pred(r)]
    has_log = lambda r: r["su_kien_khop_log"] > 0
    return {"buoc": rows, "tong": {
        "buoc_ground_truth": len(rows),
        "co_log": count(has_log),
        "co_mo_ta_3_report": count(lambda r: r["mo_ta_3_report"] in DESCRIBED),
        "co_mo_ta_va_co_log_3_report": count(lambda r: has_log(r) and r["mo_ta_3_report"] in DESCRIBED),
        "co_mo_ta_ms_sy": count(lambda r: r["mo_ta_ms_sy"] in DESCRIBED),
        "co_mo_ta_va_co_log_ms_sy": count(lambda r: has_log(r) and r["mo_ta_ms_sy"] in DESCRIBED),
        "nhan_ngoai_ground_truth": {k: v for k, v in sorted(labeled.items()) if k not in ids},
    }}


def render(res: dict) -> str:
    lines = [f"{'Bước':<6}{'Phạm vi':<10}{'Mô tả 3 rp':<12}{'Mô tả MS+SY':<13}{'Có nhãn':>9}{'Khớp log':>10}  Nguồn chính"]
    for r in res["buoc"]:
        lines.append(f"{r['buoc']:<6}{r['pham_vi']:<10}{r['mo_ta_3_report']:<12}{r['mo_ta_ms_sy']:<13}"
                     f"{r['su_kien_nhan']:>9}{r['su_kien_khop_log']:>10}  {'; '.join(r['nguon_chinh']) or '-'}")
    t = res["tong"]
    lines += ["", f"Bước ground truth: {t['buoc_ground_truth']}"]
    for key, label in (("co_log", "có sự kiện có nhãn khớp log"),
                       ("co_mo_ta_3_report", "có mô tả (rõ hoặc một phần) trong 3 report"),
                       ("co_mo_ta_va_co_log_3_report", "có mô tả và có log, 3 report"),
                       ("co_mo_ta_ms_sy", "có mô tả trong MS+SY"),
                       ("co_mo_ta_va_co_log_ms_sy", "có mô tả và có log, MS+SY")):
        lines.append(f"  {label}: {len(t[key])} — {', '.join(t[key]) or '-'}")
    lines.append(f"  nhãn có mã bước ngoài ground truth: {t['nhan_ngoai_ground_truth'] or 'không có'}")
    return "\n".join(lines)


def main(argv=None) -> int:
    from cti_hunt import config
    from cti_hunt.cli import _labels_ready
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path, help="ghi thêm bảng dạng JSON (đặt ngoài repo hoặc thư mục tạm)")
    a = p.parse_args(argv)
    ds, rp = config.load("dataset"), config.load("reports")
    con = connect(config.resolve(ds["work_dir"]))
    s = _labels_ready(con, ds)
    if s["problems"]:
        print("Nhãn chưa join sạch (xem lệnh `labels`):", *s["problems"], sep="\n  ")
        return 1
    lv = ds["labels_v1"]
    steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
    independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
    res = summarize(con, steps, independent)
    print(render(res))
    if a.out:
        a.out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nĐã ghi {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
