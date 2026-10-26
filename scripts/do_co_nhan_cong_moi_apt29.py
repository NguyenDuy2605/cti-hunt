"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Hai cổng mới (15/10, docs/METHODOLOGY.md) trên các lượt **chính** của bản tổng quát (tuyến B v3,
APT29 day 2), dòng MS+SY theo đúng cách ghép của do_co_nhan_v2_moi.py. Bốn tình huống, cùng hàm đo:
  a_cong_bo        mọi hunt đã thực thi (phải ra lại số đã công bố 08/10);
  b_bo_rong        bỏ hunt bị cổng độ rộng đánh dấu (configs/do_rong_rule.yaml);
  c_bo_rong_bt     như b, và rule có biến thể mức kỹ thuật thì chạy biến thể thay rule gốc;
  d_bo_rong_them   như b, và chạy thêm biến thể cạnh rule gốc.
Cổng độ rộng và biến thể được thiết kế trên OTRF (dữ liệu phát triển) trước khi đo; nhưng giá trị 57% của giả thuyết 443 trên
APT29 đã biết trước. Chỉ dùng cho báo cáo; không dùng chỉnh thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_cong_moi_apt29.py --out runs/co_nhan_cong_moi_01
    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_cong_moi_apt29.py --khong-nhan     # chỉ kiểm, không mở nhãn
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_pipeline_v2 as V2  # noqa: E402
import do_co_nhan_v2_moi as M  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402

CASES = ("a_cong_bo", "b_bo_rong", "c_bo_rong_bt", "d_bo_rong_them")


def planned():
    """Chỉ lượt nhóm chính của tuyến B v3."""
    return [r for r in M.runs() if r[1] == M.B3 and r[4] == "chinh"]


def variant_plain(spec: dict, cfg: dict) -> dict | None:
    """Hunt spec thường (không marker cổng) của biến thể, cùng phạm vi rule gốc; None nếu không có biến thể."""
    if not (spec.get("sigma_context") or {}).get("rule") or not rv._is_root(spec):
        return None
    var, _ = rv.variant_spec(spec, cfg)
    if var is None:
        return None
    return {"id": f"{spec['id']}__bien_the", "nhanh": "B", "gia_thuyet": var.get("gia_thuyet", ""),
            "linked_ttps": spec.get("linked_ttps") or [], "scope": spec["scope"], "candidates": var["candidates"],
            "filters": [], "_sha256": "bien_the", "_path": None}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--khong-nhan", action="store_true", help="chỉ đếm hunt bị đánh dấu và biến thể, không mở nhãn")
    a = ap.parse_args(argv)
    cfg = rv.load_config()
    runs = planned()
    if a.khong_nhan:
        from cti_hunt.data.store import connect
        con = connect(config.resolve("data/work"))
        for name, _, _, paths, _, _ in runs:
            specs = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in paths]
            wide = _breadth(con, specs)
            n_var = sum(variant_plain(s, cfg) is not None for s in specs)
            print(f"{name:32s} {len(specs):3d} hunt · rộng {len(wide)} · có biến thể {n_var}")
        return
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    if not a.out:
        raise SystemExit("cần --out")
    out = M.check_out(a.out)
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
        frames = sorted(b for b in with_log if b and b not in {s.substep for s in steps})
        per_case = {k: [] for k in CASES}
        detail = []
        for name, tuyen, report, paths, group, note in runs:
            rows = {k: [] for k in CASES}
            for p in paths:
                spec, kiem = V2.load_executed(p, con)
                h = V2.measure_hunt(con, spec, steps, independent, kiem, p)
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                wide = bool(_breadth(con, [raw]))
                var = variant_plain(raw, cfg)
                hv = V2.measure_hunt(con, var, steps, independent, {"cach": "bien_the"}, p) if var else None
                rows["a_cong_bo"].append(h)
                if not wide:
                    rows["b_bo_rong"].append(h)
                    rows["c_bo_rong_bt"].append(hv or h)
                    rows["d_bo_rong_them"] += [h] + ([hv] if hv else [])
                detail.append({"cach_chay": name, "hunt": spec["id"], "rong": wide, "co_bien_the": bool(var),
                               "goc": {k: h[k] for k in ("cuoi", "tan_cong", "fp", "buoc_cuoi")},
                               "bien_the": {k: hv[k] for k in ("cuoi", "tan_cong", "fp", "buoc_cuoi")} if hv else None})
            for k in CASES:
                per_case[k].append({"ten": name, "tuyen": tuyen, "report": report, "hunts": rows[k]})
    finally:
        con.close()
    # Chỉ có lượt tuyến B v3: ghép MS+SY trực tiếp (pipeline SY_02+MS_01; agent theo bảng giữ chỗ của do_co_nhan_v2_moi).
    pairs = [("pipeline", f"{M.B3} pipeline SY_02", f"{M.B3} pipeline MS_01")]
    pairs += [(f"agent lượt {k}", f"{M.B3} agent {sy}", f"{M.B3} agent {ms}")
              for k, (sy, ms) in enumerate(zip(M.V3_AGENT_SLOTS["SY"], M.V3_AGENT_SLOTS["MS"]), start=1)]
    result = {}
    for k in CASES:
        by = {r["ten"]: r["hunts"] for r in per_case[k]}
        rws = [V2.summarize(f"{label} MS+SY", "MS+SY", by[sy] + by[ms], steps, with_log, frames, independent,
                            independent) for label, sy, ms in pairs]
        rws += [V2.summarize(r["ten"], r["report"], r["hunts"], steps, with_log, frames, independent, [r["report"]])
                for r in per_case[k] if r["report"] == "PS"]
        result[k] = {"cach_chay": [{x: v for x, v in r.items() if x != "_keys"} for r in rws]}
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "thiet_ke": "docs/METHODOLOGY.md", "tinh_huong": result, "hunt": detail}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["| Cách chạy | " + " | ".join(CASES) + " |", "|---|" + "---|" * len(CASES)]
    names = [r["ten"] for r in result["a_cong_bo"]["cach_chay"]]
    for n in names:
        cells = []
        for k in CASES:
            r = next(x for x in result[k]["cach_chay"] if x["ten"] == n)
            cells.append(f"{len(r['buoc_5'])}/5 · FP {r['fp']}")
        lines.append(f"| {n} | " + " | ".join(cells) + " |")
    md = "\n".join(lines)
    (out / "tom_tat.md").write_text(md + "\n", encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
