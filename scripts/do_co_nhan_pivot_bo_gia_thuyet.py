"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Lấp hai chỗ trống ghi ở `docs/METHODOLOGY.md` §5 (B5, B3). Dùng đúng cách đo đã công bố
(`do_co_nhan_pipeline_v2.load_executed` và `measure_hunt`, giai đoạn cuối của `runner.run`) và đúng danh sách lượt, nhóm
chính / phụ lục, dòng MS+SY của `do_co_nhan_v2_moi` (tuyến A, tuyến B 05/10, tuyến B v3). Nhánh A không có pivot hay giả
thuyết do hệ thống sinh nên không có dòng.

- **B5 — giá trị của vòng pivot (v3.2 §6.2 ⑧).** Mỗi lượt và mỗi dòng MS+SY: số vòng và hunt pivot, bước bắt được từ hunt
  pivot, **bước chỉ bắt được nhờ pivot** (bước còn ở giai đoạn cuối của ít nhất một hunt pivot mà không hunt thường nào
  của cùng lượt/dòng bắt được), tấn công / FP từ hunt pivot. Cùng cách tính với bảng agent tuyến A §4
  (`ket_qua_co_nhan_agent_tuyen_A_1-10.md`), nay áp cả pipeline. Hunt pivot = `pivot_depth ≥ 1` trong `executed_specs`.
- **B3 — bộ giả thuyết đã kiểm chứng (v3.2 §8.3).** Mỗi hunt đã thực thi một dòng: giả thuyết, nguồn log, vòng, pivot,
  bước bắt được, tấn công / FP / FPR, loại nhầm, phân loại. Hunt trên kênh không có nhãn nào trong nhan_v1 ghi "không
  đánh giá được".

Đầu ra chỉ gồm số đếm, mã bước, mã hunt và câu giả thuyết. Chỉ dùng cho báo cáo; không dùng chỉnh prompt, rule hay thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_pivot_bo_gia_thuyet.py --out runs/co_nhan_pivot_bo_gt_01
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_v2_moi as M  # noqa: E402
from phan_tich_buoc_bo_sot import check_out  # noqa: E402

from cti_hunt import config  # noqa: E402

ROOT = config.ROOT
V2 = M.V2
LOAI = ("bat_buoc_5", "bat_buoc_ngoai_5", "chi_nhieu", "rong", "khong_danh_gia_duoc")
MO_TA = {"bat_buoc_5": "bắt ≥ 1 trong 5 bước", "bat_buoc_ngoai_5": "chỉ bắt bước ngoài 5 bước",
         "chi_nhieu": "0 tấn công, có FP", "rong": "0 sự kiện cuối",
         "khong_danh_gia_duoc": "kênh không có nhãn, có sự kiện cuối"}


def _key(p) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def depths(root: Path = ROOT) -> dict[str, int]:
    """Đường dẫn hunt đã thực thi → pivot_depth, đọc từ mọi `agent_dev_record.json` dưới EVAL."""
    out: dict[str, int] = {}
    for rec in sorted((root / M.EVAL).glob("*/*/*/agent_dev_record.json")):
        for s in json.loads(rec.read_text(encoding="utf-8"))["executed_specs"]:
            out[_key(s["path"])] = int(s["pivot_depth"])
    return out


def _steps(hunts: list[dict]) -> set[str]:
    return {b for h in hunts for b, n in (h["buoc_cuoi"] or {}).items() if b and n}


def pivot_row(name: str, hunts: list[dict], scoped: set[str]) -> dict:
    """Một dòng B5. `hunts` mang `pivot_depth` và `_luot` (để đếm vòng khi ghép hai lượt)."""
    piv = [h for h in hunts if h["pivot_depth"] >= 1]
    base = [h for h in hunts if h["pivot_depth"] == 0]
    sp, sb = _steps(piv), _steps(base)
    keys: dict[tuple, str | None] = {}
    for h in piv:
        keys.update(h["keys"])
    attack = sum(b is not None for b in keys.values())
    return {"ten": name, "so_vong": len({(h["_luot"], h["vong"]) for h in hunts}),
            "so_vong_pivot": len({(h["_luot"], h["vong"]) for h in piv}),
            "so_hunt": len(hunts), "so_hunt_pivot": len(piv),
            "buoc5_tu_pivot": sorted(sp & scoped), "buoc5_chi_nho_pivot": sorted((sp - sb) & scoped),
            "buoc_khac_chi_nho_pivot": sorted((sp - sb) - scoped),
            "tan_cong_pivot": attack, "fp_pivot": len(keys) - attack,
            "fp_pivot_kenh_khong_nhan": sum(h["fp"] for h in piv if not h["kenh_co_nhan"])}


def classify(h: dict, scoped: set[str]) -> str:
    got = _steps([h])
    if not h["kenh_co_nhan"]:
        return "khong_danh_gia_duoc" if h["cuoi"] else "rong"
    if got & scoped:
        return "bat_buoc_5"
    if got:
        return "bat_buoc_ngoai_5"
    return "chi_nhieu" if h["fp"] else "rong"


def hunt_row(run: dict, h: dict, scoped: set[str]) -> dict:
    steps = {b: n for b, n in (h["buoc_cuoi"] or {}).items() if b and n}
    return {"luot": run["ten"], "nhom": run["nhom"], "report": run["report"], "vong": h["vong"],
            "pivot_depth": h["pivot_depth"], "hunt_id": h["hunt_id"], "hypothesis_id": h.get("hypothesis_id", ""),
            "gia_thuyet": h.get("gia_thuyet", ""), "linked_ttps": h.get("linked_ttps") or [], "nguon": h["nguon"],
            "kenh_co_nhan": h["kenh_co_nhan"], "cuoi": h["cuoi"], "tan_cong": h["tan_cong"], "fp": h["fp"],
            "fpr": h["fpr"], "loai_nham": h["loai_nham"],
            "buoc5": {b: n for b, n in steps.items() if b in scoped},
            "buoc_khac": {b: n for b, n in steps.items() if b not in scoped},
            "phan_loai": classify(h, scoped)}


def build(per_run: list[dict], scoped: set[str]) -> dict:
    """per_run: {ten, tuyen, report, nhom, ghi_chu, hunts}; hunt đã có pivot_depth, kenh_co_nhan."""
    for r in per_run:
        for h in r["hunts"]:
            h["_luot"] = r["ten"]
    by = {r["ten"]: r for r in per_run}
    rows = [pivot_row(r["ten"], r["hunts"], scoped) for r in per_run]
    pair_rows = [pivot_row(name, by[sy]["hunts"] + by[ms]["hunts"], scoped) for name, sy, ms in M.pairs(set(by))]
    hunts = [hunt_row(r, h, scoped) for r in per_run for h in r["hunts"]]
    groups: dict[str, Counter] = {}
    for r in per_run:
        if r["nhom"] == "phu_luc":
            continue
        mode = "pipeline" if " pipeline " in r["ten"] else "agent"
        c = groups.setdefault(f"{r['tuyen']} {mode}", Counter())
        c.update(hunt_row(r, h, scoped)["phan_loai"] for h in r["hunts"])
    return {"pivot": rows, "pivot_ms_sy": pair_rows, "hunt": hunts,
            "phan_loai_theo_nhom": {k: {x: v.get(x, 0) for x in LOAI} for k, v in groups.items()},
            "nhom": {r["ten"]: {"nhom": r["nhom"], "ghi_chu": r["ghi_chu"]} for r in per_run}}


def _list(xs) -> str:
    return ", ".join(xs) or "—"


def _pivot_table(rows: list[dict]) -> list[str]:
    L = ["| Cách chạy | Vòng (pivot) | Hunt (pivot) | 5 bước từ hunt pivot | **5 bước chỉ nhờ pivot** | "
         "Bước khác chỉ nhờ pivot | Tấn công / FP từ hunt pivot |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        fp = f"{r['fp_pivot']}" + (f" (kênh không nhãn {r['fp_pivot_kenh_khong_nhan']})"
                                   if r["fp_pivot_kenh_khong_nhan"] else "")
        L.append(f"| {r['ten']} | {r['so_vong']} ({r['so_vong_pivot']}) | {r['so_hunt']} ({r['so_hunt_pivot']}) | "
                 f"{_list(r['buoc5_tu_pivot'])} | **{_list(r['buoc5_chi_nho_pivot'])}** | "
                 f"{_list(r['buoc_khac_chi_nho_pivot'])} | {r['tan_cong_pivot']} / {fp} |")
    return L


def _short(s: str, n: int = 140) -> str:
    s = " ".join(str(s).split()).replace("|", "/")
    return s if len(s) <= n else s[: n - 1] + "…"


def markdown(res: dict) -> str:
    main = {n for n, g in res["nhom"].items() if g["nhom"] != "phu_luc"}
    L = ["# Giá trị vòng pivot và bộ giả thuyết đã kiểm chứng — CÓ NHÃN, chỉ dùng cho báo cáo", "",
         "## 1. B5 — bước chỉ bắt được nhờ pivot (mỗi lượt được tính)", ""]
    L += _pivot_table([r for r in res["pivot"] if r["ten"] in main])
    L += ["", "## 2. B5 — dòng MS+SY (khử trùng giữa hai report; agent: lượt k theo bảng giữ chỗ)", ""]
    L += _pivot_table(res["pivot_ms_sy"])
    L += ["", "## 3. B3 — phân loại hunt đã thực thi (lượt được tính)", "",
          "| Nhóm | " + " | ".join(MO_TA[x] for x in LOAI) + " |", "|---|" + "---|" * len(LOAI)]
    for g, c in res["phan_loai_theo_nhom"].items():
        L.append(f"| {g} | " + " | ".join(str(c[x]) for x in LOAI) + " |")
    L += ["", "## 4. B3 — giả thuyết bắt được ít nhất một trong 5 bước (lượt được tính)", "",
          "| Lượt | Hunt | Vòng / pivot | Nguồn | 5 bước (số sự kiện) | Tấn công / FP | Loại nhầm | Giả thuyết |",
          "|---|---|---|---|---|---|---|---|"]
    for h in res["hunt"]:
        if h["luot"] in main and h["phan_loai"] == "bat_buoc_5":
            src = f"{h['nguon']['channel']} {h['nguon']['event_ids']}" + (
                f" · {', '.join(h['nguon']['hosts'])}" if h["nguon"].get("hosts") else "")
            L.append(f"| {h['luot']} | {h['hunt_id'].split('__')[0]} | {h['vong']} / {h['pivot_depth']} | {src} | "
                     f"{', '.join(f'{b}×{n}' for b, n in sorted(h['buoc5'].items()))} | {h['tan_cong']} / {h['fp']} | "
                     f"{h['loai_nham']} | {_short(h['gia_thuyet'])} |")
    noise = sorted((h for h in res["hunt"] if h["luot"] in main and h["phan_loai"] == "chi_nhieu"),
                   key=lambda h: -h["fp"])
    L += ["", f"## 5. B3 — giả thuyết chỉ sinh nhiễu (0 tấn công, có FP; {len(noise)} hunt, xếp theo FP)", "",
          "| Lượt | Hunt | Nguồn | FP / âm tính | FPR | Giả thuyết |", "|---|---|---|---|---|---|"]
    for h in noise:
        fpr = "-" if h["fpr"] is None else f"{h['fpr']:.2%}"
        L.append(f"| {h['luot']} | {h['hunt_id'].split('__')[0]} | {h['nguon']['channel']} {h['nguon']['event_ids']} | "
                 f"{h['fp']} | {fpr} | {_short(h['gia_thuyet'])} |")
    L += ["", "## 6. Phụ lục — lượt không vào số chính", ""]
    L += _pivot_table([r for r in res["pivot"] if r["ten"] not in main])
    return "\n".join(L) + "\n"


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    out = check_out(parser.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    planned = [p for p in M.runs() if p[2] != "-"]          # thiếu lượt thì dừng trước khi mở nhãn
    depth = depths()
    con = connect(config.resolve(ds["work_dir"]))
    try:
        summary = _labels_ready(con, ds)
        if summary["problems"]:
            raise SystemExit("Nhãn chưa join sạch, không tính: " + "; ".join(map(str, summary["problems"])))
        lv = ds["labels_v1"]
        steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
        scoped = {s.substep for s in steps if s.scope == "trong"}
        independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
        labeled = {r[0] for r in con.execute("SELECT DISTINCT e.ev_channel FROM attack_labels l "
                                             "JOIN events e USING (ev_host, ev_channel, ev_rec)").fetchall()}
        per_run = []
        for name, tuyen, report, paths, group, note in planned:
            hunts = []
            for p in paths:
                spec, kiem = V2.load_executed(p, con)
                h = V2.measure_hunt(con, spec, steps, independent, kiem, p)
                h.update({k: spec.get(k) for k in ("hypothesis_id", "gia_thuyet", "linked_ttps")})
                h["pivot_depth"] = depth[_key(p)]
                h["kenh_co_nhan"] = h["nguon"]["channel"].lower() in labeled
                hunts.append(h)
            per_run.append({"ten": name, "tuyen": tuyen, "report": report, "nhom": group, "ghi_chu": note,
                            "hunts": hunts})
    finally:
        con.close()
    res = build(per_run, scoped)
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "kenh_co_nhan": sorted(labeled), **res}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = markdown(res)
    (out / "tom_tat.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
