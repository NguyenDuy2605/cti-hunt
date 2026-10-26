"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Đo có nhãn **một lần** cho chiến dịch đánh giá v2 mốc phiên bản 3 (tuyến B v3), theo giao thức đặt trước
`docs/METHODOLOGY.md` §6 và §8. So với `do_co_nhan_pipeline_v2.py`, script này chỉ thêm:
- danh sách lượt của chiến dịch (nhóm chính / phụ lục) cạnh các cột so sánh: nhánh A, tuyến A (pipeline, agent 9 lượt),
  tuyến B 05/10 (pipeline, agent SY_01);
- dòng MS+SY của agent: "lượt k" = SY_k + MS_k, lượt thay giữ chỗ lượt bị thay (đã chốt: lượt 1 = SY_01+MS_04,
  lượt 2 = SY_02+MS_05, lượt 3 = SY_04+MS_03), kèm khoảng của cả 9 cách ghép SY×MS;
- phân tích phụ bỏ hunt rộng: ứng viên/phạm vi ≥ ngưỡng của `cti_hunt.hunt.breadth` (đếm trên `events`, không nhãn),
  áp như nhau cho mọi cột; kèm biến thể sửa đổi trước khi đo: chỉ coi là rộng khi thêm
  phạm vi ≥ 100 sự kiện, vì quy tắc gốc bắt cả hunt hẹp trên nguồn chỉ có 1–3 sự kiện. Số chính không bỏ hunt nào.
Mọi phép tính khác dùng lại nguyên hàm của `do_co_nhan_pipeline_v2.py` (`load_executed`, `measure_hunt`, `summarize`,
`markdown`) và `do_toan_kich_ban_N4.py`.

Đầu ra chỉ gồm số đếm, mã bước và mã hunt. Chỉ dùng cho báo cáo; không dùng chỉnh prompt, rule hay thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_v2_moi.py --out runs/co_nhan_v2_moi_01
"""
from __future__ import annotations

import argparse
import json
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_pipeline_v2 as V2  # noqa: E402
from phan_tich_buoc_bo_sot import BRANCH_A, check_out  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.hunt import breadth, runner  # noqa: E402

ROOT = config.ROOT
EVAL = V2.EVAL
REPORTS = V2.REPORTS
A, B05, B3 = "Tuyến A", "Tuyến B 05/10", "Tuyến B v3"

# (nhãn, thư mục, chế độ, lượt, nhóm, ghi chú) — nhóm "chinh" vào số chính, "phu_luc" báo riêng.
V3_PIPELINE = (("SY_02", "chinh", "thay pipeline SY_01"), ("PS_01", "chinh", ""), ("MS_01", "chinh", ""),
               ("SY_01", "phu_luc", "loại khỏi số chính do đề xuất ◆ lệch G0(d), quyết định trước khi đo (§5)"))
V3_AGENT = (("SY_01", "chinh", ""), ("PS_01", "chinh", ""), ("MS_04", "chinh", "thay MS_01"),
            ("SY_02", "chinh", ""), ("PS_02", "chinh", ""), ("MS_05", "chinh", "thay MS_02"),
            ("SY_04", "chinh", "thay SY_03"), ("PS_03", "chinh", ""), ("MS_03", "chinh", ""),
            ("MS_01", "phu_luc", "hỏng kỹ thuật (WinError 10054 ở ⑤), đóng bằng ghi_record_luot_ngat"),
            ("MS_02", "phu_luc", "hỏng kỹ thuật (WinError 10054 ở planner), đóng bằng ghi_record_luot_ngat"),
            ("SY_03", "phu_luc", "hỏng kỹ thuật (hết thời gian đọc ở ④), đóng bằng ghi_record_luot_ngat"))
# Lượt thay giữ chỗ lượt bị thay.
V3_AGENT_SLOTS = {"SY": ("SY_01", "SY_02", "SY_04"), "MS": ("MS_04", "MS_05", "MS_03")}
A_AGENT_SLOTS = {"SY": ("SY_01", "SY_02", "SY_03"), "MS": ("MS_01", "MS_02", "MS_03")}
# Biến thể phân tích phụ (sửa đổi trước khi đo): rộng = ≥ ngưỡng breadth VÀ phạm vi ≥ MIN_SCOPE sự kiện.
MIN_SCOPE = 100
SIDE = (("goc", f"theo giao thức: ứng viên/phạm vi ≥ {float(breadth.WARNING_RATIO):.0%}",
         lambda h: h["rong"]["broad"]),
        ("pham_vi_toi_thieu", f"biến thể sửa đổi trước khi đo: ≥ {float(breadth.WARNING_RATIO):.0%} và phạm vi ≥ {MIN_SCOPE}",
         lambda h: h["rong"]["broad"] and h["rong"]["scope"] >= MIN_SCOPE))


def _record_paths(root: Path, rel: str) -> list[Path]:
    record = root / EVAL / rel / "agent_dev_record.json"
    specs = json.loads(record.read_text(encoding="utf-8"))["executed_specs"]
    return [Path(r["path"]) for r in specs]


def runs(root: Path = ROOT):
    """(tên, nhãn tuyến, report, đường dẫn hunt, nhóm, ghi chú). Mọi lượt trong danh sách phải có; thiếu thì dừng."""
    yield "Nhánh A (H-03)", "-", "-", [root / BRANCH_A], "so_sanh", ""
    for report in REPORTS:
        yield f"{A} pipeline {report}_01", A, report, _record_paths(root, f"tuyen_A/pipeline/{report}_01"), "so_sanh", ""
    for report in REPORTS:
        for i in (1, 2, 3):
            yield (f"{A} agent {report}_{i:02d}", A, report, _record_paths(root, f"tuyen_A/agent/{report}_{i:02d}"),
                   "so_sanh", "")
    for report in REPORTS:
        yield (f"{B05} pipeline {report}_01", B05, report, _record_paths(root, f"tuyen_B/pipeline/{report}_01"),
               "so_sanh", "")
    yield f"{B05} agent SY_01", B05, "SY", _record_paths(root, "tuyen_B/agent/SY_01"), "so_sanh", ""
    for mode, table in (("pipeline", V3_PIPELINE), ("agent", V3_AGENT)):
        for name, group, note in table:
            yield (f"{B3} {mode} {name}", B3, name[:2], _record_paths(root, f"tuyen_B_v3/{mode}/{name}"), group, note)


def breadth_of(con, spec: dict) -> dict:
    """Ứng viên/phạm vi của hunt trên `events` (không nhãn), cùng ngữ nghĩa phạm vi với `runner`."""
    scope = runner._scope_where(spec["scope"])
    n_scope, n_cand = con.execute(f"SELECT count(*), count(*) FILTER (WHERE ({spec['candidates']})) "
                                  f"FROM events WHERE {scope}").fetchone()
    return breadth.summarize(int(n_scope), int(n_cand))


def pairs(names: set[str]) -> list[tuple[str, str, str]]:
    """(tên dòng MS+SY, lượt SY, lượt MS). Pipeline: một cặp mỗi tuyến; agent: "lượt k" theo bảng giữ chỗ."""
    out = [(f"{A} pipeline MS+SY", f"{A} pipeline SY_01", f"{A} pipeline MS_01"),
           (f"{B05} pipeline MS+SY", f"{B05} pipeline SY_01", f"{B05} pipeline MS_01"),
           (f"{B3} pipeline MS+SY", f"{B3} pipeline SY_02", f"{B3} pipeline MS_01")]
    for label, slots in ((A, A_AGENT_SLOTS), (B3, V3_AGENT_SLOTS)):
        for k, (sy, ms) in enumerate(zip(slots["SY"], slots["MS"]), start=1):
            out.append((f"{label} agent MS+SY lượt {k} ({sy}+{ms})", f"{label} agent {sy}", f"{label} agent {ms}"))
    missing = sorted({n for _, sy, ms in out for n in (sy, ms)} - names)
    if missing:
        raise ValueError(f"Thiếu lượt để ghép MS+SY: {missing}")
    return out


def combos(label: str, slots: dict) -> list[tuple[str, str, str]]:
    return [(f"{label} agent {sy}+{ms}", f"{label} agent {sy}", f"{label} agent {ms}")
            for sy, ms in product(slots["SY"], slots["MS"])]


def summarize_all(per_run: list[dict], steps, with_log: set[str], frames: list[str], independent: list[str],
                  keep=lambda h: True) -> tuple[list[dict], dict[str, list[dict]]]:
    """Dòng từng lượt + dòng MS+SY (khử trùng sự kiện giữa hai report) + 9 cách ghép của agent; `keep` lọc hunt."""
    by_name = {r["ten"]: r for r in per_run}

    def hunts(name):
        return [h for h in by_name[name]["hunts"] if keep(h)]

    rows = []
    for r in per_run:
        reports = None if r["report"] == "-" else [r["report"]]
        rows.append(V2.summarize(r["ten"], r["report"], hunts(r["ten"]), steps, with_log, frames, independent, reports))
    pair_rows = [V2.summarize(name, "+".join(independent), hunts(sy) + hunts(ms), steps, with_log, frames,
                              independent, independent) for name, sy, ms in pairs(set(by_name))]
    nine = {label: [V2.summarize(name, "+".join(independent), hunts(sy) + hunts(ms), steps, with_log, frames,
                                 independent, independent) for name, sy, ms in combos(label, slots)]
            for label, slots in ((A, A_AGENT_SLOTS), (B3, V3_AGENT_SLOTS))}
    return rows + pair_rows, nine


def _span(values: list) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return f"{lo}" if lo == hi else f"{lo}–{hi}"


def _pct_span(values: list) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return f"{lo:.2%}" if lo == hi else f"{lo:.2%}–{hi:.2%}"


def nine_table(nine: dict[str, list[dict]]) -> list[str]:
    L = ["| Agent | Số cách ghép | TP recall 5 bước (tuyệt đối) | Tấn công (duy nhất) | FP (duy nhất) | Precision |",
         "|---|---:|---|---|---|---|"]
    for label, rs in nine.items():
        tuyet = [r["recall_5"]["tat_ca_report"]["tuyet_doi"] for r in rs]
        L.append(f"| {label} | {len(rs)} | {_span([t['phat_hien'] for t in tuyet])}/{_span([t['mau_so'] for t in tuyet])} | "
                 f"{_span([r['tan_cong'] for r in rs])} | {_span([r['fp'] for r in rs])} | "
                 f"{_pct_span([r['precision'] for r in rs])} |")
    return L


def markdown(rows: list[dict], per_run: list[dict], frames: list[str], nine: dict, side: dict[str, tuple],
             groups: dict[str, tuple[str, str]]) -> str:
    main_names = {n for n, (g, _) in groups.items() if g != "phu_luc"}
    main_rows = [r for r in rows if r["ten"] in main_names or "MS+SY" in r["ten"]]
    main_runs = [r for r in per_run if r["ten"] in main_names]
    body = V2.markdown(main_rows, main_runs, frames).split("\n", 1)[1]
    L = ["# Đo có nhãn chiến dịch v2 mốc phiên bản 3 (tuyến B v3) cạnh các cột so sánh — CÓ NHÃN, chỉ dùng cho báo cáo",
         "", "## 0. Lượt", "", "| Cách chạy | Nhóm | Ghi chú |", "|---|---|---|"]
    for name, (g, note) in groups.items():
        L.append(f"| {name} | {g} | {note or '—'} |")
    L += ["", body.rstrip("\n"), "", "## 6. Agent MS+SY — khoảng của cả 9 cách ghép SY×MS", ""] + nine_table(nine)
    for i, (key, desc, is_broad) in enumerate(SIDE, start=1):
        broad_rows, broad_nine = side[key]
        broad = sorted({(r["ten"], h["hunt_id"], f"{h['rong']['candidates']}/{h['rong']['scope']}")
                        for r in per_run for h in r["hunts"] if is_broad(h)})
        L += ["", f"## 7.{i}. Phân tích phụ: bỏ hunt rộng — {desc} (đếm không nhãn)", "", f"Hunt bị bỏ ({len(broad)}):", ""]
        L += [f"- {t} · {h} · {c}" for t, h, c in broad] or ["- không có"]
        L += ["", "| Cách chạy | Hunt còn | Bước bắt được | TP recall | Tấn công / FP (duy nhất) | Precision |",
              "|---|---:|---|---:|---:|---:|"]
        for r in broad_rows:
            if r["ten"] in main_names or "MS+SY" in r["ten"]:
                t = r["recall_5"]["tat_ca_report"]["tuyet_doi"]
                L.append(f"| {r['ten']} | {r['so_hunt']} | {', '.join(r['buoc_5']) or '—'} | {t['phat_hien']}/{t['mau_so']} | "
                         f"{r['tan_cong']} / {r['fp']} | {V2._pct(r['precision'])} |")
        L += ["", "Agent MS+SY sau khi bỏ hunt rộng — khoảng của 9 cách ghép:", ""] + nine_table(broad_nine)
    appendix_names = [n for n, (g, _) in groups.items() if g == "phu_luc"]
    L += ["", "## 8. Phụ lục — lượt không vào số chính", "",
          "| Cách chạy | Hunt | Bước bắt được | TP recall | Tấn công / FP (duy nhất) | Precision | Loại nhầm |",
          "|---|---:|---|---:|---:|---:|---:|"]
    for r in rows:
        if r["ten"] in appendix_names:
            t = r["recall_5"]["tat_ca_report"]["tuyet_doi"]
            L.append(f"| {r['ten']} | {r['so_hunt']} | {', '.join(r['buoc_5']) or '—'} | {t['phat_hien']}/{t['mau_so']} | "
                     f"{r['tan_cong']} / {r['fp']} | {V2._pct(r['precision'])} | {r['loai_nham']} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    out = check_out(parser.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    planned = list(runs())                                   # thiếu lượt thì dừng trước khi mở nhãn
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
        per_run, groups = [], {}
        for name, tuyen, report, paths, group, note in planned:
            hunts = []
            for p in paths:
                spec, kiem = V2.load_executed(p, con)
                h = V2.measure_hunt(con, spec, steps, independent, kiem, p)
                h["rong"] = breadth_of(con, spec)
                hunts.append(h)
            per_run.append({"ten": name, "tuyen": tuyen, "report": report, "hunts": hunts})
            groups[name] = (group, note)
    finally:
        con.close()
    rows, nine = summarize_all(per_run, steps, with_log, frames, independent)
    side = {key: summarize_all(per_run, steps, with_log, frames, independent, keep=lambda h, f=is_broad: not f(h))
            for key, _, is_broad in SIDE}
    out.mkdir(parents=True)

    def clean(rs):
        return [{k: v for k, v in r.items() if k != "_keys"} for r in rs]
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "giao_thuc": "docs/METHODOLOGY.md",
               "khung_khong_co_buoc_con": frames,
               "nhom": {n: {"nhom": g, "ghi_chu": note} for n, (g, note) in groups.items()},
               "cach_chay": clean(rows), "chin_cach_ghep": {k: clean(v) for k, v in nine.items()},
               "bo_hunt_rong": {key: {"mo_ta": desc, "nguong": float(breadth.WARNING_RATIO),
                                      "pham_vi_toi_thieu": MIN_SCOPE if key != "goc" else None,
                                      "cach_chay": clean(side[key][0]),
                                      "chin_cach_ghep": {k: clean(v) for k, v in side[key][1].items()}}
                                for key, desc, _ in SIDE},
               "hunt": [{"cach_chay": r["ten"], **{k: v for k, v in h.items() if k != "keys"}}
                        for r in per_run for h in r["hunts"]]}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = markdown(rows, per_run, frames, nine, side, groups)
    (out / "tom_tat.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
