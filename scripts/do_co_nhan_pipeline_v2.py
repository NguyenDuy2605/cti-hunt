"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Đo có nhãn gói 2 (pipeline v2 trên APT29 day 2, tuyến B) và các lượt agent (tuyến A 9 lượt, agent v2 SY_01) cạnh
nhánh A và pipeline tuyến A, theo đúng cách tính đã
dùng cho tuyến A (`docs/METHODOLOGY.md` §1, §3):
- bảng chính 5 bước Living-off-the-Land: bước bắt được (còn ở giai đoạn cuối của ít nhất một hunt), TP recall, rõ /
  một phần; tấn công / FP trên sự kiện duy nhất ở giai đoạn cuối, precision mức sự kiện; loại nhầm cộng theo hunt;
- FPR theo từng hunt có FP (mẫu số = sự kiện âm tính trong phạm vi của hunt);
- bảng thêm toàn kịch bản theo bốn mẫu số N4 (`do_toan_kich_ban_N4.py`), khung 13/19 báo riêng.
Dòng MS+SY ghép SY_01 + MS_01 của cùng tuyến; sự kiện chung giữa hai report chỉ đếm một lần.

Hunt lấy đúng `executed_specs` của từng lượt và chạy bằng `runner.run` của lệnh `hunt`. Hunt v2 đi qua cổng lọc
(`runner.load_spec`). Gói lọc ghim cả mã nguồn, nên lượt chạy trước một bản sửa `src/` (SY_01 tuyến B, trước `1de1508`)
không qua cổng ở mã hiện tại; khi đó spec hiệu lực được kiểm bằng SHA256 trong `effective_manifest.json` và biên nhận
thực thi, rồi chạy đúng SQL đã lưu. Cách kiểm của từng hunt ghi ở đầu ra.

Đầu ra chỉ gồm số đếm, mã bước và mã hunt. Chỉ dùng cho báo cáo; không dùng chỉnh prompt, rule hay thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_pipeline_v2.py --out runs/co_nhan_pipeline_v2_01
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from do_toan_kich_ban_N4 import DENOMS, denominators, score  # noqa: E402
from phan_tich_buoc_bo_sot import BRANCH_A, check_out  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.eval.hunt_metrics import step_recall  # noqa: E402
from cti_hunt.hunt import runner  # noqa: E402

ROOT = config.ROOT
EVAL = "data/eval/apt29_day2"
TUYEN = (("tuyen_A", "Tuyến A"), ("tuyen_B", "Tuyến B"))
REPORTS = ("SY", "MS", "PS")
GATE_FIELDS = ("filter_policy", "filter_phase", "filter_review", "sigma_context", "rang_buoc")


def runs(root: Path = ROOT):
    """(tên, tuyến, report, đường dẫn hunt đã thực thi): nhánh A, pipeline _01 của từng tuyến (bắt buộc có), rồi mọi lượt
    agent _01–_03 đã chạy (tuyến A đủ 9 lượt; tuyến B chỉ SY_01)."""
    yield "Nhánh A (H-03)", "-", "-", [root / BRANCH_A]
    for mode, numbers in (("pipeline", (1,)), ("agent", (1, 2, 3))):
        for folder_name, label in TUYEN:
            for report in REPORTS:
                for i in numbers:
                    record = root / EVAL / folder_name / mode / f"{report}_{i:02d}" / "agent_dev_record.json"
                    if mode == "agent" and not record.exists():
                        continue
                    specs = json.loads(record.read_text(encoding="utf-8"))["executed_specs"]
                    yield f"{label} {mode} {report}_{i:02d}", label, report, [Path(r["path"]) for r in specs]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_executed(path: Path, con) -> tuple[dict, dict]:
    """Spec đã thực thi và cách kiểm. Chỉ hạ xuống kiểm theo hash khi cổng lọc từ chối spec hiệu lực v2."""
    from cti_hunt.filter_approval import POLICY, FilterReviewError
    try:
        return runner.load_spec(path, con=con), {"cach": "cong_loc_day_du"}
    except FilterReviewError as e:
        reason = str(e)
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    if spec.get("filter_policy") != POLICY or spec.get("filter_phase") != "effective":
        raise ValueError(f"{path}: không phải spec hiệu lực v2 ({reason})")
    rd = Path(spec["filter_review"]["dir"])
    manifest = rd / "effective_manifest.json"
    files = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    recorded = {str(Path(k).resolve()): v for k, v in files.items()}.get(str(path.resolve()))
    if recorded != _sha(path):
        raise ValueError(f"{path}: SHA256 không khớp effective_manifest.json")
    receipt = json.loads((rd / "execution_receipt.json").read_text(encoding="utf-8"))
    if receipt.get("kind") != "completed_execution" or receipt.get("effective_manifest_sha256") != _sha(manifest):
        raise ValueError(f"{path}: biên nhận thực thi không khớp effective_manifest.json")
    plain = {k: v for k, v in spec.items() if k not in GATE_FIELDS}
    runner.validate(plain, con=con)
    plain["_sha256"], plain["_path"] = _sha(path), None
    return plain, {"cach": "hash_spec_hieu_luc", "ly_do_cong": reason}


def final_keys(con, spec: dict) -> dict[tuple, str | None]:
    """Khóa sự kiện còn ở giai đoạn cuối và bước của nó; cùng ngữ nghĩa lọc với `runner.run`."""
    where = [runner._scope_where(spec["scope"]), f"({spec['candidates']})"]
    where += [f"({f['where']}) IS NOT TRUE" for f in spec.get("filters") or []]
    rows = con.execute("SELECT ev_host, ev_channel, ev_rec, buoc FROM labeled WHERE " + " AND ".join(where)).fetchall()
    return {(h, c, r): b for h, c, r, b in rows}


def _round(path: Path) -> str:
    return next((p.name for p in path.parents if p.name.startswith("round_")), "—")


def measure_hunt(con, spec: dict, steps, independent: list[str], kiem: dict, source: Path) -> dict:
    res = runner.run(con, spec, steps, independent)
    last = res["giai_doan"][-1]
    keys = final_keys(con, spec)
    if len(keys) != last["hits"] or sum(b is not None for b in keys.values()) != last["attacker_events"]:
        raise RuntimeError(f"{spec['id']}: khóa giai đoạn cuối lệch runner.run")
    sc = spec["scope"]
    return {"hunt_id": spec["id"], "tep": str(source), "vong": _round(source), "kiem": kiem,
            "nguon": {"channel": sc["channel"], "event_ids": sc["event_ids"], "hosts": sc.get("hosts") or []},
            "am_tinh": res["mau_so_fpr"]["am_tinh"], "cuoi": last["hits"], "tan_cong": last["attacker_events"],
            "fp": last["fp"], "fpr": last["fpr"], "buoc_cuoi": last["steps"],
            "loai_nham": sum(g["removed_attacker"] for g in res["giai_doan"][1:]), "keys": keys}


def summarize(name: str, report: str, hunts: list[dict], steps, steps_with_log: set[str], frames: list[str],
              independent: list[str], reports: list[str] | None) -> dict:
    keys: dict[tuple, str | None] = {}
    for h in hunts:
        keys.update(h["keys"])
    attack = sum(b is not None for b in keys.values())
    detected = {b for b in keys.values() if b is not None}
    scoped = [s for s in steps if s.scope == "trong"]
    levels: dict[str, list[str]] = {}
    for s in scoped:
        levels.setdefault(s.combined(None), []).append(s.substep)
    return {"ten": name, "report": report, "so_hunt": len(hunts),
            "buoc_5": sorted(b for b in detected if b in {s.substep for s in scoped}),
            "recall_5": step_recall(detected, steps, steps_with_log, independent),
            "theo_muc": {lv: {"buoc": v, "phat_hien": sorted(b for b in v if b in detected)} for lv, v in levels.items()},
            "tan_cong": attack, "fp": len(keys) - attack,
            "precision": attack / len(keys) if keys else None,
            "loai_nham": sum(h["loai_nham"] for h in hunts),
            "toan_kich_ban": {"mo_ta_theo": "3 report" if reports is None else "+".join(reports),
                              "phat_hien": sorted(detected),
                              **score(detected, denominators(steps, steps_with_log, reports), frames)},
            "_keys": keys}


def rows_from(per_run: list[dict], steps, steps_with_log: set[str], frames: list[str],
              independent: list[str]) -> list[dict]:
    """Mỗi lượt một dòng, rồi dòng MS+SY của từng tuyến (khử trùng sự kiện giữa hai report)."""
    rows = []
    for r in per_run:
        reports = None if r["report"] == "-" else [r["report"]]
        rows.append(summarize(r["ten"], r["report"], r["hunts"], steps, steps_with_log, frames, independent, reports))
    by_name = {r["ten"]: r for r in per_run}
    for _, label in TUYEN:
        sy, ms = by_name.get(f"{label} pipeline SY_01"), by_name.get(f"{label} pipeline MS_01")
        if sy and ms:
            rows.append(summarize(f"{label} pipeline MS+SY", "+".join(independent), sy["hunts"] + ms["hunts"], steps,
                                  steps_with_log, frames, independent, independent))
    return rows


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.2%}"


def markdown(rows: list[dict], per_run: list[dict], frames: list[str]) -> str:
    L = ["# Đo có nhãn pipeline v2 (gói 2) cạnh nhánh A và pipeline tuyến A — CÓ NHÃN, chỉ dùng cho báo cáo", "",
         "## 1. Năm bước Living-off-the-Land (bảng chính)", "",
         "| Cách chạy | Hunt | Bước bắt được | TP recall | Rõ | Một phần | Tấn công / FP (duy nhất) | Precision | Loại nhầm |",
         "|---|---:|---|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        tuyet = r["recall_5"]["tat_ca_report"]["tuyet_doi"]
        lv = {k: f"{len(v['phat_hien'])}/{len(v['buoc'])}" for k, v in r["theo_muc"].items()}
        L.append(f"| {r['ten']} | {r['so_hunt']} | {', '.join(r['buoc_5']) or '—'} | {tuyet['phat_hien']}/{tuyet['mau_so']} | "
                 f"{lv.get('co', '-')} | {lv.get('mot_phan', '-')} | {r['tan_cong']} / {r['fp']} | {_pct(r['precision'])} | "
                 f"{r['loai_nham']} |")
    L += ["", "TP recall ba mẫu số (tuyệt đối · trần đầu vào · trần thực tế), tất cả report / report độc lập:", ""]
    for r in rows:
        parts = []
        for key in ("tat_ca_report", "report_doc_lap"):
            b = r["recall_5"][key]
            parts.append(" · ".join(f"{b[n]['phat_hien']}/{b[n]['mau_so']}" for n in ("tuyet_doi", "tran_dau_vao", "tran_thuc_te")))
        L.append(f"- {r['ten']}: {parts[0]} | độc lập {parts[1]}")
    L += ["", "## 2. FPR theo hunt có FP", "", "| Cách chạy | Hunt | Vòng | Nguồn | FP / âm tính | FPR |",
          "|---|---|---|---|---:|---:|"]
    for r in per_run:
        for h in r["hunts"]:
            if h["fp"]:
                src = f"{h['nguon']['channel']} {h['nguon']['event_ids']}" + (
                    f" · {', '.join(h['nguon']['hosts'])}" if h["nguon"]["hosts"] else "")
                L.append(f"| {r['ten']} | {h['hunt_id']} | {h['vong']} | {src} | {h['fp']} / {h['am_tinh']} | {_pct(h['fpr'])} |")
    L += ["", "## 3. Toàn kịch bản (bảng thêm, bốn mẫu số N4)", "",
          "| Cách chạy | Mô tả theo | " + " | ".join(label for _, label in DENOMS) + " | "
          + " | ".join(f"Khung {f}" for f in frames) + " |", "|" + "---|" * (2 + len(DENOMS) + len(frames))]
    for r in rows:
        t = r["toan_kich_ban"]
        L.append(f"| {r['ten']} | {t['mo_ta_theo']} | " + " | ".join(f"{len(t[k]['phat_hien'])}/{t[k]['mau_so']}" for k, _ in DENOMS)
                 + "".join(f" | {'có' if t['khung'][f] else 'không'}" for f in frames) + " |")
    scoped = sorted({b for r in rows for b in r["recall_5"]["tat_ca_report"]["tuyet_doi"]["buoc_phat_hien"]}
                    | {b for r in rows for b in r["recall_5"]["tat_ca_report"]["tuyet_doi"]["buoc_bo_sot"]})
    L += ["", "## 4. Bước nào do hunt nào bắt (giai đoạn cuối, số sự kiện tấn công của bước)", "",
          "Hunt rộng (ứng viên gần cả phạm vi) có thể chạm nhiều bước cùng lúc; đọc kèm FP ở mục 2.", "",
          "| Cách chạy | " + " | ".join(scoped) + " |", "|---|" + "---|" * len(scoped)]
    for r in per_run:
        cells = []
        for b in scoped:
            got = [(h["hunt_id"].split("__")[0], h["buoc_cuoi"][b]) for h in r["hunts"] if h["buoc_cuoi"].get(b)]
            cells.append(", ".join(f"{i}×{n}" for i, n in got) or "—")
        L.append(f"| {r['ten']} | " + " | ".join(cells) + " |")
    fallback = [(r["ten"], h["hunt_id"]) for r in per_run for h in r["hunts"] if h["kiem"]["cach"] != "cong_loc_day_du"]
    L += ["", "## 5. Cách kiểm spec", "",
          f"- Qua cổng lọc đầy đủ: {sum(len(r['hunts']) for r in per_run) - len(fallback)} hunt.",
          f"- Kiểm theo SHA256 spec hiệu lực (gói lọc ghim mã nguồn đã đổi sau lượt): {len(fallback)} hunt"
          + (f" ({', '.join(sorted({t for t, _ in fallback}))})." if fallback else ".")]
    return "\n".join(L) + "\n"


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
        with_log = {r[0] for r in con.execute("SELECT DISTINCT l.buoc FROM attack_labels l "
                                              "JOIN events e USING (ev_host, ev_channel, ev_rec)").fetchall()}
        frames = sorted(b for b in with_log if b and b not in {s.substep for s in steps})
        per_run = []
        for name, tuyen, report, paths in runs():
            hunts = []
            for p in paths:
                spec, kiem = load_executed(p, con)
                hunts.append(measure_hunt(con, spec, steps, independent, kiem, p))
            per_run.append({"ten": name, "tuyen": tuyen, "report": report, "hunts": hunts})
    finally:
        con.close()
    rows = rows_from(per_run, steps, with_log, frames, independent)
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "khung_khong_co_buoc_con": frames,
               "cach_chay": [{k: v for k, v in r.items() if k != "_keys"} for r in rows],
               "hunt": [{"cach_chay": r["ten"], **{k: v for k, v in h.items() if k != "keys"}}
                        for r in per_run for h in r["hunts"]]}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = markdown(rows, per_run, frames)
    (out / "tom_tat.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
