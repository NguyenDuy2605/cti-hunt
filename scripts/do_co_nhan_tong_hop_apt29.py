"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Bảng tổng hợp APT29 day 2, dòng MS+SY (2 report độc lập với kịch bản), ở ba mức mẫu số thay cho chỉ 5 bước:
  bước (5 trong phạm vi · có log · toàn kịch bản) · tiến trình tấn công thấy trong Sysmon · sự kiện tấn công;
kèm báo nhầm và số sự kiện người săn phải rà. Các cách chạy (đều đã định nghĩa trong các script có nhãn trước):
  nhánh A (H-03) · hệ thống như công bố 08/10 · hệ thống + hai cổng mới (bỏ rule rộng, chạy biến thể) · SigmaHQ theo TTP
  high+critical · SigmaHQ theo TTP mọi mức · SigmaHQ high+critical toàn bộ (không theo report) · lai (hệ thống + cổng ∪
  SigmaHQ theo TTP high+critical). Chỉ dùng cho báo cáo; không dùng chỉnh thiết kế.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_tong_hop_apt29.py --out runs/co_nhan_tong_hop_01
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_cong_moi_apt29 as G  # noqa: E402
import do_co_nhan_pipeline_v2 as V2  # noqa: E402
import do_co_nhan_v2_moi as M  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.eval import g0c  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402
from cti_hunt.stages import community_rules as cr  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402

SYSMON = "microsoft-windows-sysmon/operational"
CONTRACT = "runs/khau2_20260925-161526/contract_a_{}.json"
HIGH = {"high", "critical"}


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    out = M.check_out(ap.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    vcfg = rv.load_config()
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
        # tiến trình tấn công thấy trong Sysmon: (máy, ProcessGuid) của sự kiện tấn công Sysmon
        proc_of = {(str(h), str(c), str(r)): (h, g) for h, c, r, g in con.execute(
            f"SELECT ev_host, ev_channel, ev_rec, ProcessGuid FROM labeled WHERE buoc IS NOT NULL "
            f"AND ev_channel = '{SYSMON}' AND ProcessGuid IS NOT NULL").fetchall()}
        all_procs = set(proc_of.values())
        total_attack = con.execute("SELECT count(*) FROM labeled WHERE buoc IS NOT NULL").fetchone()[0]
        # mẫu số FPR gộp theo kênh: sự kiện không phải tấn công của kênh; kênh không có sự kiện tấn công nào coi là
        # ngoài phạm vi nhãn (nhan_v1 chỉ gán Sysmon, Security, PowerShell/Operational) → báo nhầm ở đó không đánh giá được
        ch_stats = {c: (n, a) for c, n, a in con.execute(
            "SELECT ev_channel, count(*), count(buoc) FROM labeled GROUP BY 1").fetchall()}
        neg_by_ch = {c: n - a for c, (n, a) in ch_stats.items() if a > 0}
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}

        def measure(spec, source):
            return V2.measure_hunt(con, spec, steps, independent, {"cach": "tong_hop"}, Path(source))

        # hệ thống: như công bố và với hai cổng (case c của do_co_nhan_cong_moi_apt29)
        runs = [r for r in M.runs() if r[1] == M.B3 and r[4] == "chinh" and r[2] in ("MS", "SY", "PS")]
        channels = {r[0] for r in con.execute("SELECT DISTINCT ev_channel FROM events").fetchall()}
        cover = {rep: cr.coverage(cr.techniques(ContractA.model_validate_json(
            config.resolve(CONTRACT.format(rep)).read_text(encoding="utf-8"))), channels) for rep in ("MS", "SY", "PS")}
        system, gated, gated_gap = {}, {}, {}
        for name, _, rep, paths, _, _ in runs:
            a, c, g = [], [], []
            for p in paths:
                spec, kiem = V2.load_executed(p, con)
                h = V2.measure_hunt(con, spec, steps, independent, kiem, p)
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                var = G.variant_plain(raw, vcfg)
                a.append(h)
                if not _breadth(con, [raw]):
                    c.append(V2.measure_hunt(con, var, steps, independent, {"cach": "bien_the"}, p) if var else h)
                    # TTP của hunt đã có rule cộng đồng mức cao → để rule cộng đồng lo, hệ thống không sinh lại
                    levels = [cover[rep].get(t.lower(), {"muc": "khong_co_rule"})["muc"]
                              for t in raw.get("linked_ttps") or raw.get("rule_ttps") or []]
                    if "cao" not in levels:
                        g.append(c[-1])
            system[name], gated[name], gated_gap[name] = a, c, g
        # SigmaHQ
        def sigma(selected, levels=None):
            specs, _ = cr.compile_selected(selected, columns)
            hs = []
            for s in specs:
                if levels and s["nguon_rule"]["level"] not in levels:
                    continue
                s.update(_sha256="sigmahq", _path=None)
                try:
                    h = measure(s, s["nguon_rule"]["sigmahq"])
                except Exception:  # noqa: BLE001 — cột/kiểu không có ở bộ này
                    continue
                h["level"] = s["nguon_rule"]["level"]
                hs.append(h)
            return hs
        ttp = sorted({t for rep in ("MS", "SY") for t in cr.techniques(ContractA.model_validate_json(
            config.resolve(CONTRACT.format(rep)).read_text(encoding="utf-8")))})
        sig_ttp = sigma(cr.select(ttp))
        sig_ttp_high = [h for h in sig_ttp if h["level"] in HIGH]
        ttp_ps = cr.techniques(ContractA.model_validate_json(config.resolve(CONTRACT.format("PS")).read_text(encoding="utf-8")))
        sig_ps_high = [h for h in sigma(cr.select(ttp_ps)) if h["level"] in HIGH]
        metas, _ = cr._index(str(config.resolve(cr.SIGMAHQ)))
        sig_all_high = sigma([m for m in metas if m["status"] in g0c.STATUSES], HIGH)
        branch_a = next(r for r in M.runs() if r[0].startswith("Nhánh A"))
        a_hunts = []
        for p in branch_a[3]:
            spec, kiem = V2.load_executed(p, con)
            a_hunts.append(V2.measure_hunt(con, spec, steps, independent, kiem, p))
    finally:
        con.close()

    pairs = [("pipeline", f"{M.B3} pipeline SY_02", f"{M.B3} pipeline MS_01")]
    pairs += [(f"agent lượt {k}", f"{M.B3} agent {sy}", f"{M.B3} agent {ms}")
              for k, (sy, ms) in enumerate(zip(M.V3_AGENT_SLOTS["SY"], M.V3_AGENT_SLOTS["MS"]), start=1)]
    groups = [("Nhánh A (H-03), baseline", a_hunts)]
    for label, sy, ms in pairs:
        groups.append((f"Hệ thống · {label} · như công bố", system[sy] + system[ms]))
        groups.append((f"Hệ thống · {label} · + hai cổng mới", gated[sy] + gated[ms]))
    groups += [("SigmaHQ theo TTP · high+critical", sig_ttp_high), ("SigmaHQ theo TTP · mọi mức", sig_ttp),
               ("SigmaHQ high+critical · toàn bộ, không theo report", sig_all_high)]
    for label, sy, ms in pairs:
        groups.append((f"Lai · {label} · hệ thống + cổng ∪ SigmaHQ theo TTP high+critical",
                       gated[sy] + gated[ms] + sig_ttp_high))
    for label, sy, ms in pairs:
        groups.append((f"Lai chỉ khoảng trống · {label} · hunt hệ thống trên TTP chưa có rule cao ∪ SigmaHQ theo TTP "
                       "high+critical", gated_gap[sy] + gated_gap[ms] + sig_ttp_high))
    n_system = {}
    for label, sy, ms in pairs:
        n_system[f"Hệ thống · {label} · như công bố"] = len(system[sy]) + len(system[ms])
        n_system[f"Hệ thống · {label} · + hai cổng mới"] = len(gated[sy]) + len(gated[ms])
        n_system[f"Lai · {label} · hệ thống + cổng ∪ SigmaHQ theo TTP high+critical"] = len(gated[sy]) + len(gated[ms])
        n_system[f"Lai chỉ khoảng trống · {label} · hunt hệ thống trên TTP chưa có rule cao ∪ SigmaHQ theo TTP "
                 "high+critical"] = len(gated_gap[sy]) + len(gated_gap[ms])
    # PS (POSHSPY) là nguồn dựng kịch bản, không độc lập: báo riêng, mẫu số "có mô tả" theo PS
    ps_pairs = [("pipeline", f"{M.B3} pipeline PS_01")] + [(f"agent lượt {k}", f"{M.B3} agent PS_0{k}") for k in (1, 2, 3)]
    groups_ps = []
    for label, ps in ps_pairs:
        groups_ps.append((f"PS · Hệ thống · {label} · như công bố", system[ps]))
        groups_ps.append((f"PS · Hệ thống · {label} · + hai cổng mới", gated[ps]))
        n_system[f"PS · Hệ thống · {label} · như công bố"] = len(system[ps])
        n_system[f"PS · Hệ thống · {label} · + hai cổng mới"] = len(gated[ps])
    groups_ps.append(("PS · SigmaHQ theo TTP · high+critical", sig_ps_high))
    for label, ps in ps_pairs:
        groups_ps.append((f"PS · Lai · {label}", gated[ps] + sig_ps_high))
        groups_ps.append((f"PS · Lai chỉ khoảng trống · {label}", gated_gap[ps] + sig_ps_high))
        n_system[f"PS · Lai · {label}"] = len(gated[ps])
        n_system[f"PS · Lai chỉ khoảng trống · {label}"] = len(gated_gap[ps])
    rows = []
    for name, hunts, reps in [(n, h, independent) for n, h in groups] + [(n, h, ["PS"]) for n, h in groups_ps]:
        # mẫu số "có mô tả" theo đúng report của dòng: MS+SY cho dòng chính, PS cho khối PS
        r = V2.summarize(name, "+".join(reps), hunts, steps, with_log, frames, reps, reps)
        keys = r.pop("_keys")
        attack_keys = {k for k, b in keys.items() if b is not None}
        procs = {proc_of[(str(k[0]), str(k[1]), str(k[2]))] for k in attack_keys
                 if (str(k[0]), str(k[1]), str(k[2])) in proc_of}
        tk = r["toan_kich_ban"]
        fp_keys = [k for k, b in keys.items() if b is None]
        fp_lab = [k for k in fp_keys if str(k[1]) in neg_by_ch]
        pooled = {c: round(sum(1 for k in fp_lab if str(k[1]) == c) / neg, 6)
                  for c, neg in sorted(neg_by_ch.items()) if neg}
        per_hunt = sorted(h["fpr"] for h in hunts
                          if h["fpr"] is not None and h["nguon"]["channel"] in neg_by_ch and h["am_tinh"])
        fpr = {"so_hunt_tinh_duoc": len(per_hunt),
               "trung_vi": per_hunt[len(per_hunt) // 2] if per_hunt else None,
               "lon_nhat": per_hunt[-1] if per_hunt else None,
               "so_hunt_tren_1pct": sum(f > 0.01 for f in per_hunt),
               "gop_theo_kenh": pooled}
        rows.append({"ten": name, "so_hunt": r["so_hunt"], "hunt_he_thong_phai_duyet": n_system.get(name),
                     "buoc_5": len(r["buoc_5"]),
                     "buoc_5_ba_mau_so": {k: f"{v['phat_hien']}/{v['mau_so']}" for k, v in r["recall_5"]["report_doc_lap"].items()
                                          if k in ("tuyet_doi", "tran_dau_vao", "tran_thuc_te")},
                     "buoc_24_bon_mau_so": {k: f"{len(tk[k]['phat_hien'])}/{tk[k]['mau_so']}"
                                            for k in ("tuyet_doi", "co_log", "co_mo_ta", "co_mo_ta_va_co_log")},
                     "buoc_co_log": f"{len(tk['co_log']['phat_hien'])}/{tk['co_log']['mau_so']}",
                     "buoc_tuyet_doi": f"{len(tk['tuyet_doi']['phat_hien'])}/{tk['tuyet_doi']['mau_so']}",
                     "khung": tk["khung"], "tien_trinh": f"{len(procs)}/{len(all_procs)}",
                     "su_kien_tan_cong": f"{r['tan_cong']}/{total_attack}", "bao_nham": r["fp"],
                     "phai_ra": r["tan_cong"] + r["fp"], "bao_nham_kenh_co_nhan": len(fp_lab),
                     "bao_nham_kenh_khong_nhan": len(fp_keys) - len(fp_lab), "fpr": fpr,
                     "precision": None if r["precision"] is None else round(r["precision"], 4),
                     "_buoc": set(tk["tuyet_doi"]["phat_hien"]), "_procs": procs, "_attack": attack_keys})
    # phần chỉ hệ thống đóng góp: lai trừ SigmaHQ theo TTP high+critical (lai ⊇ SigmaHQ nên hiệu là phần thêm)
    bases = {"": next(r for r in rows if r["ten"] == "SigmaHQ theo TTP · high+critical"),
             "PS · ": next(r for r in rows if r["ten"] == "PS · SigmaHQ theo TTP · high+critical")}
    extra = []
    for r in rows:
        pre = "PS · " if r["ten"].startswith("PS · ") else ""
        base = bases[pre]
        if r["ten"][len(pre):].startswith("Lai"):
            extra.append({"ten": r["ten"], "buoc_them": sorted(r["_buoc"] - base["_buoc"]),
                          "tien_trinh_them": len(r["_procs"] - base["_procs"]),
                          "su_kien_tan_cong_them": len(r["_attack"] - base["_attack"])})
    for r in rows:
        for k in ("_buoc", "_procs", "_attack"):
            r.pop(k)
    out.mkdir(parents=True)
    (out / "ket_qua.json").write_text(json.dumps({"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo", "ttp_ms_sy": ttp,
                                                 "bang": rows, "chi_he_thong_them": extra}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    lines = ["Recall theo bước, mẫu số đã cam kết (v3.2 §6.1). 5 bước trong phạm vi: tuyệt đối · có mô tả trong report · có "
             "mô tả và có log. 24 bước: tuyệt đối · có log (gán được nhãn tới bước) · có mô tả · có mô tả và có log. "
             "\"Có mô tả\" tính theo MS+SY ở dòng chính, theo PS ở khối PS.", "",
             "| Cách chạy | Hunt | Hunt hệ thống phải duyệt | 5 bước (tđ · mô tả · mô tả+log) | 24 bước (tđ · log · mô tả · "
             "mô tả+log) | Tiến trình (Sysmon) | Sự kiện tấn công | Báo nhầm | Phải rà | Precision |",
             "|---|---:|---:|---|---|---|---|---:|---:|---:|"]
    for r in rows:
        pr = "—" if r["precision"] is None else f"{r['precision']:.2%}"
        nd = "—" if r["hunt_he_thong_phai_duyet"] is None else r["hunt_he_thong_phai_duyet"]
        b5 = " · ".join(r["buoc_5_ba_mau_so"][k] for k in ("tuyet_doi", "tran_dau_vao", "tran_thuc_te"))
        b24 = " · ".join(r["buoc_24_bon_mau_so"][k] for k in ("tuyet_doi", "co_log", "co_mo_ta", "co_mo_ta_va_co_log"))
        lines.append(f"| {r['ten']} | {r['so_hunt']} | {nd} | {b5} | {b24} | "
                     f"{r['tien_trinh']} | {r['su_kien_tan_cong']} | {r['bao_nham']} | {r['phai_ra']} | {pr} |")
    chans = sorted(neg_by_ch)
    short = {c: c.split("/")[0].replace("microsoft-windows-", "") for c in chans}
    lines += ["", "FPR = FP ÷ (FP + TN), mẫu số là sự kiện không tấn công cùng nguồn log. Theo hunt: nguồn = channel + mã sự "
              "kiện của hunt (chỉ hunt trên kênh có nhãn). Gộp theo kênh: hợp FP của mọi hunt trong kênh ÷ sự kiện không tấn "
              "công của cả kênh. Mẫu số theo kênh: " + ", ".join(f"{short[c]} {neg_by_ch[c]}" for c in chans) + ".", "",
              "| Cách chạy | Hunt tính FPR | FPR trung vị | FPR lớn nhất | Hunt FPR > 1% | "
              + " | ".join(f"FPR gộp {short[c]}" for c in chans) + " | FP kênh có nhãn | FP kênh không nhãn |",
              "|---|---:|---:|---:|---:|" + "---:|" * len(chans) + "---:|---:|"]

    def pc(x):
        return "—" if x is None else f"{x:.2%}"
    for r in rows:
        f = r["fpr"]
        lines.append(f"| {r['ten']} | {f['so_hunt_tinh_duoc']} | {pc(f['trung_vi'])} | {pc(f['lon_nhat'])} | "
                     f"{f['so_hunt_tren_1pct']} | " + " | ".join(pc(f["gop_theo_kenh"].get(c)) for c in chans)
                     + f" | {r['bao_nham_kenh_co_nhan']} | {r['bao_nham_kenh_khong_nhan']} |")
    lines += ["", "Phần hệ thống thêm so với SigmaHQ theo TTP high+critical (lai trừ SigmaHQ):", "",
              "| Lai | Bước thêm (24 bước) | Tiến trình thêm | Sự kiện tấn công thêm |", "|---|---|---:|---:|"]
    for e in extra:
        lines.append(f"| {e['ten']} | {', '.join(e['buoc_them']) or '—'} | {e['tien_trinh_them']} | "
                     f"{e['su_kien_tan_cong_them']} |")
    md = "\n".join(lines)
    (out / "tom_tat.md").write_text(md + "\n", encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
