"""Câu hỏi 2, hướng 2: hai cách chấm mở rộng, dùng lại nguyên hàm chấm của ``huong2_cham.py`` (giao thức 22, không sửa script đó).

- ``tap-con``: chấm trên một tập con kỹ thuật S (mẫu của lượt Claude, giao thức ``28_…`` §6). Mọi cách (SigmaHQ theo tag, đối
  chứng, từng lượt hệ thống ``--he-thong ten=thư_mục``, lai) chỉ giữ hunt của kỹ thuật trong S; phạm vi nhãn E giữ nguyên L1 như
  giao thức 22, nên báo nhầm vẫn đếm trên mọi bộ L1. Mã hunt của lượt hệ thống được thêm tiền tố ``ten__`` để hai lượt trùng mã
  không ghi đè tập khớp của nhau. Thêm McNemar giữa từng cặp cách và bảng đối đầu.
- ``cha-con``: chọn rule SigmaHQ theo tag mở rộng (định nghĩa ``30_…``): ``chinh_xac`` (G0(c), như giao thức 22), ``cha`` (thêm
  rule mang tag kỹ thuật cha của X), ``con`` (thêm rule mang tag kỹ thuật con của X), ``cha_con``. Mức cao và mọi mức. Số đo
  này là **trong mẫu**: cách chọn được đề xuất sau khi đã thấy kết quả chọn theo tag trên chính dữ liệu này.

    python scripts/huong2_cham_mo_rong.py tap-con --tap <json> --khoa <khóa danh sách> --he-thong claude=<thư mục> ... <chung>
    python scripts/huong2_cham_mo_rong.py cha-con <chung>
    <chung> = --parquet … --nhan … --pham-vi … [--sha-nhan …] [--sha-pham-vi …] [--bo-loai …] --bo-sung-danh-muc …
              [--doi-chung-toan-bo] --db <tệp duckdb> --out <thư mục>
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import huong2_cham as hc  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.eval import g0c  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402
from cti_hunt.stages import community_rules  # noqa: E402

KIEU = ("chinh_xac", "cha", "con", "cha_con")


def khop_tag(tags: set[str], ids: set[str], kieu: str) -> bool:
    """Rule mang ``tags`` có được chọn cho kỹ thuật có mã ``ids`` (mã gốc và mã hiện hành, chữ thường) theo ``kieu``."""
    if tags & ids:
        return True
    if kieu in ("cha", "cha_con") and tags & {i.split(".")[0] for i in ids if "." in i}:
        return True
    if kieu in ("con", "cha_con"):
        cha = {i for i in ids if "." not in i}
        return any("." in t and t.split(".")[0] in cha for t in tags)
    return False


def specs_theo_kieu(goc_hh: dict, columns: set[str], root, danh_muc: str, kieu: str) -> tuple[dict, dict, list]:
    """Như ``huong2_cham.specs_sigmahq`` nhưng chọn bằng ``khop_tag`` (``chinh_xac`` cho đúng tập rule của giao thức 22)."""
    metas, _ = community_rules._index(str(config.resolve(root)))
    metas = [m for m in metas if m["status"] in g0c.STATUSES]
    cache, skipped, cao, moi = {}, [], {}, {}
    for goc, hh in goc_hh.items():
        ids = {goc.lower()} | ({hh.lower()} if hh else set())
        for m in metas:
            if not khop_tag(set(m["techniques"]), ids, kieu):
                continue
            key = m["relative_path"]
            if key not in cache:
                specs, sk = community_rules.compile_selected([m], columns, root, danh_muc)
                cache[key], sk2 = hc._chay_duoc(specs, key)
                skipped += sk + sk2
            for s in cache[key]:
                moi.setdefault(goc, []).append(s)
                if s["nguon_rule"]["level"] in community_rules.HIGH:
                    cao.setdefault(goc, []).append(s)
    return cao, moi, skipped


def mo_chung(a):
    """Phần dựng chung với ``huong2_cham.main``: kiểm băm nhãn, mở tệp DuckDB, kỹ thuật của từng bộ, danh mục chấm, phạm vi."""
    for tep, sha in ((a.nhan, a.sha_nhan), (a.pham_vi, a.sha_pham_vi)):
        if sha and hc.sha_tep(Path(tep)) != sha.lower():
            raise SystemExit(f"SHA256 của {tep} không khớp giao thức")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    con = hc.mo_csdl(Path(a.parquet), Path(a.db))
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    tom_tat = json.loads((Path(a.parquet) / "tom_tat_nap.json").read_text(encoding="utf-8"))
    bo_kt = {b: r["ky_thuat"] for r in tom_tat.values() if r["trang_thai"] in ("ok", "mot_phan")
             for b in (r.get("bo_con") or [r["ma_bo"]])}
    cat = hc.AttackCatalog.from_stix(config.resolve(hc.STIX))
    goc_hh = {k: cat.resolve(k).final for k in sorted({k for v in bo_kt.values() for k in v})}
    dm = hc.danh_muc_cham(Path(a.bo_sung_danh_muc) if a.bo_sung_danh_muc else None, out)
    l1 = {x["bo"] for x in json.loads(Path(a.pham_vi).read_text(encoding="utf-8"))["bo"]}
    bo_loai = set(json.loads(Path(a.bo_loai).read_text(encoding="utf-8"))["bo"]) if a.bo_loai else set()
    if bo_loai - l1:
        raise SystemExit(f"--bo-loai có bộ ngoài phạm vi: {sorted(bo_loai - l1)[:3]}")
    dau_vao = {"tom_tat_nap.json": hc.sha_tep(Path(a.parquet) / "tom_tat_nap.json"),
               "nhan": [str(a.nhan), hc.sha_tep(Path(a.nhan))], "pham_vi": [str(a.pham_vi), hc.sha_tep(Path(a.pham_vi))],
               "bo_loai": [str(a.bo_loai), hc.sha_tep(Path(a.bo_loai))] if a.bo_loai else None,
               "bo_sung_danh_muc": [str(a.bo_sung_danh_muc), hc.sha_tep(Path(a.bo_sung_danh_muc))]
               if a.bo_sung_danh_muc else None,
               "script": hc.sha_tep(Path(__file__)), "script_huong2_cham": hc.sha_tep(Path(hc.__file__))}
    return con, columns, bo_kt, goc_hh, dm, l1 - bo_loai, out, dau_vao


def phu_sysmon(con, cach: dict) -> set[tuple[str, str]]:
    """(cách, kỹ thuật) có ít nhất một hunt kênh Sysmon chạy không lỗi."""
    loi = {h for (h,) in con.execute("SELECT hunt FROM hunt_info WHERE loi IS NOT NULL").fetchall()}
    return {(c, k) for c, by in cach.items() for k, specs in by.items()
            if any(str(s["scope"]["channel"]).lower() == hc.SYSMON and s["id"] not in loi for s in specs)}


def so_cap_va_doi_dau(kq: dict, theo_kt: list[dict], cap: list[tuple[str, str]], phu: set) -> None:
    """McNemar chính xác theo kỹ thuật trên T cho từng cặp, và bảng đối đầu (cả hai cách có hunt Sysmon chạy được)."""
    T = [r for r in theo_kt if r["trong_T"]]
    kq["so_cap"], kq["doi_dau"] = {}, {}
    for x, y in cap:
        p = sum(1 for r in T if r[f"bat_{x}"] and not r[f"bat_{y}"])
        q = sum(1 for r in T if r[f"bat_{y}"] and not r[f"bat_{x}"])
        kq["so_cap"][f"{x}_vs_{y}"] = {"chi_thu_nhat": p, "chi_thu_hai": q, "p": mcnemar_exact(p, q)}
        dd = [r for r in T if (x, r["ky_thuat"]) in phu and (y, r["ky_thuat"]) in phu]
        kq["doi_dau"][f"{x}_vs_{y}"] = {"so_ky_thuat": len(dd),
                                        "chi_thu_nhat": sum(1 for r in dd if r[f"bat_{x}"] and not r[f"bat_{y}"]),
                                        "chi_thu_hai": sum(1 for r in dd if r[f"bat_{y}"] and not r[f"bat_{x}"]),
                                        "ca_hai": sum(1 for r in dd if r[f"bat_{x}"] and r[f"bat_{y}"]),
                                        "ky_thuat": [r["ky_thuat"] for r in dd]}


def ghi(out: Path, kq: dict, theo_kt: list[dict], theo_hunt: list[dict]) -> None:
    (out / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
    for ten, rows in (("theo_ky_thuat.csv", theo_kt), ("theo_hunt.csv", theo_hunt)):
        with open(out / ten, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["trong"])
            w.writeheader()
            w.writerows(rows)
    print(f"phạm vi {kq['so_bo_L1']} bộ · T = {kq['so_ky_thuat_T']} kỹ thuật · A = {kq['so_su_kien_A']} sự kiện"
          f" · hunt lỗi {kq['so_hunt_loi']} · {kq['thoi_gian_giay']} giây")
    for ten, v in kq["cach"].items():
        print(f"  {ten:28s} hunt {v['so_hunt']:5d} · phủ {v['do_phu']:3d} · bắt {v['bat_duoc']}/{v['tren']} · báo nhầm "
              f"{v['bao_nham']} · precision {v['precision']} · FPR lớn nhất {v['fpr_theo_hunt']['lon_nhat']}")
    for k, v in kq["so_cap"].items():
        print(f"  {k}: chỉ thứ nhất {v['chi_thu_nhat']} / chỉ thứ hai {v['chi_thu_hai']} · p = {v['p']:.3g}")


def tap_con(a) -> int:
    t0 = time.monotonic()
    con, columns, bo_kt, goc_hh, dm, l1, out, dau_vao = mo_chung(a)
    S = set(json.loads(Path(a.tap).read_text(encoding="utf-8"))[a.khoa])
    if S - set(goc_hh):
        raise SystemExit(f"tập con có mã không có bộ nào: {sorted(S - set(goc_hh))[:5]}")
    goc_S = {k: v for k, v in goc_hh.items() if k in S}
    cao, moi, _ = hc.specs_sigmahq(goc_S, columns, a.sigmahq, dm)
    cach = {"sigmahq_cao": cao, "sigmahq_moi_muc": moi}
    if a.doi_chung_toan_bo:
        tb, _ = hc.specs_toan_bo(columns, a.sigmahq, dm)
        cach[hc.TOAN_BO] = {k: tb for k in sorted(S)}
    he_ten, dau_vao["he_thong"] = [], {}
    for muc in a.he_thong or []:
        ten, thu_muc = muc.split("=", 1)
        by = {k: [{**s, "id": f"{ten}__{s['id']}"} for s in v] for k, v in hc.specs_he_thong(Path(thu_muc)).items()
              if k in S}
        dau_vao["he_thong"][ten] = {"thu_muc": thu_muc, "hunt": {
            str(p.relative_to(Path(thu_muc))).replace("\\", "/"): hc.sha_tep(p)
            for p in sorted(Path(thu_muc).glob("ky_thuat/*/hunts/*.yaml")) if p.parent.parent.name in S}}
        specs = [s for v in by.values() for s in v]
        rong = _breadth(con, specs) if specs else {}
        cach[f"he_{ten}"] = by
        cach[f"he_{ten}_bo_rong"] = {k: [s for s in v if s["id"] not in rong] for k, v in by.items()}
        cach[f"lai_{ten}"] = {k: cao.get(k, []) + by.get(k, []) for k in sorted(S)}
        dau_vao["he_thong"][ten]["hunt_bi_danh_dau_rong"] = sorted(rong)
        he_ten.append(ten)
    unique = {s["id"]: s for by in cach.values() for specs in by.values() for s in specs}
    moi_chay = hc.chay_hunts(con, list(unique.values()))
    hc.nap_nhan(con, Path(a.nhan), False)
    bo_kt_S = {b: [k for k in ks if k in S] for b, ks in bo_kt.items() if any(k in S for k in ks)}
    kq = hc.cham(con, cach, bo_kt_S, l1, goc_hh, False)
    theo_hunt, theo_kt = kq.pop("_theo_hunt"), kq.pop("_theo_ky_thuat")
    cap = [(f"he_{t}", "sigmahq_cao") for t in he_ten] + [(f"lai_{t}", "sigmahq_cao") for t in he_ten]
    cap += [(f"he_{x}", f"he_{y}") for x, y in itertools.combinations(he_ten, 2)]
    so_cap_va_doi_dau(kq, theo_kt, cap, phu_sysmon(con, cach))
    khop = dict(con.execute("SELECT hunt, count(*) FROM khop GROUP BY 1").fetchall())
    kq["hunt_khop_0_o_moi_bo"] = {t: {"so_hunt": len({s["id"] for v in cach[f"he_{t}"].values() for s in v}),
                                      "khop_0": sum(1 for h in {s["id"] for v in cach[f"he_{t}"].values() for s in v}
                                                    if not khop.get(h))} for t in he_ten}
    loi = dict(con.execute("SELECT hunt, loi FROM hunt_info WHERE loi IS NOT NULL").fetchall())
    kq = {"giao_thuc": "docs/METHODOLOGY.md", "tap_con": sorted(S), "dau_vao": dau_vao,
          "so_hunt_chay_moi": moi_chay, "so_hunt_loi": len({h for h in loi if h in unique}), **kq,
          "thoi_gian_giay": round(time.monotonic() - t0, 1)}
    ghi(out, kq, theo_kt, theo_hunt)
    con.close()
    return 0


def cha_con(a) -> int:
    t0 = time.monotonic()
    con, columns, bo_kt, goc_hh, dm, l1, out, dau_vao = mo_chung(a)
    cach, so_rule = {}, {}
    for kieu in KIEU:
        cao, moi, _ = specs_theo_kieu(goc_hh, columns, a.sigmahq, dm, kieu)
        cach[f"sigmahq_cao_{kieu}"], cach[f"sigmahq_moi_muc_{kieu}"] = cao, moi
        so_rule[kieu] = {"cao": len({s["nguon_rule"]["sigmahq"] for v in cao.values() for s in v}),
                         "moi_muc": len({s["nguon_rule"]["sigmahq"] for v in moi.values() for s in v})}
    if a.doi_chung_toan_bo:
        tb, _ = hc.specs_toan_bo(columns, a.sigmahq, dm)
        cach[hc.TOAN_BO] = {k: tb for k in goc_hh}
    unique = {s["id"]: s for by in cach.values() for specs in by.values() for s in specs}
    moi_chay = hc.chay_hunts(con, list(unique.values()))
    hc.nap_nhan(con, Path(a.nhan), False)
    kq = hc.cham(con, cach, bo_kt, l1, goc_hh, False)
    theo_hunt, theo_kt = kq.pop("_theo_hunt"), kq.pop("_theo_ky_thuat")
    cap = [(f"sigmahq_{m}_{k}", f"sigmahq_{m}_chinh_xac") for m in ("cao", "moi_muc") for k in KIEU[1:]]
    so_cap_va_doi_dau(kq, theo_kt, cap, phu_sysmon(con, cach))
    T = [r for r in theo_kt if r["trong_T"]]
    kq["ky_thuat_them_so_voi_chinh_xac"] = {
        f"{m}_{k}": sorted(r["ky_thuat"] for r in T if r[f"bat_sigmahq_{m}_{k}"] and not r[f"bat_sigmahq_{m}_chinh_xac"])
        for m in ("cao", "moi_muc") for k in KIEU[1:]}
    loi = dict(con.execute("SELECT hunt, loi FROM hunt_info WHERE loi IS NOT NULL").fetchall())
    kq = {"giao_thuc": "docs/METHODOLOGY.md", "trong_mau": True, "dau_vao": dau_vao,
          "so_rule_duoc_chon": so_rule, "so_hunt_chay_moi": moi_chay, "so_hunt_loi": len({h for h in loi if h in unique}),
          **kq, "thoi_gian_giay": round(time.monotonic() - t0, 1)}
    ghi(out, kq, theo_kt, theo_hunt)
    con.close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    for ten in ("tap-con", "cha-con"):
        p = sub.add_parser(ten)
        p.add_argument("--parquet", required=True)
        p.add_argument("--nhan", required=True)
        p.add_argument("--pham-vi", required=True)
        p.add_argument("--sha-nhan")
        p.add_argument("--sha-pham-vi")
        p.add_argument("--bo-loai")
        p.add_argument("--bo-sung-danh-muc")
        p.add_argument("--doi-chung-toan-bo", action="store_true")
        p.add_argument("--sigmahq", default=community_rules.SIGMAHQ)
        p.add_argument("--db", required=True)
        p.add_argument("--out", required=True)
    p = sub.choices["tap-con"]
    p.add_argument("--tap", required=True, help="JSON chứa danh sách mã kỹ thuật gốc")
    p.add_argument("--khoa", required=True, help="khóa của danh sách trong tệp --tap (vd ky_thuat_xong, mau)")
    p.add_argument("--he-thong", action="append", help="ten=thư mục lượt sinh rule (có ky_thuat/*/hunts/*.yaml)")
    a = ap.parse_args(argv)
    return tap_con(a) if a.lenh == "tap-con" else cha_con(a)


if __name__ == "__main__":
    raise SystemExit(main())
