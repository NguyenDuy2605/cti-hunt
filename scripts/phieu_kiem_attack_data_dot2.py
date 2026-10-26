"""Phiếu kiểm mù đợt 2 cho nhãn attack_data v2, theo giao thức đặt trước `docs/METHODOLOGY.md`.

Không gọi API, không chạy rule. Lấy 40 sự kiện theo 7 nhóm (v2 tấn công; v1 tấn công thành v2 lọc F4; v1 lọc F1 thành v2 tấn
công; F3; F2; v2 vẫn lọc F1; ngoài cây), bỏ các sự kiện đã có ở phiếu đợt 1. So với đợt 1, mỗi mục hiện thêm tiến trình con của
tiến trình gây ra sự kiện và mô tả tệp log của Splunk. Tên tệp phiếu và đáp án giống đợt 1, nên chấm bằng
``nhan_attack_data.py cham --out <thư mục phiếu đợt 2>``.

    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_attack_data_dot2.py ^
        --parquet ../workspace/tu_pc_17-10/attack_data_16-10/parquet ^
        --nhan-v1 ../workspace/nhan_attack_data_18-10 --nhan-v2 ../workspace/nhan_attack_data_v2_18-10 ^
        --phieu-dot1 ../workspace/nhan_attack_data_18-10/phieu_kiem ^
        --out ../workspace/nhan_attack_data_v2_18-10/phieu_kiem_dot2
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import nhan_attack_data as N  # noqa: E402
from phieu_kiem_nhan_otrf_dot2 import META, decoded_features, short, when  # noqa: E402

from cti_hunt import config  # noqa: E402

GIAO_THUC = "docs/METHODOLOGY.md"
SEED = 20261019
DANH_SACH = "eval/inputs/attack_data_danh_sach_aafa53e.json"
# (mã nhóm, số mục, nhãn v2). Nhóm A chia đều Sysmon 1 / Sysmon khác (giao thức §3).
NHOM = (("A_tan_cong", 12, "tan_cong"), ("B_f4_doi", 8, "binh_thuong"), ("C_f1_tra_lai", 6, "tan_cong"),
        ("D_f3", 4, "binh_thuong"), ("E_f2", 2, "binh_thuong"), ("F_f1_v2", 4, "binh_thuong"),
        ("G_ngoai_cay", 4, "binh_thuong"))
MAX_CON = 6


def nhom_cua(a1, l1, trong2, l2, a2, trong_cua_so: bool) -> str | None:
    """Nhóm của một sự kiện theo trạng thái tiến trình gây ra ở v1 (a1, l1) và v2 (trong2, l2, a2)."""
    if a2:
        return "C_f1_tra_lai" if l1 == "F1" else "A_tan_cong"
    if l2 == "F4":
        return "B_f4_doi" if a1 else None
    if l2 == "F3":
        return "D_f3"
    if l2 == "F2":
        return "E_f2"
    if l2 == "F1":
        return "F_f1_v2"
    if not trong2 and trong_cua_so:
        return "G_ngoai_cay"
    return None


HEAD = N.HEAD + """# Đợt 2 thêm: con_cua_tien_trinh: các tiến trình con của tiến trình gây ra sự kiện (với sự kiện 1 là con của chính tiến trình
#   được tạo), tối đa 6, kèm tổng số con. mo_ta_bo: mô tả tệp log do Splunk ghi kèm bộ dữ liệu.
"""


def _con(children: dict, g: str) -> dict:
    kids = children.get(g, [])
    out = []
    for p in kids[:MAX_CON]:
        e = {"Image": short(p["Image"], 300), "CommandLine": short(p["CommandLine"], 300), "thoi_diem": when(p["ev_ts"])}
        feats = decoded_features({"CommandLine": p["CommandLine"]})
        if feats:
            e["lenh_ma_hoa_da_giai_ma"] = feats[:2]
        out.append(e)
    return {"tong_so_con": len(kids), "con": out}


def tao(parquet: Path, nhan_v1: Path, nhan_v2: Path, phieu_dot1: Path, out: Path, danh_sach: Path) -> dict:
    con, _ = N.mo(parquet)
    for t, d in (("t1", nhan_v1), ("t2", nhan_v2)):
        con.execute(f"CREATE TABLE {t} AS SELECT * FROM read_parquet('{(d / 'tien_trinh_L1.parquet').as_posix()}')")
    rows = con.execute(f"""SELECT e.bo, e.ev_host, e.ev_channel, CAST(e.ev_rec AS BIGINT), e.ev_eid, e.ev_ts,
        t1.tan_cong, t1.ly_do_loc, t2.trong_cay, t2.ly_do_loc, t2.tan_cong
        FROM ev e LEFT JOIN t1 ON t1.bo = e.bo AND t1.ev_host = e.ev_host AND t1.g = {N.guid_sql('e')}
        LEFT JOIN t2 ON t2.bo = e.bo AND t2.ev_host = e.ev_host AND t2.g = {N.guid_sql('e')}
        WHERE e.ev_channel = '{N.SYSMON}' AND e.bo IN (SELECT DISTINCT bo FROM t2)""").fetchall()
    da_co = {tuple(v["khoa"]) for v in json.loads((phieu_dot1 / "dap_an_khong_mo.json").read_text(encoding="utf-8")).values()}
    cua_so = {}
    for b, h, ch, rec, eid, ts, a1, l1, trong2, l2, a2 in rows:
        if a2 and ts is not None:
            lo, hi = cua_so.get((b, h), (ts, ts))
            cua_so[(b, h)] = (min(lo, ts), max(hi, ts))
    pools = collections.defaultdict(lambda: collections.defaultdict(list))
    tang_cua = {}
    for b, h, ch, rec, eid, ts, a1, l1, trong2, l2, a2 in sorted(rows, key=lambda r: (r[0], r[1], r[3])):
        if (b, h, ch, rec) in da_co:
            continue
        w = cua_so.get((b, h))
        trong_w = bool(w and ts is not None and w[0] - N.CUA_SO <= ts <= w[1] + N.CUA_SO)
        nhom = nhom_cua(a1, l1, trong2, l2, a2, trong_w)
        if not nhom:
            continue
        tang = N.TANG[0] if eid == 1 else N.TANG[1]
        k = f"{nhom}|{tang}" if nhom == "A_tan_cong" else nhom
        pools[k][b].append((b, h, ch, rec))
        tang_cua[(b, h, ch, rec)] = tang
    quota = {}
    for nhom, so, _ in NHOM:
        if nhom == "A_tan_cong":
            quota[f"{nhom}|{N.TANG[0]}"] = quota[f"{nhom}|{N.TANG[1]}"] = so // 2
        else:
            quota[nhom] = so
    rnd = random.Random(SEED)
    picked = [(k.split("|")[0], item) for k, b, item in N.chon(pools, quota, rnd)]
    rnd.shuffle(picked)
    key = ghi_phieu(con, parquet, picked, {n: nh for n, _, nh in NHOM}, tang_cua, out, danh_sach, "N", HEAD)
    dem = collections.Counter(v["nhom"] for v in key.values())
    co_san = {k: sum(len(v) for v in pools[k].values()) for k in quota}
    return {"giao_thuc": GIAO_THUC, "so_muc": len(key), "theo_nhom": dict(sorted(dem.items())),
            "so_su_kien_co_the_lay": co_san, "so_bo": len({v["bo"] for v in key.values()})}


def ghi_phieu(con, parquet: Path, picked, nhan_cua: dict, tang_cua: dict, out: Path, danh_sach: Path, tien_to: str,
              head: str) -> dict:
    """Dựng bằng chứng cho các sự kiện đã chọn và ghi phiếu + đáp án (dùng chung cho đợt 2, đợt 3). ``con`` cần bảng ``t2``
    (tiến trình của các bộ được lấy mẫu); ``picked``: [(nhóm, (bo, máy, kênh, số bản ghi))] đã trộn."""
    by_guid, children = {}, {}
    for r in con.execute(f"""SELECT bo, ev_host, lower(ProcessGuid), lower(coalesce(ParentProcessGuid, '')), Image, CommandLine, ev_ts
                             FROM ev WHERE ev_channel = '{N.SYSMON}' AND ev_eid = 1 AND bo IN (SELECT DISTINCT bo FROM t2)
                             ORDER BY ev_ts""").fetchall():
        p = {"pg": r[3], "Image": r[4], "CommandLine": r[5], "ev_ts": r[6]}
        by_guid.setdefault((r[0], r[1]), {})[r[2]] = p
        children.setdefault((r[0], r[1]), {}).setdefault(r[3], []).append(p)
    _, bo_tep = N.doc_bo(parquet)
    mo_ta = {t["duong_dan"]: t.get("mo_ta", "") for t in json.loads(danh_sach.read_text(encoding="utf-8"))["tep"]}
    items, key = [], {}
    for i, (nhom, (b, h, ch, rec)) in enumerate(picked, 1):
        iid = f"{tien_to}{i:02d}"
        cur = con.execute("SELECT * FROM ev WHERE bo = ? AND ev_host = ? AND ev_channel = ? AND CAST(ev_rec AS BIGINT) = ?",
                          [b, h, ch, rec])
        names = [c[0] for c in cur.description]
        row = dict(zip(names, cur.fetchone()))
        low = {k.lower(): v for k, v in row.items()}
        truong = {k: short(v, 300) for k, v in row.items()
                  if v not in (None, "") and not k.startswith("ev_") and k not in META and k != "bo"}
        item = {"id": iid, "bo_log": b, "mo_ta_bo": mo_ta.get(bo_tep.get(b, ""), ""), "may": h, "kenh": ch,
                "eid": row["ev_eid"], "thoi_diem": when(row["ev_ts"]), "truong": truong}
        bg, kids = by_guid.get((b, h), {}), children.get((b, h), {})
        if row["ev_eid"] == 1:
            item["chuoi_tien_trinh_cha"] = N._chuoi(bg, (low.get("parentprocessguid") or "").lower(), 3)
            g = (low.get("processguid") or "").lower()
        else:
            g = ((low.get("sourceprocessguid") if row["ev_eid"] in (8, 10) else low.get("processguid")) or "").lower()
            item["chuoi_tien_trinh_gay_ra"] = N._chuoi(bg, g, 3)
        item["con_cua_tien_trinh"] = _con(kids, g)
        feats = decoded_features(row)
        if feats:
            item["lenh_ma_hoa_da_giai_ma"] = feats[:3]
        item.update({"quyet_dinh": "", "ghi_chu": ""})
        items.append(item)
        key[iid] = {"bo": b, "tang": tang_cua[(b, h, ch, rec)], "nhan_script": nhan_cua[nhom], "nhom": nhom,
                    "khoa": [b, h, ch, rec]}
    out.mkdir(parents=True, exist_ok=True)
    (out / "phieu_kiem_nhan_attack_data.yaml").write_text(
        head + yaml.safe_dump({"nguoi_kiem": "", "su_kien": items}, allow_unicode=True, sort_keys=False, width=200),
        encoding="utf-8")
    (out / "dap_an_khong_mo.json").write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding="utf-8")
    return key


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for a in ("--parquet", "--nhan-v1", "--nhan-v2", "--phieu-dot1", "--out"):
        ap.add_argument(a, required=True)
    ap.add_argument("--danh-sach", default=DANH_SACH)
    a = ap.parse_args(argv)
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    r = tao(Path(a.parquet), Path(a.nhan_v1), Path(a.nhan_v2), Path(a.phieu_dot1), out, config.resolve(a.danh_sach))
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
