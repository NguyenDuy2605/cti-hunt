"""Phiếu kiểm mù đợt 3 cho nhãn attack_data v3, theo giao thức đặt trước `docs/METHODOLOGY.md` §3.

Không gọi API, không chạy rule. 20 sự kiện theo 5 nhóm:
- H: csc/cvtres biên dịch Add-Type mà v2 gắn tấn công, v3 lọc F5, ở bộ thuộc L1;
- I: csc/cvtres biên dịch Add-Type mà v3 vẫn gắn tấn công;
- J: tiến trình trong cây ở bộ bị đưa ra khỏi phạm vi L1;
- K: tấn công v3 ở bộ L1 chỉ có gốc R1;
- L: tấn công v3 ở bộ L1 có gốc R2 hoặc R3.
Bỏ mọi sự kiện đã có ở phiếu đợt 1, 2. Bằng chứng như đợt 2 (dùng chung ``phieu_kiem_attack_data_dot2.ghi_phieu``). Chấm bằng
``nhan_attack_data.py cham --out <thư mục phiếu đợt 3>``.

    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_attack_data_dot3.py ^
        --parquet ../workspace/tu_pc_17-10/attack_data_16-10/parquet ^
        --nhan-v2 ../workspace/nhan_attack_data_v2_18-10 --nhan-v3 ../workspace/nhan_attack_data_v3_18-10 ^
        --phieu ../workspace/nhan_attack_data_18-10/phieu_kiem ^
        --phieu ../workspace/nhan_attack_data_v2_18-10/phieu_kiem_dot2 ^
        --out ../workspace/nhan_attack_data_v3_18-10/phieu_kiem_dot3
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import nhan_attack_data as N  # noqa: E402
import phieu_kiem_attack_data_dot2 as D2  # noqa: E402

from cti_hunt import config  # noqa: E402

GIAO_THUC = "docs/METHODOLOGY.md"
SEED = 20261020
NHOM = (("H_bien_dich_loc", 6, "binh_thuong"), ("I_bien_dich_giu", 3, "tan_cong"), ("J_ngoai_pham_vi", 4, "binh_thuong"),
        ("K_winrm_tan_cong", 4, "tan_cong"), ("L_tan_cong_khac", 3, "tan_cong"))


def nhom_cua(la_bien_dich: bool, v2_tc, v3_trong, v3_ly, v3_tc, trong_l1: bool, ra_khoi: bool, goc: set) -> str | None:
    """Nhóm của một sự kiện. Bộ ra khỏi phạm vi xét trước (nhóm J gồm cả csc/cvtres ở đó), rồi mới tới H/I (giao thức §3)."""
    if ra_khoi:
        return "J_ngoai_pham_vi" if v3_trong else None
    if not trong_l1:
        return None
    if la_bien_dich:
        if v3_tc:
            return "I_bien_dich_giu"
        return "H_bien_dich_loc" if v2_tc and v3_ly == "F5" else None
    if v3_tc:
        if goc == {"R1"}:
            return "K_winrm_tan_cong"
        if goc & {"R2", "R3"}:
            return "L_tan_cong_khac"
    return None


def tao(parquet: Path, nhan_v2: Path, nhan_v3: Path, phieu_cu: list[Path], out: Path, danh_sach: Path) -> dict:
    con, _ = N.mo(parquet)
    for t, d in (("t2v", nhan_v2), ("t2", nhan_v3)):          # t2 = tiến trình v3 (ghi_phieu đọc bảng t2)
        con.execute(f"CREATE TABLE {t} AS SELECT * FROM read_parquet('{(d / 'tien_trinh_L1.parquet').as_posix()}')")
    pv = json.loads((nhan_v3 / "pham_vi_L1.json").read_text(encoding="utf-8"))
    trong_l1 = {x["bo"]: set(x["goc"]) for x in pv["bo"]}
    ra_khoi = {x["bo"] for x in pv.get("bo_ra_khoi_pham_vi", [])}
    con.execute(f"""CREATE TABLE pr AS SELECT bo, ev_host, lower(ProcessGuid) g, lower(coalesce(ParentProcessGuid, '')) pg, Image,
                   CommandLine FROM ev WHERE ev_channel = '{N.SYSMON}' AND ev_eid = 1""")
    rows = con.execute(f"""SELECT e.bo, e.ev_host, e.ev_channel, CAST(e.ev_rec AS BIGINT), e.ev_eid, p.Image, p.CommandLine,
        c.Image, c.CommandLine, v2.tan_cong, v3.trong_cay, v3.ly_do_loc, v3.tan_cong
        FROM ev e
        LEFT JOIN pr p ON p.bo = e.bo AND p.ev_host = e.ev_host AND p.g = {N.guid_sql('e')}
        LEFT JOIN pr c ON c.bo = p.bo AND c.ev_host = p.ev_host AND c.g = p.pg
        LEFT JOIN t2v v2 ON v2.bo = e.bo AND v2.ev_host = e.ev_host AND v2.g = {N.guid_sql('e')}
        LEFT JOIN t2 v3 ON v3.bo = e.bo AND v3.ev_host = e.ev_host AND v3.g = {N.guid_sql('e')}
        WHERE e.ev_channel = '{N.SYSMON}' AND e.bo IN (SELECT DISTINCT bo FROM t2)""").fetchall()
    da_co = {tuple(v["khoa"]) for d in phieu_cu
             for v in json.loads((d / "dap_an_khong_mo.json").read_text(encoding="utf-8")).values()}
    pools = collections.defaultdict(lambda: collections.defaultdict(list))
    tang_cua = {}
    for b, h, ch, rec, eid, img, cmd, pimg, pcmd, v2_tc, v3_trong, v3_ly, v3_tc in sorted(rows, key=lambda r: (r[0], r[1], r[3])):
        if (b, h, ch, rec) in da_co:
            continue
        bien_dich = N.la_csc_addtype(img, cmd) or (N.ten(img) == "cvtres.exe" and N.la_csc_addtype(pimg, pcmd))
        nhom = nhom_cua(bien_dich, v2_tc, v3_trong, v3_ly, v3_tc, b in trong_l1, b in ra_khoi, trong_l1.get(b, set()))
        if nhom:
            pools[nhom][b].append((b, h, ch, rec))
            tang_cua[(b, h, ch, rec)] = N.TANG[0] if eid == 1 else N.TANG[1]
    quota = {n: so for n, so, _ in NHOM}
    rnd = random.Random(SEED)
    picked = [(k, item) for k, b, item in N.chon(pools, quota, rnd)]
    rnd.shuffle(picked)
    key = D2.ghi_phieu(con, parquet, picked, {n: nh for n, _, nh in NHOM}, tang_cua, out, danh_sach, "O", D2.HEAD)
    dem = collections.Counter(v["nhom"] for v in key.values())
    return {"giao_thuc": GIAO_THUC, "so_muc": len(key), "theo_nhom": dict(sorted(dem.items())),
            "so_su_kien_co_the_lay": {k: sum(len(v) for v in pools[k].values()) for k in quota},
            "so_bo": len({v["bo"] for v in key.values()})}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for a in ("--parquet", "--nhan-v2", "--nhan-v3", "--out"):
        ap.add_argument(a, required=True)
    ap.add_argument("--phieu", action="append", required=True, help="thư mục phiếu đã dựng trước (lặp lại cho mỗi đợt)")
    ap.add_argument("--danh-sach", default=D2.DANH_SACH)
    a = ap.parse_args(argv)
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    r = tao(Path(a.parquet), Path(a.nhan_v2), Path(a.nhan_v3), [Path(p) for p in a.phieu], out, config.resolve(a.danh_sach))
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
