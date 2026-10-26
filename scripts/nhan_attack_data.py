"""Nhãn sự kiện cho Splunk attack_data theo giao thức đặt trước `docs/METHODOLOGY.md`.

Không gọi API, không đọc nhãn APT29, không đọc rule hay kết quả rule. Chỉ đọc log đã chuyển sang parquet.

- ``gan``: nhãn chính L1 (phương án B: lần theo tiến trình từ gốc bộ máy chạy bài thử R1–R3, lọc F1 mẫu dùng chung ≥ 5 thư mục
  kỹ thuật, F2 agent Splunk, F3 lệnh kiểm điều kiện của Invoke-AtomicTest cùng con cháu) và nền phổ biến L2 (cho phép đo phụ
  mức bộ dữ liệu). Ghi tệp nhãn, phạm vi, tóm tắt và ``CHOT_TRUOC_KHI_DO.sha256``.
- ``phieu``: phiếu kiểm mù 40 mục (giao thức §6), đáp án ở tệp riêng.
- ``cham``: chấm phiếu người vận hành đã điền.

    .venv/Scripts/python.exe -X utf8 scripts/nhan_attack_data.py gan ^
        --parquet ../workspace/tu_pc_17-10/attack_data_16-10/parquet --out ../workspace/nhan_attack_data_18-10
    .venv/Scripts/python.exe -X utf8 scripts/nhan_attack_data.py phieu --parquet <như trên> --nhan <thư mục gan> --out <thư mục phiếu>
    .venv/Scripts/python.exe -X utf8 scripts/nhan_attack_data.py cham --out <thư mục phiếu>
"""
from __future__ import annotations

import argparse
import base64
import collections
import csv
import datetime as dt
import glob
import hashlib
import json
import random
import re
import sys
from pathlib import Path

import duckdb
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from phieu_kiem_nhan_otrf_dot2 import META, decoded_features, short, when  # noqa: E402

from cti_hunt.eval.thong_ke import wilson  # noqa: E402

GIAO_THUC = "docs/METHODOLOGY.md"
SYSMON = "microsoft-windows-sysmon/operational"
DAU_ATOMIC = ("invoke-atomictest", "atomicredteam")
WINRM = ("winrshost.exe", "wsmprovhost.exe")
N_F1 = 5
F3_IF = re.compile(r"&\s*\{\s*if\s*\(")
F3_EXIT = re.compile(r"\{\s*exit\s+0\s*\}\s*else\s*\{\s*exit\s+1\s*\}")
# Lệnh PowerShell base64 sau -e, -ec, -en, -enc … -encodedcommand (nhãn v2, F4).
ENC = re.compile(r"-e(?:c|n\w*)?\s+([A-Za-z0-9+/=]{20,})", re.I)
SEED = 20261018
PER, PER_LOC = 10, 5                       # mỗi tầng: 10 tấn công; 10 không tấn công, trong đó 5 trong cây bị lọc
CUA_SO = dt.timedelta(minutes=5)
TANG = ("Sysmon 1 (tạo tiến trình)", "Sysmon khác")
# GUID tiến trình gây ra một sự kiện Sysmon: sự kiện 8, 10 dùng SourceProcessGuid, còn lại ProcessGuid (giao thức §3).
def guid_sql(t: str = "") -> str:
    p = f"{t}." if t else ""
    return f"lower(CASE WHEN {p}ev_eid IN (8, 10) THEN {p}SourceProcessGuid ELSE {p}ProcessGuid END)"


def ten(path) -> str:
    return (path or "").lower().replace("/", "\\").split("\\")[-1]


def chuan(cmd) -> str:
    s = (cmd or "").lower()
    s = re.sub(r"\{[0-9a-f-]{36}\}", "{guid}", s)
    s = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", s)
    s = re.sub(r"\d+", "<n>", s)
    s = re.sub(r"c:\\users\\[^\\]+", r"c:\\users\\<u>", s)
    return " ".join(s.split())[:200]


def la_f2(image, cmd) -> bool:
    i, c = (image or "").lower(), (cmd or "").lower()
    return "splunkuniversalforwarder" in i or "splunkuniversalforwarder" in c or ten(image) == "btool.exe" or "btool " in c


def la_f3(cmd) -> bool:
    s = " ".join((cmd or "").lower().split())
    return bool(F3_IF.search(s) and F3_EXIT.search(s))


def giai_ma(cmd) -> str:
    """Dòng lệnh chữ thường, nối thêm mọi lệnh PowerShell base64 (UTF-16LE) đi sau -e/-enc/-encodedcommand đã giải mã."""
    s = (cmd or "").lower()
    for b in ENC.findall(cmd or ""):
        try:
            s += " " + base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-16le", "ignore").lower()
        except ValueError:
            pass
    return s


def la_f4(cmd) -> bool:
    """Nhãn v2 (`17_…` §5): thao tác của khung Atomic — cài đặt, tải công cụ chuẩn bị, kiểm chuẩn bị, dọn dẹp."""
    s = giai_ma(cmd)
    if "install-atomicredteam" in s or "install-atomicsfolder" in s:
        return True
    return "invoke-atomictest" in s and any(f in s for f in ("-getprereqs", "-checkprereqs", "-cleanup"))


def la_f6(cmd) -> bool:
    """Nhãn v4 (`21_…` §6): lệnh của Ansible (thô hoặc base64 đã giải mã) — bộ máy điều khiển máy lab."""
    s = giai_ma(cmd)
    return any(m in s for m in ("ansible-tmp-", "exec_wrapper", "ansible"))


def la_csc_addtype(img, cmd) -> bool:
    """Nhãn v3 (`20_…` §2): csc.exe do Add-Type của PowerShell gọi để biên dịch C# (/noconfig … @….cmdline)."""
    c = (cmd or "").lower()
    return ten(img) == "csc.exe" and "/noconfig" in c and "@" in c and ".cmdline" in c


def khoa_mau(pimg, img, cmd, phien_ban: int = 1) -> tuple:
    """Khóa mẫu dùng chung F1: v1 (tên tệp Image, dòng lệnh); v2 thêm tên tệp tiến trình cha (`17_…` §5)."""
    return (ten(img), chuan(cmd)) if phien_ban == 1 else (ten(pimg), ten(img), chuan(cmd))


def mau_f1(rows, bo_kt: dict[str, tuple], n: int = N_F1, phien_ban: int = 1) -> set[tuple]:
    """Mẫu có ở >= n thư mục kỹ thuật khác nhau. ``rows``: (bo, Image, CommandLine) hoặc (bo, Image, CommandLine,
    ParentImage); v2 cần ParentImage."""
    kt = collections.defaultdict(set)
    for r in rows:
        b, img, cmd = r[:3]
        for t in bo_kt.get(b, ()):
            kt[khoa_mau(r[3] if len(r) > 3 else None, img, cmd, phien_ban)].add(t)
    return {k for k, v in kt.items() if len(v) >= n}


def gan_mot(procs: dict[str, dict], f1: set, phien_ban: int = 1) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """Một (bộ, máy). ``procs``: GUID -> {pg, img, pimg, cmd, pcmd} từ Sysmon 1 (GUID chữ thường).

    Trả về (gốc: GUID -> loại R1/R2/R3, tiến trình: GUID -> {trong_cay, ly_do_loc, tan_cong}) theo giao thức §3; v2 thêm F4
    và F1 có tiến trình cha (`17_…` §5)."""
    goc: dict[str, list[str]] = collections.defaultdict(list)
    for g, p in procs.items():
        if ten(p["pimg"]) in WINRM and p["pg"]:
            goc[p["pg"]].append("R1")
        if any(d in (p["cmd"] or "").lower() for d in DAU_ATOMIC):
            goc[g].append("R2")
        if p["pg"] and any(d in (p["pcmd"] or "").lower() for d in DAU_ATOMIC):
            goc[p["pg"]].append("R3")

    def to_tien(g):
        cur, seen = g, set()
        while cur and cur not in seen:
            yield cur
            seen.add(cur)
            cur = procs[cur]["pg"] if cur in procs else None

    f3 = {g for g, p in procs.items() if la_f3(p["cmd"])}
    f4 = {g for g, p in procs.items() if la_f4(p["cmd"])} if phien_ban >= 2 else set()
    out = {}
    for g, p in procs.items():
        chuoi = list(to_tien(g))
        trong = any(x in goc for x in chuoi)
        ly_do = None
        if trong:
            if any(x in f3 for x in chuoi):
                ly_do = "F3"
            elif any(x in f4 for x in chuoi):
                ly_do = "F4"
            elif la_f2(p["img"], p["cmd"]):
                ly_do = "F2"
            elif khoa_mau(p["pimg"], p["img"], p["cmd"], phien_ban) in f1:
                ly_do = "F1"
            elif phien_ban >= 4 and la_f6(p["cmd"]):
                ly_do = "F6"
        out[g] = {"trong_cay": trong, "ly_do_loc": ly_do, "tan_cong": trong and ly_do is None}
    if phien_ban >= 3:
        # F5: csc của Add-Type mang nhãn tiến trình gọi Add-Type (cha); cvtres mang nhãn cuối của csc cha.
        for g, p in procs.items():
            if la_csc_addtype(p["img"], p["cmd"]) and out[g]["tan_cong"] and not (out.get(p["pg"]) or {}).get("tan_cong"):
                out[g] = {**out[g], "ly_do_loc": "F5", "tan_cong": False}
        for g, p in procs.items():
            cha = procs.get(p["pg"])
            if (ten(p["img"]) == "cvtres.exe" and out[g]["tan_cong"] and cha and la_csc_addtype(cha["img"], cha["cmd"])
                    and not out[p["pg"]]["tan_cong"]):
                out[g] = {**out[g], "ly_do_loc": "F5", "tan_cong": False}
    return dict(goc), out


def doc_bo(parquet: Path) -> tuple[dict, dict]:
    tt = json.loads((parquet / "tom_tat_nap.json").read_text(encoding="utf-8"))
    bo_kt, bo_tep = {}, {}
    for path, r in tt.items():
        for b in r.get("bo_con") or ([r["ma_bo"]] if r.get("trang_thai") in ("ok", "mot_phan") else []):
            bo_kt[b], bo_tep[b] = tuple(r["ky_thuat"]), path
    return bo_kt, bo_tep


def mo(parquet: Path):
    files = sorted(glob.glob(str(parquet / "*" / "events.parquet")))
    lst = "[" + ", ".join("'" + f.replace("\\", "/").replace("'", "''") + "'" for f in files) + "]"
    con = duckdb.connect()
    con.execute("SET enable_progress_bar = false")
    con.execute(f"""CREATE TABLE ev AS SELECT * EXCLUDE (filename),
                   regexp_extract(replace(filename, '\\', '/'), '([^/]+)/events[.]parquet$', 1) AS bo
                   FROM read_parquet({lst}, union_by_name = true, filename = true)""")
    cols = {r[0].lower() for r in con.execute("DESCRIBE ev").fetchall()}
    for c in ("SourceProcessGuid", "ProcessGuid", "ParentProcessGuid", "ParentImage", "ParentCommandLine", "Image",
              "CommandLine", "NewProcessName", "ParentProcessName"):
        if c.lower() not in cols:
            con.execute(f"ALTER TABLE ev ADD COLUMN {c} VARCHAR")
    return con, len(files)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def gan(parquet: Path, out: Path, phien_ban: int = 1) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    bo_kt, bo_tep = doc_bo(parquet)
    con, n_files = mo(parquet)
    rows = con.execute(f"""SELECT bo, ev_host, lower(coalesce(ProcessGuid, '')), lower(coalesce(ParentProcessGuid, '')), Image,
                           ParentImage, CommandLine, ParentCommandLine FROM ev WHERE ev_channel = '{SYSMON}' AND ev_eid = 1""").fetchall()
    f1 = mau_f1([(r[0], r[4], r[6], r[5]) for r in rows], bo_kt, phien_ban=phien_ban)
    procs = collections.defaultdict(dict)
    for b, h, g, pg, img, pimg, cmd, pcmd in rows:
        if g:
            procs[(b, h)][g] = {"pg": pg, "img": img, "pimg": pimg, "cmd": cmd, "pcmd": pcmd}
    tien_trinh, goc_bo = [], collections.defaultdict(collections.Counter)
    bg_guid = []
    for (b, h), ps in procs.items():
        goc, kq = gan_mot(ps, f1, phien_ban)
        for x, loai in goc.items():
            for l in sorted(set(loai)):
                goc_bo[b][l] += 1
        for g, k in kq.items():
            tien_trinh.append((b, h, g, k["trong_cay"], k["ly_do_loc"], k["tan_cong"]))
            p = ps[g]
            if la_f2(p["img"], p["cmd"]) or khoa_mau(p["pimg"], p["img"], p["cmd"], phien_ban) in f1:
                bg_guid.append((b, h, g))
    co_goc = sorted(goc_bo)
    # v3 (`20_…` §2): bộ có gốc mà không còn tiến trình tấn công thì ra khỏi phạm vi L1. v1, v2: phạm vi = mọi bộ có gốc.
    co_tc = {b for b, h, g, trong, ly, tc in tien_trinh if tc}
    pham_vi = co_goc if phien_ban < 3 else [b for b in co_goc if b in co_tc]
    ra_khoi = [b for b in co_goc if b not in set(pham_vi)]

    def chen(sql, rows):          # DuckDB từ chối executemany với danh sách rỗng
        if rows:
            con.executemany(sql, rows)
    con.execute("CREATE TABLE tt (bo VARCHAR, ev_host VARCHAR, g VARCHAR, trong_cay BOOLEAN, ly_do_loc VARCHAR, tan_cong BOOLEAN)")
    chen("INSERT INTO tt VALUES (?, ?, ?, ?, ?, ?)", tien_trinh)
    con.execute("CREATE TABLE bg (bo VARCHAR, ev_host VARCHAR, g VARCHAR)")
    chen("INSERT INTO bg VALUES (?, ?, ?)", bg_guid)
    con.execute("CREATE TABLE pv (bo VARCHAR)")
    chen("INSERT INTO pv VALUES (?)", [(b,) for b in pham_vi])
    con.execute("CREATE TABLE cg (bo VARCHAR)")
    chen("INSERT INTO cg VALUES (?)", [(b,) for b in co_goc])
    # L1: sự kiện Sysmon trong bộ thuộc phạm vi, tiến trình gây ra là tiến trình tấn công.
    con.execute(f"""CREATE TABLE l1 AS SELECT e.bo, e.ev_host, e.ev_channel, CAST(e.ev_rec AS BIGINT) AS ev_rec FROM ev e
                    JOIN tt ON tt.bo = e.bo AND tt.ev_host = e.ev_host AND tt.g = {guid_sql('e')}
                    WHERE e.ev_channel = '{SYSMON}' AND tt.tan_cong AND e.bo IN (SELECT bo FROM pv)
                    ORDER BY 1, 2, 3, 4""")
    # L2: Sysmon theo GUID thuộc F1/F2; Security 4688 theo mẫu F1 hoặc F2.
    con.execute(f"""CREATE TABLE l2s AS SELECT e.bo, e.ev_host, e.ev_channel, CAST(e.ev_rec AS BIGINT) AS ev_rec FROM ev e
                    JOIN bg ON bg.bo = e.bo AND bg.ev_host = e.ev_host AND bg.g = {guid_sql('e')}
                    WHERE e.ev_channel = '{SYSMON}'""")
    sec = con.execute("""SELECT bo, ev_host, ev_channel, CAST(ev_rec AS BIGINT), NewProcessName, CommandLine, ParentProcessName
                         FROM ev WHERE ev_channel = 'security' AND ev_eid = 4688""").fetchall()
    sec_bg = [r[:4] for r in sec if la_f2(r[4], r[5]) or khoa_mau(r[6], r[4], r[5], phien_ban) in f1]
    chen("INSERT INTO l2s VALUES (?, ?, ?, ?)", sec_bg)
    con.execute("CREATE TABLE l2 AS SELECT DISTINCT * FROM l2s ORDER BY 1, 2, 3, 4")
    for name, table in (("nhan_tan_cong_L1.parquet", "l1"), ("nen_pho_bien_L2.parquet", "l2"),
                        # Mọi bộ có gốc (v1, v2: trùng phạm vi L1; v3 gồm cả bộ ra khỏi phạm vi, để tra lại).
                        ("tien_trinh_L1.parquet", "(SELECT * FROM tt WHERE bo IN (SELECT bo FROM cg) ORDER BY 1, 2, 3)")):
        con.execute(f"COPY {table} TO '{(out / name).as_posix()}' (FORMAT PARQUET)")
    with open(out / "mau_F1.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["image", "dong_lenh_chuan_hoa"] if phien_ban == 1 else ["parent_image", "image", "dong_lenh_chuan_hoa"])
        w.writerows(sorted(f1))

    dem_sysmon = dict(con.execute(f"SELECT bo, count(*) FROM ev WHERE ev_channel = '{SYSMON}' GROUP BY bo").fetchall())
    dem_l1 = dict(con.execute("SELECT bo, count(*) FROM l1 GROUP BY bo").fetchall())
    tt_bo = collections.defaultdict(collections.Counter)
    for b, h, g, trong, ly_do, tc in tien_trinh:
        if trong:
            tt_bo[b]["trong_cay"] += 1
            tt_bo[b]["tan_cong" if tc else f"loc_{ly_do}"] += 1
    bo_info = [{"bo": b, "tep": bo_tep.get(b), "ky_thuat": list(bo_kt.get(b, ())), "su_kien_sysmon": dem_sysmon.get(b, 0),
                # Khóa sắp thứ tự: thứ tự duyệt set đổi giữa các lần chạy (18/10, pham_vi_L1.json v1 khác thứ tự khóa ở 9 bộ).
                "su_kien_tan_cong": dem_l1.get(b, 0), "goc": dict(sorted(goc_bo[b].items())),
                "tien_trinh": dict(sorted(tt_bo[b].items()))}
               for b in pham_vi]
    ky_thuat = sorted({t for x in bo_info if x["su_kien_tan_cong"] for t in x["ky_thuat"]})
    pv_json = {"so_bo": len(bo_info), "ky_thuat_co_su_kien_tan_cong": ky_thuat, "bo": bo_info}
    if phien_ban >= 3:
        pv_json["bo_ra_khoi_pham_vi"] = [{"bo": b, "tep": bo_tep.get(b), "ky_thuat": list(bo_kt.get(b, ())),
                                          "goc": dict(sorted(goc_bo[b].items())), "tien_trinh": dict(sorted(tt_bo[b].items()))}
                                         for b in ra_khoi]
    (out / "pham_vi_L1.json").write_text(json.dumps(pv_json, ensure_ascii=False, indent=1), encoding="utf-8")
    tong = {"so_bo_nap": n_files, "so_ky_thuat_co_bo": len({t for v in bo_kt.values() for t in v}),
            "sysmon_1": len(rows), "mau_F1": len(f1), "bo_pham_vi_L1": len(pham_vi),
            "bo_L1_co_su_kien_tan_cong": sum(1 for x in bo_info if x["su_kien_tan_cong"]),
            "ky_thuat_L1": len(ky_thuat),
            "tien_trinh_trong_cay": sum(x["tien_trinh"].get("trong_cay", 0) for x in bo_info),
            "tien_trinh_tan_cong": sum(x["tien_trinh"].get("tan_cong", 0) for x in bo_info),
            "tien_trinh_loc": {k: sum(x["tien_trinh"].get(f"loc_{k}", 0) for x in bo_info)
                               for k in ("F1", "F2", "F3", "F4", "F5", "F6")[:{1: 3, 2: 4, 3: 5}.get(phien_ban, 6)]},
            "su_kien_sysmon_L1": sum(x["su_kien_sysmon"] for x in bo_info),
            "su_kien_tan_cong_L1": con.execute("SELECT count(*) FROM l1").fetchone()[0],
            "su_kien_nen_pho_bien_L2": con.execute("SELECT count(*) FROM l2").fetchone()[0],
            "trong_do_security_4688": len({tuple(r) for r in sec_bg})}
    tham_so = {"N_F1": N_F1, "dau_atomic": DAU_ATOMIC, "winrm": WINRM, "f3": [F3_IF.pattern, F3_EXIT.pattern]}
    if phien_ban >= 2:   # v1 giữ đúng khóa cũ để dựng lại được tom_tat.json như bản đã chốt (trừ SHA256 script)
        tham_so.update(phien_ban=phien_ban, quy_tac_v2="docs/METHODOLOGY.md",
                       f1_khoa="(tên tệp ParentImage, tên tệp Image, dòng lệnh chuẩn hóa)", f4_enc=ENC.pattern)
    if phien_ban >= 3:
        tham_so.update(quy_tac_v3="docs/METHODOLOGY.md",
                       f5="csc.exe có /noconfig, @, .cmdline và cvtres.exe con của nó mang nhãn tiến trình cha",
                       pham_vi="bộ có gốc và còn ít nhất một tiến trình tấn công sau mọi bước lọc")
        tong.update(bo_ra_khoi_pham_vi=len(ra_khoi), ky_thuat_ra_khoi=sorted(
            {t for b in ra_khoi for t in bo_kt.get(b, ())} - set(ky_thuat)))
    if phien_ban >= 4:
        tham_so.update(quy_tac_v4="docs/METHODOLOGY.md",
                       f6="lệnh thô hoặc base64 đã giải mã chứa ansible-tmp-, exec_wrapper hoặc ansible; chỉ lọc tiến trình đó")
    meta = {"giao_thuc": GIAO_THUC, "tham_so": tham_so,
            "sha256": {"script": sha(Path(__file__)), "tom_tat_nap.json": sha(parquet / "tom_tat_nap.json")},
            "so_dem": tong}
    (out / "tom_tat.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    tep = ["nhan_tan_cong_L1.parquet", "nen_pho_bien_L2.parquet", "tien_trinh_L1.parquet", "pham_vi_L1.json", "mau_F1.csv",
           "tom_tat.json"]
    (out / "CHOT_TRUOC_KHI_DO.sha256").write_text("".join(f"{sha(out / t)}  {t}\n" for t in tep), encoding="utf-8")
    return meta


# ---------- Phiếu kiểm mù (giao thức §6) ----------

HEAD = """# Phiếu kiểm mù nhãn Splunk attack_data. Mỗi bộ là một tệp log do Splunk ghi khi chạy thử một kỹ thuật ATT&CK; tên bộ
# có dạng ad.<kỹ thuật>.<công cụ hoặc thư mục>.<tên tệp>. Trong log có cả hoạt động nền của máy, của agent thu log, và của bộ
# máy điều khiển bài thử (WinRM, PowerShell của Atomic Red Team, lệnh kiểm điều kiện trước bài thử).
# Với mỗi sự kiện: quyet_dinh = tan_cong (do chính bài thử kỹ thuật gây ra) | binh_thuong (nền, agent, hoặc bộ máy điều khiển)
#   | khong_chac. Không chắc thì ghi khong_chac.
# Bằng chứng: chuoi_tien_trinh_*: tiến trình gây ra sự kiện rồi cha, ông (từ Sysmon 1, theo GUID). lenh_ma_hoa_da_giai_ma:
#   lệnh PowerShell base64 đã giải mã; chỉ ghi độ dài, địa chỉ mạng và các chuỗi kỹ thuật có mặt.
"""


def _chuoi(by_guid: dict, start: str | None, depth: int) -> list[dict]:
    out, cur, seen = [], start, set()
    while cur and cur not in seen and len(out) < depth:
        seen.add(cur)
        p = by_guid.get(cur)
        if not p:
            out.append({"guid": cur, "ghi_chu": "không có sự kiện tạo tiến trình trong bộ (chạy từ trước lúc ghi)"})
            break
        e = {"Image": short(p["Image"], 300), "CommandLine": short(p["CommandLine"], 300), "thoi_diem": when(p["ev_ts"])}
        feats = decoded_features({"CommandLine": p["CommandLine"]})
        if feats:
            e["lenh_ma_hoa_da_giai_ma"] = feats[:2]
        out.append(e)
        cur = p["pg"]
    return out


def chon(pools: dict[str, dict[str, list]], quota: dict[str, int], rnd: random.Random) -> list[tuple[str, str, object]]:
    """Lấy xoay vòng qua các bộ cho từng nhóm theo hạn mức. ``pools``: nhóm -> bộ -> danh sách mục."""
    picked = []
    for nhom, k in quota.items():
        by_bo = {b: list(v) for b, v in pools.get(nhom, {}).items() if v}
        order = sorted(by_bo)
        rnd.shuffle(order)
        got = 0
        while got < k and any(by_bo[b] for b in order):
            for b in order:
                if got >= k or not by_bo[b]:
                    continue
                picked.append((nhom, b, by_bo[b].pop(rnd.randrange(len(by_bo[b])))))
                got += 1
    return picked


def phieu(parquet: Path, nhan: Path, out: Path) -> dict:
    con, _ = mo(parquet)
    for t, f in (("l1", "nhan_tan_cong_L1.parquet"), ("tt", "tien_trinh_L1.parquet")):
        con.execute(f"CREATE TABLE {t} AS SELECT * FROM read_parquet('{(nhan / f).as_posix()}')")
    rows = con.execute(f"""SELECT e.bo, e.ev_host, e.ev_channel, CAST(e.ev_rec AS BIGINT), e.ev_eid, e.ev_ts, {guid_sql('e')} AS g,
        (l1.bo IS NOT NULL) AS la_tc, tt.trong_cay, tt.ly_do_loc
        FROM ev e LEFT JOIN l1 ON l1.bo = e.bo AND l1.ev_host = e.ev_host AND l1.ev_channel = e.ev_channel
             AND l1.ev_rec = CAST(e.ev_rec AS BIGINT)
        LEFT JOIN tt ON tt.bo = e.bo AND tt.ev_host = e.ev_host AND tt.g = {guid_sql('e')}
        WHERE e.ev_channel = '{SYSMON}' AND e.bo IN (SELECT DISTINCT bo FROM tt)""").fetchall()
    cua_so = {}
    for b, h, ch, rec, eid, ts, g, tc, trong, ly in rows:
        if tc and ts is not None:
            k = (b, h, eid == 1)
            lo, hi = cua_so.get(k, (ts, ts))
            cua_so[k] = (min(lo, ts), max(hi, ts))
    pools = {tang: collections.defaultdict(lambda: collections.defaultdict(list)) for tang in TANG}
    for b, h, ch, rec, eid, ts, g, tc, trong, ly in sorted(rows, key=lambda r: (r[0], r[1], r[3])):
        tang = TANG[0] if eid == 1 else TANG[1]
        if tc:
            pools[tang]["tan_cong"][b].append((b, h, ch, rec))
            continue
        w = cua_so.get((b, h, eid == 1))
        if not w or ts is None or not (w[0] - CUA_SO <= ts <= w[1] + CUA_SO):
            continue
        nhom = f"loc_{ly}" if trong and ly else "ngoai_cay"
        pools[tang]["loc" if nhom.startswith("loc_") else "ngoai_cay"][b].append((b, h, ch, rec, nhom))
    rnd = random.Random(SEED)
    picked = []
    for tang in TANG:
        p = pools[tang]
        n_loc = min(PER_LOC, sum(len(v) for v in p["loc"].values()))
        n_ngoai = min(PER - n_loc, sum(len(v) for v in p["ngoai_cay"].values()))
        n_loc = min(PER - n_ngoai, sum(len(v) for v in p["loc"].values()))
        for nhom, b, item in chon(p, {"tan_cong": PER, "loc": n_loc, "ngoai_cay": n_ngoai}, rnd):
            picked.append((tang, nhom if nhom == "tan_cong" else item[4], item[:4]))
    rnd.shuffle(picked)
    by_guid = {}
    for r in con.execute(f"""SELECT bo, ev_host, lower(ProcessGuid), lower(coalesce(ParentProcessGuid, '')), Image, CommandLine,
                             ev_ts FROM ev WHERE ev_channel = '{SYSMON}' AND ev_eid = 1 AND bo IN (SELECT DISTINCT bo FROM tt)""").fetchall():
        by_guid.setdefault((r[0], r[1]), {})[r[2]] = {"pg": r[3], "Image": r[4], "CommandLine": r[5], "ev_ts": r[6]}
    items, key = [], {}
    for i, (tang, nhom, (b, h, ch, rec)) in enumerate(picked, 1):
        iid = f"M{i:02d}"
        cur = con.execute("SELECT * FROM ev WHERE bo = ? AND ev_host = ? AND ev_channel = ? AND CAST(ev_rec AS BIGINT) = ?",
                          [b, h, ch, rec])
        names = [c[0] for c in cur.description]
        row = dict(zip(names, cur.fetchone()))
        truong = {k: short(v, 300) for k, v in row.items()
                  if v not in (None, "") and not k.startswith("ev_") and k not in META and k != "bo"}
        item = {"id": iid, "bo_log": b, "may": h, "kenh": ch, "eid": row["ev_eid"], "thoi_diem": when(row["ev_ts"]),
                "truong": truong}
        bg = by_guid.get((b, h), {})
        # Tên cột trong log không cùng kiểu chữ (Sysmon 10 ghi SourceProcessGUID); SQL không phân biệt, dict thì có.
        low = {k.lower(): v for k, v in row.items()}
        if row["ev_eid"] == 1:
            item["chuoi_tien_trinh_cha"] = _chuoi(bg, (low.get("parentprocessguid") or "").lower(), 3)
        else:
            g = (low.get("sourceprocessguid") if row["ev_eid"] in (8, 10) else low.get("processguid")) or ""
            item["chuoi_tien_trinh_gay_ra"] = _chuoi(bg, g.lower(), 3)
        feats = decoded_features(row)
        if feats:
            item["lenh_ma_hoa_da_giai_ma"] = feats[:3]
        item.update({"quyet_dinh": "", "ghi_chu": ""})
        items.append(item)
        key[iid] = {"bo": b, "tang": tang, "nhan_script": "tan_cong" if nhom == "tan_cong" else "binh_thuong",
                    "nhom": nhom, "khoa": [b, h, ch, rec]}
    out.mkdir(parents=True, exist_ok=True)
    (out / "phieu_kiem_nhan_attack_data.yaml").write_text(
        HEAD + yaml.safe_dump({"nguoi_kiem": "", "su_kien": items}, allow_unicode=True, sort_keys=False, width=200),
        encoding="utf-8")
    (out / "dap_an_khong_mo.json").write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding="utf-8")
    dem = collections.Counter((v["tang"], v["nhom"]) for v in key.values())
    return {"so_muc": len(items), "theo_tang_nhom": {f"{a} / {b}": n for (a, b), n in sorted(dem.items())},
            "so_bo": len({v["bo"] for v in key.values()})}


def nhan_lai(key: dict, nhan: Path) -> dict:
    """Đáp án của phiếu tính lại theo một bộ nhãn khác (vd v2): sự kiện có trong ``nhan_tan_cong_L1.parquet`` là tấn công;
    nhóm theo trạng thái tiến trình gây ra ở ``tien_trinh_L1.parquet`` của bộ nhãn đó. Không đổi tệp đáp án gốc."""
    con = duckdb.connect()
    tc = {tuple(r) for r in con.execute(f"""SELECT bo, ev_host, ev_channel, ev_rec
          FROM read_parquet('{(nhan / 'nhan_tan_cong_L1.parquet').as_posix()}')""").fetchall()}
    out = {}
    for iid, k in key.items():
        b, h, ch, rec = k["khoa"]
        moi = "tan_cong" if (b, h, ch, int(rec)) in tc else "binh_thuong"
        out[iid] = {**k, "nhan_script": moi, "nhan_script_goc": k["nhan_script"],
                    "nhom": k["nhom"] if moi == k["nhan_script"] else f"doi_tu_{k['nhan_script']}"}
    return out


def cham(out: Path, nhan: Path | None = None) -> dict:
    form = yaml.safe_load((out / "phieu_kiem_nhan_attack_data.yaml").read_text(encoding="utf-8"))
    key = json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    if nhan is not None:
        key = nhan_lai(key, nhan)
    done = [x for x in form["su_kien"] if x.get("quyet_dinh") in ("tan_cong", "binh_thuong", "khong_chac")]
    sure = [x for x in done if x["quyet_dinh"] != "khong_chac"]
    agree = sum(x["quyet_dinh"] == key[x["id"]]["nhan_script"] for x in sure)

    def split(group) -> dict:
        t: dict = {}
        for x in done:
            g = t.setdefault(group(x), {"quyet_duoc": 0, "khong_chac": 0, "khop": 0})
            if x["quyet_dinh"] == "khong_chac":
                g["khong_chac"] += 1
            else:
                g["quyet_duoc"] += 1
                g["khop"] += x["quyet_dinh"] == key[x["id"]]["nhan_script"]
        return dict(sorted(t.items()))
    res = {"nguoi_kiem": form.get("nguoi_kiem"), "tong_muc": len(form["su_kien"]), "da_cham": len(done),
           "khong_chac": len(done) - len(sure), "khop": agree, "tren": len(sure),
           "ty_le_khop": round(agree / len(sure), 4) if sure else None,
           "wilson95": wilson(agree, len(sure)) if sure else None,
           "theo_tang": split(lambda x: key[x["id"]]["tang"]),
           "theo_nhan_script": split(lambda x: key[x["id"]]["nhan_script"]),
           "theo_nhom": split(lambda x: key[x["id"]]["nhom"]),
           "lech": [{"id": x["id"], **key[x["id"]], "nguoi": x["quyet_dinh"], "ghi_chu": x.get("ghi_chu", "")}
                    for x in sure if x["quyet_dinh"] != key[x["id"]]["nhan_script"]]}
    res["dap_an_theo"] = "dap_an_khong_mo.json" if nhan is None else f"nhãn ở {nhan.as_posix()} (nhan_lai)"
    # Chấm theo bộ nhãn khác ghi tệp riêng, không ghi đè kết quả chấm theo đáp án gốc.
    ten_tep = "ket_qua_cham.json" if nhan is None else f"ket_qua_cham_theo_{nhan.name}.json"
    (out / ten_tep).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("viec", choices=("gan", "phieu", "cham"))
    ap.add_argument("--parquet")
    ap.add_argument("--nhan")
    ap.add_argument("--out", required=True)
    ap.add_argument("--phien-ban", type=int, choices=(1, 2, 3, 4), default=1,
                    help="gan: 1 = giao thức 16; 2 = thêm F1 có cha, F4 (`17_…` §5); 3 = thêm F5, điều kiện phạm vi (`20_…` §2); "
                         "4 = thêm F6 lệnh Ansible (`21_…` §6)")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    if a.viec == "gan":
        print(json.dumps(gan(Path(a.parquet), out, a.phien_ban)["so_dem"], ensure_ascii=False, indent=1))
    elif a.viec == "phieu":
        print(json.dumps(phieu(Path(a.parquet), Path(a.nhan), out), ensure_ascii=False, indent=1))
    else:
        r = cham(out, Path(a.nhan) if a.nhan else None)
        print(json.dumps({k: v for k, v in r.items() if k != "lech"}, ensure_ascii=False))
        for d in r["lech"]:
            print("  lệch:", d)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
