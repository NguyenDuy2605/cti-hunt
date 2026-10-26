"""Câu hỏi 2, hướng 2: chấm rule SigmaHQ và rule hệ thống sinh, theo từng kỹ thuật, trên mọi bộ Splunk attack_data đã nạp.

Giao thức: ``docs/METHODOLOGY.md`` (thiết kế gốc ``07``, ``09`` §4; nhãn ``16``, ``17``, ``19``,
``21``). Nhãn sự kiện tấn công là **đầu vào** (``--nhan``: tệp parquet có cột ``bo, ev_host, ev_channel, ev_rec``) do
``nhan_attack_data.py gan`` dựng; script này không tự gắn nhãn. ``--nhan-gia-lap`` chỉ để kiểm đường ống.

Hai pha, cùng một tệp DuckDB (``--db``):

1. **Chạy hunt:** bảng ``events`` gộp mọi bộ (cột ``bo`` = tên thư mục); mỗi hunt chạy một lần, tập khớp lưu ở bảng ``khop``
   theo SHA256 của hunt spec. Lần chấm sau dùng lại, không chạy lại hunt đã có.
2. **Chấm** cho một bộ nhãn và một phạm vi (``--pham-vi``, ``--bo-loai``): chỉ số chính chỉ tính trên E = sự kiện kênh Sysmon
   trong các bộ thuộc phạm vi L1 (giao thức 22 §4); khớp ngoài E không có nhãn nên chỉ đếm riêng, không là báo nhầm.
   ``--nen`` thêm phép đo phụ mức bộ dữ liệu theo nền phổ biến L2 (§7), không gọi là recall hay FPR.

Cách được chấm (§3): ``sigmahq_cao``, ``sigmahq_moi_muc`` (rule SigmaHQ stable/test có tag trùng chính xác mã gốc hoặc mã
hiện hành, giữ khối lọc của rule), ``he_thong`` (chỉ phần chọn ứng viên), ``he_thong_bo_rong``, ``lai``; thêm
``sigmahq_cao_toan_bo`` (mọi rule high/critical, không xét tag) khi có ``--doi-chung-toan-bo``. Không gọi mô hình, không mạng.

    python scripts/huong2_cham.py --parquet <thư mục bộ đã nạp> --sinh-rule <thư mục huong2_sinh_rule> --nhan <tệp nhãn>
        --pham-vi <pham_vi_L1.json> [--bo-loai <json danh sách bộ>] [--nen <nen_pho_bien_L2.parquet>] --db <tệp duckdb>
        --out <thư mục>
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
import yaml

from cti_hunt import config
from cti_hunt.attack.catalog import AttackCatalog
from cti_hunt.eval import g0c
from cti_hunt.eval.thong_ke import mcnemar_exact, wilson
from cti_hunt.filter_approval import _breadth
from cti_hunt.hunt import runner
from cti_hunt.stages import community_rules

STIX = "data/attack/enterprise-attack-19.2.json"
SYSMON = "microsoft-windows-sysmon/operational"
KHOA = "bo, ev_host, ev_channel, ev_rec"
TOAN_BO = "sigmahq_cao_toan_bo"


def sha_tep(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# Phiên bản cách chạy hunt, gộp vào khóa cache của tập khớp: đổi cách chạy thì mọi tập khớp cũ bị chạy lại.
# khop_v2 (19/10): đặt default_collation='nocase' như store.connect; tập khớp khop_v1 tính khi chưa đặt (đếm thiếu).
CHAY_VERSION = "khop_v2_nocase"


def sha_spec(spec: dict) -> str:
    return hashlib.sha256((CHAY_VERSION + json.dumps(spec, sort_keys=True, ensure_ascii=False, default=str)).encode()).hexdigest()


def mo_csdl(parquet: Path, db: Path):
    """Tệp DuckDB có bảng ``events`` = hợp mọi bộ, thêm cột ``bo`` (mã bộ = tên thư mục). Dựng một lần."""
    con = duckdb.connect(str(db))
    con.execute("SET enable_progress_bar = false")
    # Adapter dịch phép bằng của Sigma thành '=' và dựa vào chế độ này, như store.connect của hệ thống (lỗi tìm ra 19/10).
    con.execute("SET default_collation = 'nocase'")
    # Laptop 19/10: gộp 664 bộ (2,29 triệu sự kiện, hàng trăm cột) kèm ORDER BY làm DuckDB hết bộ nhớ. Bỏ sắp xếp (chỉ để truy
    # vấn nhanh hơn, không đổi kết quả), đặt trần bộ nhớ và cho tràn ra đĩa cạnh tệp DuckDB.
    con.execute("SET memory_limit = '6GB'")
    con.execute("SET preserve_insertion_order = false")
    con.execute(f"SET temp_directory = '{(Path(db).parent / 'duckdb_tmp').as_posix()}'")
    if not con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name = 'events'").fetchone()[0]:
        files = sorted(glob.glob(str(parquet / "*" / "events.parquet")))
        lst = "[" + ", ".join("'" + f.replace("\\", "/").replace("'", "''") + "'" for f in files) + "]"
        con.execute(f"""CREATE TABLE events AS SELECT * EXCLUDE (filename),
                        regexp_extract(replace(filename, '\\', '/'), '([^/]+)/events\\.parquet$', 1) AS bo
                        FROM read_parquet({lst}, union_by_name = true, filename = true)""")
    con.execute("""CREATE TABLE IF NOT EXISTS hunt_info (hunt VARCHAR PRIMARY KEY, sha VARCHAR, channel VARCHAR,
                   event_ids VARCHAR, loi VARCHAR)""")
    con.execute("CREATE TABLE IF NOT EXISTS khop (hunt VARCHAR, bo VARCHAR, ev_host VARCHAR, ev_channel VARCHAR, ev_rec BIGINT)")
    return con


def chay_hunts(con, specs: list[dict]) -> int:
    """Chạy mỗi hunt chưa có (hoặc đã đổi spec) một lần, lưu tập khớp. Hunt lỗi: ghi lỗi, tính là không khớp."""
    co = dict(con.execute("SELECT hunt, sha FROM hunt_info").fetchall())
    moi = 0
    for s in specs:
        hid, sha = s["id"], sha_spec(s)
        if co.get(hid) == sha:
            continue
        if hid in co:                       # cùng mã nhưng spec đổi: chạy lại
            con.execute("DELETE FROM khop WHERE hunt = ?", [hid])
            con.execute("DELETE FROM hunt_info WHERE hunt = ?", [hid])
        where = [runner._scope_where(s["scope"]), f"({s['candidates']})"]
        where += [f"({f['where']}) IS NOT TRUE" for f in s.get("filters") or []]
        loi = None
        try:
            con.execute(f"INSERT INTO khop SELECT ?, {KHOA} FROM events WHERE {' AND '.join(where)}", [hid])
        except Exception as e:  # noqa: BLE001 — hunt lỗi trên dữ liệu này: ghi lại, tính là không khớp
            loi = f"{type(e).__name__}: {str(e)[:200]}"
            con.execute("DELETE FROM khop WHERE hunt = ?", [hid])
        con.execute("INSERT INTO hunt_info VALUES (?, ?, ?, ?, ?)",
                    [hid, sha, str(s["scope"]["channel"]).lower(), json.dumps(s["scope"]["event_ids"]), loi])
        moi += 1
    return moi


def specs_he_thong(sinh: Path) -> dict[str, list[dict]]:
    out = {}
    for f in sorted(sinh.glob("ky_thuat/*/hunts/*.yaml")):
        spec = yaml.safe_load(f.read_text(encoding="utf-8"))
        spec["filters"] = []                            # mục lọc do mô hình đề xuất không áp (giao thức 09 §2.5)
        out.setdefault(f.parent.parent.name, []).append(spec)
    return out


def _chay_duoc(specs: list[dict], key: str) -> tuple[list[dict], list[dict]]:
    # Runner của hệ thống đòi mã sự kiện đi kèm channel; rule không giới hạn mã sự kiện không chạy được.
    return ([s for s in specs if s["scope"]["event_ids"]],
            [{"rule": key, "ly_do": f"hunt {s['id']} không có mã sự kiện"} for s in specs if not s["scope"]["event_ids"]])


DANH_MUC = "configs/logsource_catalog.yaml"


def danh_muc_cham(bo_sung: Path | None, out: Path) -> str:
    """Danh mục logsource dùng để biên dịch rule SigmaHQ khi chấm: danh mục hệ thống, gộp thêm category trong ``bo_sung``
    (giao thức 22, Q-C3). Không ghi đè category đã có; bản gộp ghi vào thư mục ra."""
    if not bo_sung:
        return DANH_MUC
    base = yaml.safe_load(config.resolve(DANH_MUC).read_text(encoding="utf-8")) or {}
    them = yaml.safe_load(Path(bo_sung).read_text(encoding="utf-8")) or {}
    if set(base) & set(them):
        raise SystemExit(f"tệp bổ sung trùng category đã có: {sorted(set(base) & set(them))}")
    p = out / "danh_muc_cham.yaml"
    p.write_text(yaml.safe_dump({**base, **them}, allow_unicode=True, sort_keys=True), encoding="utf-8")
    return str(p)


def specs_sigmahq(goc_hien_hanh: dict[str, str | None], columns: set[str],
                  root: str | Path = community_rules.SIGMAHQ, danh_muc: str = DANH_MUC) -> tuple[dict, dict, list]:
    """{kỹ thuật gốc: [spec]} cho mức cao và mọi mức; rule dùng chung giữa kỹ thuật chỉ biên dịch một lần."""
    cache, skipped = {}, []
    cao, moi = {}, {}
    for goc, hh in goc_hien_hanh.items():
        ids = {goc.lower()} | ({hh.lower()} if hh else set())
        for m in community_rules.select(sorted(ids), root):
            key = m["relative_path"]
            if key not in cache:
                specs, sk = community_rules.compile_selected([m], columns, root, danh_muc)
                cache[key], sk2 = _chay_duoc(specs, key)
                skipped += sk + sk2
            for s in cache[key]:
                moi.setdefault(goc, []).append(s)
                if s["nguon_rule"]["level"] in community_rules.HIGH:
                    cao.setdefault(goc, []).append(s)
    return cao, moi, skipped


def specs_toan_bo(columns: set[str], root: str | Path = community_rules.SIGMAHQ,
                  danh_muc: str = DANH_MUC) -> tuple[list[dict], list]:
    """Đối chứng: mọi rule SigmaHQ stable/test mức high/critical, không xét tag."""
    metas, _ = community_rules._index(str(config.resolve(root)))
    specs, skipped = community_rules.compile_selected([m for m in metas if m["status"] in g0c.STATUSES], columns, root,
                                                      danh_muc)
    specs = [s for s in specs if s["nguon_rule"]["level"] in community_rules.HIGH]
    ok, sk = _chay_duoc(specs, "toan_bo")
    return ok, skipped + sk


def tham_chieu_atomic(specs: list[dict], root: str | Path = community_rules.SIGMAHQ) -> dict:
    """Số rule SigmaHQ (không phải hunt) có tài liệu tham khảo trỏ tới Atomic Red Team (giao thức 22 §8, §9)."""
    base = config.resolve(root)
    rules = sorted({s["nguon_rule"]["sigmahq"] for s in specs if s.get("nguon_rule")})
    co = 0
    for r in rules:
        refs = (yaml.safe_load((base / r).read_text(encoding="utf-8")) or {}).get("references") or []
        co += any("atomic-red-team" in str(x).lower() or "atomicredteam" in str(x).lower() for x in refs)
    return {"so_rule": len(rules), "co_tham_chieu_atomic": co}


def _bang(con, ten: str, cot: str, rows: list[tuple]) -> None:
    """Bảng tạm từ danh sách dòng; chèn theo lô nhiều dòng (executemany của DuckDB chạy từng câu, rất chậm)."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE {ten} ({cot})")
    for i in range(0, len(rows), 1000):
        lo = rows[i:i + 1000]
        o = "(" + ", ".join("?" * len(lo[0])) + ")"
        con.execute(f"INSERT INTO {ten} VALUES {', '.join([o] * len(lo))}", [v for r in lo for v in r])


def nap_nhan(con, nhan: Path | None, gia_lap: bool) -> None:
    if gia_lap:      # chỉ kiểm đường ống: sự kiện tạo tiến trình có đường dẫn Atomic trong dòng lệnh
        con.execute(f"""CREATE OR REPLACE TEMP TABLE nhan AS SELECT {KHOA} FROM events
                        WHERE ev_eid = 1 AND ev_channel = '{SYSMON}' AND CommandLine ILIKE '%atomicredteam%'""")
        return
    src = str(nhan).replace("\\", "/")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE nhan AS SELECT DISTINCT bo, ev_host, ev_channel, CAST(ev_rec AS BIGINT) AS ev_rec
                    FROM read_parquet('{src}')""")


def cham(con, cach: dict[str, dict[str, list[dict]]], bo_kt: dict[str, list[str]], l1: set[str], goc_hh: dict,
         co_nen: bool) -> dict:
    """Chỉ số của giao thức 22 §4, §5, §7 cho mọi cách, trên bảng ``khop`` đã có và bảng ``nhan`` (và ``nen``)."""
    _bang(con, "l1", "bo VARCHAR", [(b,) for b in sorted(l1)])
    _bang(con, "bk", "bo VARCHAR, ky_thuat VARCHAR", sorted({(b, k) for b, ks in bo_kt.items() for k in ks}))
    _bang(con, "ch", "cach VARCHAR, ky_thuat VARCHAR, hunt VARCHAR",
          sorted({(c, k, s["id"]) for c, by in cach.items() if c != TOAN_BO for k, specs in by.items() for s in specs}))
    if TOAN_BO in cach:     # mọi hunt của đối chứng là hunt của mọi kỹ thuật: dựng bằng phép nối chéo
        _bang(con, "tb", "hunt VARCHAR", sorted({(s["id"],) for specs in cach[TOAN_BO].values() for s in specs}))
        con.execute(f"INSERT INTO ch SELECT '{TOAN_BO}', k.ky_thuat, tb.hunt FROM (SELECT DISTINCT ky_thuat FROM bk) k CROSS JOIN tb")
    con.execute("CREATE OR REPLACE TEMP TABLE cach_hunt AS SELECT DISTINCT cach, hunt FROM ch")
    con.execute("CREATE OR REPLACE TEMP TABLE bk1 AS SELECT bk.* FROM bk JOIN l1 USING (bo)")
    con.execute(f"CREATE OR REPLACE TEMP TABLE a AS SELECT n.* FROM nhan n JOIN l1 USING (bo) WHERE n.ev_channel = '{SYSMON}'")
    n_nhan_ngoai = con.execute(f"SELECT count(*) FROM nhan WHERE ev_channel <> '{SYSMON}'").fetchone()[0]
    if n_nhan_ngoai:
        raise SystemExit(f"nhãn có {n_nhan_ngoai} sự kiện ngoài kênh Sysmon: không đúng định nghĩa L1")
    # Hunt Sysmon chạy được (không lỗi) — dùng cho độ phủ, FPR và bảng đối đầu.
    con.execute(f"""CREATE OR REPLACE TEMP TABLE hunt_ok AS SELECT hunt, channel = '{SYSMON}' AS sysmon FROM hunt_info
                    WHERE loi IS NULL""")
    T = sorted({k for (k,) in con.execute("SELECT DISTINCT ky_thuat FROM bk1").fetchall()}
               & {k for (k,) in con.execute("SELECT DISTINCT bk1.ky_thuat FROM bk1 JOIN a USING (bo)").fetchall()})
    ten_cach = list(cach)

    # Khớp tấn công trong bộ của chính kỹ thuật: (cách, X) → số sự kiện A của X bị khớp.
    khop_a = {(c, k): n for c, k, n in con.execute("""
        SELECT c.cach, c.ky_thuat, count(DISTINCT (k.bo, k.ev_host, k.ev_channel, k.ev_rec))
        FROM ch c JOIN khop k ON k.hunt = c.hunt JOIN bk1 ON bk1.bo = k.bo AND bk1.ky_thuat = c.ky_thuat
        JOIN a ON a.bo = k.bo AND a.ev_host = k.ev_host AND a.ev_channel = k.ev_channel AND a.ev_rec = k.ev_rec
        GROUP BY 1, 2""").fetchall()}
    a_kt = dict(con.execute("SELECT bk1.ky_thuat, count(*) FROM a JOIN bk1 USING (bo) GROUP BY 1").fetchall())
    phu = {(c, k) for c, k in con.execute("""SELECT DISTINCT c.cach, c.ky_thuat FROM ch c JOIN hunt_ok h USING (hunt)
                                             WHERE h.sysmon""").fetchall()}

    # Tổng theo cách (mỗi sự kiện một lần trong một cách).
    tong = {c: dict(zip(("khop_E", "khop_A", "khop_ngoai"), r)) for c, *r in con.execute(f"""
        WITH m AS (SELECT DISTINCT ch.cach, k.bo, k.ev_host, k.ev_channel, k.ev_rec FROM cach_hunt ch JOIN khop k USING (hunt))
        SELECT m.cach,
               count(*) FILTER (WHERE l1.bo IS NOT NULL AND m.ev_channel = '{SYSMON}'),
               count(*) FILTER (WHERE a.bo IS NOT NULL),
               count(*) FILTER (WHERE l1.bo IS NULL OR m.ev_channel <> '{SYSMON}')
        FROM m LEFT JOIN l1 USING (bo)
        LEFT JOIN a ON a.bo = m.bo AND a.ev_host = m.ev_host AND a.ev_channel = m.ev_channel AND a.ev_rec = m.ev_rec
        GROUP BY 1""").fetchall()}
    cheo = {c: (cap, sk) for c, cap, sk in con.execute(f"""
        WITH x AS (SELECT DISTINCT c.cach, c.ky_thuat, k.bo, k.ev_host, k.ev_channel, k.ev_rec
                   FROM ch c JOIN khop k ON k.hunt = c.hunt
                   JOIN a ON a.bo = k.bo AND a.ev_host = k.ev_host AND a.ev_channel = k.ev_channel AND a.ev_rec = k.ev_rec
                   WHERE c.cach <> '{TOAN_BO}' AND NOT EXISTS (
                         SELECT 1 FROM bk WHERE bk.bo = k.bo AND bk.ky_thuat = c.ky_thuat))
        SELECT cach, count(*), count(DISTINCT (bo, ev_host, ev_channel, ev_rec)) FROM x GROUP BY 1""").fetchall()}

    # FPR theo hunt Sysmon: mẫu số = sự kiện thuộc E, không thuộc A, cùng channel và mã sự kiện.
    mau_so_cache: dict[str, int] = {}
    theo_hunt = []
    info = {h: (ch_, ids, loi) for h, ch_, ids, loi in con.execute("SELECT hunt, channel, event_ids, loi FROM hunt_info").fetchall()}
    fp_hunt = {h: (e, fp) for h, e, fp in con.execute(f"""
        WITH k AS (SELECT DISTINCT hunt, {KHOA} FROM khop)
        SELECT k.hunt, count(*) FILTER (WHERE l1.bo IS NOT NULL AND k.ev_channel = '{SYSMON}'),
               count(*) FILTER (WHERE l1.bo IS NOT NULL AND k.ev_channel = '{SYSMON}' AND a.bo IS NULL)
        FROM k LEFT JOIN l1 USING (bo)
        LEFT JOIN a ON a.bo = k.bo AND a.ev_host = k.ev_host AND a.ev_channel = k.ev_channel AND a.ev_rec = k.ev_rec
        GROUP BY 1""").fetchall()}
    n_khop = dict(con.execute(f"SELECT hunt, count(DISTINCT ({KHOA})) FROM khop GROUP BY 1").fetchall())
    hunt_cach: dict[str, set] = {}
    for c, h in con.execute("SELECT cach, hunt FROM cach_hunt").fetchall():
        hunt_cach.setdefault(h, set()).add(c)
    hunt_kt: dict[str, set] = {}
    for c, k, h in con.execute(f"SELECT cach, ky_thuat, hunt FROM ch WHERE cach <> '{TOAN_BO}'").fetchall():
        hunt_kt.setdefault(h, set()).add(k)
    fpr_cach: dict[str, list] = {c: [] for c in ten_cach}
    for h in sorted(hunt_cach):
        ch_, ids, loi = info[h]
        e, fp = fp_hunt.get(h, (0, 0))
        fpr = ms = None
        if ch_ == SYSMON and loi is None:
            sc = runner._scope_where({"channel": ch_, "event_ids": json.loads(ids)})
            if sc not in mau_so_cache:
                mau_so_cache[sc] = con.execute(f"""SELECT count(*) FROM events JOIN l1 USING (bo) WHERE {sc} AND NOT EXISTS (
                    SELECT 1 FROM a WHERE a.bo = events.bo AND a.ev_host = events.ev_host AND a.ev_channel = events.ev_channel
                    AND a.ev_rec = events.ev_rec)""").fetchone()[0]
            ms = mau_so_cache[sc]
            fpr = fp / ms if ms else 0.0
            for c in hunt_cach[h]:
                fpr_cach[c].append(fpr)
        theo_hunt.append({"hunt": h, "cach": ";".join(sorted(hunt_cach[h])),
                          "ky_thuat": ";".join(sorted(hunt_kt.get(h, ()))) or "*", "channel": ch_, "event_ids": ids,
                          "loi": loi or "", "khop": n_khop.get(h, 0), "khop_E": e, "bao_nham": fp,
                          "mau_so_fpr": "" if ms is None else ms, "fpr": "" if fpr is None else round(fpr, 6)})

    def bat(c, k):
        return khop_a.get((c, k), 0) > 0

    kq = {"so_ky_thuat_T": len(T), "so_bo_L1": len(l1), "so_su_kien_A": con.execute("SELECT count(*) FROM a").fetchone()[0],
          "so_su_kien_E": con.execute(f"SELECT count(*) FROM events JOIN l1 USING (bo) WHERE ev_channel = '{SYSMON}'").fetchone()[0],
          "cach": {}}
    for c in ten_cach:
        b = [k for k in T if bat(c, k)]
        lo, hi = wilson(len(b), len(T)) if T else (0, 0)
        ti_le = sorted(khop_a.get((c, k), 0) / a_kt[k] for k in T if a_kt.get(k))
        t = tong.get(c, {"khop_E": 0, "khop_A": 0, "khop_ngoai": 0})
        f = sorted(fpr_cach[c])
        kq["cach"][c] = {
            "so_hunt": con.execute("SELECT count(*) FROM cach_hunt WHERE cach = ?", [c]).fetchone()[0],
            "do_phu": sum(1 for k in T if (c, k) in phu), "bat_duoc": len(b), "tren": len(T), "wilson95": [lo, hi],
            "recall_su_kien_trung_vi": ti_le[len(ti_le) // 2] if ti_le else None,
            "recall_su_kien_gop": (sum(khop_a.get((c, k), 0) for k in T) / sum(a_kt.get(k, 0) for k in T)) if T else None,
            "bao_nham": t["khop_E"] - t["khop_A"], "precision": (t["khop_A"] / t["khop_E"]) if t["khop_E"] else None,
            "fpr_theo_hunt": {"so_hunt_tinh": len(f), "trung_vi": f[len(f) // 2] if f else None,
                              "lon_nhat": f[-1] if f else None, "so_hunt_tren_1pct": sum(1 for x in f if x > 0.01)},
            "khop_ngoai_pham_vi_nhan": t["khop_ngoai"],
            "khop_cheo_tan_cong": None if c == TOAN_BO else {"cap": cheo.get(c, (0, 0))[0], "su_kien": cheo.get(c, (0, 0))[1]}}
    kq["so_cap"] = {}
    for x, y in (("he_thong", "sigmahq_cao"), ("lai", "sigmahq_cao"), ("he_thong_bo_rong", "sigmahq_cao")):
        if x in cach and y in cach:
            p = sum(1 for k in T if bat(x, k) and not bat(y, k))
            q = sum(1 for k in T if bat(y, k) and not bat(x, k))
            kq["so_cap"][f"{x}_vs_{y}"] = {"chi_thu_nhat": p, "chi_thu_hai": q, "p": mcnemar_exact(p, q)}
    kq["doi_dau"] = []
    for k in T:
        if ("he_thong", k) in phu and ("sigmahq_cao", k) in phu:
            dong = {"ky_thuat": k, "su_kien_A": a_kt.get(k, 0)}
            for c in ("he_thong", "sigmahq_cao"):
                dong[f"bat_{c}"], dong[f"khop_A_{c}"] = int(bat(c, k)), khop_a.get((c, k), 0)
            kq["doi_dau"].append(dong)

    if co_nen:
        kd = {(c, k) for c, k in con.execute("""
            SELECT DISTINCT c.cach, c.ky_thuat FROM ch c JOIN khop k ON k.hunt = c.hunt
            JOIN bk ON bk.bo = k.bo AND bk.ky_thuat = c.ky_thuat
            WHERE NOT EXISTS (SELECT 1 FROM nen n WHERE n.bo = k.bo AND n.ev_host = k.ev_host AND n.ev_channel = k.ev_channel
                              AND n.ev_rec = k.ev_rec)""").fetchall()}
        cheo_nen = dict(con.execute(f"""
            SELECT c.cach, count(DISTINCT (k.bo, k.ev_host, k.ev_channel, k.ev_rec)) FROM ch c JOIN khop k ON k.hunt = c.hunt
            WHERE c.cach <> '{TOAN_BO}' AND NOT EXISTS (SELECT 1 FROM bk WHERE bk.bo = k.bo AND bk.ky_thuat = c.ky_thuat)
            AND NOT EXISTS (SELECT 1 FROM nen n WHERE n.bo = k.bo AND n.ev_host = k.ev_host AND n.ev_channel = k.ev_channel
                            AND n.ev_rec = k.ev_rec) GROUP BY 1""").fetchall())
        co_hunt = {(c, k) for c, k in con.execute("SELECT DISTINCT c.cach, c.ky_thuat FROM ch c JOIN hunt_ok USING (hunt)").fetchall()}
        goc = sorted({k for ks in bo_kt.values() for k in ks})
        kt_he = sorted(cach.get("he_thong", {}))
        kq["phu_L2"] = {"ghi_chu": "khớp được = khớp ≥ 1 sự kiện không thuộc nền phổ biến L2 trong bộ của kỹ thuật; không phải recall",
                        "cach": {c: {"co_hunt": sum(1 for k in goc if (c, k) in co_hunt),
                                     "khop_duoc": sum(1 for k in goc if (c, k) in kd),
                                     "khop_cheo_su_kien": None if c == TOAN_BO else cheo_nen.get(c, 0)} for c in ten_cach},
                        "tren_ky_thuat_he_thong": {k: {c: int((c, k) in kd) for c in ("he_thong", "sigmahq_cao", "sigmahq_moi_muc")
                                                       if c in cach} for k in kt_he}}
    kq["_theo_hunt"] = theo_hunt
    kq["_theo_ky_thuat"] = [{"ky_thuat": k, "hien_hanh": goc_hh.get(k), "trong_T": int(k in T), "su_kien_A": a_kt.get(k, 0),
                             **{f"so_hunt_{c}": len(cach[c].get(k, [])) for c in ten_cach if c != TOAN_BO},
                             **{f"bat_{c}": int(bat(c, k)) for c in ten_cach},
                             **{f"khop_A_{c}": khop_a.get((c, k), 0) for c in ten_cach}}
                            for k in sorted({k for ks in bo_kt.values() for k in ks})]
    return kq


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--sinh-rule", required=True)
    ap.add_argument("--nhan")
    ap.add_argument("--nhan-gia-lap", action="store_true")
    ap.add_argument("--pham-vi", help="pham_vi_L1.json của bộ nhãn; bỏ trống thì phạm vi là mọi bộ (chỉ để kiểm đường ống)")
    ap.add_argument("--bo-loai", help="JSON có khóa 'bo': danh sách bộ bỏ khỏi phạm vi (phân tích độ nhạy)")
    ap.add_argument("--nen", help="nen_pho_bien_L2.parquet: thêm phép đo phụ mức bộ dữ liệu")
    ap.add_argument("--sha-nhan", help="SHA256 phải khớp của tệp --nhan (giao thức 22 §2)")
    ap.add_argument("--sha-pham-vi", help="SHA256 phải khớp của tệp --pham-vi")
    ap.add_argument("--doi-chung-toan-bo", action="store_true", help=f"thêm cách {TOAN_BO}")
    ap.add_argument("--sigmahq", default=community_rules.SIGMAHQ)
    ap.add_argument("--bo-sung-danh-muc", help="YAML category logsource thêm vào danh mục khi biên dịch rule SigmaHQ (Q-C3)")
    ap.add_argument("--db", help="tệp DuckDB dùng chung giữa các lần chấm (mặc định <out>/events.duckdb)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if not a.nhan and not a.nhan_gia_lap:
        raise SystemExit("cần --nhan (tệp nhãn theo giao thức) hoặc --nhan-gia-lap (chỉ kiểm đường ống)")
    for tep, sha in ((a.nhan, a.sha_nhan), (a.pham_vi, a.sha_pham_vi)):
        if sha and (not tep or sha_tep(Path(tep)) != sha.lower()):
            raise SystemExit(f"SHA256 của {tep} không khớp giao thức")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    con = mo_csdl(Path(a.parquet), Path(a.db) if a.db else out / "events.duckdb")
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    tom_tat = json.loads((Path(a.parquet) / "tom_tat_nap.json").read_text(encoding="utf-8"))
    # Một tệp có thể thành nhiều bộ (mỗi lần ghi một bộ, attack_data_sang_parquet.tach_lan_ghi); bộ nào nạp được đều tính.
    bo_kt = {b: r["ky_thuat"] for r in tom_tat.values() if r["trang_thai"] in ("ok", "mot_phan")
             for b in (r.get("bo_con") or [r["ma_bo"]])}
    cat = AttackCatalog.from_stix(config.resolve(STIX))
    goc = sorted({k for v in bo_kt.values() for k in v})
    goc_hh = {k: cat.resolve(k).final for k in goc}

    dm = danh_muc_cham(Path(a.bo_sung_danh_muc) if a.bo_sung_danh_muc else None, out)
    sig_cao, sig_moi, khong_dich = specs_sigmahq(goc_hh, columns, a.sigmahq, dm)
    he = specs_he_thong(Path(a.sinh_rule))
    he_specs = [s for v in he.values() for s in v]
    rong = _breadth(con, he_specs) if he_specs else {}
    cach = {"sigmahq_cao": sig_cao, "sigmahq_moi_muc": sig_moi, "he_thong": he,
            "he_thong_bo_rong": {k: [s for s in v if s["id"] not in rong] for k, v in he.items()}}
    cach["lai"] = {k: cach["sigmahq_cao"].get(k, []) + he.get(k, []) for k in goc}
    toan_bo_skip = []
    if a.doi_chung_toan_bo:
        tb, toan_bo_skip = specs_toan_bo(columns, a.sigmahq, dm)
        cach[TOAN_BO] = {k: tb for k in goc}

    unique = {s["id"]: s for by in cach.values() for specs in by.values() for s in specs}
    moi = chay_hunts(con, list(unique.values()))
    nap_nhan(con, Path(a.nhan) if a.nhan else None, a.nhan_gia_lap)
    if a.nen:
        con.execute(f"""CREATE OR REPLACE TEMP TABLE nen AS SELECT DISTINCT bo, ev_host, ev_channel, CAST(ev_rec AS BIGINT) AS ev_rec
                        FROM read_parquet('{str(a.nen).replace(chr(92), '/')}')""")
    if a.pham_vi:
        pv = json.loads(Path(a.pham_vi).read_text(encoding="utf-8"))
        l1 = {x["bo"] for x in pv["bo"]}
    else:
        l1 = set(bo_kt)
    bo_loai = set(json.loads(Path(a.bo_loai).read_text(encoding="utf-8"))["bo"]) if a.bo_loai else set()
    if bo_loai - l1:
        raise SystemExit(f"--bo-loai có bộ ngoài phạm vi: {sorted(bo_loai - l1)[:3]}")
    l1 -= bo_loai
    kq_cham = cham(con, cach, bo_kt, l1, goc_hh, bool(a.nen))
    theo_hunt, theo_kt = kq_cham.pop("_theo_hunt"), kq_cham.pop("_theo_ky_thuat")
    loi = dict(con.execute("SELECT hunt, loi FROM hunt_info WHERE loi IS NOT NULL").fetchall())
    sig_all = [s for by in (sig_moi,) for v in by.values() for s in v]
    kq = {"giao_thuc": "docs/METHODOLOGY.md", "thoi_gian_giay": None,
          "dau_vao": {"tom_tat_nap.json": sha_tep(Path(a.parquet) / "tom_tat_nap.json"),
                      "nhan": (str(a.nhan), sha_tep(Path(a.nhan))) if a.nhan else "gia_lap",
                      "pham_vi": (str(a.pham_vi), sha_tep(Path(a.pham_vi))) if a.pham_vi else None,
                      "bo_loai": (str(a.bo_loai), sha_tep(Path(a.bo_loai)), sorted(bo_loai)) if a.bo_loai else None,
                      "nen": (str(a.nen), sha_tep(Path(a.nen))) if a.nen else None,
                      "hunt_he_thong": {str(p.relative_to(Path(a.sinh_rule))).replace("\\", "/"): sha_tep(p)
                                        for p in sorted(Path(a.sinh_rule).glob("ky_thuat/*/hunts/*.yaml"))},
                      "bo_sung_danh_muc": (str(a.bo_sung_danh_muc), sha_tep(Path(a.bo_sung_danh_muc)))
                      if a.bo_sung_danh_muc else None,
                      "script": sha_tep(Path(__file__))},
          "so_bo": len(bo_kt), "so_ky_thuat": len(goc), "so_hunt_chay_moi": moi, "so_hunt_loi": len(loi), "loi": loi,
          # Một mục bỏ có thể chỉ là một nguồn của rule (vd Security 4688 không có OriginalFileName), rule vẫn chạy trên Sysmon.
          "muc_bo_theo_nguon_sigmahq": len(khong_dich), "muc_bo_theo_nguon_sigmahq_chi_tiet": khong_dich,
          "rule_sigmahq_khong_chay_tren_nguon_nao": len({x["rule"] for x in khong_dich}
                                                        - {s["nguon_rule"]["sigmahq"] for s in sig_all}),
          "toan_bo_khong_chay_duoc": len(toan_bo_skip),
          "tham_chieu_atomic": {"sigmahq_moi_muc": tham_chieu_atomic(sig_all, a.sigmahq),
                                "sigmahq_cao": tham_chieu_atomic([s for v in sig_cao.values() for s in v], a.sigmahq)},
          "he_thong_hunt_bi_danh_dau_rong": rong, **kq_cham}
    kq["thoi_gian_giay"] = round(time.monotonic() - t0, 1)
    (out / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
    for ten, rows in (("theo_ky_thuat.csv", theo_kt), ("theo_hunt.csv", theo_hunt)):
        with open(out / ten, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["trong"])
            w.writeheader()
            w.writerows(rows)
    print(f"{kq['so_bo']} bộ · phạm vi {kq['so_bo_L1']} bộ · T = {kq['so_ky_thuat_T']} kỹ thuật · A = {kq['so_su_kien_A']} sự kiện"
          f" · hunt lỗi {kq['so_hunt_loi']} · {kq['thoi_gian_giay']} giây")
    for ten, v in kq["cach"].items():
        print(f"  {ten:20s} hunt {v['so_hunt']:5d} · phủ {v['do_phu']:3d} · bắt {v['bat_duoc']}/{v['tren']} · báo nhầm "
              f"{v['bao_nham']} · precision {v['precision']} · FPR lớn nhất {v['fpr_theo_hunt']['lon_nhat']}")
    for k, v in kq["so_cap"].items():
        print(f"  {k}: chỉ thứ nhất {v['chi_thu_nhat']} / chỉ thứ hai {v['chi_thu_hai']} · p = {v['p']:.3g}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
