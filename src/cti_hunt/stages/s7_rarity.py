"""Khâu ⑦: xếp hạng sự kiện còn lại sau các mục loại trừ đã duyệt.

Chỉ đọc view ``events``. Điểm dùng để ưu tiên xem xét, không tự loại sự kiện hay
tạo mục loại trừ. Mỗi thành phần và mẫu số được trả về để có thể giải trình.
"""
from __future__ import annotations

import hashlib
import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import timedelta

import duckdb

from ..hunt.runner import _scope_where, validate

KEY = ("ev_host", "ev_channel", "ev_rec")
SCORE_VERSION = "khau7_v1"
OPTIONAL = ("ParentImage", "Image", "CommandLine", "User", "SubjectUserName", "TargetUserName", "AccountName")
RECON = re.compile(r"(?i)\b(?:whoami|hostname|ipconfig|systeminfo|nltest|dsquery)(?:\.exe)?\b|"
                   r"\bnet(?:\.exe)?\s+(?:user|group|localgroup|view|use)\b")
ENCODED = re.compile(r"(?i)(?:\b(?:base64|frombase64string)\b|(?:^|\s)-(?:enc|encodedcommand)\b)")
TOKEN = re.compile(r"[A-Za-z0-9+/=]{24,}")


def _account(row: dict) -> str:
    for col in ("User", "SubjectUserName", "TargetUserName", "AccountName"):
        value = str(row.get(col) or "").strip()
        if value:
            return value.split("\\")[-1].split("@")[0].lower()
    return ""


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def _rows(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    cursor = con.execute(sql)
    names = [x[0] for x in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _select_columns(con: duckdb.DuckDBPyConnection) -> str:
    present = {r[0].lower(): r[0] for r in con.execute("DESCRIBE events").fetchall()}
    needed = {k.lower() for k in KEY} | {"ev_eid", "ev_ts"}
    missing = needed - set(present)
    if missing:
        raise ValueError(f"events thiếu cột bắt buộc: {sorted(missing)}")
    fields = [f'"{present[c.lower()]}" AS "{c}"' if c.lower() in present else f'NULL AS "{c}"' for c in OPTIONAL]
    return ", ".join(["ev_host", "ev_channel", "ev_rec", "ev_ts"] + fields)


def _survivors(con: duckdb.DuckDBPyConnection, spec: dict, fields: str) -> tuple[list[dict], list[dict]]:
    where = _scope_where(spec["scope"])
    ctes = [f"c0 AS (SELECT * FROM events WHERE {where} AND ({spec['candidates']}))"]
    filters = spec.get("filters") or []
    for i, f in enumerate(filters, start=1):
        ctes.append(f"r{i} AS (SELECT {', '.join(KEY)} FROM c{i-1} WHERE ({f['where']}))")
        ctes.append(f"c{i} AS (SELECT * FROM c{i-1} ANTI JOIN r{i} USING ({', '.join(KEY)}))")
    prefix = "WITH " + ", ".join(ctes)
    counts = con.execute(prefix + " SELECT " + ", ".join(f"(SELECT count(*) FROM c{i})" for i in range(len(filters) + 1))).fetchone()
    log = [{"stage": "ung_vien", "hits": counts[0], "removed": 0}]
    for i, f in enumerate(filters, start=1):
        log.append({"stage": f"sau_{f['id']}", "id": f["id"], "hits": counts[i],
                    "removed": counts[i - 1] - counts[i], "ly_do": f["ly_do"],
                    "nguoi_chiu_trach_nhiem": f["nguoi_chiu_trach_nhiem"], "het_han": f["het_han"]})
    return _rows(con, prefix + f" SELECT {fields} FROM c{len(filters)}"), log


def score(con: duckdb.DuckDBPyConnection, specs: list[dict], *, window_seconds: int = 5,
          entropy_threshold: float = 4.0) -> dict:
    """Trả điểm và bằng chứng cho từng sự kiện; không đọc nhãn hoặc sửa hunt spec.

    Đường cơ sở là mọi sự kiện cùng channel/EID trên toàn tập, kể cả máy ngoài
    scope của hunt. Nhờ vậy thu hẹp hunt không làm một mẫu quen thuộc thành hiếm.
    """
    if window_seconds < 1 or entropy_threshold <= 0:
        raise ValueError("window_seconds và entropy_threshold phải dương")
    fields = _select_columns(con)
    seen_ids: set[str] = set()
    survivors: list[tuple[dict, dict]] = []
    filter_logs = []
    baselines: dict[tuple[str, tuple[int, ...]], list[dict]] = {}
    for spec in specs:
        validate(spec, con=con)
        if spec["id"] in seen_ids:
            raise ValueError(f"hunt id trùng: {spec['id']}")
        seen_ids.add(spec["id"])
        kept, log = _survivors(con, spec, fields)
        filter_logs.append({"hunt_id": spec["id"], "hunt_sha256": spec.get("_sha256"), "giai_doan": log})
        for row in kept:
            survivors.append((spec, row))
        scope = spec["scope"]
        baseline_key = (str(scope["channel"]).lower(), tuple(sorted(int(e) for e in scope["event_ids"])))
        if baseline_key not in baselines:
            baseline_scope = {"channel": scope["channel"], "event_ids": scope["event_ids"]}
            baselines[baseline_key] = _rows(con, f"SELECT {fields} FROM events WHERE {_scope_where(baseline_scope)}")

    # Các tập dưới đây chỉ chứa sự kiện không nhãn từ events.
    stats = {}
    for key, rows in baselines.items():
        host_pair, global_pair = Counter(), Counter()
        first_account_host: dict[tuple[str, str], object] = {}
        recon_by_actor: dict[tuple[str, str], list] = defaultdict(list)
        for row in rows:
            parent, image = str(row.get("ParentImage") or "").lower(), str(row.get("Image") or "").lower()
            if parent and image:
                host_pair[(row["ev_host"], parent, image)] += 1
                global_pair[(parent, image)] += 1
            account = _account(row)
            if account and row["ev_ts"] is not None:
                k = (row["ev_host"], account)
                if k not in first_account_host or row["ev_ts"] < first_account_host[k]:
                    first_account_host[k] = row["ev_ts"]
            if account and row["ev_ts"] is not None and RECON.search(str(row.get("CommandLine") or "")):
                recon_by_actor[(row["ev_host"], account)].append(row["ev_ts"])
        for times in recon_by_actor.values():
            times.sort()
        stats[key] = (len(rows), host_pair, global_pair, first_account_host, recon_by_actor)

    entity_hyps: dict[tuple[str, str], set[str]] = defaultdict(set)
    for spec, row in survivors:
        hid = str(spec.get("hypothesis_id") or spec["id"])
        entity_hyps[("may", row["ev_host"])].add(hid)
        if acc := _account(row):
            entity_hyps[("tai_khoan", acc)].add(hid)

    output = []
    for spec, row in survivors:
        scope = spec["scope"]
        key = (str(scope["channel"]).lower(), tuple(sorted(int(e) for e in scope["event_ids"])))
        base_n, host_pair, global_pair, first_account_host, recon_by_actor = stats[key]
        parent, image = str(row.get("ParentImage") or "").lower(), str(row.get("Image") or "").lower()
        host_n = host_pair[(row["ev_host"], parent, image)] if parent and image else None
        global_n = global_pair[(parent, image)] if parent and image else None
        account = _account(row)
        first = bool(account and row["ev_ts"] is not None and
                     row["ev_ts"] == first_account_host.get((row["ev_host"], account)))
        cmd = str(row.get("CommandLine") or "")
        entropy = max((_entropy(token) for token in TOKEN.findall(cmd)), default=0.0)
        encoded = bool(ENCODED.search(cmd))
        high_entropy = entropy >= entropy_threshold
        density = 0
        if account and row["ev_ts"] is not None:
            times = recon_by_actor[(row["ev_host"], account)]
            window = timedelta(seconds=window_seconds)
            density = bisect_right(times, row["ev_ts"]) - bisect_left(times, row["ev_ts"] - window)
        host_hyps = len(entity_hyps[("may", row["ev_host"])])
        account_hyps = len(entity_hyps[("tai_khoan", account)]) if account else 0
        components = {
            "cap_may": round(1 / host_n, 4) if host_n else 0.0,
            "cap_toan_tap": round(1 / global_n, 4) if global_n else 0.0,
            "tai_khoan_lan_dau": int(first),
            "trinh_sat_day": int(density >= 2),
            "base64_hoac_entropy_cao": int(encoded or high_entropy),
            "nhieu_gia_thuyet": min(max(host_hyps, account_hyps) - 1, 3) / 3,
        }
        output.append({
            "hunt_id": spec["id"], "hunt_sha256": spec.get("_sha256"),
            "hypothesis_id": str(spec.get("hypothesis_id") or spec["id"]),
            "ev_host": row["ev_host"], "ev_channel": row["ev_channel"], "ev_rec": row["ev_rec"],
            "ev_ts": str(row["ev_ts"]), "score": round(sum(components.values()), 4),
            "thanh_phan": components,
            "bang_chung": {"baseline_events": base_n, "parent_image_host_count": host_n,
                           "parent_image_global_count": global_n, "account": account,
                           "first_account_host_at": str(first_account_host.get((row["ev_host"], account)) or ""),
                           "recon_commands_in_window": density, "command_max_entropy": round(entropy, 3),
                           "encoded_marker": encoded, "host_hypotheses": host_hyps,
                           "account_hypotheses": account_hyps},
        })
    output.sort(key=lambda r: (-r["score"], r["ev_ts"], r["hunt_id"], r["ev_host"], r["ev_rec"]))
    return {"tham_so": {"version": SCORE_VERSION, "window_seconds": window_seconds,
                         "recon_window": "[t-window_seconds, t], cùng máy và tài khoản; thiếu tài khoản thì không cộng",
                         "recon_min_events": 2, "entropy_threshold": entropy_threshold,
                         "entropy_token_min_length": 24,
                         "baseline": "cùng channel/EID, mọi máy và thời gian trong events",
                         "score": "tổng 6 thành phần; chỉ xếp hạng, không tự loại"},
            "so_su_kien": len(output), "nhat_ky_loc": filter_logs,
            "su_kien": output, "de_xuat_loai_tru": []}


def propose_exclusion(sample: dict, *, reason: str, owner: str, expires: str) -> dict:
    """Tạo phiếu chờ duyệt từ mẫu đã được chuyên viên xác nhận là hợp lệ.

    Không gắn phiếu vào hunt spec. Bắt buộc đủ đường dẫn con, dòng lệnh,
    tài khoản và máy để tránh loại rộng theo mỗi tên cha hay tên tệp.
    """
    required = ("Image", "CommandLine", "User", "ev_host")
    missing = [field for field in required if field not in sample or
               (field != "CommandLine" and not str(sample.get(field) or "").strip())]
    if missing or not all(str(x).strip() for x in (reason, owner, expires)):
        raise ValueError(f"thiếu mẫu/phạm vi hoặc giải trình mục loại trừ: {missing}")
    def literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"
    where = " AND ".join(
        f'COALESCE("CommandLine", \'\') = {literal(str(sample[field] or ""))}' if field == "CommandLine"
        else f'"{field}" = {literal(str(sample[field]))}' for field in required)
    digest = hashlib.sha256(where.encode("utf-8")).hexdigest()[:12]
    return {"id": f"P-{digest}", "status": "pending_review", "where": where,
            "pham_vi": {"may": sample["ev_host"]},
            "mau": {field: sample[field] for field in required},
            "ly_do": reason, "nguoi_chiu_trach_nhiem": owner, "het_han": expires,
            "nguon": "phan_hoi_chuyen_vien", "ghi_chu": "Chỉ đề xuất; cần phê duyệt trước khi thêm vào hunt spec."}
