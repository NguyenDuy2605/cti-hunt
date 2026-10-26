"""Khâu ⑧ — gom nhóm, tương quan chéo giữa giả thuyết, quyết định pivot (v3 §4.2 ⑧, §4.4). Phần XÁC ĐỊNH.

Phần do mô hình làm (viết nội dung giả thuyết pivot ở khâu ④, origin=pivot) chưa có; ở đây chỉ ra đề xuất pivot
có cấu trúc, và đề xuất đó vẫn phải qua điểm dừng ◆.

Nguyên tắc:
- KHÔNG NHÌN NHÃN. Chạy lại truy vấn đã thực thi (candidates + filters, lấy từ kết quả runner) trên view `events`.
  Không dùng view `labeled`, không dùng `ket_qua_cuoi` của runner (bị cắt 300 dòng và có cột `buoc`). Quyết định
  pivot mà dựa trên nhãn thì chỉ số "giá trị của vòng lặp" (v3 §6.2 ⑧) vô nghĩa.
- NGƯỠNG DO MÃ QUYẾT (v3 §4.4): thực thể được đề xuất pivot khi khớp từ `min_hypotheses` giả thuyết trở lên.
  Xếp hạng: nhiều giả thuyết hơn → nhiều nguồn log hơn → ÍT sự kiện hơn (hiếm hơn) → tên.
- THỰC THỂ PIVOT chỉ gồm máy và tài khoản (như ví dụ v3 §5.1). Tiến trình như powershell.exe xuất hiện khắp nơi
  trong Living-off-the-Land; pivot theo tiến trình chỉ sinh nhiễu.
- KHÔNG LOẠI ÂM THẦM: tài khoản hệ thống (SYSTEM, máy$…) bị loại khỏi ứng viên pivot đều ghi kèm lý do.
- TRẦN CỨNG (v3 §7, pivot không hội tụ): max_pivot_depth, max_pivots_per_round, max_queries_total.
- Cụm thời gian chỉ gom TRONG CÙNG MÁY. Không tự nối sự kiện giữa các máy thành "chuỗi di chuyển ngang": v2 từng
  gộp ba sự kiện trên ba máy thành một mẫu và sai (v3 §5.1, ghi chú sửa đổi).
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

import duckdb

from ..hunt.runner import _scope_where

ACCOUNT_COLUMNS = ("User", "SubjectUserName", "TargetUserName", "AccountName")
PROCESS_COLUMNS = ("Image", "NewProcessName")


def spec_from_result(res: dict) -> dict:
    """Dựng lại truy vấn đã chạy từ kết quả runner (runner ghi `truy_van` từ 21/9)."""
    q = res.get("truy_van")
    if not q:
        raise ValueError(f"{res['hunt']['id']}: kết quả runner không có `truy_van` — chạy lại `hunt` bằng bản mới")
    from ..filter_approval import FilterReviewError, path_policy, require_executable
    if res.get("filter_contract"):
        from copy import deepcopy
        spec = deepcopy(res["filter_contract"])
        require_executable(spec)
        expected = {"candidates": spec["candidates"],
                    "filters": [{"id": f["id"], "where": f["where"]} for f in spec["filters"]]}
        if (q != expected or res["hunt"]["id"] != spec["id"] or res["hunt"]["scope"] != spec["scope"] or
                res["hunt"].get("hypothesis_id") != spec.get("hypothesis_id")):
            raise FilterReviewError("kết quả/provenance lọc không khớp hunt hiệu lực")
        return spec
    if res.get("hunt_file") and path_policy(res["hunt_file"]):
        raise FilterReviewError("kết quả v2 thiếu provenance lọc")
    return {"id": res["hunt"]["id"], "hypothesis_id": res["hunt"].get("hypothesis_id") or res["hunt"]["id"],
            "scope": res["hunt"]["scope"], "candidates": q["candidates"], "filters": q.get("filters") or []}


def norm_account(v) -> str:
    """'DMEVALS\\mscott' và 'mscott' là một tài khoản: bỏ miền, chữ thường."""
    s = str(v or "").strip()
    return s.split("\\")[-1].split("@")[0].strip().lower()


def final_rows(con: duckdb.DuckDBPyConnection, spec: dict, columns: set[str]) -> list[dict]:
    from ..filter_approval import require_executable
    require_executable(spec, con=con)
    acc = [c for c in ACCOUNT_COLUMNS if c in columns]
    proc = [c for c in PROCESS_COLUMNS if c in columns]
    sel = ", ".join(["ev_host", "ev_channel", "ev_rec", "ev_ts"] + [f'"{c}"' for c in acc + proc])
    cte = f"c AS (SELECT * FROM events WHERE {_scope_where(spec['scope'])} AND ({spec['candidates']}))"
    if spec["filters"]:
        removed = " UNION ".join(f"SELECT ev_host, ev_channel, ev_rec FROM c WHERE ({f['where']})" for f in spec["filters"])
        sql = f"WITH {cte}, r AS ({removed}) SELECT {sel} FROM c ANTI JOIN r USING (ev_host, ev_channel, ev_rec)"
    else:
        sql = f"WITH {cte} SELECT {sel} FROM c"
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    rows = [dict(zip(names, r)) for r in cur.fetchall()]
    for r in rows:
        r["_accounts"] = {norm_account(r[c]) for c in acc if r.get(c)} - {""}
        r["_process"] = next((str(r[c]) for c in proc if r.get(c)), "")
    return rows


def triage(con: duckdb.DuckDBPyConnection, specs: list[dict], cfg: dict, pivot_depth: int = 0,
           queries_used: int = 0, already_pivoted: set[tuple[str, str]] | None = None) -> dict:
    t = cfg["triage"]
    excl = [re.compile(p, re.I) for p in t.get("exclude_accounts") or []]
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    already = already_pivoted or set()

    ent = defaultdict(lambda: {"gia_thuyet": set(), "nguon_log": set(), "keys": set(), "ts": []})
    by_host: dict[str, list] = defaultdict(list)
    hunts = []
    for spec in specs:
        rows = final_rows(con, spec, columns)
        hunts.append({"hypothesis_id": spec["hypothesis_id"], "hunt_id": spec["id"],
                      "nguon_log": spec["scope"]["channel"], "so_su_kien": len(rows)})
        for r in rows:
            key = (r["ev_host"], r["ev_channel"], r["ev_rec"])
            for kind, val in [("may", r["ev_host"])] + [("tai_khoan", a) for a in r["_accounts"]]:
                e = ent[(kind, val)]
                e["gia_thuyet"].add(spec["hypothesis_id"])
                e["nguon_log"].add(spec["scope"]["channel"])
                e["keys"].add(key)
                e["ts"].append(r["ev_ts"])
            by_host[r["ev_host"]].append((r["ev_ts"], spec["hypothesis_id"], key, r["_process"]))

    entities, excluded = [], []
    for (kind, val), e in ent.items():
        row = {"loai": kind, "gia_tri": val, "gia_thuyet": sorted(e["gia_thuyet"]),
               "so_gia_thuyet": len(e["gia_thuyet"]), "so_nguon_log": len(e["nguon_log"]),
               "so_su_kien": len(e["keys"]), "dau_tien": str(min(e["ts"])), "cuoi_cung": str(max(e["ts"]))}
        hit = next((p.pattern for p in excl if kind == "tai_khoan" and p.search(val)), None)
        if hit:
            excluded.append({**row, "ly_do": f"tài khoản hệ thống/máy (mẫu {hit}) — không làm ứng viên pivot"})
        else:
            entities.append(row)
    rank = lambda r: (-r["so_gia_thuyet"], -r["so_nguon_log"], r["so_su_kien"], r["loai"], r["gia_tri"])
    entities.sort(key=rank)

    # Cụm thời gian: sự kiện cùng máy, cách nhau không quá cửa sổ, và thuộc từ 2 giả thuyết trở lên.
    win = timedelta(minutes=float(t["time_window_minutes"]))
    clusters = []
    for host, evs in by_host.items():
        evs.sort(key=lambda x: x[0])
        cur = [evs[0]]
        for ev in evs[1:]:
            if ev[0] - cur[-1][0] <= win:
                cur.append(ev)
            else:
                clusters.append((host, cur))
                cur = [ev]
        clusters.append((host, cur))
    clusters = [{"may": h, "bat_dau": str(c[0][0]), "ket_thuc": str(c[-1][0]),
                 "gia_thuyet": sorted({x[1] for x in c}), "so_su_kien": len({x[2] for x in c}),
                 "tien_trinh": sorted({x[3].split("\\")[-1] for x in c if x[3]})[:8]}
                for h, c in clusters if len({x[1] for x in c}) >= 2]
    clusters.sort(key=lambda c: (-len(c["gia_thuyet"]), c["bat_dau"]))

    # Quyết định pivot — hoàn toàn bằng ngưỡng và trần.
    cands = [e for e in entities if e["so_gia_thuyet"] >= int(t["min_hypotheses"])]
    skipped_seen = [e for e in cands if (e["loai"], e["gia_tri"]) in already]
    cands = [e for e in cands if (e["loai"], e["gia_tri"]) not in already]
    max_depth = int(cfg["max_pivot_depth"])
    room = min(int(t["max_pivots_per_round"]), max(0, int(t["max_queries_total"]) - queries_used))
    chosen, over, stop = [], [], ""
    if not cands:
        stop = "không còn thực thể vượt ngưỡng"
    elif pivot_depth + 1 > max_depth:
        over, stop = cands, f"đạt trần độ sâu ({max_depth})"
    else:
        chosen, over = cands[:room], cands[room:]
        if over:
            stop = ("đạt trần số truy vấn" if int(t["max_queries_total"]) - queries_used <= int(t["max_pivots_per_round"])
                    else "đạt trần số pivot mỗi vòng") + f" — {len(over)} ứng viên chưa được xét"
    def proposal(e):
        return {"loai": e["loai"], "gia_tri": e["gia_tri"], "pivot_depth": pivot_depth + 1,
                "tu_gia_thuyet": e["gia_thuyet"], "status": "pending_review",
                "ly_do": f"khớp {e['so_gia_thuyet']} giả thuyết ({', '.join(e['gia_thuyet'])}) trên "
                         f"{e['so_nguon_log']} nguồn log, {e['so_su_kien']} sự kiện"}
    proposals = [proposal(e) for e in chosen]
    # D10: agent được chọn trong mọi ứng viên qua ngưỡng, còn pipeline giữ top-N ở de_xuat.
    eligible = [proposal(e) for e in cands] if room > 0 and pivot_depth + 1 <= max_depth else []
    return {
        "tham_so": {**t, "exclude_accounts": t.get("exclude_accounts"), "max_pivot_depth": max_depth,
                    "pivot_depth_hien_tai": pivot_depth, "so_truy_van_da_dung": queries_used},
        "hunts": hunts, "thuc_the": entities, "loai_tru": excluded, "cum_thoi_gian": clusters,
        "pivot": {"de_xuat": proposals, "ung_vien_du_dieu_kien": eligible,
                  "chua_xet": [{"loai": e["loai"], "gia_tri": e["gia_tri"]} for e in over],
                  "da_pivot_truoc": [{"loai": e["loai"], "gia_tri": e["gia_tri"]} for e in skipped_seen],
                  "ly_do_dung": stop},
        "nhat_ky_vong": {"vong": pivot_depth + 1, "pivot_depth": pivot_depth, "so_hunt": len(specs),
                         "so_de_xuat": len(proposals), "ly_do_dung": stop or "còn đề xuất, chờ duyệt ◆"},
    }
