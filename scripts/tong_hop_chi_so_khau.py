"""Tổng hợp chỉ số theo khâu từ các lượt đánh giá đã lưu — chỉ đọc, không nhãn, không gọi API.

Lấp các dòng v3.2 §6.2 chưa có bảng tổng hợp (đối chiếu cam kết 10/10, mục B1–B2):
- Vận hành: thời gian chạy toàn trình và thời gian tới giả thuyết đầu, tách thời gian chờ người duyệt.
- ④: tỷ lệ giả thuyết đủ thành phần bắt buộc (kiểm cấu trúc tự động của `s4_hypothesis.postprocess`).
- ⑤: tỷ lệ rule hợp lệ lần đầu và sau sửa.
- ⑦: mục loại trừ — phân bố tỷ lệ ứng viên bị loại và lý do người duyệt; v3.2 không đặt ngưỡng "quá rộng".

Chỉ đọc tệp trong thư mục lượt: `run_meta.json`, `round_*/{hypotheses,approval_log,agent_proposal,agent_execute}.json`,
`round_*/filter_review/*/{manifest,preview,approval_log}.json`, `round_*/khau5_requests.jsonl` (đếm lần gọi ở lượt
ngắt), `su_co.json`, và giờ sửa tệp. Không đọc thư mục nhãn, thư mục `runs` hay checkpoint.

    .venv/Scripts/python.exe -X utf8 scripts/tong_hop_chi_so_khau.py --out <thư mục ngoài data/>
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path("data/eval/apt29_day2")

DOT = {"tuyen_A": "Tuyến A (30/9–01/10)", "tuyen_B": "v2 (05/10)", "tuyen_B_v3": "v2 mới (07–08/10)"}

# Lượt không tính vào số chính (giao thức v2 mới 07/10 và quy tắc sự cố); vẫn báo ở phụ lục.
PHU_LUC = {
    ("tuyen_B_v3", "pipeline", "SY_01"): "loại khỏi số chính: đề xuất ◆ ngoài G0(d) (giao thức 07/10)",
    ("tuyen_B_v3", "agent", "MS_01"): "lỗi mạng ở ⑤, thay bằng lượt khác",
    ("tuyen_B_v3", "agent", "MS_02"): "lỗi mạng ở planner, thay bằng lượt khác",
    ("tuyen_B_v3", "agent", "SY_03"): "hết giờ đọc ở ④, thay bằng lượt khác",
}

# ④: mục bị bỏ vì thiếu/sai thành phần bắt buộc (s4_hypothesis.postprocess). Trùng lặp và vượt trần không phải lỗi
# cấu trúc của mục; còn lại là sửa nhẹ trên mục vẫn được giữ.
BO_CAU_TRUC = {"khong_neo_ttp", "thieu_thanh_phan", "nguon_log_ngoai_danh_muc", "ma_su_kien_ngoai_danh_muc",
               "thieu_truong"}
BO_KHAC = {"trung_gia_thuyet", "vuot_tran"}
SUA_GIU = {"ttp_ref_la", "truong_ngoai_danh_muc", "mo_rong_ma_sai", "mo_rong_ky_thuat", "priority_la"}
LO_SAI = "dau_ra_sai_luoc_do"

# ⑤: lỗi cuối của rule không hợp lệ, theo nhóm (s5_rule).
KHONG_GOI = {"khong_co_logsource", "het_ngan_sach", "thieu_moc_neo", "relative_time", "event_sequence",
             "timeframe_unbound", "rang_buoc_loi", "moc_neo"}

# Mã lý do từ chối ở ◆ (quyet_dinh_G0_a-d_26-9.md §G0(d)); ghi ở đầu `ly_do`.
MA_G0D = ("thieu_thanh_phan", "nguon_khong_phu_hop", "khong_bam_nguon", "trung_gia_thuyet")

# Mã lý do đề xuất cho phiếu lọc (de_xuat_duyet_muc_loc_khau5_v2.md §6).
MA_LY_DO = ("thieu_can_cu_lanh_tinh", "pham_vi_qua_rong", "xung_dot_hanh_vi_san", "thieu_truong_phan_biet",
            "logic_khong_ro")

_ROUND = re.compile(r"round_(\d+)$")
_BO_QUA = {"checkpoint.sqlite", "checkpoint.sqlite-shm", "checkpoint.sqlite-wal", "hunt_record.md",
           "agent_dev_record.json", "su_co.json"}


def _json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def _mtime(p: Path) -> datetime:
    return datetime.fromtimestamp(p.stat().st_mtime)


def _rounds(run: Path) -> list[Path]:
    return sorted((d for d in run.glob("round_*") if d.is_dir() and _ROUND.search(d.name)),
                  key=lambda d: int(_ROUND.search(d.name).group(1)))


def _reviews(rd: Path) -> list[Path]:
    return sorted(d for d in (rd / "filter_review").glob("r*") if d.is_dir())


def discover(root: Path = ROOT) -> list[dict]:
    out = []
    for tuyen in DOT:
        for mode in ("pipeline", "agent"):
            for run in sorted((root / tuyen / mode).glob("*")):
                if (run / "run_meta.json").exists():
                    key = (tuyen, mode, run.name)
                    out.append({"tuyen": tuyen, "mode": mode, "id": run.name, "path": run,
                                "tinh": key not in PHU_LUC, "phu_luc": PHU_LUC.get(key, "")})
    return out


# ---------------------------------------------------------------- vận hành

def times(run: Path) -> dict:
    """Thời gian theo giờ sửa tệp (giờ máy). Chờ người duyệt = từ lúc phát phiếu tới lúc phiếu được nhận khi resume."""
    start = datetime.fromisoformat(_json(run / "run_meta.json")["bat_dau"])
    su_co = run / "su_co.json"
    files = [p for p in run.rglob("*") if p.is_file() and p.name not in _BO_QUA]
    last_work = max(_mtime(p) for p in files)
    # Lượt ngắt: record dựng sau bằng script, nên kết thúc tính ở tệp làm việc cuối cùng trước sự cố.
    end = last_work if su_co.exists() else _mtime(run / "hunt_record.md")
    waits, first = [], None
    for rd in _rounds(run):
        hyp, appr = rd / "hypotheses.json", rd / "approval_log.json"
        if hyp.exists() and first is None:
            first = _mtime(hyp)
        if hyp.exists() and appr.exists():
            waits.append({"loai": "gia_thuyet", "vong": rd.name, "tu": _mtime(hyp), "den": _mtime(appr)})
        for rv in _reviews(rd):
            man, log = rv / "manifest.json", rv / "approval_log.json"
            if man.exists() and log.exists() and _json(log).get("kind") != "no_filters":
                waits.append({"loai": "loc", "vong": f"{rd.name}/{rv.name}", "tu": _mtime(man), "den": _mtime(log)})
    wait_s = sum(max(0.0, (w["den"] - w["tu"]).total_seconds()) for w in waits)
    total = (end - start).total_seconds()
    stamps = sorted({start, end, *(_mtime(p) for p in files)})
    gaps = []
    for a, b in zip(stamps, stamps[1:]):
        if b > end:
            break
        covered = sum(max(0.0, (min(b, w["den"]) - max(a, w["tu"])).total_seconds()) for w in waits)
        gaps.append(((b - a).total_seconds() - covered, a, b))
    gap = max(gaps, default=(0.0, start, start), key=lambda g: g[0])
    return {"bat_dau": start.isoformat(timespec="seconds"), "ket_thuc": end.isoformat(timespec="seconds"),
            "ket_thuc_theo": "tep_lam_viec_cuoi_truoc_su_co" if su_co.exists() else "hunt_record.md",
            "toan_trinh_giay": round(total), "cho_duyet_giay": round(wait_s), "may_giay": round(total - wait_s),
            "toi_gia_thuyet_dau_giay": round((first - start).total_seconds()) if first else None,
            "so_lan_cho_gia_thuyet": sum(w["loai"] == "gia_thuyet" for w in waits),
            "so_lan_cho_loc": sum(w["loai"] == "loc" for w in waits),
            "khoang_may_lon_nhat_giay": round(gap[0]),
            "khoang_may_lon_nhat": [gap[1].isoformat(timespec="seconds"), gap[2].isoformat(timespec="seconds")]}


# ---------------------------------------------------------------- ④ và ◆

def _calls(k4: dict) -> list[dict]:
    """Mỗi lời gọi ④ một dòng: vòng thường ghi một log; vòng pivot ghi `chi_tiet` theo từng thực thể (s8_pivot)."""
    if "chi_tiet" in k4:
        return k4["chi_tiet"]
    return [k4]


def khau4(run: Path) -> dict:
    tho = giu = lo = lo_sai = bo_lo = vong = khong_proposal = 0
    bo, sua, la = Counter(), Counter(), Counter()
    duyet, tu_choi = Counter(), Counter()
    for rd in _rounds(run):
        p = rd / "agent_proposal.json"
        if not p.exists():
            khong_proposal += 1
            continue
        vong += 1
        for c in _calls(_json(p).get("khau4") or {}):
            if c.get("ly_do_bo"):              # thực thể pivot bị bỏ trước khi có đầu ra (từ chối, hết ngân sách)
                bo_lo += 1
                continue
            lo += 1
            ms = {k: int(v) for k, v in (c.get("ma_sua") or {}).items() if int(v)}
            tho += int(c.get("so_muc_tho") or 0)
            giu += int(c.get("so_gia_thuyet") or 0)
            lo_sai += int(LO_SAI in ms)
            for k, v in ms.items():
                if k in BO_CAU_TRUC or k.startswith("rang_buoc_") or k in BO_KHAC:
                    bo[k] += v
                elif k in SUA_GIU:
                    sua[k] += v
                elif k != LO_SAI:
                    la[k] += v
        a = rd / "approval_log.json"
        if a.exists():
            log = _json(a)
            duyet.update({k: int(v) for k, v in (log.get("dem") or {}).items()})
            for q in (log.get("quyet_dinh") or {}).values():
                if q.get("quyet_dinh") == "rejected":
                    # Mã đứng trước dấu hai chấm, có thể nhiều mã một mục: đếm mỗi mã một lần (như bảng chiến dịch 08/10).
                    head = (q.get("ly_do") or "").split(":", 1)[0]
                    tu_choi.update([m for m in MA_G0D if m in head] or ["khong_ma"])
    loi_ct = sum(v for k, v in bo.items() if k not in BO_KHAC)
    return {"so_vong_co_khau4": vong, "so_vong_khong_co_de_xuat": khong_proposal,
            "so_lo": lo, "so_lo_sai_luoc_do": lo_sai, "so_lo_bo_truoc_dau_ra": bo_lo,
            "so_muc_tho": tho, "so_muc_du_thanh_phan": tho - loi_ct, "so_gia_thuyet_giu": giu,
            "bo_theo_ly_do": dict(bo), "sua_tren_muc_giu": dict(sua), "ma_la": dict(la),
            "duyet": {k: duyet.get(k, 0) for k in ("approved", "rejected", "pending_review")},
            "tu_choi_theo_ma": dict(tu_choi)}


# ---------------------------------------------------------------- ⑤

def _rule_rows(rd: Path) -> tuple[list[dict], str]:
    e = rd / "agent_execute.json"
    if e.exists():
        return _json(e)["rules"], "agent_execute.json"
    rows = []
    for rv in _reviews(rd)[:1]:
        m = rv / "manifest.json"
        if m.exists():
            rows = [{"hypothesis_id": r["hypothesis_id"], "hop_le": r["hop_le"], "so_lan_sua": r["so_lan_sua"],
                     "loi": r["lan_thu"][-1]["loi"] if r.get("lan_thu") else []}
                    for r in _json(m)["context"].get("rule_log") or []]
    return rows, ("manifest.json" if rows else "")


def _interrupted_rows(run: Path, done: set[str]) -> list[dict]:
    """Giả thuyết đã duyệt ở vòng bị ngắt chưa có nhật ký ⑤ (`su_co.json` của ghi_record_luot_ngat.py)."""
    p = run / "su_co.json"
    if not p.exists():
        return []
    rows = []
    for m in _json(p).get("gia_thuyet_da_duyet_chua_thuc_thi") or []:
        if m["vong"] in done:
            continue
        if m.get("co_rule_hop_le"):
            req = run / m["vong"] / "khau5_requests.jsonl"
            calls = [json.loads(x) for x in req.read_text(encoding="utf-8").splitlines() if x.strip()] \
                if req.exists() else []
            n = sum(c["hypothesis_id"] == m["hypothesis_id"] for c in calls)
            rows.append({"hypothesis_id": m["hypothesis_id"], "hop_le": True, "so_lan_sua": max(0, n - 1),
                         "loi": [], "luot_ngat": True})
        else:
            rows.append({"hypothesis_id": m["hypothesis_id"], "hop_le": False, "so_lan_sua": 0,
                         "loi": [{"kind": "luot_ngat"}], "luot_ngat": True})
    return rows


def khau5(run: Path) -> dict:
    c = Counter()
    loi_cuoi = Counter()
    nguon = Counter()
    rows_all, done = [], set()
    for rd in _rounds(run):
        rows, src = _rule_rows(rd)
        if src:
            nguon[src] += 1
            done.add(rd.name)
        rows_all += rows
    extra = _interrupted_rows(run, done)
    if extra:
        nguon["su_co.json"] += len(extra)
    for r in rows_all + extra:
        c["tong"] += 1
        c["luot_ngat"] += bool(r.get("luot_ngat"))
        if r["hop_le"] and int(r["so_lan_sua"]) == 0:
            c["hop_le_lan_dau"] += 1
        elif r["hop_le"]:
            c["hop_le_sau_sua"] += 1
        else:
            kinds = [i["kind"] for i in r.get("loi") or []]
            loi_cuoi.update(kinds)
            if "luot_ngat" in kinds:
                c["luot_ngat_chua_co_rule"] += 1
            elif any(k in KHONG_GOI for k in kinds):
                c["khong_goi_mo_hinh"] += 1
            elif "mo_hinh_tu_choi" in kinds:
                c["mo_hinh_tu_choi"] += 1
            elif "nguon_khong_co_su_kien" in kinds:
                c["dung_sua_nguon_rong"] += 1
            else:
                c["loi_tinh_con_lai"] += 1
        if int(r["so_lan_sua"]) > 0:
            c["so_rule_co_sua"] += 1
            c["so_lan_sua"] += int(r["so_lan_sua"])
    keys = ("tong", "hop_le_lan_dau", "hop_le_sau_sua", "khong_goi_mo_hinh", "mo_hinh_tu_choi",
            "dung_sua_nguon_rong", "loi_tinh_con_lai", "luot_ngat_chua_co_rule", "luot_ngat", "so_rule_co_sua",
            "so_lan_sua")
    return {**{k: c.get(k, 0) for k in keys}, "loi_cuoi": dict(loi_cuoi), "nguon": dict(nguon)}


# ---------------------------------------------------------------- ⑦ mục loại trừ

def nhom_ty_le(removed: int, candidates: int) -> str:
    if candidates <= 0:
        return "khong_co_ung_vien"
    r = removed / candidates
    if removed == 0:
        return "0"
    if r < 0.5:
        return "<50%"
    if r < 0.9:
        return "50–<90%"
    if r < 1:
        return "90–<100%"
    return "100%"


NHOM = ("khong_co_ung_vien", "0", "<50%", "50–<90%", "90–<100%", "100%")


def loc(run: Path) -> dict:
    """Mục loại trừ do ⑤ sinh. Có cổng duyệt (v2): đọc phiếu và preview; không cổng (tuyến A): đọc stage `sau_*`."""
    items: dict[str, dict] = {}
    co_cong = False
    for rd in _rounds(run):
        reviews = _reviews(rd)
        if reviews:
            co_cong = True
            for rv in reviews:            # bản sau ghi đè quyết định bản trước cho cùng mục
                pv, log = rv / "preview.json", rv / "approval_log.json"
                matched = {}
                if pv.exists():
                    for h in _json(pv):
                        for f in h.get("filters") or []:
                            matched[f"{h['hunt_id']}__{f['id']}"] = (int(f.get("matched") or 0),
                                                                    int(h.get("candidates") or 0))
                if log.exists():
                    for q in _json(log).get("quyet_dinh") or []:
                        m, cand = matched.get(q["id"], (0, 0))
                        items[f"{rd.name}/{q['id']}"] = {
                            "vong": rd.name, "id": q["id"], "quyet_dinh": q["quyet_dinh"], "loai": m, "ung_vien": cand,
                            "nhom": nhom_ty_le(m, cand),
                            "ma_ly_do": [c for c in MA_LY_DO if c in (q.get("ly_do") or "")]}
            continue
        e = rd / "agent_execute.json"
        if not e.exists():
            continue
        for o in _json(e)["observations"]:
            st = o["stages"]
            cand = next((s["hits"] for s in st if s["stage"] == "ung_vien"), 0)
            prev = cand
            for s in st:
                if s["stage"].startswith("sau_"):
                    fid = s["stage"][4:]
                    removed = prev - int(s["hits"])
                    items[f"{rd.name}/{o['hunt_id']}__{fid}"] = {
                        "vong": rd.name, "id": f"{o['hunt_id']}__{fid}", "quyet_dinh": "ap_tu_dong",
                        "loai": removed, "ung_vien": cand, "nhom": nhom_ty_le(removed, cand), "ma_ly_do": []}
                    prev = int(s["hits"])
    rows = list(items.values())
    return {"co_cong_duyet": co_cong, "so_muc": len(rows),
            "theo_quyet_dinh": dict(Counter(r["quyet_dinh"] for r in rows)),
            "theo_nhom_ty_le": {g: sum(r["nhom"] == g for r in rows) for g in NHOM},
            "ap_dung_theo_nhom": {g: sum(r["nhom"] == g and r["quyet_dinh"] in ("approved", "ap_tu_dong")
                                         for r in rows) for g in NHOM},
            "tu_choi_theo_ma": dict(Counter(c for r in rows if r["quyet_dinh"] == "rejected" for c in r["ma_ly_do"])),
            "tu_choi_khong_ma": sum(r["quyet_dinh"] == "rejected" and not r["ma_ly_do"] for r in rows),
            "muc": rows}


# ---------------------------------------------------------------- tổng hợp

def summarize(runs: list[dict]) -> dict:
    out = {}
    for r in runs:
        r["thoi_gian"] = times(r["path"])
        r["khau4"] = khau4(r["path"])
        r["khau5"] = khau5(r["path"])
        r["loc"] = loc(r["path"])
        r["su_co"] = (r["path"] / "su_co.json").exists()
    for tuyen in DOT:
        for mode in ("pipeline", "agent"):
            g = [r for r in runs if r["tuyen"] == tuyen and r["mode"] == mode and r["tinh"]]
            if not g:
                continue
            t = [r["thoi_gian"] for r in g]
            def med(k):
                vals = [x[k] for x in t if x[k] is not None]
                return {"trung_vi": statistics.median(vals), "nho_nhat": min(vals), "lon_nhat": max(vals)} if vals else None
            k4 = Counter()
            for r in g:
                for k in ("so_muc_tho", "so_muc_du_thanh_phan", "so_gia_thuyet_giu", "so_lo", "so_lo_sai_luoc_do",
                          "so_lo_bo_truoc_dau_ra", "so_vong_co_khau4", "so_vong_khong_co_de_xuat"):
                    k4[k] += r["khau4"][k]
                for k, v in r["khau4"]["duyet"].items():
                    k4["duyet_" + k] += v
            tc = sum((Counter(r["khau4"]["tu_choi_theo_ma"]) for r in g), Counter())
            k5 = Counter()
            for r in g:
                k5.update({k: v for k, v in r["khau5"].items() if isinstance(v, int)})
            lc = Counter()
            ap = Counter()
            for r in g:
                lc.update(r["loc"]["theo_nhom_ty_le"])
                ap.update(r["loc"]["ap_dung_theo_nhom"])
            out[f"{tuyen}/{mode}"] = {
                "so_luot": len(g), "luot": [r["id"] for r in g], "luot_su_co": [r["id"] for r in g if r["su_co"]],
                "thoi_gian": {k: med(k) for k in ("toan_trinh_giay", "may_giay", "cho_duyet_giay",
                                                  "toi_gia_thuyet_dau_giay")},
                "khau4": {**k4, "tu_choi_theo_ma": dict(tc)}, "khau5": dict(k5),
                "loc": {"so_muc": sum(r["loc"]["so_muc"] for r in g),
                        "theo_quyet_dinh": dict(sum((Counter(r["loc"]["theo_quyet_dinh"]) for r in g), Counter())),
                        "theo_nhom_ty_le": {k: lc.get(k, 0) for k in NHOM},
                        "ap_dung_theo_nhom": {k: ap.get(k, 0) for k in NHOM},
                        "tu_choi_theo_ma": dict(sum((Counter(r["loc"]["tu_choi_theo_ma"]) for r in g), Counter())),
                        "tu_choi_khong_ma": sum(r["loc"]["tu_choi_khong_ma"] for r in g)}}
    return out


def _phut(s) -> str:
    return "—" if s is None else f"{s / 60:.1f}"


def markdown(runs: list[dict], groups: dict) -> str:
    L = ["# Chỉ số theo khâu từ các lượt đánh giá đã lưu (không nhãn)", "",
         "Sinh bởi `scripts/tong_hop_chi_so_khau.py`; chỉ đọc thư mục lượt, không nhãn, không API. "
         "Nhóm chỉ gồm lượt được tính; lượt phụ lục liệt kê riêng ở bảng chi tiết.", "",
         "## Vận hành (phút; trung vị [nhỏ nhất–lớn nhất])", "",
         "| Nhóm | Lượt | Toàn trình | Máy | Chờ duyệt | Tới giả thuyết đầu |", "|---|---|---|---|---|---|"]
    for k, g in groups.items():
        t = g["thoi_gian"]
        cell = lambda x: "—" if not x else f"{_phut(x['trung_vi'])} [{_phut(x['nho_nhat'])}–{_phut(x['lon_nhat'])}]"
        L.append(f"| {k} | {g['so_luot']} | {cell(t['toan_trinh_giay'])} | {cell(t['may_giay'])} | "
                 f"{cell(t['cho_duyet_giay'])} | {cell(t['toi_gia_thuyet_dau_giay'])} |")
    L += ["", "## ④ đủ thành phần và ◆", "",
          "| Nhóm | Lời gọi ④ | Sai lược đồ cả lô | Mục thô | Đủ thành phần | Giữ | Duyệt | Từ chối | Chờ |",
          "|---|---|---|---|---|---|---|---|---|"]
    for k, g in groups.items():
        a = g["khau4"]
        L.append(f"| {k} | {a.get('so_lo', 0)} | {a.get('so_lo_sai_luoc_do', 0)} | {a.get('so_muc_tho', 0)} | "
                 f"{a.get('so_muc_du_thanh_phan', 0)} | {a.get('so_gia_thuyet_giu', 0)} | {a.get('duyet_approved', 0)} | "
                 f"{a.get('duyet_rejected', 0)} | {a.get('duyet_pending_review', 0)} |")
    L += ["", "Từ chối ở ◆ theo mã G0(d):", ""]
    for k, g in groups.items():
        tc = g["khau4"]["tu_choi_theo_ma"]
        L.append(f"- {k}: " + (", ".join(f"{m} {n}" for m, n in sorted(tc.items())) or "—"))
    L += ["", "## ⑤ rule hợp lệ", "",
          "| Nhóm | Giả thuyết đã duyệt | Hợp lệ lần đầu | Hợp lệ sau sửa | Không gọi mô hình | Từ chối | "
          "Dừng sửa (nguồn rỗng) | Lỗi tĩnh còn lại | Lượt ngắt, chưa có rule |",
          "|---|---|---|---|---|---|---|---|---|"]
    for k, g in groups.items():
        b = g["khau5"]
        L.append(f"| {k} | {b.get('tong', 0)} | {b.get('hop_le_lan_dau', 0)} | {b.get('hop_le_sau_sua', 0)} | "
                 f"{b.get('khong_goi_mo_hinh', 0)} | {b.get('mo_hinh_tu_choi', 0)} | {b.get('dung_sua_nguon_rong', 0)} | "
                 f"{b.get('loi_tinh_con_lai', 0)} | {b.get('luot_ngat_chua_co_rule', 0)} |")
    L += ["", "## ⑦ mục loại trừ do ⑤ sinh — tỷ lệ ứng viên bị loại", "",
          "| Nhóm | Mục | Quyết định | " + " | ".join(NHOM) + " | Áp dụng ≥90% | Từ chối theo mã |",
          "|---|---|---|" + "---|" * len(NHOM) + "---|---|"]
    for k, g in groups.items():
        c = g["loc"]
        ap90 = c["ap_dung_theo_nhom"]["90–<100%"] + c["ap_dung_theo_nhom"]["100%"]
        ma = ", ".join(f"{m} {n}" for m, n in sorted(c["tu_choi_theo_ma"].items())) or "—"
        qd = ", ".join(f"{m} {n}" for m, n in sorted(c["theo_quyet_dinh"].items())) or "—"
        L.append(f"| {k} | {c['so_muc']} | {qd} | " + " | ".join(str(c["theo_nhom_ty_le"][x]) for x in NHOM)
                 + f" | {ap90} | {ma}; không mã {c['tu_choi_khong_ma']} |")
    L += ["", "## Chi tiết từng lượt", "",
          "| Lượt | Tính | Toàn trình | Máy | Chờ | Tới GT đầu | Khoảng máy lớn nhất (giây) | ④ thô/đủ/giữ | ⑤ rule/đầu/sau | Mục lọc | Sự cố |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        t, a, b = r["thoi_gian"], r["khau4"], r["khau5"]
        L.append(f"| {r['tuyen']}/{r['mode']}/{r['id']} | {'có' if r['tinh'] else 'phụ lục'} | "
                 f"{_phut(t['toan_trinh_giay'])} | {_phut(t['may_giay'])} | {_phut(t['cho_duyet_giay'])} | "
                 f"{_phut(t['toi_gia_thuyet_dau_giay'])} | {t['khoang_may_lon_nhat_giay']} | "
                 f"{a['so_muc_tho']}/{a['so_muc_du_thanh_phan']}/{a['so_gia_thuyet_giu']} | "
                 f"{b['tong']}/{b['hop_le_lan_dau']}/{b['hop_le_sau_sua']} | {r['loc']['so_muc']} | "
                 f"{'có' if r['su_co'] else ''} |")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    if "labels" in a.root.resolve().parts or "labels" in a.out.resolve().parts:
        print("từ chối: đường dẫn nằm trong thư mục nhãn", file=sys.stderr)
        return 2
    runs = discover(a.root)
    if not runs:
        print(f"không tìm thấy lượt nào dưới {a.root}", file=sys.stderr)
        return 1
    groups = summarize(runs)
    a.out.mkdir(parents=True, exist_ok=True)
    data = {"nguon": str(a.root), "nhom": groups,
            "luot": [{k: (str(v) if isinstance(v, Path) else v) for k, v in r.items()} for r in runs]}
    (a.out / "chi_so_khau.json").write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n",
                                            encoding="utf-8")
    (a.out / "chi_so_khau.md").write_text(markdown(runs, groups), encoding="utf-8")
    print(f"{len(runs)} lượt → {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
