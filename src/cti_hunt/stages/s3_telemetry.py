"""Khâu ③ — Telemetry Mapping bằng tra bảng, không dùng mô hình ngôn ngữ.

Hai phần:

- Danh mục chung configs/telemetry_catalog.yaml: kỹ thuật -> trạng thái khi thu thập đủ nguồn, mọi nguồn log có thể
  dùng (channel + EventID), trường khóa, trường bắt buộc, lý do partial, ghi chú chung. Không số đếm, không câu về
  một bộ dữ liệu, không dẫn chiếu báo cáo: `load_catalog` từ chối.
- Hồ sơ theo bộ dữ liệu (`build_profile`): sinh từ `events` của chính bộ đang chạy, gắn dataset_id. M1: huntable nghĩa
  là log được thu thập, không phải có sự kiện. Nguồn chỉ bị bỏ khi kênh không có mặt trong bộ dữ liệu, hoặc nguồn có
  sự kiện mà trường bắt buộc không có giá trị ở sự kiện nào; mã sự kiện chưa có sự kiện nào trong kênh đã thu thập vẫn
  giữ. Kỹ thuật chỉ thành not_huntable khi mọi nguồn của nó bị bỏ.

`apply_profile` ghép hai phần thành danh mục hiệu lực cùng dạng với danh mục chung, dùng cho prompt ④, ④ pivot, view
của planner và hunt record ⑨. G0(b), chốt 26/9: key_fields của nguồn được giữ bỏ các trường đã xác nhận rỗng;
nguồn 0 sự kiện chưa kiểm được thì giữ trường. M2: dòng hồ sơ trong ghi chú chỉ nói kênh nào có/không thu thập và trường khóa nào không
có giá trị — không có số sự kiện; số đếm chỉ nằm trong JSON hồ sơ và run_meta để truy vết.

Ghi chú đi vào prompt khâu ④ và hunt record bản vận hành, nên không được mang mã bước tấn công của ground truth
(11.A–20.B): mô hình và người duyệt không bao giờ thấy nhãn (docs/METHODOLOGY.md §4.2, §4.5).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

STATUSES = ("huntable", "partial", "not_huntable")
STEP_ID = re.compile(r"\b(?:1[1-9]|20)\.[A-D]\b")
PROFILE_VERSION = "ho_so_v1"
PROFILE_FILE = "ho_so_du_lieu.json"
NOTE_FIELDS = ("ghi_chu", "ly_do_partial")

# Phần chung của danh mục: không số đếm ("4697 = 18", "716 sự kiện", "chỉ 18"), không câu về một bộ dữ liệu, không dẫn
# chiếu báo cáo (v3 §…). Mã sự kiện ("Sysmon 1", "4104") vẫn được phép.
_COUNT = re.compile(r"=\s*\d|\d[\d.,]*\s*sự kiện|\bchỉ\s+\d", re.IGNORECASE)
_DATASET = re.compile(r"tập dữ liệu|bộ dữ liệu|dataset|trong dữ liệu", re.IGNORECASE)
_REPORT_REF = re.compile(r"§|\bv3(?:\.\d+)?\b", re.IGNORECASE)


def _check_note(tid: str, key: str, text: str) -> None:
    if STEP_ID.search(text):
        raise ValueError(f"{tid}: {key} có mã bước tấn công — thông tin suy từ nhãn không được vào prompt "
                         "khâu ④ hay hunt record")
    for pattern, what in ((_COUNT, "số đếm sự kiện"), (_DATASET, "câu về một bộ dữ liệu"),
                          (_REPORT_REF, "dẫn chiếu báo cáo")):
        if pattern.search(text):
            raise ValueError(f"{tid}: {key} có {what} — danh mục chỉ giữ phần chung; phần theo bộ dữ liệu do hồ sơ "
                             "sinh từ events")


def load_catalog(path: Path) -> dict[str, dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    techniques = data.get("techniques") or {}
    for tid, entry in techniques.items():
        if entry.get("status") not in STATUSES:
            raise ValueError(f"{tid}: status phải thuộc {STATUSES}")
        for key in NOTE_FIELDS:
            _check_note(tid, key, str(entry.get(key) or ""))
        if entry["status"] == "partial" and not str(entry.get("ly_do_partial") or "").strip():
            raise ValueError(f"{tid}: TTP partial cần ly_do_partial (lý do chung vì sao chỉ săn được một phần)")
        for src in entry.get("sources") or []:
            if not src.get("channel") or not src.get("event_ids"):
                raise ValueError(f"{tid}: mỗi nguồn log cần channel và event_ids (mã sự kiện đi kèm channel)")
            keys = {f.lower() for f in src.get("key_fields") or []}
            required = src.get("truong_bat_buoc") or []
            if not required or not {f.lower() for f in required} <= keys:
                raise ValueError(f"{tid}: nguồn {src['channel']} {src['event_ids']} cần truong_bat_buoc khác rỗng, "
                                 "nằm trong key_fields")
    return techniques


# Sysmon event types whose record carries `ProcessGuid` (100% non-empty in the seven OTRF development sets, 07/10).
# 8 and 10 use Source/TargetProcessGuid and 4/6/16/19–21 have no process: not touched.
SYSMON = "microsoft-windows-sysmon/operational"
PROCESS_GUID_EIDS = frozenset({1, 2, 3, 5, 7, 9, 11, 12, 13, 14, 15, 17, 18, 22, 23})


def add_process_guid(doc: dict, version: str) -> dict:
    """Catalog v2.1: v2 plus `ProcessGuid` in key_fields of Sysmon sources whose event types carry it,
    so a "same process" multi-event constraint can pass ④'s field check. Not a required field: G0(b) still drops it
    on a dataset where it is empty. Everything else is copied unchanged."""
    out = json.loads(json.dumps(doc))
    out["phien_ban"] = version
    for entry in out["techniques"].values():
        for src in entry.get("sources") or []:
            if (src["channel"] == SYSMON and set(src["event_ids"]) <= PROCESS_GUID_EIDS
                    and "processguid" not in {f.lower() for f in src.get("key_fields") or []}):
                src["key_fields"] = [*(src.get("key_fields") or []), "ProcessGuid"]
    return out


def map_technique(tid: str, catalog: dict[str, dict]) -> dict:
    tid = tid.strip().upper()
    entry = catalog.get(tid) or catalog.get(tid.split(".")[0])
    if entry is None:            # cha không có mục riêng: nhận nếu có mục con nào của cùng cha
        kin = [v for k, v in catalog.items() if k.split(".")[0] == tid.split(".")[0]]
        entry = kin[0] if len(kin) == 1 else None
    if entry is None:
        return {"technique_id": tid, "status": "not_huntable", "ly_do": "không có trong danh mục nguồn log"}
    return {"technique_id": tid, **entry}


# ---------- hồ sơ theo bộ dữ liệu ----------

def _source_row(con, cols: dict[str, str], kenh: dict[str, int], src: dict) -> dict:
    ch, eids = src["channel"], list(src["event_ids"])
    fields = list(src.get("key_fields") or [])
    collected = kenh.get(ch.lower(), 0) > 0
    n, missing = 0, []
    if collected:
        present = [f for f in fields if f.lower() in cols]
        agg = "".join(f", count(NULLIF(trim(CAST(\"{cols[f.lower()]}\" AS VARCHAR)), ''))" for f in present)
        row = con.execute(f"SELECT count(*){agg} FROM events WHERE ev_channel = ? AND ev_eid IN "
                          f"({', '.join(str(int(x)) for x in eids)})", [ch]).fetchone()
        n = int(row[0])
        if n:    # chỉ kiểm được trường khi nguồn có sự kiện; 0 sự kiện trong kênh đã thu thập thì giữ (M1)
            filled = dict(zip(present, row[1:]))
            missing = [f for f in fields if not filled.get(f)]
    required = {f.lower() for f in src.get("truong_bat_buoc") or []}
    lost = [f for f in missing if f.lower() in required]
    reason = "" if collected and not lost else ("kenh_khong_thu_thap" if not collected else "thieu_truong_bat_buoc")
    return {"channel": ch, "event_ids": eids, "kenh_thu_thap": collected, "so_su_kien": n, "da_kiem_truong": n > 0,
            "truong_khong_co_gia_tri": missing, "giu": not reason, "ly_do_bo": reason}


def build_profile(con, catalog: dict[str, dict], dataset_id: str) -> dict:
    """Hồ sơ của bộ dữ liệu trên view `events`: kênh nào được thu thập, nguồn nào giữ/bỏ, trường khóa nào không có giá
    trị. Xác định: cùng events + cùng danh mục thì cùng hồ sơ (không có thời điểm), để SHA256 kiểm được khi resume."""
    if not str(dataset_id or "").strip():
        raise ValueError("hồ sơ bộ dữ liệu cần dataset_id")
    cols = {r[0].lower(): r[0] for r in con.execute("DESCRIBE events").fetchall()}
    channels = sorted({s["channel"] for e in catalog.values() for s in e.get("sources") or []})
    kenh = {str(c).lower(): int(n) for c, n in con.execute(
        "SELECT ev_channel, count(*) FROM events GROUP BY ev_channel").fetchall() if c is not None}
    techniques = {}
    for tid in sorted(catalog):
        entry = catalog[tid]
        rows = [_source_row(con, cols, kenh, s) for s in entry.get("sources") or []]
        status = entry["status"]
        if status != "not_huntable" and rows and not any(r["giu"] for r in rows):
            status = "not_huntable"
        techniques[tid] = {"trang_thai_danh_muc": entry["status"], "trang_thai": status, "nguon": rows}
    return {"phien_ban": PROFILE_VERSION, "dataset_id": dataset_id,
            "kenh": {c: kenh.get(c.lower(), 0) for c in channels}, "ky_thuat": techniques}


def profile_bytes(profile: dict) -> bytes:
    """Dạng ghi file và băm: JSON sắp khóa, LF, UTF-8."""
    return (json.dumps(profile, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def profile_sha256(profile: dict) -> str:
    return hashlib.sha256(profile_bytes(profile)).hexdigest()


def write_profile(profile: dict, directory: Path) -> tuple[Path, str]:
    path = Path(directory) / PROFILE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(profile_bytes(profile))
    return path, profile_sha256(profile)


def profile_note(profile_entry: dict) -> str:
    """Dòng hồ sơ trong ghi chú gửi prompt ④ (M2): kênh có/không thu thập, trường khóa không có giá trị. Không số đếm."""
    rows = profile_entry.get("nguon") or []
    if not rows:
        return ""
    have = sorted({r["channel"] for r in rows if r["kenh_thu_thap"]})
    absent = sorted({r["channel"] for r in rows if not r["kenh_thu_thap"]})
    parts = []
    if have:
        parts.append("có thu thập " + ", ".join(have))
    if absent:
        parts.append("không thu thập " + ", ".join(absent) + " (bỏ nguồn này)")
    for r in rows:
        if r["truong_khong_co_gia_tri"]:
            parts.append(f"{r['channel']} {r['event_ids']} không có giá trị ở trường "
                         + ", ".join(r["truong_khong_co_gia_tri"])
                         + (" (thiếu trường bắt buộc, bỏ nguồn này)" if r["ly_do_bo"] == "thieu_truong_bat_buoc" else ""))
    return "Bộ dữ liệu đang chạy: " + "; ".join(parts) + "."


def apply_profile(catalog: dict[str, dict], profile: dict) -> dict[str, dict]:
    """Danh mục hiệu lực của bộ dữ liệu: bỏ nguồn theo M1, hạ not_huntable khi mọi nguồn bị bỏ, ghép ghi chú
    = lý do partial + ghi chú chung + dòng hồ sơ. G0(b): bỏ trường đã xác nhận rỗng khỏi key_fields, nhưng giữ
    nguyên trường của nguồn chưa có sự kiện để kiểm (M1). Không sửa danh mục chung hay hồ sơ tại chỗ."""
    got = profile.get("ky_thuat") or {}
    if set(got) != set(catalog):
        raise ValueError("hồ sơ bộ dữ liệu lập từ danh mục khác (tập kỹ thuật không khớp)")
    out = {}
    for tid, entry in catalog.items():
        p, sources = got[tid], list(entry.get("sources") or [])
        if [(s["channel"], list(s["event_ids"])) for s in sources] != [(r["channel"], r["event_ids"]) for r in p["nguon"]]:
            raise ValueError(f"{tid}: nguồn trong hồ sơ khác danh mục — lập lại hồ sơ")
        status, line = p["trang_thai"], profile_note(p)
        note = " ".join(x for x in ((entry.get("ly_do_partial") or "").strip() if status == "partial" else "",
                                    str(entry.get("ghi_chu") or "").strip(), line) if x)
        effective_sources = []
        for src, row in zip(sources, p["nguon"]):
            if not row["giu"]:
                continue
            missing = {f.lower() for f in row["truong_khong_co_gia_tri"]} if row["da_kiem_truong"] else set()
            effective_sources.append({**src, "key_fields": [f for f in src.get("key_fields") or []
                                                            if f.lower() not in missing]})
        eff = {**entry, "status": status, "sources": effective_sources, "ghi_chu": note}
        if status == "not_huntable" and entry["status"] != "not_huntable":
            eff["ly_do"] = "Không nguồn nào của kỹ thuật dùng được trên bộ dữ liệu đang chạy. " + line
        out[tid] = eff
    return out
