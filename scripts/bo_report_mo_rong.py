"""Bộ report mở rộng cho câu hỏi 1 (TTP) theo giao thức đặt trước `docs/METHODOLOGY.md` bản 2.

Không gọi API mô hình, không đọc nhãn sự kiện, không đọc Silver. Hai bước:

- ``chon``: dựng danh sách ứng viên từ ATT&CK v19.2 (giao thức §2–3), sắp theo ``source_name`` rồi trộn bằng
  ``random.Random(20261016)``; ghi ``ung_vien.json`` (thứ tự, URL, năm, số kỹ thuật đáp án). Không tải gì.
- ``tai``: đi lần lượt theo thứ tự, tải và đọc bằng ``s1_ingest.ingest`` (như lệnh ``ingest-report``, không selector), nhận nếu
  ``s2_report.prepare`` dựng được đoạn mục tiêu và văn bản mục tiêu từ 2.000 ký tự; dừng khi nhận 30 hoặc đã thử 60. Ghi
  ``nhat_ky_tai.json`` sau mỗi report (chạy lại thì bỏ qua report đã thử).

    .venv/Scripts/python.exe -X utf8 scripts/bo_report_mo_rong.py chon --out <thư mục>
    .venv/Scripts/python.exe -X utf8 scripts/bo_report_mo_rong.py tai --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS  # noqa: E402
from do_ttp_mitre import STIX  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.stages import s1_ingest, s2_report  # noqa: E402

HAT_GIONG = 20261016
NAM_TU = 2021
KY_THUAT_TOI_THIEU = 10
NHAN_TOI_DA, THU_TOI_DA, KY_TU_TOI_THIEU = 30, 60, 2000
TEN_MIEN_LOAI = ("twitter.com", "x.com", "github.com", "attack.mitre.org", "wikipedia.org", "youtube.com")


def nam_xuat_ban(source_name: str, description: str) -> int | None:
    """Giao thức §3 điều 3: năm trong cặp ngoặc đầu tiên của description; không có thì năm lớn nhất trong source_name."""
    m = re.search(r"\(\s*((?:19|20)\d\d)\b", description or "")
    if m:
        return int(m.group(1))
    ys = [int(y) for y in re.findall(r"\b((?:19|20)\d\d)\b", source_name or "")]
    return max(ys) if ys else None


def ung_vien(stix: dict) -> list[dict]:
    by_id = {o["id"]: o for o in stix["objects"]}
    techs: dict[str, set[str]] = {}
    ref: dict[str, dict] = {}
    for o in stix["objects"]:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        t = by_id.get(o.get("target_ref", ""))
        if not t or t.get("type") != "attack-pattern" or t.get("revoked") or t.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in t.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        for r in o.get("external_references", []) or []:
            s = r.get("source_name")
            if tid and s:
                techs.setdefault(s, set()).add(tid)
                ref.setdefault(s, r)
    da_dung = {v[1] for v in REPORTS.values()}
    out = []
    for s in sorted(techs):
        r = ref[s]
        url = r.get("url") or ""
        host = (urlparse(url).hostname or "").lower()
        nam = nam_xuat_ban(s, r.get("description", ""))
        if not url or len(techs[s]) < KY_THUAT_TOI_THIEU or nam is None or nam < NAM_TU or s in da_dung:
            continue
        if any(host == d or host.endswith("." + d) for d in TEN_MIEN_LOAI):
            continue
        out.append({"source_name": s, "url": url, "nam": nam, "so_ky_thuat": len(techs[s]),
                    "dap_an": sorted(techs[s]), "description": r.get("description", "")})
    random.Random(HAT_GIONG).shuffle(out)
    for i, x in enumerate(out, 1):
        x["thu_tu"] = i
    return out


def chon(out: Path) -> int:
    stix = json.loads(config.resolve(STIX).read_text(encoding="utf-8"))
    uv = ung_vien(stix)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ung_vien.json").write_text(json.dumps({"hat_giong": HAT_GIONG, "so_ung_vien": len(uv), "ung_vien": uv},
                                                  ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(uv)} ứng viên; 5 đầu: " + "; ".join(f"{x['thu_tu']}. {x['source_name']}" for x in uv[:5]))
    return 0


def tai(out: Path) -> int:
    uv = json.loads((out / "ung_vien.json").read_text(encoding="utf-8"))["ung_vien"]
    log_path = out / "nhat_ky_tai.json"
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else []
    da_thu = {x["source_name"] for x in log}
    for x in uv:
        nhan = sum(1 for e in log if e["ket_qua"] == "nhan")
        if nhan >= NHAN_TOI_DA or len(log) >= THU_TOI_DA:
            break
        if x["source_name"] in da_thu:
            continue
        rid = f"RM-{x['thu_tu']:03d}"
        bundle = out / "bundles" / rid
        e = {"thu_tu": x["thu_tu"], "ma": rid, "source_name": x["source_name"], "url": x["url"], "nam": x["nam"],
             "so_ky_thuat": x["so_ky_thuat"]}
        try:
            manifest = s1_ingest.ingest(x["url"], rid, bundle, None)
            e.update(trang_thai_doc=manifest.get("status"), canh_bao=manifest.get("warnings", []))
            _, requests = s2_report.prepare(bundle, config.resolve(STIX), config.resolve("prompts/khau2_ttp_v2.md"), {},
                                            top_k=8)
            texts = [t["text"] for r in requests for t in json.loads(r["user"])["targets"]]
            n = sum(len(t) for t in texts)
            e.update(so_doan=len(texts), so_ky_tu=n)
            e["ket_qua"] = "nhan" if n >= KY_TU_TOI_THIEU else "loai"
            if e["ket_qua"] == "loai":
                e["ly_do"] = f"văn bản mục tiêu {n} ký tự < {KY_TU_TOI_THIEU}"
        except Exception as exc:  # noqa: BLE001 — mọi lỗi tải/đọc là lý do loại, ghi nguyên văn
            e.update(ket_qua="loai", ly_do=f"{type(exc).__name__}: {str(exc)[:300]}")
        log.append(e)
        log_path.write_text(json.dumps(log, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"{rid} {e['ket_qua']:4s} {x['source_name']}" + (f" — {e.get('ly_do')}" if e["ket_qua"] == "loai" else
                                                                f" ({e['so_doan']} đoạn, {e['so_ky_tu']} ký tự)"))
    nhan = sum(1 for e in log if e["ket_qua"] == "nhan")
    print(f"Đã thử {len(log)}, nhận {nhan}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("lenh", choices=["chon", "tai"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    return chon(Path(a.out)) if a.lenh == "chon" else tai(Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
