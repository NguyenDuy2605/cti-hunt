"""Câu hỏi 2, hướng 2: lập danh sách tệp log cần tải từ Splunk attack_data (ghim commit), chỉ log Windows Sysmon và Security.

Không tải log: chỉ đọc cây tệp (một lời gọi API), các tệp YAML mô tả và con trỏ Git LFS (vài trăm byte mỗi tệp) để lấy mã băm
SHA256 và dung lượng thật. Kết quả là danh sách cố định (ghi trước khi tải), để ``attack_data_tai.py`` tải đúng các tệp đó và
kiểm băm.

Chọn tệp (``docs/METHODOLOGY.md``, Q1): mục ``datasets`` trong YAML của
``datasets/attack_techniques/**`` có ``sourcetype`` dạng XML (``XmlWinEventLog``) và ``source`` là Sysmon/Operational hoặc
Security. Kỹ thuật lấy từ ``mitre_technique`` của YAML.

    .venv/Scripts/python.exe -X utf8 scripts/attack_data_lap_danh_sach.py --commit <sha> --cay <tree.json> --out <tệp .json>
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

RAW = "https://raw.githubusercontent.com/splunk/attack_data/{commit}/{path}"
NGUON = {"xmlwineventlog:microsoft-windows-sysmon/operational": "sysmon", "xmlwineventlog:security": "security"}


def _get(url: str, n: int = 4) -> bytes:
    last = None
    for _ in range(n):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 — thử lại lỗi mạng tạm thời
            last = e
    raise RuntimeError(f"không tải được {url}: {last}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--commit", required=True)
    ap.add_argument("--cay", required=True, help="kết quả gh api repos/splunk/attack_data/git/trees/<sha>?recursive=1")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    tree = json.loads(Path(a.cay).read_text(encoding="utf-8"))
    assert not tree["truncated"]
    files = {x["path"] for x in tree["tree"] if x["type"] == "blob"}
    ymls = sorted(p for p in files if p.startswith("datasets/attack_techniques/") and p.endswith((".yml", ".yaml")))
    with ThreadPoolExecutor(8) as ex:
        docs = list(ex.map(lambda p: (p, _get(RAW.format(commit=a.commit, path=p))), ymls))
    chon, bo = [], {"khong_doc_duoc_yaml": 0, "khong_phai_sysmon_security_xml": 0, "khong_co_tep": 0}
    for p, raw in docs:
        try:
            d = yaml.safe_load(raw.decode("utf-8", "replace"))
        except yaml.YAMLError:
            bo["khong_doc_duoc_yaml"] += 1
            continue
        if not isinstance(d, dict):
            bo["khong_doc_duoc_yaml"] += 1
            continue
        kt = [str(t).upper() for t in (d.get("mitre_technique") or [])]
        for ds in d.get("datasets") or []:
            src = str(ds.get("source", "")).lower()
            loai = NGUON.get(src)
            if loai is None or "xml" not in str(ds.get("sourcetype", "")).lower():
                bo["khong_phai_sysmon_security_xml"] += 1
                continue
            path = str(ds.get("path", "")).lstrip("/")
            if path not in files:
                bo["khong_co_tep"] += 1
                continue
            chon.append({"yaml": p, "ky_thuat": kt, "ten": ds.get("name"), "duong_dan": path, "loai": loai,
                         "mo_ta": str(d.get("description", ""))[:500], "moi_truong": d.get("environment")})
    seen, uniq = set(), []
    for c in chon:                       # một tệp có thể được nhiều YAML nhắc tới: giữ một mục, gộp kỹ thuật
        if c["duong_dan"] in seen:
            next(u for u in uniq if u["duong_dan"] == c["duong_dan"])["ky_thuat"] = sorted(
                set(next(u for u in uniq if u["duong_dan"] == c["duong_dan"])["ky_thuat"]) | set(c["ky_thuat"]))
            continue
        seen.add(c["duong_dan"])
        uniq.append(c)

    def con_tro(c):
        raw = _get(RAW.format(commit=a.commit, path=c["duong_dan"])).decode("utf-8", "replace")
        oid = re.search(r"oid sha256:([0-9a-f]{64})", raw)
        size = re.search(r"size (\d+)", raw)
        return {**c, "lfs": bool(oid), "sha256": oid.group(1) if oid else None, "kich_thuoc": int(size.group(1)) if size else len(raw)}

    with ThreadPoolExecutor(8) as ex:
        uniq = list(ex.map(con_tro, uniq))
    ky_thuat = sorted({k for c in uniq for k in c["ky_thuat"]})
    out = {"nguon": "https://github.com/splunk/attack_data", "giay_phep": "Apache-2.0", "commit": a.commit,
           "so_yaml": len(ymls), "bo_qua": bo, "so_tep": len(uniq), "so_ky_thuat": len(ky_thuat),
           "tong_byte": sum(c["kich_thuoc"] for c in uniq),
           "theo_loai": {l: {"tep": sum(c["loai"] == l for c in uniq), "byte": sum(c["kich_thuoc"] for c in uniq if c["loai"] == l)}
                         for l in ("sysmon", "security")},
           "tep": uniq}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "tep"}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
