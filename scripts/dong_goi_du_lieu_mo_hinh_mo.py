"""Đóng gói / giải gói dữ liệu cần để chạy ``trich_ttp_mo_hinh_mo.py`` trên máy khác (dữ liệu không nằm trong git).

Gói gồm đúng những gì script đọc, không có nhãn hay kết quả chạy:
- ``data/attack/enterprise-attack-19.2.json`` (ATT&CK, SHA256 ghim ở ``configs/reports.yaml``);
- bundle đã đọc của 4 report cũ (``do_ttp_bm25_mitre.REPORTS`` có lượt LLM), bỏ thư mục ``extractions``/``extraction``;
- bộ 30 report mở rộng: ``nhat_ky_tai.json``, ``ung_vien.json`` và ``bundles/`` của report được nhận.
Mỗi tệp có SHA256 trong ``MANIFEST.json`` của gói; ``giai`` kiểm lại sau khi giải (tệp bị Defender cách ly sẽ báo thiếu).

    python scripts/dong_goi_du_lieu_mo_hinh_mo.py dong --out <tệp .zip>
    python scripts/dong_goi_du_lieu_mo_hinh_mo.py giai --zip <tệp .zip> --repo <thư mục repo> --bo-mo-rong <thư mục bộ 30>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BO_MO_RONG = Path("../workspace/bo_mo_rong_16-10")
BO_QUA = {"extractions", "extraction"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tep_can(bo_mo_rong: Path) -> list[tuple[Path, str]]:
    """(đường dẫn thật, đường dẫn trong gói). Trong gói: 'repo/...' hoặc 'bo_mo_rong/...'."""
    out = [(REPO / "data/attack/enterprise-attack-19.2.json", "repo/data/attack/enterprise-attack-19.2.json")]
    for bundle, _, llm_case in REPORTS.values():
        if not llm_case:
            continue
        root = REPO / bundle
        for f in sorted(root.rglob("*")):
            if f.is_file() and not (set(f.relative_to(root).parts) & BO_QUA):
                out.append((f, f"repo/{bundle}/{f.relative_to(root).as_posix()}"))
    log = json.loads((bo_mo_rong / "nhat_ky_tai.json").read_text(encoding="utf-8"))
    for name in ("nhat_ky_tai.json", "ung_vien.json"):
        out.append((bo_mo_rong / name, f"bo_mo_rong/{name}"))
    for e in log:
        if e["ket_qua"] != "nhan":
            continue
        root = bo_mo_rong / "bundles" / e["ma"]
        for f in sorted(root.rglob("*")):
            if f.is_file():
                out.append((f, f"bo_mo_rong/bundles/{e['ma']}/{f.relative_to(root).as_posix()}"))
    return out


def dong(out: Path, bo_mo_rong: Path) -> int:
    files = tep_can(bo_mo_rong)
    manifest = {}
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for src, arc in files:
            data = src.read_bytes()
            manifest[arc] = _sha(data)
            z.writestr(arc, data)
        z.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=1))
    print(f"{len(files)} tệp → {out} ({out.stat().st_size / 1e6:.1f} MB); SHA256 gói: {_sha(out.read_bytes())}")
    return 0


def giai(zpath: Path, repo: Path, bo_mo_rong: Path) -> int:
    with zipfile.ZipFile(zpath) as z:
        manifest = json.loads(z.read("MANIFEST.json"))
        for arc in manifest:
            dst = (repo / arc[len("repo/"):]) if arc.startswith("repo/") else (bo_mo_rong / arc[len("bo_mo_rong/"):])
            if dst.exists():
                if _sha(dst.read_bytes()) != manifest[arc]:
                    raise SystemExit(f"{dst} đã có nhưng khác nội dung; không ghi đè")
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(z.read(arc))
    thieu, sai = [], []
    for arc, h in manifest.items():
        dst = (repo / arc[len("repo/"):]) if arc.startswith("repo/") else (bo_mo_rong / arc[len("bo_mo_rong/"):])
        if not dst.exists():
            thieu.append(str(dst))
        elif _sha(dst.read_bytes()) != h:
            sai.append(str(dst))
    print(f"{len(manifest)} tệp; thiếu {len(thieu)}, sai SHA256 {len(sai)}")
    for x in (thieu + sai)[:20]:
        print("  ", x)
    return 1 if thieu or sai else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("dong")
    p.add_argument("--out", required=True)
    p.add_argument("--bo-mo-rong", default=str(BO_MO_RONG))
    p = sub.add_parser("giai")
    p.add_argument("--zip", required=True)
    p.add_argument("--repo", default=str(REPO))
    p.add_argument("--bo-mo-rong", required=True)
    a = ap.parse_args(argv)
    if a.lenh == "dong":
        return dong(Path(a.out), Path(a.bo_mo_rong))
    return giai(Path(a.zip), Path(a.repo), Path(a.bo_mo_rong))


if __name__ == "__main__":
    raise SystemExit(main())
