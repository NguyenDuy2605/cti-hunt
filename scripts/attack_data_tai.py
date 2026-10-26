"""Tải các tệp log trong danh sách cố định (``attack_data_lap_danh_sach.py``) từ Splunk attack_data, kiểm SHA256 từng tệp.

Tải qua địa chỉ Git LFS của GitHub tại đúng commit đã ghim. Tệp đã có và đúng băm thì bỏ qua; tệp sai băm bị xóa và tải lại.
Chạy lại cùng lệnh để tiếp tục sau khi đứt mạng.

    python scripts/attack_data_tai.py --danh-sach eval/inputs/attack_data_danh_sach_aafa53e.json --out <thư mục>
    tùy chọn: --chi N (N tệp nhỏ nhất, để thử) · --luong 4 (số tệp tải song song)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/{commit}/{path}"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tai(commit: str, c: dict, out: Path, lan_thu: int = 4) -> tuple[str, str]:
    dst = out / c["duong_dan"]
    if dst.exists() and sha256(dst) == c["sha256"]:
        return "da_co", c["duong_dan"]
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tai")
    last = None
    for i in range(lan_thu):
        try:
            with urllib.request.urlopen(MEDIA.format(commit=commit, path=c["duong_dan"]), timeout=120) as r, open(tmp, "wb") as f:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
            if sha256(tmp) != c["sha256"]:
                raise ValueError("sai SHA256")
            tmp.replace(dst)
            return "tai_xong", c["duong_dan"]
        except Exception as e:  # noqa: BLE001 — lỗi mạng/băm: thử lại, cuối cùng báo
            last = e
            time.sleep(2 * (i + 1))
    tmp.unlink(missing_ok=True)
    return f"loi: {type(last).__name__}: {str(last)[:150]}", c["duong_dan"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--danh-sach", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chi", type=int, help="chỉ tải N tệp nhỏ nhất (để thử)")
    ap.add_argument("--luong", type=int, default=4)
    a = ap.parse_args(argv)
    d = json.loads(Path(a.danh_sach).read_text(encoding="utf-8"))
    tep = sorted(d["tep"], key=lambda c: c["kich_thuoc"])
    if a.chi:
        tep = tep[: a.chi]
    out = Path(a.out)
    tong = sum(c["kich_thuoc"] for c in tep)
    print(f"{len(tep)} tệp, {tong / 1e9:.2f} GB, commit {d['commit'][:10]}", flush=True)
    dem, xong_byte, loi = {}, 0, []
    with ThreadPoolExecutor(a.luong) as ex:
        futs = {ex.submit(tai, d["commit"], c, out): c for c in tep}
        for i, f in enumerate(as_completed(futs), 1):
            kq, path = f.result()
            dem[kq.split(":")[0]] = dem.get(kq.split(":")[0], 0) + 1
            xong_byte += futs[f]["kich_thuoc"]
            if kq.startswith("loi"):
                loi.append((path, kq))
            if i % 25 == 0 or i == len(tep):
                print(f"  {i}/{len(tep)} tệp · {xong_byte / 1e9:.2f}/{tong / 1e9:.2f} GB · {dem}", flush=True)
    (out / "ket_qua_tai.json").write_text(json.dumps({"commit": d["commit"], "dem": dem, "loi": loi}, ensure_ascii=False,
                                                     indent=1), encoding="utf-8")
    for path, kq in loi:
        print("LỖI", path, kq)
    return 1 if loi else 0


if __name__ == "__main__":
    sys.exit(main())
