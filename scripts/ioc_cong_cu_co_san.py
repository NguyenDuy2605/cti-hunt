"""Chạy công cụ rút IOC có sẵn (iocsearcher, iocextract) trên văn bản 19 report của ``goi_ioc_19.json`` (câu hỏi 1, phần IOC, A).

Chạy bằng môi trường riêng có ``iocsearcher``, ``iocextract`` (không thuộc phụ thuộc của repo), không import ``cti_hunt``:

    <venv công cụ>/python.exe -I -X utf8 scripts/ioc_cong_cu_co_san.py --goi <goi_ioc_19.json> --out <thư mục>

Dùng đúng cách gọi trong README của mỗi công cụ, không chỉnh tham số theo đáp án:
- iocsearcher: ``Searcher().search_data(văn bản)``; lấy loại md5/sha1/sha256 → mã băm, ip4 → IP, fqdn → tên miền, url → URL.
- iocextract: ``extract_urls(…, refang=True)``, ``extract_ipv4s(…, refang=True)``, ``extract_md5/sha1/sha256_hashes``.
  iocextract không có hàm tách tên miền; tên miền bị che (``a[.]b``) nó trả thành ``http:a.b``.
  Biến thể ``iocextract_sua_http`` (chỉnh tay, ghi rõ): chuỗi ``http:x`` không có ``//`` đổi thành tên miền hoặc IP ``x``.
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import re
from pathlib import Path

RX_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def chay_iocsearcher(text: str) -> dict[str, list[str]]:
    from iocsearcher.searcher import Searcher
    m = {"md5": "hash", "sha1": "hash", "sha256": "hash", "ip4": "ip", "fqdn": "domain", "url": "url"}
    out: dict[str, set[str]] = {k: set() for k in ("hash", "ip", "domain", "url")}
    for ioc in Searcher().search_data(text):
        if ioc.name in m:
            out[m[ioc.name]].add(str(ioc.value))
    return {k: sorted(v) for k, v in out.items()}


def chay_iocextract(text: str) -> dict[str, list[str]]:
    import iocextract as X
    out = {"hash": set(X.extract_md5_hashes(text)) | set(X.extract_sha1_hashes(text)) | set(X.extract_sha256_hashes(text)),
           "ip": set(X.extract_ipv4s(text, refang=True)), "domain": set(), "url": set(X.extract_urls(text, refang=True))}
    return {k: sorted(v) for k, v in out.items()}


def sua_http(res: dict[str, list[str]]) -> dict[str, list[str]]:
    out = {k: set(v) for k, v in res.items()}
    for u in list(out["url"]):
        m = re.match(r"^https?:(?!//)(.+)$", u, re.I)
        if m:
            out["url"].discard(u)
            host = m.group(1).strip("/")
            out["ip" if RX_IP.match(host) else "domain"].add(host)
    return {k: sorted(v) for k, v in out.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--goi", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    G = json.loads(Path(a.goi).read_text(encoding="utf-8"))
    kq = {}
    for r in G["report"]:
        s = chay_iocsearcher(r["van_ban"])
        e = chay_iocextract(r["van_ban"])
        kq[r["report"]] = {"iocsearcher": s, "iocextract": e, "iocextract_sua_http": sua_http(e)}
        print(f"{r['report']}: iocsearcher {sum(map(len, s.values()))} · iocextract {sum(map(len, e.values()))}")
    out = {"cong_cu": ["iocsearcher", "iocextract", "iocextract_sua_http"],
           "phien_ban": {p: md.version(p) for p in ("iocsearcher", "iocextract")}, "ket_qua": kq}
    Path(a.out).mkdir(parents=True, exist_ok=True)
    (Path(a.out) / "ket_qua_cong_cu.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
