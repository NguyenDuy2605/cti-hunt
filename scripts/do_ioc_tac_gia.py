"""Đo bộ rút IOC (khâu ②, regex) so với danh sách IOC chính tác giả report công bố, rồi quét các IOC đó trên log.

Không gọi API, không đọc nhãn. Đáp án mỗi report là các giá trị nằm trong mục IOC của chính report (ranh giới mục ghi ở
`REPORTS`, đã rà bằng mắt 14/10): mã băm MD5/SHA1/SHA256, IPv4, tên miền, URL và tên tệp (đã bỏ dạng che như [.], [:],
hxxp). Quy ước giống bộ rút: tên miền/IP nằm trong URL hay đường dẫn không tính thành dòng riêng. Bộ rút chạy trên toàn
bộ report (mọi khối), đúng như lúc hệ thống chạy thật; giá trị rút ra đưa về dạng thật bằng `s2_ioc.normalize` rồi so.

Hai biến thể của bộ rút: đầy đủ (cấu hình hiện hành `configs/ioc_rules.yaml`) và tắt xử lý dạng che (bảng `defang` rỗng).
Mục "thừa" chia theo chỗ: trong mục IOC hay ngoài mục IOC (thân bài), kèm khối nguồn để rà tay.

Quét log: mỗi log một lượt; nối mọi trường chuỗi gốc (bỏ cột dẫn xuất `ev_*`) của từng sự kiện, chữ thường, giữ sự kiện
khớp một trong các IOC (mã băm, IP, tên miền, URL so chuỗi con; tên tệp so cả từ). Chỉ đếm, không đọc nhãn.

    .venv/Scripts/python.exe -X utf8 scripts/do_ioc_tac_gia.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import duckdb

from cti_hunt import config
from cti_hunt.stages import s1_ingest, s2_ioc

NGOAI = "../workspace/ioc_14-10/report_moi"
# report: (thư mục bundle, khối đầu mục IOC, khối đầu tiên SAU mục IOC hoặc None nếu mục chạy tới hết bài)
REPORTS = {
    "Solorigate (Microsoft)": ("data/dev/kiem_ocr_ms_01", "N1-MS-KIEM-0160", "N1-MS-KIEM-0167"),
    "Raindrop (Symantec)": ("data/dev/kiem_ocr_sy_01", "N1-SY-KIEM-0096", "N1-SY-KIEM-0108"),
    "Volt Typhoon (Microsoft)": ("data/reports/moi/VOLT-MS-1310", "VOLT-MS-1310-0090", None),
    "IcedID / ALPHV (The DFIR Report)": ("tmp/thu_cti_icedid_7-10/bundle2", "DEV-ICEDID-2024-0268", "DEV-ICEDID-2024-0273"),
    # Bốn report tải mới ngày 14/10 bằng `ingest-report`, lưu ngoài repo; chưa từng dùng khi viết bộ rút IOC.
    # Bài Unit 42 TA551 (IOC-MOI-04) bị loại: mục IOC chỉ trỏ sang một repo GitHub, trong bài không có IOC nào.
    "BlackSuit (The DFIR Report)": (f"{NGOAI}/IOC-MOI-01", "IOC-MOI-01-0306", "IOC-MOI-01-0311"),
    "ToddyCat (Kaspersky Securelist)": (f"{NGOAI}/IOC-MOI-02", "IOC-MOI-02-0224", "IOC-MOI-02-0285"),
    "OilRig Outer Space / Juicy Mix (ESET)": (f"{NGOAI}/IOC-MOI-03", "IOC-MOI-03-0143", "IOC-MOI-03-0163"),
    "Latrodectus (Elastic Security Labs)": (f"{NGOAI}/IOC-MOI-05", "IOC-MOI-05-0271", "IOC-MOI-05-0279"),
}
# Chuỗi trong mục IOC trông giống IOC nhưng không phải, bỏ tay khỏi đáp án (đã xem từng chuỗi): {report: {giá trị: lý do}}
EXCLUDE: dict[str, dict[str, str]] = {
    "OilRig Outer Space / Juicy Mix (ESET)": {
        "psw.agent.ah": "tên mã phát hiện của ESET (cột ESET detection name), không phải tên miền",
        "psw.agent.aw": "tên mã phát hiện của ESET", "psw.agent.sxj": "tên mã phát hiện của ESET",
        "trojandropper.agent.pcc": "tên mã phát hiện của ESET"},
    "ToddyCat (Kaspersky Securelist)": {
        "wusa.exe": "tiến trình hệ thống bị tiêm mã, nằm ở cột mô tả (\"Loader Simple VLC – wusa.exe inject\")"},
}
LOGS = {"APT29 day 2": "data/work/events.parquet", **{p.name: str(p / "events.parquet")
                                                      for p in sorted(Path("data/dev").glob("otrf-*"))}}
TYPES = ("hash", "ip", "domain", "url", "tep")
CORE = ("hash", "ip", "domain", "url")
FILE_EXT = ("exe", "dll", "ps1", "bat", "lnk", "zip", "vbs", "js", "msi", "iso", "sys", "scr", "hta", "cmd", "jar", "7z", "rar",
            "doc", "docx", "docm", "xls", "xlsm", "dat", "bin", "key")
DEFANG = [(r"\[\.\]", "."), (r"\(\.\)", "."), (r"\{\.\}", "."), (r"\[dot\]", "."), (r"\[:\]", ":"), (r"\[://\]", "://"),
          (r"hxxps", "https"), (r"hxxp", "http")]
RX_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
# Đường dẫn Windows trong mục IOC: thư mục được có dấu cách (C:\Program Files\…), phải kết thúc bằng tên tệp có đuôi.
# (Bộ rút IOC của hệ thống dừng ở dấu cách nên cắt cụt các đường dẫn này — là điểm yếu được đo, không sửa ở đây.)
RX_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n\s]+\.(?:" + "|".join(FILE_EXT) + r")\b", re.I)
RX_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
RX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RX_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
RX_FILE = re.compile(r"[\w\-\[\].]+\.(?:" + "|".join(FILE_EXT) + r")\b", re.I)


# Phân loại mục "thừa" (bộ rút ra, không có trong danh sách tác giả) — luật + danh sách đã xem tay từng chuỗi ngày 14/10.
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "9.9.9.9", "1.1.1.1", "208.67.220.220", "208.67.222.222", "84.200.70.40",
              # dải đặc biệt của IANA mà thư viện ipaddress vẫn coi là "global" (gặp trong danh sách cidrmatch của một rule EQL)
              "192.0.0.9", "192.0.0.10", "192.175.48.0", "192.31.196.0", "192.52.193.0", "192.88.99.0"}
REF_HOSTS = ("microsoft.com", "aka.ms", "github.com", "medium.com", "proofpoint.com", "compass-security.com", "falconforce.nl",
             "eset.com", "sigmasearchengine.com", "threatview.io", "detection.fyi", "thedfirreport.com")
MANUAL = {
    "dich_vu_hop_le_ha_tang_chung": {"login.microsoftonline.com", "ns1.dnsowl.com", "ns2.dnsowl.com", "ns3.dnsowl.com",
                                     "104.21.76.140", "172.67.196.25", "socket.io", "https://d.docs.live.net/[user-id"},
    "chuoi_hieu_nham_hoac_vi_du": {"solorigate.sa", "1.0.0.0", "www.meow123.com",
                                   "organization.co.il"},
}
CATEGORY_VI = {"ip_rieng_du_tru_dns_cong_cong": "IP riêng/dự trữ/DNS công cộng",
               "link_tham_khao": "link của nhà xuất bản hoặc tài liệu tham khảo",
               "dich_vu_hop_le_ha_tang_chung": "dịch vụ hợp lệ / hạ tầng dùng chung (CDN, máy chủ tên miền)",
               "chuoi_hieu_nham_hoac_vi_du": "chuỗi hiểu nhầm (tên mã phát hiện, số phiên bản) hoặc ví dụ/mẫu",
               "chi_dau_that_trong_than_bai": "chỉ dấu thật trong thân bài, không có trong danh sách tác giả"}


def classify_extra(kind: str, v: str) -> str:
    host = (urlsplit(v).hostname or "") if kind == "url" else v
    if kind == "ip" or RX_IP.fullmatch(host or ""):
        import ipaddress
        a = ipaddress.ip_address(host)
        if not a.is_global or a.is_multicast or host in PUBLIC_DNS:      # gồm cả dải dùng chung 100.64/10, dải đặc biệt 192.0.0/24
            return "ip_rieng_du_tru_dns_cong_cong"
    for cat, vals in MANUAL.items():
        if v in vals or host in vals:
            return cat
    if any(host == h or host.endswith("." + h) for h in REF_HOSTS):
        return "link_tham_khao"
    return "chi_dau_that_trong_than_bai"


def refang(s: str) -> str:
    for a, b in DEFANG:
        s = re.sub(a, b, s, flags=re.I)
    return s


def kind_of(t: str) -> str | None:
    return {"hash": "hash", "ip": "ip", "url": "url", "domain": "domain", "ten_file": "tep", "duong_dan": "tep"}.get(t)


def basename(v: str) -> str:
    return re.split(r"[\\/]", v)[-1]


def gold_from_section(text: str) -> dict[str, set[str]]:
    """Đáp án từ chữ của mục IOC. URL và đường dẫn lấy trước rồi xóa khỏi chữ, để tên miền/IP bên trong không đếm hai lần."""
    text = refang(text)
    gold = {k: set() for k in TYPES}
    for m in RX_URL.findall(text):
        gold["url"].add(m.lower().rstrip("./,;)"))           # cùng cách chuẩn hóa với s2_ioc.normalize
    for m in RX_PATH.findall(text):
        gold["tep"].add(basename(m).lower())
    rest = RX_PATH.sub(" ", RX_URL.sub(" ", text))
    for m in RX_FILE.findall(rest):
        gold["tep"].add(m.lower())
    rest = RX_FILE.sub(" ", rest)
    gold["hash"] |= {h.lower() for h in RX_HASH.findall(rest)}
    for ip in RX_IP.findall(rest):
        if all(0 <= int(x) <= 255 for x in ip.split(".")):
            gold["ip"].add(ip)
    rest = RX_IP.sub(" ", rest)
    for d in RX_DOMAIN.findall(rest):
        if not re.fullmatch(r"[a-f0-9.]+", d, re.I):
            gold["domain"].add(d.lower())
    return gold


def extracted(rows: list[dict], rules: dict, norm_rules: dict) -> dict[str, dict[str, str]]:
    """{loại: {giá trị đã đưa về dạng thật: mã khối xuất hiện đầu tiên}}."""
    out: dict[str, dict[str, str]] = {k: {} for k in TYPES}
    for ioc in s2_ioc.extract_report(rows, rules):
        k = kind_of(ioc.type)
        if k is None:
            continue
        v = s2_ioc.normalize(ioc.value, norm_rules)
        if k == "tep":
            v = basename(v)
        out[k].setdefault(v, ioc.source_span.segment_id or "")
    return out


def strong_score(rows: list[dict], rules: dict, gold: dict[str, set[str]], publisher: str) -> dict:
    """Tập IOC mạnh mà khâu quét IOC (s2_ioc_sweep, 14/10) thực sự quét, so với đáp án (bốn loại lõi). Ngữ cảnh để nhận
    imphash/JA3 là cả khối chứa IOC (khi chạy thật, s2_report ghi ±100 ký tự quanh giá trị)."""
    from cti_hunt.stages import s2_ioc_sweep
    text = {r["ma_doan"]: r.get("van_ban", "") for r in rows}
    got = set()
    for ioc in s2_ioc.extract_report(rows, rules):
        if kind_of(ioc.type) not in CORE:
            continue
        ioc = ioc.model_copy(update={"source_span": ioc.source_span.model_copy(
            update={"text": text.get(ioc.source_span.segment_id, "")})})
        value = s2_ioc.normalize(ioc.value, rules)
        if s2_ioc_sweep.classify(ioc, value, publisher)[0] == "manh":
            got.add(value)
    core = set().union(*(gold[k] for k in CORE))
    tp = len(got & core)
    return {"rut_manh": len(got), "dung": tp, "dap_an": len(core), "precision": tp / len(got) if got else None,
            "recall": tp / len(core) if core else None, "manh_khong_co_trong_dap_an": sorted(got - core),
            "dap_an_bi_xep_yeu_hoac_bo": sorted(core - got)}


def score(got: dict[str, dict[str, str]], gold: dict[str, set[str]], section_ids: set[str]) -> dict:
    res = {}
    for k in TYPES:
        g, e = gold[k], set(got[k])
        tp = e & g
        extra = sorted(e - g)
        res[k] = {"dap_an": len(g), "rut_duoc": len(e), "dung": len(tp), "thieu": sorted(g - e),
                  "thua_trong_muc_ioc": [(v, got[k][v]) for v in extra if got[k][v] in section_ids],
                  "thua_ngoai_muc_ioc": [(v, got[k][v]) for v in extra if got[k][v] not in section_ids]}

    def total(keys):
        tp = sum(res[k]["dung"] for k in keys)
        g = sum(res[k]["dap_an"] for k in keys)
        e = sum(res[k]["rut_duoc"] for k in keys)
        p, r = (tp / e if e else None), (tp / g if g else None)
        f1 = 2 * p * r / (p + r) if p and r else None
        return {"dap_an": g, "rut_duoc": e, "dung": tp, "precision": p, "recall": r, "f1": f1}

    res["tong_loi"] = total(CORE)
    res["tong_ke_ca_tep"] = total(TYPES)
    cats: dict[str, list] = {}
    for k in CORE:
        for v, seg in res[k]["thua_trong_muc_ioc"] + res[k]["thua_ngoai_muc_ioc"]:
            cats.setdefault(classify_extra(k, v), []).append([k, v, seg])
    res["phan_loai_thua_loi"] = cats
    # Phép thử "nếu bộ rút bỏ IP riêng/dự trữ/DNS công cộng" — chỉ tính lại trên kết quả, không sửa bộ rút.
    drop = len(cats.get("ip_rieng_du_tru_dns_cong_cong", []))
    t = res["tong_loi"]
    res["neu_bo_ip_rieng"] = {"rut_duoc": t["rut_duoc"] - drop,
                              "precision": t["dung"] / (t["rut_duoc"] - drop) if t["rut_duoc"] - drop else None}
    return res


def sweep_patterns(values: dict[str, str]) -> dict[str, str]:
    """{giá trị: regex}; tên tệp so cả từ, loại khác so chuỗi con."""
    out = {}
    for v, k in values.items():
        esc = re.escape(v.lower())
        out[v] = rf"(?:^|[^a-z0-9_.\-]){esc}(?:[^a-z0-9_.\-]|$)" if k == "tep" else esc
    return out


def sweep(values: dict[str, str]) -> dict:
    pats = sweep_patterns(values)
    # DuckDB chỉ lọc bằng chuỗi nguyên văn (gộp các chuỗi thường được tăng tốc tốt); ranh giới từ của tên tệp kiểm ở Python.
    # (Gộp thẳng các mẫu có lớp ký tự ở đầu làm thư viện regex của DuckDB chạy hơn 5.000 giây CPU, 14/10.)
    big = "|".join(re.escape(v.lower()) for v in values)
    compiled = {v: re.compile(p) for v, p in pats.items()}
    con = duckdb.connect()
    con.execute("SET preserve_insertion_order=false")
    out = {}
    for name, path in LOGS.items():
        if not Path(path).exists():
            continue
        t0 = time.time()
        cols = [row[0] for row in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{path}')").fetchall()
                if "VARCHAR" in str(row[1]).upper() and not row[0].startswith("ev_")]
        blob = "lower(concat_ws(' ', " + ", ".join(f'"{c}"' for c in cols) + "))"
        total = con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]
        rows = con.execute(f"SELECT ev_host, ev_channel, ev_eid, b FROM (SELECT ev_host, ev_channel, ev_eid, {blob} AS b "
                           f"FROM read_parquet('{path}')) WHERE regexp_matches(b, ?)", [big]).fetchall()
        hits: dict[str, dict] = {}
        for host, ch, eid, b in rows:
            for v, rx in compiled.items():
                if rx.search(b):
                    h = hits.setdefault(v, {"loai": values[v], "so_su_kien": 0, "nguon": {}})
                    h["so_su_kien"] += 1
                    key = f"{host} · {ch} · {eid}"
                    h["nguon"][key] = h["nguon"].get(key, 0) + 1
        out[name] = {"so_su_kien": total, "so_truong_quet": len(cols), "su_kien_khop_it_nhat_1_ioc": len(rows),
                     "ioc_khop": hits, "giay": round(time.time() - t0, 1)}
        print(f"  quét {name}: {total} sự kiện, {len(cols)} trường, {len(rows)} khớp, {out[name]['giay']} giây", flush=True)
    return out


def stage_sweep(rules: dict) -> dict:
    """Chính khâu quét IOC của hệ thống (s2_ioc_sweep, 14/10) trên IOC bộ rút lấy từ mỗi report, mọi log: số sự kiện khớp khi
    chỉ quét IOC mạnh (mặc định) và khi quét cả IOC yếu."""
    from cti_hunt.contracts import ContractA
    from cti_hunt.stages import s2_ioc_sweep
    out = {}
    for name, (d, _, _) in REPORTS.items():
        manifest, rows, prov = s1_ingest.load_bundle(Path(d))
        text = {r["ma_doan"]: r.get("van_ban", "") for r in rows}
        iocs = s2_ioc.extract_report([s for s in rows if s1_ingest.extraction_ready(s, prov)], rules)
        for ioc in iocs:                   # như s2_report.run: ngữ cảnh quanh giá trị để nhận imphash/JA3
            body = text.get(ioc.source_span.segment_id, "")
            at = body.find(ioc.value)
            ioc.source_span.text = body[max(0, at - 100):at + len(ioc.value) + 100]
        src = str(manifest.get("resolved_source") or "")
        ca = ContractA(report_id=name, source_url=src if src.startswith("http") else "", iocs=iocs)
        items = s2_ioc_sweep.plan(ca, rules)
        row = {"so_gia_tri": len(items), "manh": sum(i["muc"] == "manh" for i in items), "log": {}}
        for log, path in LOGS.items():
            if not Path(path).exists():
                continue
            strong = s2_ioc_sweep.sweep_dir(items, Path(path).parent)
            weak = s2_ioc_sweep.sweep_dir(items, Path(path).parent, include_weak=True)
            row["log"][log] = {"chi_ioc_manh": {m["gia_tri"]: m["so_su_kien"] for m in strong["muc"] if m["so_su_kien"]},
                               "ca_ioc_yeu": {m["gia_tri"]: m["so_su_kien"] for m in weak["muc"] if m["so_su_kien"]}}
        out[name] = row
        hits_s = sum(sum(v["chi_ioc_manh"].values()) for v in row["log"].values())
        hits_w = sum(sum(v["ca_ioc_yeu"].values()) for v in row["log"].values())
        print(f"khâu quét IOC · {name:38s} {row['manh']}/{row['so_gia_tri']} mạnh · khớp (chỉ mạnh) {hits_s} · khớp (cả yếu) {hits_w}")
    return out


def fmt(x):
    return "—" if x is None else f"{x:.2f}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--khong-quet-log", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
    no_defang = copy.deepcopy(rules)
    no_defang["defang"] = {}
    result: dict = {"bao_cao": {}}
    to_sweep: dict[str, str] = {}
    src_of: dict[str, set[str]] = {}
    for name, (d, first, after) in REPORTS.items():
        manifest, rows, provenance = s1_ingest.load_bundle(Path(d))
        src = str(manifest.get("resolved_source") or "")
        publisher = (urlsplit(src).hostname or "").lower().removeprefix("www.") if src.startswith("http") else ""
        ids = [r["ma_doan"] for r in rows]
        i0 = ids.index(first)
        i1 = ids.index(after) if after else len(rows)
        section = rows[i0:i1]
        gold = gold_from_section("\n".join(r.get("van_ban", "") for r in section))
        for k in TYPES:
            gold[k] -= set(EXCLUDE.get(name, {}))
        sec_ids = {r["ma_doan"] for r in section}
        # Đúng như s2_report.run: bộ rút IOC chỉ đọc khối chữ gốc hoặc chữ OCR đã duyệt; bỏ khối ảnh và tiêu đề.
        text_rows = [s for s in rows if s1_ingest.extraction_ready(s, provenance)]
        full = extracted(text_rows, rules, rules)
        r = {"muc_ioc": [first, section[-1]["ma_doan"]], "so_khoi_bai": len(rows), "so_khoi_bo_rut_doc": len(text_rows),
             "so_khoi_muc_ioc": len(section), "so_ioc_bo_rut_moi_loai": len(s2_ioc.extract_report(text_rows, rules)),
             "dap_an": {k: sorted(v) for k, v in gold.items()},
             "day_du": score(full, gold, sec_ids),
             "tat_xu_ly_dang_che": score(extracted(text_rows, no_defang, rules), gold, sec_ids),
             "ioc_manh": strong_score(text_rows, rules, gold, publisher)}
        result["bao_cao"][name] = r
        for k in TYPES:
            for v in gold[k]:
                to_sweep.setdefault(v, k)
                src_of.setdefault(v, set()).add(f"{name} (đáp án)")
            if k == "tep":
                continue                                   # tên tệp rút từ thân bài quá chung để quét; chỉ quét tên tệp tác giả công bố
            for v in full[k]:
                to_sweep.setdefault(v, k)
                src_of.setdefault(v, set()).add(f"{name} (bộ rút)")
        for p in RX_PATH.findall(refang("\n".join(r.get("van_ban", "") for r in section))):
            to_sweep.setdefault(p.lower(), "duong_dan")       # tên tệp kèm đường dẫn tác giả ghi: quét cả đường dẫn
            src_of.setdefault(p.lower(), set()).add(f"{name} (đáp án, đường dẫn đầy đủ)")
        for u in list(gold["url"]) + list(full["url"]):
            host = urlsplit(u).hostname
            if host:
                k = "ip" if RX_IP.fullmatch(host) else "domain"
                to_sweep.setdefault(host, k)
                src_of.setdefault(host, set()).add(f"{name} (tên máy trong URL)")
    for name, r in result["bao_cao"].items():
        print(f"\n== {name}: mục IOC {r['muc_ioc'][0]} → {r['muc_ioc'][1]} ({r['so_khoi_muc_ioc']}/{r['so_khoi_bai']} khối; "
              f"bộ rút đọc {r['so_khoi_bo_rut_doc']} khối, ra {r['so_ioc_bo_rut_moi_loai']} IOC mọi loại)")
        for v in ("day_du", "tat_xu_ly_dang_che"):
            s = r[v]
            per = " · ".join(f"{k} {s[k]['dung']}/{s[k]['dap_an']} (rút {s[k]['rut_duoc']})" for k in TYPES)
            for t in ("tong_loi", "tong_ke_ca_tep"):
                x = s[t]
                print(f"  {v:20s} {t:15s} đúng {x['dung']}/{x['dap_an']} · rút {x['rut_duoc']} · P {fmt(x['precision'])} "
                      f"R {fmt(x['recall'])} F1 {fmt(x['f1'])}")
            print(f"  {'':20s} {per}")
        m = r["ioc_manh"]
        print(f"  {'IOC mạnh (khâu quét)':20s} đúng {m['dung']}/{m['dap_an']} · rút {m['rut_manh']} · P {fmt(m['precision'])} "
              f"R {fmt(m['recall'])}")
    if not a.khong_quet_log:
        print(f"\nQuét {len(to_sweep)} giá trị trên {len(LOGS)} log:")
        result["quet_log"] = sweep(to_sweep)
        result["khau_quet_ioc"] = stage_sweep(rules)
        result["nguon_gia_tri_quet"] = {v: sorted(s) for v, s in src_of.items()}
    (out / "ket_qua_ioc.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    for name, s in result.get("quet_log", {}).items():
        print(f"quét log {name:22s} | {s['so_su_kien']} sự kiện · khớp {s['su_kien_khop_it_nhat_1_ioc']} | "
              + ", ".join(f"{v} [{h['loai']}] {h['so_su_kien']}" for v, h in s["ioc_khop"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
