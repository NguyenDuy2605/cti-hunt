"""Đổi log XML của Splunk attack_data sang ``events.parquet`` theo đúng quy ước cột của hệ thống, qua bước nạp có sẵn.

Mỗi tệp log là một bộ dữ liệu riêng (số thứ tự sự kiện chỉ duy nhất trong một lần ghi, gộp nhiều tệp có thể trùng khóa
``(ev_host, ev_channel, ev_rec)``). Mỗi sự kiện XML thành một dòng JSON giống log OTRF:
- ``Hostname`` ← ``Computer``, ``Channel``, ``EventID``, ``RecordNumber`` ← ``EventRecordID``, ``SourceName`` ← Provider;
- ``EventTime`` ← ``TimeCreated/@SystemTime`` (đã là UTC, cắt tới giây) và nạp với ``offset_hours=0``; Sysmon vẫn lấy
  ``UtcTime`` trong EventData như mọi bộ khác;
- mọi ``EventData/Data[@Name]`` giữ đúng tên; ``UserData`` (vd 1102) lấy các phần tử con của phần tử đầu tiên. Trường trùng
  tên khóa hệ thống thì thêm tiền tố ``Data_``.
Sau đó gọi lõi nạp ``data.ingest.ingest`` (cột dẫn xuất ``ev_*``, kiểm khóa ``(ev_host, ev_channel, ev_rec)`` không trùng và
không thiếu). Không dùng phép kiểm lệch giờ của ``ingest_dev`` (dành cho OTRF: so ``UtcTime`` với giờ địa phương), vì ở đây
giờ lấy thẳng từ ``SystemTime`` là UTC; log Security không có ``UtcTime`` nên phép kiểm đó từ chối nhầm. Giữ chốt E1: từ chối
bộ có máy của APT29 day 2 (``configs/dataset.yaml`` ``raw.hosts``). Tệp không nạp được thì ghi lý do, không sửa tay.

Làm sạch (16/10, áp như nhau cho mọi tệp, không dựa vào kết quả rule): (1) bỏ sự kiện lặp y hệt mọi trường, giữ bản đầu, đếm
lại; (2) tệp còn trùng khóa sau bước (1) là nhiều lần ghi gộp lại, số thứ tự đếm lại từ đầu: sắp theo thời gian, cắt ở khoảng
trống ≥ 1 giờ, mỗi lần ghi nạp thành một bộ ``<mã>.p<k>``; lần ghi nào vẫn trùng khóa thì không nạp, ghi lý do.

    python scripts/attack_data_sang_parquet.py --danh-sach <danh sách .json> --tai <thư mục đã tải> --out <thư mục parquet>
    tùy chọn: --chi-tep <chuỗi trong đường dẫn> (thử vài tệp)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from cti_hunt import config
from cti_hunt.data.ingest import ingest

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
KHOA_HE_THONG = {"Hostname", "Channel", "EventID", "RecordNumber", "EventTime", "SourceName"}


def ma_bo(path: str) -> str:
    """Mã bộ dữ liệu từ đường dẫn tệp: ad.<kỹ thuật>.<thư mục>.<tên tệp>, chỉ chữ, số, '.', '_', '-', tối đa 80 ký tự."""
    parts = path.split("/")[2:]                      # bỏ datasets/attack_techniques
    s = "ad." + ".".join(p.rsplit(".log", 1)[0] for p in parts)
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s if len(s) <= 80 else s[:71] + "." + hashlib.sha1(path.encode("utf-8")).hexdigest()[:8]


def _ten(tag: str) -> str:
    return tag.split("}", 1)[-1]


def su_kien(xml: str) -> dict:
    root = ET.fromstring(xml)
    sysm = root.find(NS + "System")
    if sysm is None:
        raise ValueError("thiếu System")
    get = lambda name: (sysm.find(NS + name).text if sysm.find(NS + name) is not None else None)  # noqa: E731
    tc = sysm.find(NS + "TimeCreated")
    t = (tc.get("SystemTime") if tc is not None else "") or ""
    prov = sysm.find(NS + "Provider")
    ev = {"Hostname": get("Computer"), "Channel": get("Channel"), "EventID": get("EventID"),
          "RecordNumber": get("EventRecordID"), "EventTime": t.replace("T", " ")[:19],
          "SourceName": prov.get("Name") if prov is not None else None}
    data = []
    ed = root.find(NS + "EventData")
    if ed is not None:
        data = [(d.get("Name"), d.text or "") for d in ed.findall(NS + "Data") if d.get("Name")]
    ud = root.find(NS + "UserData")
    if ud is not None and len(ud):
        data += [(_ten(c.tag), c.text or "") for c in ud[0]]
    for k, v in data:
        ev[("Data_" + k) if k in KHOA_HE_THONG else k] = v
    return ev


def doc_tep(path: Path) -> tuple[list[dict], int]:
    """Đọc từng sự kiện (thường mỗi dòng một sự kiện; gộp dòng nếu một sự kiện trải nhiều dòng). Trả (sự kiện, số lỗi)."""
    out, loi, buf = [], 0, []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            buf.append(line.rstrip("\n"))
            if "</Event>" not in line:
                continue
            try:
                out.append(su_kien("".join(buf)))
            except (ET.ParseError, ValueError):
                loi += 1
            buf = []
    return out, loi + (1 if buf else 0)


def _khoa(ev: dict) -> tuple:
    """Đúng cách lõi nạp dựng khóa: máy (tên ngắn, hoa), channel (thường), số thứ tự."""
    return (str(ev.get("Hostname") or "").split(".")[0].upper(), str(ev.get("Channel") or "").lower(),
            str(ev.get("RecordNumber") or ""))


def bo_lap(evs: list[dict]) -> tuple[list[dict], int]:
    """Bỏ sự kiện lặp y hệt (mọi trường giống nhau), giữ bản đầu. Trả (sự kiện, số bản lặp đã bỏ)."""
    seen, out = set(), []
    for ev in evs:
        k = json.dumps(ev, sort_keys=True, ensure_ascii=False)
        if k not in seen:
            seen.add(k)
            out.append(ev)
    return out, len(evs) - len(out)


GIAN_CACH_LAN_GHI = 3600     # giây: hai sự kiện liên tiếp cách nhau từ chừng này trở lên là hai lần ghi khác nhau


def tach_lan_ghi(evs: list[dict]) -> list[list[dict]]:
    """Tệp không trùng khóa thì giữ nguyên một phần. Tệp còn trùng khóa (sau khi bỏ bản lặp y hệt) thường là nhiều lần ghi
    gộp lại, số thứ tự đếm lại từ đầu: sắp theo thời gian, cắt ở khoảng trống ≥ ``GIAN_CACH_LAN_GHI`` giây."""
    if len({_khoa(e) for e in evs}) == len(evs):
        return [evs]
    from datetime import datetime
    def ts(e):
        try:
            return datetime.strptime(e.get("EventTime") or "", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.min
    s = sorted(evs, key=ts)
    parts, cur = [], [s[0]]
    for a, b in zip(s, s[1:]):
        if (ts(b) - ts(a)).total_seconds() >= GIAN_CACH_LAN_GHI:
            parts.append(cur)
            cur = []
        cur.append(b)
    parts.append(cur)
    return parts


def nap_mot(evs: list[dict], bo: str, out: Path, c: dict, ds: dict, time_cfg: dict, eval_hosts: set) -> dict:
    """Ghi JSON tạm rồi nạp một bộ bằng lõi nạp; trả trạng thái của bộ."""
    tmp = out / ".json" / f"{bo}.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for ev in evs:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    dst = out / bo
    shutil.rmtree(dst, ignore_errors=True)
    try:
        m = ingest(tmp, dst, sysmon_channel=ds["sysmon_channel"], time_cfg=time_cfg,
                   event_key=ds["event_key"], threads=ds.get("ingest_threads", 2))
        may = sorted(m.get("hosts") or [])
        van_de = list(m["problems"])
        if set(may) & eval_hosts:
            van_de.append(f"E1: có máy của tập đánh giá {sorted(set(may) & eval_hosts)}")
        if m.get("ev_ts_null"):
            van_de.append(f"{m['ev_ts_null']} sự kiện không có thời điểm")
        if van_de:
            shutil.rmtree(dst, ignore_errors=True)
            return {"trang_thai": "khong_nap_duoc", "ly_do": "; ".join(van_de)[:500], "so_dong_parquet": 0}
        m.update(nguon_attack_data=c["duong_dan"], sha256_tep=c["sha256"], ky_thuat=c["ky_thuat"])
        (dst / "ingest_manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"trang_thai": "ok", "so_dong_parquet": m["rows"], "may": may, "thoi_gian_utc": m.get("ev_ts_range_utc")}
    finally:
        tmp.unlink(missing_ok=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--danh-sach", required=True)
    ap.add_argument("--tai", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chi-tep", help="chỉ đổi các tệp có chuỗi này trong đường dẫn")
    a = ap.parse_args(argv)
    d = json.loads(Path(a.danh_sach).read_text(encoding="utf-8"))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tom_tat_path = out / "tom_tat_nap.json"
    tom_tat = json.loads(tom_tat_path.read_text(encoding="utf-8")) if tom_tat_path.exists() else {}
    tep = [c for c in d["tep"] if not a.chi_tep or a.chi_tep in c["duong_dan"]]
    ds = config.load("dataset")
    time_cfg = {**ds["time"], "other_offset_hours": 0}
    eval_hosts = {str(h).upper() for h in ds["raw"].get("hosts") or []}
    t0 = time.monotonic()
    for i, c in enumerate(tep, 1):
        bo = ma_bo(c["duong_dan"])
        if tom_tat.get(c["duong_dan"], {}).get("trang_thai") == "ok":
            continue
        src = Path(a.tai) / c["duong_dan"]
        rec = {"ma_bo": bo, "ky_thuat": c["ky_thuat"], "loai": c["loai"], "sha256_tep": c["sha256"]}
        if not src.exists():
            rec.update(trang_thai="chua_tai")
        else:
            evs, loi = doc_tep(src)
            rec.update(so_su_kien=len(evs), dong_loi=loi)
            if not evs:
                rec.update(trang_thai="xml_hong" if loi else "rong")
            else:
                evs, so_lap = bo_lap(evs)
                phan = tach_lan_ghi(evs)
                rec.update(so_lap_y_het_bo=so_lap, so_lan_ghi=len(phan))
                ket = []
                for k, part in enumerate(phan, 1):
                    pid = bo if len(phan) == 1 else f"{bo[:74]}.p{k}"
                    ket.append({"ma_bo": pid, **nap_mot(part, pid, out, c, ds, time_cfg, eval_hosts)})
                ok = [x for x in ket if x["trang_thai"] == "ok"]
                rec.update(phan=ket, bo_con=[x["ma_bo"] for x in ok],
                           so_dong_parquet=sum(x["so_dong_parquet"] for x in ok),
                           trang_thai="ok" if len(ok) == len(ket) else ("mot_phan" if ok else "khong_nap_duoc"))
                if not ok:
                    rec["ly_do"] = "; ".join(x.get("ly_do", "") for x in ket)[:500]
        tom_tat[c["duong_dan"]] = rec
        if i % 20 == 0 or i == len(tep):
            tom_tat_path.write_text(json.dumps(tom_tat, ensure_ascii=False, indent=1), encoding="utf-8")
            dem = {}
            for r in tom_tat.values():
                dem[r["trang_thai"]] = dem.get(r["trang_thai"], 0) + 1
            print(f"  {i}/{len(tep)} tệp · {dem} · {(time.monotonic() - t0) / 60:.1f} phút", flush=True)
    tom_tat_path.write_text(json.dumps(tom_tat, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
