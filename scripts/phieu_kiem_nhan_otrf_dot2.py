"""Phiếu kiểm mù nhãn OTRF đợt 2 (15/10): phân tầng theo loại sự kiện, kèm bằng chứng thô để người kiểm tự nối sự kiện với
tiến trình. Không gọi API, không đọc nhãn APT29.

Đợt 1 (`phieu_kiem_nhan_otrf.py`): 21/21 mục quyết được khớp, nhưng 21/42 mục "không chắc" dồn vào PowerShell 800/4103 và
Security, và mẫu không rơi vào Sysmon 1, 3, PowerShell 4104. Đợt 2 lấy đều 5 tầng — Sysmon 1, Sysmon 3, PowerShell/Operational
4103/4104, Windows PowerShell 800, Security — mỗi tầng 4 sự kiện nhãn tấn công và 4 sự kiện nhãn bình thường **khó** (cùng
máy, cùng tầng, trong khoảng tấn công của bộ nới 5 phút mỗi bên), lấy xoay vòng qua các bộ. Hạt giống cố định, mã mục đánh sau
khi trộn.

Bằng chứng kèm mỗi mục, không đi qua cách nối của script nhãn (để phép kiểm không vòng tròn):
- sự kiện Sysmon: chuỗi tiến trình theo ProcessGuid (tiến trình gây ra, cha, ông) từ Sysmon 1;
- sự kiện PowerShell/Operational (ExecutionProcessID) và Security (ProcessId): **mọi** lần chạy từng mang PID đó trên máy đó,
  với lúc tạo, lúc thoát, chương trình, dòng lệnh — người kiểm tự xem lần chạy nào đang sống lúc sự kiện xảy ra;
- lệnh PowerShell mã hóa base64 (ở sự kiện hoặc ở tiến trình liên quan): giải mã rồi chỉ ghi độ dài, địa chỉ mạng và các chuỗi
  kỹ thuật có mặt (không chép nội dung đã giải mã, vì tệp văn bản chứa mã của công cụ tấn công bị Windows Defender cách ly).

    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_nhan_otrf_dot2.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_nhan_otrf.py cham --out <thư mục>
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_co_nhan_otrf as m  # noqa: E402
import nhan_otrf as N  # noqa: E402
from phieu_kiem_nhan_otrf import FIELDS  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402

SEED = 20261016
PER = 4                                       # mỗi tầng: 4 mục nhãn tấn công + 4 mục nhãn bình thường
SYS, PSOP, WPS = N.SYSMON, N.PSOP, "windows powershell"
EXTRA = ("ProcessGuid", "ParentProcessGuid", "ProcessId", "NewProcessId", "ExecutionProcessID", "SourceProcessGUID",
         "UtcTime")
TEXT = ("CommandLine", "ParentCommandLine", "HostApplication", "ScriptBlockText", "Payload", "ContextInfo", "Message")
# Trường siêu dữ liệu của bộ thu log, không giúp quyết: bỏ khỏi phiếu. Mọi trường khác có giá trị đều hiện (đợt 1 chỉ hiện một
# danh sách cố định nên sự kiện PowerShell 800 và Security 5158 gần như trống).
META = {"@timestamp", "@version", "Channel", "EventID", "EventReceivedTime", "EventTime", "Hostname", "Keywords", "Opcode",
        "OpcodeValue", "RecordNumber", "Severity", "SeverityValue", "SourceModuleName", "SourceModuleType", "SourceName",
        "Task", "ThreadID", "Version", "host", "port", "tags", "ProviderGuid", "UtcTime"}
WORDS = ("WebClient", "DownloadData", "DownloadString", "Net.Sockets", "Invoke-Expression", "IEX", "FromBase64String",
         "Reflection.Assembly", "AmsiUtils", "cachedGroupPolicySettings", "ScriptBlockLogging", "User-Agent", "Start-Sleep")
URL = re.compile(r"https?://[^\s'\"`;)]+", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def stratum(ch: str, eid: int) -> str | None:
    if ch == SYS and eid == 1:
        return "Sysmon 1 (tạo tiến trình)"
    if ch == SYS and eid == 3:
        return "Sysmon 3 (kết nối mạng)"
    if ch == PSOP and eid in (4103, 4104):
        return "PowerShell/Operational 4103/4104"
    if ch == WPS and eid == 800:
        return "Windows PowerShell 800"
    if ch == "security":
        return "Security"
    return None


def short(v, n=250) -> str:
    return str(v)[:n]


def when(t) -> str:
    return str(t)[:23] if t is not None else ""


def decoded_features(rec: dict) -> list[dict]:
    out = []
    for f in TEXT:
        for b in N.ENC.findall(str(rec.get(f) or "")):
            try:
                txt = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-16le", "ignore")
            except ValueError:
                continue
            low = txt.lower()
            words = [w for w in WORDS if (re.search(r"(?<![a-z])iex(?![a-z])", low) if w == "IEX" else w.lower() in low)]
            nets = sorted(set(URL.findall(txt)) | {ip for ip in IP.findall(txt)})[:5]
            out.append({"o_truong": f, "do_dai_sau_giai_ma": len(txt), "dia_chi_mang": nets, "co_cac_chuoi": words})
    return out


class Dataset:
    def __init__(self, ds: str, nhan: Path):
        self.ds = ds
        self.attack, _ = m.load_labels(nhan, ds)
        con = self.con = connect(config.resolve(f"data/dev/{ds}"))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        want = [c for c in dict.fromkeys(FIELDS + EXTRA) if c in cols]
        text_cols = [c for c in ("Message", "ScriptBlockText", "Payload") if c in cols]
        has_text = (" OR ".join(f"coalesce(\"{c}\", '') <> ''" for c in text_cols)) or "FALSE"
        rows = con.execute(f"SELECT ev_host, ev_channel, CAST(ev_eid AS INTEGER), CAST(ev_rec AS VARCHAR), ev_ts, "
                           f"({has_text}) AS co_noi_dung, {', '.join(chr(34) + c + chr(34) for c in want)} FROM events").fetchall()
        names = ["ev_host", "ev_channel", "ev_eid", "ev_rec", "ev_ts", "co_noi_dung"] + want
        self.recs = [dict(zip(names, r)) for r in rows]
        self.by_guid = {}
        self.runs = defaultdict(list)            # (máy, pid) -> lần chạy được tạo trong bộ
        exits = defaultdict(list)                # (máy, pid) -> lúc thoát
        for r in self.recs:
            ch, eid, host = r["ev_channel"], r["ev_eid"], r["ev_host"]
            if ch == SYS and eid == 1 and r.get("ProcessGuid"):
                self.by_guid[(host, r["ProcessGuid"])] = r
                p = N.pid(r.get("ProcessId"))
                if p is not None:
                    self.runs[(host, p)].append({"tao": r["ev_ts"], "nguon": "Sysmon 1", "Image": r.get("Image"),
                                                 "CommandLine": r.get("CommandLine"), "ParentImage": r.get("ParentImage"),
                                                 "User": r.get("User")})
            elif ch == "security" and eid == 4688 and N.pid(r.get("NewProcessId")) is not None:
                self.runs[(host, N.pid(r["NewProcessId"]))].append(
                    {"tao": r["ev_ts"], "nguon": "Security 4688", "Image": r.get("NewProcessName"),
                     "CommandLine": r.get("CommandLine"), "ParentImage": r.get("ParentProcessName"),
                     "User": r.get("SubjectUserName")})
            elif ch == SYS and eid == 5 and N.pid(r.get("ProcessId")) is not None:
                exits[(host, N.pid(r["ProcessId"]))].append(r["ev_ts"])
            elif ch == "security" and eid == 4689 and N.pid(r.get("ProcessId")) is not None:
                exits[(host, N.pid(r["ProcessId"]))].append(r["ev_ts"])
        self.exits = exits
        att = [r for r in self.recs if self.key(r) in self.attack]
        ts = [r["ev_ts"] for r in att if isinstance(r["ev_ts"], datetime)]
        self.window = (min(ts) - timedelta(minutes=5), max(ts) + timedelta(minutes=5)) if ts else None

    @staticmethod
    def key(r) -> tuple:
        return str(r["ev_host"]), str(r["ev_channel"]), str(r["ev_rec"])

    def pools(self, layer: str) -> tuple[list, list]:
        # Sự kiện PowerShell không có nội dung (Windows không giải được thông điệp, gặp ở 800) không có gì để người kiểm xem:
        # loại khỏi mẫu ở cả hai phía.
        recs = [r for r in self.recs if stratum(r["ev_channel"], r["ev_eid"]) == layer
                and (r["co_noi_dung"] or r["ev_channel"] not in (PSOP, WPS))]
        att = [r for r in recs if self.key(r) in self.attack]
        hosts = {r["ev_host"] for r in att}
        lo, hi = self.window or (None, None)
        hard = [r for r in recs if self.key(r) not in self.attack and r["ev_host"] in hosts and lo is not None
                and isinstance(r["ev_ts"], datetime) and lo <= r["ev_ts"] <= hi]
        return att, hard

    def chain(self, host, guid, depth=3) -> list[dict]:
        out = []
        while guid and len(out) < depth:
            p = self.by_guid.get((host, guid))
            if p is None:
                out.append({"ghi_chu": "tiến trình không có Sysmon 1 trong bộ (khởi chạy trước khi bộ log bắt đầu ghi)"})
                break
            e = {"thoi_diem": when(p["ev_ts"]), "Image": short(p.get("Image")),
                 "CommandLine": short(p.get("CommandLine")), "User": short(p.get("User"))}
            feats = decoded_features(p)          # giải mã trên dòng lệnh đầy đủ, không trên bản đã cắt
            if feats:
                e["lenh_ma_hoa_da_giai_ma"] = feats[:2]
            out.append(e)
            guid = p.get("ParentProcessGuid")
        return out

    def same_pid(self, host, p) -> list[dict]:
        if p is None:
            return []
        runs = sorted(self.runs.get((host, p), []), key=lambda x: x["tao"])
        ends = sorted(self.exits.get((host, p), []))
        out = []
        for x in runs:
            end = next((e for e in ends if e >= x["tao"]), None)
            e = {"tao_luc": when(x["tao"]), "thoat_luc": when(end) or "không thấy trong bộ", "nguon": x["nguon"],
                 "Image": short(x["Image"]), "CommandLine": short(x["CommandLine"]), "ParentImage": short(x["ParentImage"])}
            feats = decoded_features({"CommandLine": x["CommandLine"]})
            if feats:
                e["lenh_ma_hoa_da_giai_ma"] = feats[:2]
            out.append(e)
        before = [e for e in ends if not runs or e < runs[0]["tao"]]
        if before or not runs:
            out.insert(0, {"tao_luc": "trước khi bộ log bắt đầu ghi (không thấy sự kiện tạo)",
                           "thoat_luc": when(before[0]) if before else "không thấy trong bộ"})
        return out

    def full(self, r) -> dict:
        """Mọi trường có giá trị của sự kiện, trừ siêu dữ liệu; Message chỉ hiện khi không có nội dung script riêng."""
        cur = self.con.execute("SELECT * FROM events WHERE ev_host = ? AND ev_channel = ? AND CAST(ev_rec AS VARCHAR) = ?",
                               [r["ev_host"], r["ev_channel"], str(r["ev_rec"])])
        names = [c[0] for c in cur.description]
        row = dict(zip(names, cur.fetchone()))
        out = {k: v for k, v in row.items() if v not in (None, "") and not k.startswith("ev_") and k not in META}
        if out.get("ScriptBlockText") or out.get("Payload"):
            out.pop("Message", None)
        return out

    def evidence(self, r) -> dict:
        host, ch, eid = r["ev_host"], r["ev_channel"], r["ev_eid"]
        ev: dict = {}
        if ch == SYS:
            if eid == 1:
                ev["chuoi_tien_trinh_cha"] = self.chain(host, r.get("ParentProcessGuid"))
            else:
                ev["chuoi_tien_trinh_gay_ra"] = self.chain(host, r.get("ProcessGuid") or r.get("SourceProcessGUID"))
        elif ch == PSOP:
            p = N.pid(r.get("ExecutionProcessID"))
            ev["pid_thuc_thi"] = p
            ev["moi_lan_chay_mang_pid_nay"] = self.same_pid(host, p)
        elif ch == "security":
            p = N.pid(r.get("ProcessId"))
            ev["pid_tien_trinh_thuc_hien"] = p
            ev["moi_lan_chay_mang_pid_nay"] = self.same_pid(host, p)
        enc = decoded_features(r)
        if enc:
            ev["lenh_ma_hoa_da_giai_ma"] = enc[:3]
        return ev


HEAD = """# Phiếu kiểm mù nhãn OTRF — đợt 2. Mỗi bộ OTRF ghi một cuộc mô phỏng tấn công bằng công cụ Empire (tên bộ = kỹ thuật).
# Với mỗi sự kiện: quyet_dinh = tan_cong (do kẻ tấn công gây ra) | binh_thuong | khong_chac. Không chắc thì ghi khong_chac.
# Bằng chứng kèm theo (đọc như người phân tích):
#   chuoi_tien_trinh_*: tiến trình gây ra sự kiện, rồi cha, rồi ông (từ Sysmon 1).
#   moi_lan_chay_mang_pid_nay: mọi tiến trình từng mang PID đó trên máy đó, kèm lúc tạo/thoát. PID được Windows dùng lại,
#     nên phải tự xem lần chạy nào đang sống ở thoi_diem của sự kiện.
#   lenh_ma_hoa_da_giai_ma: lệnh PowerShell base64 đã giải mã; chỉ ghi độ dài, địa chỉ mạng và chuỗi kỹ thuật có mặt.
#     WebClient/DownloadData/DownloadString/Net.Sockets: tải dữ liệu qua mạng. Invoke-Expression/IEX: chạy chuỗi như mã.
#     FromBase64String/Reflection.Assembly: giải mã hoặc nạp mã trong bộ nhớ. AmsiUtils: thành phần quét mã của PowerShell.
#     cachedGroupPolicySettings/ScriptBlockLogging: thiết lập ghi log script block. Start-Sleep: chờ giữa các lần liên lạc.
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    rnd = random.Random(SEED)
    data = [Dataset(ds, Path(a.nhan)) for ds in N.DATASETS]
    layers = ["Sysmon 1 (tạo tiến trình)", "Sysmon 3 (kết nối mạng)", "PowerShell/Operational 4103/4104",
              "Windows PowerShell 800", "Security"]
    picked = []
    for layer in layers:
        for label, idx in (("tan_cong", 0), ("binh_thuong", 1)):
            pools = {d.ds: (d, list(d.pools(layer)[idx])) for d in data}
            order = [ds for ds in N.DATASETS if pools[ds][1]]
            rnd.shuffle(order)
            got = 0
            while got < PER and any(pools[ds][1] for ds in order):
                for ds in order:
                    d, pool = pools[ds]
                    if got >= PER or not pool:
                        continue
                    r = pool.pop(rnd.randrange(len(pool)))
                    picked.append((d, layer, label, r))
                    got += 1
    rnd.shuffle(picked)
    items, key = [], {}
    for i, (d, layer, label, r) in enumerate(picked, 1):
        iid = f"M{i:02d}"
        key[iid] = {"bo": d.ds, "tang": layer, "nhan_script": label, "khoa": list(d.key(r))}
        full = d.full(r)
        item = {"id": iid, "bo_log": d.ds, "may": r["ev_host"], "kenh": r["ev_channel"], "eid": r["ev_eid"],
                "thoi_diem": when(r["ev_ts"]),
                "truong": {k: short(v, 600 if k == "Message" else 300) for k, v in full.items()}}
        item.update(d.evidence({**r, **full}))
        item.update({"quyet_dinh": "", "ghi_chu": ""})
        items.append(item)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phieu_kiem_nhan_otrf.yaml").write_text(
        HEAD + yaml.safe_dump({"nguoi_kiem": "", "su_kien": items}, allow_unicode=True, sort_keys=False, width=200),
        encoding="utf-8")
    (out / "dap_an_khong_mo.json").write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding="utf-8")
    count = defaultdict(int)
    for v in key.values():
        count[v["tang"]] += 1
    print(f"Đã ghi {len(items)} sự kiện vào {out / 'phieu_kiem_nhan_otrf.yaml'}: {dict(count)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
