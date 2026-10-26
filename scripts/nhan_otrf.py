"""Dựng nhãn sự kiện cho 7 bộ OTRF bằng dòng tiến trình (giao thức docs/METHODOLOGY.md).

Q1 dấu stager Empire (`cachedGroupPolicySettings`, trần hoặc trong lệnh PowerShell mã hóa) → Q2 tập tiến trình tấn công và con
cháu → Q3 sự kiện của các tiến trình đó → Q4 đối tượng WMI cùng tên consumer có dấu stager. Không gọi API, không đọc nhãn
APT29. Nhãn ghi ra ngoài repo:

    .venv/Scripts/python.exe -X utf8 scripts/nhan_otrf.py --out ../workspace/nhan_otrf_14-10

PID có thể bị dùng lại trong vài phút (đã gặp: taskhostw.exe và conhost.exe của kẻ tấn công cùng PID 7448 cách nhau 3 phút),
nên tiến trình được nhận theo **lần chạy**: (máy, PID, lúc tạo, lúc thoát). Sự kiện chỉ mang PID được gán cho lần chạy đang
sống ở thời điểm của sự kiện; sự kiện Sysmon gán theo GUID.
"""
from __future__ import annotations

import argparse
import base64
import bisect
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from cti_hunt import config
from cti_hunt.data.store import connect

DATASETS = ["otrf-dcom", "otrf-psexec", "otrf-psremoting", "otrf-runkeys", "otrf-schtasks", "otrf-wmi-exec", "otrf-wmi-sub"]
MARK = "cachedgrouppolicysettings"
ENC = re.compile(r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=]{40,})", re.I)
SYSMON = "microsoft-windows-sysmon/operational"
PSOP = "microsoft-windows-powershell/operational"
LABELED = {SYSMON, "security", PSOP, "windows powershell"}
COLS = ["ProcessGuid", "ParentProcessGuid", "ParentProcessId", "SourceProcessGUID", "SourceProcessGuid__2", "SourceProcessId",
        "TargetProcessGUID", "TargetProcessGuid__2", "TargetProcessId", "ProcessId", "NewProcessId", "ExecutionProcessID",
        "CommandLine", "ParentCommandLine", "Name", "Consumer", "TaskName", "TargetObject"]
HOSTAPP = re.compile(r"HostApplication=(.*?)\r?\n")
HIVE = re.compile(r"^(?:hku\\[^\\]+|hklm|hkcu|hkcr|hkey_[a-z_]+)\\")
TASK = re.compile(r"/tn\s+\"?([^\"\s]+)", re.I)
SLACK = timedelta(seconds=2)       # Security/PowerShell ghi giờ tới giây, Sysmon tới mili giây


def stager(text) -> bool:
    """Q1: chuỗi chứa stager Empire, trần hoặc trong lệnh PowerShell mã hóa."""
    if not text:
        return False
    text = str(text)
    if MARK in text.lower():
        return True
    for b in ENC.findall(text):
        try:
            if MARK in base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-16le", "ignore").lower():
                return True
        except ValueError:
            continue
    return False


def pid(v) -> int | None:
    if v in (None, "", "-"):
        return None
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def ts(v) -> datetime:
    s = str(v)
    return datetime.fromisoformat(s[:26]) if "." in s else datetime.fromisoformat(s[:19])


class Instances:
    """Lần chạy của tiến trình theo máy và PID; lần chạy không có sự kiện tạo trong bộ coi như sống từ trước."""

    def __init__(self):
        self.start = defaultdict(list)       # (máy, pid) -> [(lúc tạo, id)] đã sắp
        self.before = {}                     # (máy, pid) -> id lần chạy sống từ trước khi bộ ghi
        self.end = {}                        # id -> lúc thoát
        self.n = 0

    def new(self) -> int:
        self.n += 1
        return self.n

    def create(self, host, p, t) -> int:
        lst = self.start[(host, p)]
        for t0, i in lst:                    # cùng một lần tạo ghi ở cả Sysmon 1 và 4688
            if abs(t0 - t) <= SLACK:
                return i
        i = self.new()
        bisect.insort(lst, (t, i))
        return i

    def active(self, host, p, t) -> int | None:
        if p is None:
            return None
        best = None
        for t0, i in self.start.get((host, p), []):
            if t0 <= t + SLACK:
                best = i
        if best is None:
            if (host, p) not in self.before:
                self.before[(host, p)] = self.new()
            best = self.before[(host, p)]
        end = self.end.get(best)
        if end is not None and t > end + SLACK:
            return None                      # lần chạy đã thoát; PID sau đó thuộc tiến trình khác chưa thấy lúc tạo
        return best


def label(con, version: int = 1) -> dict:
    """``version`` 1: nhãn chốt 14/10 (Q1–Q4). 2: thêm Q5 (tiến trình kích hoạt chỗ bám) và Q6 (sự kiện kênh Windows PowerShell cùng
    phiên tấn công), 15/10 sau phiếu kiểm mù đợt 2."""
    desc = con.execute("DESCRIBE events").fetchall()
    cols = {r[0] for r in desc}
    have = [c for c in COLS if c in cols]
    rows = con.execute(f"SELECT ev_host, ev_channel, CAST(ev_eid AS INTEGER), ev_rec, CAST(ev_ts AS VARCHAR), "
                       f"{', '.join(chr(34) + c + chr(34) for c in have)} FROM events ORDER BY ev_ts").fetchall()
    idx = {c: i + 5 for i, c in enumerate(have)}
    g = lambda r, c: r[idx[c]] if c in idx else None  # noqa: E731

    q1 = set()
    for c in [r[0] for r in desc if r[1] == "VARCHAR" and not r[0].startswith("ev_")]:
        hits = con.execute(f'SELECT ev_host, ev_channel, ev_rec, "{c}" FROM events WHERE "{c}" ILIKE \'%{MARK}%\' '
                           f'OR regexp_matches("{c}", \'(?i)-e[a-z]*\\s+[A-Za-z0-9+/=]{{40,}}\')').fetchall()
        q1.update((h, ch, rec) for h, ch, rec, v in hits if stager(v))

    inst = Instances()
    guid_inst = {}                                       # (máy, guid) -> id lần chạy
    created = {}                                         # khóa sự kiện tạo -> id lần chạy được tạo
    # 1. lần chạy từ sự kiện tạo tiến trình; lúc thoát từ 4689 / Sysmon 5
    for r in rows:
        host, ch, eid, rec, t = r[0], r[1], r[2], r[3], ts(r[4])
        if ch == "security" and eid == 4688 and pid(g(r, "NewProcessId")) is not None:
            created[(host, ch, rec)] = inst.create(host, pid(g(r, "NewProcessId")), t)
        elif ch == SYSMON and eid == 1 and g(r, "ProcessGuid"):
            p = pid(g(r, "ProcessId"))
            i = inst.create(host, p, t) if p is not None else inst.new()
            created[(host, ch, rec)] = i
            guid_inst[(host, g(r, "ProcessGuid"))] = i
    for r in rows:
        host, ch, eid, t = r[0], r[1], r[2], ts(r[4])
        if ch == "security" and eid == 4689:
            i = inst.active(host, pid(g(r, "ProcessId")), t)
            if i is not None:
                inst.end.setdefault(i, t)
        elif ch == SYSMON and eid == 5 and (host, g(r, "ProcessGuid")) in guid_inst:
            inst.end.setdefault(guid_inst[(host, g(r, "ProcessGuid"))], t)
    # 2. nối GUID ↔ lần chạy qua các cặp (PID, GUID) Sysmon ghi, tại thời điểm của sự kiện
    pairs = [("ParentProcessId", "ParentProcessGuid"), ("SourceProcessId", "SourceProcessGUID"),
             ("SourceProcessId", "SourceProcessGuid__2"), ("TargetProcessId", "TargetProcessGUID"),
             ("TargetProcessId", "TargetProcessGuid__2"), ("ProcessId", "ProcessGuid")]
    for r in rows:
        host, ch, t = r[0], r[1], ts(r[4])
        if ch != SYSMON:
            continue
        for pc, gc in pairs:
            gu = g(r, gc)
            if gu and (host, gu) not in guid_inst:
                i = inst.active(host, pid(g(r, pc)), t)
                if i is not None:
                    guid_inst[(host, gu)] = i

    def by_pid(r, col):
        return inst.active(r[0], pid(g(r, col)), ts(r[4]))

    # 3. hạt giống Q1 rồi lan tới con cháu
    attack_inst = set()
    for r in rows:
        host, ch, eid, rec = r[:4]
        if (host, ch, rec) not in q1:
            continue
        if ch == SYSMON and eid == 1:
            if stager(g(r, "CommandLine")):
                attack_inst.add(created[(host, ch, rec)])
            if stager(g(r, "ParentCommandLine")) and (host, g(r, "ParentProcessGuid")) in guid_inst:
                attack_inst.add(guid_inst[(host, g(r, "ParentProcessGuid"))])
        elif ch == "security" and eid == 4688 and stager(g(r, "CommandLine")):
            attack_inst.add(created[(host, ch, rec)])
        elif ch == PSOP and pid(g(r, "ExecutionProcessID")):
            i = by_pid(r, "ExecutionProcessID")
            if i is not None:
                attack_inst.add(i)
    def close():
        while True:
            before = len(attack_inst)
            for r in rows:
                host, ch, eid, rec = r[:4]
                if ch == SYSMON and eid == 1 and guid_inst.get((host, g(r, "ParentProcessGuid"))) in attack_inst:
                    attack_inst.add(created[(host, ch, rec)])
                elif ch == "security" and eid == 4688 and by_pid(r, "ProcessId") in attack_inst:
                    attack_inst.add(created[(host, ch, rec)])
            if len(attack_inst) == before:
                break
        attack_inst.discard(None)

    close()
    launchers = set()
    if version >= 2:
        # Q5 (v2, 15/10; lỗ hổng tìm ra ở phiếu kiểm mù đợt 2): tiến trình có dòng lệnh đọc giá trị registry mà tiến trình tấn
        # công đã ghi (Sysmon 13) là tiến trình kích hoạt chỗ bám (vd Run key chạy `gp HKCU:...\CurrentVersion Debug` rồi
        # `powershell -enc $x`). Quy tắc v1 chỉ lan xuống con cháu của stager nên bỏ sót tiến trình này. Lan lại xuống con cháu.
        written = set()
        for r in rows:
            if r[1] == SYSMON and r[2] == 13 and g(r, "TargetObject") \
                    and guid_inst.get((r[0], g(r, "ProcessGuid"))) in attack_inst:
                parts = HIVE.sub("", str(g(r, "TargetObject")).lower()).rsplit("\\", 1)
                if len(parts) == 2 and parts[0] and parts[1]:
                    written.add((r[0], parts[0], parts[1]))

        def reads_written(host, cmd) -> bool:
            c = str(cmd or "").lower()
            return any(h == host and key in c and re.search(r"(?<![a-z0-9_])" + re.escape(val) + r"(?![a-z0-9_])", c)
                       for h, key, val in written)

        for r in rows:
            host, ch, eid, rec = r[:4]
            if ((ch == SYSMON and eid == 1) or (ch == "security" and eid == 4688)) and reads_written(host, g(r, "CommandLine")):
                i = created.get((host, ch, rec))
                if i is not None and i not in attack_inst:
                    launchers.add(i)
        attack_inst |= launchers
        close()

    # Q6 (v2): sự kiện kênh Windows PowerShell (400/403/600/800) không có PID; v1 chỉ nhận khi nội dung chứa dấu stager, nên bỏ sót các sự kiện
    # khác của cùng phiên tấn công. v2 nhận khi HostApplication trùng dòng lệnh của một lần chạy tấn công trên cùng máy, đang
    # sống ở thời điểm sự kiện.
    q6 = set()
    if version >= 2 and "Message" in cols:
        def norm(cmd) -> str:
            return re.sub(r"\s+", " ", str(cmd or "").replace('"', "").replace("'", "")).strip().lower()
        live = defaultdict(list)                         # (máy, dòng lệnh chuẩn hóa) -> [(lúc tạo, lúc thoát)]
        for r in rows:
            host, ch, eid, rec = r[:4]
            if ((ch == SYSMON and eid == 1) or (ch == "security" and eid == 4688)) \
                    and created.get((host, ch, rec)) in attack_inst and g(r, "CommandLine"):
                i = created[(host, ch, rec)]
                live[(host, norm(g(r, "CommandLine")))].append((ts(r[4]), inst.end.get(i)))
        for host, ch, rec, t, msg in con.execute(
                "SELECT ev_host, ev_channel, ev_rec, CAST(ev_ts AS VARCHAR), Message FROM events "
                "WHERE ev_channel = 'windows powershell'").fetchall():
            app = HOSTAPP.search(str(msg or ""))
            if not app:
                continue
            te = ts(t)
            if any(t0 - SLACK <= te and (end is None or te <= end + SLACK) for t0, end in live.get((host, norm(app.group(1))), [])):
                q6.add((host, ch, rec))

    consumers = {str(g(r, "Name")).strip().strip('"').lower() for r in rows
                 if r[1] == SYSMON and r[2] == 20 and (r[0], r[1], r[3]) in q1 and g(r, "Name")}
    # tên scheduled task trong dòng lệnh (/TN) của tiến trình tấn công
    tasks = {m.lower().lstrip("\\") for r in rows
             if ((r[1] == SYSMON and r[2] == 1) or (r[1] == "security" and r[2] == 4688))
             and created.get((r[0], r[1], r[3])) in attack_inst for m in TASK.findall(str(g(r, "CommandLine") or ""))}
    attack, why = set(), Counter()
    for r in rows:
        host, ch, eid, rec = r[:4]
        key = (host, ch, rec)
        reason = None
        if key in q1:
            reason = "Q1"
        elif ch == SYSMON and any(guid_inst.get((host, g(r, c))) in attack_inst
                                  for c in ("ProcessGuid", "SourceProcessGUID", "SourceProcessGuid__2")):
            reason = "Q3_sysmon"
        elif ch == "security" and (created.get(key) in attack_inst or by_pid(r, "ProcessId") in attack_inst):
            reason = "Q3_security"
        elif ch == PSOP and by_pid(r, "ExecutionProcessID") in attack_inst:
            reason = "Q3_powershell"
        elif ch == SYSMON and eid in (19, 21) and consumers and any(
                n in str(g(r, "Name") or "").lower() + " " + str(g(r, "Consumer") or "").lower() for n in consumers):
            reason = "Q4_wmi"
        elif (ch == "security" and eid in (4698, 4699, 4700, 4701, 4702)
              and str(g(r, "TaskName") or "").lower().lstrip("\\") in tasks):
            reason = "Q4_task"
        elif key in q6:
            reason = "Q6_windows_powershell"
        if reason:
            attack.add(key)
            why[reason] += 1
    return {"attack": attack, "why": dict(why), "attack_inst": attack_inst, "q1": len(q1), "created": created,
            "lan_chay_kich_hoat_cho_bam": len(launchers)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--phien-ban", type=int, default=1, choices=(1, 2),
                    help="1: nhãn chốt 14/10 (mặc định, dựng lại đúng từng byte); 2: thêm Q5, Q6 (15/10)")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    for ds in DATASETS:
        con = connect(config.resolve(f"data/dev/{ds}"))
        res = label(con, a.phien_ban)
        per = con.execute("SELECT ev_channel, count(*) FROM events GROUP BY 1").fetchall()
        attack_by = Counter(ch for _, ch, _ in res["attack"])
        path = out / f"{ds}.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["ev_host", "ev_channel", "ev_rec"])
            for k in sorted(res["attack"]):
                w.writerow(k)
        # tiến trình tấn công được tạo trong bộ (Sysmon 1 / 4688), để người đọc kiểm
        made = []
        for (h, ch, rec), i in res["created"].items():
            if i in res["attack_inst"]:
                img = con.execute(f"SELECT coalesce(Image, NewProcessName), CAST(ev_ts AS VARCHAR) FROM events WHERE "
                                  f"ev_host='{h}' AND ev_channel='{ch}' AND ev_rec='{rec}'").fetchone()
                made.append(f"{h} {img[1][:19]} {str(img[0]).rsplit(chr(92), 1)[-1]} ({'sysmon' if ch == SYSMON else '4688'})")
        summary[ds] = {"su_kien": sum(n for _, n in per), "su_kien_tan_cong": len(res["attack"]),
                       "theo_kenh": {ch: {"tong": n, "tan_cong": attack_by.get(ch, 0), "co_nhan": ch in LABELED}
                                     for ch, n in sorted(per)},
                       "ly_do": res["why"], "q1": res["q1"], "lan_chay_tan_cong": len(res["attack_inst"]),
                       "tien_trinh_tao_trong_bo": sorted(made), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        if a.phien_ban >= 2:                    # v1 giữ đúng khuôn tom_tat.json cũ
            summary[ds].update({"phien_ban": a.phien_ban, "lan_chay_kich_hoat_cho_bam": res["lan_chay_kich_hoat_cho_bam"]})
        print(f"{ds:16s} {summary[ds]['su_kien_tan_cong']:6d}/{summary[ds]['su_kien']:6d} tấn công · {res['why']} · "
              f"{len(res['attack_inst'])} lần chạy")
        for m in sorted(made):
            print("     ", m)
    (out / "tom_tat.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
