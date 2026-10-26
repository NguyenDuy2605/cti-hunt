"""H-03: đếm ứng viên theo tiến trình cha và số còn lại qua F-01, F-02a, F-02b. KHÔNG dùng nhãn.
Chỉ dùng thư viện chuẩn Python — chạy được trên máy không cài gói nào. Chỉ in tên tiến trình cha và số đếm, không in dòng lệnh.

    python h03_dem_khong_nhan.py
    python h03_dem_khong_nhan.py "D:\\duong\\dan\\khac.json"

Điều kiện chép đúng hunts/manual/H-03.yaml (bản sau gói F-02):
  phạm vi   : Channel = microsoft-windows-sysmon/operational (không phân biệt hoa thường), EventID = 1
  ứng viên  : lower(ParentImage) kết thúc bằng \\wmiprvse.exe | \\wsmprovhost.exe | \\services.exe
  F-01      : lower(Image) kết thúc bằng \\wmiapsrv.exe | \\wmiadap.exe | \\svchost.exe
  F-02a/b   : lower(Image), lower(trim(CommandLine)), lower(User) khớp chính xác
Kỳ vọng: phạm vi 581 · ứng viên 152 · sau F-01 30 · sau F-02a 25 · sau F-02b 19.
"""
import json
import sys
from collections import Counter

PATH = sys.argv[1] if len(sys.argv) > 1 else r"data\raw\apt29_evals_day2_manual_2020-05-02035409.json"
SYSMON = "microsoft-windows-sysmon/operational"
CHA = ("\\wmiprvse.exe", "\\wsmprovhost.exe", "\\services.exe")
F01 = ("\\wmiapsrv.exe", "\\wmiadap.exe", "\\svchost.exe")
TI = "c:\\windows\\servicing\\trustedinstaller.exe"
SPP = "c:\\windows\\system32\\sppsvc.exe"


def s(ev, k):
    v = ev.get(k)
    return "" if v is None else str(v)


def f02a(ev):
    return (s(ev, "Image").lower() == TI and s(ev, "CommandLine").strip(" ").lower() == TI
            and s(ev, "User").lower() == "nt authority\\system")


def f02b(ev):
    return (s(ev, "Image").lower() == SPP and s(ev, "CommandLine").strip(" ").lower() == SPP
            and s(ev, "User").lower() == "nt authority\\network service")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    n_lines = n_bad = n_scope = 0
    cand = []
    with open(PATH, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            n_lines += 1
            try:
                ev = json.loads(line)
            except ValueError:
                n_bad += 1
                continue
            if s(ev, "Channel").lower() != SYSMON:
                continue
            try:
                if int(str(ev.get("EventID")).strip()) != 1:
                    continue
            except ValueError:
                continue
            n_scope += 1
            if s(ev, "ParentImage").lower().endswith(CHA):
                cand.append(ev)

    by_parent = Counter(s(ev, "ParentImage").lower().rsplit("\\", 1)[-1] for ev in cand)
    after_f01 = [ev for ev in cand if not s(ev, "Image").lower().endswith(F01)]
    after_f02a = [ev for ev in after_f01 if not f02a(ev)]
    after_f02b = [ev for ev in after_f02a if not f02b(ev)]

    print(f"Dòng JSON: {n_lines} (lỗi parse: {n_bad}) — kỳ vọng 587286")
    print(f"Phạm vi (Sysmon EID 1): {n_scope} — kỳ vọng 581")
    print(f"Ứng viên H-03: {len(cand)} — kỳ vọng 152")
    for cha, n in sorted(by_parent.items(), key=lambda x: (-x[1], x[0])):
        print(f"  cha {cha:<20}{n:>5}")
    print(f"Sau F-01 : {len(after_f01):>4} (loại {len(cand) - len(after_f01)}) — kỳ vọng 30 (loại 122)")
    print(f"Sau F-02a: {len(after_f02a):>4} (loại {len(after_f01) - len(after_f02a)}) — kỳ vọng 25 (loại 5)")
    print(f"Sau F-02b: {len(after_f02b):>4} (loại {len(after_f02a) - len(after_f02b)}) — kỳ vọng 19 (loại 6)")


if __name__ == "__main__":
    main()
