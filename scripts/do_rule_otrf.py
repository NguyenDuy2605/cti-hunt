"""Rule hệ thống đã sinh ở đợt đánh giá bản tổng quát (APT29, 07–08/10) chạy trên 7 bộ log OTRF khác kịch bản.

Câu hỏi: rule sinh từ report Solorigate/Raindrop/POSHSPY cho kỹ thuật X có bắt được X ở một lab khác, và có khớp ở bộ log
không mô phỏng X không. Không gọi API, không đọc nhãn sự kiện (APT29 hay OTRF đều không có nhãn ở đây).

Nhãn mức bộ dữ liệu (ghi cố định trước khi chạy, theo tên và mô tả bộ của OTRF): mỗi bộ mô phỏng một kỹ thuật bằng Empire;
mọi bộ đều có bước khởi chạy Empire bằng PowerShell (T1059.001). Đây là nhãn thô: không biết sự kiện nào của kẻ tấn công,
nên "rule đúng kỹ thuật có khớp" chưa phải là "bắt đúng sự kiện tấn công", và "rule kỹ thuật khác có khớp" chưa chắc là báo
nhầm (Empire còn để lại dấu vết khác). Mẫu sự kiện được in ra để người đọc kiểm.

Lấy hunt từ 12 lượt được tính (pipeline SY_02, PS_01, MS_01; agent SY_01, SY_02, SY_04, PS_01–03, MS_03–05); bỏ hunt pivot (gắn
máy/tài khoản của APT29) và hunt có ràng buộc neo; gộp hunt trùng truy vấn. Chạy lại truy vấn và mục lọc đã duyệt trực tiếp,
không qua cổng duyệt của lượt (cổng gắn gói duyệt với đúng lượt và bộ log gốc).

    .venv/Scripts/python.exe -X utf8 scripts/do_rule_otrf.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

from cti_hunt import config
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner

EVAL = "data/eval/apt29_day2/tuyen_B_v3"
COUNTED = ["pipeline/SY_02", "pipeline/PS_01", "pipeline/MS_01", "agent/SY_01", "agent/SY_02", "agent/SY_04", "agent/PS_01",
           "agent/PS_02", "agent/PS_03", "agent/MS_03", "agent/MS_04", "agent/MS_05"]
COMMON = {"T1059.001"}                                    # bước khởi chạy Empire có ở mọi bộ
DATASETS = {                                              # bộ: kỹ thuật được mô phỏng
    "otrf-dcom": {"T1021.003"},                           # DCOM ShellWindows
    "otrf-psexec": {"T1021.002", "T1569.002", "T1543.003"},  # PsExec qua svcctl: SMB + tạo/chạy dịch vụ
    "otrf-psremoting": {"T1021.006"},                     # WinRM
    "otrf-wmi-exec": {"T1047"},                           # WMI IWbemServices ExecMethod
    "otrf-schtasks": {"T1053.005"},                       # tạo và chạy scheduled task
    "otrf-wmi-sub": {"T1546.003"},                        # WMI event subscription
    "otrf-runkeys": {"T1547.001"},                        # Run key
}
SAMPLE_COLS = ("Image", "CommandLine", "ParentImage", "TargetObject", "TargetFilename", "Name", "Consumer", "ScriptBlockText",
               "ServiceName", "TaskName")


def parent(t: str) -> str:
    return t.split(".")[0]


def related(t: str, d: str) -> bool:
    """Cùng kỹ thuật, hoặc một bên là kỹ thuật cha của bên kia (T1021 với T1021.003). Hai kỹ thuật con khác nhau thì không."""
    return t == d or t == parent(d) or parent(t) == d


def load_rules() -> list[dict]:
    seen, rules = {}, []
    for run in COUNTED:
        for path in sorted(config.resolve(f"{EVAL}/{run}").glob("round_*/hunts_effective/*/*.yaml")):
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            b = spec["sigma_context"]["binding"]
            if b.get("pivot_value") or spec.get("rang_buoc") or spec["scope"].get("hosts") or spec["scope"].get("time_from"):
                continue
            key = (spec["scope"]["channel"].lower(), tuple(spec["scope"]["event_ids"]), spec["candidates"],
                   tuple(f["where"] for f in spec.get("filters") or []))
            if key in seen:
                seen[key]["luot"].append(run)
                continue
            rule = {"id": spec["id"], "luot": [run], "ttp": sorted(set(spec.get("linked_ttps") or [])),
                    "scope": spec["scope"], "candidates": spec["candidates"], "filters": spec.get("filters") or [],
                    "gia_thuyet": spec.get("gia_thuyet", "")}
            seen[key] = rule
            rules.append(rule)
    return rules


def count(con, rule: dict, sample: int = 3) -> dict:
    scope = runner._scope_where(rule["scope"])
    where = [scope, f"({rule['candidates']})"] + [f"({f['where']}) IS NOT TRUE" for f in rule["filters"]]
    try:
        pham_vi = con.execute(f"SELECT count(*) FROM events WHERE {scope}").fetchone()[0]
        cuoi = con.execute(f"SELECT count(*) FROM events WHERE {' AND '.join(where)}").fetchone()[0]
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        pick = ["ev_host", "ev_eid"] + [f'"{c}"' for c in SAMPLE_COLS if c in cols]
        rows = con.execute(f"SELECT {', '.join(pick)} FROM events WHERE {' AND '.join(where)} LIMIT {sample}").fetchall()
        names = ["ev_host", "ev_eid"] + [c for c in SAMPLE_COLS if c in cols]
        mau = [{k: str(v)[:200] for k, v in zip(names, r) if v not in (None, "")} for r in rows]
        return {"pham_vi": pham_vi, "cuoi": cuoi, "mau": mau}
    except Exception as e:  # noqa: BLE001 — cột không có ở bộ này: báo, không đoán
        return {"loi": f"{type(e).__name__}: {str(e)[:160]}"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    rules = load_rules()
    table = {}
    for ds, techs in DATASETS.items():
        con = connect(config.resolve(f"data/dev/{ds}"))
        rows = []
        for rule in rules:
            r = count(con, rule)
            kind = ("dung_ky_thuat" if any(related(t, d) for t in rule["ttp"] for d in techs)
                    else "khoi_chay_chung" if any(related(t, d) for t in rule["ttp"] for d in COMMON) else "ky_thuat_khac")
            rows.append({"rule": rule["id"], "ttp": rule["ttp"], "loai": kind, **r})
        table[ds] = rows
    summary = {}
    for ds, rows in table.items():
        s = defaultdict(lambda: {"so_rule": 0, "co_khop": 0, "loi": 0})
        for r in rows:
            x = s[r["loai"]]
            x["so_rule"] += 1
            x["loi"] += "loi" in r
            x["co_khop"] += r.get("cuoi", 0) > 0
        summary[ds] = dict(s)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_rule_otrf.json").write_text(json.dumps({"so_rule": len(rules), "rules": rules, "tong_hop": summary,
                                                           "chi_tiet": table}, ensure_ascii=False, indent=1),
                                               encoding="utf-8")
    print(f"{len(rules)} rule khác nhau từ {len(COUNTED)} lượt")
    for ds, s in summary.items():
        parts = " · ".join(f"{k}: {v['co_khop']}/{v['so_rule']} có khớp" + (f" ({v['loi']} lỗi)" if v["loi"] else "")
                           for k, v in sorted(s.items()))
        print(f"{ds:16s} {sorted(DATASETS[ds])} | {parts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
