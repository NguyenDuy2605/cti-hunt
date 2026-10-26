"""Preflight không nhãn cho nhánh lọc approved trên OTRF scheduled task; không API, không tự duyệt.

Tái lập căn cứ để người duyệt xem trước khi điền phiếu: tập khóa C, từng C∩Fi, union và phần
còn lại của rule mock; chuỗi sự kiện quanh hai tác vụ UpdateOrchestrator trên WORKSTATION6;
vòng đời tạo/xóa; bối cảnh đăng nhập. Với --splunk-probe: chỉ tìm kiếm trên index WMI đã nạp
để kiểm các dạng điều kiện của mục lọc ở hai engine (không nạp, không ghi lên Splunk).

    python scripts/chuan_bi_loc_approved_otrf.py --out data/dev/loc_approved_otrf_preflight_01 [--splunk-probe]
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import yaml

from cti_hunt import config, filter_approval as F, integrity
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.agent.dev_data import check_manifest
from cti_hunt.agent.session import check_dataset
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner

from thu_duyet_loc_otrf import _event_checks
from thu_graph_loc_approved_otrf import DATASET, HYPOTHESIS, MOCK_RULE, SOURCE_SHA

HOST, SYSMON, TS = "WORKSTATION6", "microsoft-windows-sysmon/operational", "microsoft-windows-taskscheduler/operational"
WINDOW = ("2020-09-21 22:00:50", "2020-09-21 22:01:10")
PUBLIC_SOURCES = [
    {"url": "https://keyliner.blogspot.com/2020/02/windows-10-wakes-from-sleep-solution.html",
     "loai": "blog cá nhân", "noi_dung": "liệt kê \\Microsoft\\Windows\\UpdateOrchestrator\\AC Power Download/Install "
     "trong danh sách tác vụ có thể tắt; không nêu action/trigger/tiến trình tạo"},
    {"url": "https://learn.microsoft.com/en-us/answers/questions/3212758/how-to-disable-system-task-waking-up-the-pc-repeat",
     "loai": "Microsoft Q&A (moderator + người dùng cộng đồng)", "noi_dung": "tác vụ UpdateOrchestrator và usoclient.exe; "
     "người dùng cộng đồng báo tác vụ bị tạo lại sau khi xóa; không nêu riêng AC Power Download/Install"},
]


def _rows(con, sql):
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in zip(names, r) if v not in (None, "")}
            for r in cur.fetchall()]


def mock_spec(con, catalog):
    """Biên dịch rule mock qua đúng adapter v2, thu scope về EID của giả thuyết như ⑤."""
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    hunts, skipped = duckdb_sigma.compile_text(MOCK_RULE, catalog, cols, filter_policy=F.POLICY)
    specs = [h.to_hunt_spec() for h in hunts if h.scope["channel"] == HYPOTHESIS["data_source"]]
    if skipped or len(specs) != 1:
        raise ValueError("rule mock không biên dịch đúng một nguồn Security")
    spec = specs[0]
    spec["scope"] = {**spec["scope"], "event_ids": HYPOTHESIS["event_ids"]}
    return spec


def key_sets(con, spec):
    """C, từng C∩Fi (IS TRUE, giữ NULL), union khử trùng và phần còn lại nếu áp mọi mục."""
    base = (f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {runner._scope_where(spec['scope'])} "
            f"AND ({spec['candidates']})")
    c = set(con.execute(base).fetchall())
    filters = []
    for f in spec["filters"]:
        hit = set(con.execute(base + f" AND (({f['where']}) IS TRUE)").fetchall())
        filters.append({"id": f["id"], "bieu_thuc_sigma": f["bieu_thuc_sigma"], "where": f["where"],
                        "matched": len(hit), "keys": sorted(hit)})
    union = set().union(*[set(f["keys"]) for f in filters])
    return {"candidates": len(c), "candidate_keys": sorted(c), "filters": filters,
            "union": len(union), "remaining_if_all_approved": len(c - union),
            "remaining_keys_if_all_approved": sorted(c - union)}


def chain(con):
    """Chuỗi sự kiện quanh hai tác vụ trên WORKSTATION6; trường đã chọn, không mẫu payload khác."""
    w = f"ev_host='{HOST}' AND ev_ts BETWEEN TIMESTAMP '{WINDOW[0]}' AND TIMESTAMP '{WINDOW[1]}'"
    return {
        "window_utc": list(WINDOW), "host": HOST,
        "sysmon_1": _rows(con, f"""SELECT ev_ts, ev_rec, Image, CommandLine, ParentImage, ParentCommandLine, "User"
            FROM events WHERE {w} AND ev_channel='{SYSMON}' AND ev_eid=1 ORDER BY ev_ts, ev_rec"""),
        "security_4688": _rows(con, f"""SELECT ev_ts, ev_rec, NewProcessName, CommandLine, ParentProcessName,
            SubjectUserName FROM events WHERE {w} AND ev_channel='security' AND ev_eid=4688 ORDER BY ev_ts, ev_rec"""),
        "security_task": _rows(con, f"""SELECT ev_ts, ev_eid, ev_rec, TaskName, SubjectUserSid, SubjectUserName,
            SubjectLogonId FROM events WHERE {w} AND ev_channel='security' AND ev_eid IN (4698,4699,4702)
            ORDER BY ev_ts, ev_rec"""),
        "taskscheduler": _rows(con, f"""SELECT ev_ts, ev_eid, ev_rec, TaskName, UserContext, Path FROM events
            WHERE {w} AND ev_channel='{TS}' ORDER BY ev_ts, ev_rec"""),
    }


def task_content(con):
    """Các dòng phần tử của TaskContent cho đúng những 4698 do SYSTEM tạo trên WORKSTATION6."""
    out = []
    for rec, name, tc in con.execute(f"""SELECT ev_rec, TaskName, TaskContent FROM events WHERE ev_host='{HOST}'
            AND ev_channel='security' AND ev_eid=4698 AND SubjectUserSid='S-1-5-18' ORDER BY ev_ts""").fetchall():
        lines = [x.strip() for x in tc.split("\r\n")]
        keep = [x for x in lines if any(t in x for t in ("Command", "Arguments", "UserId", "RunLevel", "Trigger",
                                                         "StateName", "SecurityDescriptor", "URI", "Exec", "Actions"))]
        out.append({"ev_rec": rec, "TaskName": name, "exec_count": tc.count("&lt;Exec&gt;"),
                    "actions_count": tc.count("&lt;Actions "), "lines": keep,
                    "task_content_sha256": hashlib.sha256(tc.encode("utf-8")).hexdigest()})
    return out


def lifecycle(con):
    """Thời điểm tạo (4698) và xóa (4699) của cùng TaskName trên cùng máy."""
    return _rows(con, """SELECT c.ev_host, c.TaskName, c.ev_ts AS tao_utc, d.ev_ts AS xoa_utc,
        date_diff('second', c.ev_ts, d.ev_ts) AS giay
        FROM events c LEFT JOIN events d ON d.ev_channel='security' AND d.ev_eid=4699
          AND d.ev_host=c.ev_host AND d.TaskName=c.TaskName AND d.ev_ts >= c.ev_ts
        WHERE c.ev_channel='security' AND c.ev_eid=4698 ORDER BY c.ev_ts""")


def context(con):
    return {
        "logon_events_host": con.execute(f"""SELECT count(*) FROM events WHERE ev_host='{HOST}'
            AND ev_channel='security' AND ev_eid IN (4624,4625,4648)""").fetchone()[0],
        "sysmon_1_users_host": _rows(con, f"""SELECT "User", min(ev_ts) AS dau, max(ev_ts) AS cuoi, count(*) AS n
            FROM events WHERE ev_host='{HOST}' AND ev_channel='{SYSMON}' AND ev_eid=1 GROUP BY 1 ORDER BY 1"""),
        "task_events_by_subject": _rows(con, """SELECT ev_host, ev_eid, SubjectUserSid, count(*) AS n FROM events
            WHERE ev_channel='security' AND ev_eid IN (4698,4699,4702) GROUP BY ALL ORDER BY ALL"""),
    }


def splunk_probe(root):
    """Chỉ tìm kiếm localhost trên index WMI đã nạp và xác nhận: so dạng điều kiện ở hai engine."""
    from sigma.backends.splunk import SplunkBackend
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.rule import SigmaRule
    from cti_hunt.adapters.splunk import SplunkConnection
    events = root / "data/dev/otrf-wmi-exec"
    con = connect(events)
    sp = SplunkConnection("127.0.0.1")
    catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset", root)["logsource_catalog"], root))
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    crlf = ('&lt;Actions Context="NetworkService"&gt;\r\n    &lt;ComHandler&gt;\r\n      &lt;ClassId&gt;'
            '{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}&lt;/ClassId&gt;')
    one_line = {"Hostname": "WORKSTATION5.theshire.local", "SubjectUserSid": "S-1-5-20",
                "TaskName": "\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask",
                "TaskContentNew|contains|all": ["&lt;Source&gt;$(@%systemroot%\\system32\\sppc.dll,-200)&lt;/Source&gt;",
                                                "&lt;Data&gt;&lt;![CDATA[timer]]&gt;&lt;/Data&gt;"]}
    wrong = deepcopy(one_line)
    wrong["TaskContentNew|contains|all"][1] = "&lt;Data&gt;&lt;![CDATA[timerX]]&gt;&lt;/Data&gt;"
    cases = {
        "crlf_dung": ({"TaskContentNew|contains": crlf}, ("selection and filter_x",)),
        "crlf_chi_lf": ({"TaskContentNew|contains": crlf.replace("\r\n", "\n")}, ("selection and filter_x",)),
        "mot_dong_dung": (one_line, ("selection", "selection and filter_x", "selection and not filter_x")),
        "mot_dong_sai_mot_manh": (wrong, ("selection", "selection and filter_x", "selection and not filter_x")),
    }
    where = runner._scope_where({"channel": "security", "event_ids": [4702]})
    out = {"index": "cti_wmi_dev", "read_only_search": True,
           "index_count": sp.search('search index="cti_wmi_dev" | stats count', earliest_time="0", latest_time="now"),
           "cases": {}}
    try:
        for name, (filt, conds) in cases.items():
            res = {}
            for cond in conds:
                doc = {"title": "probe", "status": "experimental",
                       "logsource": {"product": "windows", "service": "security"},
                       "detection": {"selection": {"EventID": 4702}, "filter_x": filt, "condition": cond}}
                spl = SplunkBackend(processing_pipeline=ProcessingPipeline()).convert_rule(SigmaRule.from_dict(doc))[0]
                hunts, _ = duckdb_sigma.compile_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), catalog, cols)
                hs = hunts[0].to_hunt_spec()
                base = f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {where} AND ({hs['candidates']})"
                keys = set(con.execute(base).fetchall())
                for f in hs["filters"]:
                    keys -= set(con.execute(base + f" AND (({f['where']}) IS TRUE)").fetchall())
                duck = sorted([str(x) for x in k] for k in keys)
                rows = sp.search(f'search index="cti_wmi_dev" ev_channel="security" ev_eid=4702 ({spl}) '
                                 "| table ev_host ev_channel ev_rec", earliest_time="0", latest_time="now")
                splunk = sorted({(r.get("ev_host"), r.get("ev_channel"), str(r.get("ev_rec"))) for r in rows})
                res[cond] = {"spl": spl, "duckdb": duck, "splunk": [list(k) for k in splunk],
                             "khop": duck == [list(k) for k in splunk]}
            out["cases"][name] = res
    finally:
        con.close()
    return out


def run(out, root=config.ROOT, *, probe=False):
    root, out = Path(root).resolve(), Path(out).resolve()
    if not out.is_relative_to(root / "data/dev") or out == root / "data/dev" or out.exists():
        raise ValueError("cần thư mục mới trong data/dev, không ghi đè bằng chứng cũ")
    events = root / "data/dev" / DATASET
    manifest_path = events / "ingest_manifest.json"
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    check_dataset(events, root)
    check_manifest(events, DATASET, SOURCE_SHA, root)
    if integrity.sha256_file(Path(m["source"])) != SOURCE_SHA:
        raise ValueError("gói OTRF scheduled task khác SHA256 E1 đã chốt")
    here = Path(__file__)
    pinned = [manifest_path, events / "events.parquet", here, here.with_name("thu_graph_loc_approved_otrf.py"),
              root / "data/dev/api_budget.sqlite"]
    before = {str(p.resolve()): integrity.sha256_file(p) for p in pinned}
    con = connect(events)
    try:
        _, checks = _event_checks(con, {"manifest_rows": m["rows"]}, root)
        catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset", root)["logsource_catalog"], root))
        spec = mock_spec(con, catalog)
        result = {"kind": "otrf_schtasks_approved_filter_preflight_unlabeled",
                  "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
                  "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(),
                  "api_called": False, "human_decisions_written": False, "dataset_id": DATASET,
                  "source_sha256": SOURCE_SHA, "events_checks": checks, "pinned_sha256": before,
                  "mock_rule_sha256": hashlib.sha256(MOCK_RULE.encode("utf-8")).hexdigest(),
                  "mock_spec_scope": spec["scope"], "key_sets": key_sets(con, spec), "chain": chain(con),
                  "system_task_content": task_content(con), "lifecycle": lifecycle(con), "context": context(con),
                  "public_sources": PUBLIC_SOURCES}
    finally:
        con.close()
    out.mkdir(parents=True)
    F._write(out / "evidence.json", result)
    if probe:
        F._write(out / "splunk_probe.json", splunk_probe(root))
    if {str(p.resolve()): integrity.sha256_file(p) for p in pinned} != before:
        raise ValueError("dữ liệu/công cụ/sổ ngân sách đổi trong lúc preflight")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--splunk-probe", action="store_true", help="chỉ tìm kiếm localhost trên index WMI đã nạp")
    args = parser.parse_args(argv)
    result = run(args.out, probe=args.splunk_probe)
    ks = result["key_sets"]
    print(json.dumps({"candidates": ks["candidates"], "filters": [{k: f[k] for k in ("id", "matched", "keys")}
                      for f in ks["filters"]], "union": ks["union"],
                      "remaining_if_all_approved": ks["remaining_if_all_approved"],
                      "evidence": str(args.out / "evidence.json")}, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
