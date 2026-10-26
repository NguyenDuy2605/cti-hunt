"""Khảo sát không nhãn: trong phạm vi nguồn log của 5 bộ OTRF phát triển còn lại, có cụm nào đủ căn cứ để
đề xuất mục lọc hay không. Không API, không tạo phiếu, không tự duyệt.

Phạm vi lấy đúng như session v2: danh mục ③ hiệu lực (load_catalog → build_profile → apply_profile) của TTP trong
Contract A phát triển. Mỗi nguồn được gom theo trường khóa của danh mục; chuỗi dài chỉ giữ tiền tố để không nhân
bản payload. Không dùng mô tả kịch bản OTRF để phân loại sự kiện. Kết quả là bảng cụm cho người rà, không phải
quyết định lọc.

    python scripts/ra_ung_vien_loc_otrf.py --out data/dev/ra_ung_vien_loc_otrf_01
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from cti_hunt import config, filter_approval as F, integrity
from cti_hunt.agent.dev_data import check_manifest
from cti_hunt.agent.session import check_dataset
from cti_hunt.contracts import ContractA
from cti_hunt.data.store import connect
from cti_hunt.stages import s3_telemetry

from thu_duyet_loc_otrf import _event_checks

# Mã bộ, Contract A phát triển, SHA256 gói gốc đã chốt E1 (docs/METHODOLOGY.md).
DATASETS = {
    "otrf-dcom": ("DEV-DCOM", "9ec1bcfffc46158565ad99a06b9a0a6bac97a152a513c32686be2084f54065c9"),
    "otrf-psexec": ("DEV-PSEXEC", "8f40e7fc86bbbf31ebd50b3ba537cf0f4378392ae3e74de84bee00aeb0de1fa5"),
    "otrf-psremoting": ("DEV-PSREMOTING", "214355730c8cf903f4423c96aa7459fed7b74258e2a6766b794ba316e9d3a46e"),
    "otrf-runkeys": ("DEV-RUNKEYS", "2965f791bcaf5e6ccfc4059985e81fd7e67ec87f17855b6c383edd1b03a19c36"),
    "otrf-wmi-sub": ("DEV-WMISUB", "a507f2edd768b592e6b3157e974fd0468965eee00407387d88356ecb8fd20fea"),
}
SYSMON = "microsoft-windows-sysmon/operational"
PREFIX = 120
# Biểu thức gom theo nguồn: trường khóa của danh mục, chuỗi dài chỉ giữ tiền tố.
GROUPS = {
    (SYSMON, (1,)): ["ParentImage", "Image", '"User"'],
    ("security", (4697,)): ["ServiceName", "ServiceFileName", "SubjectUserName"],
    ("system", (7045,)): ["ServiceName", "ImagePath", "AccountName", "StartType"],
    ("microsoft-windows-powershell/operational", (4104,)): [f"left(ScriptBlockText, {PREFIX})"],
    (SYSMON, (12, 13)): ["Image", "regexp_replace(TargetObject, '\\\\[^\\\\]*$', '')", "EventType"],
    (SYSMON, (19, 20, 21)): ["Operation", "EventNamespace", f"left(coalesce(Name, Consumer, ''), {PREFIX})", '"User"'],
    ("microsoft-windows-wmi-activity/operational", (5861,)): [f"left(Message, {PREFIX})"],
}


# Hai mục lọc ĐỀ XUẤT sau khi rà (chưa ai duyệt): chỉ để tính tập khóa và kiểm SPL một dòng, không tạo phiếu.
# Selection là phạm vi tự nhiên của giả thuyết theo TTP; mỗi mục ghim máy, chủ thể và nội dung một dòng.
PROPOSALS = {
    "otrf-wmi-sub": ([5861], r"""title: De xuat loc SCM Event Log (chua duyet)
logsource: {product: windows, service: wmi}
detection:
  selection:
    EventID: 5861
  filter_scm_event_log:
    Hostname: 'WORKSTATION5.theshire.local'
    Message|contains|all:
      - 'Eventfilter = SCM Event Log Filter (refer to its activate eventid:5859); Consumer = NTEventLogEventConsumer="SCM Event Log Consumer";'
      - 'instance of NTEventLogEventConsumer'
      - 'Query = "select * from MSFT_SCMEventLogEvent";'
      - 'SourceName = "Service Control Manager";'
  condition: selection and not filter_scm_event_log
"""),
    "otrf-runkeys": ([12, 13], r"""title: De xuat loc Run WindowsDefender cua MsMpEng (chua duyet)
logsource: {product: windows, category: registry_event}
detection:
  selection:
    EventID: [12, 13]
    TargetObject|contains: '\CurrentVersion\Run'
  filter_defender_set:
    Hostname: 'WORKSTATION5.theshire.local'
    Image: 'C:\Program Files\Windows Defender\MsMpEng.exe'
    EventType: 'SetValue'
    TargetObject: 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsDefender'
    Details: '"%%ProgramFiles%%\Windows Defender\MSASCuiL.exe"'
  filter_defender_delete:
    Hostname: 'WORKSTATION5.theshire.local'
    Image: 'C:\Program Files\Windows Defender\MsMpEng.exe'
    EventType: 'DeleteValue'
    TargetObject: 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsDefender'
  condition: selection and not filter_defender_set and not filter_defender_delete
"""),
}


def proposal(con, rule: str, event_ids: list[int], root: Path) -> dict:
    """Tập khóa C, từng C∩Fi (IS TRUE) và phần còn lại; SPL của C và từng Fi phải qua kiểm một dòng."""
    from copy import deepcopy
    import yaml
    from sigma.backends.splunk import SplunkBackend
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.rule import SigmaRule
    from cti_hunt.adapters import duckdb_sigma
    from cti_hunt.eval.splunk_compare import single_line, split_spl
    from cti_hunt.hunt import runner
    catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset", root)["logsource_catalog"], root))
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    hunts, skipped = duckdb_sigma.compile_text(rule, catalog, cols, filter_policy=F.POLICY)
    if skipped or len(hunts) != 1:
        raise ValueError("đề xuất phải biên dịch đúng một nguồn")
    spec = hunts[0].to_hunt_spec()
    spec["scope"] = {**spec["scope"], "event_ids": event_ids}      # như ⑤ thu về EID của giả thuyết
    base = f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {runner._scope_where(spec['scope'])} AND ({spec['candidates']})"
    c = set(con.execute(base).fetchall())
    doc, removed, filters = yaml.safe_load(rule), set(), []
    for cond in [spec["sigma_context"]["candidate_condition"]] + [f["bieu_thuc_sigma"] for f in spec["filters"]]:
        d = deepcopy(doc)
        d["detection"]["condition"] = cond
        split_spl(single_line(SplunkBackend(processing_pipeline=ProcessingPipeline()).convert_rule(SigmaRule.from_dict(d))[0]))
    for f in spec["filters"]:
        hit = set(con.execute(base + f" AND (({f['where']}) IS TRUE)").fetchall())
        removed |= hit
        filters.append({"id": f["id"], "bieu_thuc_sigma": f["bieu_thuc_sigma"], "khop": sorted(hit)})
    return {"scope": spec["scope"], "candidates": sorted(c), "filters": filters, "union": len(removed),
            "con_lai_neu_duyet_het": sorted(c - removed), "spl_mot_dong": True, "trang_thai": "de_xuat_chua_duyet"}


def _clean(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    text = str(value)
    return text if len(text) <= PREFIX else text[:PREFIX] + "…"


def survey_source(con, src: dict) -> dict:
    channel, eids = src["channel"], tuple(int(e) for e in src["event_ids"])
    cols = {r[0].lower() for r in con.execute("DESCRIBE events").fetchall()}
    exprs = [e for e in GROUPS.get((channel, eids), [])
             if all(tok.strip('"').lower() in cols for tok in _fields(e))]
    where = f"ev_channel = '{channel}' AND ev_eid IN ({', '.join(map(str, eids))})"
    total = con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]
    groups = []
    if total and exprs:
        select = ", ".join(f"{e} AS g{i}" for i, e in enumerate(exprs))
        rows = con.execute(f"""SELECT {select}, count(*) AS n, count(DISTINCT ev_host) AS hosts,
                min(ev_ts) AS dau, max(ev_ts) AS cuoi, list(DISTINCT ev_host) AS may
                FROM events WHERE {where} GROUP BY ALL ORDER BY n DESC, 1 LIMIT 25""").fetchall()
        for r in rows:
            groups.append({"nhom": dict(zip(exprs, map(_clean, r[:len(exprs)]))), "so_su_kien": r[len(exprs)],
                           "so_may": r[len(exprs) + 1], "dau": _clean(r[len(exprs) + 2]),
                           "cuoi": _clean(r[len(exprs) + 3]), "may": sorted(r[len(exprs) + 4])})
    distinct = con.execute(f"SELECT count(*) FROM (SELECT DISTINCT {', '.join(exprs)} FROM events WHERE {where})"
                           ).fetchone()[0] if total and exprs else 0
    return {"channel": channel, "event_ids": list(eids), "so_su_kien": total, "gom_theo": exprs,
            "so_nhom": distinct, "nhom_lon_nhat": groups}


def _fields(expr: str) -> list[str]:
    import re
    return [t for t in re.findall(r'"?[A-Za-z][A-Za-z0-9_]*"?', expr)
            if t.strip('"') not in {"left", "coalesce", "regexp_replace"}]


def survey(root: Path, dataset: str, contract_id: str, sha: str) -> dict:
    events = root / "data/dev" / dataset
    manifest = json.loads((events / "ingest_manifest.json").read_text(encoding="utf-8"))
    check_dataset(events, root)
    check_manifest(events, dataset, sha, root)
    if integrity.sha256_file(Path(manifest["source"])) != sha:
        raise ValueError(f"{dataset}: gói gốc khác SHA256 E1 đã chốt")
    contract = root / f"dev/contract_a_v2/contract_a_{contract_id}.json"
    ca = ContractA.model_validate_json(contract.read_text(encoding="utf-8"))
    ds = config.load("dataset", root)
    catalog = s3_telemetry.load_catalog(config.resolve(ds["telemetry_catalog"], root))
    con = connect(events)
    try:
        _, checks = _event_checks(con, {"manifest_rows": manifest["rows"]}, root)
        effective = s3_telemetry.apply_profile(catalog, s3_telemetry.build_profile(con, catalog, dataset))
        ttps, sources = [], {}
        for t in ca.ttps:
            m = s3_telemetry.map_technique(t.technique_id, effective)
            ttps.append({"technique_id": t.technique_id, "status": m["status"],
                         "nguon": [(s["channel"], s["event_ids"]) for s in m.get("sources", [])]})
            for s in m.get("sources", []):
                sources.setdefault((s["channel"], tuple(s["event_ids"])), s)
        result = {"dataset_id": dataset, "contract_a": contract_id, "events_checks": checks,
                  "parquet_sha256": integrity.sha256_file(events / "events.parquet"),
                  "contract_sha256": integrity.sha256_file(contract), "ttps": ttps,
                  "nguon": [survey_source(con, s) for s in sources.values()]}
        if dataset in PROPOSALS:
            eids, rule = PROPOSALS[dataset]
            result["de_xuat_loc"] = proposal(con, rule, eids, root)
        return result
    finally:
        con.close()


def run(out: Path, root: Path = config.ROOT) -> dict:
    root, out = Path(root).resolve(), Path(out).resolve()
    if not out.is_relative_to(root / "data/dev") or out == root / "data/dev" or out.exists():
        raise ValueError("cần thư mục mới trong data/dev, không ghi đè bằng chứng cũ")
    ledger = root / "data/dev/api_budget.sqlite"
    before = integrity.sha256_file(ledger)
    result = {"kind": "otrf_filter_candidate_survey_unlabeled", "at_utc": datetime.now(timezone.utc).isoformat(),
              "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(),
              "api_called": False, "human_decisions_written": False, "prefix_chars": PREFIX,
              "datasets": [survey(root, d, *v) for d, v in DATASETS.items()]}
    if integrity.sha256_file(ledger) != before:
        raise ValueError("sổ ngân sách đổi trong lúc khảo sát")
    result["api_ledger_sha256"] = before
    out.mkdir(parents=True)
    F._write(out / "survey.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    result = run(args.out)
    for d in result["datasets"]:
        print(d["dataset_id"], [(t["technique_id"], t["status"]) for t in d["ttps"]])
        for s in d["nguon"]:
            print("   ", s["channel"], s["event_ids"], "sự kiện", s["so_su_kien"], "nhóm", s["so_nhom"])
    print(f"Đã ghi {args.out / 'survey.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
