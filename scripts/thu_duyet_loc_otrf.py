"""Thử cổng lọc v2 trên đúng OTRF phát triển, không API và không tự điền phiếu.

Tái dùng H01/rule đã lưu của sonnet5_pipeline_03 và _04, cùng dữ liệu đã ghim.
Thêm một rule mock cố ý rộng để kiểm nhóm AND và union chồng lấn; không khẳng
định đây là mẫu lành tính. Hai phiếu có lọc giữ trống. Chỉ rule không có lọc
được thực thi không nhãn, với mẫu kết quả bằng 0 (số đếm vẫn đầy đủ).

    python scripts/thu_duyet_loc_otrf.py --out data/dev/duyet_loc_otrf_v2_01
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import yaml

from cti_hunt import approval, config, filter_approval as F, integrity
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.agent.dev_data import check_manifest
from cti_hunt.agent.session import check_dataset, tracked_files
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner
from cti_hunt.hunt.observe import run_unlabeled, unlabeled_result
from cti_hunt.llm.prompting import load_sections
from cti_hunt.stages import s5_rule

SOURCES = (
    ("otrf-schtasks", "sonnet5_pipeline_03", "DEV-SCHTASKS-H01",
     "74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b"),
    ("otrf-wmi-exec", "sonnet5_pipeline_04", "DEV-WMIEXEC-H01",
     "96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88"),
)
MOCK_RULE = r"""title: MOCK ONLY - overlapping filter groups, no benign claim
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  filter_mock_image:
    Image|startswith: 'C:\Windows\System32\'
  filter_mock_event:
    EventID: 1
  condition: selection and not (filter_mock_image and filter_mock_event) and not filter_mock_event
level: low
"""


class RuleMock:
    model_id = "mock-filter-structure"

    def __init__(self):
        self.calls = 0

    def complete_json(self, system, user, json_schema, log=None):
        if json_schema["title"] != "LLMRule":
            raise ValueError("mock chỉ hỗ trợ sinh rule cố định")
        self.calls += 1
        return {"rule_yaml": MOCK_RULE, "note": "MOCK ONLY: không phải bằng chứng lành tính"}


def _json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _snapshot(paths):
    return {str(p.resolve()): integrity.sha256_file(p) for p in paths}


def _source(root, dataset, old_run, hid, sha):
    events = root / "data/dev" / dataset
    old = root / "data/dev" / old_run
    review = old / "round_01"
    manifest_path = events / "ingest_manifest.json"
    m = _json(manifest_path)
    check_dataset(events, root)
    check_manifest(events, dataset, sha, root)
    approval.verify_saved_review(review)
    hyps = [h for h in approval.load_hypotheses(review / approval.APPROVED_FILE)
            if h.hypothesis_id == hid and h.status == "approved"]
    if len(hyps) != 1:
        raise ValueError("cần đúng H01 đã duyệt, không tự điền phiếu giả thuyết")
    meta = _json(old / "run_meta.json")
    parquet_sha = integrity.sha256_file(events / "events.parquet")
    if (meta["dataset"] != {"kind": "otrf_dev", "id": dataset, "sha256": sha}
            or Path(meta["events"]["dir"]).resolve() != events.resolve()
            or meta["events"]["parquet_sha256"] != parquet_sha):
        raise ValueError("dữ liệu không còn khớp lượt giả thuyết/rule đã duyệt")
    rule_path = review / "rules" / f"{hid}.yml"
    paths = [manifest_path, events / "events.parquet", old / "run_meta.json",
             *[review / name for name in (approval.HYP_FILE, approval.REVIEW_FILE,
                                          approval.APPROVED_FILE, approval.LOG_FILE)],
             rule_path]
    archive = Path(m["source"])
    if not archive.is_file() or integrity.sha256_file(archive) != sha:
        raise ValueError("gói OTRF gốc thiếu hoặc khác SHA256 E1 đã chốt")
    paths.append(archive)
    return {"dataset_id": dataset, "events": events, "hypothesis": hyps[0],
            "rule": rule_path, "paths": paths, "manifest_rows": m["rows"],
            "source_sha256": sha, "parquet_sha256": parquet_sha,
            "previous_review_dir": str(review),
            "previous_reviewer": _json(review / approval.LOG_FILE)["nguoi_duyet"]}


def _event_checks(con, source, root):
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    if {c.lower() for c in columns} & {"buoc", "labeled", "attack_labels"}:
        raise ValueError("không nhận trường nhãn")
    rows, keys, missing = con.execute("""SELECT count(*),
        count(DISTINCT (ev_host, ev_channel, ev_rec)),
        count(*) FILTER (WHERE ev_host IS NULL OR ev_channel IS NULL OR ev_rec IS NULL OR ev_ts IS NULL)
        FROM events""").fetchone()
    if rows != source["manifest_rows"] or keys != rows or missing:
        raise ValueError("OTRF thực tế lệch manifest/khóa/thời điểm")
    hosts = {h.upper() for (h,) in con.execute("SELECT DISTINCT ev_host FROM events").fetchall()}
    forbidden = {h.upper() for h in config.load("dataset", root)["raw"]["hosts"]}
    if hosts & forbidden:
        raise ValueError("OTRF có máy trùng tập đánh giá")
    return columns, {"rows": rows, "unique_keys": keys, "missing_keys_or_time": missing,
                     "hosts": sorted(hosts), "evaluation_host_overlap": sorted(hosts & forbidden)}


def _case(root, out, name, source, dependencies, catalog, prompt, *, mock=False):
    case_root = out / name
    inputs = case_root / "inputs"
    inputs.mkdir(parents=True)
    con = connect(source["events"])
    try:
        columns, checks = _event_checks(con, source, root)
        mock_calls = 0
        rule_path = source["rule"]
        if mock:
            client = RuleMock()
            result = s5_rule.generate_rule(source["hypothesis"], client, prompt, catalog, 0,
                                          columns, con, inputs, filter_policy=F.POLICY)
            if not result["hop_le"] or client.calls != 1 or any(a["api_events"] for a in result["lan_thu"]):
                raise ValueError("mock không qua kiểm tĩnh hoặc xuất hiện API event")
            mock_calls = client.calls
            rule_path = inputs / "mock_rule.yml"
            rule_path.write_bytes(result["rule_yaml"].encode("utf-8"))
        errors, specs = s5_rule.validate_rule(rule_path.read_text(encoding="utf-8"), source["hypothesis"],
                                            catalog, columns, con, filter_policy=F.POLICY)
        if errors or len(specs) != 1:
            raise ValueError("; ".join(e.message for e in errors) or "cần đúng một spec theo nguồn đã duyệt")
        F.bind(con, case_root, dependencies=[*dependencies, *source["paths"], rule_path])
        rd = F.prepare(con, specs, case_root, case_root / "filter_review/r01",
                       context={"kind": "otrf_development_gate_check", "mock_rule": mock,
                                "mock_calls": mock_calls, "api_called": False,
                                "rule_path": str(rule_path), "dataset_id": source["dataset_id"],
                                "previous_review_dir": source["previous_review_dir"]})
        _, form = F.validate_form(rd, con=con, complete=False)
        if form["nguoi_duyet"] or any(row[k] for row in form["muc_loc"] for k in F.HUMAN_FIELDS):
            raise ValueError("phiếu mới phải trống, người duyệt tự điền")
        preview = F._read(rd / "preview.json")[0]
        try:
            run_unlabeled(con, specs[0], sample_limit=0)
        except F.FilterReviewError:
            draft_blocked = True
        else:
            raise ValueError("draft lọt cổng truy vấn")
        execution = None
        if form["muc_loc"]:
            try:
                F.finalize(rd, con=con)
            except F.PendingFilterReview:
                status = "waiting_for_human_filter_review"
            else:
                raise ValueError("pending không chặn finalize")
            if (rd / F.EFFECTIVE).exists() or (rd / "approval_log.json").exists():
                raise ValueError("pending đã sinh artifact hiệu lực")
        else:
            files = F.finalize(rd, con=con)
            started = F.utcnow().isoformat()
            # Full counts, zero detail samples: do not duplicate raw task payloads.
            results = [unlabeled_result(con, runner.load_spec(p, con=con), detail_limit=0) for p in files]
            F.receipt(rd, con=con, executed_at=started)
            execution = {"kind": "effective_execution_unlabeled", "api_called": False,
                         "results": results, "original_receipt": F._read(rd / "execution_receipt.json")}
            F._write(case_root / "execution.json", execution)
            status = "completed_no_filters"
        summary = {"case": name, "status": status, "dataset_id": source["dataset_id"],
                   "source_sha256": source["source_sha256"], "parquet_sha256": source["parquet_sha256"],
                   "events_checks": checks, "hypothesis_id": source["hypothesis"].hypothesis_id,
                   "previous_review_dir": source["previous_review_dir"],
                   "previous_reviewer": source["previous_reviewer"],
                   "rule_path": str(rule_path), "rule_sha256": integrity.sha256_file(rule_path),
                   "mock_rule": mock, "mock_calls": mock_calls, "api_called": False,
                   "draft_execution_blocked": draft_blocked, "review_dir": str(rd),
                   "manifest_sha256": integrity.sha256_file(rd / F.MANIFEST),
                   "preview_sha256": integrity.sha256_file(rd / "preview.json"),
                   "form_sha256_at_prepare": integrity.sha256_file(rd / F.FORM),
                   "decisions": {"approved": 0, "rejected": 0, "pending": len(form["muc_loc"])},
                   "preview": {k: v for k, v in preview.items() if k != "filters"},
                   "filter_matches": [{"id": f["id"], "matched": f["matched"], "sample_count": len(f["sample"])}
                                      for f in preview["filters"]],
                   "executed_final_hits": execution["results"][0]["giai_doan"][-1]["hits"] if execution else None}
        F._write(case_root / "verification.json", summary)
        return summary
    finally:
        con.close()


def run(out, root=config.ROOT):
    root, out = Path(root).resolve(), Path(out).resolve()
    if not out.is_relative_to(root / "data/dev") or out.exists():
        raise ValueError("cần thư mục mới trong data/dev, không ghi đè lượt cũ")
    cfg = config.agent_config("v2", root)
    sources = [_source(root, *args) for args in SOURCES]
    dependencies = [config.resolve(p, root) for p in tracked_files(root, "v2")]
    dependencies.append(Path(__file__).resolve())
    originals = list(dict.fromkeys([*dependencies, *[p for s in sources for p in s["paths"]],
                                   root / "data/dev/api_budget.sqlite"]))
    before = _snapshot(originals)
    catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset", root)["logsource_catalog"], root))
    prompt = load_sections(config.resolve(cfg["prompt_khau5"], root), ("SYSTEM", "USER", "REPAIR"))
    with patch("cti_hunt.llm.providers.from_config", side_effect=RuntimeError("cấm dựng client API trong phép thử")):
        cases = [_case(root, out, "wmi_saved", sources[1], dependencies, catalog, prompt),
                 _case(root, out, "wmi_mock_groups", sources[1], dependencies, catalog, prompt, mock=True),
                 _case(root, out, "schtasks_no_filters", sources[0], dependencies, catalog, prompt)]
    if _snapshot(originals) != before:
        raise ValueError("đầu vào gốc/mã/config/prompt/sổ ngân sách đã đổi trong phép thử")
    result = {"kind": "otrf_development_filter_gate_check", "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
              "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(),
              "api_called": False, "planner_called": False, "mock_rule_calls": 1,
              "human_decisions_written": False, "original_inputs_unchanged": True,
              "api_ledger_sha256": before[str((root / "data/dev/api_budget.sqlite").resolve())],
              "original_input_sha256": before, "cases": cases}
    F._write(out / "verification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.out)
    print(json.dumps({"verification": str(args.out / "verification.json"),
                      "cases": [{k: c[k] for k in ("case", "status", "decisions", "preview",
                                                    "filter_matches", "executed_final_hits")} for c in result["cases"]]},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
