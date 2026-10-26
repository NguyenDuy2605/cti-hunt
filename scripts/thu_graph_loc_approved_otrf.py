"""Graph pipeline v2 trên OTRF scheduled task: kiểm nhánh lọc approved, mock mọi client.

Rule ⑤ mock do agent soạn: selection Security 4698 như DEV-SCHTASKS-H01 cũ, cộng hai nhóm
lọc hẹp cho hai tác vụ UpdateOrchestrator do SYSTEM tạo rồi xóa trên WORKSTATION6. Căn cứ
và giới hạn ở docs/METHODOLOGY.md. người vận hành tự điền cả hai phiếu; công cụ
không điền thay, không tạo chấp thuận. Chỉ thư mục mới trong data/dev; dùng chính script
này cho start/resume/inspect/probe-pending (lệnh agent thông thường không có lớp mock).
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from functools import partial
import json
from pathlib import Path
from unittest.mock import patch

import yaml

from cti_hunt import approval, config, filter_approval as F, integrity
from cti_hunt.agent import session, stage_tools
from cti_hunt.agent.dev_data import check_manifest
from cti_hunt.contracts import ContractA
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner
from cti_hunt.stages import s8_triage

from thu_duyet_loc_otrf import SOURCES, _event_checks
from thu_graph_duyet_loc_otrf import _forbidden, _human_forms, _probe, _read, _run_path, _snapshot

DATASET = "otrf-schtasks"
SOURCE_SHA = SOURCES[0][3]
CONTRACT = "dev/contract_a_v2/contract_a_DEV-SCHTASKS.json"
MARKER = "mock_trial_inputs.json"
KIND = "otrf_schtasks_graph_v2_approved_filter_mock_only"

# Giữ đúng hành vi/phạm vi/nguồn của DEV-SCHTASKS-H01 đã duyệt ở sonnet5_pipeline_03; người vận hành duyệt lại ở lượt mới.
HYPOTHESIS = {
    "ttp_refs": [0],
    "behavior": "Tạo mới một tác vụ lập lịch (scheduled task) trên máy cục bộ nhằm duy trì hiện diện",
    "scope": "Toàn bộ host và tài khoản trong log thu thập",
    "timeframe": "toàn bộ khoảng thời gian của log",
    "data_source": "security", "event_ids": [4698],
    "key_fields": ["TaskName", "TaskContent", "SubjectUserName", "Hostname"],
    "extra_techniques": [], "priority": "cao",
    "rationale": "MOCK: giả thuyết cố định để kiểm cổng lọc, không đo chất lượng sinh giả thuyết."}

# Mảnh một dòng: Splunk không khớp giá trị contains có CRLF (kiểm preflight), DuckDB có.
# TaskContent của bộ này thoát HTML (&lt; &gt;), nên mảnh giữ đúng dạng lưu trong log.
MOCK_RULE = r"""title: MOCK step5 agent-authored - Security 4698 task creation, two narrow USO filter groups
status: experimental
description: Rule mock do agent soan de kiem nhanh loc approved; khong phai dau ra mo hinh. Hai nhom loc chi la de xuat, can nguoi duyet quyet dinh.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter_uso_ac_power_download:
    Hostname: 'WORKSTATION6.theshire.local'
    SubjectUserSid: 'S-1-5-18'
    TaskName: '\Microsoft\Windows\UpdateOrchestrator\AC Power Download'
    TaskContent|contains|all:
      - '&lt;Command&gt;%systemroot%\system32\usoclient.exe&lt;/Command&gt;'
      - '&lt;Arguments&gt;StartDownload&lt;/Arguments&gt;'
  filter_uso_ac_power_install:
    Hostname: 'WORKSTATION6.theshire.local'
    SubjectUserSid: 'S-1-5-18'
    TaskName: '\Microsoft\Windows\UpdateOrchestrator\AC Power Install'
    TaskContent|contains|all:
      - '&lt;Command&gt;%systemroot%\system32\usoclient.exe&lt;/Command&gt;'
      - '&lt;Arguments&gt;StartInstall&lt;/Arguments&gt;'
  condition: selection and not filter_uso_ac_power_download and not filter_uso_ac_power_install
level: low
tags:
  - attack.t1053.005
  - attack.persistence
"""


class SchtasksMock:
    model_id = "mock-schtasks-approved-filter-gate"

    def __init__(self, calls):
        self.calls = calls

    def describe(self):
        return {"model": self.model_id, "kieu_api": "mock", "network_allowed": False}

    def complete_json(self, system, user, json_schema, log=None):
        title = json_schema["title"]
        self.calls.append(title)
        if title == "LLMHypothesisBatch":
            return {"items": [dict(HYPOTHESIS)]}
        if title == "LLMRule":
            return {"rule_yaml": MOCK_RULE,
                    "note": "MOCK ⑤ do agent soạn; hai nhóm lọc chỉ là đề xuất, người duyệt quyết định."}
        raise ValueError(f"mock không hỗ trợ lược đồ {title!r}")


@contextmanager
def mock_only(calls):
    """Cùng lớp chặn cho start, inspect, probe và resume ở tiến trình mới."""
    with ExitStack() as stack:
        stack.enter_context(patch("cti_hunt.llm.providers.from_config", side_effect=lambda cfg: SchtasksMock(calls)))
        for target in ("cti_hunt.llm.providers.AnthropicClient", "cti_hunt.llm.providers.OpenAICompatibleClient",
                       "socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection"):
            stack.enter_context(patch(target, side_effect=_forbidden))
        # Không nhân bản payload thô; SQL, số đếm, ⑦/⑧ và tập khóa vẫn đầy đủ.
        stack.enter_context(patch.object(stage_tools, "run_unlabeled", partial(stage_tools.run_unlabeled, sample_limit=0)))
        stack.enter_context(patch.object(stage_tools, "unlabeled_result", partial(stage_tools.unlabeled_result, detail_limit=0)))
        yield


def _inputs(root):
    events = root / "data/dev" / DATASET
    contract = root / CONTRACT
    manifest_path = events / "ingest_manifest.json"
    m = _read(manifest_path)
    session.check_dataset(events, root)
    check_manifest(events, DATASET, SOURCE_SHA, root)
    archive = Path(m["source"])
    if integrity.sha256_file(archive) != SOURCE_SHA:
        raise ValueError("gói OTRF scheduled task khác SHA256 E1 đã chốt")
    ca = ContractA.model_validate_json(contract.read_text(encoding="utf-8"))
    if ca.report_id != "DEV-SCHTASKS" or len(ca.ttps) != 1 or ca.ttps[0].technique_id != "T1053.005":
        raise ValueError("cần đúng Contract A phát triển scheduled task, một TTP T1053.005")
    con = connect(events)
    try:
        _, checks = _event_checks(con, {"manifest_rows": m["rows"]}, root)
    finally:
        con.close()
    here = Path(__file__)
    paths = [config.resolve(p, root) for p in session.tracked_files(root, "v2")]
    paths += [here, here.with_name("thu_graph_duyet_loc_otrf.py"), here.with_name("thu_duyet_loc_otrf.py"),
              contract, manifest_path, archive, events / "events.parquet", root / "data/dev/api_budget.sqlite"]
    return contract, events, checks, _snapshot(paths)


def _validate_trial(out, root):
    marker = _read(out / MARKER)
    if (marker["kind"] != KIND or Path(marker["run_dir"]).resolve() != out
            or Path(marker["repo_root"]).resolve() != root):
        raise ValueError("thư mục không phải lượt graph mock này")
    meta = _read(out / session.META_FILE)
    if (meta.get("phien_ban") != "v2" or meta["mode"] != "pipeline"
            or meta["dataset"] != {"kind": "otrf_dev", "id": DATASET, "sha256": SOURCE_SHA}
            or integrity.sha256_file(out / session.META_FILE) != marker["run_meta_sha256"]):
        raise ValueError("run_meta khác lượt mock đã ghim")
    contract, events, _, now = _inputs(root)
    if (now != marker["immutable_inputs_sha256"]
            or Path(meta["contract_a"]["path"]).resolve() != contract.resolve()
            or Path(meta["events"]["dir"]).resolve() != events.resolve()):
        raise ValueError("đầu vào, công cụ mock hoặc sổ ngân sách đã đổi; không tiếp tục lượt cũ")
    session._check_unchanged(meta, root)
    return marker, events


def _keys(con, sql):
    return set(con.execute(sql).fetchall())


def _verify_spec(con, spec, observation):
    """Tập khóa đầy đủ: C, từng C∩Fi đề xuất, union khử trùng, tập còn lại sau đúng các mục approved."""
    rd = Path(spec["filter_review"]["dir"])
    manifest = F._read(rd / F.MANIFEST)
    draft = next(s for s in manifest["specs"] if s["id"] == spec["id"])
    preview = next(p for p in F._read(rd / "preview.json") if p["hunt_id"] == spec["id"])
    decisions = {r["id"]: r["quyet_dinh"] for r in F.load_form(rd)["muc_loc"]}
    candidate = (f"SELECT ev_host, ev_channel, ev_rec FROM events "
                 f"WHERE {runner._scope_where(draft['scope'])} AND ({draft['candidates']})")
    c = _keys(con, candidate)
    proposed = []
    for f in draft["filters"]:
        hit = _keys(con, candidate + f" AND (({f['where']}) IS TRUE)")
        shown = next(p for p in preview["filters"] if p["id"] == f["id"])
        if len(hit) != shown["matched"]:
            raise ValueError("số khớp từng mục khác preview đã phát")
        proposed.append({"id": f["id"], "decision": decisions[f"{spec['id']}__{f['id']}"],
                         "matched": len(hit), "keys": sorted(hit)})
    union_all = set().union(*[set(map(tuple, p["keys"])) for p in proposed])
    if len(c) != preview["candidates"] or len(union_all) != preview["union_removed"]:
        raise ValueError("ứng viên hoặc union khác preview đã phát")
    approved = [p["id"] for p in proposed if p["decision"] == "approved"]
    if [f["id"] for f in spec["filters"]] != approved or any(f.get("status") != "approved" for f in spec["filters"]):
        raise ValueError("spec hiệu lực không đúng tập mục approved")
    if spec["candidates"] != draft["candidates"] or spec["scope"] != draft["scope"]:
        raise ValueError("spec hiệu lực đổi ứng viên hoặc phạm vi")
    remaining, stages = set(c), []
    for p in proposed:
        if p["decision"] == "approved":
            remaining -= set(map(tuple, p["keys"]))
            stages.append(len(remaining))
    rows = s8_triage.final_rows(con, spec, {r[0] for r in con.execute("DESCRIBE events").fetchall()})
    actual = {(r["ev_host"], r["ev_channel"], r["ev_rec"]) for r in rows}
    observed = [s["hits"] for s in observation["stages"]]
    if actual != remaining or observed[1:] != [len(c), *stages]:
        raise ValueError("số graph hoặc tập khóa sau lọc không khớp")
    rejected = set().union(*[set(map(tuple, p["keys"])) for p in proposed if p["decision"] == "rejected"])
    if not (rejected - (c - remaining)) <= actual:
        raise ValueError("mục rejected đã loại sự kiện")
    return {"hunt_id": spec["id"], "review_dir": str(rd), "candidates": len(c), "candidate_keys": sorted(c),
            "proposed_filters": proposed, "union_all_proposed": len(union_all),
            "approved_filters": approved, "removed_by_approved": len(c - remaining),
            "final": len(remaining), "final_keys": sorted(remaining), "observed_stages": observation["stages"]}


def _completed(out, events):
    """Đối chiếu số graph với tập khóa đầy đủ, hash phiếu/log, record và audit giữ nguyên receipt."""
    record = _read(out / "agent_dev_record.json")
    md = (out / "hunt_record.md").read_text(encoding="utf-8")
    if [s for s in md.splitlines() if s.startswith("## ")] != ["## Learn", "## Observe", "## Check", "## Keep"]:
        raise ValueError("Hunt Record thiếu bốn mục LOCK")
    con = connect(events)
    try:
        cases, keys = [], set()
        for row in record["executed_specs"]:
            spec = runner.load_spec(Path(row["path"]), con=con)
            observation = next(o for o in record["observations"] if o["hunt_id"] == spec["id"])
            case = _verify_spec(con, spec, observation)
            for p in case["proposed_filters"]:
                if f"| {spec['id']}__{p['id']} | {p['decision']} |" not in md:
                    raise ValueError("Hunt Record thiếu quyết định lọc của người duyệt")
            cases.append(case)
            keys |= set(map(tuple, case["final_keys"]))
        reviews = []
        for rd in sorted(out.glob("round_*/filter_review/r*")):
            receipt = rd / "execution_receipt.json"
            before = integrity.sha256_file(receipt)
            with F.audit_context(con, rd):
                for path in (Path(p) for p in _read(rd / F.EFFECTIVE)["files"]):
                    stage_tools.unlabeled_result(con, runner.load_spec(path, con=con))
            if integrity.sha256_file(receipt) != before:
                raise ValueError("audit đã ghi lại receipt")
            log = _read(rd / "approval_log.json")
            if log["phieu_sha256"] != integrity.sha256_file(rd / F.FORM):
                raise ValueError("phiếu lọc đổi sau khi ghi log quyết định")
            reviews.append({"review_dir": str(rd), "receipt_sha256": before,
                            "manifest_sha256": integrity.sha256_file(rd / F.MANIFEST),
                            "form_sha256": integrity.sha256_file(rd / F.FORM),
                            "approval_log_sha256": integrity.sha256_file(rd / "approval_log.json"),
                            "effective_manifest_sha256": integrity.sha256_file(rd / F.EFFECTIVE),
                            "reviewer": log["nguoi_duyet"], "decided_at_utc": log["thoi_diem_utc"]})
        return {"cases": cases, "distinct_final_keys": sorted(keys), "unique_final_events": len(keys),
                "reviews_audited": reviews, "hunt_record_sha256": integrity.sha256_file(out / "hunt_record.md")}
    finally:
        con.close()


def run(action, out, root=config.ROOT):
    root = Path(root).resolve()
    out = _run_path(out, root)
    if action not in ("start", "resume", "inspect", "probe-pending"):
        raise ValueError("hành động không hợp lệ")
    calls = []
    if action == "start":
        if out.exists():
            raise ValueError("start cần thư mục mới; không ghi đè lượt cũ")
        if session.git_state(root)["co_thay_doi_chua_commit"]:
            raise ValueError("commit mã/công cụ và tài liệu trước khi bắt đầu lượt chờ người vận hành duyệt")
        contract, events, checks, before = _inputs(root)
    else:
        marker, events = _validate_trial(out, root)
        checks, before = marker["events_checks"], marker["immutable_inputs_sha256"]
    forms_before = _human_forms(out)
    with mock_only(calls):
        if action == "start":
            result = session.start("pipeline", contract, events, out, dataset_kind="otrf_dev",
                                   dataset_id=DATASET, dataset_sha256=SOURCE_SHA, root=root, version="v2")
            if calls != ["LLMHypothesisBatch"] or result.get("review_kind") != "hypothesis":
                raise ValueError("start không dừng đúng cổng giả thuyết")
            form = yaml.safe_load((Path(result["review_dir"]) / approval.REVIEW_FILE).read_text(encoding="utf-8"))
            if form["nguoi_duyet"] or any(r["quyet_dinh"] or r["ly_do"] for r in form["gia_thuyet"]):
                raise ValueError("phiếu mới phải để người vận hành tự điền")
        elif action == "probe-pending":
            result = _probe(out, root, calls)
        elif action == "inspect":
            result = session.inspect(out, root)
        else:
            previous = session.inspect(out, root)
            if previous["trang_thai"] != "cho_duyet":
                raise ValueError("lượt không đang chờ phiếu; không thực thi lại lượt đã xong")
            result = session.resume(out, root)
            if previous["review_kind"] == "filter" and calls:
                raise ValueError("resume cổng lọc đã sinh lại giả thuyết/rule")
            if result.get("review_kind") == "filter":
                form = F.load_form(Path(result["review_dir"]))
                if form["nguoi_duyet"] or any(r[k] for r in form["muc_loc"] for k in F.HUMAN_FIELDS):
                    raise ValueError("phiếu lọc mới phải để người vận hành tự điền")
        verification = _completed(out, events) if result["trang_thai"] == "xong" else None
    if _snapshot(before) != before or _snapshot(forms_before) != forms_before:
        raise ValueError("đầu vào bất biến hoặc phiếu người duyệt bị thay đổi trong thao tác")
    if action == "start":
        F._write(out / MARKER, {"kind": KIND, "repo_root": str(root), "run_dir": str(out),
                               "run_meta_sha256": integrity.sha256_file(out / session.META_FILE),
                               "events_checks": checks, "immutable_inputs_sha256": before,
                               "mock_rule_author": "agent (không phải đầu ra mô hình)",
                               "evidence_doc": "docs/METHODOLOGY.md"})
    operations = out / "mock_operations"
    index = len(list(operations.glob("*.json"))) + 1
    evidence = {"kind": KIND, "action": action, "at_utc": datetime.now(timezone.utc).isoformat(),
                "api_called": False, "mock_calls": calls, "human_forms_written": False,
                "original_inputs_unchanged": True, "human_form_sha256": _human_forms(out),
                "api_ledger_sha256": before[str((root / "data/dev/api_budget.sqlite").resolve())],
                "result": result, "completed_verification": verification,
                "detail_sample_limit": 0, "event_key_verification": "full set after execution"}
    path = operations / f"{index:03d}_{action}.json"
    if path.exists():
        raise ValueError("không ghi đè bằng chứng thao tác cũ")
    F._write(path, evidence)
    return {**result, "mock_calls": calls, "verification": str(path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("start", "resume", "inspect", "probe-pending"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    result = run(args.action, args.out)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
