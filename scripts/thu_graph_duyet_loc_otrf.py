"""Graph pipeline v2 trên WMI OTRF: mock mọi client, người vận hành tự duyệt cả hai cổng.

Chỉ dùng thư mục mới trong data/dev. Dùng chính script này cho start/resume/
inspect/probe-pending; lệnh agent thông thường không có lớp mock của phép thử.
Không đổi commit, mã, config, prompt hoặc đầu vào khi lượt còn chờ duyệt.
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

from thu_duyet_loc_otrf import MOCK_RULE, SOURCES, _event_checks

DATASET = "otrf-wmi-exec"
SOURCE_SHA = SOURCES[1][3]
MARKER = "mock_trial_inputs.json"
KIND = "otrf_wmi_graph_v2_human_review_mock_only"
SYS = "microsoft-windows-sysmon/operational"


class WMIMock:
    model_id = "mock-wmi-two-human-gates"

    def __init__(self, calls):
        self.calls = calls

    def describe(self):
        return {"model": self.model_id, "kieu_api": "mock", "network_allowed": False}

    def complete_json(self, system, user, json_schema, log=None):
        title = json_schema["title"]
        self.calls.append(title)
        if title == "LLMHypothesisBatch":
            return {"items": [{
                "ttp_refs": [0],
                "behavior": "Tìm tiến trình có tiến trình cha WmiPrvSE.exe, dấu hiệu cần kiểm tra của thực thi qua WMI.",
                "scope": "mọi máy và tài khoản trong log",
                "timeframe": "toàn bộ log",
                "data_source": SYS, "event_ids": [1],
                "key_fields": ["ParentImage", "Image", "CommandLine", "User", "Hostname"],
                "extra_techniques": [], "priority": "cao",
                "rationale": "MOCK: giả thuyết cố định để kiểm graph, không đo chất lượng sinh giả thuyết."}]}
        if title == "LLMRule":
            return {"rule_yaml": MOCK_RULE, "note": "MOCK ONLY: hai nhóm chồng lấn, chưa có căn cứ lành tính."}
        raise ValueError(f"mock không hỗ trợ lược đồ {title!r}")


def _forbidden(*args, **kwargs):
    raise RuntimeError("Phép thử này cấm client API thật và kết nối mạng")


@contextmanager
def mock_only(calls):
    """Dùng cùng lớp chặn khi start, inspect, probe và resume ở tiến trình mới."""
    with ExitStack() as stack:
        stack.enter_context(patch("cti_hunt.llm.providers.from_config", side_effect=lambda cfg: WMIMock(calls)))
        for target in ("cti_hunt.llm.providers.AnthropicClient", "cti_hunt.llm.providers.OpenAICompatibleClient",
                       "socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection"):
            stack.enter_context(patch(target, side_effect=_forbidden))
        # Không nhân bản payload thô; SQL, số đếm, ⑦/⑧ và tập khóa vẫn đầy đủ.
        stack.enter_context(patch.object(stage_tools, "run_unlabeled", partial(stage_tools.run_unlabeled, sample_limit=0)))
        stack.enter_context(patch.object(stage_tools, "unlabeled_result", partial(stage_tools.unlabeled_result, detail_limit=0)))
        yield


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _snapshot(paths):
    return {str(Path(p).resolve()): integrity.sha256_file(Path(p)) for p in paths}


def _run_path(out, root):
    out = Path(out).resolve()
    if not out.is_relative_to(root / "data/dev") or out == root / "data/dev":
        raise ValueError("lượt phải nằm trong một thư mục riêng dưới data/dev")
    return out


def _inputs(root):
    events = root / "data/dev" / DATASET
    contract = root / "dev/contract_a_v2/contract_a_DEV-WMIEXEC.json"
    manifest_path = events / "ingest_manifest.json"
    m = _read(manifest_path)
    session.check_dataset(events, root)
    check_manifest(events, DATASET, SOURCE_SHA, root)
    archive = Path(m["source"])
    if integrity.sha256_file(archive) != SOURCE_SHA:
        raise ValueError("gói WMI OTRF khác SHA256 E1 đã chốt")
    ca = ContractA.model_validate_json(contract.read_text(encoding="utf-8"))
    if ca.report_id != "DEV-WMIEXEC" or len(ca.ttps) != 1 or ca.ttps[0].technique_id != "T1047":
        raise ValueError("cần đúng Contract A phát triển WMI, một TTP T1047")
    con = connect(events)
    try:
        _, checks = _event_checks(con, {"manifest_rows": m["rows"]}, root)
    finally:
        con.close()
    paths = [config.resolve(p, root) for p in session.tracked_files(root, "v2")]
    paths += [Path(__file__), Path(__file__).with_name("thu_duyet_loc_otrf.py"), contract,
              manifest_path, archive, events / "events.parquet", root / "data/dev/api_budget.sqlite"]
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


def _human_forms(out):
    return _snapshot([*out.glob("round_*/duyet.yaml"), *out.glob("round_*/filter_review/r*/duyet_loc.yaml")])


def _probe(out, root, calls):
    state = session.inspect(out, root)
    if state["trang_thai"] != "cho_duyet":
        raise ValueError("probe chỉ dùng khi lượt đang chờ duyệt")
    rd = Path(state["review_dir"])
    if state["review_kind"] == "hypothesis":
        form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding="utf-8"))
        if any(str(r.get("quyet_dinh") or "").strip() for r in form["gia_thuyet"]):
            raise ValueError("probe giả thuyết chỉ dùng khi chưa điền quyết định")
        expected = session.SessionError
    else:
        form = F.load_form(rd)
        if not any(not r["quyet_dinh"] for r in form["muc_loc"]):
            raise ValueError("probe lọc cần ít nhất một mục chưa duyệt")
        expected = F.PendingFilterReview
    before = _snapshot([out / session.CHECKPOINT_FILE, *rd.rglob("*.json"), *rd.rglob("*.yaml")])
    try:
        session.resume(out, root)
    except expected as exc:
        if calls or _snapshot(before) != before or (rd / F.EFFECTIVE).exists():
            raise ValueError("probe pending đã gọi mock, đổi artifact hoặc tạo gói hiệu lực") from exc
        return {**state, "pending_resume_blocked": True, "error_type": type(exc).__name__}
    raise ValueError("phiếu chưa duyệt nhưng resume không bị chặn")


def _completed(out, events):
    """Đối chiếu số đếm graph với tập khóa đầy đủ và audit giữ nguyên receipt."""
    record = _read(out / "agent_dev_record.json")
    md = (out / "hunt_record.md").read_text(encoding="utf-8")
    if [s for s in md.splitlines() if s.startswith("## ")] != ["## Learn", "## Observe", "## Check", "## Keep"]:
        raise ValueError("Hunt Record thiếu bốn mục LOCK")
    con = connect(events)
    try:
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        keys, cases = set(), []
        for row in record["executed_specs"]:
            spec = runner.load_spec(Path(row["path"]), con=con)
            rows = s8_triage.final_rows(con, spec, columns)
            actual = {(r["ev_host"], r["ev_channel"], r["ev_rec"]) for r in rows}
            scope = runner._scope_where(spec["scope"])
            candidate = f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {scope} AND ({spec['candidates']})"
            expected = set(con.execute(candidate).fetchall())
            for f in spec["filters"]:
                expected -= set(con.execute(candidate + f" AND ({f['where']})").fetchall())
            observation = next(o for o in record["observations"] if o["hunt_id"] == spec["id"])
            if actual != expected or len(actual) != observation["stages"][-1]["hits"]:
                raise ValueError("số graph hoặc tập khóa sau lọc không khớp")
            keys |= actual
            cases.append({"hunt_id": spec["id"], "stages": observation["stages"],
                          "effective_filters": [f["id"] for f in spec["filters"]], "keys": sorted(actual)})
        receipts = []
        for rd in sorted(out.glob("round_*/filter_review/r*")):
            receipt = rd / "execution_receipt.json"
            before = integrity.sha256_file(receipt)
            with F.audit_context(con, rd):
                files = [Path(p) for p in _read(rd / F.EFFECTIVE)["files"]]
                for path in files:
                    stage_tools.unlabeled_result(con, runner.load_spec(path, con=con))
            if integrity.sha256_file(receipt) != before:
                raise ValueError("audit đã ghi lại receipt")
            receipts.append({"review_dir": str(rd), "receipt_sha256": before})
        return {"cases": cases, "distinct_event_keys": sorted(keys), "unique_events": len(keys),
                "receipts_audited": receipts, "hunt_record_sha256": integrity.sha256_file(out / "hunt_record.md")}
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
        verification = _completed(out, events) if result["trang_thai"] == "xong" else None
    if _snapshot(before) != before or _snapshot(forms_before) != forms_before:
        raise ValueError("đầu vào bất biến hoặc phiếu người duyệt bị thay đổi trong thao tác")
    if action == "start":
        F._write(out / MARKER, {"kind": KIND, "repo_root": str(root), "run_dir": str(out),
                               "run_meta_sha256": integrity.sha256_file(out / session.META_FILE),
                               "events_checks": checks, "immutable_inputs_sha256": before})
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
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
