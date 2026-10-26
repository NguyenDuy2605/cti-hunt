"""Validate and execute existing, explicitly approved rules without another model call.

For migration of pre-checkpoint demo artifacts. This does not manufacture graph
history or transfer approvals to newly generated hypotheses/rules.
"""
import json
from pathlib import Path

import yaml

from . import approval, config, demo, integrity
from .contracts import ContractA
from .data.store import connect
from .adapters import duckdb_sigma
from .hunt import runner
from .hunt.observe import run_unlabeled
from .stages import s3_telemetry, s5_rule, s7_rarity, s8_triage, s9_record, s1_ingest


def approved_rules(bundle: Path, extraction: Path, old_run: Path, events: Path, out: Path) -> dict:
    from .filter_approval import path_policy
    if path_policy(old_run / "rules"):
        raise ValueError("Replay v2 dùng effective_packet hoặc phát phiếu lọc mới từ rule đã lưu; không hạ xuống v1")
    if out.exists():
        raise ValueError("Thư mục replay đã tồn tại; giữ lượt cũ và dùng tên mới")
    contract_path = demo.verified_contract(bundle, extraction)
    dataset = demo.dataset(events)
    ca = ContractA.model_validate_json(contract_path.read_text(encoding="utf-8"))
    cov = json.loads((extraction / "coverage.json").read_text(encoding="utf-8"))
    events_hash = integrity.sha256_file(events / "events.parquet")
    if (cov.get("events_sha256") != events_hash
            or cov.get("contract_a_sha256") != integrity.sha256_file(contract_path)):
        raise ValueError("Coverage cũ không gắn với đúng Contract A/bộ log; không chuyển phiếu duyệt sang dữ liệu khác")
    form_path, hp = old_run / approval.REVIEW_FILE, old_run / approval.HYP_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    log = json.loads((old_run / approval.LOG_FILE).read_text(encoding="utf-8"))
    if (form.get("hypotheses_sha256") != integrity.sha256_file(hp)
            or log.get("hypotheses_sha256") != integrity.sha256_file(hp)
            or log.get("phieu_sha256") != integrity.sha256_file(form_path)):
        raise ValueError("Phiếu/hypotheses/approval log không khớp; không replay")
    hyps = approval.load_hypotheses(hp)
    saved = approval.load_hypotheses(old_run / approval.APPROVED_FILE)
    choices = {r["id"]: r.get("quyet_dinh") or "pending_review" for r in form["gia_thuyet"]}
    if set(choices) != {h.hypothesis_id for h in hyps} or len(choices) != len(form["gia_thuyet"]):
        raise ValueError("Phiếu có giả thuyết thiếu, thừa hoặc trùng")
    expected = [h.model_copy(update={"status": choices.get(h.hypothesis_id, "pending_review")}) for h in hyps]
    if [h.model_dump() for h in expected] != [h.model_dump() for h in saved] or not form.get("nguoi_duyet"):
        raise ValueError("File approved không khớp quyết định đã ghi")
    accepted = [h for h in saved if h.status == "approved"]
    if not accepted:
        raise ValueError("Không có giả thuyết approved")
    cfg = config.load("agent")
    catalog = s3_telemetry.load_catalog(config.resolve(config.load("dataset")["telemetry_catalog"]))
    ls = duckdb_sigma.load_catalog(config.resolve(config.load("dataset")["logsource_catalog"]))
    con = connect(events)
    try:
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        profile = s3_telemetry.build_profile(con, catalog, dataset["dataset_id"])
        telemetry = s3_telemetry.apply_profile(catalog, profile)
        out.mkdir(parents=True, exist_ok=False)
        (out / "hunts").mkdir()
        results, specs, statuses = [], [], []
        from .hunt.observe import unlabeled_result
        for h in accepted:
            rule_path = demo.inside(old_run / "rules" / f"{h.hypothesis_id}.yml", old_run)
            if not rule_path.exists():
                statuses.append({"id": h.hypothesis_id, "status": "missing_rule"})
                continue
            errors, bound = s5_rule.validate_rule(rule_path.read_text(encoding="utf-8"), h, ls, cols, con)
            statuses.append({"id": h.hypothesis_id, "rule_sha256": integrity.sha256_file(rule_path),
                             "status": "blocked" if errors else "validated",
                             "errors": [{"kind": e.kind, "message": e.message} for e in errors]})
            for n, spec in enumerate(bound):
                path = out / "hunts" / f"{h.hypothesis_id}_{n}.yaml"
                path.write_text(yaml.safe_dump(spec, allow_unicode=True), encoding="utf-8")
                spec = runner.load_spec(path)
                specs.append(spec)
                results.append(unlabeled_result(con, spec))
        rarity = s7_rarity.score(con, specs, window_seconds=int(cfg["rarity"]["recon_window_seconds"]),
                                 entropy_threshold=float(cfg["rarity"]["entropy_threshold"])) if specs else None
        tri = s8_triage.triage(con, specs, cfg) if specs else None
        if tri:
            tri["pivot"]["ly_do_dung"] = "Replay một lượt đã duyệt; pivot mới phải qua lượt graph và phiếu mới"
        md = s9_record.render(ca, telemetry, saved, results, rarity=rarity, triage=tri)
        (out / "hunt_record.md").write_text("# Replay rule đã duyệt — không gọi LLM, không phải lượt agent mới\n\n" + md, encoding="utf-8")
        record = {"kind": "development_only_unlabeled", "mode": "approved_rule_replay", "report_id": ca.report_id,
                  "dataset": {"id": dataset["dataset_id"], "events_sha256": events_hash},
                  "contract_a_sha256": integrity.sha256_file(contract_path), "approval_log_sha256": integrity.sha256_file(old_run / approval.LOG_FILE),
                  "rules": statuses, "observations": [run_unlabeled(con, s) for s in specs],
                  "rarity_summary": rarity, "triage": tri, "history": [],
                  "executed_specs": [{"path": s["_path"], "sha256": s["_sha256"]} for s in specs],
                  "hunt_record": str(out / "hunt_record.md"), "api_called": False}
        s1_ingest.write_json(out / "agent_dev_record.json", record)
        return record
    finally:
        con.close()


def effective_packet(review_dir: Path, con, out: Path, *, audit: bool = False) -> dict:
    """Execute/replay one immutable v2 packet on events only, never invoke a planner."""
    from contextlib import nullcontext
    from . import filter_approval as F
    from .hunt.observe import unlabeled_result
    if out.exists():
        raise ValueError("đầu ra đã tồn tại; dùng tệp mới")
    rd = review_dir.resolve()
    packet = F.verify_packet(rd, con=con)
    if audit:
        files = [Path(p) for p in F._read(rd / F.EFFECTIVE)["files"]]
        context = F.audit_context(con, rd)
    else:
        F.bind(con, Path(packet["run_root"]))
        files = F.finalize(rd, con=con)
        context = nullcontext()
    started = F.utcnow().isoformat()
    with context:
        specs = [runner.load_spec(p, con=con) for p in files]
        for s in specs:
            F.require_executable(s, con=con)
        results = [unlabeled_result(con, s) for s in specs]
    if not audit:
        F.receipt(rd, con=con, executed_at=started)
    record = {"kind": "audit_replay_only" if audit else "effective_execution_unlabeled",
              "api_called": False, "planner_called": False, "new_authorization": False,
              "manifest_sha256": F._sha(rd / F.MANIFEST), "effective_manifest_sha256": F._sha(rd / F.EFFECTIVE),
              "original_receipt": F._read(rd / "execution_receipt.json"), "replayed_at_utc": started,
              "results": results}
    F._write(out, record)
    return record
