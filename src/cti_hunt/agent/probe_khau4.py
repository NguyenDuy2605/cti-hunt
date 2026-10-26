"""One approved ④ v5 development probe (06/10): offline preparation, then the operator sends once."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import duckdb

from .. import config, integrity
from ..contracts import ContractA, ContractB, SourceSpan, TTP
from ..llm import budget, providers
from ..llm.prompting import fill, load_sections
from ..stages import s4_hypothesis as S4

PROBE_ID = "khau4-v5-0610-one-request"
CAP = "0.40"
OUT = config.ROOT / "tmp/thu_khau4_v5_6-10"
SYS = "microsoft-windows-sysmon/operational"
COUNT = {"truong": "DestinationIp", "theo": ["ev_host", "ProcessGuid"], "cua_so_giay": 120, "toi_thieu": 3}
ABSENCE = {"channel": SYS, "event_ids": [22], "khop": [
    {"ung_vien": "ev_host", "nguon": "ev_host"}, {"ung_vien": "ProcessGuid", "nguon": "ProcessGuid"}], "truoc_giay": 60}
ANCHOR = {"gia_thuyet": "PROBE-NEO-H01", "trong_vong_giay": 180, "cung": ["ev_host", "ProcessGuid"]}
QUOTES = [
    "In this fictional lab, each process, identified by its unique process GUID on a host, establishes "
    "connections to at least three distinct destination IP addresses in the centered interval extending "
    "120 seconds before and 120 seconds after a connection event. This is self-authored development text.",
    "In this fictional lab, a process makes a network connection with no DNS query from that same process GUID "
    "on the same host during the inclusive 60 seconds preceding the connection event. This is self-authored text.",
    "In this fictional lab, a process writes a downloaded file strictly after its process-start event, "
    "by at most 180 seconds, on the same host and with the same process GUID. This is self-authored text.",
    "In this fictional lab, a process connects to several destination IP addresses over a brief period. "
    "The description specifies no numeric threshold or time window. This is self-authored development text.",
]


def fixture():
    ca = ContractA(report_id="PROBE-0610", title="Self-authored ④ development probe", ttps=[
        TTP(tactic="Command and Control", technique_id="T1071" if i != 2 else "T1105",
            behavior_description=q, source_span=SourceSpan(segment_id=f"PROBE-{i+1:03d}", text=q), confidence=1.0)
        for i, q in enumerate(QUOTES)])
    telemetry = {
        "T1071": {"status": "huntable", "sources": [
            {"channel": SYS, "event_ids": [3], "key_fields": ["Image", "ProcessGuid", "DestinationIp", "DestinationPort"]},
            {"channel": SYS, "event_ids": [22], "key_fields": ["Image", "ProcessGuid", "QueryName"]}]},
        "T1105": {"status": "huntable", "sources": [
            {"channel": SYS, "event_ids": [11], "key_fields": ["Image", "ProcessGuid", "TargetFilename"]}]},
    }
    anchor = ContractB(hypothesis_id=ANCHOR["gia_thuyet"], behavior="Khởi tạo tiến trình trong fixture tự soạn",
        scope="máy tổng hợp", timeframe="toàn bộ khoảng thời gian của log", status="approved",
        evidence={"data_source": SYS, "event_ids": [1], "key_fields": ["Image", "ProcessGuid"]},
        linked_ttps=["T1059"], source_spans=[SourceSpan(segment_id="PROBE-NEO-001",
            text="Self-authored fixture: a process starts on a synthetic host with a unique process GUID.")])
    # Execute the synthetic anchor locally; no real ◆ form or evaluation events exist here.
    with duckdb.connect() as con:
        con.execute("CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, "
                    "ev_rec BIGINT, ev_ts TIMESTAMP, ProcessGuid VARCHAR, Image VARCHAR)")
        con.execute("INSERT INTO events VALUES ('FIXTURE', ?, 1, 1, TIMESTAMP '2020-01-01', 'fixture-guid', 'fixture.exe')", [SYS])
        keys = con.execute("SELECT ev_host, ev_channel, ev_rec FROM events WHERE ev_eid=1").fetchall()
    return ca, telemetry, [anchor], {"simulated": True, "executed_anchor_keys": keys}


def _dump(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write(path, value):
    Path(path).write_bytes(_dump(value))


def _ledger_status(path):
    """Read-only even in offline mode; never create/reset/change the shared budget."""
    if not Path(path).is_file():
        raise budget.BudgetError("Thiếu sổ ngân sách dùng chung")
    con = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        con.execute("BEGIN")
        limit, known, held, pending = budget.Ledger._state(con)
        return {"remaining_usd": budget.usd(limit - known - held), "pending_count": len(pending)}
    finally:
        con.close()


def build(root=config.ROOT):
    cfg, llm_cfg = config.agent_config("v2", root), config.load("llm_hunt", root)
    # This protocol pins the existing model/settings instead of lowering them to fit the cap.
    if (not cfg.get("sinh_rang_buoc") or cfg["prompt_khau4"] != "prompts/khau4_gia_thuyet_v5.md"
            or llm_cfg.get("provider") != "anthropic" or llm_cfg.get("model") != "claude-sonnet-5"
            or llm_cfg.get("effort") != "high" or llm_cfg.get("max_output_tokens") != 32000
            or llm_cfg.get("request_timeout_giay") != 600 or llm_cfg.get("base_url") not in (None, "", "https://api.anthropic.com")):
        raise ValueError("Cấu hình đã đổi so với phép thử được chốt; chưa gửi yêu cầu")
    ledger = config.resolve(llm_cfg["budget_ledger"], root)
    llm_cfg = {**llm_cfg, "budget_ledger": str(ledger)}
    client = providers.from_config(llm_cfg)
    client.request_budget_usd = CAP
    prompt = load_sections(config.resolve(cfg["prompt_khau4"], root))
    ca, telemetry, anchors, proof = fixture()
    inputs, _ = S4.select_inputs(ca, telemetry)
    user = fill(prompt["sections"]["USER"], report_id=ca.report_id, techniques=S4.render_inputs(inputs),
                max_items=str(cfg["max_hypotheses_per_round"]), executed_hypotheses=S4.render_anchors(anchors))
    payload = client.build_payload(prompt["sections"]["SYSTEM"], user, S4.output_model(cfg).model_json_schema())
    watched = ["configs/agent_v2.yaml", "configs/llm_hunt.yaml", cfg["filter_policy"], cfg["prompt_khau4"],
               "scripts/probe_khau4_v5.py", "src/cti_hunt/agent/probe_khau4.py",
               "src/cti_hunt/contracts.py", "src/cti_hunt/stages/s4_hypothesis.py",
               "src/cti_hunt/stages/s3_telemetry.py", "src/cti_hunt/llm/providers.py",
               "src/cti_hunt/llm/budget.py", "src/cti_hunt/llm/prompting.py", "src/cti_hunt/config.py"]
    protocol = {"probe_id": PROBE_ID, "cap_usd": CAP, "generation_attempts": 1,
                "data": "self_authored_only", "fixture_anchor": proof, "model": client.describe(),
                "rate_version": budget.RATE_VERSION,
                "payload_sha256": hashlib.sha256(_dump(payload)).hexdigest(),
                "files_sha256": {p: integrity.sha256_file(config.resolve(p, root)) for p in watched},
                "criteria": {"ref_0": {"dem_khac_nhau": COUNT}, "ref_1": {"vang_mat": ABSENCE},
                             "ref_2": {"moc_neo": ANCHOR}, "ref_3": "no_invented_numeric_constraint"}}
    return cfg, client, prompt, ca, telemetry, anchors, payload, protocol


def _canonical(value):
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value.lower() if isinstance(value, str) else value


def check_result(raw, accepted):
    """Parameter/coverage checks on self-authored cases, not a semantic-quality score."""
    try:
        items = S4.LLMHypothesisBatchV2.model_validate(raw).items
    except ValueError:
        return {"schema_ok": False, "criteria_met": False, "manual_review_required": True}
    expected = [(0, "dem_khac_nhau", COUNT, 3), (1, "vang_mat", ABSENCE, 3), (2, "moc_neo", ANCHOR, 11)]
    checks = {}
    for ref, kind, want, eid in expected:
        matched = [it for it in items if ref in it.ttp_refs]
        # Must also survive the real ④ postprocessor, with code-owned source quotes.
        retained = [h for h in accepted if any(s.segment_id == f"PROBE-{ref+1:03d}" for s in h.source_spans)]
        exact = bool(matched and retained)
        for it in matched:
            part = getattr(it.rang_buoc, kind, None) if it.rang_buoc else None
            exact &= part is not None and _canonical(part.model_dump()) == _canonical(want)
            exact &= it.data_source.lower() == SYS and set(it.event_ids) == {eid}
        checks[f"ref_{ref}_parameters_and_coverage"] = exact
    allowed = {0: {"dem_khac_nhau"}, 1: {"vang_mat"}, 2: {"moc_neo"}, 3: set()}
    grounded = True
    for it in items:
        refs = set(it.ttp_refs)
        grounded &= bool(refs) and refs <= set(allowed)
        kinds = {k for k, v in it.rang_buoc.model_dump(exclude_none=True).items() if v} if it.rang_buoc else set()
        grounded &= kinds <= set().union(*(allowed.get(r, set()) for r in refs))
        if 3 in refs:
            grounded &= not kinds
    checks["no_unreferenced_or_vague_numeric_constraint"] = grounded
    return {"schema_ok": True, "checks": checks, "criteria_met": all(checks.values()),
            "manual_review_required": True, "meaning": "kiểm tham số trên câu tự soạn; không phải chất lượng săn"}


class _ObservedClient:
    def __init__(self, client, out):
        self.client, self.out, self.events = client, out, []
        self.model_id = client.model_id

    def complete_json(self, system, user, schema, log=None):
        def record(event):
            self.events.append({k: event[k] for k in providers.SAFE_EVENT_KEYS if k in event})
            _write(self.out / "api_events.json", self.events)
            if log:
                log(event)
        return self.client.complete_json(system, user, schema, log=record)


def run(out=OUT, *, send=False, root=config.ROOT):
    out = Path(out)
    marker = out / "attempt.json"
    if marker.exists():
        raise ValueError(f"Phép thử đã được bắt đầu; không gửi lại. Xem {out / 'result.json'}")
    cfg, client, prompt, ca, telemetry, anchors, payload, protocol = build(root)
    if not send:
        out.mkdir(parents=True, exist_ok=True)
        _write(out / "protocol.json", protocol)
        _write(out / "payload.json", payload)
        _write(out / "contract_a.json", ca.model_dump(mode="json"))
        _write(out / "telemetry.json", telemetry)
        _write(out / "fixture_anchors.json", [h.model_dump(mode="json") for h in anchors])
        try:
            status = _ledger_status(client.budget_ledger)
        except (budget.BudgetError, sqlite3.Error) as exc:
            status = {"error_type": type(exc).__name__}
        preflight = {"mode": "OFFLINE_NO_API", "cap_usd": CAP, "out": str(out), "ledger": status,
                     "minimum_reservation_usd": budget.usd(budget.min_reserve(client.model_id, client.max_output_tokens)),
                     "exact_reservation": "computed by API token counting only when the operator sends",
                     "generation_attempts": 0, "model": client.model_id, "prompt_sha256": prompt["sha256"]}
        _write(out / "preflight.json", preflight)
        return preflight
    # A send must use the exact offline-prepared inputs/code, and the current shared budget.
    if not (out / "protocol.json").is_file() or (out / "protocol.json").read_bytes() != _dump(protocol):
        raise ValueError("Chưa chuẩn bị ngoại tuyến hoặc mã/đầu vào đã đổi; chưa gửi yêu cầu")
    for name, value in (("payload.json", payload), ("contract_a.json", ca.model_dump(mode="json")),
                        ("telemetry.json", telemetry), ("fixture_anchors.json", [h.model_dump(mode="json") for h in anchors])):
        if (out / name).read_bytes() != _dump(value):
            raise ValueError(f"{name} không khớp bản chuẩn bị; chưa gửi yêu cầu")
    status = _ledger_status(client.budget_ledger)
    if status["pending_count"] or budget.money(status["remaining_usd"], allow_zero=True) < budget.min_reserve(client.model_id, client.max_output_tokens):
        raise budget.BudgetError("Sổ có khoản chưa đối soát hoặc không đủ giữ trước; chưa gửi yêu cầu")
    if not os.environ.get(client.api_key_env):
        raise providers.LLMError(f"Chưa đặt {client.api_key_env}; chưa gửi yêu cầu")
    # Exclusive creation: concurrent/repeated invocations cannot both enter the API call.
    with marker.open("xb") as f:
        f.write(_dump({"probe_id": PROBE_ID, "state": "attempt_started_no_retry", "cap_usd": CAP,
                       "protocol_sha256": hashlib.sha256(_dump(protocol)).hexdigest()}))
    observed = _ObservedClient(client, out)
    try:
        result = S4.generate(ca, telemetry, observed, prompt, cfg, run_dir=out, anchors=anchors)
        _write(out / "hypotheses.json", [h.model_dump(mode="json") for h in result["hypotheses"]])
        _write(out / "khau4_log.json", result["log"])
        raw = json.loads((out / "response_raw.json").read_text(encoding="utf-8"))
        checks = check_result(raw, result["hypotheses"])
        if any(e.get("stop_reason") == "max_tokens" for e in observed.events):
            checks.update(criteria_met=False, truncated=True)
        summary = {"state": "received", "probe_id": PROBE_ID, "out": str(out), **checks,
                   "so_muc_tho": result["log"]["so_muc_tho"], "so_gia_thuyet": len(result["hypotheses"]),
                   "ma_sua": result["log"]["ma_sua"]}
    except (providers.LLMError, budget.BudgetError, ValueError, OSError) as exc:
        message = str(exc).replace(os.environ.get(client.api_key_env) or "\x00", "[REDACTED]")
        summary = {"state": "failed_no_retry", "probe_id": PROBE_ID, "out": str(out),
                   "error_type": type(exc).__name__, "error": message[:1500]}
    usage = providers.token_totals(observed.events)
    ir, ore = budget.RATES[client.model_id]
    known = any(e.get("input_tokens") is not None and e.get("output_tokens") is not None for e in observed.events)
    summary["known_cost_usd"] = budget.usd(usage["input_tokens"] * ir + usage["output_tokens"] * ore) if known else None
    summary["usage"] = usage if known else None
    summary["cap_usd"] = CAP
    summary["cost_exceeds_cap"] = (budget.money(summary["known_cost_usd"], allow_zero=True) > budget.money(CAP)) if known else None
    summary["api_events"] = observed.events
    _write(out / "result.json", summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="người vận hành: gửi một lần, không thử lại, trần giữ trước 0,40 USD")
    args = parser.parse_args(argv)
    try:
        result = run(send=args.send)
    except (ValueError, OSError, budget.BudgetError, providers.LLMError) as exc:
        print(f"[DỪNG] {exc}")
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get("state") == "failed_no_retry" or result.get("criteria_met") is False else 0
