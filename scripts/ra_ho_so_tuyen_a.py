"""Đối chiếu artifact không nhãn và đóng gói demo chỉ đọc; không tạo LLM."""
from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal
from pathlib import Path

from cti_hunt.approval import verify_saved_review
from cti_hunt.agent.chi_phi import run_cost
from cti_hunt.data.store import connect
from cti_hunt.eval.exec_accuracy import result_keys
from cti_hunt.hunt.observe import run_unlabeled
from cti_hunt.hunt.runner import load_spec

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data/dev/ho_so_tuyen_a_20261002_02"
DEMO = "data/dev/report_emotet_28-9/case/handoff_send/hunt_v3"
AGENT = "data/eval/apt29_day2/tuyen_A/agent/SY_02"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def allowed(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    rel = path.relative_to(root.resolve()).as_posix()
    if not (rel.startswith("data/dev/") or rel.startswith("data/eval/apt29_day2/tuyen_A/")):
        raise ValueError("Nguồn ngoài phạm vi artifact không nhãn")
    if any(part.lower() in {"runs", "labels"} for part in path.parts):
        raise ValueError("Nguồn nhãn bị cấm")
    return path


def load_demo(folder: Path, root: Path = ROOT) -> dict:
    path = folder / "demo.json"
    if sha(path) != (folder / "demo.sha256").read_text().strip():
        raise ValueError("Gói demo đã đổi")
    data = json.loads(path.read_text(encoding="utf-8"))
    for relative, expected in data["source_hashes"].items():
        if sha(allowed(root, relative)) != expected:
            raise ValueError(f"Nguồn demo đã đổi: {relative}")
    return data


class Evidence:
    def __init__(self):
        self.hashes: dict[str, str] = {}

    def track(self, path: Path) -> Path:
        relative = path.resolve().relative_to(ROOT).as_posix()
        self.hashes.setdefault(relative, sha(path))
        return path

    def read(self, path: Path) -> str:
        return self.track(path).read_text(encoding="utf-8-sig")

    def json(self, path: Path):
        return json.loads(self.read(path))

    def unchanged(self):
        changed = [p for p, h in self.hashes.items() if sha(ROOT / p) != h]
        if changed:
            raise ValueError(f"Đầu vào đã đổi: {changed}")


def audit_run(ev: Evidence, folder: Path, con) -> dict:
    record = ev.json(folder / "agent_dev_record.json")
    meta = ev.json(folder / "run_meta.json")
    parquet = Path(meta["events"]["dir"]) / "events.parquet"
    relative = parquet.resolve().relative_to(ROOT).as_posix()
    if meta["events"]["parquet_sha256"] != ev.hashes[relative]:
        raise ValueError(f"Dữ liệu khác hash lượt gốc: {folder}")
    rules, approved, observations = [], 0, {}
    for rnd in sorted(folder.glob("round_*")):
        for name in ("hypotheses.json", "duyet.yaml", "approval_log.json", "hypotheses_da_duyet.json"):
            ev.track(rnd / name)
        verify_saved_review(rnd)
        approved += sum(h["status"] == "approved" for h in ev.json(rnd / "hypotheses_da_duyet.json"))
        execute = rnd / "agent_execute.json"
        if execute.exists():
            data = ev.json(execute)
            rules.extend(data["rules"])
            observations.update({o["hunt_id"]: o for o in data["observations"]})
        for path in rnd.glob("rules/*.yml"):
            ev.track(path)
    # Track every file consumed by run_cost, which never reads checkpoint or EVAL.
    for pattern in ("agent_plan_requests.jsonl", "round_*/agent_proposal.json",
                    "round_*/pivot_requests.jsonl", "round_*/khau5_requests.jsonl"):
        for path in folder.glob(pattern):
            ev.track(path)
    unique, checks = set(), []
    for row in record["executed_specs"]:
        path = allowed(ROOT, Path(row["path"]).resolve().relative_to(ROOT).as_posix())
        ev.track(path)
        spec = load_spec(path, con=con)
        actual = run_unlabeled(con, spec, sample_limit=0)
        expected = observations[spec["id"]]["stages"]
        if actual["stages"] != expected:
            raise ValueError(f"Số đếm khác nhật ký: {path}")
        keys = result_keys(con, spec)["cuoi"]
        if len(keys) != expected[-1]["hits"]:
            raise ValueError(f"Khóa sự kiện không khớp: {path}")
        unique.update(keys)
        checks.append({"hypothesis_id": row["hypothesis_id"], "stages": actual["stages"]})
    return {"path": folder.relative_to(ROOT).as_posix(), "mode": meta["mode"],
            "approved": approved, "rule_records": len(rules),
            "valid_first": sum(r["hop_le"] and r["so_lan_sua"] == 0 for r in rules),
            "valid_final": sum(r["hop_le"] for r in rules),
            "executed": len(checks), "unique_final_events": len(unique),
            "cost_from_logs": run_cost(folder), "unlabeled_checks": checks}


def build_demo(ev: Evidence, audit: dict) -> dict:
    base = ROOT / DEMO
    before = set(ev.hashes)
    manifest = ev.json(ROOT / "data/dev/report_emotet_28-9/bundle/manifest.json")
    contract = ev.json(ROOT / "data/dev/report_emotet_28-9/case/extraction/contract_a.json")
    ev.track(ROOT / "data/dev/report_emotet_28-9/bundle/segments.jsonl")
    cases = []
    for rnd in sorted(base.glob("round_*")):
        execute = ev.json(rnd / "agent_execute.json")
        hyps = ev.json(rnd / "hypotheses_da_duyet.json")
        review = ev.json(rnd / "approval_log.json")
        for h in hyps:
            hid = h["hypothesis_id"]
            specs = list((rnd / "hunts").glob(hid + "__*.yaml"))
            obs = [o for o in execute["observations"] if o["hypothesis_id"] == hid]
            cases.append({"hypothesis": h, "review": review,
                          "rule": ev.read(rnd / "rules" / (hid + ".yml")),
                          "specs": [ev.read(p) for p in specs], "observations": obs})
    record = ev.json(base / "agent_dev_record.json")
    agent = ev.json(ROOT / AGENT / "agent_dev_record.json")
    payload = {"schema": "saved_demo_v1", "original_mode": "pipeline",
               "original_run": DEMO, "report": manifest, "contract_a": contract,
               "cases": cases, "history": record["history"],
               "hunt_record": ev.read(base / "hunt_record.md"),
               "agent_history": agent["history"], "agent_run": AGENT,
               "verified_summary": audit}
    # Include all demo-source hashes, including sources already consumed by the audit.
    payload["source_hashes"] = {p: h for p, h in ev.hashes.items()
                               if p.startswith(DEMO + "/") or p.startswith(AGENT + "/")
                               or p not in before}
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "data/dev") or out.exists():
        raise ValueError("Output phải là thư mục mới trong data/dev")
    ev = Evidence()
    ev.track(ROOT / "data/dev/api_budget.sqlite")
    for top in ("configs", "prompts"):
        for path in (ROOT / top).rglob("*"):
            if path.is_file():
                ev.track(path)
    evaluation = ROOT / "data/eval/apt29_day2/tuyen_A"
    ev.track(ROOT / "data/work/events.parquet")
    con = connect(ROOT / "data/work")
    rows = []
    try:
        for mode in ("pipeline", "agent"):
            names = [f"{report}_{i:02d}" for report in ("MS", "PS", "SY")
                     for i in range(1, 2 if mode == "pipeline" else 4)]
            for name in names:
                folder = evaluation / mode / name
                row = audit_run(ev, folder, con)
                if row["mode"] != mode:
                    raise ValueError(f"Chế độ không khớp: {folder}")
                rows.append(row)
    finally:
        con.close()
    totals = {}
    for mode in ("pipeline", "agent"):
        subset = [r for r in rows if r["mode"] == mode]
        totals[mode] = {k: sum(r[k] for r in subset)
                        for k in ("approved", "rule_records", "valid_first", "valid_final", "executed")}
        totals[mode].update(calls=sum(r["cost_from_logs"]["loi_goi"] for r in subset),
                            usd=str(sum(Decimal(str(r["cost_from_logs"]["usd"])) for r in subset)))
    incident = ev.json(evaluation / "pipeline/PS_01/su_co.json")
    ev.track(ROOT / "data/dev/otrf-wmi-exec/events.parquet")
    con = connect(ROOT / "data/dev/otrf-wmi-exec")
    try:
        demo_audit = audit_run(ev, ROOT / DEMO, con)
    finally:
        con.close()
    payload = build_demo(ev, demo_audit)
    ev.unchanged()
    proof = {"date": "2026-10-02", "new_api_calls": 0, "raw_labels_read": False,
             "totals": totals, "runs": rows, "pipeline_interruption": incident,
             "demo": demo_audit, "input_hashes": ev.hashes, "inputs_unchanged": True,
             "limits": "TP/FP/recall lấy từ tài liệu kết quả đã lập; không tính lại với nhãn."}
    out.mkdir(parents=True)
    for name, data in (("doi_chieu.json", proof), ("demo.json", payload)):
        path = out / name
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        path.with_suffix(".sha256").write_text(sha(path) + "\n", encoding="ascii")
    print(json.dumps({"out": str(out), "totals": totals, "demo": demo_audit}, ensure_ascii=True))


if __name__ == "__main__":
    main()
