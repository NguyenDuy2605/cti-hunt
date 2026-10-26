"""Thêm lượt v2 chạy thật (OTRF, 02/10) vào một gói demo mới; chỉ đọc artifact đã lưu, không gọi API, không thực thi.

Gói nền là gói demo hiện có (`chuan_bi_demo_loc_v2.DEMO_OUTPUT`), được kiểm hash nguồn khi nạp. Không ghi đè gói cũ.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from cti_hunt.approval import verify_saved_review
from cti_hunt.filter_approval import HUMAN_FIELDS, _rows
from chuan_bi_demo_loc_v2 import DEMO_OUTPUT as BASE_DEMO, check
from ra_ho_so_tuyen_a import ROOT, Evidence, allowed, load_demo, sha

DEMO_OUTPUT = ROOT / "data/dev/demo_tuyen_a_v2_that_20261002_01"
REAL_RUN = "data/dev/thu_v2_otrf_01"
PINNED = ("configs/telemetry_catalog_v2.yaml", "configs/agent_v2.yaml", "prompts/agent_plan_v3.md",
          "prompts/khau5_sigma_v2.md", "configs/chinh_sach_loc_v2.yaml")
SAMPLE_FIELDS = ("ev_host", "ev_ts", "Image", "User")      # không đưa CommandLine (có thể chứa lệnh mã hóa)


def check_rejected(rows: list[dict]) -> None:
    """Ca demo này là nhánh từ chối: mọi mục lọc phải rejected và có lý do của người duyệt."""
    check(rows, "Không có mục lọc nào trong phiếu")
    for row in rows:
        check(row["quyet_dinh"] == "rejected" and str(row["ly_do"]).strip(),
              f"Mục {row['id']} không phải rejected có lý do")


def filter_review(ev: Evidence, rnd: Path) -> dict:
    review = rnd / "filter_review/r01"
    manifest = ev.json(review / "manifest.json")
    form = yaml.safe_load(ev.read(review / "duyet_loc.yaml"))
    log = ev.json(review / "approval_log.json")
    effective = ev.json(review / "effective_manifest.json")
    receipt = ev.json(review / "execution_receipt.json")
    preview = ev.json(review / "preview.json")
    mh = sha(review / "manifest.json")
    check(form["manifest_sha256"] == log["manifest_sha256"] == effective["manifest_sha256"] == mh,
          "Manifest/phiếu/log hiệu lực không khớp")
    check(manifest["preview_sha256"] == sha(review / "preview.json"), "Preview khác gói duyệt")
    check(log["phieu_sha256"] == sha(review / "duyet_loc.yaml"), "Phiếu lọc đã đổi")
    check(form["nguoi_duyet"] == log["nguoi_duyet"] and form["nguoi_duyet"].strip(), "Người duyệt không khớp")
    check(form["muc_loc"] == log["quyet_dinh"], "Quyết định phiếu/log không khớp")
    expected = _rows(manifest)
    check({r["id"] for r in form["muc_loc"]} == {r["id"] for r in expected} and
          len(form["muc_loc"]) == len(expected), "Danh sách mục lọc không khớp")
    for row in form["muc_loc"]:
        original = next(r for r in expected if r["id"] == row["id"])
        check({k: v for k, v in row.items() if k not in HUMAN_FIELDS} ==
              {k: v for k, v in original.items() if k not in HUMAN_FIELDS}, "Nội dung lọc khác manifest")
    check_rejected(form["muc_loc"])
    check(effective["approval_log_sha256"] == sha(review / "approval_log.json"), "Log khác gói hiệu lực")
    check(receipt["kind"] == "completed_execution" and
          receipt["effective_manifest_sha256"] == sha(review / "effective_manifest.json"), "Biên nhận không khớp")
    for path_string, expected_sha in effective["files"].items():
        path = allowed(ROOT, Path(path_string).resolve().relative_to(ROOT).as_posix())
        spec = yaml.safe_load(ev.read(path))
        check(sha(path) == expected_sha, "Spec hiệu lực đã đổi")
        check(spec.get("filter_phase") == "effective" and spec["filters"] == [],
              "Spec hiệu lực còn mục lọc đã bị từ chối")
    rules = {row["hypothesis_id"]: ev.read(rnd / f"rules_draft/{row['hypothesis_id']}.yml") for row in form["muc_loc"]}
    return {"nguoi_duyet": log["nguoi_duyet"], "thoi_diem_utc": log["thoi_diem_utc"],
            "muc_loc": [{k: row[k] for k in ("id", "hunt_id", "hypothesis_id", "bieu_thuc_sigma", "where",
                                               "quyet_dinh", "ly_do")} for row in form["muc_loc"]],
            "preview": preview, "rule_co_muc_loc": rules, "so_spec_hieu_luc": len(effective["files"]),
            "executed_at_utc": receipt["executed_at_utc"]}


def round_evidence(ev: Evidence, rnd: Path) -> dict:
    for name in ("hypotheses.json", "duyet.yaml", "hypotheses_da_duyet.json", "approval_log.json"):
        ev.track(rnd / name)
    verify_saved_review(rnd)
    log = ev.json(rnd / "approval_log.json")
    hypotheses = [h for h in ev.json(rnd / "hypotheses_da_duyet.json") if h["status"] == "approved"]
    drafts = sorted(ev.track(p).stem for p in rnd.glob("rules_draft/*.yml"))
    execute = rnd / "agent_execute.json"
    data = ev.json(execute) if execute.exists() else None
    if data:
        for obs in data["observations"]:
            check([s["stage"] for s in obs["stages"]] == ["pham_vi", "ung_vien"],
                  "Hunt đã thực thi còn tầng lọc dù mọi mục lọc bị từ chối")
    return {"vong": rnd.name, "nguoi_duyet": log["nguoi_duyet"], "thoi_diem": log["thoi_diem"], "dem": log["dem"],
            "gia_thuyet": [{"id": h["hypothesis_id"], "hanh_vi": h.get("behavior", ""), "ttp": h.get("linked_ttps", []),
                            "nguon": (h.get("evidence") or {}).get("data_source", ""),
                            "eid": (h.get("evidence") or {}).get("event_ids", [])} for h in hypotheses],
            "rule_hop_le": drafts,
            "rule": [{k: r[k] for k in ("hypothesis_id", "hop_le", "so_lan_sua", "loi")} for r in data["rules"]]
            if data else [],
            "ket_qua": [{"hypothesis_id": o["hypothesis_id"], "nguon": o["source"], "stages": o["stages"],
                         "mau": [{k: s.get(k) for k in SAMPLE_FIELDS} for s in o["sample"]]}
                        for o in data["observations"]] if data else [],
            "da_thuc_thi": data is not None}


def real_run_evidence(ev: Evidence, base: Path) -> dict:
    meta = ev.json(base / "run_meta.json")
    check(meta["phien_ban"] == "v2" and meta["mode"] == "agent", "Lượt không phải agent v2")
    check(all(k in meta["tep"] for k in PINNED), "Lượt không ghim đủ cấu hình/prompt v2")
    record = ev.json(base / "agent_dev_record.json")
    incident = ev.json(base / "su_co.json")
    check(incident["khong_goi_api"] is True and incident["node_dang_cho"] == ["prepare_rules"],
          "Sự cố không đúng lượt bị ngắt giữa ⑤")
    check(sha(ev.track(base / "checkpoint.sqlite")) == incident["checkpoint_sha256"], "Checkpoint đã đổi sau sự cố")
    rounds = [round_evidence(ev, rnd) for rnd in sorted(base.glob("round_*"))]
    history = []
    for row in record["history"]:
        names = {c["ref"]: c["technique_id"] for c in row.get("candidate_scores") or []}
        decision = row["decision"]
        history.append({"action": decision["action"], "ttp": [names.get(r, str(r)) for r in decision.get("ttp_refs") or []],
                        "ly_do": decision.get("reason", "")})
    return {"run": REAL_RUN, "bat_dau": meta["bat_dau"], "commit": meta["git"]["commit"],
            "dataset": meta["dataset"], "ghim": {p: meta["tep"][p] for p in PINNED},
            "planner": history, "vong": rounds, "cong_loc": filter_review(ev, base / "round_01"),
            "su_co": {k: incident[k] for k in ("ly_do", "node_dang_cho", "gia_thuyet_da_duyet_chua_thuc_thi",
                                               "so_hunt_da_thuc_thi")},
            "chi_phi": record["chi_phi_api_luot"], "hunt_record": ev.read(base / "hunt_record.md")}


def build(base_demo: Path = BASE_DEMO, out: Path = DEMO_OUTPUT):
    out = out.resolve()
    check(out.is_relative_to(ROOT / "data/dev") and not out.exists(), "Output phải mới trong data/dev")
    payload = load_demo(base_demo)
    ev = Evidence()
    ev.track(ROOT / "data/dev/api_budget.sqlite")
    payload["real_v2"] = real_run_evidence(ev, ROOT / REAL_RUN)
    ev.unchanged()
    payload["source_hashes"].update({p: h for p, h in ev.hashes.items() if p.startswith(REAL_RUN + "/")})
    payload["schema"] = "saved_demo_v3"
    proof = {"base_demo_sha256": sha(base_demo / "demo.json"), "inputs_unchanged": True,
             "input_hashes": ev.hashes, "api_calls": 0,
             "scope": "Liên kết artifact lượt v2 thật đã đóng; không thực thi lại, không chạy SQL/Splunk"}
    out.mkdir(parents=True)
    for name, value in (("demo.json", payload), ("kiem_goi_v2_that.json", proof)):
        path = out / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        path.with_suffix(".sha256").write_text(sha(path) + "\n", encoding="ascii")
    print(json.dumps({"out": str(out), "sources": len(payload["source_hashes"]), "api_calls": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=BASE_DEMO)
    parser.add_argument("--out", type=Path, default=DEMO_OUTPUT)
    args = parser.parse_args()
    build(args.base, args.out)
