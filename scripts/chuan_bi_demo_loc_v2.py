"""Thêm bằng chứng lọc v2 vào gói demo mới; chỉ đọc lượt lịch sử, không thực thi."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from cti_hunt.approval import verify_saved_review
from cti_hunt.filter_approval import HUMAN_FIELDS, _rows, digest
from ra_ho_so_tuyen_a import OUTPUT, ROOT, Evidence, allowed, load_demo, sha

DEMO_OUTPUT = ROOT / "data/dev/demo_tuyen_a_loc_v2_20261002_01"
FILTER_RUN = "data/dev/graph_loc_approved_otrf_v2_01"


def check(condition, message):
    if not condition:
        raise ValueError(message)


def filter_evidence(ev: Evidence, base: Path) -> dict:
    rnd = base / "round_01"
    review = rnd / "filter_review/r01"
    for name in ("hypotheses.json", "duyet.yaml", "hypotheses_da_duyet.json", "approval_log.json"):
        ev.track(rnd / name)
    verify_saved_review(rnd)
    manifest = ev.json(review / "manifest.json")
    form = yaml.safe_load(ev.read(review / "duyet_loc.yaml"))
    log = ev.json(review / "approval_log.json")
    effective = ev.json(review / "effective_manifest.json")
    receipt = ev.json(review / "execution_receipt.json")
    mh = sha(review / "manifest.json")
    check(form["manifest_sha256"] == log["manifest_sha256"] == effective["manifest_sha256"] == mh,
          "Manifest/phiếu/log hiệu lực không khớp")
    check(log["phieu_sha256"] == sha(review / "duyet_loc.yaml"), "Phiếu lọc đã đổi")
    check(form["nguoi_duyet"] == log["nguoi_duyet"] and form["nguoi_duyet"].strip(), "Người duyệt không khớp")
    check(form["muc_loc"] == log["quyet_dinh"], "Quyết định phiếu/log không khớp")
    expected = _rows(manifest)
    check(len(form["muc_loc"]) == len(expected) and
          {r["id"] for r in form["muc_loc"]} == {r["id"] for r in expected}, "Danh sách mục lọc không khớp")
    for row, original in zip(form["muc_loc"], expected):
        check({k: v for k, v in row.items() if k not in HUMAN_FIELDS} ==
              {k: v for k, v in original.items() if k not in HUMAN_FIELDS}, "Nội dung lọc khác manifest")
        check(row["quyet_dinh"] == "approved", "Ca demo này cần hai quyết định approved đã lưu")
    check(effective["approval_log_sha256"] == sha(review / "approval_log.json"), "Log khác gói hiệu lực")
    check(receipt["kind"] == "completed_execution" and
          receipt["effective_manifest_sha256"] == sha(review / "effective_manifest.json"), "Biên nhận không khớp")
    specs = []
    for path_string, expected_sha in effective["files"].items():
        path = allowed(ROOT, Path(path_string).resolve().relative_to(ROOT).as_posix())
        text = ev.read(path)
        check(sha(path) == expected_sha, "Spec hiệu lực đã đổi")
        spec = yaml.safe_load(text)
        approved = [r for r in form["muc_loc"] if r["hunt_id"] == spec["id"]]
        check(spec.get("filter_phase") == "effective" and
              {f["id"] for f in spec["filters"]} == {r["id"].rsplit("__", 1)[-1] for r in approved},
              "Spec thiếu hoặc thừa mục lọc đã duyệt")
        for f in spec["filters"]:
            row = next(r for r in form["muc_loc"] if r["hunt_id"] == spec["id"] and r["id"].endswith("__" + f["id"]))
            check(f["where"] == row["where"] and f["status"] == "approved" and
                  f["het_han"] == row["hieu_luc_den_utc"], "Spec không đúng quyết định lọc")
        specs.append(spec)
    post = ev.json(base / "post_splunk_verification.json")
    comparison_path = base / "splunk_compare_01/comparison.json"
    comparison = ev.json(comparison_path)
    imported_path = base / "splunk_goi_nap/import/import_manifest.confirmed.json"
    imported = ev.json(imported_path)
    for path, key in ((comparison_path, "comparison.json"),
                      (base / "splunk_compare_01/plan.json", "plan.json"),
                      (imported_path, "import_manifest.confirmed.json")):
        ev.track(path)
        check(sha(path) == post["sha256"][key], "Bằng chứng Splunk đã đổi")
    check(imported["operator"].strip() and imported["license_checked"], "Thiếu xác nhận nạp")
    check(comparison["import_manifest_sha256"] == hashlib.sha256(json.dumps(imported, sort_keys=True).encode()).hexdigest(),
          "Manifest nạp khác lượt so")
    check(comparison["events_sha256"] == manifest["events"]["sha256"] == imported["events_sha256"], "Nguồn log khác nhau")
    check(len(comparison["rules"]) == len(specs) == 1 and
          comparison["rules"][0]["rule_sha256"] == digest(specs[0]), "Spec khác lượt so Splunk")
    execute = ev.json(rnd / "agent_execute.json")
    counts = execute["observations"][0]["stages"][1:]
    stages = comparison["rules"][0]["results"]
    check([r["stage"] for r in stages] == ["ung_vien"] + ["sau_" + f["id"] for f in specs[0]["filters"]],
          "Thứ tự tầng lọc khác spec hiệu lực")
    check([(r["stage"], r["hits"]) for r in counts] == [(r["stage"], r["duck_count"]) for r in stages],
          "Số đếm khác nhật ký thực thi")
    for saved, stage in zip(post["stages"], stages):
        check(all(saved[k] == stage[k] for k in saved), "Bảng tóm tắt khác lượt so")
    check(len(post["stages"]) == len(stages) == 3 and post["api_llm_called"] is False,
          "Bằng chứng không đúng ca mock ba tầng")
    return {"run": FILTER_RUN, "executed_at_utc": receipt["executed_at_utc"],
            "historical_only": True, "rule_origin": "mock", "review": log,
            "stages": post["stages"], "imported": imported,
            "hypothesis": ev.json(rnd / "hypotheses_da_duyet.json")[0],
            "rule": ev.read(rnd / "rules_draft/DEV-SCHTASKS-H01.yml"),
            "hunt_record": ev.read(base / "hunt_record.md"), "comparison": comparison,
            "receipt": receipt, "effective_manifest": effective}


def build(source: Path = OUTPUT, out: Path = DEMO_OUTPUT):
    out = out.resolve()
    check(out.is_relative_to(ROOT / "data/dev") and not out.exists(), "Output phải mới trong data/dev")
    payload = load_demo(source)
    ev = Evidence()
    ev.track(ROOT / "data/dev/api_budget.sqlite")
    payload["filter_demo"] = filter_evidence(ev, ROOT / FILTER_RUN)
    ev.unchanged()
    payload["source_hashes"].update({p: h for p, h in ev.hashes.items() if p.startswith(FILTER_RUN + "/")})
    payload["schema"] = "saved_demo_v2"
    proof = {"base_demo_sha256": sha(source / "demo.json"), "inputs_unchanged": True,
             "input_hashes": ev.hashes, "api_calls": 0,
             "scope": "Liên kết artifact lịch sử; không kiểm lại gói với runtime/phiếu hết hạn, không chạy SQL/Splunk"}
    out.mkdir(parents=True)
    for name, value in (("demo.json", payload), ("kiem_goi_loc.json", proof)):
        path = out / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        path.with_suffix(".sha256").write_text(sha(path) + "\n", encoding="ascii")
    print(json.dumps({"out": str(out), "sources": len(payload["source_hashes"]), "api_calls": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=OUTPUT)
    parser.add_argument("--out", type=Path, default=DEMO_OUTPUT)
    args = parser.parse_args()
    build(args.base, args.out)
