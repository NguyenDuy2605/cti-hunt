"""D14 bước 0: kiểm tra pySigma -> SPL, không kết nối Splunk hay đọc log."""
from __future__ import annotations

import argparse
import json
from importlib.metadata import version
from pathlib import Path


def convert_rule(path: Path) -> list[str]:
    """Giữ nguyên tên trường Sigma/OTRF bằng pipeline rỗng, trả SPL của từng condition."""
    from ..filter_approval import FilterReviewError, path_policy
    if path_policy(path):
        raise FilterReviewError("SPL v2 phải xuất từ hunt hiệu lực, không từ rule draft còn mục rejected/pending")
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.processing.pipeline import ProcessingPipeline

    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    return SplunkBackend(processing_pipeline=ProcessingPipeline(name="otrf_identity")).convert(collection)


def convert_effective(spec: dict, index: str) -> dict:
    """Export the pinned candidate and ONLY approved positive groups, source by source."""
    import re
    from datetime import datetime, timezone
    from sigma.backends.splunk import SplunkBackend
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.rule import SigmaRule
    from .. import demo, filter_approval as filters
    from ..eval.splunk_compare import single_line, split_spl
    filters.require_executable(spec)
    if spec.get("filter_policy") != filters.POLICY:
        raise filters.FilterReviewError("convert_effective chỉ nhận hunt v2")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", index):
        raise ValueError("index phải là tên cụ thể, không wildcard/SPL")
    ctx = spec["sigma_context"]
    mapping = ctx["field_map"]
    def convert(condition):
        from copy import deepcopy
        doc = deepcopy(ctx["rule"])
        doc["detection"]["condition"] = condition
        pipeline = ProcessingPipeline.from_dict({"name": "reviewed_mapping", "priority": 10,
                    "transformations": [{"id": "map", "type": "field_name_mapping", "mapping": mapping}]}) if mapping else ProcessingPipeline()
        result = SplunkBackend(processing_pipeline=pipeline).convert_rule(SigmaRule.from_dict(doc))
        if len(result) != 1:
            raise ValueError("condition sinh nhiều SPL ngoài phạm vi hỗ trợ")
        return split_spl(single_line(result[0]))
    selection, *pipes = convert(ctx["candidate_condition"])
    for command in pipes:
        if not re.fullmatch(r'regex\s+[A-Za-z_][A-Za-z0-9_]*\s*!?=\s*"(?:[^"\\]|\\.)*"', command):
            raise ValueError("candidate có pipeline SPL chưa hỗ trợ")
    if ctx.get("account_binding"):
        binding = ctx["account_binding"]
        if binding.get("message_keys"):
            # H7: DuckDB còn so tài khoản trong Message; chưa có vế SPL tương đương nên dừng, không xuất SPL lệch nghĩa.
            raise ValueError("ràng buộc tài khoản trong Message chưa hỗ trợ xuất SPL; dừng xuất")
        fields = binding["fields"]
        if not fields or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", f) for f in fields):
            raise ValueError("trường tài khoản pivot không hợp lệ")
        parts = [f'lower(trim(mvindex(split(mvindex(split(coalesce({f},""),"\\\\"),-1),"@"),0)))={json.dumps(binding["value"])}'
                 for f in fields]
        pipes.append("where (" + " OR ".join(parts) + ")")
    exclusions = []
    for f in spec["filters"]:
        parts = convert(f["bieu_thuc_sigma"])
        if len(parts) != 1:
            raise ValueError("filter có pipeline SPL chưa hỗ trợ; dừng xuất")
        exclusions.append(parts[0])
    scope = spec["scope"]
    base = f'search index="{index}" ev_channel={json.dumps(scope["channel"])}'
    base += " (" + " OR ".join(f"ev_eid={int(e)}" for e in scope["event_ids"]) + ")"
    if scope.get("hosts"):
        base += " (" + " OR ".join("ev_host=" + json.dumps(h) for h in scope["hosts"]) + ")"
    for key, command in (("time_from", "earliest"), ("time_to", "latest")):
        if scope.get(key):
            dt = datetime.fromisoformat(scope[key].replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # DuckDB scope timestamps are normalized UTC.
            base += f" {command}={dt.timestamp()}"
    base += f" ({selection})"
    stages = []
    for i, stage in enumerate(demo.sql_stages(spec)):
        spl = base + "".join(f" NOT ({e})" for e in exclusions[:i])
        spl += "".join(" | " + p for p in pipes) + " | table ev_host ev_channel ev_rec"
        stages.append({**stage, "spl": spl})
    return {"kind": "reviewed_filter_spl_export", "index": index, "hunt_id": spec["id"],
            "effective_spec_sha256": filters.digest(filters._clean(spec)), "filter_review": spec["filter_review"],
            "stages": stages, "executed_on_splunk": False}


def check_paths(paths: list[Path]) -> dict:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted((*path.rglob("*.yml"), *path.rglob("*.yaml"))))
        else:
            files.append(path)
    results = []
    for path in sorted(set(files)):
        parts = [part.lower() for part in path.parts]
        if any(parts[i : i + 2] == ["data", "labels"] for i in range(len(parts) - 1)):
            results.append({"file": str(path), "status": "error", "reason": "refused: data/labels is outside D14 scope"})
            continue
        try:
            queries = convert_rule(path)
            results.append({"file": str(path), "status": "ok", "queries": queries})
        except Exception as exc:
            results.append({"file": str(path), "status": "error", "reason": f"{type(exc).__name__}: {exc}"})
    return {
        "backend": "pysigma-backend-splunk",
        "backend_version": version("pysigma-backend-splunk"),
        "pipeline": "otrf_identity (no field mapping)",
        "converted": sum(item["status"] == "ok" for item in results),
        "failed": sum(item["status"] == "error" for item in results),
        "rules": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="D14: chuyển rule Sigma sang SPL, không truy vấn Splunk")
    parser.add_argument("paths", nargs="+", type=Path, help="tệp/thư mục rule được phép đọc")
    args = parser.parse_args()
    result = check_paths(args.paths)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
