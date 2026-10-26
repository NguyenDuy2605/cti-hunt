"""Compare engine result sets, NOT labeled detection accuracy.

Both engines must have canonical ev_* fields from the same exported dataset,
the same UTC time window, source, field mapping and cumulative filter stage.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingPipeline

from .. import demo, integrity
from ..adapters import duckdb_sigma as adapter
from ..hunt import runner

KEYS = ("ev_host", "ev_channel", "ev_rec")


def json_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    raise TypeError(f"Không xuất ngầm kiểu {type(value).__name__}")


NULL_MODES = ("included", "omitted")


def export_row(row: dict, omit_null: bool) -> dict:
    """Cột NULL của bảng gộp là trường sự kiện gốc không có; bỏ đi để Splunk thấy đúng hình dạng sự kiện."""
    return {k: v for k, v in row.items() if v is not None} if omit_null else row


def verify_payload(expected_rows: list[dict], actual_rows: list[dict], omit_null: bool = False) -> None:
    """Matching keys alone cannot detect truncated JSON or misassigned timestamps."""
    expected_keys, actual_keys = keys(expected_rows), keys(actual_rows)
    if not expected_keys or expected_keys != actual_keys:
        raise ValueError("Tập sự kiện trong cửa sổ không khớp hoặc rỗng; kiểm nạp đủ dữ liệu và _time=ev_ts trước khi chấm")
    expected = {next(iter(keys([row]))): row for row in expected_rows}
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for row in actual_rows:
        key = next(iter(keys([row])))
        original = expected[key]
        try:
            raw = json.loads(row["_raw"])
            indexed_time = Decimal(str(row["cti_indexed_epoch"]))
        except (KeyError, TypeError, ValueError, InvalidOperation) as e:
            raise ValueError(f"Thiếu/sai _raw hoặc _time tại khóa {key}") from e
        canonical = json.loads(json.dumps(export_row(original, omit_null), default=json_timestamp, allow_nan=False))
        if raw != canonical:
            raise ValueError(f"Nội dung _raw khác bản xuất tại khóa {key}; chưa tính độ đồng thuận engine")
        dt = original["ev_ts"]
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - epoch
        seconds = Decimal(delta.days * 86400 + delta.seconds) + Decimal(delta.microseconds) / 1000000
        if not indexed_time.is_finite() or abs(indexed_time - seconds) > Decimal("0.000001"):
            raise ValueError(f"_time khác ev_ts UTC tại khóa {key}; chưa tính độ đồng thuận engine")


def parse_source(text: str) -> tuple[str, int]:
    channel, sep, eid = text.strip().rpartition(":")
    if not sep or not channel.strip() or not re.fullmatch(r"\d+", eid):
        raise ValueError(f"Nguồn loại trừ phải có dạng <channel>:<EID>, nhận: {text!r}")
    return channel.strip().lower(), int(eid)


def import_scope(plans_: list[dict], excluded: list[tuple[str, int]] = ()) -> list[dict]:
    """Union of (channel, EID) the planned stages query, minus sources the operator cannot import."""
    union: dict[str, set[int]] = {}
    for plan in plans_:
        for stage in plan["stages"]:
            sc = stage["scope"]
            union.setdefault(str(sc["channel"]).lower(), set()).update(int(e) for e in sc["event_ids"])
    for channel, eid in excluded:
        if eid not in union.get(channel, set()):
            raise ValueError(f"Nguồn loại trừ {channel}:{eid} không có trong phạm vi các rule; kiểm lại tên")
        union[channel].discard(eid)
    scope = [{"channel": ch, "event_ids": sorted(eids)} for ch, eids in sorted(union.items()) if eids]
    if not scope:
        raise ValueError("Phạm vi nạp rỗng sau khi loại trừ")
    return scope


def check_scope(scope) -> list[dict] | None:
    """None = manifest cũ, đã nạp toàn bộ dataset. Có phạm vi thì phải đúng dạng import_scope sinh."""
    if scope is None:
        return None
    if not isinstance(scope, list) or not scope:
        raise ValueError("Phạm vi nạp trong manifest phải là danh sách khác rỗng")
    for s in scope:
        if (not isinstance(s, dict) or set(s) != {"channel", "event_ids"} or not isinstance(s["channel"], str)
                or s["channel"] != s["channel"].lower() or not s["channel"].strip()
                or not isinstance(s["event_ids"], list) or not s["event_ids"]
                or any(type(e) is not int for e in s["event_ids"])):
            raise ValueError("Phạm vi nạp trong manifest sai dạng {channel chữ thường, event_ids số nguyên}")
    return scope


def scope_where(scope: list[dict]) -> str:
    return "(" + " OR ".join(f"({runner._scope_where(s)})" for s in scope) + ")"


def covered(stage_scope: dict, scope: list[dict] | None) -> bool:
    """Stage chỉ được so khi mọi EID của nó thuộc cùng một channel đã nạp."""
    if scope is None:
        return True
    channel = str(stage_scope["channel"]).lower()
    eids = {int(e) for e in stage_scope["event_ids"]}
    return any(s["channel"] == channel and eids <= set(s["event_ids"]) for s in scope)


def export_events(con, out: Path, events_sha256: str, index: str, scope: list[dict] | None = None,
                  excluded: list[dict] | None = None, omit_null: bool = False) -> dict:
    """Prepare a new local import package; operator attestation remains unfilled."""
    sql = "SELECT * FROM events" + (" WHERE " + scope_where(check_scope(scope)) if scope is not None else "")
    cur = con.execute(sql)
    names = [x[0] for x in cur.description]
    rows = [dict(zip(names, r)) for r in cur.fetchall()]
    keys(rows)
    if not rows or any(not isinstance(r.get("ev_ts"), datetime) for r in rows):
        raise ValueError("Dataset rỗng hoặc có ev_ts thiếu/sai kiểu; chưa xuất để đối chiếu")
    out.mkdir(parents=True, exist_ok=False)
    path = out / "events.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(export_row(row, omit_null), ensure_ascii=False, default=json_timestamp,
                               allow_nan=False) + "\n")
    times = [r["ev_ts"] for r in rows]
    manifest = {"events_sha256": events_sha256, "export_sha256": integrity.sha256_file(path),
                "export_file": path.name, "rows": len(rows), "bytes": path.stat().st_size,
                "index": index, "time_field": "ev_ts", "canonical_keys": list(KEYS),
                "null_fields": NULL_MODES[omit_null],
                "ev_ts_min_utc": json_timestamp(min(times)), "ev_ts_max_utc": json_timestamp(max(times)),
                "operator": "", "license_checked": False,
                "note": "Bản nháp. Người nạp xác nhận index, _time=ev_ts và giấy phép sau khi nạp; không tự xác nhận."}
    if scope is not None:
        manifest.update(scope=scope, excluded_sources=list(excluded or []))
    from ..stages.s1_ingest import write_json
    write_json(out / "import_manifest.draft.json", manifest)
    return manifest


def window(start: str, end: str) -> tuple[str, str, str, str]:
    a, b = [datetime.fromisoformat(v.replace("Z", "+00:00")) for v in (start, end)]
    if a.tzinfo is None or b.tzinfo is None or a >= b:
        raise ValueError("Cần thời gian có múi giờ, bắt đầu < kết thúc (cận cuối loại trừ)")
    a, b = a.astimezone(timezone.utc), b.astimezone(timezone.utc)
    return (a.replace(tzinfo=None).isoformat(" "), b.replace(tzinfo=None).isoformat(" "),
            str(a.timestamp()), str(b.timestamp()))


def single_line(query: str) -> str:
    """Giá trị Sigma có CR/LF: DuckDB khớp nhưng Splunk không (kiểm chỉ đọc 1/10, DuckDB 1 / Splunk 0).
    Chặn cả rule thay vì báo lệch giả; xem docs/METHODOLOGY.md.
    Chỉ xét CR/LF trong chuỗi có nháy: pySigma tự xuống dòng giữa các lệnh (trước `| regex`)."""
    quote, escaped = None, False
    for char in query:
        if quote and char in "\r\n":
            raise ValueError("Giá trị Sigma có xuống dòng (CR/LF): Splunk không khớp như DuckDB; "
                             "không so rule này, dùng mảnh một dòng nếu cần so engine")
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
    return query


def split_spl(query: str) -> list[str]:
    """Split backend pipeline commands, preserving pipes inside quoted regex/literals."""
    parts, current, quote, escaped = [], [], None, False
    for char in query:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            current.append(char)
            quote = char
        elif char == "|":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quote or escaped:
        raise ValueError("SPL có chuỗi chưa đóng")
    parts.append("".join(current).strip())
    if any(not part for part in parts):
        raise ValueError("SPL có nhánh rỗng")
    return parts


def plans(rule_path: Path, catalog: dict, columns: set, index: str, start: str, end: str) -> dict:
    from ..filter_approval import FilterReviewError, path_policy
    if path_policy(rule_path):
        raise FilterReviewError("So SPL v2 phải nhận hunt hiệu lực, không biên dịch lại draft theo v1")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", index) or index.startswith("_"):
        raise ValueError("Cần tên index riêng, không wildcard hoặc SPL")
    parts = [s.lower() for s in rule_path.resolve().parts]
    if "labels" in parts or "runs" in parts:
        raise ValueError("Không dùng đường dẫn nhãn/kết quả đánh giá trong phép thử phát triển")
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    if len(collection.rules) != 1 or len(collection.rules[0].detection.condition) != 1:
        raise ValueError("Phép so hiện hỗ trợ một rule/một condition; không bỏ qua condition còn lại")
    rule = collection.rules[0]
    split = adapter.split_condition(rule.detection.condition[0])
    hunts, skipped = adapter.compile_rule(rule_path, catalog, columns)
    if not hunts:
        raise ValueError("Không có nguồn biên dịch được với schema dataset")
    sources = {s["name"]: s for values in catalog.values() for s in values}
    lo, hi, epoch_lo, epoch_hi = window(start, end)
    stages = []
    for h in hunts:
        src = sources[h.source]
        mapping = src.get("field_map") or {}
        def convert(condition):
            doc = rule.to_dict()
            doc["detection"]["condition"] = condition
            pipeline = ProcessingPipeline.from_dict({"name": "same_as_duckdb", "priority": 10,
                "transformations": [{"id": "map", "type": "field_name_mapping", "mapping": mapping}]}) if mapping else ProcessingPipeline()
            result = SplunkBackend(processing_pipeline=pipeline).convert_rule(SigmaRule.from_dict(doc))
            if len(result) != 1:
                raise ValueError("Condition sinh SPL nhiều nhánh ngoài phạm vi đã kiểm")
            return split_spl(single_line(result[0]))
        selection, *selection_pipes = convert(split.candidates)
        for command in selection_pipes:
            if not re.fullmatch(r'regex\s+[A-Za-z_][A-Za-z0-9_]*\s*!?=\s*"(?:[^"\\]|\\.)*"', command):
                raise ValueError("Selection sinh pipeline ngoài dạng regex field được hỗ trợ")
        exclusions = []
        for f in split.filters:
            converted = convert(f)
            if len(converted) != 1:
                raise ValueError("Filter có pipeline riêng chưa hỗ trợ; không bỏ qua điều kiện")
            exclusions.append(converted[0])
        spec = h.to_hunt_spec()
        spec["scope"].update(time_from=lo, time_to=hi)
        channel = json.dumps(h.scope["channel"])
        eids = " OR ".join(f"ev_eid={int(n)}" for n in h.scope["event_ids"])
        base = f'search index="{index}" ev_channel={channel} ({eids}) ({selection})'
        for i, stage in enumerate(demo.sql_stages(spec)):
            spl = base + "".join(f" NOT ({s})" for s in exclusions[:i])
            spl += "".join(" | " + command for command in selection_pipes)
            stages.append({"id": h.id + ":" + stage["stage"], "source": h.source,
                           "stage": stage["stage"], "scope": spec["scope"],
                           "sql": stage["sql"].replace("SELECT *", "SELECT " + ", ".join(KEYS), 1),
                           "spl": spl + " | table " + " ".join(KEYS)})
    return {"rule_sha256": integrity.sha256_file(rule_path), "index": index,
            "start_utc": lo, "end_utc_exclusive": hi, "earliest_time": epoch_lo, "latest_time": epoch_hi,
            "stages": stages, "skipped_sources": [s.__dict__ for s in skipped]}


def plans_effective(spec: dict, con, index: str, start: str, end: str) -> dict:
    """Use the effective artifact; an outer comparison window must cover its full scope."""
    from .. import filter_approval as filters
    from ..adapters.splunk_sigma import convert_effective
    if spec.get("rang_buoc"):
        raise ValueError("Hunt có ràng buộc nhiều sự kiện chỉ thực thi trong SQL (rang_buoc); SPL sinh từ Sigma không "
                         "có phần này nên không so engine")
    filters.require_executable(spec, con=con)
    if not filters._connections.get(con, {}).get("policy"):
        packet = filters.verify_packet(Path(spec["filter_review"]["dir"]), con=con)
        filters.bind(con, Path(packet["run_root"]))
    exported = convert_effective(spec, index)
    lo, hi, epoch_lo, epoch_hi = window(start, end)
    lower, upper = [datetime.fromisoformat(v) for v in (lo, hi)]
    # This window only drives the index inventory. It must never truncate the approved hunt.
    from ..hunt.runner import _scope_where
    bounds = con.execute(f"SELECT min(ev_ts), max(ev_ts) FROM events WHERE {_scope_where(spec['scope'])}").fetchone()
    if bounds[0] is not None and (bounds[0] < lower or bounds[1] >= upper):
        raise filters.FilterReviewError("cửa sổ so SPL không bao trọn scope/dữ liệu đã duyệt")
    stages = [{"id": spec["id"] + ":" + s["stage"], "source": spec["sigma_context"]["source"],
               "scope": spec["scope"], **s,
               "sql": s["sql"].replace("SELECT *", "SELECT " + ", ".join(KEYS), 1)} for s in exported["stages"]]
    return {"rule_sha256": filters.digest(filters._clean(spec)),
            "index": index, "start_utc": lo, "end_utc_exclusive": hi,
            "earliest_time": epoch_lo, "latest_time": epoch_hi, "stages": stages,
            "skipped_sources": [], **filters.result_contract(spec)}


def _check_effective_plan(con, plan: dict) -> None:
    from .. import filter_approval as filters
    if not plan.get("filter_contract"):
        filters.require_executable({"_path": plan.get("rule")}, con=con)
        return
    expected = plans_effective(plan["filter_contract"], con, plan["index"],
                               plan["start_utc"] + "Z", plan["end_utc_exclusive"] + "Z")
    if any(plan.get(k) != v for k, v in expected.items()):
        raise filters.FilterReviewError("SQL/SPL/kế hoạch khác hunt hiệu lực")


def keys(rows: list[dict]) -> set[tuple]:
    result = set()
    for row in rows:
        if any(k not in row or row[k] is None or not str(row[k]).strip() for k in KEYS):
            raise ValueError("Thiếu khóa sự kiện; không chấm điểm trên bản ghi lỗi")
        host, channel, rec = (str(row[k]) for k in KEYS)
        if not re.fullmatch(r"\d+", rec) or host != host.upper() or channel != channel.lower():
            raise ValueError("Cần ev_host/ev_channel/ev_rec chuẩn hóa giống bản xuất; không sửa khóa ngầm")
        key = (host, channel, int(rec))
        if key in result:
            raise ValueError("Trùng khóa sự kiện/luồng export; không âm thầm deduplicate")
        result.add(key)
    return result


def metrics(duck: set, splunk: set) -> dict:
    common, union = duck & splunk, duck | splunk
    return {"duck_count": len(duck), "splunk_count": len(splunk), "intersection": len(common),
            "jaccard": len(common) / len(union) if union else None,
            "precision_vs_duckdb": len(common) / len(splunk) if splunk else None,
            "recall_vs_duckdb": len(common) / len(duck) if duck else None,
            "only_duckdb": sorted(duck - splunk), "only_splunk": sorted(splunk - duck),
            "status": "no_matches" if not union else "compared"}


def _check_manifest(imported: dict, index: str, events_sha256: str) -> tuple[list[dict] | None, bool]:
    """Trả (phạm vi đã nạp, có bỏ trường null). Manifest cũ không có hai khóa này = nạp toàn bộ, giữ null."""
    if (imported.get("events_sha256") != events_sha256 or imported.get("index") != index
            or imported.get("time_field") != "ev_ts"
            or imported.get("canonical_keys") != list(KEYS)):
        raise ValueError("Manifest nạp không khớp dataset/index/chuẩn khóa/thời gian")
    operator = imported.get("operator")
    if not isinstance(operator, str) or not operator.strip() or imported.get("license_checked") is not True:
        raise ValueError("Cần xác nhận người nạp và kiểm giấy phép/dung lượng trước phép đối chiếu thật")
    null_fields = imported.get("null_fields", "included")
    if null_fields not in NULL_MODES:
        raise ValueError("null_fields trong manifest phải là included hoặc omitted")
    return check_scope(imported.get("scope")), null_fields == "omitted"


def _engines(con, client, plan: dict):
    _check_effective_plan(con, plan)
    def duck_rows(sql):
        _check_effective_plan(con, plan)
        cur = con.execute(sql)
        names = [x[0] for x in cur.description]
        return [dict(zip(names, r)) for r in cur.fetchall()]
    def query(spl):
        _check_effective_plan(con, plan)
        return client.search(spl, earliest_time=plan["earliest_time"], latest_time=plan["latest_time"])
    return duck_rows, query


def _verify_inventory(duck_rows, query, plan: dict, scope: list[dict] | None, omit_null: bool) -> set:
    """Index chỉ chứa phần đã nạp, nên DuckDB phải lấy đúng cửa sổ và đúng phạm vi đó."""
    where = f"ev_ts >= TIMESTAMP '{plan['start_utc']}' AND ev_ts < TIMESTAMP '{plan['end_utc_exclusive']}'"
    if scope is not None:
        where += " AND " + scope_where(scope)
    inventory_spl = (f'search index="{plan["index"]}" | eval cti_indexed_epoch=printf("%.6f",_time) | table '
                     + " ".join(KEYS) + " _raw cti_indexed_epoch")
    expected_rows, actual_rows = duck_rows("SELECT * FROM events WHERE " + where), query(inventory_spl)
    verify_payload(expected_rows, actual_rows, omit_null)
    return keys(actual_rows)


def _compare_stages(duck_rows, query, plan: dict, actual: set, scope: list[dict] | None, *, con=None) -> list[dict]:
    output = []
    for stage in plan["stages"]:
        _check_effective_plan(con, plan)
        if not covered(stage["scope"], scope):
            output.append({**stage, "status": "not_imported",
                           "note": "Nguồn/EID của stage không nằm trong phạm vi đã nạp; không so"})
            continue
        d, s = keys(duck_rows(stage["sql"])), keys(query(stage["spl"]))
        if not s <= actual:
            raise ValueError("Kết quả Splunk chứa khóa ngoài inventory đã kiểm")
        output.append({**stage, **metrics(d, s)})
    return output


def _header(imported: dict, events_sha256: str, inventory: set, scope) -> dict:
    return {"kind": "engine_agreement_unlabeled", "events_sha256": events_sha256,
            "import_manifest_sha256": hashlib.sha256(json.dumps(imported, sort_keys=True).encode()).hexdigest(),
            "import_scope": scope, "inventory_count": len(inventory),
            "raw_payload_verified": True, "event_time_verified": True}


def compare(con, client, plan: dict, imported: dict, events_sha256: str) -> dict:
    scope, omit_null = _check_manifest(imported, plan["index"], events_sha256)
    duck_rows, query = _engines(con, client, plan)
    actual = _verify_inventory(duck_rows, query, plan, scope, omit_null)
    output = _compare_stages(duck_rows, query, plan, actual, scope, con=con)
    return {**_header(imported, events_sha256, actual, scope), "plan": plan, "results": output,
            "note": "Độ tương đồng hai engine; không phải precision/recall phát hiện tấn công theo nhãn"}


def compare_suite(con, client, plans_: list[dict], imported: dict, events_sha256: str) -> dict:
    """Nhiều rule cùng index/cửa sổ: kiểm tập sự kiện một lần, rồi so từng stage của từng rule."""
    if not plans_:
        raise ValueError("Không có kế hoạch so nào")
    first = plans_[0]
    window_keys = ("index", "start_utc", "end_utc_exclusive", "earliest_time", "latest_time")
    if any(p[k] != first[k] for p in plans_ for k in window_keys):
        raise ValueError("Các kế hoạch khác index/cửa sổ thời gian; không gộp một lượt so")
    scope, omit_null = _check_manifest(imported, first["index"], events_sha256)
    duck_rows, query = _engines(con, client, first)
    actual = _verify_inventory(duck_rows, query, first, scope, omit_null)
    rules = [{"rule": p.get("rule", ""), "rule_sha256": p["rule_sha256"], "skipped_sources": p["skipped_sources"],
              "results": _compare_stages(duck_rows, query, p, actual, scope, con=con)} for p in plans_]
    return {**_header(imported, events_sha256, actual, scope), "rules": rules, "summary": summarize(rules),
            "note": "Độ tương đồng hai engine; không phải precision/recall phát hiện tấn công theo nhãn"}


def summarize(rules: list[dict]) -> dict:
    stages = [r for rule in rules for r in rule["results"]]
    def differs(r):
        return r["status"] == "compared" and bool(r["only_duckdb"] or r["only_splunk"])
    return {"rules": len(rules), "stages": len(stages),
            "stages_compared_nonempty": sum(r["status"] == "compared" for r in stages),
            "stages_both_empty": sum(r["status"] == "no_matches" for r in stages),
            "stages_not_imported": sum(r["status"] == "not_imported" for r in stages),
            "stages_differ": sum(map(differs, stages)),
            "rules_with_difference": sorted({rule["rule"] for rule in rules if any(map(differs, rule["results"]))}),
            "rules_all_not_imported": sum(all(r["status"] == "not_imported" for r in rule["results"])
                                          for rule in rules)}
