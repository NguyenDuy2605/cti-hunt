"""Reviewed exclusions v2: immutable packets, local previews and a shared query gate.

SHA256 links detect stale/changed artifacts; they are not reviewer authentication.
No model calls, labels, automatic decisions, or global reusable allowlist.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4
from weakref import WeakKeyDictionary

import yaml

from . import integrity

POLICY = "duyet_loc_khau5_v2"
FORM = "duyet_loc.yaml"
MANIFEST = "manifest.json"
EFFECTIVE = "effective_manifest.json"
CONTEXT = "filter_policy.json"
CANCEL = "cancellation.json"
KEY = ("ev_host", "ev_channel", "ev_rec")
HUMAN_FIELDS = ("quyet_dinh", "ly_do", "can_cu", "nguoi_chiu_trach_nhiem", "hieu_luc_den_utc")
MUTABLE = set(HUMAN_FIELDS)
# 09/10: rule có giá trị/regex ⑤ tự thêm (đối chiếu B3) phải được người duyệt giữ hoặc bỏ trước khi chạy.
# Phiếu riêng, chỉ có khi context của gói bật `doi_chieu_rule`; gói cũ không có phiếu này và giữ nguyên hành vi.
RULE_FORM = "duyet_rule.yaml"
RULE_POLICY_V1 = "duyet_rule_khau5_v1"
RULE_HUMAN_V1 = ("quyet_dinh", "ly_do")
# 10/10: thêm `rut_gon` — bỏ đúng các mục đối chiếu đã chọn (`bo_muc`, số thứ tự mục) khỏi rule; graph phát
# bản sửa của gói để duyệt lại trước khi chạy. Gói cũ không ghi chính sách trong manifest nên giữ v1.
RULE_POLICY = "duyet_rule_khau5_v2"
RULE_HUMAN = ("quyet_dinh", "ly_do", "bo_muc")
# 15/10: cổng độ rộng — rule giữ từ ngưỡng trở lên của một nguồn log khối lượng lớn (configs/do_rong_rule.yaml)
# cũng có dòng trong phiếu rule; giữ rule rộng phải ghi lý do. Chỉ khi context bật `do_rong_rule`; gói v1/v2 giữ nguyên.
RULE_POLICY_V3 = "duyet_rule_khau5_v3"
BREADTH_CONFIG = "configs/do_rong_rule.yaml"
BREADTH_VERSION = "do_rong_rule_v1"
REVISION = "revision.json"
_connections: WeakKeyDictionary = WeakKeyDictionary()


class FilterReviewError(ValueError):
    pass


class PendingFilterReview(FilterReviewError):
    pass


def _bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n").encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def _sha(path: Path) -> str:
    try:
        return integrity.sha256_file(path)
    except OSError as exc:
        raise FilterReviewError(f"thiếu/không đọc được artifact: {path.name}") from exc


def _versions() -> dict:
    packages = ("duckdb", "pysigma", "pysigma-backend-sqlite", "pysigma-backend-splunk", "langgraph")
    result = {}
    for name in packages:
        try:
            result[name] = version(name)
        except PackageNotFoundError:
            result[name] = "not_installed"
    return result


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FilterReviewError(f"không đọc được gói duyệt: {path.name}") from exc


def _write(path: Path, value, *, yaml_format=False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8") if yaml_format else _bytes(value)
    temp = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        temp.write_bytes(data)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: str) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError) as exc:
        raise FilterReviewError("thời hạn phải là timestamp UTC có timezone") from exc


def register_events(con, path: Path) -> None:
    ctx = _connections.setdefault(con, {})
    ctx["events_path"] = str(path.resolve())
    ctx["events_view_sql"] = _events_view(con)


def _events_view(con) -> str:
    rows = con.execute("SELECT sql FROM duckdb_views() WHERE view_name='events'").fetchall()
    if len(rows) != 1:
        raise FilterReviewError("cần đúng view events từ store.connect")
    return rows[0][0]


def bind(con, root: Path, *, dependencies: list[Path] = (), sample_limit: int = 5) -> None:
    if sample_limit != 5:
        raise FilterReviewError("policy v2 đã chốt sample_limit = 5")
    ctx = _connections.setdefault(con, {})
    ctx.update(policy=POLICY, root=str(root.resolve()), sample_limit=sample_limit,
               versions=_versions(),
               dependencies={str(Path(p).resolve()): _sha(Path(p)) for p in dependencies})


def _fingerprint(con) -> dict:
    ctx = _connections.get(con, {})
    if ctx.get("events_path"):
        if _events_view(con) != ctx.get("events_view_sql"):
            raise FilterReviewError("view events đã bị thay khỏi parquet được ghim")
        path = Path(ctx["events_path"])
        return {"path": str(path), "sha256": _sha(path)}
    # Fixtures in memory: exact deterministic fingerprint, never a sample.
    cols = [r[0] for r in con.execute("DESCRIBE events").fetchall()]
    if {c.lower() for c in cols} & {"buoc", "labeled", "attack_labels"}:
        raise FilterReviewError("events của preview không được có trường nhãn")
    if not set(KEY) <= set(cols):
        raise FilterReviewError("events thiếu khóa sự kiện")
    h = hashlib.sha256(_bytes(cols))
    cursor = con.execute("SELECT * FROM events ORDER BY ev_host, ev_channel, ev_rec")
    while rows := cursor.fetchmany(4096):
        for row in rows:
            h.update(_bytes(row))
    return {"path": None, "sha256": h.hexdigest()}


def _context(con, root: Path) -> dict:
    ctx = deepcopy(_connections.get(con, {}))
    if ctx.get("policy") != POLICY or ctx.get("root") != str(root.resolve()):
        raise FilterReviewError("cần context v2 đúng lượt trước khi tạo gói")
    ctx["run_id"] = digest({"root": ctx["root"], "dependencies": ctx.get("dependencies", {})})
    return ctx


def _inside(path: Path, root: Path) -> Path:
    p = path.resolve()
    if not p.is_relative_to(root.resolve()):
        raise FilterReviewError("artifact duyệt nằm ngoài lượt")
    return p


def _clean(spec: dict) -> dict:
    return {k: deepcopy(v) for k, v in spec.items() if not k.startswith("_")}


def _rows(manifest: dict) -> list[dict]:
    rows = []
    for spec in manifest["specs"]:
        for f in spec["filters"]:
            rows.append({"id": f"{spec['id']}__{f['id']}", "hunt_id": spec["id"],
                         "hypothesis_id": spec.get("hypothesis_id"), "scope": spec["scope"],
                         "where": f["where"], "bieu_thuc_sigma": f["bieu_thuc_sigma"],
                         "selectors": f["selectors"], "de_xuat": f["ly_do"],
                         "content_sha256": digest({"scope": spec["scope"], "candidate": spec["candidates"], "filter": f}),
                         **{k: "" for k in HUMAN_FIELDS}})
    return rows


def _grounding_rows(specs: list[dict]) -> list[dict]:
    """Draft có mục đối chiếu (giá trị/regex ở khối ứng viên mà giả thuyết đã duyệt không chứa). Tính một lần lúc phát
    gói rồi lưu trong manifest đã băm, để phiếu không đổi khi mã đối chiếu đổi về sau."""
    from sigma.collection import SigmaCollection
    from .contracts import ContractB
    from .stages import rule_fidelity
    rows = []
    for spec in specs:
        ctx = spec["sigma_context"]
        if not ctx.get("binding"):
            continue
        rule = SigmaCollection.from_yaml(yaml.safe_dump(ctx["rule"], allow_unicode=True, sort_keys=False)).rules[0]
        items = rule_fidelity.condition_grounding(rule, ContractB.model_validate(ctx["binding"]))
        if items:
            rows.append({"id": spec["id"], "hypothesis_id": spec.get("hypothesis_id"), "doi_chieu": items,
                         "content_sha256": digest({"rule": ctx["rule"], "doi_chieu": items})})
    return rows


def _breadth(con, specs: list[dict]) -> dict[str, dict]:
    """Rule giữ từ ngưỡng trở lên của một nguồn log khối lượng lớn: id hunt → số giữ/phạm vi. Đếm trên `events`, không nhãn,
    không gửi cho mô hình. Tính một lần lúc phát gói rồi lưu trong manifest đã băm."""
    from . import config
    from .hunt import runner
    cfg = yaml.safe_load(config.resolve(BREADTH_CONFIG).read_text(encoding="utf-8"))
    if cfg.get("version") != BREADTH_VERSION:
        raise FilterReviewError(f"{BREADTH_CONFIG}: version phải là {BREADTH_VERSION}")
    big = {str(ch).lower(): {int(e) for e in eids} for ch, eids in (cfg.get("nguon_khoi_luong_lon") or {}).items()}
    out = {}
    for spec in specs:
        sc = spec["scope"]
        if not set(int(e) for e in sc["event_ids"]) <= big.get(str(sc["channel"]).lower(), set()):
            continue
        scope = runner._scope_where(sc)
        total = con.execute(f"SELECT count(*) FROM events WHERE {scope}").fetchone()[0]
        kept = con.execute(f"SELECT count(*) FROM events WHERE {scope} AND ({spec['candidates']})").fetchone()[0]
        if total and kept / total >= float(cfg["nguong"]):
            out[spec["id"]] = {"giu": kept, "pham_vi": total, "ty_le": round(kept / total, 4),
                               "nguong": float(cfg["nguong"]), "version": BREADTH_VERSION}
    return out


def _variant(con, spec: dict, cfg: dict) -> dict | None:
    """Biến thể mức kỹ thuật (stages/rule_variant) của một rule gốc, kèm số sự kiện gốc và biến thể giữ trên `events`
    (không nhãn). Hunt pivot và hunt có ràng buộc nhiều sự kiện không có biến thể."""
    from .hunt import runner
    from .stages import rule_variant
    if not (spec.get("sigma_context") or {}).get("rule") or not rule_variant._is_root(spec):
        return None
    var, note = rule_variant.variant_spec(spec, cfg)
    if var is None:
        return None
    scope = runner._scope_where(spec["scope"])
    count = lambda where: con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]  # noqa: E731
    return {"version": rule_variant.VERSION, "mo_ta": note, "candidates": var["candidates"],
            "rule": var["bien_the"]["rule"], "pham_vi": count(scope),
            "goc_giu": count(f"{scope} AND ({spec['candidates']})"),
            "bien_the_giu": count(f"{scope} AND ({var['candidates']})")}


def _rule_rows_v3(con, specs: list[dict], grounding: bool) -> list[dict]:
    """Phiếu rule v3: mục đối chiếu (nếu bật), độ rộng, biến thể mức kỹ thuật; rule có ít nhất một trong ba thì có dòng."""
    from .stages import rule_variant
    by_id = {r["id"]: r for r in (_grounding_rows(specs) if grounding else [])}
    wide = _breadth(con, specs)
    var_cfg = rule_variant.load_config()
    rows = []
    for spec in specs:
        var = _variant(con, spec, var_cfg)
        if spec["id"] not in by_id and spec["id"] not in wide and var is None:
            continue
        items = by_id.get(spec["id"], {}).get("doi_chieu", [])
        rows.append({"id": spec["id"], "hypothesis_id": spec.get("hypothesis_id"), "doi_chieu": items,
                     "do_rong": wide.get(spec["id"]), "bien_the": var,
                     "content_sha256": digest({"rule": (spec.get("sigma_context") or {}).get("rule"), "doi_chieu": items,
                                               "do_rong": wide.get(spec["id"]), "bien_the": var})})
    return rows


def _rule_policy(manifest: dict) -> str:
    return manifest.get("doi_chieu_rule_policy", RULE_POLICY_V1)


def _rule_human(manifest: dict) -> tuple[str, ...]:
    return RULE_HUMAN if _rule_policy(manifest) in (RULE_POLICY, RULE_POLICY_V3) else RULE_HUMAN_V1


def _rule_rows(manifest: dict) -> list[dict]:
    blank = {"quyet_dinh": "", "ly_do": "", "bo_muc": []}
    return [{**row, **{k: deepcopy(blank[k]) for k in _rule_human(manifest)}}
            for row in manifest.get("doi_chieu_rule") or []]


def needs_review(review_dir: Path) -> bool:
    """Graph dừng ở cổng khi có mục lọc hoặc có rule cần giữ/bỏ."""
    return bool(load_form(review_dir)["muc_loc"]) or bool(_read(review_dir / MANIFEST).get("doi_chieu_rule"))


def _catalog(ctx: dict) -> dict:
    from sigma.rule import SigmaRule
    logsource = SigmaRule.from_dict(ctx["rule"]).logsource
    key = f"service:{logsource.service}" if logsource.service else logsource.category
    return {key: [ctx["source_config"]]}


def _derive(con, spec: dict, rule: dict) -> tuple[list, list[dict]]:
    """Dựng draft từ rule + binding/nguồn/neo đã lưu trong draft, đúng đường của ⑤ (kiểm tĩnh, biên dịch, ràng buộc,
    EXPLAIN). Dùng để tái kiểm draft khi phát gói và để dựng draft của rule người duyệt rút gọn."""
    from .contracts import ContractB
    from .stages.s5_rule import validate_rule
    ctx = spec["sigma_context"]
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    text = yaml.safe_dump(rule, allow_unicode=True, sort_keys=False)
    # Ràng buộc mốc neo tái kiểm bằng đúng SQL tập neo đã lưu trong draft (nằm trong gói đã băm).
    rb = spec.get("rang_buoc") or {}
    anchors = {rb["dieu_kien"]["moc_neo"]["gia_thuyet"]: rb["neo_sql"]} if rb.get("neo_sql") else None
    return validate_rule(text, ContractB.model_validate(ctx["binding"]), _catalog(ctx), columns, con,
                         filter_policy=POLICY, anchors=anchors,
                         candidate_regex_policy=ctx.get("candidate_regex_policy", ""))


def _validate_draft(con, spec: dict) -> None:
    from .adapters import duckdb_sigma as adapter
    from .hunt.runner import validate
    ctx = spec["sigma_context"]
    if ctx.get("binding"):
        errors, expected = _derive(con, spec, ctx["rule"])
        if errors:
            raise FilterReviewError("binding/draft không còn biên dịch được")
    else:
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        text = yaml.safe_dump(ctx["rule"], allow_unicode=True, sort_keys=False)
        catalog = _catalog(ctx)
        compiled, _ = adapter.compile_text(text, catalog, columns, filter_policy=POLICY)
        expected = [h.to_hunt_spec() for h in compiled]
    match = [s for s in expected if s["id"] == spec["id"]]
    if len(match) != 1 or _clean(match[0]) != _clean(spec):
        raise FilterReviewError("draft khác rule/cấu trúc/binding gốc; không phát phiếu")
    validate(spec, for_execution=False)


def _preview(con, spec: dict) -> dict:
    from .adapters.duckdb_sigma import rule_fields
    from .hunt.runner import _scope_where
    from sigma.rule import SigmaRule
    scope = _scope_where(spec["scope"])
    candidate = f"({scope}) AND ({spec['candidates']})"
    cols = {r[0].lower(): r[0] for r in con.execute("DESCRIBE events").fetchall()}
    if set(cols) & {"buoc", "labeled", "attack_labels"}:
        raise FilterReviewError("preview không nhận trường nhãn")
    context = spec["sigma_context"]
    fields = sorted(rule_fields(SigmaRule.from_dict(context["rule"])))
    mapped = [context["field_map"].get(f, f) for f in fields]
    mapped += (context.get("account_binding") or {}).get("fields", [])
    select = list(KEY) + ["ev_ts"] + [cols[f.lower()] for f in mapped if f.lower() in cols and f not in (*KEY, "ev_ts")]
    select = list(dict.fromkeys(select))
    quoted = ", ".join('"' + c.replace('"', '""') + '"' for c in select)
    def count(where):
        return con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]
    filters = []
    for f in spec["filters"]:
        where = f"{candidate} AND ({f['where']}) IS TRUE"
        cur = con.execute(f"SELECT {quoted} FROM events WHERE {where} ORDER BY ev_ts, ev_host, ev_channel, ev_rec LIMIT 5")
        sample = [dict(zip(select, row)) for row in cur.fetchall()]
        filters.append({"id": f["id"], "matched": count(where),
                        "sample": sample, "sample_limit": 5,
                        "missing_fields": [f for f in mapped if f.lower() not in cols]})
    union = " OR ".join(f"({f['where']}) IS TRUE" for f in spec["filters"]) or "FALSE"
    return {"hunt_id": spec["id"], "scope": count(scope), "candidates": count(candidate),
            "union_removed": count(f"{candidate} AND ({union})"), "filters": filters, "kind": "preview_only_unlabeled"}


def _check_drafts(con, clean: list[dict], context: dict | None, review_dir: Path) -> None:
    """Kiểm draft trước khi phát gói. Bản sửa (rút gọn rule) phải giữ đúng các hunt của gói trước; draft giữ nguyên phải
    trùng đúng draft đã lưu ở gói trước — gói đó đã tái kiểm lúc phát, được băm và là phụ thuộc của bản sửa — nên không
    dựng lại: manifest JSON sắp khóa làm đổi thứ tự trường của rule, dựng lại ra SQL cùng nghĩa khác chữ (kiểm thật 10/10).
    Chỉ draft rút gọn được dựng lại và tái kiểm như draft do ⑤ sinh."""
    if len({s["id"] for s in clean}) != len(clean):
        raise FilterReviewError("hunt id trùng trong lô")
    prev = (context or {}).get("ban_sua_cua")
    carried, cut = {}, set()
    if prev:
        path = Path(review_dir).parent / prev["goi"] / MANIFEST
        if _sha(path) != prev["manifest_sha256"]:
            raise FilterReviewError("gói trước của bản sửa đã đổi")
        carried = {s["id"]: s for s in _read(path)["specs"]}
        cut = {c["id"] for c in prev["rut_gon"]}
        if [s["id"] for s in clean] != list(carried) or not cut <= set(carried):
            raise FilterReviewError("bản sửa phải giữ đúng các hunt của gói trước")
    for s in clean:
        if s.get("filter_policy") != POLICY or s.get("filter_phase") != "draft" or not s.get("sigma_context"):
            raise FilterReviewError("chỉ draft đã phân tích cấu trúc v2 được phát phiếu")
        if prev and s["id"] not in cut:
            if s != carried[s["id"]]:
                raise FilterReviewError("bản sửa chỉ được đổi rule đã chọn rút gọn")
            continue
        _validate_draft(con, s)


def prepare(con, specs: list[dict], root: Path, review_dir: Path, *, context: dict | None = None,
            dependencies: list[Path] = ()) -> Path:
    """Commit immutable draft/preview before entering a graph interrupt. Never approve."""
    root, review_dir = root.resolve(), _inside(review_dir, root)
    ctx = _context(con, root)
    if (review_dir / MANIFEST).exists():
        old = verify_packet(review_dir, con=con)
        if old["specs"] != [_clean(s) for s in specs] or old["context"] != (context or {}):
            raise FilterReviewError("gói đã tồn tại với nội dung khác; cần revision mới")
        return review_dir
    if review_dir.exists() and any(review_dir.iterdir()):
        raise FilterReviewError("gói xuất dở; giữ bằng chứng và dùng revision mới")
    clean = [_clean(s) for s in specs]
    _check_drafts(con, clean, context, review_dir)
    data = _fingerprint(con)
    previews = [_preview(con, s) for s in clean]
    if _fingerprint(con) != data:
        raise FilterReviewError("events đổi trong lúc preview")
    envelope = root / CONTEXT
    if envelope.exists() and _read(envelope) != ctx:
        raise FilterReviewError("context lượt đã đổi")
    _write(envelope, ctx)
    _write(review_dir / "preview.json", previews)
    all_dependencies = {**ctx.get("dependencies", {}),
                        **{str(Path(p).resolve()): _sha(Path(p)) for p in dependencies}}
    manifest = {"policy": POLICY, "run_root": str(root), "run_id": ctx["run_id"],
                "context_sha256": _sha(envelope), "events": data,
                "dependencies": all_dependencies, "context": context or {},
                "preview_sha256": _sha(review_dir / "preview.json"), "specs": clean}
    if (context or {}).get("do_rong_rule"):
        manifest["doi_chieu_rule"] = _rule_rows_v3(con, clean, bool((context or {}).get("doi_chieu_rule")))
        manifest["doi_chieu_rule_policy"] = RULE_POLICY_V3
    elif (context or {}).get("doi_chieu_rule"):
        manifest["doi_chieu_rule"] = _grounding_rows(clean)
        manifest["doi_chieu_rule_policy"] = RULE_POLICY
    rows = _rows(manifest)
    if len({r["id"] for r in rows}) != len(rows):
        raise FilterReviewError("id mục lọc trùng")
    _write(review_dir / MANIFEST, manifest)
    _write(review_dir / FORM, {"manifest_sha256": _sha(review_dir / MANIFEST),
                             "quy_tac_duyet": POLICY, "nguoi_duyet": "", "muc_loc": rows}, yaml_format=True)
    if manifest.get("doi_chieu_rule"):
        _write(review_dir / RULE_FORM, {"manifest_sha256": _sha(review_dir / MANIFEST),
                                        "quy_tac_duyet": manifest["doi_chieu_rule_policy"],
                                        "nguoi_duyet": "", "rule": _rule_rows(manifest)}, yaml_format=True)
    return review_dir


def verify_packet(review_dir: Path, *, con=None, manifest_sha256: str | None = None) -> dict:
    review_dir = review_dir.resolve()
    if (review_dir / CANCEL).exists():
        raise FilterReviewError("lượt đã hủy tại cổng lọc; không được thực thi")
    path = review_dir / MANIFEST
    if manifest_sha256 and _sha(path) != manifest_sha256:
        raise FilterReviewError("manifest đã đổi")
    m = _read(path)
    if m.get("policy") != POLICY:
        raise FilterReviewError("policy không đúng v2")
    root = Path(m["run_root"])
    _inside(review_dir, root)
    envelope = root / CONTEXT
    if _sha(envelope) != m["context_sha256"]:
        raise FilterReviewError("context lượt đã đổi")
    if _read(envelope).get("run_id") != m["run_id"]:
        raise FilterReviewError("run_id không khớp")
    if _read(envelope).get("versions") != _versions():
        raise FilterReviewError("phiên bản backend đã đổi; cần revision mới")
    if _sha(review_dir / "preview.json") != m["preview_sha256"]:
        raise FilterReviewError("preview đã đổi")
    for path_string, sha in m["dependencies"].items():
        if _sha(Path(path_string)) != sha:
            raise FilterReviewError("đầu vào/phiếu giả thuyết/config/prompt đã đổi")
    if con is not None:
        if _fingerprint(con) != m["events"]:
            raise FilterReviewError("events không khớp gói")
        runtime = _connections.get(con, {})
        if runtime.get("policy") and (runtime["policy"] != POLICY or runtime["root"] != str(root.resolve())):
            raise FilterReviewError("gói duyệt thuộc lượt khác")
    elif m["events"]["path"] and _sha(Path(m["events"]["path"])) != m["events"]["sha256"]:
        raise FilterReviewError("events đã đổi")
    return m


def load_form(review_dir: Path) -> dict:
    try:
        form = yaml.safe_load((review_dir / FORM).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise FilterReviewError("phiếu lọc không đọc được") from exc
    if not isinstance(form, dict):
        raise FilterReviewError("phiếu lọc phải là mapping")
    return form


def validate_form(review_dir: Path, *, con=None, complete=True, now=None, proposed=None) -> tuple[dict, dict]:
    form = load_form(review_dir) if proposed is None else proposed
    if set(form) != {"manifest_sha256", "quy_tac_duyet", "nguoi_duyet", "muc_loc"} or form["quy_tac_duyet"] != POLICY:
        raise FilterReviewError("header phiếu đã đổi")
    if not isinstance(form["manifest_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", form["manifest_sha256"]):
        raise FilterReviewError("manifest_sha256 phải là SHA256 hợp lệ")
    m = verify_packet(review_dir, con=con, manifest_sha256=form["manifest_sha256"])
    expected = {r["id"]: r for r in _rows(m)}
    rows = form["muc_loc"]
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise FilterReviewError("danh sách mục lọc sai kiểu")
    ids = [r.get("id") for r in rows]
    if any(not isinstance(i, str) for i in ids) or len(ids) != len(expected) or len(set(ids)) != len(ids) or set(ids) != set(expected):
        raise FilterReviewError("mục lọc thiếu/thừa/trùng")
    reviewer = form["nguoi_duyet"]
    if not isinstance(reviewer, str):
        raise FilterReviewError("nguoi_duyet phải là chữ")
    pending = False
    instant = now or utcnow()
    for row in rows:
        if {k: v for k, v in row.items() if k not in MUTABLE} != {k: v for k, v in expected[row["id"]].items() if k not in MUTABLE}:
            raise FilterReviewError("trường bất biến của phiếu đã đổi")
        if not all(isinstance(row.get(k), str) for k in MUTABLE):
            raise FilterReviewError("quyết định/căn cứ phải là chữ; không nhận boolean")
        decision = row["quyet_dinh"]
        if decision not in ("", "approved", "rejected"):
            raise FilterReviewError("quyết định không hợp lệ")
        if not decision:
            pending = True
            continue
        if not reviewer.strip() or not row["ly_do"].strip():
            raise FilterReviewError("cần nguoi_duyet và ly_do cho mọi quyết định")
        if decision == "approved":
            if not row["can_cu"].strip() or not row["nguoi_chiu_trach_nhiem"].strip():
                raise FilterReviewError("approved cần căn cứ và người chịu trách nhiệm")
            if re.match(r"he_thong\b", row["nguoi_chiu_trach_nhiem"].strip(), re.I):
                raise FilterReviewError("hệ thống không thể là người chịu trách nhiệm lọc")
            if _time(row["hieu_luc_den_utc"]) <= instant:
                raise FilterReviewError("chấp thuận lọc đã hết hạn")
    if pending and complete:
        raise PendingFilterReview("còn mục pending_review; cả lô giữ ở cổng ◆")
    validate_rule_form(review_dir, m, complete=complete)
    return m, form


def load_rule_form(review_dir: Path) -> dict:
    try:
        form = yaml.safe_load((review_dir / RULE_FORM).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise FilterReviewError("phiếu rule không đọc được") from exc
    if not isinstance(form, dict):
        raise FilterReviewError("phiếu rule phải là mapping")
    return form


def validate_rule_form(review_dir: Path, m: dict, *, complete=True, proposed=None) -> dict:
    """Phiếu giữ/bỏ/rút gọn rule có mục đối chiếu. Gói không bật thì không được có phiếu này.
    Phiếu v1 (gói trước 10/10) chỉ có giu/bo; v2 thêm rut_gon với bo_muc là số thứ tự các mục bỏ."""
    expected = {r["id"]: r for r in _rule_rows(m)}
    if not expected:
        if (review_dir / RULE_FORM).exists() or proposed is not None:
            raise FilterReviewError("phiếu rule không thuộc gói này")
        return {"rule": []}
    policy, human = _rule_policy(m), _rule_human(m)
    form = load_rule_form(review_dir) if proposed is None else proposed
    if set(form) != {"manifest_sha256", "quy_tac_duyet", "nguoi_duyet", "rule"} or form["quy_tac_duyet"] != policy:
        raise FilterReviewError("header phiếu rule đã đổi")
    if form["manifest_sha256"] != _sha(review_dir / MANIFEST):
        raise FilterReviewError("phiếu rule không thuộc manifest này")
    rows = form["rule"]
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise FilterReviewError("danh sách rule sai kiểu")
    ids = [r.get("id") for r in rows]
    if len(ids) != len(expected) or len(set(ids)) != len(ids) or set(ids) != set(expected):
        raise FilterReviewError("rule thiếu/thừa/trùng")
    reviewer = form["nguoi_duyet"]
    if not isinstance(reviewer, str):
        raise FilterReviewError("nguoi_duyet phải là chữ")
    pending = False
    for row in rows:
        if set(row) != set(expected[row["id"]]) or {k: v for k, v in row.items() if k not in human} != \
                {k: v for k, v in expected[row["id"]].items() if k not in human}:
            raise FilterReviewError("trường bất biến của phiếu rule đã đổi")
        if not all(isinstance(row.get(k), str) for k in ("quyet_dinh", "ly_do")):
            raise FilterReviewError("quyết định/lý do rule phải là chữ")
        if policy in (RULE_POLICY, RULE_POLICY_V3):
            if policy == RULE_POLICY_V3:
                if row["quyet_dinh"] not in ("", "giu", "bo", "rut_gon", "bien_the"):
                    raise FilterReviewError("quyết định rule chỉ là giu, bo, rut_gon hoặc bien_the")
                if row["quyet_dinh"] == "bien_the" and not row.get("bien_the"):
                    raise FilterReviewError("rule này không có biến thể mức kỹ thuật")
            elif row["quyet_dinh"] not in ("", "giu", "bo", "rut_gon"):
                raise FilterReviewError("quyết định rule chỉ là giu, bo hoặc rut_gon")
            cut = row["bo_muc"]
            if (not isinstance(cut, list) or any(type(i) is not int for i in cut) or len(set(cut)) != len(cut)
                    or any(not 0 <= i < len(row["doi_chieu"]) for i in cut)):
                raise FilterReviewError("bo_muc phải là danh sách số thứ tự mục đối chiếu, không trùng")
            if (row["quyet_dinh"] == "rut_gon") != bool(cut):
                raise FilterReviewError("bo_muc chỉ dùng, và bắt buộc có, khi quyết định là rut_gon")
        elif row["quyet_dinh"] not in ("", "giu", "bo"):
            raise FilterReviewError("quyết định rule chỉ là giu hoặc bo")
        if not row["quyet_dinh"]:
            pending = True
            continue
        if not reviewer.strip():
            raise FilterReviewError("cần nguoi_duyet cho quyết định rule")
        if row["quyet_dinh"] in ("bo", "rut_gon") and not row["ly_do"].strip():
            raise FilterReviewError("bỏ hoặc rút gọn rule cần lý do")
        if row.get("do_rong") and row["quyet_dinh"] in ("giu", "rut_gon") and not row["ly_do"].strip():
            raise FilterReviewError("giữ rule rộng (giữ phần lớn nguồn log) cần lý do")
        if row["quyet_dinh"] == "bien_the" and not row["ly_do"].strip():
            raise FilterReviewError("chạy biến thể thay rule gốc cần lý do")
    if pending and complete:
        raise PendingFilterReview("còn rule chưa quyết định giữ/bỏ; cả lô giữ ở cổng ◆")
    return form


def save_rule_decisions(review_dir: Path, reviewer: str, choices: dict[str, dict], expected_form_sha256: str) -> None:
    """UI chỉ sửa trường người điền của phiếu rule; widget cũ không ghi đè phiếu mới."""
    path = review_dir / RULE_FORM
    if _sha(path) != expected_form_sha256:
        raise FilterReviewError("phiếu rule đã đổi; tải lại trước khi lưu")
    m = verify_packet(review_dir)
    form = deepcopy(validate_rule_form(review_dir, m, complete=False))
    known = {r["id"] for r in form["rule"]}
    if not set(choices) <= known or any(not set(v) <= set(_rule_human(m)) for v in choices.values()):
        raise FilterReviewError("quyết định không thuộc phiếu rule/trường người điền")
    for row in form["rule"]:
        row.update(choices.get(row["id"], {}))
    form["nguoi_duyet"] = reviewer
    validate_rule_form(review_dir, m, complete=False, proposed=form)
    if _sha(path) != expected_form_sha256:
        raise FilterReviewError("phiếu rule đã đổi")
    _write(path, form, yaml_format=True)


def blocked_rules(review_dir: Path) -> dict[str, dict]:
    """Rule người duyệt bỏ: id hunt → {hypothesis_id, ly_do}. Gói không có phiếu rule thì rỗng."""
    m = _read(review_dir / MANIFEST)
    if not m.get("doi_chieu_rule"):
        return {}
    form = validate_rule_form(review_dir, m, complete=False)
    return {r["id"]: {"hypothesis_id": r["hypothesis_id"], "ly_do": r["ly_do"]}
            for r in form["rule"] if r["quyet_dinh"] == "bo"}


def chosen_variants(review_dir: Path) -> dict[str, dict]:
    """Rule người duyệt chọn chạy biến thể mức kỹ thuật (phiếu v3): id hunt → biến thể đã băm trong manifest."""
    m = _read(review_dir / MANIFEST)
    if _rule_policy(m) != RULE_POLICY_V3 or not m.get("doi_chieu_rule"):
        return {}
    form = validate_rule_form(review_dir, m, complete=False)
    return {r["id"]: r["bien_the"] for r in form["rule"] if r["quyet_dinh"] == "bien_the"}


def shortened(review_dir: Path) -> list[dict]:
    """Rule người duyệt chọn rút gọn: id hunt, giả thuyết, đúng các mục bỏ (theo thứ tự trong phiếu), lý do."""
    m = _read(review_dir / MANIFEST)
    if not m.get("doi_chieu_rule"):
        return []
    form = validate_rule_form(review_dir, m, complete=False)
    return [{"id": r["id"], "hypothesis_id": r["hypothesis_id"], "bo_muc": [r["doi_chieu"][i] for i in sorted(r["bo_muc"])],
             "ly_do": r["ly_do"]} for r in form["rule"] if r["quyet_dinh"] == "rut_gon"]


def revision_requested(review_dir: Path) -> bool:
    return bool(shortened(review_dir))


def shorten_draft(con, draft: dict, items: list[dict]) -> dict:
    """Draft mới của rule đã bỏ đúng các mục chọn — chỉ xóa — dựng lại qua đúng đường kiểm tĩnh/biên dịch/ràng buộc
    như rule do ⑤ sinh; không gọi mô hình. Không làm được thì từ chối, người duyệt chỉ còn giữ hoặc bỏ cả rule."""
    from .contracts import ContractB
    from .stages import rule_fidelity
    ctx = draft["sigma_context"]
    if not ctx.get("binding"):
        raise FilterReviewError(f"{draft['id']}: draft không gắn giả thuyết đã duyệt; không rút gọn được")
    try:
        rule = rule_fidelity.shorten_rule(ctx["rule"], ContractB.model_validate(ctx["binding"]), items)
    except rule_fidelity.ShortenError as exc:
        raise FilterReviewError(f"không rút gọn được {draft['id']}: {exc}") from exc
    errors, expected = _derive(con, draft, rule)
    if errors:
        raise FilterReviewError(f"rule rút gọn {draft['id']} không qua kiểm tĩnh: " + "; ".join(e.message for e in errors))
    match = [s for s in expected if s["id"] == draft["id"]]
    if len(match) != 1:
        raise FilterReviewError(f"rule rút gọn {draft['id']} đổi nguồn log hoặc định danh hunt")
    return _clean(match[0])


def revision_specs(con, review_dir: Path) -> dict:
    """Bản sửa của gói: draft rút gọn cho rule đã chọn, draft giữ nguyên cho rule khác (đúng như đã lưu), context ghi gói
    nguồn và các mục bỏ, thư mục bản sửa, phụ thuộc (gồm manifest và hai phiếu của gói nguồn)."""
    review_dir = Path(review_dir)
    m = verify_packet(review_dir, con=con)
    cuts = {c["id"]: c for c in shortened(review_dir)}
    if not cuts:
        raise FilterReviewError("không có rule chọn rút gọn")
    specs = [shorten_draft(con, s, cuts[s["id"]]["bo_muc"]) if s["id"] in cuts else _clean(s) for s in m["specs"]]
    context = {**m["context"], "ban_sua_cua": {"goi": review_dir.name, "manifest_sha256": _sha(review_dir / MANIFEST),
                                               "rut_gon": list(cuts.values())}}
    dependencies = [Path(p) for p in m["dependencies"]] + [review_dir / MANIFEST, review_dir / FORM, review_dir / RULE_FORM]
    return {"specs": specs, "context": context, "dependencies": dependencies,
            "new_dir": review_dir.parent / f"r{int(review_dir.name[1:]) + 1:02d}"}


def check_revision(review_dir: Path, con) -> None:
    """Dựng và kiểm bản sửa đúng như lúc phát, không ghi gì: chạy trước khi tiếp tục graph để lỗi trả về ngay và lượt vẫn
    đứng ở cổng."""
    plan = revision_specs(con, review_dir)
    _check_drafts(con, plan["specs"], plan["context"], plan["new_dir"])


def mark_revised(review_dir: Path, new_dir: Path) -> None:
    """Khóa gói đã có bản sửa (ghi sau khi bản sửa đã phát): chỉ bản sửa được thực thi."""
    data = {"ban_sua": new_dir.name, "manifest_ban_sua_sha256": _sha(new_dir / MANIFEST),
            "phieu_sha256": _sha(review_dir / FORM), "phieu_rule_sha256": _sha(review_dir / RULE_FORM)}
    path = review_dir / REVISION
    if path.exists() and _read(path) != data:
        raise FilterReviewError("gói đã có bản sửa khác")
    _write(path, data)


def revision_chain(review_dir: Path) -> list[dict]:
    """Các lần rút gọn dẫn tới gói này, cũ trước: gói nguồn, hunt, giả thuyết, mục bỏ, lý do."""
    out, rd = [], Path(review_dir)
    while (prov := _read(rd / MANIFEST)["context"].get("ban_sua_cua")):
        out = [{"goi": prov["goi"], **c} for c in prov["rut_gon"]] + out
        rd = rd.parent / prov["goi"]
    return out


def save_decisions(review_dir: Path, reviewer: str, choices: dict[str, dict], expected_form_sha256: str) -> None:
    """UI edits only explicit human fields. A stale widget never overwrites a new form."""
    path = review_dir / FORM
    if _sha(path) != expected_form_sha256:
        raise FilterReviewError("phiếu đã đổi; tải lại trước khi lưu")
    validate_form(review_dir, complete=False)
    form = load_form(review_dir)
    known = {r["id"] for r in form["muc_loc"]}
    if not set(choices) <= known or any(not set(v) <= MUTABLE for v in choices.values()):
        raise FilterReviewError("quyết định không thuộc phiếu/trường người điền")
    for row in form["muc_loc"]:
        row.update(choices.get(row["id"], {}))
    form["nguoi_duyet"] = reviewer
    validate_form(review_dir, complete=False, proposed=form)
    if _sha(path) != expected_form_sha256:
        raise FilterReviewError("phiếu đã đổi")
    _write(path, form, yaml_format=True)


def _effective_specs(m: dict, form: dict, review_dir: Path, log_sha: str) -> list[dict]:
    choices = {r["id"]: r for r in form["muc_loc"]}
    blocked = blocked_rules(review_dir)              # rule người duyệt bỏ: không thành hunt hiệu lực
    variants = chosen_variants(review_dir)           # rule chạy bằng biến thể mức kỹ thuật (phiếu v3)
    specs = []
    for draft in m["specs"]:
        if draft["id"] in blocked:
            continue
        spec = deepcopy(draft)
        if spec["id"] in variants:
            v = variants[spec["id"]]
            # Biến thể là rule mới: điều kiện của biến thể, không mang mục lọc của rule gốc.
            spec.update(candidates=v["candidates"], filters=[],
                        bien_the={"version": v["version"], "mo_ta": v["mo_ta"], "candidates_goc": draft["candidates"]})
        kept = []
        for f in spec["filters"]:
            row = choices[f"{spec['id']}__{f['id']}"]
            if row["quyet_dinh"] == "approved":
                f.update(status="approved", ly_do=row["ly_do"], can_cu=row["can_cu"],
                         nguoi_chiu_trach_nhiem=row["nguoi_chiu_trach_nhiem"], het_han=row["hieu_luc_den_utc"])
                kept.append(f)
        spec.update(filters=kept, filter_phase="effective", filter_review={"dir": str(review_dir.resolve()),
                    "manifest_sha256": _sha(review_dir / MANIFEST), "approval_log_sha256": log_sha})
        specs.append(spec)
    return specs


def finalize(review_dir: Path, *, con=None) -> list[Path]:
    review_dir = review_dir.resolve()
    if (review_dir / REVISION).exists():
        raise FilterReviewError("gói đã có bản sửa (rule rút gọn); chỉ bản sửa được thực thi")
    m, form = validate_form(review_dir, con=con)
    if shortened(review_dir):
        raise FilterReviewError("còn rule chọn rút gọn; phát bản sửa của gói trước khi thực thi")
    complete = review_dir / EFFECTIVE
    if complete.exists():
        saved = _read(complete)
        if (saved.get("policy") != POLICY or saved.get("manifest_sha256") != form["manifest_sha256"] or
                saved.get("approval_log_sha256") != _sha(review_dir / "approval_log.json") or
                len(saved.get("files", {})) != len(m["specs"]) - len(blocked_rules(review_dir))):
            raise FilterReviewError("gói hiệu lực chưa hoàn tất hoặc đã đổi")
        # Bỏ hết rule thì không còn tệp để require_executable đối chiếu phiếu với log: kiểm ở đây.
        log = _read(review_dir / "approval_log.json")
        if log.get("phieu_sha256") != _sha(review_dir / FORM) or (
                m.get("doi_chieu_rule") and log.get("phieu_rule_sha256") != _sha(review_dir / RULE_FORM)):
            raise FilterReviewError("phiếu đã đổi sau khi xuất gói hiệu lực")
        files = [Path(p) for p in saved["files"]]
        for path in files:
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            require_executable(spec, con=con)
        return files
    if (review_dir / "approval_log.json").exists():
        raise FilterReviewError("gói hiệu lực xuất dở; giữ artifact và phát revision mới")
    instant = utcnow()
    log = {"policy": POLICY, "manifest_sha256": form["manifest_sha256"],
           "phieu_sha256": _sha(review_dir / FORM), "nguoi_duyet": form["nguoi_duyet"],
           "thoi_diem_utc": instant.isoformat(), "quyet_dinh": form["muc_loc"],
           "kind": "reviewed_filters" if form["muc_loc"] else "no_filters"}
    if m.get("doi_chieu_rule"):
        rule_form = validate_rule_form(review_dir, m)
        log.update(phieu_rule_sha256=_sha(review_dir / RULE_FORM), nguoi_duyet_rule=rule_form["nguoi_duyet"],
                   quyet_dinh_rule=rule_form["rule"])
    _write(review_dir / "approval_log.json", log)
    log_sha = _sha(review_dir / "approval_log.json")
    specs = _effective_specs(m, form, review_dir, log_sha)
    output = _inside(review_dir.parent.parent / "hunts_effective" / review_dir.name, Path(m["run_root"]))
    files = {}
    for i, spec in enumerate(specs):
        path = output / f"hunt_{i:03d}.yaml"
        _write(path, spec, yaml_format=True)
        files[str(path.resolve())] = _sha(path)
    _write(complete, {"policy": POLICY, "manifest_sha256": form["manifest_sha256"],
                      "approval_log_sha256": log_sha, "files": files})
    return [Path(p) for p in files]


def _discover(spec: dict) -> dict:
    if spec.get("_path"):
        for parent in Path(spec["_path"]).resolve().parents:
            envelope = parent / CONTEXT
            if envelope.exists():
                return _read(envelope)
            meta = parent / "run_meta.json"
            if meta.exists() and _read(meta).get("phien_ban") == "v2":
                return {"policy": POLICY, "root": str(parent)}
    return {}


def path_policy(path: Path) -> str:
    return _discover({"_path": str(path)}).get("policy", "")


def result_contract(spec: dict) -> dict:
    """Preserve the exact effective spec across result -> triage/record boundaries."""
    return {"filter_contract": _clean(spec)} if spec.get("filter_policy") else {}


def decision_preview(review_dir: Path, con) -> list[dict]:
    """Local counts for explicit choices; pending rows stay visible and never execute."""
    from .hunt.runner import _scope_where
    m, form = validate_form(review_dir, con=con, complete=False)
    choices = {r["id"]: r["quyet_dinh"] for r in form["muc_loc"]}
    results = []
    for s in m["specs"]:
        where = f"({_scope_where(s['scope'])}) AND ({s['candidates']})"
        def count():
            return con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]
        previous = count()
        stages = [{"stage": "ung_vien", "hits": previous}]
        for f in s["filters"]:
            if choices[f"{s['id']}__{f['id']}"] != "approved":
                continue
            where += f" AND ({f['where']}) IS NOT TRUE"
            remaining = count()
            stages.append({"stage": f"sau_{f['id']}", "hits": remaining, "removed": previous - remaining})
            previous = remaining
        results.append({"hunt_id": s["id"], "kind": "decision_preview_only", "stages": stages})
    return results


def require_executable(spec: dict, *, con=None, audit_at: str | None = None) -> None:
    """Shared gate for every execution path, including specs supplied in memory."""
    runtime = _connections.get(con, {}) if con is not None else {}
    discovered = _discover(spec)
    marked = spec.get("filter_policy")
    if not marked and not runtime.get("policy") and not discovered.get("policy"):
        return                          # pinned v1 semantics
    if marked != POLICY or spec.get("filter_phase") != "effective":
        raise FilterReviewError("v2 chỉ thực thi hunt hiệu lực sau ◆; draft/thiếu marker bị chặn")
    ref = spec.get("filter_review") or {}
    if not ref.get("dir") or not ref.get("manifest_sha256") or not ref.get("approval_log_sha256"):
        raise FilterReviewError("thiếu provenance duyệt lọc")
    rd = Path(ref["dir"])
    m = verify_packet(rd, con=con, manifest_sha256=ref["manifest_sha256"])
    for ctx in (runtime, discovered):
        if ctx.get("policy") and ctx.get("root") != m["run_root"]:
            raise FilterReviewError("hunt/gói thuộc lượt khác")
    log_path = rd / "approval_log.json"
    if _sha(log_path) != ref["approval_log_sha256"]:
        raise FilterReviewError("log duyệt đã đổi")
    log = _read(log_path)
    audit_at = audit_at or runtime.get("audit_at")
    instant = _time(audit_at) if audit_at else utcnow()
    # Audit time must be the recorded official execution, not a caller-chosen old date.
    if audit_at:
        rec = _read(rd / "execution_receipt.json")
        if (audit_at != rec.get("executed_at_utc") or
                rec.get("effective_manifest_sha256") != _sha(rd / EFFECTIVE) or
                rec.get("kind") != "completed_execution"):
            raise FilterReviewError("audit replay cần receipt hoàn tất của đúng gói thực thi gốc")
        if instant < _time(log["thoi_diem_utc"]) or instant > utcnow():
            raise FilterReviewError("thời điểm thực thi gốc không hợp lệ")
        if runtime.get("audit_dir") and runtime["audit_dir"] != str(rd.resolve()):
            raise FilterReviewError("audit không được đổi sang gói khác")
    _, form = validate_form(rd, con=con, now=instant)
    if (_sha(rd / FORM) != log["phieu_sha256"] or form["muc_loc"] != log["quyet_dinh"] or
            log.get("nguoi_duyet") != form["nguoi_duyet"] or log.get("policy") != POLICY or
            log.get("manifest_sha256") != ref["manifest_sha256"]):
        raise FilterReviewError("phiếu/log quyết định không khớp")
    if m.get("doi_chieu_rule"):
        rule_form = validate_rule_form(rd, m)
        if (_sha(rd / RULE_FORM) != log.get("phieu_rule_sha256") or rule_form["rule"] != log.get("quyet_dinh_rule") or
                rule_form["nguoi_duyet"] != log.get("nguoi_duyet_rule")):
            raise FilterReviewError("phiếu/log quyết định rule không khớp")
    expected = _effective_specs(m, form, rd, ref["approval_log_sha256"])
    match = [s for s in expected if s["id"] == spec["id"]]
    if len(match) != 1 or _clean(spec) != match[0]:
        raise FilterReviewError("hunt hiệu lực khác nội dung đã duyệt")
    complete = _read(rd / EFFECTIVE)
    if (complete.get("policy") != POLICY or complete.get("manifest_sha256") != ref["manifest_sha256"] or
            complete.get("approval_log_sha256") != ref["approval_log_sha256"] or
            len(complete.get("files", {})) != len(expected)):
        raise FilterReviewError("gói hiệu lực chưa hoàn tất hoặc đã đổi")
    for path, sha in complete["files"].items():
        _inside(Path(path), Path(m["run_root"]))
        if _sha(Path(path)) != sha:
            raise FilterReviewError("hunt hiệu lực đã đổi")


def receipt(review_dir: Path, *, con, executed_at: str | None = None) -> None:
    files = finalize(review_dir, con=con)
    for path in files:
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        require_executable(spec, con=con)
    path = review_dir / "execution_receipt.json"
    if not path.exists():
        _write(path, {"kind": "completed_execution" if files else "no_executable_rules",
                      "executed_at_utc": executed_at or utcnow().isoformat(),
                      "effective_manifest_sha256": _sha(review_dir / EFFECTIVE)})
    elif _read(path).get("effective_manifest_sha256") != _sha(review_dir / EFFECTIVE):
        raise FilterReviewError("receipt hiện có không khớp gói hiệu lực")


@contextmanager
def audit_context(con, review_dir: Path):
    """Only replay the completed packet; no planner, generation, or new authorization."""
    rd = review_dir.resolve()
    m = verify_packet(rd, con=con)
    rec = _read(rd / "execution_receipt.json")
    old = deepcopy(_connections.get(con, {}))
    bind(con, Path(m["run_root"]))
    _connections[con].update(audit_at=rec.get("executed_at_utc"), audit_dir=str(rd))
    try:
        if not rec.get("executed_at_utc"):
            raise FilterReviewError("receipt thiếu thời điểm thực thi")
        yield
    finally:
        _connections[con] = old


def cancel(review_dir: Path, reviewer: str, reason: str) -> Path:
    rd = review_dir.resolve()
    verify_packet(rd)
    if (rd / "execution_receipt.json").exists():
        raise FilterReviewError("gói đã thực thi; không thể hủy như chưa chạy")
    if not reviewer.strip() or not reason.strip():
        raise FilterReviewError("hủy cần người xác nhận và lý do")
    path = rd / CANCEL
    _write(path, {"kind": "cancelled_before_execution", "manifest_sha256": _sha(rd / MANIFEST),
                  "nguoi_xac_nhan": reviewer, "ly_do": reason, "thoi_diem_utc": utcnow().isoformat()})
    return path
