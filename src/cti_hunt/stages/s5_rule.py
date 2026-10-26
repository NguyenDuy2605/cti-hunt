"""Khâu ⑤ — sinh rule Sigma cho giả thuyết ĐÃ DUYỆT, kiểm tra tĩnh, tự sửa khi lỗi (v3 §4.2 ⑤, §6.2). Tuần 4.

Kiểm tra tĩnh (`validate_rule`), theo thứ tự, dừng ở tầng đầu tiên có lỗi:

    yaml_loi               không đọc được YAML, hoặc không phải một tài liệu dạng ánh xạ
    yaml_trung_khoa        cùng một khối có khóa lặp (07/10): YAML chỉ giữ khóa cuối nên điều kiện trước mất lặng lẽ
    sigma_loi              pySigma báo lỗi: modifier sai, condition trỏ tới khối không tồn tại...
    so_rule                không đúng một rule
    regex_lap_so_khong_ho_tro  prompt v4: lặp số trong regex ứng viên nằm ngoài ngôn ngữ hỗ trợ
    co_ma_hoa_tren_noi_dung_script  prompt v6 (12/10): cờ khởi chạy mã hóa (-e/-enc/-EncodedCommand) đặt lên
                           ScriptBlockText/Payload mà giả thuyết không nêu cờ đó là nội dung script
    pivot_tai_khoan_trong_rule  giả thuyết pivot theo tài khoản mà khối sinh ứng viên tự đặt điều kiện trên trường
                           tài khoản (08/10): mã đã ràng buộc tài khoản khi thực thi, rule tự viết thì trùng và
                           dễ sai định dạng (`User: dschrute` không khớp giá trị có tên miền `DMEVALS/dschrute`)
    khong_co_logsource     nguồn log của giả thuyết không có logsource Sigma nào trong danh mục — báo ngay, không
                           gọi mô hình (đứng trước mọi tầng dưới)
    logsource_khong_co     logsource không có nguồn log nào trong configs/logsource_catalog.yaml
    truong_khong_co        rule dùng trường mà nguồn log của giả thuyết không có
    khac_nguon_gia_thuyet  rule biên dịch ra nguồn log khác với evidence của giả thuyết (khác mẫu số FPR)
    hunt_spec_loi          hunt spec không qua runner.validate (vd tham chiếu nhãn)
    sql_loi                DuckDB từ chối truy vấn ở bước EXPLAIN (chỉ khi có kết nối dữ liệu)

Vòng tự sửa gửi lại cho mô hình ĐÚNG các thông báo lỗi trên, không gì khác. Nó không bao giờ thấy số kết quả
truy vấn hay nhãn: EXPLAIN chỉ lập kế hoạch, không chạy trên dữ liệu. Nếu mô hình thấy số kết quả, nó sẽ chỉnh
điều kiện theo dữ liệu đánh giá và execution accuracy không còn ý nghĩa.

Báo cáo cả hai con số theo §6.2: hợp lệ ngay lần đầu, và hợp lệ sau khi sửa. Chỉ báo con số sau sửa là che mất tỷ
lệ lỗi thật của mô hình.

Chỉ v2: lỗi `truong_khong_co` trên nguồn log
(channel + mã sự kiện của giả thuyết) không có sự kiện nào thì không gọi sửa — cột thiếu vì loại sự kiện đó vắng hẳn,
không lần sửa nào hợp lệ được. Mã đếm trên `events`, số đếm không vào prompt. Xem
docs/METHODOLOGY.md.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import duckdb
import yaml
from pydantic import BaseModel, ValidationError
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetectionItem

from ..adapters import duckdb_sigma as adapter
from ..approval import require_approved
from ..contracts import ContractB
from ..hunt import runner
from ..llm import providers
from ..llm.budget import BudgetExhausted
from ..llm.prompting import fill
from .s8_pivot import PivotError, bind_spec
from . import execution_semantics, rule_fidelity, s8_triage
from ..adapters import filter_structure

BUDGET_KIND = "het_ngan_sach"
REFUSAL_KIND = "mo_hinh_tu_choi"
EMPTY_SOURCE_KIND = "nguon_khong_co_su_kien"
DUPLICATE_KEY_KIND = "yaml_trung_khoa"
PIVOT_ACCOUNT_KIND = "pivot_tai_khoan_trong_rule"


class DuplicateKeyError(yaml.constructor.ConstructorError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses a repeated key in one mapping instead of keeping only the last value.

    Seen with a real model 07/10: three `CommandLine|contains` keys in one selection silently became one condition.
    """


def _unique_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise DuplicateKeyError(None, None, f"khóa {key!r} lặp lại", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


@dataclass
class RuleIssue:
    kind: str
    message: str


class LLMRule(BaseModel):
    rule_yaml: str = ""
    note: str = ""


def candidate_policy(prompt: dict) -> str:
    """Static policy pinned together with the prompt; legacy prompts opt out."""
    policy = prompt["sections"].get("STATIC_POLICY", "")
    rule_fidelity.check_policy(policy)
    return policy


def _target(h: ContractB) -> tuple[str, list[int]]:
    return h.evidence.data_source.lower(), sorted(set(h.evidence.event_ids))


def _covers(source_eids: list[int] | None, eids: list[int]) -> bool:
    """Nguồn log của danh mục chứa được nguồn log của giả thuyết: cùng tập mã sự kiện, tập rộng hơn, hoặc logsource
    dạng `service:` không cố định mã sự kiện (vd `service: security` — rule tự lọc EventID)."""
    s = set(source_eids or [])
    return not s or set(eids) <= s


def _sigma_logsource(key: str) -> dict:
    kind, _, name = key.partition(":")
    return {"product": "windows", "service": name} if kind == "service" and name else \
        {"product": "windows", "category": key}


def logsources_for(h: ContractB, ls_catalog: dict[str, list[dict]]) -> list[dict]:
    """Logsource Sigma chứa được nguồn log của giả thuyết, kèm tên trường Sigma tương ứng key_fields.

    Nguồn log của hunt luôn là nguồn log của giả thuyết (mẫu số FPR, v3.2 §6.1): logsource rộng hơn thì phạm vi hunt
    được mã thu về đúng channel + mã sự kiện của giả thuyết (`validate_rule`).
    """
    ch, eids = _target(h)
    out = []
    for category, sources in ls_catalog.items():
        for s in sources:
            if s["channel"].lower() == ch and _covers(s.get("event_ids"), eids):
                inverse = {v.lower(): k for k, v in (s.get("field_map") or {}).items()}
                fields = [inverse.get(f.lower(), f) for f in h.evidence.key_fields]
                out.append({"category": category, "logsource": _sigma_logsource(category), "source": s["name"],
                            "event_ids": eids, "fields": fields, "unavailable_fields": s.get("unavailable") or []})
    return out


def pivot_account_issues(rule, h: ContractB) -> list[RuleIssue]:
    """Giả thuyết pivot theo tài khoản: `s8_pivot.bind_spec` tự thêm điều kiện tài khoản khi thực thi (bỏ tên miền, chữ
    thường, trên mọi cột tài khoản của nguồn). Khối sinh ứng viên không được tự đặt điều kiện trên trường tài khoản:
    trùng lặp và dễ sai định dạng — gặp ở 3 lượt đánh giá 08/10, `User: dschrute` không khớp giá trị có tên miền.
    Chỉ nhìn cấu trúc rule (tên trường), không chạy truy vấn hay dùng số kết quả."""
    if h.origin != "pivot" or h.pivot_kind != "tai_khoan":
        return []
    detections = rule.detection.detections
    try:
        candidates, _ = filter_structure.partition(rule)
        names = filter_structure.Parser(candidates, list(detections)).parse().names()
    except filter_structure.FilterStructureError:
        names = [n for n in detections if not n.lower().startswith("filter")]
    account = {c.lower() for c in s8_triage.ACCOUNT_COLUMNS}
    found = []
    for name in names:
        stack = [detections[name]]
        while stack:
            node = stack.pop()
            if isinstance(node, SigmaDetectionItem):
                if node.field and node.field.lower() in account:
                    found.append(f"{name}.{node.field}")
            else:
                stack.extend(node.detection_items)
    if not found:
        return []
    return [RuleIssue(PIVOT_ACCOUNT_KIND,
                      f"Giả thuyết pivot theo tài khoản '{h.pivot_value}': mã tự thêm điều kiện tài khoản khi thực thi "
                      f"(bỏ tên miền, không phân biệt hoa thường, trên các trường {', '.join(s8_triage.ACCOUNT_COLUMNS)}). "
                      f"Bỏ điều kiện tài khoản khỏi khối sinh ứng viên: {', '.join(sorted(set(found)))}.")]


def validate_rule(text: str, h: ContractB, ls_catalog: dict[str, list[dict]],
                  columns: set[str] | None = None,
                  con: duckdb.DuckDBPyConnection | None = None, *, filter_policy: str = "",
                  anchors: dict[str, str] | None = None,
                  candidate_regex_policy: str = "") -> tuple[list[RuleIssue], list[dict]]:
    rule_fidelity.check_policy(candidate_regex_policy)
    semantic_issues = execution_semantics.issues(h)
    if semantic_issues:
        return [RuleIssue(i['kind'], i['message']) for i in semantic_issues], []
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)
    except DuplicateKeyError as e:
        # Static message only: names the key and line, never a result count.
        return [RuleIssue(DUPLICATE_KEY_KIND,
                          f"{e.problem} (dòng {e.problem_mark.line + 1}) trong cùng một khối; YAML chỉ giữ giá trị cuối nên "
                          "điều kiện trước bị mất. Gộp các giá trị cùng trường bằng modifier |all (cần đủ) hoặc danh sách "
                          "(một trong số), hoặc tách thành khối selection riêng nối bằng and trong condition.")], []
    except yaml.YAMLError as e:
        return [RuleIssue("yaml_loi", str(e).replace("\n", " "))], []
    if not isinstance(doc, dict):
        return [RuleIssue("yaml_loi", "không phải một tài liệu YAML dạng ánh xạ (key: value)")], []
    try:
        coll = SigmaCollection.from_yaml(text, collect_errors=True)
    except Exception as e:                                   # noqa: BLE001 — lỗi nào của pySigma cũng là lỗi rule
        return [RuleIssue("sigma_loi", f"{type(e).__name__}: {e}")], []
    errs = list(dict.fromkeys(str(e) for e in [*coll.errors, *(x for r in coll.rules for x in r.errors)]))
    if errs:
        return [RuleIssue("sigma_loi", e) for e in errs], []
    if len(coll.rules) != 1:
        return [RuleIssue("so_rule", f"cần đúng 1 rule, có {len(coll.rules)}")], []
    try:
        fidelity = rule_fidelity.candidate_regex_issues(coll.rules[0], candidate_regex_policy, h)
        if fidelity:
            return [RuleIssue(**i) for i in fidelity], []
        pivot_account = pivot_account_issues(coll.rules[0], h)
        if pivot_account:
            return pivot_account, []
        hunts, skipped = adapter.compile_text(text, ls_catalog, columns, filter_policy=filter_policy)
    except Exception as e:                                   # noqa: BLE001
        from ..adapters.filter_structure import FilterStructureError
        if isinstance(e, FilterStructureError):
            return [RuleIssue("blocked_filter_structure", str(e))], []
        return [RuleIssue("sigma_loi", f"{type(e).__name__}: {e}")], []

    ch, eids = _target(h)
    wanted = {s["source"] for s in logsources_for(h, ls_catalog)}
    match = [x for x in hunts if x.source in wanted]
    if not match:
        own = [s for s in skipped if s.source in wanted]
        if own:
            return [RuleIssue("truong_khong_co", f"{s.source}: {s.ly_do}") for s in own], []
        if not hunts and all("logsource" in s.ly_do for s in skipped):
            return [RuleIssue("logsource_khong_co", s.ly_do) for s in skipped], []
        got = [f"{x.source} ({x.scope['channel']} EID {x.scope['event_ids']})" for x in hunts] or ["không nguồn nào"]
        return [RuleIssue("khac_nguon_gia_thuyet",
                          f"giả thuyết cần {ch} EID {eids}; rule biên dịch ra: {', '.join(got)}. "
                          f"Dùng logsource: {sorted(wanted) or 'không có trong danh mục'}")], []

    if h.origin == "pivot" and len(match) != 1:
        return [RuleIssue("pivot_nhieu_truy_van", "một giả thuyết pivot chỉ được sinh một truy vấn")], []

    issues, specs = [], []
    for x in match:
        spec = x.to_hunt_spec()
        spec["scope"] = {**spec["scope"], "event_ids": eids}      # thu về đúng nguồn log của giả thuyết
        spec["id"] = f"{h.hypothesis_id}__{spec['id']}"
        spec.update(hypothesis_id=h.hypothesis_id, gia_thuyet=h.behavior, linked_ttps=list(h.linked_ttps),
                    rule_ttps=x.linked_ttps)
        try:
            spec = bind_spec(execution_semantics.bind_window(spec, h), h, columns, for_execution=False)
            spec = execution_semantics.bind_constraints(spec, h, columns, anchors)
            if filter_policy:
                spec["sigma_context"]["binding"] = h.model_dump(mode="json")
                if candidate_regex_policy:
                    spec["sigma_context"]["candidate_regex_policy"] = candidate_regex_policy
            runner.validate(spec, for_execution=False)
        except (runner.HuntSpecError, PivotError) as e:
            issues.append(RuleIssue("hunt_spec_loi", str(e)))
            continue
        except execution_semantics.ConstraintError as e:
            issues.append(RuleIssue(e.kind, str(e)))
            continue
        if con is not None:
            base = f"SELECT 1 FROM events WHERE {runner._scope_where(spec['scope'])}"
            for label, where in [("ứng viên", spec["candidates"])] + [(f["id"], f["where"]) for f in spec["filters"]]:
                try:
                    con.execute(f"EXPLAIN {base} AND ({where})")
                except duckdb.Error as e:
                    issues.append(RuleIssue("sql_loi", f"{label}: {str(e).splitlines()[0]}"))
        specs.append(spec)
    return issues, (specs if not issues else [])


def _scope_is_empty(con: duckdb.DuckDBPyConnection, h: ContractB) -> bool:
    ch, eids = _target(h)
    return con.execute(f"SELECT count(*) FROM events WHERE "
                       f"{runner._scope_where({'channel': ch, 'event_ids': eids})}").fetchone()[0] == 0


def generate_rule(h: ContractB, llm, prompt: dict, ls_catalog: dict[str, list[dict]], max_repair: int,
                  columns: set[str] | None = None, con: duckdb.DuckDBPyConnection | None = None,
                  run_dir: Path | None = None, *, filter_policy: str = "",
                  stop_repair_on_empty_source: bool = False, anchors: dict[str, str] | None = None) -> dict:
    require_approved(h)
    semantic_issues = execution_semantics.issues(h)
    if not semantic_issues and h.rang_buoc and h.rang_buoc.moc_neo \
            and not (anchors or {}).get(h.rang_buoc.moc_neo.gia_thuyet):
        # Neo chưa chạy thì không rule nào thực thi được: báo trước, không tốn lời gọi mô hình.
        semantic_issues = [{"kind": "thieu_moc_neo", "message": f"giả thuyết neo {h.rang_buoc.moc_neo.gia_thuyet} "
                                                                "chưa có hunt đã chạy ở vòng trước"}]
    if semantic_issues:
        return {'hypothesis_id': h.hypothesis_id, 'hop_le': False, 'hop_le_lan_dau': False,
                'so_lan_sua': 0, 'rule_yaml': None, 'hunt_specs': [],
                'lan_thu': [{'lan': 0, 'loai': 'bo_qua', 'note': 'Không thực thi giả thuyết thiếu khả năng ngữ nghĩa.',
                            'rule_sha256': '', 'rule_yaml': '', 'loi': semantic_issues, 'api_events': []}],
                'token': providers.token_totals([])}
    allowed = logsources_for(h, ls_catalog)
    if not allowed:
        # Không logsource Sigma nào chứa được nguồn log này: mô hình không thể viết rule hợp lệ, gọi là tốn lượt.
        ch, eids = _target(h)
        issue = RuleIssue("khong_co_logsource", f"không có logsource Sigma nào trong danh mục cho {ch} EID {eids}")
        return {"hypothesis_id": h.hypothesis_id, "hop_le": False, "hop_le_lan_dau": False, "so_lan_sua": 0,
                "rule_yaml": None, "hunt_specs": [],
                "lan_thu": [{"lan": 0, "loai": "bo_qua", "note": "", "rule_sha256": "", "rule_yaml": "",
                             "loi": [asdict(issue)], "api_events": []}],
                "token": providers.token_totals([])}
    sec = prompt["sections"]
    # Policy is part of the versioned prompt's hash, never inferred from a filename
    # or from model output. Old prompts have no STATIC_POLICY section.
    candidate_regex_policy = candidate_policy(prompt)
    ls_text = json.dumps(allowed, ensure_ascii=False, indent=2)
    # Không gửi source_spans: câu trích report chứa tên riêng (tệp, tác vụ, domain) mà rule không được dùng (v3 §3.5).
    hyp_fields = {"hypothesis_id", "behavior", "scope", "timeframe", "evidence", "linked_ttps"}
    if h.rang_buoc is not None:
        # Tell the model which multi-event conditions code implements; do not approximate them in Sigma.
        # Unconstrained hypotheses retain the original payload shape (including legacy v1).
        hyp_fields.update({"rang_buoc", "required_operations"})
    hyp_text = json.dumps(h.model_dump(include=hyp_fields), ensure_ascii=False, indent=2)
    # A derived supported representation of approved prose, not a new Contract B
    # field or an automatic human decision. Keep old payloads unchanged.
    trace = None
    if candidate_regex_policy in rule_fidelity.ENCODED_POLICIES:
        from . import encoded_trace
        trace = encoded_trace.requirements(h)
    trace_text = json.dumps(trace, ensure_ascii=False, indent=2)
    user = fill(sec["USER"], hypothesis=hyp_text, logsources=ls_text, primary_trace_requirements=trace_text)
    attempts, specs = [], []
    for n in range(max_repair + 1):
        api_events, record = providers.event_recorder()
        try:
            data = llm.complete_json(sec["SYSTEM"], user, LLMRule.model_json_schema(), log=record)
        except BudgetExhausted as e:
            # Chưa gửi yêu cầu: không có rule mới; các lần thử trước (đã tính tiền) giữ nguyên trong nhật ký.
            attempts.append({"lan": n, "loai": "bo_qua", "note": "", "rule_sha256": "", "rule_yaml": "",
                             "loi": [asdict(budget_issue(e))], "api_events": api_events})
            break
        except providers.RefusalError as e:
            # Đã gửi và đã tính tiền; không gọi lại, không đổi mô hình. Giả thuyết này không có rule, các giả
            # thuyết khác vẫn chạy. Lưu nguyên yêu cầu bị từ chối để phân tích nguyên nhân về sau.
            attempts.append({"lan": n, "loai": "tu_choi", "note": "", "rule_sha256": "", "rule_yaml": "",
                             "loi": [asdict(refusal_issue(e))], "api_events": api_events})
            if run_dir:
                run_dir.mkdir(parents=True, exist_ok=True)
                with open(run_dir / "khau5_requests.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"hypothesis_id": h.hypothesis_id, "lan": n, "user": user, "raw": None,
                                        "tu_choi": str(e), "api_events": api_events}, ensure_ascii=False) + "\n")
            break
        try:
            out = LLMRule.model_validate(data)
        except ValidationError:
            out = LLMRule()
        text = out.rule_yaml
        if text.strip():
            issues, specs = validate_rule(text, h, ls_catalog, columns, con, filter_policy=filter_policy,
                                          anchors=anchors, candidate_regex_policy=candidate_regex_policy)
        else:
            issues, specs = [RuleIssue("khong_co_rule", "đầu ra không có rule_yaml")], []
        attempts.append({"lan": n, "loai": "sinh" if n == 0 else "sua", "note": out.note,
                         "rule_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "rule_yaml": text,
                         "loi": [asdict(i) for i in issues], "api_events": api_events})
        if run_dir:
            run_dir.mkdir(parents=True, exist_ok=True)
            with open(run_dir / "khau5_requests.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps({"hypothesis_id": h.hypothesis_id, "lan": n, "user": user,
                                    "raw": data, "api_events": api_events}, ensure_ascii=False) + "\n")
        if not issues:
            break
        if (stop_repair_on_empty_source and con is not None and n < max_repair
                and all(i.kind == "truong_khong_co" for i in issues) and _scope_is_empty(con, h)):
            ch, eids = _target(h)
            stop = RuleIssue(EMPTY_SOURCE_KIND, f"không gọi sửa: {ch} EID {eids} không có sự kiện nào trong bộ dữ "
                                                f"liệu, lỗi thiếu trường không sửa được; giả thuyết không thực thi được")
            # Không phải lần gọi mô hình, không tính vào số lần sửa; lỗi gốc giữ cạnh lý do dừng.
            attempts.append({"lan": n + 1, "loai": "dung_sua", "note": "", "rule_sha256": "", "rule_yaml": "",
                             "loi": [asdict(stop), *(asdict(i) for i in issues)], "api_events": []})
            break
        user = fill(sec["REPAIR"], rule_yaml=text or "(trống)", logsources=ls_text, hypothesis=hyp_text,
                    primary_trace_requirements=trace_text,
                    issues="\n".join(f"- [{i.kind}] {i.message}" for i in issues))
    ok = not attempts[-1]["loi"]
    return {"hypothesis_id": h.hypothesis_id, "hop_le": ok, "hop_le_lan_dau": not attempts[0]["loi"],
            "so_lan_sua": sum(a["loai"] != "dung_sua" for a in attempts) - 1,
            "rule_yaml": attempts[-1]["rule_yaml"] if ok else None,
            "hunt_specs": specs if ok else [], "lan_thu": attempts,
            "token": providers.token_totals([e for a in attempts for e in a["api_events"]])}


def budget_issue(e: Exception) -> RuleIssue:
    return RuleIssue(BUDGET_KIND, f"chưa gọi mô hình vì hết ngân sách API cục bộ: {e}")


def refusal_issue(e: Exception) -> RuleIssue:
    return RuleIssue(REFUSAL_KIND, f"mô hình từ chối, không gọi lại: {e}")


def budget_exhausted(result: dict) -> str:
    """Thông điệp hết ngân sách nếu lần thử cuối của rule dừng vì không đủ tiền giữ trước, ngược lại rỗng."""
    return next((i["message"] for i in result["lan_thu"][-1]["loi"] if i["kind"] == BUDGET_KIND), "")


def budget_skipped(h: ContractB, message: str) -> dict:
    """Giả thuyết đã duyệt nhưng không gọi ⑤ vì lô đã hết ngân sách: chưa kiểm bằng truy vấn, không phải 0 kết quả."""
    return {"hypothesis_id": h.hypothesis_id, "hop_le": False, "hop_le_lan_dau": False, "so_lan_sua": 0,
            "rule_yaml": None, "hunt_specs": [],
            "lan_thu": [{"lan": 0, "loai": "bo_qua", "note": "", "rule_sha256": "", "rule_yaml": "",
                         "loi": [{"kind": BUDGET_KIND, "message": message}], "api_events": []}],
            "token": providers.token_totals([])}


def summarize(results: list[dict]) -> dict:
    """Tỷ lệ hợp lệ cú pháp (v3 §6.2), báo dạng số đếm."""
    n = len(results)
    return {"so_gia_thuyet": n,
            "hop_le_lan_dau": sum(r["hop_le_lan_dau"] for r in results),
            "hop_le_sau_sua": sum(r["hop_le"] for r in results),
            "loi_lan_dau_theo_loai": _count_kinds(r["lan_thu"][0]["loi"] for r in results)}


def _count_kinds(lists) -> dict[str, int]:
    out: dict[str, int] = {}
    for issues in lists:
        for i in issues:
            out[i["kind"]] = out.get(i["kind"], 0) + 1
    return out
