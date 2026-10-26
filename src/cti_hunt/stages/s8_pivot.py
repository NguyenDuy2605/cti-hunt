"""Khâu ⑧ → ④: chọn pivot theo D7, sinh Contract B rồi dừng ở phiếu ◆.

Chỉ nhận thống kê từ ``events`` của s8_triage. Các ràng buộc máy/tài khoản
được mã gắn lại vào hunt spec sau khi Sigma biên dịch, không giao cho LLM.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import duckdb
from pydantic import ValidationError

from ..contracts import ContractA, ContractB
from ..hunt import runner
from ..llm import providers
from ..llm.budget import BudgetExhausted
from ..llm.prompting import fill
from . import s4_hypothesis, s8_triage


class PivotError(ValueError):
    pass


def _history_state(history: list[dict], cfg: dict) -> tuple[int, set[tuple[str, str]]]:
    used = 0
    already: set[tuple[str, str]] = set()
    for index, round_log in enumerate(history):
        if round_log.get("source_depth") != index:
            raise PivotError("lịch sử pivot phải đủ các vòng theo đúng độ sâu")
        selected = round_log.get("selected")
        if not isinstance(selected, list) or len(selected) > int(cfg["triage"]["max_pivots_per_round"]):
            raise PivotError("lịch sử pivot thiếu danh sách selected hoặc vượt trần mỗi vòng")
        for p in selected:
            kind, value, depth = p.get("loai"), str(p.get("gia_tri") or ""), p.get("pivot_depth")
            if kind not in ("may", "tai_khoan") or not value or depth != index + 1 or depth > int(cfg["max_pivot_depth"]):
                raise PivotError("lịch sử pivot có thực thể/độ sâu không hợp lệ")
            key = (kind, value)
            if key in already:
                raise PivotError(f"thực thể pivot lặp trong lịch sử: {kind} {value}")
            already.add(key)
            used += 1  # bảo lưu một truy vấn cho mỗi pivot được chọn, kể cả chưa được duyệt
    if used > int(cfg["triage"]["max_queries_total"]):
        raise PivotError("lịch sử pivot vượt trần truy vấn D7")
    return used, already


def plan_round(con: duckdb.DuckDBPyConnection, specs: list[dict], hypotheses: list[ContractB],
               cfg: dict, history: list[dict] | None = None) -> dict:
    """Tính lại điều kiện pivot từ truy vấn không nhãn; không tin số tự khai trong file lịch sử."""
    if not specs:
        raise PivotError("vòng pivot cần ít nhất một hunt spec có truy vấn")
    by_id = {h.hypothesis_id: h for h in hypotheses}
    if len(by_id) != len(hypotheses):
        raise PivotError("hypothesis_id trùng trong các vòng")
    ids = {s.get("hypothesis_id") for s in specs}
    if None in ids or any(hid not in by_id or by_id[hid].status != "approved" for hid in ids):
        raise PivotError("chỉ dùng kết quả của giả thuyết đã duyệt ◆")
    depths = {by_id[hid].pivot_depth for hid in ids}
    if len(depths) != 1:
        raise PivotError("kết quả đầu vào phải thuộc cùng một độ sâu pivot")
    depth = depths.pop()
    history = history or []
    if len(history) != depth:
        raise PivotError("cần đúng một nhật ký cho mỗi độ sâu pivot đã qua")
    used, already = _history_state(history, cfg)
    if depth > 0:
        last = history[-1]
        generated = set(last.get("generated_ids") or [])
        targets = {(p["loai"], p["gia_tri"]) for p in last["selected"]}
        if not ids <= generated or any((by_id[hid].pivot_kind, by_id[hid].pivot_value) not in targets for hid in ids):
            raise PivotError("kết quả vòng hiện tại không truy được về lịch sử pivot trước")
    tri = s8_triage.triage(con, specs, cfg, pivot_depth=depth, queries_used=used, already_pivoted=already)
    selected = tri["pivot"]["de_xuat"]
    if len(selected) > int(cfg["triage"]["max_pivots_per_round"]) or used + len(selected) > int(cfg["triage"]["max_queries_total"]):
        raise PivotError("đề xuất pivot vượt trần D7")
    return {"triage": tri, "selected": selected, "source_depth": depth,
            "queries_reserved_before": used, "queries_reserved_after": used + len(selected)}


def generate_round(contract_a: ContractA, telemetry: dict[str, dict], hypotheses: list[ContractB],
                   plan: dict, llm, prompt: dict, cfg: dict, attack_catalog=None,
                   run_dir: Path | None = None, anchors: list[ContractB] | None = None) -> dict:
    """Một giả thuyết tối đa cho mỗi thực thể được mã chọn; mọi giả thuyết chờ duyệt ◆."""
    selected = plan["selected"]
    if selected != plan["triage"]["pivot"]["de_xuat"]:
        raise PivotError("danh sách pivot khác đầu ra triage")
    if len(selected) > int(cfg["triage"]["max_pivots_per_round"]):
        raise PivotError("vượt trần pivot mỗi vòng")
    approved = {h.hypothesis_id: h for h in hypotheses if h.status == "approved"}
    inputs, _ = s4_hypothesis.select_inputs(contract_a, telemetry)
    prefix = re.compile(rf"^{re.escape(contract_a.report_id)}-H(\d+)$")
    next_index = 1 + max((int(m.group(1)) for h in hypotheses if (m := prefix.fullmatch(h.hypothesis_id))), default=0)
    out: list[ContractB] = []
    logs = []
    all_events: list[dict] = []
    for p in selected:
        kind, value, depth = p["loai"], str(p["gia_tri"]), p["pivot_depth"]
        if kind not in ("may", "tai_khoan") or not value or depth != plan["source_depth"] + 1 or depth > int(cfg["max_pivot_depth"]):
            raise PivotError("thực thể hoặc độ sâu pivot không hợp lệ")
        source_ids = p["tu_gia_thuyet"]
        if not source_ids or any(hid not in approved for hid in source_ids):
            raise PivotError("pivot phải bắt nguồn từ giả thuyết đã duyệt")
        tids = {tid for hid in source_ids for tid in approved[hid].linked_ttps}
        allowed = [item for item in inputs if item["ttp"].technique_id in tids]
        if not allowed:
            logs.append({"loai": kind, "gia_tri": value, "ly_do_bo": "không có TTP report còn huntable"})
            continue
        if len(out) >= int(cfg["max_hypotheses_per_round"]):
            logs.append({"loai": kind, "gia_tri": value, "ly_do_bo": "đạt trần giả thuyết mỗi vòng"})
            continue
        context = [{"hypothesis_id": hid, "behavior": approved[hid].behavior,
                    "data_source": approved[hid].evidence.data_source,
                    "event_ids": approved[hid].evidence.event_ids} for hid in source_ids]
        sec = prompt["sections"]
        user = fill(sec["USER"], report_id=contract_a.report_id, pivot_kind=kind, pivot_value=value,
                    source_hypotheses=json.dumps(context, ensure_ascii=False, indent=2),
                    techniques=s4_hypothesis.render_inputs(allowed),
                    executed_hypotheses=s4_hypothesis.render_anchors(anchors or []))
        api_events, record = providers.event_recorder()
        try:
            batch_model = s4_hypothesis.output_model(cfg)
            data = llm.complete_json(sec["SYSTEM"], user, batch_model.model_json_schema(),
                                     log=record)
        except BudgetExhausted as e:
            # Chưa gửi yêu cầu cho thực thể này. Chưa có giả thuyết nào thì báo lên graph dừng lượt;
            # đã có thì giữ các giả thuyết đã trả tiền để duyệt, ghi các thực thể bị bỏ.
            if not out:
                raise
            done = {(x["loai"], x["gia_tri"]) for x in logs}
            logs.extend({"loai": q["loai"], "gia_tri": str(q["gia_tri"]),
                         "ly_do_bo": f"hết ngân sách API cục bộ: {e}"}
                        for q in selected if (q["loai"], str(q["gia_tri"])) not in done)
            break
        except providers.RefusalError as e:
            # Đã gửi và đã tính tiền; không gọi lại. Thực thể này không có giả thuyết, các thực thể khác vẫn chạy.
            all_events.extend(api_events)
            if run_dir:
                run_dir.mkdir(parents=True, exist_ok=True)
                with open(run_dir / "pivot_requests.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"pivot": {"loai": kind, "gia_tri": value}, "system": sec["SYSTEM"],
                                        "user": user, "response_raw": None, "tu_choi": str(e),
                                        "api_events": api_events}, ensure_ascii=False) + "\n")
            logs.append({"loai": kind, "gia_tri": value, "tu_gia_thuyet": source_ids,
                         "ly_do_bo": f"mô hình từ chối, không gọi lại: {e}"})
            continue
        all_events.extend(api_events)
        if run_dir:
            run_dir.mkdir(parents=True, exist_ok=True)
            with open(run_dir / "pivot_requests.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps({"pivot": {"loai": kind, "gia_tri": value}, "system": sec["SYSTEM"],
                                    "user": user, "response_raw": data, "api_events": api_events},
                                   ensure_ascii=False) + "\n")
        try:
            items = batch_model.model_validate(data).items
            parse_errors = 0
        except ValidationError:
            items, parse_errors = [], 1
        hyps, fixes = s4_hypothesis.postprocess(
            items, allowed, contract_a.report_id, max_items=1, attack_catalog=attack_catalog,
            origin="pivot", pivot_depth=depth, start_index=next_index,
            pivot_kind=kind, pivot_value=value, anchors=anchors)
        for h in hyps:
            h.scope = f"{h.scope}; pivot {kind}={value} (ràng buộc khi thực thi)"
        out.extend(hyps)
        next_index += len(hyps)
        logs.append({"loai": kind, "gia_tri": value, "tu_gia_thuyet": source_ids,
                     "so_muc_tho": len(items), "so_gia_thuyet": len(hyps),
                     "ma_sua": {**dict(fixes), **({"dau_ra_sai_luoc_do": parse_errors} if parse_errors else {})}})
    return {"hypotheses": out, "log": {"so_pivot": len(selected), "so_gia_thuyet": len(out),
                                        "chi_tiet": logs, "prompt": prompt["path"],
                                        "prompt_sha256": prompt["sha256"],
                                        "model": getattr(llm, "model_id", "?"),
                                        "token": providers.token_totals(all_events)}}


# Kênh → khóa đứng trước dấu "=" trong Message mang tài khoản thao tác (định dạng bản tin Windows, không theo bộ dữ liệu):
# WMI-Activity 5858 ghi "User = MIỀN\tên", 5860 ghi "UserName = MIỀN\tên". 5857 không có; 5861 chỉ có CreatorSID.
MESSAGE_ACCOUNT_KEYS = {"microsoft-windows-wmi-activity/operational": ("User", "UserName")}


def bind_spec(spec: dict, hypothesis: ContractB, columns: set[str] | None, *, for_execution: bool = True) -> dict:
    """Ràng buộc pivot vào WHERE/scope; gọi trước EXPLAIN và trước ghi hunt spec."""
    if hypothesis.origin != "pivot":
        return spec
    if not hypothesis.pivot_kind or not hypothesis.pivot_value:
        raise PivotError("giả thuyết pivot thiếu thực thể")
    out = {**spec, "scope": dict(spec["scope"])}
    value = hypothesis.pivot_value
    if hypothesis.pivot_kind == "may":
        host = value.upper()
        prior = out["scope"].get("hosts") or []
        if prior and host not in {str(h).upper() for h in prior}:
            raise PivotError("máy pivot nằm ngoài phạm vi hunt")
        out["scope"]["hosts"] = [host]
    else:
        names = {c.lower(): c for c in (columns or set(hypothesis.evidence.key_fields))}
        account_fields = [names[c.lower()] for c in s8_triage.ACCOUNT_COLUMNS if c.lower() in names]
        if not account_fields:
            raise PivotError("nguồn log không có cột tài khoản để ràng buộc pivot")
        escaped = value.lower().replace("'", "''")
        parts = []
        for c in account_fields:
            quoted = c.replace('"', '""')
            parts.append(f"lower(trim(split_part(split_part(coalesce(\"{quoted}\", ''), chr(92), -1), '@', 1))) = '{escaped}'")
        # H7 (12/10): kênh ghi tài khoản thao tác trong Message chứ không ở cột. Thiếu vế này thì pivot tài khoản trên
        # WMI-Activity so tên người dùng với tài khoản dịch vụ đã ghi bản ghi (SYSTEM…) và luôn ra 0.
        message_keys = MESSAGE_ACCOUNT_KEYS.get(str(out["scope"].get("channel") or "").lower(), ())
        if message_keys and "message" in names:
            pattern = (rf"(?i)(?:^|;\s*)(?:{'|'.join(message_keys)})\s*=\s*(?:[^;\\]*\\)?"
                       rf"{re.escape(value.lower())}(?:@[^;]*)?\s*(?:;|$)").replace("'", "''")
            quoted = names["message"].replace('"', '""')
            parts.append(f"regexp_matches(coalesce(\"{quoted}\", ''), '{pattern}')")
        else:
            message_keys = ()
        out["candidates"] = f"({spec['candidates']}) AND ({' OR '.join(parts)})"
        if out.get("filter_policy"):
            from copy import deepcopy
            out["sigma_context"] = deepcopy(spec["sigma_context"])
            out["sigma_context"]["account_binding"] = {"fields": account_fields, "value": value.lower(),
                                                       **({"message_keys": list(message_keys)} if message_keys else {})}
    runner.validate(out, for_execution=for_execution)
    return out
