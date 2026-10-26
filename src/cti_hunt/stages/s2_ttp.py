"""Khâu ② — nhánh TTP + bối cảnh bằng mô hình ngôn ngữ, đầu ra ép lược đồ Contract A (v3 §4.2, §4.5).

Mô hình chỉ làm phần cần đọc hiểu. Mọi thứ kiểm tra được bằng mã đều do mã làm sau đó (v3 §4.4, §7):

    mã kỹ thuật      tra danh mục ATT&CK v19.2; mã bị thu hồi thì quy đổi, mã không tồn tại thì loại
    technique_name   ghi đè theo tên ở v19.2 (R14), không lấy tên mô hình tự đặt
    tactic           phải thuộc danh sách tactic của v19
    quote            phải xuất hiện nguyên văn trong đoạn, nếu không thì xóa và ghi log
    command_example  phải xuất hiện nguyên văn trong đoạn, nếu không thì để trống (v3 §7 bối cảnh bị bịa)
    đoạn tiêu đề     bỏ (R9); trùng cặp (đoạn, kỹ thuật) thì giữ một (R1)

Mỗi lần chạy ghi lại đủ để chạy lại: hash prompt, tên mô hình, tham số, đầu vào, đầu ra thô, số lần
mã sửa từng loại. Con số chính thức ngày 29/9 là prompt v1 chạy một lần.

v2 bật bằng `V2Options`: khối ứng viên ATT&CK lấy theo từng đoạn rồi gộp, và một
lượt kiểm mỗi lô (giu | sua_ma | bo). Không truyền `V2Options` thì chạy đúng v1.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field, ValidationError

from ..attack.catalog import AttackCatalog, tactic_key
from ..contracts import ContractA, SourceSpan, TTP, TTPContext
from ..llm import providers
from ..integrity import require_frozen

HEADING = "tiêu đề"
UNKNOWN = "khong_ro"


class LLMClient(Protocol):
    model_id: str

    def complete_json(self, system: str, user: str, json_schema: dict) -> dict: ...


class ExtractedContext(BaseModel):
    tool: str = ""
    execution_path: str = ""
    source_role: str = ""
    target_role: str = ""
    account_type: str = ""
    preceded_by: list[str] = Field(default_factory=list)
    command_example: str = ""


class ExtractedTTP(BaseModel):
    segment_id: str
    tactic: str = ""
    technique_id: str
    technique_name: str = ""
    behavior_description: str = ""
    quote: str = ""
    context: ExtractedContext = Field(default_factory=ExtractedContext)
    confidence: float = 0.5
    note: str = ""


class ExtractionBatch(BaseModel):
    items: list[ExtractedTTP] = Field(default_factory=list)


class VerifyDecision(BaseModel):
    index: int
    quyet_dinh: Literal["giu", "sua_ma", "bo"]
    ma_moi: str = ""
    ly_do: str = ""


class VerifyBatch(BaseModel):
    decisions: list[VerifyDecision] = Field(default_factory=list)


@dataclass
class V2Options:
    """Khâu ② v2: chỉ mục BM25 (định nghĩa + procedure example đã loại trừ), prompt lượt kiểm, mô tả đầy đủ."""
    index: Any
    verify_prompt: dict
    descriptions: dict[str, str]
    per_segment: int = 2
    desc_chars: int = 300

    def describe(self) -> dict:
        return {"index_stix_sha256": self.index.source_sha256,
                "procedure_ids_sha256": getattr(self.index, "procedure_ids_sha256", ""),
                "so_cau_vi_du": getattr(self.index, "example_count", 0), "ung_vien_moi_doan": self.per_segment,
                "ky_tu_mo_ta": self.desc_chars, "prompt_kiem": self.verify_prompt["path"],
                "prompt_kiem_sha256": self.verify_prompt["sha256"]}


def load_prompt(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"^## (SYSTEM|USER)\s*$", text, flags=re.M)
    if len(parts) < 5:
        raise ValueError(f"{path} phải có mục '## SYSTEM' và '## USER'")
    sections = {parts[i]: parts[i + 1].strip() for i in (1, 3)}
    return {"system": sections["SYSTEM"], "user": sections["USER"],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "path": path.as_posix()}


def _segment_blocks(segments: list[dict]) -> str:
    return "\n\n".join(
        f"<segment id=\"{s['ma_doan']}\" loai=\"{s.get('loai', '')}\">\n{s.get('van_ban', '')}\n</segment>"
        for s in segments)


def _fill(template: str, values: dict[str, str]) -> str:
    """Điền một lượt: chữ vừa chèn (report, ứng viên) không bị thay tiếp."""
    return re.sub(r"\{(" + "|".join(values) + r")\}", lambda m: values[m.group(1)], template)


def render_batch(prompt: dict, report_id: str, segments: list[dict], candidates: str | None = None) -> str:
    blocks = _segment_blocks(segments)
    if "{candidates}" not in prompt["user"]:               # v1: giữ đúng cách điền cũ
        if candidates is not None:
            raise ValueError("Prompt này không có chỗ cho khối ứng viên")
        return prompt["user"].replace("{report_id}", report_id).replace("{segments}", blocks)
    if candidates is None:
        raise ValueError("Prompt v2 cần khối ứng viên")
    return _fill(prompt["user"], {"report_id": report_id, "segments": blocks, "candidates": candidates})


def candidates_for_batch(index, segments: list[dict], per_segment: int = 2) -> list[dict]:
    """Mỗi đoạn (trừ tiêu đề) lấy `per_segment` ứng viên BM25, gộp theo thứ tự xuất hiện, không trùng."""
    seen, out = set(), []
    for s in segments:
        if s.get("loai") == HEADING or not (s.get("van_ban") or "").strip():
            continue
        for d in index.search(s["van_ban"], per_segment):
            if d["technique_id"] not in seen:
                seen.add(d["technique_id"])
                out.append(d)
    return out


def _short(text: str, chars: int) -> str:
    """Mô tả ATT&CK rút gọn: bỏ link/mã của kỹ thuật khác và thẻ HTML (chỉ để mồi ngữ nghĩa, không mồi mã)."""
    from ..attack.procedures import clean_text
    text = clean_text(text or "")[0]
    if len(text) <= chars:
        return text
    cut = text[:chars].rsplit(" ", 1)[0]
    return cut + " …"


def render_candidates(candidates: list[dict], chars: int = 300) -> str:
    if not candidates:
        return "(none)"
    return "\n".join(f"- {d['technique_id']} | {d['name']} | {_short(d['description'], chars)}" for d in candidates)


def render_verify(prompt: dict, report_id: str, segments: list[dict], items: list[ExtractedTTP],
                  descriptions: dict[str, str]) -> str:
    lines = "\n".join(json.dumps({"index": i, "segment_id": it.segment_id, "technique_id": it.technique_id,
                                  "quote": it.quote, "behavior_description": it.behavior_description},
                                 ensure_ascii=False) for i, it in enumerate(items))
    tids = sorted({it.technique_id.strip().upper() for it in items})
    desc = "\n\n".join(f"{t}: {_short(descriptions.get(t, '(không có trong ATT&CK v19.2)'), 2400)}" for t in tids)
    return _fill(prompt["user"], {"report_id": report_id, "segments": _segment_blocks(segments),
                                  "items": lines, "descriptions": desc})


def apply_verify(items: list[ExtractedTTP], decisions: list[VerifyDecision]) -> tuple[list[ExtractedTTP], Counter]:
    """Áp quyết định lượt kiểm. Thiếu quyết định cho một mục thì giữ mục đó và đếm, không đoán."""
    log: Counter = Counter()
    by_index: dict[int, VerifyDecision] = {}
    for d in decisions:
        if not 0 <= d.index < len(items):
            log["kiem_index_la"] += 1
        elif d.index in by_index:
            log["kiem_trung_index"] += 1
        else:
            by_index[d.index] = d
    out = []
    for i, it in enumerate(items):
        d = by_index.get(i)
        if d is None:
            log["kiem_thieu_quyet_dinh"] += 1
            out.append(it)
        elif d.quyet_dinh == "bo":
            log["kiem_bo"] += 1
        elif d.quyet_dinh == "sua_ma" and d.ma_moi.strip():
            log["kiem_sua_ma"] += 1
            note = f"lượt kiểm đổi mã từ {it.technique_id}: {d.ly_do}".strip()
            out.append(it.model_copy(update={"technique_id": d.ma_moi.strip().upper(),
                                             "note": f"{it.note} | {note}" if it.note else note}))
        else:
            log["kiem_sua_ma_thieu_ma" if d.quyet_dinh == "sua_ma" else "kiem_giu"] += 1
            out.append(it)
    return out, log


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def postprocess(items: list[ExtractedTTP], segments: dict[str, dict], catalog: AttackCatalog,
                drop_unquoted: bool = False) -> tuple[list[TTP], Counter]:
    log: Counter = Counter()
    tactics = {t.lower() for t in catalog.tactics.values()}
    out: dict[tuple[str, str], TTP] = {}
    for item in items:
        seg = segments.get(item.segment_id)
        if seg is None:
            log["segment_id_la"] += 1
            continue
        if seg.get("loai") == HEADING:
            log["doan_tieu_de"] += 1
            continue
        res = catalog.resolve(item.technique_id)
        if res.status == "unknown":
            log["ma_khong_ton_tai"] += 1
            continue
        if res.status == "revoked":
            log["ma_bi_thu_hoi"] += 1
        if res.status == "deprecated":
            log["ma_deprecated"] += 1
        tid = res.final or item.technique_id.strip().upper()
        if item.tactic.strip().lower() not in tactics:
            log["tactic_khong_hop_le"] += 1

        body = seg.get("van_ban", "")
        quote = item.quote
        if quote and _norm(quote) not in _norm(body):
            log["quote_khong_co_trong_doan"] += 1
            if drop_unquoted:
                continue
            quote = ""
        cmd = item.context.command_example
        if cmd and _norm(cmd) not in _norm(body):
            log["command_example_bi_bia"] += 1
            cmd = ""
        path = item.context.execution_path.strip().lower()
        if path not in ("local", "remote", UNKNOWN, ""):
            log["execution_path_khong_hop_le"] += 1
            path = ""
        preceded = []
        for p in item.context.preceded_by:
            r = catalog.resolve(p)
            if r.status in ("ok", "revoked") and r.final:
                preceded.append(r.final)
            else:
                log["preceded_by_khong_hop_le"] += 1

        ttp = TTP(
            tactic=item.tactic.strip(), technique_id=tid,
            technique_name=catalog.techniques[tid].name if tid in catalog.techniques else "",
            behavior_description=item.behavior_description,
            context=TTPContext(
                tool="" if item.context.tool.strip().lower() == UNKNOWN else item.context.tool.strip(),
                execution_path="" if path == UNKNOWN else path,
                source_role=item.context.source_role, target_role=item.context.target_role,
                account_type=item.context.account_type, preceded_by=preceded, command_example=cmd),
            source_span=SourceSpan(section=seg.get("loai", ""), page=0, text=quote,
                                   segment_id=item.segment_id),
            confidence=max(0.0, min(1.0, item.confidence)))
        key = (item.segment_id, tid)
        if key in out:                                    # R1: một cặp (đoạn, kỹ thuật) một dòng
            log["trung_cap_doan_ky_thuat"] += 1
            if ttp.confidence <= out[key].confidence:
                continue
        out[key] = ttp
    return list(out.values()), log


def doc_lo_da_co(run_dir: Path, key: str = "raw") -> dict[str, dict[int, dict]]:
    """Lô đã có kết quả dùng được trong responses.jsonl, theo report -> số lô -> đầu ra thô.

    Dùng khi chạy tiếp (`ttp --resume`) sau khi lần chạy dừng vì lỗi mạng: lô đã có kết quả
    KHÔNG BAO GIỜ được gọi lại (giao thức 29/9). `key="kiem_raw"` đọc kết quả lượt kiểm của v2.
    """
    out: dict[str, dict[int, dict]] = {}
    f = run_dir / "responses.jsonl"
    if not f.exists():
        return out
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        if d.get("loi") or key not in d:              # bản ghi của lần gọi hỏng hoặc của lượt khác
            continue
        out.setdefault(d["report"], {})[d["batch"]] = d[key]
    return out


def _call(llm: LLMClient, system: str, user: str, model, run_dir: Path | None, record: dict, key: str,
          su_co: dict, retry_key: str) -> tuple[Any, str]:
    """Một lời gọi theo giao thức 29/9: lô hỏng gọi lại tối đa một lần; refusal không gọi lại."""
    schema, parsed, ly_do = model.model_json_schema(), None, ""
    tag = {"report": record["report"], "lo": record["batch"]}       # cùng khóa sự cố với v1
    for lan in (1, 2):
        mang: list[dict] = []
        try:
            data = llm.complete_json(system, user, schema, log=mang.append)
            if run_dir:
                _append(run_dir / "responses.jsonl", {**record, "lan": lan, key: data})
            parsed = model.model_validate(data)
            break
        except providers.RefusalError as e:
            ly_do = f"refusal: {e}"
            break
        except (providers.BadOutputError, ValidationError) as e:
            ly_do = f"{type(e).__name__}: {e}"
            if lan == 1:
                su_co[retry_key].append({**tag, "ly_do": ly_do})
        finally:
            for m in mang:
                khoa = "stop_reason_theo_lo" if "stop_reason" in m else "lan_thu_mang"
                su_co[khoa].append({**tag, "lan": lan, "luot": key, **m})
            if run_dir and parsed is None and ly_do:
                _append(run_dir / "responses.jsonl", {**record, "lan": lan, "loi" if key == "raw" else "kiem_loi": ly_do})
    return parsed, ly_do


def extract_report(report_id: str, segments: list[dict], llm: LLMClient, catalog: AttackCatalog,
                   prompt: dict, batch_size: int = 8, run_dir: Path | None = None,
                   da_co: dict[int, dict] | None = None, v2: V2Options | None = None,
                   kiem_da_co: dict[int, dict] | None = None) -> tuple[list[TTP], dict]:
    """Chạy khâu ② cho một report.

    Xử lý sự cố theo giao thức 29/9:
    - Lô HỎNG (không có tool_use VÀ text không ra JSON hợp lệ theo lược đồ) → gọi lại **tối đa một lần**,
      y nguyên prompt và tham số; lần hai vẫn hỏng thì ghi thất bại. JSON hợp lệ nhưng ít/không có TTP
      KHÔNG phải lô hỏng, không gọi lại.
    - Mô hình từ chối (refusal) → thất bại ngay, không gọi lại.
    - Lỗi mạng → đã thử lại trong adapter; hết lượt thì ném ra ngoài để dừng cả lần chạy (resume được).
    """
    schema = ExtractionBatch.model_json_schema()
    by_id = {s["ma_doan"]: s for s in segments}
    raw_items: list[ExtractedTTP] = []
    log: Counter = Counter()
    su_co: dict[str, list] = {"lo_goi_lai": [], "lo_that_bai": [], "lan_thu_mang": [],
                              "stop_reason_theo_lo": []}
    if v2:
        su_co.update(kiem_goi_lai=[], kiem_that_bai=[])
    da_co = da_co or {}
    kiem_da_co = kiem_da_co or {}

    for i in range(0, len(segments), batch_size):
        so_lo = i // batch_size
        batch = segments[i:i + batch_size]
        ma_doan = [s["ma_doan"] for s in batch]
        candidates = candidates_for_batch(v2.index, batch, v2.per_segment) if v2 else []
        user = render_batch(prompt, report_id, batch,
                            render_candidates(candidates, v2.desc_chars) if v2 else None)

        if so_lo in da_co:                                # resume: không gọi lại lô đã có kết quả
            log["lo_dung_lai_tu_lan_truoc"] += 1
            try:
                items = ExtractionBatch.model_validate(da_co[so_lo]).items
            except ValidationError:
                log["batch_sai_luoc_do"] += 1
                continue
        else:
            if run_dir:
                _append(run_dir / "requests.jsonl", {"report": report_id, "batch": so_lo, "segment_ids": ma_doan,
                                                     "user": user, **({"ung_vien": [d["technique_id"] for d in candidates]}
                                                                      if v2 else {})})
            if v2 is None:                                # v1: đúng đường gọi cũ
                items, ly_do = None, ""
                for lan in (1, 2):                        # lần 2 chỉ dành cho lô hỏng
                    mang: list[dict] = []
                    try:
                        data = llm.complete_json(prompt["system"], user, schema, log=mang.append)
                        if run_dir:
                            _append(run_dir / "responses.jsonl", {"report": report_id, "batch": so_lo,
                                                                  "lan": lan, "raw": data})
                        items = ExtractionBatch.model_validate(data).items
                        break
                    except providers.RefusalError as e:   # không gọi lại, không đổi mô hình
                        ly_do = f"refusal: {e}"
                        break
                    except (providers.BadOutputError, ValidationError) as e:
                        ly_do = f"{type(e).__name__}: {e}"
                        if lan == 1:
                            su_co["lo_goi_lai"].append({"report": report_id, "lo": so_lo, "ly_do": ly_do})
                    finally:
                        for m in mang:
                            khoa = "stop_reason_theo_lo" if "stop_reason" in m else "lan_thu_mang"
                            su_co[khoa].append({"report": report_id, "lo": so_lo, "lan": lan, **m})
                        if run_dir and items is None and ly_do:
                            _append(run_dir / "responses.jsonl", {"report": report_id, "batch": so_lo,
                                                                  "lan": lan, "loi": ly_do})
            else:
                parsed, ly_do = _call(llm, prompt["system"], user, ExtractionBatch, run_dir,
                                      {"report": report_id, "batch": so_lo}, "raw", su_co, "lo_goi_lai")
                items = parsed.items if parsed is not None else None
            if items is None:
                log["lo_that_bai"] += 1
                su_co["lo_that_bai"].append({"report": report_id, "lo": so_lo, "segment_ids": ma_doan,
                                             "ly_do": ly_do})
                continue

        if v2 and items:                                  # lượt kiểm N3 §2.2
            if so_lo in kiem_da_co:
                log["kiem_dung_lai_tu_lan_truoc"] += 1
                verdict = VerifyBatch.model_validate(kiem_da_co[so_lo])
            else:
                vuser = render_verify(v2.verify_prompt, report_id, batch, items, v2.descriptions)
                verdict, vly_do = _call(llm, v2.verify_prompt["system"], vuser, VerifyBatch, run_dir,
                                        {"report": report_id, "batch": so_lo}, "kiem_raw", su_co, "kiem_goi_lai")
                if verdict is None:                       # giữ mục chưa kiểm, đếm riêng; không bỏ cả lô
                    log["kiem_that_bai"] += 1
                    su_co["kiem_that_bai"].append({"report": report_id, "lo": so_lo, "so_muc": len(items),
                                                   "ly_do": vly_do})
            if verdict is not None:
                items, vlog = apply_verify(items, verdict.decisions)
                log.update(vlog)
        raw_items += items

    ttps, plog = postprocess(raw_items, by_id, catalog)
    log.update(plog)
    return ttps, {"so_muc_tho": len(raw_items), "so_muc_giu": len(ttps), "ma_sua": dict(log),
                  "su_co": su_co}


def _append(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def build_contract_a(report_id: str, ttps: list[TTP], iocs: list | None = None, **meta) -> ContractA:
    return ContractA(report_id=report_id, ttps=ttps, iocs=list(iocs or []), **meta)


def pairs(ttps: list[TTP], report_id: str) -> set[tuple[str, str]]:
    """Khóa so khớp khi đo khâu ② (R9, R13): (report, technique_id)."""
    return {(report_id, t.technique_id) for t in ttps}


KHOA_CAU_HINH = ("prompt_sha256", "model", "batch_size", "segments_sha256")


def run_on_eval_set(segments_jsonl: Path, frozen_dir: Path, llm: LLMClient, catalog: AttackCatalog,
                    prompt: dict, batch_size: int = 8, run_dir: Path | None = None,
                    resume: bool = False, v2: V2Options | None = None) -> dict[str, dict]:
    """Chạy trên 3 report đánh giá. Chỉ được chạy sau khi bộ nhãn tham chiếu đã đóng băng.

    `resume=True`: chạy tiếp vào đúng run_dir cũ sau khi lần chạy dừng vì lỗi mạng. Lô đã có kết quả
    không bao giờ được gọi lại, và cấu hình phải trùng khít bản ghi trong meta.json (giao thức 29/9).
    """
    require_frozen(frozen_dir)
    by_report: dict[str, list[dict]] = {}
    with open(segments_jsonl, encoding="utf-8") as f:
        for line in f:
            seg = json.loads(line)
            by_report.setdefault(seg["report"], []).append(seg)

    meta = {
        "chay_luc": datetime.now().isoformat(timespec="seconds"),
        "prompt": prompt["path"], "prompt_sha256": prompt["sha256"],
        "model": getattr(llm, "model_id", "?"), "batch_size": batch_size,
        # tham số thực gửi lên API (kiểu API, effort, tool_choice…): đủ để chạy lại đúng lần này
        "cau_hinh_mo_hinh": llm.describe() if hasattr(llm, "describe") else {},
        "segments_jsonl": segments_jsonl.as_posix(),
        "segments_sha256": hashlib.sha256(segments_jsonl.read_bytes()).hexdigest(),
        "attack_version": catalog.version,
    }
    if v2:
        meta["v2"] = v2.describe()
    da_co: dict[str, dict[int, dict]] = {}
    kiem_da_co: dict[str, dict[int, dict]] = {}
    if run_dir:
        cu_path = run_dir / "meta.json"
        if resume:
            if not cu_path.exists():
                raise ValueError(f"Không có {cu_path} để chạy tiếp")
            cu = json.loads(cu_path.read_text(encoding="utf-8"))
            lech = [k for k in KHOA_CAU_HINH + ("v2",) if cu.get(k) != meta.get(k)]
            if lech:
                raise ValueError(f"Chạy tiếp phải đúng cấu hình của lần chạy cũ; lệch: {lech}")
            meta["chay_luc"] = cu["chay_luc"]
            meta["chay_tiep_luc"] = [*cu.get("chay_tiep_luc", []),
                                     datetime.now().isoformat(timespec="seconds")]
            da_co = doc_lo_da_co(run_dir)
            kiem_da_co = doc_lo_da_co(run_dir, "kiem_raw")
        run_dir.mkdir(parents=True, exist_ok=True)
        # Ghi meta TRƯỚC khi gọi API: dừng giữa chừng vẫn còn đủ cấu hình để chạy tiếp.
        cu_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    result = {}
    for report_id, segs in sorted(by_report.items()):
        ttps, log = extract_report(report_id, segs, llm, catalog, prompt, batch_size, run_dir,
                                   da_co=da_co.get(report_id), v2=v2, kiem_da_co=kiem_da_co.get(report_id))
        result[report_id] = {"ttps": ttps, "log": log}
        if run_dir:
            (run_dir / f"contract_a_{report_id}.json").write_text(
                build_contract_a(report_id, ttps).model_dump_json(indent=2), encoding="utf-8")
    if run_dir:
        meta["xong_luc"] = datetime.now().isoformat(timespec="seconds")
        meta["log"] = {r: v["log"] for r, v in result.items()}
        (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
