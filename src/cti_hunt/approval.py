"""Điểm dừng phê duyệt ◆ giữa khâu ④ và ⑤ (v3 §3.3, §4.1). Mọi vòng pivot cũng đi qua đây.

Cơ chế bằng tệp, không cần tiến trình chạy liên tục:
1. `write_review` ghi hypotheses.json (Contract B, status pending_review) và phiếu duyet.yaml.
2. Người duyệt điền phiếu: nguoi_duyet, và với từng giả thuyết quyet_dinh = approved | rejected (+ ly_do).
3. `apply_review` kiểm phiếu, ghi hypotheses_da_duyet.json và approval_log.json.
4. Khâu ⑤ chỉ nhận giả thuyết approved (`require_approved`).

Phiếu gắn với đúng nội dung được duyệt qua SHA256 của hypotheses.json: nội dung đổi sau khi phát phiếu thì phiếu
bị từ chối. Giả thuyết không có quyết định vẫn là pending_review và không đi tiếp.
Người duyệt không sửa nội dung giả thuyết; muốn khác thì từ chối kèm lý do, và giả thuyết mới đi lại từ khâu ④.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import yaml

from .contracts import ContractB
from .stages.execution_semantics import issues as execution_issues
from .stages.hypothesis_grounding import warnings as grounding_warnings

HYP_FILE, REVIEW_FILE = "hypotheses.json", "duyet.yaml"
APPROVED_FILE, LOG_FILE = "hypotheses_da_duyet.json", "approval_log.json"
DECISIONS = ("approved", "rejected")
REVIEW_POLICY = "G0-d-v1"

_HEADER = """# Phiếu duyệt giả thuyết — điểm dừng ◆ (v3 §4.1). Điền rồi chạy: python -m cti_hunt approve {run_dir}
#   nguoi_duyet : bắt buộc nếu có ít nhất một quyết định
#   quyet_dinh  : approved | rejected   (để trống = chưa duyệt, giả thuyết không đi tiếp sang khâu ⑤)
#   ly_do       : bắt buộc khi rejected
# Không sửa các trường khác. Phiếu gắn với hypotheses_sha256; giả thuyết đổi thì phải phát phiếu mới.
# Quy tắc G0(d): docs/METHODOLOGY.md — áp dụng cho cả vòng gốc và pivot.
# Kiểm đủ hành vi/phạm vi/thời gian/bằng chứng, danh mục hiệu lực, câu nguồn, không trùng trong lượt.
# Không duyệt/từ chối theo nhãn, đáp án kịch bản hoặc dự đoán số kết quả. Người duyệt tự điền quyết định.
# canh_bao_thieu_can_cu: chuỗi kỹ thuật (tệp, đường dẫn, cờ lệnh, lớp WMI, cmdlet, cổng) trong hành vi/phạm vi chưa
#   thấy ở câu nguồn hay ghi chú danh mục nguồn log. Chỉ để rà, không tự chặn; rỗng không chứng minh đúng nguồn.
"""


class ReviewError(ValueError):
    pass


class NotApprovedError(PermissionError):
    pass


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_hypotheses(path: Path) -> list[ContractB]:
    return [ContractB.model_validate(h) for h in json.loads(path.read_text(encoding="utf-8"))]


def write_review(hyps: list[ContractB], run_dir: Path, *, telemetry: dict | None = None) -> Path:
    """`telemetry` (danh mục ③ hiệu lực của lượt) chỉ dùng cho cảnh báo H5 trên phiếu; hypotheses.json không phụ thuộc."""
    run_dir.mkdir(parents=True, exist_ok=True)
    hp = run_dir / HYP_FILE
    hp.write_text(json.dumps([h.model_dump(mode='json') for h in hyps], ensure_ascii=False, indent=2), encoding="utf-8")
    form = {
        "hypotheses_sha256": _sha(hp),
        "quy_tac_duyet": REVIEW_POLICY,
        "nguoi_duyet": "",
        "gia_thuyet": [{
            "id": h.hypothesis_id,
            "hanh_vi": h.behavior,
            "pham_vi": h.scope,
            "thoi_gian": h.timeframe,
            "cua_so_thuc_thi_utc": h.execution_window.model_dump(mode='json') if h.execution_window else None,
            "phep_toan_yeu_cau": h.required_operations,
            "loi_kha_nang_thuc_thi": execution_issues(h),
            "canh_bao_thieu_can_cu": grounding_warnings(h, telemetry),
            **({"rang_buoc": h.rang_buoc.model_dump(mode="json", exclude_none=True)} if h.rang_buoc else {}),
            "bang_chung": f"{h.evidence.data_source} · EID {h.evidence.event_ids} · {', '.join(h.evidence.key_fields)}",
            "ttp": h.linked_ttps,
            "nguon": [s.segment_id or s.text[:80] for s in h.source_spans],
            "nguon_chi_tiet": [s.model_dump() for s in h.source_spans],
            "quyet_dinh": "",
            "ly_do": "",
        } for h in hyps],
    }
    rp = run_dir / REVIEW_FILE
    rp.write_text(_HEADER.format(run_dir=run_dir.as_posix())
                  + yaml.safe_dump(form, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")
    return rp


def apply_review(run_dir: Path) -> dict:
    hp, rp = run_dir / HYP_FILE, run_dir / REVIEW_FILE
    form = yaml.safe_load(rp.read_text(encoding="utf-8")) or {}
    if form.get("hypotheses_sha256") != _sha(hp):
        raise ReviewError(f"{HYP_FILE} đã đổi sau khi phát phiếu duyệt — phiếu không còn khớp nội dung")
    hyps = {h.hypothesis_id: h for h in load_hypotheses(hp)}
    errors, decided = [], {}
    for row in form.get("gia_thuyet") or []:
        hid, d = row.get("id"), row.get("quyet_dinh")
        if hid not in hyps:
            errors.append(f"{hid}: không có trong {HYP_FILE}")
            continue
        if isinstance(d, bool):         # YAML đọc yes/no/on thành boolean
            errors.append(f"{hid}: quyet_dinh phải là chữ approved hoặc rejected, không phải yes/no")
            continue
        d = (d or "").strip().lower()
        if not d:
            continue
        if d not in DECISIONS:
            errors.append(f"{hid}: quyet_dinh '{d}' không hợp lệ ({' | '.join(DECISIONS)})")
        elif d == "rejected" and not str(row.get("ly_do") or "").strip():
            errors.append(f"{hid}: từ chối phải có ly_do")
        else:
            decided[hid] = (d, str(row.get("ly_do") or "").strip())
    reviewer = str(form.get("nguoi_duyet") or "").strip()
    if decided and not reviewer:
        errors.append("thiếu nguoi_duyet")
    if errors:
        raise ReviewError("Phiếu duyệt chưa hợp lệ:\n  " + "\n  ".join(errors))

    out = []
    for hid, h in hyps.items():
        if hid in decided:
            h = h.model_copy(update={"status": decided[hid][0]})
        out.append(h)
    (run_dir / APPROVED_FILE).write_text(json.dumps([h.model_dump(mode='json') for h in out], ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    counts = {s: sum(1 for h in out if h.status == s) for s in ("approved", "rejected", "pending_review")}
    log = {"nguoi_duyet": reviewer, "thoi_diem": datetime.now().isoformat(timespec="seconds"),
           "quy_tac_duyet": form.get("quy_tac_duyet"),
           "hypotheses_sha256": form["hypotheses_sha256"], "phieu_sha256": _sha(rp), "dem": counts,
           "quyet_dinh": {hid: {"quyet_dinh": d, "ly_do": ly} for hid, (d, ly) in decided.items()}}
    (run_dir / LOG_FILE).write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
    return log


def require_approved(h: ContractB) -> None:
    if h.status != "approved":
        raise NotApprovedError(f"{h.hypothesis_id} đang ở trạng thái {h.status}: chỉ giả thuyết đã duyệt mới sang khâu ⑤")


def verify_saved_review(run_dir: Path) -> None:
    """Read-only verification before v2 prepares rules; do not reapply/rewrite decisions."""
    form = yaml.safe_load((run_dir / REVIEW_FILE).read_text(encoding="utf-8"))
    log = json.loads((run_dir / LOG_FILE).read_text(encoding="utf-8"))
    if (log.get("hypotheses_sha256") != _sha(run_dir / HYP_FILE) or
            log.get("phieu_sha256") != _sha(run_dir / REVIEW_FILE) or
            form.get("hypotheses_sha256") != log.get("hypotheses_sha256")):
        raise ReviewError("phiếu/log/giả thuyết đã duyệt không còn khớp")
    hyps = load_hypotheses(run_dir / HYP_FILE)
    saved = load_hypotheses(run_dir / APPROVED_FILE)
    choices = log.get("quyet_dinh") or {}
    rows = form.get("gia_thuyet") or []
    ids = [r.get("id") for r in rows]
    if (len(ids) != len(set(ids)) or set(ids) != {h.hypothesis_id for h in hyps} or
            log.get("nguoi_duyet") != form.get("nguoi_duyet") or not set(choices) <= set(ids)):
        raise ReviewError("ID/người duyệt không khớp phiếu giả thuyết")
    for r in rows:
        decision = str(r.get("quyet_dinh") or "").strip().lower()
        expected = {"quyet_dinh": decision, "ly_do": str(r.get("ly_do") or "").strip()}
        if decision and choices.get(r["id"]) != expected:
            raise ReviewError("quyết định phiếu/log giả thuyết không khớp")
    expected_hyps = [h.model_copy(update={"status": choices.get(h.hypothesis_id, {}).get("quyet_dinh", "pending_review")})
                     for h in hyps]
    if [h.model_dump() for h in saved] != [h.model_dump() for h in expected_hyps]:
        raise ReviewError("approved khác nội dung giả thuyết đã duyệt")


def save_decisions(run_dir: Path, reviewer: str, decisions: dict[str, dict], expected_form_sha256: str) -> None:
    """Save explicit UI decisions; graph still applies the review at its interrupt.

    Compare the displayed form hash to prevent applying stale widgets to a new
    hypothesis/round. Validation happens before any write; no implicit approval.
    """
    path = run_dir / REVIEW_FILE
    if _sha(path) != expected_form_sha256:
        raise ReviewError("Phiếu đã thay đổi; tải lại trước khi duyệt")
    form = yaml.safe_load(path.read_text(encoding="utf-8"))
    if form["hypotheses_sha256"] != _sha(run_dir / HYP_FILE):
        raise ReviewError("Giả thuyết đã đổi sau khi phát phiếu")
    known = {h.hypothesis_id for h in load_hypotheses(run_dir / HYP_FILE)}
    ids = [row["id"] for row in form["gia_thuyet"]]
    if set(ids) != known or len(ids) != len(known):
        raise ReviewError("Danh sách giả thuyết trong phiếu bị thiếu, thừa hoặc trùng")
    if not set(decisions) <= known:
        raise ReviewError("Quyết định chứa mã giả thuyết không thuộc phiếu")
    for row in form["gia_thuyet"]:
        choice = decisions.get(row["id"], {})
        decision, note = choice.get("quyet_dinh", ""), choice.get("ly_do", "")
        if decision not in ("", *DECISIONS) or not isinstance(note, str):
            raise ReviewError("Quyết định/lý do không hợp lệ")
        if decision and not reviewer.strip():
            raise ReviewError("Cần tên người duyệt")
        if decision == "rejected" and not note.strip():
            raise ReviewError("Từ chối cần lý do")
        row.update(quyet_dinh=decision, ly_do=note.strip())
    form["nguoi_duyet"] = reviewer.strip()
    import uuid
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temp.write_text(_HEADER.format(run_dir=run_dir.as_posix())
                        + yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)
