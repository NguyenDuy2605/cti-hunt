"""Kiểm hình thức đề xuất duyệt của agent trước khi đưa người vận hành (giao thức `docs/METHODOLOGY.md` §4).

Chỉ đọc. Không gọi API, không ghi phiếu, không đọc nhãn hay kết quả hunt. Đề xuất chỉ được `rejected` qua một kiểm tra
của bảng quy tắc không đạt: ◆ theo G0(d) (`docs/METHODOLOGY.md` §3), phiếu lọc theo §6.2 của
`docs/METHODOLOGY.md`. Lý do ngoài bảng (độ rộng của giả thuyết, số kết quả dự kiến,
khả năng bắt bước) không có chỗ trong cấu trúc này. Từ khóa đáng ngờ chỉ là cảnh báo để agent đọc lại, không tự quyết.

Phiếu đã có quyết định của người vận hành thì in thêm bảng đề xuất ↔ quyết định (để báo cáo, không phải để chấm người vận hành).

    .venv/Scripts/python.exe -X utf8 scripts/kiem_de_xuat_duyet.py <de_xuat.yaml> <duyet.yaml | duyet_loc.yaml>
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# kiểm tra → mã lý do từ chối được phép
GIA_THUYET = {"quy_tac": "G0-d-v1", "hash": "hypotheses_sha256", "muc": "gia_thuyet",
              "kiem_tra": {"bon_thanh_phan": {"thieu_thanh_phan"}, "nguon_log": {"nguon_khong_phu_hop"},
                           "cau_nguon": {"khong_bam_nguon"}, "khong_trung": {"trung_gia_thuyet"}},
              "canh_bao": ("rộng", "toàn bộ https", "số kết quả", "nhiều kết quả", "0 kết quả", "ứng viên", "nhãn",
                           "bước tấn công", "emulation", "đáp án", "bắt được")}
# Trách nhiệm/hiệu lực do người duyệt tự điền khi approved, agent không đánh giá thay.
LOC = {"quy_tac": "duyet_loc_khau5_v2", "hash": "manifest_sha256", "muc": "muc_loc",
       "kiem_tra": {"logic": {"logic_khong_ro"}, "lanh_tinh": {"thieu_can_cu_lanh_tinh"},
                    "mau_pham_vi": {"pham_vi_qua_rong", "thieu_truong_phan_biet"},
                    "xung_dot": {"xung_dot_hanh_vi_san"}},
       "canh_bao": ("nhãn", "bước tấn công", "emulation", "đáp án", "bắt được")}
DE_XUAT = ("approved", "rejected")
MA_GIA_THUYET = re.compile(r"\b[A-Z]{2,}-H\d+\b")


def _load(path: Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: không phải ánh xạ YAML")
    return data


def kind_of(form: dict) -> dict:
    if "gia_thuyet" in form:
        return GIA_THUYET
    if "muc_loc" in form:
        return LOC
    raise ValueError("phiếu không có `gia_thuyet` hay `muc_loc`")


def check(proposal: dict, form: dict) -> tuple[list[str], list[str]]:
    """Trả (lỗi, cảnh báo). Lỗi = đề xuất không được đưa người vận hành."""
    k = kind_of(form)
    errors, warnings = [], []
    if proposal.get("quy_tac") != k["quy_tac"] or proposal.get("quy_tac") != form.get("quy_tac_duyet"):
        errors.append(f"quy_tac phải là {k['quy_tac']} và khớp phiếu ({form.get('quy_tac_duyet')})")
    if proposal.get(k["hash"]) != form.get(k["hash"]):
        errors.append(f"{k['hash']} không khớp phiếu: đề xuất cho nội dung khác")
    form_ids = [m["id"] for m in form.get(k["muc"]) or []]
    items = proposal.get("muc") or []
    ids = [m.get("id") for m in items]
    if sorted(ids) != sorted(form_ids) or len(set(ids)) != len(ids):
        errors.append(f"tập mục khác phiếu: thiếu {sorted(set(form_ids) - set(ids))}, "
                      f"thừa {sorted(set(ids) - set(form_ids))}, lặp {sorted({i for i in ids if ids.count(i) > 1})}")
    for item in items:
        errors += [f"{item.get('id')}: {e}" for e in _check_item(item, k, warnings)]
    return errors, warnings


def _check_item(item: dict, k: dict, warnings: list[str]) -> list[str]:
    errors, checks = [], item.get("kiem_tra")
    if not isinstance(checks, dict) or set(checks) != set(k["kiem_tra"]):
        return [f"kiem_tra phải có đúng {sorted(k['kiem_tra'])}"]
    failed = []
    for name, value in checks.items():
        if not isinstance(value, dict) or type(value.get("dat")) is not bool \
                or not str(value.get("can_cu") or "").strip():
            errors.append(f"{name}: cần `dat` true/false và `can_cu` không rỗng")
        elif not value["dat"]:
            failed.append(name)
    if errors:
        return errors
    decision, codes = item.get("de_xuat"), item.get("ma_ly_do") or []
    codes = [codes] if isinstance(codes, str) else codes
    if decision not in DE_XUAT:
        return [f"de_xuat phải là {'/'.join(DE_XUAT)}"]
    if decision == "approved":
        if failed:
            errors.append(f"approved nhưng kiểm tra không đạt: {failed}")
        if codes:
            errors.append("approved không mang ma_ly_do")
        return errors
    if not failed:
        errors.append("rejected nhưng cả bốn kiểm tra đều đạt: lý do nằm ngoài bảng quy tắc")
    allowed = {c for name in failed for c in k["kiem_tra"][name]}
    if not codes or not set(codes) <= allowed:
        errors.append(f"ma_ly_do {codes} phải thuộc mã của kiểm tra không đạt {sorted(allowed)}")
    if "trung_gia_thuyet" in codes and not MA_GIA_THUYET.search(checks["khong_trung"]["can_cu"]):
        errors.append("trung_gia_thuyet phải ghi ID bản được giữ")
    for name in failed:
        text = checks[name]["can_cu"].lower()
        hits = [w for w in k["canh_bao"] if w in text]
        if hits:
            warnings.append(f"{item['id']}: {name} có từ cần đọc lại {hits}")
    return errors


def compare(proposal: dict, form: dict) -> list[tuple[str, str, str]]:
    """(id, đề xuất, quyết định người vận hành) cho các mục người vận hành đã điền."""
    k = kind_of(form)
    decided = {m["id"]: m.get("quyet_dinh") for m in form.get(k["muc"]) or [] if m.get("quyet_dinh")}
    return [(m["id"], m["de_xuat"], decided[m["id"]]) for m in proposal.get("muc") or [] if m.get("id") in decided]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("de_xuat", type=Path)
    parser.add_argument("phieu", type=Path)
    args = parser.parse_args(argv)
    proposal, form = _load(args.de_xuat), _load(args.phieu)
    errors, warnings = check(proposal, form)
    for w in warnings:
        print("CẢNH BÁO", w)
    for e in errors:
        print("LỖI", e)
    rows = compare(proposal, form)
    if rows:
        same = sum(1 for _, a, b in rows if a == b)
        print(f"Đề xuất ↔ quyết định người vận hành: {same}/{len(rows)} giống")
        for i, a, b in rows:
            if a != b:
                print(f"  khác {i}: đề xuất {a}, người vận hành {b}")
    print("ĐẠT" if not errors else f"KHÔNG ĐẠT: {len(errors)} lỗi")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
