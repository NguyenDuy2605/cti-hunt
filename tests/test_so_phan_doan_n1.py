"""Bốn chỉ số so phân đoạn N1 §5.1 trên văn bản tự soạn."""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/so_phan_doan_n1.py"
spec = importlib.util.spec_from_file_location("so_phan_doan_n1", SCRIPT)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def seg(ma, loai, text, report="XX"):
    return {"ma_doan": ma, "report": report, "loai": loai, "van_ban": text}


OLD = [seg("XX-001", "tiêu đề", "Attack overview"),
       seg("XX-002", "đoạn văn", "The actor used rundll32 to run the payload , then moved laterally."),
       seg("XX-003", "mã/truy vấn", "DeviceProcessEvents | where FileName =~ \"rundll32.exe\""),
       seg("XX-004", "ảnh", "[ẢNH] fig1.png")]
NEW = [seg("N-001", "đoạn văn", "Share"),
       seg("N-002", "tiêu đề", "Attack overview"),
       seg("N-003", "đoạn văn", "The actor used rundll32 to run the payload, then moved laterally."),
       seg("N-004", "dòng bảng", "DeviceProcessEvents | where FileName =~ \"rundll32.exe\""),
       seg("N-005", "ảnh", "[CHƯA ĐỌC img] fig1.png"),
       seg("N-006", "ảnh", "[CHƯA ĐỌC img] fig1.png")]


def test_whitespace_only_difference_is_covered_and_matched():
    r = S.compare(OLD, NEW)
    assert r["do_phu_van_ban"] == 1.0                     # chỉ lệch dấu cách trước dấu phẩy
    assert r["khop_doan"] == [3, 3] and r["doan_cu_khong_khop"] == []


def test_extra_text_and_type_mismatch_are_reported():
    r = S.compare(OLD, NEW)
    assert [e["ma_doan"] for e in r["doan_moi_thua"]] == ["N-001"]
    assert r["ky_tu_thua"] == len("Share") and r["van_ban_thua"] == round(len("Share") / r["ky_tu_moi"], 4)
    assert r["khop_loai"] == [2, 3]
    assert r["khop_khac_loai"][0]["loai_cu"] == "mã/truy vấn" and r["khop_khac_loai"][0]["loai_moi"] == "dòng bảng"


def test_images_are_counted_but_not_scored_as_text():
    r = S.compare(OLD, NEW)
    assert (r["anh_cu"], r["anh_moi"]) == (1, 2)
    assert r["doan_cu_co_chu"] == 3 and r["doan_moi_co_chu"] == 4


def test_missing_text_lowers_coverage_and_match():
    r = S.compare(OLD, NEW[:3])
    assert r["do_phu_van_ban"] < 1.0 and r["khop_doan"] == [2, 3]
    assert r["doan_cu_khong_khop"][0]["ma_doan"] == "XX-003"
