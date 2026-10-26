"""07/10: đề xuất duyệt của agent chỉ được từ chối qua một kiểm tra G0(d)/§6.2 không đạt (giao thức đánh giá v2 mới §4)."""
import copy
import importlib.util
import sys

import yaml

from cti_hunt.config import ROOT

spec = importlib.util.spec_from_file_location("kiem_de_xuat_duyet", ROOT / "scripts" / "kiem_de_xuat_duyet.py")
K = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = K
spec.loader.exec_module(K)

FORM = {"hypotheses_sha256": "a" * 64, "quy_tac_duyet": "G0-d-v1", "nguoi_duyet": "",
        "gia_thuyet": [{"id": "SY-H01", "quyet_dinh": "", "ly_do": ""},
                       {"id": "SY-H02", "quyet_dinh": "", "ly_do": ""}]}
OK = {"dat": True, "can_cu": "đạt theo bảng"}


def item(i, decision="approved", codes=None, **failed):
    checks = {name: dict(OK) for name in ("bon_thanh_phan", "nguon_log", "cau_nguon", "khong_trung")}
    for name, reason in failed.items():
        checks[name] = {"dat": False, "can_cu": reason}
    return {"id": i, "kiem_tra": checks, "de_xuat": decision, "ma_ly_do": codes}


def proposal(*items):
    return {"quy_tac": "G0-d-v1", "hypotheses_sha256": "a" * 64, "muc": list(items)}


def test_all_checks_pass_is_approved():
    errors, warnings = K.check(proposal(item("SY-H01"), item("SY-H02")), FORM)
    assert errors == [] and warnings == []


def test_reject_outside_the_table_is_an_error():
    # Lỗi SY_01 07/10: từ chối "mọi kết nối 443" vì rộng, trong khi cả bốn kiểm tra G0(d) đều đạt.
    errors, _ = K.check(proposal(item("SY-H01"), item("SY-H02", "rejected", ["khong_bam_nguon"])), FORM)
    assert any("ngoài bảng quy tắc" in e for e in errors)


def test_reject_code_must_match_a_failed_check():
    bad = item("SY-H02", "rejected", ["nguon_khong_phu_hop"], cau_nguon="thêm 'ra ngoài' không có trong câu nguồn")
    errors, _ = K.check(proposal(item("SY-H01"), bad), FORM)
    assert any("phải thuộc mã" in e for e in errors)
    good = item("SY-H02", "rejected", "khong_bam_nguon", cau_nguon="thêm 'ra ngoài' không có trong câu nguồn")
    assert K.check(proposal(item("SY-H01"), good), FORM) == ([], [])


def test_approved_with_failed_check_and_breadth_warning():
    errors, _ = K.check(proposal(item("SY-H01", nguon_log="EID 13 không ghi xóa khóa"), item("SY-H02")), FORM)
    assert any("approved nhưng" in e for e in errors)
    _, warnings = K.check(proposal(item("SY-H01"), item("SY-H02", "rejected", ["thieu_thanh_phan"],
                                                         bon_thanh_phan="quá rộng, nhiều kết quả")), FORM)
    assert warnings and "rộng" in warnings[0]


def test_duplicate_needs_kept_id():
    no_id = item("SY-H02", "rejected", ["trung_gia_thuyet"], khong_trung="trùng giả thuyết trước")
    assert any("ID bản được giữ" in e for e in K.check(proposal(item("SY-H01"), no_id), FORM)[0])
    with_id = item("SY-H02", "rejected", ["trung_gia_thuyet"], khong_trung="trùng SY-H01: cùng hành vi, nguồn, thời gian")
    assert K.check(proposal(item("SY-H01"), with_id), FORM) == ([], [])


def test_items_and_hash_must_match_the_form():
    errors, _ = K.check(proposal(item("SY-H01")), FORM)
    assert any("thiếu ['SY-H02']" in e for e in errors)
    other = proposal(item("SY-H01"), item("SY-H02"))
    other["hypotheses_sha256"] = "b" * 64
    assert any("hypotheses_sha256" in e for e in K.check(other, FORM)[0])
    missing = proposal(item("SY-H01"), item("SY-H02"))
    del missing["muc"][1]["kiem_tra"]["khong_trung"]
    assert any("kiem_tra phải có đúng" in e for e in K.check(missing, FORM)[0])


def test_filter_form_and_comparison(tmp_path, capsys):
    form = {"manifest_sha256": "c" * 64, "quy_tac_duyet": "duyet_loc_khau5_v2", "nguoi_duyet": "người vận hành",
            "muc_loc": [{"id": "SY-H07__x__S-01", "quyet_dinh": "rejected", "ly_do": "x"}]}
    checks = {name: dict(OK) for name in ("logic", "lanh_tinh", "mau_pham_vi", "xung_dot")}
    checks["xung_dot"] = {"dat": False, "can_cu": "loại chính cơ chế giả thuyết cần quan sát"}
    prop = {"quy_tac": "duyet_loc_khau5_v2", "manifest_sha256": "c" * 64,
            "muc": [{"id": "SY-H07__x__S-01", "kiem_tra": checks, "de_xuat": "rejected",
                     "ma_ly_do": ["xung_dot_hanh_vi_san"]}]}
    assert K.check(prop, form) == ([], [])
    assert K.compare(prop, form) == [("SY-H07__x__S-01", "rejected", "rejected")]
    wrong_rule = copy.deepcopy(prop)
    wrong_rule["quy_tac"] = "G0-d-v1"
    assert K.check(wrong_rule, form)[0]
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(prop, allow_unicode=True), encoding="utf-8")
    (tmp_path / "f.yaml").write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    assert K.main([str(tmp_path / "p.yaml"), str(tmp_path / "f.yaml")]) == 0
    assert "1/1 giống" in capsys.readouterr().out
