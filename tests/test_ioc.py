"""Khâu ② nhánh IOC. Văn bản test do tự soạn, không lấy từ 3 report đánh giá."""
import pytest

from cti_hunt.config import ROOT
from cti_hunt.stages import s2_ioc

RULES = s2_ioc.load_rules(ROOT / "configs" / "ioc_rules.yaml")


def kinds(text):
    return [(i.type, i.value) for i in s2_ioc.extract(text, RULES)]


@pytest.mark.parametrize("text, expect", [
    ("beacon to bigtopweb[.]com", ("domain", "bigtopweb[.]com")),          # R10: giữ nguyên dạng defang
    ("C2 at 185[.]86[.]148[.]227 today", ("ip", "185[.]86[.]148[.]227")),
    ("visit hxxps://cdn.example.org/a.php now", ("url", "hxxps://cdn.example.org/a.php")),
    ("mail ops[at]corp.example.com sent", ("email", "ops[at]corp.example.com")),
])
def test_defanged_forms_kept_verbatim(text, expect):
    assert kinds(text) == [expect]


def test_types_and_priority():
    text = (r"drops C:\Users\mscott\m.exe and kxwn.lock, writes "
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater, opens \\.\pipe\atctl, "
            "hash 5b6c1b5b9b2f2a0f4a5c8e9d0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d")
    assert kinds(text) == [
        ("duong_dan", r"C:\Users\mscott\m.exe"),
        ("ten_file", "kxwn.lock"),
        ("registry", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"),
        ("named_pipe", r"\\.\pipe\atctl"),
        ("hash", "5b6c1b5b9b2f2a0f4a5c8e9d0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d"),
    ]


def test_url_does_not_also_yield_domain():
    assert kinds("see https://cdn.example.org/a.php") == [("url", "https://cdn.example.org/a.php")]


def test_email_does_not_also_yield_domain():
    assert kinds("write to ops@corp.example.com") == [("email", "ops@corp.example.com")]


@pytest.mark.parametrize("text", [
    "ran powershell.exe with flags",                 # R10: binary hệ thống, tên và vị trí mặc định
    r"ran C:\Windows\System32\rundll32.exe now",
    "build version 10.0.19041.1 released",           # không phải IP, không phải domain
    "the file was opened",
])
def test_not_iocs(text):
    assert kinds(text) == []


@pytest.mark.parametrize("text, expect", [
    (r"dropped C:\Users\public\rundll32.exe here", ("duong_dan", r"C:\Users\public\rundll32.exe")),
    ("renamed to rundll32.dll in temp", ("ten_file", "rundll32.dll")),
])
def test_system_binary_only_skipped_at_default_location(text, expect):
    assert kinds(text) == [expect]


@pytest.mark.parametrize("text, expect", [
    # Thư mục có dấu cách: trước 14/10 bị cắt thành C:\Program (ToddyCat); nay lấy trọn khi kết thúc bằng tên tệp có đuôi
    (r"C:\Program Files\Windows Mail\AcroRd64.exe | LoFiSe", [("duong_dan", r"C:\Program Files\Windows Mail\AcroRd64.exe")]),
    # Không có tên tệp ở cuối thì giữ cách cũ, không nuốt chữ phía sau
    (r"saved in C:\Windows\Temp\ then ran run.bat", [("duong_dan", "C:\\Windows\\Temp\\"), ("ten_file", "run.bat")]),
])
def test_path_with_spaces(text, expect):
    assert kinds(text) == expect


def test_parenthesised_scheme_defang():
    # Symantec viết https(://)abc(.)com; trước 14/10 chỉ ra tên miền, mất URL
    assert kinds("URLs | https(://)infinitysoftwares(.)com/files/a.pdf") == [
        ("url", "https(://)infinitysoftwares(.)com/files/a.pdf")]


def test_unknown_defang_form_in_host_does_not_crash():
    # Dạng che không có trong bảng defang để lại "[" trong phần máy chủ; urlsplit ném "Invalid IPv6 URL" (gặp 14/10)
    assert all(t != "url" for t, _ in kinds("C2 at https://evil.example[d]com/a today"))


def test_curly_quotes_do_not_stick_to_paths_urls_and_keys():
    # 15/10: trên 6/19 report, dấu nháy cong cuối câu dính vào giá trị (C:\Windows\System32\cmd.exe”)
    got = kinds("ran “C:\\Windows\\System32\\cmd.exe” and “C:\\Program Files\\A B\\x.exe” then "
                "“https://evil-c2.net/a” and set “HKCU\\Software\\Evil\\Run1”")
    assert ("duong_dan", "C:\\Program Files\\A B\\x.exe") in got
    assert ("url", "https://evil-c2.net/a") in got
    assert ("registry", "HKCU\\Software\\Evil\\Run1") in got
    assert all(not any(q in v for q in "“”‘’") for _, v in got)


def test_dropped_system_path_is_not_cut_into_a_domain():
    # 15/10: R10 bỏ đường dẫn chương trình hệ thống, nhưng trước đây để mẫu tên miền lấy `Microsoft.NET` từ giữa đường dẫn
    got = kinds(r"launches C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe to inject")
    assert all(t != "domain" for t, _ in got)


def test_rules_serialize_the_same_in_every_process():
    # 15/10 (lỗi ghi từ 12/10): thứ tự system_dirs cùng độ dài theo hạt băm của tiến trình -> băm quy tắc IOC đổi giữa các lần chạy
    import subprocess
    import sys
    code = ("import json; from cti_hunt import config; from cti_hunt.stages import s2_ioc; "
            "r = s2_ioc.load_rules(config.resolve('configs/ioc_rules.yaml')); "
            "print(json.dumps(r, sort_keys=True, default=lambda x: sorted(x) if isinstance(x, set) else str(x)))")
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                           env={**__import__("os").environ, "PYTHONHASHSEED": str(seed)}).stdout for seed in range(1, 9)}
    assert len(outs) == 1


def test_ambiguous_extension_resolves_to_domain():
    assert kinds("traffic to update.example.com seen") == [("domain", "update.example.com")]
    assert kinds("dropped payload.lock file") == [("ten_file", "payload.lock")]


def test_first_occurrence_per_report_and_other_form_noted():
    segs = [{"ma_doan": "XX-001", "van_ban": "C2 is bigtopweb[.]com"},
            {"ma_doan": "XX-002", "van_ban": "again bigtopweb.com and bigtopweb[.]com"}]
    iocs = s2_ioc.extract_report(segs, RULES)
    assert [(i.type, i.value, i.source_span.segment_id) for i in iocs] == [
        ("domain", "bigtopweb[.]com", "XX-001")]
    assert "bigtopweb.com" in iocs[0].context


def test_eval_set_blocked_before_freeze(tmp_path):
    from cti_hunt.integrity import NotFrozenError
    seg = tmp_path / "s.jsonl"
    seg.write_text('{"ma_doan": "SY-001", "report": "SY", "van_ban": "bigtopweb[.]com"}\n', encoding="utf-8")
    with pytest.raises(NotFrozenError):
        s2_ioc.run_on_eval_set(seg, tmp_path / "chua_dong_bang", RULES)


def test_evaluate_iocs_separates_wrong_type_from_missing():
    from cti_hunt.eval.extraction_metrics import evaluate_iocs
    norm = lambda v: s2_ioc.normalize(v, RULES)
    gold = [("SY", "bigtopweb[.]com", "domain"), ("SY", "https://a.example.org/x", "url"),
            ("SY", "kxwn.lock", "ten_file")]
    pred = [("SY", "bigtopweb.com", "domain"), ("SY", "https://a.example.org/x", "domain"),
            ("SY", "m.exe", "ten_file")]
    r = evaluate_iocs(gold, pred, norm)
    assert r["tp"] == 2 and r["fn"] == 1 and r["fp"] == 1          # so theo giá trị, không theo dạng viết
    assert r["dung_ca_loai"] == 1 and r["sai_loai"][0]["he_thong"] == "domain"
