"""H5: cảnh báo chuỗi kỹ thuật thiếu căn cứ trên phiếu ◆ — fixture tự soạn, không đọc tập đánh giá hay nhãn."""
import inspect
import json
import re

import duckdb
import pytest
import yaml

from cti_hunt import approval, cli
from cti_hunt.agent import graph as agent_graph
from cti_hunt.config import load as load_cfg
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.integrity import sha256_file
from cti_hunt.llm import providers
from cti_hunt.stages import hypothesis_grounding as g

SYS = "microsoft-windows-sysmon/operational"
NEW = "canh_bao_thieu_can_cu"
OLD_ROW_KEYS = ["id", "hanh_vi", "pham_vi", "thoi_gian", "cua_so_thuc_thi_utc", "phep_toan_yeu_cau",
                "loi_kha_nang_thuc_thi", "bang_chung", "ttp", "nguon", "nguon_chi_tiet", "quyet_dinh", "ly_do"]


def _source(channel, eids, fields):
    return {"channel": channel, "event_ids": eids, "key_fields": fields, "truong_bat_buoc": fields[:1]}


CATALOG = {
    "T1047": {"status": "huntable", "sources": [_source(SYS, [1], ["Image", "ParentImage"])],
              "ghi_chu": "Tiến trình sinh qua WMI thấy ở Sysmon 1 với tiến trình cha WmiPrvSE.exe."},
    "T1021.002": {"status": "partial", "sources": [_source(SYS, [3], ["Image", "DestinationPort"])],
                  "ly_do_partial": "Chia sẻ quản trị dùng cổng 445; Sysmon 3 ghi kết nối."},
    "T1569.002": {"status": "partial", "sources": [_source("security", [4697], ["ServiceName"])],
                  "ly_do_partial": "Lần chạy dịch vụ chỉ thấy qua tiến trình con của services.exe."},
}


def hyp(behavior, scope="mọi máy trong log", quotes=("Self-authored sentence.",), ttps=("T1047",), eids=(1,),
        channel=SYS, **kw):
    return ContractB(hypothesis_id="SYN-H01", behavior=behavior, scope=scope, timeframe="toàn bộ",
                     evidence=Evidence(data_source=channel, event_ids=list(eids), key_fields=["Image"]),
                     linked_ttps=list(ttps),
                     source_spans=[SourceSpan(segment_id=f"SYN-{i}", text=q) for i, q in enumerate(quotes)], **kw)


def found(h, telemetry=None):
    return [(w["loai"], w["gia_tri"]) for w in g.warnings(h, telemetry)]


@pytest.mark.parametrize("behavior, expected", [
    ("Tiến trình rundll32.exe nạp thư viện.", [("tep", "rundll32.exe")]),
    (r"Tệp được ghi vào C:\Users\Public\a.dll rồi chạy.", [("duong_dan", r"C:\Users\Public\a.dll")]),
    (r"Lệnh chạy 'C:\Program Files\Tool\run.bat' trên máy.", [("duong_dan", r"C:\Program Files\Tool\run.bat")]),
    (r"Giá trị mới dưới SOFTWARE\Microsoft\Windows\CurrentVersion\Run.",
     [("duong_dan", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]),
    (r"Đọc tệp ở \\FILESRV01\share\tools.", [("duong_dan", r"\\FILESRV01\share\tools")]),
    (r"Tiến trình cha kết thúc bằng \\mshta.exe.", [("tep", "mshta.exe")]),          # dấu \ viết đôi, không phải UNC
    ("Dòng lệnh chứa -enc hoặc /domain_trusts.", [("co_lenh", "-enc"), ("co_lenh", "/domain_trusts")]),
    ("Gọi phương thức Create của Win32_Process, đăng ký __EventFilter và ActiveScriptEventConsumer.",
     [("lop_wmi", "Win32_Process"), ("lop_wmi", "__EventFilter"), ("lop_wmi", "ActiveScriptEventConsumer")]),
    ("Script gọi Invoke-WmiMethod.", [("cmdlet", "Invoke-WmiMethod")]),
    ("Chạy Invoke-Mimikatz.ps1 trên máy.", [("tep", "Invoke-Mimikatz.ps1")]),     # một chuỗi, không báo thêm cmdlet
    ("Kết nối tới cổng 443 và DestinationPort=8080, hoặc 445/tcp.",
     [("cong", "443"), ("cong", "8080"), ("cong", "445")]),
])
def test_each_kind_of_literal_is_flagged_when_no_source_has_it(behavior, expected):
    assert found(hyp(behavior)) == expected


@pytest.mark.parametrize("behavior, quote", [
    ("Tiến trình cha là WmiPrvSE.exe.", "The parent process is wmiprvse.exe."),            # hoa/thường, chấm cuối câu
    ("Tiến trình powershell.exe được tạo.", "The macro spawns a PowerShell command."),    # tên bỏ đuôi
    (r"Ghi tệp vào C:\Windows\Temp.", "The file is dropped to C:/Windows/Temp/a.dll"),     # / và \, thư mục cha
    (r"Ghi vào C:\\Windows\\Temp\\a.dll.", r"dropped to C:\Windows\Temp\a.dll"),           # dấu \ viết đôi
    (r"Đặt giá trị dưới HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run.",
     r"modifying Run keys (i.e. HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run) for persistence"),
    (r"Đặt giá trị dưới HKLM\Software\Run.", r"writes to HKEY_LOCAL_MACHINE\Software\Run"),
    (r"Giá trị dưới Software\Microsoft\Windows\CurrentVersion\Run.",
     r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run is set"),
    ("Dòng lệnh có /c và -EncodedCommand.", "cmd.exe /c powershell -encodedcommand <blob>"),
    ("Dùng lớp Win32_Process.", "uses the WMI Win32_Process class and method Create"),
    ("Script gọi Invoke-WmiMethod.", "runs Invoke-WmiMethod -Class Win32_Process"),
    ("Kết nối tới cổng 8080.", "beacons to hxxp://203.0.113.7:8080/gate.php"),
    ("Kết nối tới cổng 443.", "communicates over port 443."),
])
def test_literal_present_in_a_source_quote_is_not_flagged(behavior, quote):
    assert g.details(behavior), "ca thử phải có chuỗi kỹ thuật để kiểm"
    assert found(hyp(behavior, quotes=(quote,))) == []


@pytest.mark.parametrize("behavior, quote, expected", [
    ("Tiến trình cmd.exe được tạo.", "drops evil-cmd.exe and runs it", [("tep", "cmd.exe")]),
    ("Dòng lệnh có -enc.", "powershell -EncodedCommand <blob>", [("co_lenh", "-enc")]),
    ("Script gọi Get-Process.", "calls Get-ProcessMitigation", [("cmdlet", "Get-Process")]),
    ("Tiến trình sc.exe tạo dịch vụ.", "sc is used to create a service", [("tep", "sc.exe")]),   # tên bỏ đuôi < 3 ký tự
    ("Kết nối tới cổng 443.", "beacons to 203.0.113.443 using HTTPS", [("cong", "443")]),
    (r"Ghi vào C:\Windows\Temp\a.dll.", r"a.dll is written under C:\Windows",
     [("duong_dan", r"C:\Windows\Temp\a.dll")]),
])
def test_lookalike_in_the_source_does_not_count(behavior, quote, expected):
    assert found(hyp(behavior, quotes=(quote,))) == expected


@pytest.mark.parametrize("text", [
    "Toàn bộ host/tài khoản trong log microsoft-windows-sysmon/operational và WMI-Activity/Operational.",
    "Thiết bị read-only và/hoặc dùng TCP/IP; xem https://example.org/a/b ngày 12/10.",
    "Sự kiện Sysmon Event ID 3, Security 4688 (EID 4688) trong report 2019 - phần 2.",
    r"Tài khoản DMEVALS\pbeesly trên máy SCRANTON; pivot tai_khoan=pgustavo (ràng buộc khi thực thi)",
    "Mục **in đậm**, tên biến __private__ và e-mail a-b@example.org.",
])
def test_prose_that_only_looks_technical_yields_nothing(text):
    assert g.details(text) == []


def test_catalog_note_supports_only_a_linked_technique_whose_source_is_the_one_selected():
    child = "Tiến trình con của WmiPrvSE.exe được tạo."
    assert found(hyp(child)) == [("tep", "WmiPrvSE.exe")]                     # không truyền danh mục: chỉ so câu nguồn
    assert found(hyp(child), CATALOG) == []
    assert found(hyp(child, ttps=("T1021.002",), eids=(3,)), CATALOG) == [("tep", "WmiPrvSE.exe")]   # kỹ thuật khác
    assert found(hyp(child, eids=(3,)), CATALOG) == [("tep", "WmiPrvSE.exe")]        # đúng kỹ thuật, khác mã sự kiện
    assert found(hyp(child, ttps=("T9999",)), CATALOG) == [("tep", "WmiPrvSE.exe")]  # kỹ thuật ngoài danh mục
    service = "Tiến trình con của services.exe."
    assert found(hyp(service, ttps=("T1569.002",)), CATALOG) == [("tep", "services.exe")]            # khác channel
    assert found(hyp(service, ttps=("T1569.002",), eids=(4697,), channel="security"), CATALOG) == []


def test_catalog_number_supports_a_port_only_when_written_as_a_port():
    net = dict(ttps=("T1021.002",), eids=(3,))
    assert found(hyp("Kết nối tới cổng 445.", **net), CATALOG) == []
    assert found(hyp("Kết nối tới cổng 3.", **net), CATALOG) == [("cong", "3")]      # "Sysmon 3" là mã sự kiện


def test_one_item_per_literal_and_quotes_are_never_stitched_together():
    h = hyp("Tiến trình certutil.exe chạy với -urlcache.", scope="Máy có certutil.exe")
    assert g.warnings(h) == [{"loai": "tep", "gia_tri": "certutil.exe", "truong": ["hanh_vi", "pham_vi"]},
                             {"loai": "co_lenh", "gia_tri": "-urlcache", "truong": ["hanh_vi"]}]
    assert g.describe(g.warnings(h)) == ("`certutil.exe` (tên tệp, trong hành vi và phạm vi); "
                                         "`-urlcache` (cờ lệnh, trong hành vi)")
    split = hyp(r"Ghi vào C:\Users\Public\a.dll.", quotes=(r"dropped to C:\Users", r"\Public\a.dll"))
    assert found(split) == [("duong_dan", r"C:\Users\Public\a.dll")]


def _form(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_form_gains_one_field_and_everything_else_is_unchanged(tmp_path):
    h = hyp("Tiến trình con của WmiPrvSE.exe chạy với -enc.")
    plain = _form(approval.write_review([h], tmp_path / "a"))
    informed = _form(approval.write_review([h], tmp_path / "b", telemetry=CATALOG))
    assert (tmp_path / "a" / approval.HYP_FILE).read_bytes() == (tmp_path / "b" / approval.HYP_FILE).read_bytes()
    assert NEW not in json.loads((tmp_path / "b" / approval.HYP_FILE).read_text(encoding="utf-8"))[0]
    assert [w["gia_tri"] for w in plain["gia_thuyet"][0][NEW]] == ["WmiPrvSE.exe", "-enc"]
    assert informed["gia_thuyet"][0][NEW] == [{"loai": "co_lenh", "gia_tri": "-enc", "truong": ["hanh_vi"]}]
    for form in (plain, informed):
        assert [k for k in form["gia_thuyet"][0] if k != NEW] == OLD_ROW_KEYS
        assert list(form) == ["hypotheses_sha256", "quy_tac_duyet", "nguoi_duyet", "gia_thuyet"]
    assert ({k: v for k, v in plain["gia_thuyet"][0].items() if k != NEW}
            == {k: v for k, v in informed["gia_thuyet"][0].items() if k != NEW})


def test_warning_never_blocks_or_alters_an_approval(tmp_path):
    h = hyp("Tiến trình WINWORD.EXE tạo tiến trình con.")
    path = approval.write_review([h], tmp_path)
    issued = _form(path)["gia_thuyet"][0]
    assert issued[NEW] and issued["quyet_dinh"] == "" and issued["loi_kha_nang_thuc_thi"] == []
    approval.save_decisions(tmp_path, "Synthetic fixture reviewer",
                            {"SYN-H01": {"quyet_dinh": "approved", "ly_do": ""}}, sha256_file(path))
    assert _form(path)["gia_thuyet"][0][NEW] == issued[NEW]
    assert approval.apply_review(tmp_path)["dem"] == {"approved": 1, "rejected": 0, "pending_review": 0}
    approved = approval.load_hypotheses(tmp_path / approval.APPROVED_FILE)[0]
    approval.require_approved(approved)
    approval.verify_saved_review(tmp_path)
    assert approved.model_dump(exclude={"status"}) == h.model_dump(exclude={"status"})


def test_form_issued_before_this_check_is_still_saved_and_applied(tmp_path):
    path = approval.write_review([hyp("Tiến trình WINWORD.EXE tạo tiến trình con.")], tmp_path)
    old = _form(path)
    del old["gia_thuyet"][0][NEW]
    # Phiếu kiểu cũ: không dòng chú thích mới ở đầu, không trường mới.
    path.write_text(yaml.safe_dump(old, allow_unicode=True, sort_keys=False), encoding="utf-8")
    approval.save_decisions(tmp_path, "Synthetic fixture reviewer",
                            {"SYN-H01": {"quyet_dinh": "rejected", "ly_do": "synthetic"}}, sha256_file(path))
    assert NEW not in _form(path)["gia_thuyet"][0]                      # lưu quyết định không tự thêm cảnh báo
    assert approval.apply_review(tmp_path)["dem"]["rejected"] == 1
    approval.verify_saved_review(tmp_path)


class _Tools:
    def __init__(self, telemetry):
        if telemetry is not None:
            self.telemetry = telemetry

    def propose(self, state, decision, run_dir):
        return [hyp("Tiến trình con của WmiPrvSE.exe được tạo.")]

    def execute(self, state, approved):
        raise AssertionError("ca này dừng ở phiếu ◆")

    def record(self, state):
        return "record"


@pytest.mark.parametrize("telemetry, expected", [(CATALOG, []), (None, ["WmiPrvSE.exe"])])
def test_graph_hands_the_catalog_of_its_tools_to_the_form(tmp_path, telemetry, expected):
    initial = {"report_id": "SYN", "remaining_refs": [0], "observations": [], "eligible_pivots": [],
               "techniques": [{"ref": 0, "technique_id": "T1047", "tactic": "Execution",
                               "behavior_description": "Self-authored"}],
               "pivot_depth": 0, "queries_reserved": 0, "history": []}
    with agent_graph.open_sqlite_graph(lambda view: {"action": "hunt", "ttp_refs": [0], "reason": "fixture"},
                                       _Tools(telemetry), load_cfg("agent"), tmp_path,
                                       tmp_path / "checkpoint.sqlite") as graph:
        out = graph.invoke(initial, {"configurable": {"thread_id": "syn"}})
    assert "__interrupt__" in out
    row = _form(tmp_path / "round_01" / approval.REVIEW_FILE)["gia_thuyet"][0]
    assert [w["gia_tri"] for w in row[NEW]] == expected


def test_cli_hypotheses_hands_the_effective_catalog_to_the_form(tmp_path, monkeypatch, capsys):
    work = tmp_path / "work"
    work.mkdir()
    con = duckdb.connect()
    con.execute("CREATE TABLE e (ev_host VARCHAR, ev_channel VARCHAR, ev_rec INTEGER, ev_eid INTEGER, "
                "ev_ts TIMESTAMP, ParentImage VARCHAR, Image VARCHAR)")
    con.execute("INSERT INTO e VALUES ('A', ?, 1, 1, '2020-01-01 00:00:00', 'p', 'i')", [SYS])
    con.execute(f"COPY e TO '{(work / 'events.parquet').as_posix()}' (FORMAT PARQUET)")
    con.close()
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(yaml.safe_dump({"techniques": {"T1047": CATALOG["T1047"]}}, allow_unicode=True),
                       encoding="utf-8")
    contract = tmp_path / "contract_a_SYN.json"
    contract.write_text(ContractA(report_id="SYN", ttps=[TTP(
        tactic="Execution", technique_id="T1047", behavior_description="Self-authored",
        source_span=SourceSpan(segment_id="SYN-0", text="Self-authored sentence."))]).model_dump_json(),
        encoding="utf-8")
    item = {"ttp_refs": [0], "behavior": "Tiến trình con của WmiPrvSE.exe chạy với -enc.", "scope": "mọi máy",
            "timeframe": "toàn bộ", "data_source": SYS, "event_ids": [1], "key_fields": ["ParentImage", "Image"],
            "extra_techniques": [], "priority": "cao"}
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work), "telemetry_catalog": str(catalog)})
    monkeypatch.setattr(cli, "_rp", lambda: {"eval_reports": [], "attack": {"stix_path": str(tmp_path / "none.json")}})
    monkeypatch.setattr(providers, "from_config", lambda cfg: providers.MockClient(responses=[{"items": [item]}]))
    out = tmp_path / "run"
    assert cli.main(["hypotheses", str(contract), "--out", str(out)]) == 0
    capsys.readouterr()
    row = _form(out / approval.REVIEW_FILE)["gia_thuyet"][0]
    assert row[NEW] == [{"loai": "co_lenh", "gia_tri": "-enc", "truong": ["hanh_vi"]}]


def test_every_production_form_writer_passes_a_catalog():
    """Lệnh `pivot` cần kết quả săn thật nên chỉ kiểm ở mức mã nguồn: không nơi phát phiếu nào bỏ quên danh mục."""
    calls = re.findall(r"approval\.write_review\((.*)\)", inspect.getsource(cli) + inspect.getsource(agent_graph))
    assert len(calls) == 3 and all("telemetry=" in c for c in calls)


def _show(tmp_path, review_dir):
    from streamlit.testing.v1 import AppTest
    app = tmp_path / f"form_{review_dir.name}.py"
    app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import hypothesis_form\n"
                   f"hypothesis_form(Path({str(review_dir)!r}), Path({str(tmp_path)!r}))\n", encoding="utf-8")
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception and not at.error
    return at


def test_ui_shows_the_warning_and_still_saves_an_approval(tmp_path):
    flagged, clean, old = tmp_path / "flagged", tmp_path / "clean", tmp_path / "old"
    approval.write_review([hyp(r"Tiến trình WINWORD.EXE ghi C:\Users\Public\a$.dll.")], flagged)
    approval.write_review([hyp("Một tiến trình được tạo.")], clean)
    path = approval.write_review([hyp("Tiến trình WINWORD.EXE tạo tiến trình con.")], old)
    form = _form(path)
    del form["gia_thuyet"][0][NEW]
    path.write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")

    at = _show(tmp_path, flagged)
    shown = [w.value for w in at.warning]
    assert len(shown) == 1 and "`WINWORD.EXE` (tên tệp, trong hành vi)" in shown[0]
    assert r"`C:\Users\Public\a$.dll` (đường dẫn, trong hành vi)" in shown[0] and "không tự chặn" in shown[0]
    assert [x.value for x in at.selectbox if x.label == "Quyết định"] == [""]          # không chọn sẵn quyết định
    next(x for x in at.text_input if x.label == "Người duyệt").set_value("Synthetic UI tester")
    next(x for x in at.selectbox if x.label == "Quyết định").set_value("approved")
    next(x for x in at.button if x.label == "Lưu phiếu duyệt").click().run()
    assert not at.exception and not at.error
    assert _form(flagged / approval.REVIEW_FILE)["gia_thuyet"][0]["quyet_dinh"] == "approved"
    assert approval.apply_review(flagged)["dem"]["approved"] == 1

    at = _show(tmp_path, clean)
    assert not at.warning and any("Không chứng minh giả thuyết bám đúng câu nguồn" in c.value for c in at.caption)
    at = _show(tmp_path, old)                                     # phiếu cũ: không cảnh báo, không câu "đã kiểm"
    assert not at.warning and not any("Kiểm chuỗi kỹ thuật" in c.value for c in at.caption)
