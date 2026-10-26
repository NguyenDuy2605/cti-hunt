"""Q2/Q3/Q5/Q7 (09/10): phần hiển thị của UI sau nghiệm thu; chỉ đổi cách hiện, không đổi dữ liệu hay luồng."""
import json

from cti_hunt import config, demo

SAVED = {"poshspy": {"title": "POSHSPY — kết quả trích ngày 25/9", "source_title_contains": "(POSHSPY)"},
         "no_match_rule": {"title": "không có điều kiện tiêu đề", "source_title_contains": ""}}


def test_saved_extraction_is_offered_only_for_the_report_it_belongs_to():
    assert list(demo.saved_options_for("CERT-EU - Detecting and Preventing Emotet 2019 Campaign", SAVED)) == []
    assert list(demo.saved_options_for("Dissecting One of APT29's ... Backdoors (poshspy) | Blog", SAVED)) == ["poshspy"]


def test_report_label_shows_title_and_falls_back_to_folder_name(tmp_path):
    good, broken, empty = tmp_path / "DEV-A", tmp_path / "DEV-B", tmp_path / "DEV-C"
    for d in (good, broken, empty):
        d.mkdir()
    (good / "manifest.json").write_text(json.dumps({"title": "Tiêu đề tự soạn"}), encoding="utf-8")
    (broken / "manifest.json").write_text("{không phải json", encoding="utf-8")
    (empty / "manifest.json").write_text(json.dumps({"title": ""}), encoding="utf-8")
    assert [demo.report_label(d) for d in (good, broken, empty)] == ["DEV-A — Tiêu đề tự soạn", "DEV-B", "DEV-C"]


def test_markdown_safe_only_escapes_dollar_signs():
    text = "mẫu ^system$ và tài khoản máy workstation6$ — **đậm**"
    assert demo.markdown_safe(text) == "mẫu ^system\\$ và tài khoản máy workstation6\\$ — **đậm**"


def test_memory_note_names_both_stores_and_says_when_they_are_the_same(monkeypatch, tmp_path):
    search = config.ROOT / "data/reports/moi"
    monkeypatch.setattr(config, "agent_config", lambda version, root=config.ROOT: {"memory_root": "data/dev/kho_rieng"})
    note = demo.memory_note(search, "v2")
    assert "data/reports/moi" in note and "data/dev/kho_rieng" in note and "không đi vào planner" in note
    monkeypatch.setattr(config, "agent_config", lambda version, root=config.ROOT: {"memory_root": "data/reports/moi"})
    assert "cũng là kho planner v1 đọc" in demo.memory_note(search, "v1")
