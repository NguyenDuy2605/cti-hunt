"""Khâu ② nhánh TTP: phần hậu kiểm bằng mã. Mô hình được thay bằng MockClient."""
import json

import pytest

from cti_hunt.config import ROOT
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s2_ttp

from .test_attack_and_reports import catalog as build_catalog

PROMPT = s2_ttp.load_prompt(ROOT / "prompts" / "khau2_ttp_v1.md")
SEGMENTS = [
    {"ma_doan": "XX-001", "report": "XX", "loai": "tiêu đề", "van_ban": "Lateral Movement"},
    {"ma_doan": "XX-002", "report": "XX", "loai": "đoạn văn",
     "van_ban": "The actor ran wmic /node:SRV1 process call create to execute commands on other hosts."},
]


def item(**kw):
    base = {"segment_id": "XX-002", "tactic": "Lateral Movement", "technique_id": "T1047",
            "technique_name": "tên mô hình tự đặt", "behavior_description": "chạy lệnh từ xa",
            "quote": "The actor ran wmic /node:SRV1 process call create to execute commands on other hosts.",
            "context": {"tool": "WMI", "execution_path": "remote"}, "confidence": 0.9}
    base.update(kw)
    return base


def run(items, segments=SEGMENTS, catalog=None, tmp_path=None):
    llm = MockClient(responses=[{"items": items}])
    cat = catalog or build_catalog(tmp_path)
    return s2_ttp.extract_report("XX", segments, llm, cat, PROMPT, batch_size=len(segments))


def test_prompt_file_has_both_sections_and_no_leftover_placeholder():
    assert "One item per (segment, technique)" in PROMPT["system"]
    rendered = s2_ttp.render_batch(PROMPT, "XX", SEGMENTS)
    assert "{segments}" not in rendered and "{report_id}" not in rendered and "{{" not in rendered
    assert '<segment id="XX-002"' in rendered


def test_technique_name_comes_from_catalog_not_model(tmp_path):
    ttps, log = run([item()], tmp_path=tmp_path)
    assert [t.technique_name for t in ttps] == ["Windows Management Instrumentation"]
    assert log["so_muc_giu"] == 1


def test_revoked_code_mapped_and_unknown_dropped(tmp_path):
    ttps, log = run([item(technique_id="T1000"), item(technique_id="T9999")], tmp_path=tmp_path)
    assert [t.technique_id for t in ttps] == ["T1546.003"]
    assert log["ma_sua"]["ma_bi_thu_hoi"] == 1 and log["ma_sua"]["ma_khong_ton_tai"] == 1


def test_heading_segment_and_unknown_segment_dropped(tmp_path):
    ttps, log = run([item(segment_id="XX-001"), item(segment_id="XX-999")], tmp_path=tmp_path)
    assert ttps == [] and log["ma_sua"] == {"doan_tieu_de": 1, "segment_id_la": 1}


def test_fabricated_quote_and_command_are_removed(tmp_path):
    ttps, log = run([item(quote="Câu này không có trong đoạn.",
                          context={"tool": "WMI", "execution_path": "remote",
                                   "command_example": "Invoke-WmiMethod -Class Win32_Process"})],
                    tmp_path=tmp_path)
    assert ttps[0].source_span.text == "" and ttps[0].context.command_example == ""
    assert log["ma_sua"]["quote_khong_co_trong_doan"] == 1 and log["ma_sua"]["command_example_bi_bia"] == 1


def test_verbatim_command_is_kept(tmp_path):
    cmd = "wmic /node:SRV1 process call create"
    ttps, _ = run([item(context={"tool": "WMI", "execution_path": "remote", "command_example": cmd})],
                  tmp_path=tmp_path)
    assert ttps[0].context.command_example == cmd


def test_duplicate_pair_keeps_highest_confidence(tmp_path):
    ttps, log = run([item(confidence=0.4), item(confidence=0.8)], tmp_path=tmp_path)
    assert len(ttps) == 1 and ttps[0].confidence == 0.8 and log["ma_sua"]["trung_cap_doan_ky_thuat"] == 1


def test_khong_ro_becomes_empty_and_bad_tactic_logged(tmp_path):
    ttps, log = run([item(tactic="Định hướng", context={"tool": "khong_ro", "execution_path": "khong_ro"})],
                    tmp_path=tmp_path)
    assert ttps[0].context.tool == "" and ttps[0].context.execution_path == ""
    assert log["ma_sua"]["tactic_khong_hop_le"] == 1


def test_batching_and_run_log(tmp_path):
    segs = [{"ma_doan": f"XX-{i:03d}", "report": "XX", "loai": "đoạn văn", "van_ban": "text"} for i in range(5)]
    llm = MockClient(responses=[{"items": []} for _ in range(3)])
    run_dir = tmp_path / "run"
    s2_ttp.extract_report("XX", segs, llm, build_catalog(tmp_path), PROMPT, batch_size=2, run_dir=run_dir)
    assert len(llm.calls) == 3
    reqs = [json.loads(l) for l in (run_dir / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [len(r["segment_ids"]) for r in reqs] == [2, 2, 1]


def test_eval_set_blocked_before_freeze(tmp_path):
    from cti_hunt.integrity import NotFrozenError
    seg = tmp_path / "s.jsonl"
    seg.write_text(json.dumps({"ma_doan": "SY-001", "report": "SY", "loai": "đoạn văn", "van_ban": "x"}) + "\n",
                   encoding="utf-8")
    with pytest.raises(NotFrozenError):
        s2_ttp.run_on_eval_set(seg, tmp_path / "chua", MockClient(), build_catalog(tmp_path), PROMPT)
