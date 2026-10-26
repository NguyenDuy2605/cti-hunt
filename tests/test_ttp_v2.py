"""Khâu ② v2 (N3): khối ứng viên theo đoạn, lượt kiểm, chấm tập phát triển, chặn CLI. Mô hình là MockClient."""
import re

import pytest

from cti_hunt import cli
from cti_hunt.config import ROOT
from cti_hunt.eval import proc_examples as D
from cti_hunt.llm import providers
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s2_ttp

from .test_attack_and_reports import catalog as build_catalog

V1 = s2_ttp.load_prompt(ROOT / "prompts" / "khau2_ttp_v1.md")
V2 = s2_ttp.load_prompt(ROOT / "prompts" / "khau2_ttp_v2.md")
KIEM = s2_ttp.load_prompt(ROOT / "prompts" / "khau2_kiem_v2.md")
QUOTE_WMI = "The actor ran wmic /node:SRV1 process call create to execute commands on other hosts."
QUOTE_SUB = "It registered a WMI event subscription that launched the payload at logon."
SEGMENTS = [
    {"ma_doan": "XX-001", "report": "XX", "loai": "tiêu đề", "van_ban": "Lateral Movement"},
    {"ma_doan": "XX-002", "report": "XX", "loai": "đoạn văn", "van_ban": QUOTE_WMI},
    {"ma_doan": "XX-003", "report": "XX", "loai": "đoạn văn", "van_ban": QUOTE_SUB},
]


class FakeIndex:
    source_sha256 = "stix"
    procedure_ids_sha256 = "ids"
    example_count = 0

    def __init__(self):
        self.queries = []

    def search(self, query, k):
        self.queries.append((query, k))
        table = {QUOTE_WMI: ["T1047", "T1546.003", "T1021"], QUOTE_SUB: ["T1546.003", "T1047", "T1053"]}
        return [{"technique_id": t, "name": f"Name {t}",
                 "description": f"See [Other](https://attack.mitre.org/techniques/T1112) <code>x</code> about {t}."}
                for t in table.get(query, [])[:k]]


def options(index=None):
    return s2_ttp.V2Options(index=index or FakeIndex(), verify_prompt=KIEM,
                            descriptions={"T1047": "WMI description", "T1546.003": "Subscription description"})


def item(seg="XX-002", tid="T1047", quote=QUOTE_WMI, **kw):
    return {"segment_id": seg, "tactic": "Execution", "technique_id": tid, "quote": quote,
            "behavior_description": "did something", "confidence": 0.9, **kw}


@pytest.mark.parametrize("path", ["khau2_ttp_v2.md", "khau2_kiem_v2.md"])
def test_v2_prompts_contain_no_technique_ids(path):
    assert not re.search(r"\bT\d{4}", (ROOT / "prompts" / path).read_text(encoding="utf-8"))


def test_render_keeps_v1_and_requires_candidates_for_v2():
    assert s2_ttp.render_batch(V1, "XX", SEGMENTS) == \
        V1["user"].replace("{report_id}", "XX").replace("{segments}", s2_ttp._segment_blocks(SEGMENTS))
    with pytest.raises(ValueError):
        s2_ttp.render_batch(V1, "XX", SEGMENTS, "- T1047 | x | y")
    with pytest.raises(ValueError):
        s2_ttp.render_batch(V2, "XX", SEGMENTS)
    user = s2_ttp.render_batch(V2, "{segments}", SEGMENTS, "- T1047 | {report_id} | y")
    assert "- T1047 | {report_id} | y" in user and "{candidates}" not in user   # chữ chèn vào không bị thay tiếp


def test_candidates_are_per_segment_union_without_headings():
    index = FakeIndex()
    cands = s2_ttp.candidates_for_batch(index, SEGMENTS, per_segment=2)
    assert [c["technique_id"] for c in cands] == ["T1047", "T1546.003"]
    assert [q for q, _ in index.queries] == [QUOTE_WMI, QUOTE_SUB] and all(k == 2 for _, k in index.queries)
    block = s2_ttp.render_candidates(cands, 300)
    assert block.startswith("- T1047 | Name T1047 | See Other x about")
    assert "T1112" not in block and "https://" not in block and "<code>" not in block
    assert s2_ttp.render_candidates([], 300) == "(none)"


def test_v2_extract_applies_verify_and_reruns_postprocess(tmp_path):
    llm = MockClient(responses=[
        {"items": [item(), item("XX-003", "T1047", QUOTE_SUB), item("XX-003", "T1047", "not in text")]},
        {"decisions": [{"index": 0, "quyet_dinh": "giu", "ly_do": "khớp"},
                       {"index": 1, "quyet_dinh": "sua_ma", "ma_moi": "t1546.003", "ly_do": "là subscription"},
                       {"index": 2, "quyet_dinh": "bo", "ly_do": "không có trong đoạn"}]}])
    ttps, log = s2_ttp.extract_report("XX", SEGMENTS, llm, build_catalog(tmp_path), V2, batch_size=3,
                                      run_dir=tmp_path / "run", v2=options())
    assert sorted((t.source_span.segment_id, t.technique_id) for t in ttps) == \
        [("XX-002", "T1047"), ("XX-003", "T1546.003")]
    assert log["ma_sua"]["kiem_giu"] == 1 and log["ma_sua"]["kiem_sua_ma"] == 1 and log["ma_sua"]["kiem_bo"] == 1
    extract_user, verify_user = llm.calls[0][1], llm.calls[1][1]
    assert "- T1047 | Name T1047" in extract_user
    # §2.2: chỉ mô tả của kỹ thuật các mục đã chọn (ở đây mọi mục là T1047), không phải mọi ứng viên
    assert '"index": 2' in verify_user and "T1047: WMI description" in verify_user
    assert "Subscription description" not in verify_user
    assert llm.calls[1][0] == KIEM["system"]
    responses = (tmp_path / "run" / "responses.jsonl").read_text(encoding="utf-8")
    assert '"kiem_raw"' in responses and '"ung_vien"' in (tmp_path / "run" / "requests.jsonl").read_text(encoding="utf-8")
    resumed = s2_ttp.doc_lo_da_co(tmp_path / "run", "kiem_raw")
    assert resumed["XX"][0]["decisions"][2]["quyet_dinh"] == "bo"


@pytest.mark.parametrize("failure", ["bad_twice", "refusal"])
def test_verify_failure_keeps_unverified_items_and_counts(tmp_path, failure):
    errors = [providers.BadOutputError("x"), providers.BadOutputError("y")] if failure == "bad_twice" \
        else [providers.RefusalError("no")]
    llm = MockClient(responses=[{"items": [item()]}, *errors])
    ttps, log = s2_ttp.extract_report("XX", SEGMENTS, llm, build_catalog(tmp_path), V2, batch_size=3, v2=options())
    assert [t.technique_id for t in ttps] == ["T1047"]
    assert log["ma_sua"]["kiem_that_bai"] == 1 and len(log["su_co"]["kiem_that_bai"]) == 1
    assert len(llm.calls) == (3 if failure == "bad_twice" else 2)               # refusal: không gọi lại
    assert len(log["su_co"]["kiem_goi_lai"]) == (1 if failure == "bad_twice" else 0)


def test_empty_extraction_skips_verify(tmp_path):
    llm = MockClient(responses=[{"items": []}])
    ttps, _ = s2_ttp.extract_report("XX", SEGMENTS, llm, build_catalog(tmp_path), V2, batch_size=3, v2=options())
    assert ttps == [] and len(llm.calls) == 1


def test_apply_verify_edge_cases():
    items = [s2_ttp.ExtractedTTP.model_validate(item()), s2_ttp.ExtractedTTP.model_validate(item(tid="T1546.003"))]
    D_ = s2_ttp.VerifyDecision
    out, log = s2_ttp.apply_verify(items, [D_(index=0, quyet_dinh="sua_ma"), D_(index=0, quyet_dinh="bo"),
                                           D_(index=7, quyet_dinh="bo")])
    assert [i.technique_id for i in out] == ["T1047", "T1546.003"]
    assert log == {"kiem_sua_ma_thieu_ma": 1, "kiem_trung_index": 1, "kiem_index_la": 1, "kiem_thieu_quyet_dinh": 1}


def test_v1_extract_unchanged_without_v2(tmp_path):
    llm = MockClient(responses=[{"items": [item()]}])
    ttps, log = s2_ttp.extract_report("XX", SEGMENTS, llm, build_catalog(tmp_path), V1, batch_size=3)
    assert [t.technique_id for t in ttps] == ["T1047"] and len(llm.calls) == 1
    assert "kiem_that_bai" not in log["su_co"] and llm.calls[0][1] == s2_ttp.render_batch(V1, "XX", SEGMENTS)


def test_score_dev_counts_recall_and_lower_bound_precision(tmp_path):
    items = [{"id": "a", "technique_id": "T1047", "text": QUOTE_WMI, "co_link_hoac_ma_ky_thuat": False},
             {"id": "b", "technique_id": "T1546.003", "text": QUOTE_SUB, "co_link_hoac_ma_ky_thuat": True}]
    segs = D.dev_segments(items)
    llm = MockClient(responses=[{"items": [item(segs[0]["ma_doan"]), item(segs[1]["ma_doan"], "T1047", QUOTE_SUB)]}])
    ttps, _ = s2_ttp.extract_report("DEV", segs, llm, build_catalog(tmp_path), V1, batch_size=2)
    score = D.score_dev(items, segs, ttps)
    assert score["tat_ca"]["dung_ma"] == 1 and score["tat_ca"]["so_ma_dau_ra"] == 2
    assert score["tat_ca"]["precision_gioi_han_duoi"] == 0.5 and score["co_link_ma"]["dung_ma"] == 0


def test_dev_set_v1_baseline_uses_same_model_as_v2_only_prompt_differs():
    from cti_hunt import config
    cfg2 = config.load("llm_v2")
    v1, v2 = cli.dev_ttp_config("v1", cfg2), cli.dev_ttp_config("v2", cfg2)
    assert v1["prompt_file"] == config.load("llm")["prompt_file"] and v2["prompt_file"] == cfg2["prompt_file"]
    for key in ("provider", "model", "effort", "max_output_tokens", "budget_ledger", "request_timeout_giay"):
        assert v1[key] == v2[key]
    assert cfg2["model"] == "claude-sonnet-5"                       # đã chốt, có biểu giá trong sổ
    assert cli.dev_ttp_config("v1", cfg2, "medium")["effort"] == cli.dev_ttp_config("v2", cfg2, "medium")["effort"] \
        == "medium" and cfg2["effort"] == "high"                    # ghi đè như nhau, không sửa cấu hình gốc


def test_cli_guards_held_out_set_and_unlocked_v2(capsys):
    assert cli.main(["dev-ttp", "--tap", "giu_lai"]) == 1
    assert "khóa v2" in capsys.readouterr().out
    if not (ROOT / "docs" / "giao_thuc_khau2_v2.md").exists():
        assert cli.main(["ttp", "--phien-ban", "v2"]) == 1
        assert "giao_thuc_khau2_v2" in capsys.readouterr().out
