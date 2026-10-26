"""Chấm toàn kịch bản N4 §2.1 trên bước và kết quả hunt tổng hợp (không dữ liệu thật, không nhãn thật)."""
import importlib.util
from pathlib import Path

from cti_hunt.labels.ground_truth import Step

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/do_toan_kich_ban_N4.py"
spec = importlib.util.spec_from_file_location("do_toan_kich_ban_N4", SCRIPT)
N4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N4)

STEPS = [Step("12.A", "a", "T1", "ngoai", {"PS": "khong", "MS": "co", "SY": "khong"}),
         Step("15.A", "b", "T2", "trong", {"PS": "co", "MS": "mot_phan", "SY": "co"}),
         Step("16.C", "c", "T3", "trong", {"PS": "co", "MS": "khong", "SY": "mot_phan"}),
         Step("17.C", "d", "T4", "ngoai", {"PS": "co", "MS": "khong", "SY": "khong"}),
         Step("19.A", "e", "T5", "ngoai", {"PS": "khong", "MS": "khong", "SY": "khong"})]
WITH_LOG = {"12.A", "15.A", "16.C", "17.C", "19"}          # 19.A chỉ có nhãn mức khung "19"


def test_denominators_follow_the_run_report():
    sy = N4.denominators(STEPS, WITH_LOG, ["SY"])
    assert sy == {"tuyet_doi": ["12.A", "15.A", "16.C", "17.C", "19.A"], "co_log": ["12.A", "15.A", "16.C", "17.C"],
                  "co_mo_ta": ["15.A", "16.C"], "co_mo_ta_va_co_log": ["15.A", "16.C"]}
    assert N4.denominators(STEPS, WITH_LOG, None)["co_mo_ta"] == ["12.A", "15.A", "16.C", "17.C"]


def test_rows_score_each_run_and_paired_ms_sy():
    per_run = [{"ten": "Nhánh A (H-03)", "report": "-", "phat_hien": {"15.A"}},
               {"ten": "pipeline SY_01", "report": "SY", "phat_hien": {"16.C", "19"}},
               {"ten": "pipeline MS_01", "report": "MS", "phat_hien": {"12.A"}},
               {"ten": "pipeline PS_01", "report": "PS", "phat_hien": {"17.C"}}]
    rows = {r["ten"]: r for r in N4.rows_from(per_run, STEPS, WITH_LOG, ["19"], ["MS", "SY"])}
    a = rows["Nhánh A (H-03)"]
    assert (len(a["tuyet_doi"]["phat_hien"]), a["tuyet_doi"]["mau_so"], a["co_mo_ta"]["mau_so"]) == (1, 5, 4)
    sy = rows["pipeline SY_01"]
    assert sy["khung"] == {"19": True} and sy["co_log"]["phat_hien"] == ["16.C"]   # khung 19 không vào mẫu số theo bước
    pair = rows["pipeline MS+SY"]
    assert pair["phat_hien"] == ["12.A", "16.C", "19"] and pair["mo_ta_theo"] == "MS+SY"
    assert (pair["co_mo_ta_va_co_log"]["phat_hien"], pair["co_mo_ta_va_co_log"]["mau_so"]) == (["12.A", "16.C"], 3)
    assert "agent MS+SY lượt 1" not in rows                 # chỉ ghép khi có đủ hai lượt


def test_markdown_shows_counts_and_frames():
    per_run = [{"ten": "pipeline SY_01", "report": "SY", "phat_hien": {"16.C"}}]
    md = N4.markdown(N4.rows_from(per_run, STEPS, WITH_LOG, ["19"], ["MS", "SY"]), ["19"])
    assert "| pipeline SY_01 | SY | 1/5 | 1/4 | 1/2 | 1/2 | không | 16.C |" in md
