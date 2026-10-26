"""Phân loại khâu làm mất bước trên fixture tổng hợp (nhãn giả trong conftest), không đọc nhãn thật."""
import importlib.util
import json
from pathlib import Path

import pytest

from cti_hunt.labels.ground_truth import Step

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/phan_tich_buoc_bo_sot.py"
spec_ = importlib.util.spec_from_file_location("phan_tich_buoc_bo_sot", SCRIPT)
P = importlib.util.module_from_spec(spec_)
spec_.loader.exec_module(P)

STEPS = [Step("14.B", "", "", "lien_ke", {"PS": "mo_ho"}),
         Step("15.A", "", "", "trong", {"MS": "co"}),
         Step("16.C", "", "", "trong", {"SY": "co"}),
         Step("16.D", "", "", "trong", {"SY": "mot_phan"})]
PS = "Microsoft-Windows-PowerShell/Operational"

SYSMON_HUNT = {   # 16.D vào ứng viên rồi bị F-02 loại; 14.B còn ở cuối nhưng ngoài scope
    "id": "H-SYS", "scope": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_ids": [1]},
    "candidates": r"lower(ParentImage) LIKE '%\wmiprvse.exe' OR lower(ParentImage) LIKE '%\wsmprovhost.exe'",
    "filters": [{"id": "F-02", "where": r"lower(Image) LIKE '%\m.exe'", "ly_do": "x",
                 "nguoi_chiu_trach_nhiem": "fixture", "het_han": "het_de_tai"}]}
PS_MISS = {"id": "H-PS-MISS", "scope": {"channel": PS, "event_ids": [4104]},
           "candidates": "ScriptBlockText ILIKE '%khong-co%'"}
PS_HIT = {"id": "H-PS-HIT", "scope": {"channel": PS, "event_ids": [4104]},
          "candidates": "ScriptBlockText ILIKE '%Invoke-Command%'"}


def analyze(con, specs):
    wanted = P.inscope(STEPS)
    hunts = [P.analyze_hunt(con, s, STEPS, ["MS", "SY"], wanted) for s in specs]
    return hunts, P.summarize(hunts, wanted)


def test_inscope_follows_ground_truth_scope():
    assert P.inscope(STEPS) == ["15.A", "16.C", "16.D"]


def test_filtered_and_out_of_scope(con_labeled):
    con, _ = con_labeled
    hunts, s = analyze(con, [SYSMON_HUNT])
    assert {k: v["khau"] for k, v in s.items()} == {
        "15.A": "ngoai_pham_vi", "16.C": "ngoai_pham_vi", "16.D": "bi_loc"}
    h = hunts[0]
    assert (h["pham_vi"], h["ung_vien"], h["cuoi"], h["loai_nham"]) == ({"16.D": 1}, {"16.D": 1}, {}, {"16.D": 1})
    assert s["16.D"]["hunt_co_ung_vien"] == ["H-SYS"] and s["16.D"]["hunt_con_cuoi"] == []


def test_in_scope_but_condition_misses(con_labeled):
    con, _ = con_labeled
    _, s = analyze(con, [PS_MISS])
    assert s["16.C"] == {"khau": "khong_khop_dieu_kien", "hunt_trong_pham_vi": ["H-PS-MISS"],
                         "hunt_co_ung_vien": [], "hunt_con_cuoi": []}


def test_any_final_hunt_wins(con_labeled):
    con, _ = con_labeled
    _, s = analyze(con, [SYSMON_HUNT, PS_MISS, PS_HIT])
    assert s["16.C"]["khau"] == "bat_duoc" and s["16.C"]["hunt_con_cuoi"] == ["H-PS-HIT"]
    assert s["16.D"]["khau"] == "bi_loc" and s["15.A"]["khau"] == "ngoai_pham_vi"


def test_output_has_counts_only_no_event_rows(con_labeled):
    con, _ = con_labeled
    hunts, s = analyze(con, [SYSMON_HUNT, PS_HIT])
    text = json.dumps({"hunt": hunts, "buoc": s}, ensure_ascii=False)
    assert "ket_qua_cuoi" not in text and "ev_rec" not in text and "Invoke-Command -ComputerName" not in text
    md = P.markdown([{"ten": "fixture", "so_hunt": 2, "buoc": s}], P.inscope(STEPS))
    assert "| fixture | 2 | P | B | L |" in md


def test_output_only_new_folder_under_runs(tmp_path):
    (tmp_path / "runs" / "co_san").mkdir(parents=True)
    with pytest.raises(ValueError):
        P.check_out(tmp_path / "runs" / "co_san", root=tmp_path)
    with pytest.raises(ValueError):
        P.check_out(tmp_path / "data" / "dev" / "x", root=tmp_path)
    assert P.check_out(tmp_path / "runs" / "moi", root=tmp_path) == (tmp_path / "runs" / "moi").resolve()
