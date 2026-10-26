import pytest
import yaml

from cti_hunt.eval.hunt_metrics import stage_metrics, step_recall
from cti_hunt.hunt import runner
from cti_hunt.labels.ground_truth import Step

STEPS = [Step("14.B", "", "", "lien_ke", {"PS": "mo_ho"}),
         Step("15.A", "", "", "trong", {"PS": "co", "MS": "co"}),
         Step("16.C", "", "", "trong", {"SY": "co"}),
         Step("16.D", "", "", "trong", {"MS": "mo_ho", "SY": "mot_phan"}),
         Step("20.B", "", "", "trong", {"SY": "khong"})]

H03 = {
    "id": "H-T", "scope": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_ids": [1]},
    "candidates": r"lower(ParentImage) LIKE '%\wmiprvse.exe' OR lower(ParentImage) LIKE '%\wsmprovhost.exe'"
                  r" OR lower(ParentImage) LIKE '%\services.exe'",
    "filters": [{"id": "F-01", "where": r"lower(Image) LIKE '%\svchost.exe'", "ly_do": "x",
                 "nguoi_chiu_trach_nhiem": "người vận hành", "het_han": "het_de_tai"},
                {"id": "F-02", "where": r"lower(Image) LIKE '%\m.exe'", "ly_do": "lọc sai cố ý",
                 "nguoi_chiu_trach_nhiem": "người vận hành", "het_han": "het_de_tai"}],
}


def test_stage_metrics_by_hand():
    s = stage_metrics("x", ["20.A", None, None, "16.D"], negatives_in_scope=575)
    assert (s.hits, s.attacker_events, s.fp, s.tn) == (4, 2, 2, 573)
    assert s.fpr == pytest.approx(2 / 575) and s.precision == 0.5


def test_step_recall_three_denominators():
    r = step_recall({"14.B", "16.D"}, STEPS, steps_with_log={"15.A", "16.C", "16.D"}, independent_reports=["MS", "SY"])
    a = r["tat_ca_report"]
    assert (a["tuyet_doi"]["phat_hien"], a["tuyet_doi"]["mau_so"]) == (1, 4)
    assert a["tran_dau_vao"]["mau_so"] == 3          # 20.B 'khong' không tính là có mô tả
    assert a["tran_thuc_te"]["mau_so"] == 3
    assert r["buoc_ngoai_scope_bat_duoc"] == ["14.B"]
    assert r["report_doc_lap"]["tran_dau_vao"]["mau_so"] == 3   # 15.A vẫn rõ nhờ MS


def test_runner_on_fixture(con_labeled):
    con, _ = con_labeled
    runner.validate(H03)
    res = runner.run(con, H03, STEPS, ["MS", "SY"])
    assert res["mau_so_fpr"] == {"su_kien_trong_pham_vi": 5, "su_kien_tan_cong": 2, "am_tinh": 3}
    g = {x["stage"]: x for x in res["giai_doan"]}
    assert g["ung_vien"]["hits"] == 4 and g["ung_vien"]["fp"] == 2
    assert g["sau_F-01"]["removed"] == 1 and g["sau_F-01"]["removed_attacker"] == 0
    assert g["sau_F-02"]["removed_attacker"] == 1 and g["sau_F-02"]["removed_attacker_steps"] == {"16.D": 1}
    assert [r["buoc"] for r in res["ket_qua_cuoi"]] == ["14.B", None]


@pytest.mark.parametrize("bad, msg", [
    ({"scope": {"event_ids": [1]}}, "channel"),
    ({"candidates": "buoc IS NOT NULL"}, "nhãn"),
    ({"filters": [{"id": "F", "where": "1=1"}]}, "thiếu"),
])
def test_spec_validation(bad, msg):
    spec = {**H03, **bad}
    with pytest.raises(runner.HuntSpecError, match=msg):
        runner.validate(spec)


def test_shipped_h03_is_valid():
    from cti_hunt.config import ROOT
    runner.load_spec(ROOT / "hunts" / "manual" / "H-03.yaml")
