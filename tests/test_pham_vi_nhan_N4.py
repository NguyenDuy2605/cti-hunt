"""Script N4 câu 1 trên nhãn tổng hợp của conftest: chỉ số đếm theo bước, không in sự kiện."""
import importlib.util
from pathlib import Path

from cti_hunt.labels.ground_truth import Step

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/pham_vi_nhan_N4.py"
spec = importlib.util.spec_from_file_location("pham_vi_nhan_N4", SCRIPT)
N4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N4)

STEPS = [Step("16.C", "PowerShell từ xa", "T1059.001", "trong", {"PS": "co", "MS": "mot_phan", "SY": "khong"}),
         Step("16.D", "Thực thi trên máy đích", "T1021.006", "trong", {"PS": "co", "MS": "khong", "SY": "co"}),
         Step("20.A", "Bước không có nhãn", "T1053.005", "trong", {"PS": "khong", "MS": "khong", "SY": "mo_ho"})]


def test_counts_per_step_and_denominators(con_labeled):
    con, _ = con_labeled
    res = N4.summarize(con, STEPS, ["MS", "SY"])
    rows = {r["buoc"]: r for r in res["buoc"]}
    assert (rows["16.C"]["su_kien_khop_log"], rows["16.D"]["su_kien_khop_log"], rows["20.A"]["su_kien_khop_log"]) == (1, 1, 0)
    assert rows["16.C"]["nguon_chinh"] == ["microsoft-windows-powershell/operational EID 4104: 1"]
    assert (rows["16.C"]["mo_ta_ms_sy"], rows["16.D"]["mo_ta_ms_sy"], rows["20.A"]["mo_ta_ms_sy"]) == ("mot_phan", "co", "mo_ho")
    t = res["tong"]
    assert t["co_log"] == ["16.C", "16.D"] and t["co_mo_ta_3_report"] == ["16.C", "16.D"]
    assert t["co_mo_ta_va_co_log_ms_sy"] == ["16.C", "16.D"] and t["co_mo_ta_ms_sy"] == ["16.C", "16.D"]
    assert t["nhan_ngoai_ground_truth"] == {"14.B": 1}     # nhãn có mã bước không nằm trong ground truth


def test_render_prints_counts_not_events(con_labeled):
    con, _ = con_labeled
    text = N4.render(N4.summarize(con, STEPS, ["MS", "SY"]))
    assert "có mô tả và có log, MS+SY: 2 — 16.C, 16.D" in text and "14.B" in text
    assert "m.exe" not in text and "powershell.exe" not in text and "Invoke-Command" not in text
