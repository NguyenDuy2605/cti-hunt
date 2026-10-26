"""Đo có nhãn pipeline v2 trên nhãn và hunt tổng hợp (fixture `con_labeled`; không dữ liệu thật, không nhãn thật)."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from cti_hunt.filter_approval import POLICY, FilterReviewError
from cti_hunt.hunt import runner
from cti_hunt.labels.ground_truth import Step

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/do_co_nhan_pipeline_v2.py"
spec = importlib.util.spec_from_file_location("do_co_nhan_pipeline_v2", SCRIPT)
V2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V2)

SYS = "Microsoft-Windows-Sysmon/Operational"
STEPS = [Step("14.B", "", "", "lien_ke", {"PS": "mo_ho"}),
         Step("15.A", "", "", "trong", {"PS": "co", "MS": "co"}),
         Step("16.C", "", "", "trong", {"SY": "co"}),
         Step("16.D", "", "", "trong", {"MS": "mo_ho", "SY": "mot_phan"}),
         Step("20.B", "", "", "trong", {"SY": "khong"})]
WITH_LOG = {"14.B", "16.C", "16.D"}
OK = {"cach": "cong_loc_day_du"}


def hunt(hid, candidates, channel=SYS, eids=(1,), filters=()):
    return {"id": hid, "scope": {"channel": channel, "event_ids": list(eids)}, "candidates": candidates,
            "filters": [{"id": f"F-{i}", "where": w, "ly_do": "x", "nguoi_chiu_trach_nhiem": "người vận hành",
                         "het_han": "het_de_tai"} for i, w in enumerate(filters, start=1)]}


REMOTE = hunt("H-REMOTE", r"lower(ParentImage) LIKE '%\wmiprvse.exe' OR lower(ParentImage) LIKE '%\wsmprovhost.exe'")
SERVICES = hunt("H-SERVICES", r"lower(ParentImage) LIKE '%\services.exe'")
WMI_ONLY = hunt("H-WMI", r"lower(ParentImage) LIKE '%\wmiprvse.exe'")
SCRIPT_4104 = hunt("H-4104", "ScriptBlockText ILIKE '%Invoke-Command%'", "Microsoft-Windows-PowerShell/Operational", (4104,))
FILTERED = hunt("H-LOC", REMOTE["candidates"], filters=[r"lower(Image) LIKE '%\m.exe'"])


def measure(con, h, round_name="round_01"):
    return V2.measure_hunt(con, h, STEPS, ["MS", "SY"], OK, Path(f"luot/{round_name}/hunts/{h['id']}.yaml"))


def test_measure_hunt_matches_runner_and_counts_wrongly_removed_attacks(con_labeled):
    con, _ = con_labeled
    r = measure(con, REMOTE)
    assert (r["cuoi"], r["tan_cong"], r["fp"], r["loai_nham"], r["vong"]) == (2, 2, 0, 0, "round_01")
    s = measure(con, SERVICES, "round_02")
    assert (s["fp"], s["am_tinh"], s["fpr"], s["vong"]) == (2, 3, pytest.approx(2 / 3), "round_02")
    f = measure(con, FILTERED)
    assert (f["tan_cong"], f["loai_nham"]) == (1, 1)                  # lọc loại nhầm sự kiện của 16.D
    assert set(f["keys"].values()) == {"14.B"}


def test_rows_dedupe_events_across_hunts_and_reports(con_labeled):
    con, _ = con_labeled
    per_run = [{"ten": "Tuyến B pipeline SY_01", "report": "SY", "hunts": [measure(con, REMOTE), measure(con, SERVICES)]},
               {"ten": "Tuyến B pipeline MS_01", "report": "MS", "hunts": [measure(con, WMI_ONLY), measure(con, SCRIPT_4104)]}]
    rows = {r["ten"]: r for r in V2.rows_from(per_run, STEPS, WITH_LOG, [], ["MS", "SY"])}
    sy = rows["Tuyến B pipeline SY_01"]
    assert (sy["tan_cong"], sy["fp"], sy["precision"], sy["buoc_5"]) == (2, 2, 0.5, ["16.D"])
    pair = rows["Tuyến B pipeline MS+SY"]
    # sự kiện WmiPrvSE của H-WMI trùng H-REMOTE nên chỉ đếm một lần; 14.B ngoài scope không vào 5 bước
    assert (pair["so_hunt"], pair["tan_cong"], pair["fp"]) == (4, 3, 2)
    assert pair["buoc_5"] == ["16.C", "16.D"]
    assert pair["recall_5"]["tat_ca_report"]["tuyet_doi"]["phat_hien"] == 2
    assert pair["theo_muc"]["co"] == {"buoc": ["15.A", "16.C"], "phat_hien": ["16.C"]}
    assert pair["toan_kich_ban"]["mo_ta_theo"] == "MS+SY"
    assert "Tuyến A pipeline MS+SY" not in rows                       # chỉ ghép khi có đủ hai lượt

    md = V2.markdown(V2.rows_from(per_run, STEPS, WITH_LOG, [], ["MS", "SY"]), per_run, [])
    assert "| Tuyến B pipeline MS+SY | 4 | 16.C, 16.D | 2/4 | 1/2 | 1/1 | 3 / 2 | 60.00% | 0 |" in md
    assert "| Tuyến B pipeline SY_01 | H-SERVICES | round_01 |" in md and "2 / 3 | 66.67% |" in md
    assert "Qua cổng lọc đầy đủ: 4 hunt." in md and "buoc" not in md.replace("buoc_", "")
    # bước 5 nào do hunt nào bắt: 16.D chỉ do H-REMOTE (SY), 16.C do H-4104 (MS)
    assert "| Tuyến B pipeline SY_01 | — | — | H-REMOTE×1 | — |" in md
    assert "| Tuyến B pipeline MS_01 | — | H-4104×1 | — | — |" in md


def _effective(tmp_path: Path, h: dict) -> Path:
    rd = tmp_path / "round_05" / "filter_review" / "r01"
    rd.mkdir(parents=True)
    path = tmp_path / "round_05" / "hunts_effective" / "r01" / "hunt_000.yaml"
    path.parent.mkdir(parents=True)
    doc = {**h, "filter_policy": POLICY, "filter_phase": "effective",
           "filter_review": {"dir": str(rd), "manifest_sha256": "a" * 64, "approval_log_sha256": "b" * 64},
           "sigma_context": {"rule": {"title": "x"}}}
    path.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    manifest = rd / "effective_manifest.json"
    manifest.write_text(json.dumps({"files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}), encoding="utf-8")
    (rd / "execution_receipt.json").write_text(json.dumps(
        {"kind": "completed_execution", "effective_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}),
        encoding="utf-8")
    return path


def test_load_executed_falls_back_to_effective_hash_only_when_the_gate_refuses(con_labeled, tmp_path, monkeypatch):
    con, _ = con_labeled
    plain = tmp_path / "v1.yaml"
    plain.write_text(yaml.safe_dump(REMOTE), encoding="utf-8")
    assert V2.load_executed(plain, con)[1] == OK                     # cổng đầy đủ khi qua được

    path = _effective(tmp_path, REMOTE)

    def refuse(p, *, con=None):
        raise FilterReviewError("đầu vào/phiếu giả thuyết/config/prompt đã đổi")
    monkeypatch.setattr(runner, "load_spec", refuse)
    got, kiem = V2.load_executed(path, con)
    assert kiem == {"cach": "hash_spec_hieu_luc", "ly_do_cong": "đầu vào/phiếu giả thuyết/config/prompt đã đổi"}
    assert "filter_policy" not in got and got["candidates"] == REMOTE["candidates"]
    assert measure(con, got)["tan_cong"] == 2                         # chạy đúng SQL đã lưu

    path.write_text(path.read_text(encoding="utf-8") + "# sửa\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256"):
        V2.load_executed(path, con)
    with pytest.raises(ValueError, match="không phải spec hiệu lực"):
        V2.load_executed(plain, con)


def test_runs_require_pipelines_and_include_only_agent_runs_that_exist(tmp_path):
    def record(rel, name):
        d = tmp_path / V2.EVAL / rel
        d.mkdir(parents=True)
        (d / "agent_dev_record.json").write_text(json.dumps({"executed_specs": [{"path": f"{name}.yaml"}]}),
                                                 encoding="utf-8")
    for tuyen in ("tuyen_A", "tuyen_B"):
        for report in ("SY", "MS", "PS"):
            record(f"{tuyen}/pipeline/{report}_01", f"{tuyen}-{report}")
    record("tuyen_A/agent/SY_02", "a-sy2")
    record("tuyen_B/agent/SY_01", "b-sy1")
    got = [(name, report, [p.name for p in paths]) for name, _, report, paths in V2.runs(tmp_path)]
    assert got[0][0] == "Nhánh A (H-03)" and len(got) == 9
    assert got[-2:] == [("Tuyến A agent SY_02", "SY", ["a-sy2.yaml"]), ("Tuyến B agent SY_01", "SY", ["b-sy1.yaml"])]
    (tmp_path / V2.EVAL / "tuyen_B/pipeline/MS_01/agent_dev_record.json").unlink()
    with pytest.raises(FileNotFoundError):                   # thiếu lượt pipeline thì dừng, không bỏ qua
        list(V2.runs(tmp_path))
