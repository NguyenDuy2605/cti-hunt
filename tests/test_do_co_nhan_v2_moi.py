"""Script đo có nhãn chiến dịch v2 mốc phiên bản 3 trên nhãn và hunt tổng hợp (fixture `con_labeled`; không dữ liệu
thật, không nhãn thật). Chỉ kiểm phần script thêm so với `do_co_nhan_pipeline_v2.py`: danh sách lượt, ghép MS+SY của
agent, phân tích phụ bỏ hunt rộng."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from cti_hunt.labels.ground_truth import Step

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("do_co_nhan_v2_moi", SCRIPTS / "do_co_nhan_v2_moi.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

SYS = "Microsoft-Windows-Sysmon/Operational"
STEPS = [Step("14.B", "", "", "lien_ke", {"PS": "mo_ho"}),
         Step("15.A", "", "", "trong", {"PS": "co", "MS": "co"}),
         Step("16.C", "", "", "trong", {"SY": "co"}),
         Step("16.D", "", "", "trong", {"MS": "mo_ho", "SY": "mot_phan"}),
         Step("20.B", "", "", "trong", {"SY": "khong"})]
WITH_LOG = {"14.B", "16.C", "16.D"}
OK = {"cach": "cong_loc_day_du"}


def hunt(hid, candidates, channel=SYS, eids=(1,)):
    return {"id": hid, "scope": {"channel": channel, "event_ids": list(eids)}, "candidates": candidates, "filters": []}


REMOTE = hunt("H-REMOTE", r"lower(ParentImage) LIKE '%\wmiprvse.exe' OR lower(ParentImage) LIKE '%\wsmprovhost.exe'")
ALL_EXE = hunt("H-RONG", r"lower(Image) LIKE '%.exe'")           # 5/5 sự kiện Sysmon 1 → rộng
SCRIPT_4104 = hunt("H-4104", "ScriptBlockText ILIKE '%Invoke-Command%'", "Microsoft-Windows-PowerShell/Operational", (4104,))


def measured(con, h):
    r = M.V2.measure_hunt(con, h, STEPS, ["MS", "SY"], OK, Path(f"luot/round_01/{h['id']}.yaml"))
    r["rong"] = M.breadth_of(con, h)
    return r


def _tree(root: Path, skip: str | None = None) -> None:
    rels = [f"tuyen_A/pipeline/{r}_01" for r in M.REPORTS]
    rels += [f"tuyen_A/agent/{r}_{i:02d}" for r in M.REPORTS for i in (1, 2, 3)]
    rels += [f"tuyen_B/pipeline/{r}_01" for r in M.REPORTS] + ["tuyen_B/agent/SY_01"]
    rels += [f"tuyen_B_v3/pipeline/{n}" for n, _, _ in M.V3_PIPELINE]
    rels += [f"tuyen_B_v3/agent/{n}" for n, _, _ in M.V3_AGENT]
    for rel in rels:
        if rel == skip:
            continue
        d = root / M.EVAL / rel
        d.mkdir(parents=True)
        (d / "agent_dev_record.json").write_text(
            json.dumps({"executed_specs": [{"path": rel.replace("/", "-") + ".yaml"}]}), encoding="utf-8")


def test_runs_list_campaign_with_groups_and_stop_when_a_run_is_missing(tmp_path):
    _tree(tmp_path)
    got = list(M.runs(tmp_path))
    names = [g[0] for g in got]
    assert names[0] == "Nhánh A (H-03)" and len(got) == 1 + 3 + 9 + 3 + 1 + 4 + 12
    groups = {g[0]: g[4] for g in got}
    assert groups["Tuyến B v3 pipeline SY_01"] == "phu_luc" and groups["Tuyến B v3 pipeline SY_02"] == "chinh"
    assert {n for n, g in groups.items() if g == "phu_luc"} == {
        "Tuyến B v3 pipeline SY_01", "Tuyến B v3 agent MS_01", "Tuyến B v3 agent MS_02", "Tuyến B v3 agent SY_03"}
    assert sum(g == "chinh" for g in groups.values()) == 3 + 9
    row = next(g for g in got if g[0] == "Tuyến B v3 agent MS_04")
    assert row[2] == "MS" and row[3] == [Path("tuyen_B_v3-agent-MS_04.yaml")] and "MS_01" in row[5]

    other = tmp_path / "thieu"
    _tree(other, skip="tuyen_B_v3/agent/SY_04")
    with pytest.raises(FileNotFoundError):                   # thiếu lượt thì dừng, không bỏ qua
        list(M.runs(other))


def test_pairs_follow_slot_replacement_and_combos_cover_nine(tmp_path):
    _tree(tmp_path)
    names = {g[0] for g in M.runs(tmp_path)}
    p = {n: (sy, ms) for n, sy, ms in M.pairs(names)}
    assert p["Tuyến B v3 pipeline MS+SY"] == ("Tuyến B v3 pipeline SY_02", "Tuyến B v3 pipeline MS_01")
    assert p["Tuyến B v3 agent MS+SY lượt 1 (SY_01+MS_04)"] == ("Tuyến B v3 agent SY_01", "Tuyến B v3 agent MS_04")
    assert p["Tuyến B v3 agent MS+SY lượt 2 (SY_02+MS_05)"] == ("Tuyến B v3 agent SY_02", "Tuyến B v3 agent MS_05")
    assert p["Tuyến B v3 agent MS+SY lượt 3 (SY_04+MS_03)"] == ("Tuyến B v3 agent SY_04", "Tuyến B v3 agent MS_03")
    assert p["Tuyến A agent MS+SY lượt 2 (SY_02+MS_02)"] == ("Tuyến A agent SY_02", "Tuyến A agent MS_02")
    assert len(p) == 3 + 3 + 3
    nine = M.combos(M.B3, M.V3_AGENT_SLOTS)
    assert len(nine) == 9 and len({(sy, ms) for _, sy, ms in nine}) == 9
    assert not any("SY_03" in sy or "MS_01" in ms or "MS_02" in ms for _, sy, ms in nine)   # lượt hỏng không ghép
    with pytest.raises(ValueError, match="Thiếu lượt"):
        M.pairs(names - {"Tuyến B v3 agent MS_05"})


def test_breadth_counts_candidates_over_scope_without_labels(con_labeled):
    con, _ = con_labeled
    assert M.breadth_of(con, REMOTE) == {"scope": 5, "candidates": 2, "ratio": 0.4, "broad": False}
    assert M.breadth_of(con, ALL_EXE)["broad"] is True
    assert M.breadth_of(con, SCRIPT_4104) == {"scope": 1, "candidates": 1, "ratio": 1.0, "broad": True}


def test_side_variants_differ_only_on_minimum_scope():
    rule, variant = (f for _, _, f in M.SIDE)
    tiny = {"rong": {"scope": 1, "candidates": 1, "broad": True}}
    wide = {"rong": {"scope": 99218, "candidates": 99192, "broad": True}}
    narrow = {"rong": {"scope": 2186, "candidates": 1244, "broad": False}}
    assert (rule(tiny), variant(tiny)) == (True, False)
    assert (rule(wide), variant(wide)) == (True, True)
    assert (rule(narrow), variant(narrow)) == (False, False)
    assert [k for k, _, _ in M.SIDE] == ["goc", "pham_vi_toi_thieu"] and M.MIN_SCOPE == 100


def test_summarize_all_dedupes_pairs_and_drops_only_broad_hunts_in_the_side_analysis(con_labeled, tmp_path):
    con, _ = con_labeled
    _tree(tmp_path)
    remote, broad = measured(con, REMOTE), measured(con, ALL_EXE)
    per_run = []
    for name, _, report, _, _, _ in M.runs(tmp_path):
        hunts = [remote, broad] if report in ("SY", "-") else [remote]
        per_run.append({"ten": name, "report": report, "hunts": hunts})
    rows, nine = M.summarize_all(per_run, STEPS, WITH_LOG, [], ["MS", "SY"])
    by = {r["ten"]: r for r in rows}
    sy = by["Tuyến B v3 agent SY_04"]
    assert (sy["so_hunt"], sy["tan_cong"], sy["fp"]) == (2, 2, 3)          # H-RONG gồm cả 2 sự kiện của H-REMOTE
    pair = by["Tuyến B v3 agent MS+SY lượt 3 (SY_04+MS_03)"]
    assert (pair["so_hunt"], pair["tan_cong"], pair["fp"]) == (3, 2, 3)    # sự kiện chung giữa hai report đếm một lần
    assert len(nine[M.B3]) == 9 and len(nine[M.A]) == 9

    side, side_nine = M.summarize_all(per_run, STEPS, WITH_LOG, [], ["MS", "SY"], keep=lambda h: not h["rong"]["broad"])
    side_by = {r["ten"]: r for r in side}
    assert (side_by["Tuyến B v3 agent SY_04"]["so_hunt"], side_by["Tuyến B v3 agent SY_04"]["fp"]) == (1, 0)
    assert side_by["Nhánh A (H-03)"]["so_hunt"] == 1
    assert all(r["so_hunt"] <= by[r["ten"]]["so_hunt"] for r in side)


def test_markdown_has_groups_nine_way_span_side_analysis_and_appendix(con_labeled, tmp_path):
    con, _ = con_labeled
    _tree(tmp_path)
    remote, broad = measured(con, REMOTE), measured(con, ALL_EXE)
    per_run, groups = [], {}
    for name, _, report, _, group, note in M.runs(tmp_path):
        per_run.append({"ten": name, "report": report, "hunts": [remote, broad] if "MS_05" in name else [remote]})
        groups[name] = (group, note)
    rows, nine = M.summarize_all(per_run, STEPS, WITH_LOG, [], ["MS", "SY"])
    side = {key: M.summarize_all(per_run, STEPS, WITH_LOG, [], ["MS", "SY"], keep=lambda h, f=f: not f(h))
            for key, _, f in M.SIDE}
    md = M.markdown(rows, per_run, [], nine, side, groups)
    assert md.startswith("# Đo có nhãn chiến dịch v2 mốc phiên bản 3")
    assert "| Tuyến B v3 agent SY_03 | phu_luc | hỏng kỹ thuật" in md
    assert "## 1. Năm bước Living-off-the-Land" in md and "## 6. Agent MS+SY" in md
    assert "| Tuyến B v3 | 9 | 1/4 | 2 | 0–3 | 40.00%–100.00% |" in md            # 3 cách ghép có MS_05 thêm hunt rộng
    rule, variant = md.split("## 7.1.")[1].split("## 7.2.")
    assert "theo giao thức: ứng viên/phạm vi ≥ 95%" in rule and "- Tuyến B v3 agent MS_05 · H-RONG · 5/5" in rule
    assert "phạm vi ≥ 100" in variant and "Hunt bị bỏ (0):" in variant      # phạm vi 5 < 100: biến thể không bỏ
    main_part, appendix = md.split("## 8. Phụ lục", 1)
    assert "Tuyến B v3 agent MS_02" in appendix and "| Tuyến B v3 pipeline SY_01 |" in appendix
    assert "| Tuyến B v3 agent MS_02 | 1 |" not in main_part.split("## 6.")[0]     # lượt phụ lục không vào bảng chính
    assert "buoc" not in md.replace("buoc_", "")
