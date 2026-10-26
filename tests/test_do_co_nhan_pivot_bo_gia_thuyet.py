"""Script có nhãn B5/B3 (pivot, bộ giả thuyết) trên nhãn và hunt tổng hợp (fixture `con_labeled`; không dữ liệu thật,
không nhãn thật). Kiểm phần script thêm: bước chỉ nhờ pivot, phân loại hunt, bảng markdown, đọc pivot_depth."""
import importlib.util
import json
import sys
from pathlib import Path

from cti_hunt.labels.ground_truth import Step

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("do_co_nhan_pivot_bo_gia_thuyet", SCRIPTS / "do_co_nhan_pivot_bo_gia_thuyet.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
M = P.M

SYS = "Microsoft-Windows-Sysmon/Operational"
STEPS = [Step("14.B", "", "", "lien_ke", {"PS": "mo_ho"}),
         Step("15.A", "", "", "trong", {"PS": "co", "MS": "co"}),
         Step("16.C", "", "", "trong", {"SY": "co"}),
         Step("16.D", "", "", "trong", {"MS": "mo_ho", "SY": "mot_phan"}),
         Step("20.B", "", "", "trong", {"SY": "khong"})]
SCOPED = {s.substep for s in STEPS if s.scope == "trong"}
OK = {"cach": "cong_loc_day_du"}


def hunt(hid, candidates, channel=SYS, eids=(1,)):
    return {"id": hid, "scope": {"channel": channel, "event_ids": list(eids)}, "candidates": candidates, "filters": []}


REMOTE = hunt("H-REMOTE", r"lower(ParentImage) LIKE '%\wmiprvse.exe' OR lower(ParentImage) LIKE '%\wsmprovhost.exe'")
ALL_EXE = hunt("H-RONG", r"lower(Image) LIKE '%.exe'")
SCRIPT_4104 = hunt("H-4104", "ScriptBlockText ILIKE '%Invoke-Command%'", "Microsoft-Windows-PowerShell/Operational", (4104,))
NOTEPAD = hunt("H-NOTEPAD", r"lower(Image) LIKE '%notepad.exe'")
SYSTEM = hunt("H-SYSTEM", "1=1", "System", (1,))


def measured(con, h, depth=0, rnd=1, labeled=True):
    r = M.V2.measure_hunt(con, h, STEPS, ["MS", "SY"], OK, Path(f"luot/round_{rnd:02d}/{h['id']}.yaml"))
    r.update({"pivot_depth": depth, "kenh_co_nhan": labeled, "hypothesis_id": h["id"],
              "gia_thuyet": f"giả thuyết | {h['id']}", "linked_ttps": ["T1047"]})
    return r


def _tree(root: Path) -> None:
    rels = [f"tuyen_A/pipeline/{r}_01" for r in M.REPORTS]
    rels += [f"tuyen_A/agent/{r}_{i:02d}" for r in M.REPORTS for i in (1, 2, 3)]
    rels += [f"tuyen_B/pipeline/{r}_01" for r in M.REPORTS] + ["tuyen_B/agent/SY_01"]
    rels += [f"tuyen_B_v3/pipeline/{n}" for n, _, _ in M.V3_PIPELINE]
    rels += [f"tuyen_B_v3/agent/{n}" for n, _, _ in M.V3_AGENT]
    for rel in rels:
        d = root / M.EVAL / rel
        d.mkdir(parents=True)
        specs = [{"path": f"data\\eval\\{rel}\\round_01\\a.yaml", "pivot_depth": 0},
                 {"path": f"data/eval/{rel}/round_02/b.yaml", "pivot_depth": 1}]
        (d / "agent_dev_record.json").write_text(json.dumps({"executed_specs": specs}), encoding="utf-8")


def test_pivot_row_tach_buoc_chi_nho_pivot(con_labeled):
    con, _ = con_labeled
    hunts = [measured(con, REMOTE), measured(con, SCRIPT_4104, 1, 2), measured(con, ALL_EXE, 1, 2)]
    for h in hunts:
        h["_luot"] = "L"
    r = P.pivot_row("L", hunts, SCOPED)
    assert (r["so_vong"], r["so_vong_pivot"], r["so_hunt"], r["so_hunt_pivot"]) == (2, 1, 3, 2)
    assert r["buoc5_tu_pivot"] == ["16.C", "16.D"]
    assert r["buoc5_chi_nho_pivot"] == ["16.C"]               # 16.D hunt thường cũng bắt
    assert r["buoc_khac_chi_nho_pivot"] == []                 # 14.B hunt thường cũng bắt
    assert (r["tan_cong_pivot"], r["fp_pivot"]) == (3, 3)     # hợp sự kiện của hai hunt pivot, đếm một lần


def test_classify(con_labeled):
    con, _ = con_labeled
    assert P.classify(measured(con, REMOTE), SCOPED) == "bat_buoc_5"
    assert P.classify(measured(con, NOTEPAD), SCOPED) == "chi_nhieu"
    assert P.classify(measured(con, hunt("H-0", "1=0")), SCOPED) == "rong"
    assert P.classify(measured(con, SYSTEM, labeled=False), SCOPED) == "khong_danh_gia_duoc"
    only_14b = hunt("H-14B", r"lower(ParentImage) LIKE '%\wmiprvse.exe'")
    assert P.classify(measured(con, only_14b), SCOPED) == "bat_buoc_ngoai_5"


def test_build_va_markdown(con_labeled, tmp_path):
    con, _ = con_labeled
    _tree(tmp_path)
    per_run = []
    for name, tuyen, report, _, group, note in M.runs(tmp_path):
        if report == "-":
            continue
        hunts = [measured(con, NOTEPAD), measured(con, SCRIPT_4104, 1, 2)] if report == "SY" else \
            [measured(con, REMOTE), measured(con, SYSTEM, 1, 2, labeled=False)]
        per_run.append({"ten": name, "tuyen": tuyen, "report": report, "nhom": group, "ghi_chu": note, "hunts": hunts})
    res = P.build(per_run, SCOPED)
    piv = {r["ten"]: r for r in res["pivot"]}
    assert piv["Tuyến A pipeline SY_01"]["buoc5_chi_nho_pivot"] == ["16.C"]
    assert piv["Tuyến A pipeline MS_01"]["buoc5_chi_nho_pivot"] == []
    assert piv["Tuyến A pipeline MS_01"]["fp_pivot_kenh_khong_nhan"] == 1
    pairs = {r["ten"]: r for r in res["pivot_ms_sy"]}
    pair = pairs["Tuyến A pipeline MS+SY"]
    assert (pair["so_vong"], pair["so_hunt_pivot"], pair["buoc5_chi_nho_pivot"]) == (4, 2, ["16.C"])
    assert len(pairs) == 3 + 3 + 3
    assert res["phan_loai_theo_nhom"]["Tuyến B v3 agent"] == {
        "bat_buoc_5": 9, "bat_buoc_ngoai_5": 0, "chi_nhieu": 3, "rong": 0, "khong_danh_gia_duoc": 6}  # 3 SY + 6 PS/MS
    md = P.markdown(res)
    assert md.startswith("# Giá trị vòng pivot và bộ giả thuyết đã kiểm chứng — CÓ NHÃN")
    main_part, appendix = md.split("## 6. Phụ lục", 1)
    assert "| Tuyến B v3 agent MS_02 |" in appendix and "| Tuyến B v3 agent MS_02 |" not in main_part
    assert "| Tuyến A pipeline SY_01 | 2 (1) | 2 (1) | 16.C | **16.C** | — | 1 / 0 |" in md
    assert "| Tuyến A pipeline MS_01 | 2 (1) | 2 (1) | — | **—** | — | 0 / 1 (kênh không nhãn 1) |" in md
    assert "giả thuyết / H-REMOTE" in md                       # dấu | trong câu không vỡ bảng
    assert "buoc" not in md.replace("buoc_", "")


def test_depths_doc_pivot_depth_theo_duong_dan(tmp_path):
    _tree(tmp_path)
    d = P.depths(tmp_path)
    assert d[P._key("data/eval/tuyen_A/agent/SY_01/round_01/a.yaml")] == 0
    assert d[P._key("data\\eval\\tuyen_A\\agent\\SY_01\\round_02\\b.yaml")] == 1
    assert len(d) == 2 * sum(1 for _ in (tmp_path / M.EVAL).glob("*/*/*/agent_dev_record.json"))
