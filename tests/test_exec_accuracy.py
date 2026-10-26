"""Execution accuracy khâu ⑤ (v3 §6.2): so tập kết quả, không dùng nhãn."""
import json

import pytest
import yaml

from cti_hunt import cli, integrity
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.config import ROOT
from cti_hunt.eval import exec_accuracy as ea
from cti_hunt.hunt import runner
from cti_hunt.data.store import connect

CATALOG = A.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")


def _manual_until_f01():
    """F-02 là lọc riêng của nhánh A, không có trong rule Sigma -> so với rule chỉ tính tới F-01."""
    spec = runner.load_spec(ROOT / "hunts" / "manual" / "H-03.yaml")
    return dict(spec, filters=[f for f in spec["filters"] if f["id"] == "F-01"])


def test_compare_counts():
    k = lambda i: ("UTICA", "security", i)
    c = ea.compare({k(1), k(2), k(3), k(4)}, {k(3), k(4), k(5)})
    assert (c["chung"], c["chi_chuan"], c["chi_sinh"]) == (2, 2, 1)
    assert (c["jaccard"], c["precision"], c["recall"]) == (2 / 5, 2 / 3, 2 / 4)
    assert c["vi_du_chi_sinh"] == [["UTICA", "security", 5]]
    assert ea.compare(set(), set())["jaccard"] is None


def test_manual_h03_equals_sigma_h03(con_labeled):
    con, _ = con_labeled
    ref = _manual_until_f01()
    gen = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)[0][0].to_hunt_spec()
    res = ea.evaluate(con, ref, gen)
    assert res["so_duoc"]
    for st in ("ung_vien", "cuoi"):
        assert res["giai_doan"][st]["jaccard"] == 1.0
    assert (res["giai_doan"]["ung_vien"]["chuan"], res["giai_doan"]["cuoi"]["chuan"]) == (4, 3)


def test_wrong_filter_shows_up_only_after_filtering(con_labeled):
    """Rule sinh đúng ứng viên nhưng khối lọc rộng quá: giai đoạn ứng viên khớp, giai đoạn cuối lệch."""
    con, _ = con_labeled
    ref = _manual_until_f01()
    gen = dict(ref, id="gen", filters=[dict(ref["filters"][0], where="lower(Image) LIKE '%.exe'")])
    res = ea.evaluate(con, ref, gen)
    assert res["giai_doan"]["ung_vien"]["jaccard"] == 1.0
    c = res["giai_doan"]["cuoi"]
    assert (c["sinh"], c["recall"]) == (0, 0.0)


def test_different_log_source_is_not_compared(con_labeled):
    con, _ = con_labeled
    hunts = A.compile_rule(ROOT / "hunts" / "sigma" / "H-03.yml", CATALOG)[0]
    res = ea.evaluate(con, hunts[0].to_hunt_spec(), hunts[1].to_hunt_spec())
    assert res["so_duoc"] is False and "khác phạm vi" in res["ly_do"]


def _reference(hid, where, filters=None):
    return {"id": hid, "scope": {"channel": "microsoft-windows-sysmon/operational", "event_ids": [1]},
            "candidates": where, "filters": filters or []}


def test_union_deduplicates_events_and_applies_each_rules_own_filters(work):
    # r1: hai sự kiện UTICA; bỏ rec=12. r2: rec=12 + hai sự kiện NEWYORK (cùng rec khác máy).
    filt = {"id": "F", "where": "ev_rec = 12", "ly_do": "fixture", "nguoi_chiu_trach_nhiem": "test",
            "het_han": "het_de_tai"}
    r1 = _reference("r1", "ev_host = 'UTICA' AND ev_rec IN (11, 12)", [filt])
    r2 = _reference("r2", "ev_rec = 12 OR ev_host = 'NEWYORK'")
    gen = _reference("gen", "ev_rec = 11")
    with connect(work) as con:
        result = ea.evaluate_union(con, [r1, r2], gen)
    assert result["so_duoc"] and result["cach_gop"] == "hop_tap"
    # rec=12 còn ở r2: không lấy hợp các bộ lọc rồi áp lên hợp ứng viên.
    for row in result["giai_doan"].values():
        assert (row["chuan"], row["sinh"], row["chung"]) == (4, 2, 2)
        assert (row["jaccard"], row["precision"], row["recall"]) == (0.5, 1, 0.5)


def test_union_keeps_stages_separate_and_does_not_reward_empty_sets(work):
    filt = {"id": "F", "where": "ev_rec = 12", "ly_do": "fixture", "nguoi_chiu_trach_nhiem": "test",
            "het_han": "het_de_tai"}
    ref = _reference("r", "ev_rec = 12", [filt])
    gen = _reference("g", "ev_rec = 12")
    with connect(work) as con:
        res = ea.evaluate_union(con, [ref, ref], gen)
        empty = ea.evaluate_union(con, [_reference("empty", "FALSE")], _reference("empty-gen", "FALSE"))
    assert res["giai_doan"]["ung_vien"]["chuan"] == 1  # cùng khóa không đếm hai lần
    assert res["giai_doan"]["ung_vien"]["jaccard"] == 1
    assert res["giai_doan"]["cuoi"]["jaccard"] == 0
    assert all(r["jaccard"] is None for r in empty["giai_doan"].values())


@pytest.mark.parametrize("scope_change", [
    {"channel": "security"}, {"event_ids": [3]}, {"hosts": ["UTICA"]},
    {"time_from": "2020-05-02 08:00:00"}, {"time_to": "2020-05-02 08:05:00"},
])
def test_union_rejects_any_mismatched_reference_before_queries(scope_change):
    gen, good, bad = [_reference(n, "TRUE") for n in ("gen", "good", "bad")]
    bad["scope"].update(scope_change)
    res = ea.evaluate_union(None, [good, bad], gen)  # con=None: kiểm phải dừng trước truy vấn
    assert res["so_duoc"] is False and "khác phạm vi" in res["ly_do"]
    assert "giai_doan" not in res


def test_union_without_reference_has_no_score():
    res = ea.evaluate_union(None, [], _reference("gen", "TRUE"))
    assert res["so_duoc"] is False and res["ly_do"] == "không có chuẩn"
    assert "giai_doan" not in res


def test_cli_single_reference_keeps_existing_result_fields(work, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work)})
    ref, gen = tmp_path / "ref.yaml", tmp_path / "gen.yaml"
    ref.write_text(yaml.safe_dump(_reference("ref", "TRUE")), encoding="utf-8")
    gen.write_text(yaml.safe_dump(_reference("gen", "TRUE")), encoding="utf-8")
    out = tmp_path / "single.json"
    assert cli.main(["exec-acc", str(ref), str(gen), "--out", str(out)]) == 0
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert res["chuan"] == "ref" and res["sinh"] == "gen"
    assert res["file_chuan"] == ref.as_posix() and res["sha256_chuan"] == integrity.sha256_file(ref)
    assert res["giai_doan"]["cuoi"]["jaccard"] == 1


@pytest.mark.parametrize("mismatched", [False, True])
def test_cli_records_union_and_all_reference_hashes(work, tmp_path, monkeypatch, mismatched):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work)})
    r1 = _reference("r1", "ev_host = 'UTICA'")
    r2 = _reference("r2", "ev_host = 'NEWYORK'")
    if mismatched:
        r2["scope"]["hosts"] = ["NEWYORK"]
    gen = _reference("gen", "ev_rec = 11")
    paths = []
    for spec in (r1, r2, gen):
        path = tmp_path / f"{spec['id']}.yaml"
        path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        paths.append(path)
    out = tmp_path / "comparison.json"
    code = cli.main(["exec-acc", str(paths[0]), str(paths[2]), "--ref-extra", str(paths[1]), "--out", str(out)])
    assert code == (1 if mismatched else 0)
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert res["so_duoc"] is not mismatched
    assert [(r["file"], r["sha256"]) for r in res["bo_chuan"]] == [
        (str(p), integrity.sha256_file(p)) for p in paths[:2]]
    assert res["sha256_sinh"] == integrity.sha256_file(paths[2])
    if mismatched:
        assert "giai_doan" not in res and str(paths[1]) in res["ly_do"]
    else:
        assert res["cach_gop"] == "hop_tap"
        assert res["giai_doan"]["ung_vien"]["chuan"] == 5


@pytest.mark.parametrize("bad_kind", ["scope", "yaml", "sigma_condition", "security_scope",
                                    "missing_field", "missing_file", "sql"])
def test_cli_keeps_failed_reference_and_never_scores_partial_set(work, tmp_path, monkeypatch, bad_kind):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work),
                                            "logsource_catalog": "configs/logsource_catalog.yaml"})
    good, bad, gen = (tmp_path / f'{n}.yaml' for n in ('good', 'bad', 'gen'))
    good.write_text(yaml.safe_dump(_reference("good", "TRUE")), encoding="utf-8")
    gen.write_text(yaml.safe_dump(_reference("gen", "TRUE")), encoding="utf-8")
    if bad_kind in ("scope", "sql"):
        spec = _reference("bad", "MissingFixtureColumn = 1" if bad_kind == "sql" else "TRUE")
        if bad_kind == "scope":
            spec["scope"]["event_ids"] = []
        bad.write_text(yaml.safe_dump(spec), encoding="utf-8")
    elif bad_kind == "yaml":
        bad.write_text('scope: [broken', encoding="utf-8")
    elif bad_kind != "missing_file":
        rule = {"title": "Fixture reference", "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4698}, "condition": "selection"}}
        if bad_kind == "sigma_condition":
            rule["detection"]["condition"] = "undefined_selection"
        elif bad_kind == "missing_field":
            rule["detection"]["selection"]["MissingFixtureColumn"] = "value"
        bad.write_text(yaml.safe_dump(rule), encoding="utf-8")
    if bad_kind != "sql":
        def forbidden(*args, **kwargs):
            raise AssertionError("reference input errors must stop before any hit query")
        monkeypatch.setattr(ea, "result_keys", forbidden)
    out = tmp_path / 'result.json'
    assert cli.main(["exec-acc", str(good), str(gen), "--ref-extra", str(bad), "--out", str(out)]) == 1
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert res["so_duoc"] is False and "giai_doan" not in res
    assert [r["file"] for r in res["bo_chuan"]] == [str(good), str(bad)]
    assert res["bo_chuan"][1]["sha256"] == (None if bad_kind == "missing_file" else integrity.sha256_file(bad))
    assert res["sha256_sinh"] == integrity.sha256_file(gen)
    if bad_kind == "sql":
        assert 'MissingFixtureColumn' in res["loi_do"]["ly_do"]
    else:
        assert res["bo_chuan"][1]["loi"]
        if bad_kind == "security_scope":
            error, = res["bo_chuan"][1]["loi"]
            assert error["giai_doan"] == "kiem_hunt" and error["scope"]["event_ids"] == []
            assert 'scope.event_ids' in error["ly_do"]


def test_cli_invalid_generated_hunt_still_writes_a_failure_record(work, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work)})
    ref, gen = tmp_path / 'ref.yaml', tmp_path / 'gen.yaml'
    ref.write_text(yaml.safe_dump(_reference("ref", "TRUE")), encoding="utf-8")
    gen.write_text('scope: {}', encoding="utf-8")
    out = tmp_path / 'bad-gen.json'
    assert cli.main(["exec-acc", str(ref), str(gen), "--out", str(out)]) == 1
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert res["loi_sinh"] and not res["so_duoc"] and 'giai_doan' not in res
    assert res["sha256_sinh"] == integrity.sha256_file(gen)
    assert res["bo_chuan"][0]["sha256"] == integrity.sha256_file(ref)


def test_cli_explicit_events_directory_overrides_default(work, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(tmp_path / 'must-not-open')})
    spec = tmp_path / 'hunt.yaml'
    spec.write_text(yaml.safe_dump(_reference("same", "TRUE")), encoding="utf-8")
    out = tmp_path / 'dev.json'
    assert cli.main(["exec-acc", str(spec), str(spec), "--events", str(work), "--out", str(out)]) == 0
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert res["events_dir"] == work.as_posix()
    assert res["giai_doan"]["cuoi"]["chuan"] == 5


@pytest.mark.parametrize("same_channel", [True, False])
def test_cli_retains_per_source_errors_without_scoring_a_broken_source(work, tmp_path, monkeypatch, same_channel):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work),
                                            "logsource_catalog": "configs/logsource_catalog.yaml"})
    channel = "microsoft-windows-sysmon/operational"
    good = A.CompiledHunt(id="good", title="fixture", source="sysmon",
                          scope={"channel": channel, "event_ids": [1]}, candidates="TRUE")
    bad = A.CompiledHunt(id="bad", title="fixture", source="broken",
                         scope={"channel": channel if same_channel else "security", "event_ids": []},
                         candidates="TRUE")
    monkeypatch.setattr(A, "compile_rule", lambda *args: ([good, bad], []))
    ref, gen, out = (tmp_path / n for n in ('ref.yaml', 'gen.yaml', 'result.json'))
    ref.write_text('detection: {}', encoding="utf-8")
    gen.write_text(yaml.safe_dump(_reference("gen", "TRUE")), encoding="utf-8")
    code = cli.main(["exec-acc", str(ref), str(gen), "--out", str(out)])
    res, = json.loads(out.read_text(encoding="utf-8"))
    assert code == (1 if same_channel else 0)
    assert res["so_duoc"] is not same_channel
    assert res["bo_chuan"][0]["loi"][0]["hunt_id"] == "bad"
    if same_channel:
        assert "giai_doan" not in res
    else:
        assert res["giai_doan"]["cuoi"]["jaccard"] == 1
