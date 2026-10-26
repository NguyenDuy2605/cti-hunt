import json
from pathlib import Path

import pytest

from cti_hunt import config
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.adapters.splunk import SplunkConnection, SplunkError
from cti_hunt.data.store import connect
from cti_hunt.eval import splunk_compare as C


def test_comparison_plan_matches_sources_time_and_filter_stages(work):
    con = connect(work)
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    plan = C.plans(config.ROOT / "hunts/sigma/H-03.yml", duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml")),
                   cols, "cti_dev", "2020-05-02T07:00:00Z", "2020-05-02T09:00:00Z")
    assert len(plan["stages"]) == 2  # security source cannot satisfy this fixture's fields
    assert "ev_channel=" in plan["stages"][0]["spl"] and "ev_eid=1" in plan["stages"][0]["spl"]
    assert " NOT (" in plan["stages"][1]["spl"]
    counts = [len(con.execute(s["sql"]).fetchall()) for s in plan["stages"]]
    assert counts == [4, 3]
    imported = {"events_sha256": "sha", "index": "cti_dev", "time_field": "ev_ts", "canonical_keys": list(C.KEYS),
                "operator": "fixture", "license_checked": True}
    calls = []
    class Client:
        def search(self, spl, **kwargs):
            calls.append((spl, kwargs))
            if len(calls) == 1:
                cur = con.execute("SELECT * FROM events")
                names = [x[0] for x in cur.description]
                from datetime import timezone
                rows = [dict(zip(names, r)) for r in cur.fetchall()]
                return [{**{k: r[k] for k in C.KEYS}, "_raw": json.dumps(r, default=C.json_timestamp),
                         "cti_indexed_epoch": str(r["ev_ts"].replace(tzinfo=timezone.utc).timestamp())} for r in rows]
            else:
                sql = plan["stages"][len(calls)-2]["sql"]
            return [dict(zip(C.KEYS, r)) for r in con.execute(sql).fetchall()]
    out = C.compare(con, Client(), plan, imported, "sha")
    assert all(r["jaccard"] == 1 for r in out["results"])
    assert out["raw_payload_verified"] and out["event_time_verified"]
    assert all(k["earliest_time"] == plan["earliest_time"] for _, k in calls)
    imported["events_sha256"] = "other"
    with pytest.raises(ValueError, match="Manifest"):
        C.compare(con, Client(), plan, imported, "sha")
    con.close()


def test_no_matches_and_invalid_inventory_are_not_perfect_scores():
    assert C.metrics(set(), set())["jaccard"] is None
    assert C.metrics({("A", "x", 1)}, set())["recall_vs_duckdb"] == 0
    row = {"ev_host": "A", "ev_channel": "x", "ev_rec": "1"}
    with pytest.raises(ValueError, match="Trùng"):
        C.keys([row, row])
    with pytest.raises(ValueError, match="Thiếu"):
        C.keys([{}])
    with pytest.raises(ValueError):
        C.window("2020-01-01", "2021-01-01")


@pytest.mark.parametrize("body", ['not json', '{"messages":[{"type":"ERROR","text":"bad query"}]}'])
def test_export_errors_fail_closed(monkeypatch, body):
    monkeypatch.setenv("SPLUNK_USER", "test")
    monkeypatch.setenv("SPLUNK_PASS", "test")
    class Response:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def __iter__(self): return iter([body.encode()])
    monkeypatch.setattr('urllib.request.OpenerDirector.open', lambda *a, **kw: Response())
    with pytest.raises(SplunkError):
        SplunkConnection("localhost").search("index=fixture")


def test_export_preserves_keys_fields_and_does_not_attest_import(work, tmp_path):
    con = connect(work)
    out = tmp_path / "export"
    manifest = C.export_events(con, out, "sha", "cti_dev")
    rows = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["rows"] == len(rows) == 9
    assert not manifest["license_checked"] and manifest["operator"] == ""
    assert all(row["ev_ts"].endswith("Z") for row in rows)
    assert any(row.get("ParentImage") for row in rows)
    assert len(C.keys(rows)) == 9
    with pytest.raises(FileExistsError):
        C.export_events(con, out, "sha", "cti_dev")
    con.close()


def test_mismatched_inventory_stops_before_scoring(work):
    con = connect(work)
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    catalog = duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    plan = C.plans(config.ROOT / "hunts/sigma/H-03.yml", catalog, cols,
                   "cti_dev", "2020-05-02T07:00:00Z", "2020-05-02T09:00:00Z")
    imported = {"events_sha256": "sha", "index": "cti_dev", "time_field": "ev_ts", "canonical_keys": list(C.KEYS),
                "operator": "fixture", "license_checked": True}
    class Client:
        def search(self, *args, **kwargs): return []
    with pytest.raises(ValueError, match="không khớp hoặc rỗng"):
        C.compare(con, Client(), plan, imported, "sha")
    with pytest.raises(ValueError, match="index"):
        C.plans(config.ROOT / "hunts/sigma/H-03.yml", catalog, cols, "cti | delete", "x", "y")
    con.close()


def test_localhost_redirect_rejected():
    from cti_hunt.adapters.splunk import LocalOnlyRedirect
    with pytest.raises(SplunkError, match="redirect"):
        LocalOnlyRedirect().redirect_request(None, None, 302, "", {}, "https://example.com")


@pytest.mark.parametrize("change", ["payload", "time", "missing_raw", "nan"])
def test_same_keys_but_bad_content_or_timestamp_rejected(change):
    from datetime import datetime, timezone
    row = {"ev_host": "A", "ev_channel": "security", "ev_rec": 1,
           "ev_ts": datetime(2020, 1, 1), "CommandLine": "original"}
    actual = {k: row[k] for k in C.KEYS}
    actual.update(_raw=json.dumps(row, default=C.json_timestamp),
                  cti_indexed_epoch=str(row["ev_ts"].replace(tzinfo=timezone.utc).timestamp()))
    C.verify_payload([row], [actual])
    if change == "payload": actual["_raw"] = actual["_raw"].replace("original", "changed")
    elif change == "time": actual["cti_indexed_epoch"] = str(float(actual["cti_indexed_epoch"]) + 1)
    elif change == "nan": actual["cti_indexed_epoch"] = "NaN"
    else: del actual["_raw"]
    with pytest.raises(ValueError):
        C.verify_payload([row], [actual])


def test_regex_selection_pipeline_preserves_scope_and_exclusions(work, tmp_path):
    rule = tmp_path / "regex.yml"
    rule.write_text('''title: Regex fixture
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|re|i: 'wmi(prvse|other)'
  filter_good:
    Image|endswith: '\\wmiadap.exe'
  condition: selection and not filter_good
''', encoding="utf-8")
    con = connect(work)
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    plan = C.plans(rule, duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml")),
                   columns, "cti_dev", "2020-05-02T07:00:00Z", "2020-05-02T09:00:00Z")
    assert [len(con.execute(s["sql"]).fetchall()) for s in plan["stages"]] == [1, 1]
    query = plan["stages"][1]["spl"]
    assert query.index('ev_channel=') < query.index('NOT (') < query.index(' | regex ') < query.index(' | table ')
    assert 'wmi(prvse|other)' in query
    assert len(C.split_spl(query)) == 3
    con.close()


PS_RULE = '''title: PowerShell fixture
status: experimental
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains: 'Invoke-Command'
  condition: selection
'''
PS = "microsoft-windows-powershell/operational"
SYSMON_LC = "microsoft-windows-sysmon/operational"


def _two_plans(con, tmp_path):
    rule = tmp_path / "ps.yml"
    rule.write_text(PS_RULE, encoding="utf-8")
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    catalog = duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    plans = [C.plans(path, catalog, cols, "cti_dev", "2020-05-02T07:00:00Z", "2020-05-02T09:00:00Z")
             for path in (config.ROOT / "hunts/sigma/H-03.yml", rule)]
    for name, plan in zip(("H-03", "ps"), plans):
        plan["rule"] = name
    return plans


def _splunk_from_export(con, plans, export_dir, drop_key=None):
    """Mô phỏng index chứa đúng gói JSONL đã xuất; stage trả kết quả DuckDB tương ứng."""
    from datetime import datetime
    indexed = []
    for line in (export_dir / "events.jsonl").read_bytes().splitlines():
        row = json.loads(line)
        epoch = datetime.fromisoformat(row["ev_ts"].replace("Z", "+00:00")).timestamp()
        indexed.append({**{k: row[k] for k in C.KEYS}, "_raw": line.decode("utf-8"), "cti_indexed_epoch": str(epoch)})
    by_spl = {s["spl"]: s["sql"] for p in plans for s in p["stages"]}
    calls = []

    class Client:
        def search(self, spl, **kwargs):
            calls.append(spl)
            if "cti_indexed_epoch" in spl:
                return indexed
            rows = [dict(zip(C.KEYS, r)) for r in con.execute(by_spl[spl]).fetchall()]
            return [r for r in rows if (r["ev_host"], r["ev_channel"], r["ev_rec"]) != drop_key]
    return Client(), calls


def test_import_scope_union_exclusion_and_coverage():
    plans = [{"stages": [{"scope": {"channel": SYSMON_LC, "event_ids": [12, 13, 14]}},
                         {"scope": {"channel": SYSMON_LC, "event_ids": [1]}}]},
             {"stages": [{"scope": {"channel": PS, "event_ids": [4103]}},
                         {"scope": {"channel": PS, "event_ids": [4104]}}]}]
    scope = C.import_scope(plans, [C.parse_source(PS + ":4103"), (SYSMON_LC, 12), (SYSMON_LC, 13)])
    assert scope == [{"channel": PS, "event_ids": [4104]}, {"channel": SYSMON_LC, "event_ids": [1, 14]}]
    assert C.covered({"channel": SYSMON_LC, "event_ids": [1]}, scope)
    assert not C.covered({"channel": SYSMON_LC, "event_ids": [12, 13, 14]}, scope)  # thiếu một phần cũng không so
    assert not C.covered({"channel": PS, "event_ids": [4103]}, scope)
    assert C.covered({"channel": PS, "event_ids": [4103]}, None)  # manifest cũ = đã nạp toàn bộ
    with pytest.raises(ValueError, match="không có trong phạm vi"):
        C.import_scope(plans, [("security", 4688)])
    with pytest.raises(ValueError, match="rỗng"):
        C.import_scope(plans[1:], [(PS, 4103), (PS, 4104)])
    for bad in ("security", "security:abc", ":4688"):
        with pytest.raises(ValueError, match="channel"):
            C.parse_source(bad)
    for bad in ([], [{"channel": "Security", "event_ids": [4688]}], [{"channel": "security", "event_ids": ["4688"]}],
                [{"channel": "security", "event_ids": [4688], "x": 1}], [{"channel": "security", "event_ids": []}]):
        with pytest.raises(ValueError, match="Phạm vi nạp"):
            C.check_scope(bad)


def test_scoped_export_and_suite_compare_mark_unimported_stages(work, tmp_path):
    con = connect(work)
    plans = _two_plans(con, tmp_path)
    scope = C.import_scope(plans, [(PS, 4104)])
    assert scope == [{"channel": SYSMON_LC, "event_ids": [1]}]
    manifest = C.export_events(con, tmp_path / "import", "sha", "cti_dev", scope=scope,
                               excluded=[{"channel": PS, "event_id": 4104, "reason": "fixture"}], omit_null=True)
    assert manifest["rows"] == 5 and manifest["scope"] == scope and not manifest["license_checked"]
    assert manifest["excluded_sources"][0]["reason"] == "fixture" and manifest["null_fields"] == "omitted"
    exported = [json.loads(x) for x in (tmp_path / "import/events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(None not in row.values() and "NewProcessName" not in row and row["Image"] for row in exported)
    assert manifest["ev_ts_min_utc"].endswith("Z") and manifest["ev_ts_min_utc"] < manifest["ev_ts_max_utc"]
    imported = {**manifest, "operator": "fixture", "license_checked": True}

    client, calls = _splunk_from_export(con, plans, tmp_path / "import")
    out = C.compare_suite(con, client, plans, imported, "sha")
    assert out["inventory_count"] == 5 and out["import_scope"] == scope
    h03, ps = out["rules"]
    assert [r["jaccard"] for r in h03["results"]] == [1, 1]
    assert [r["status"] for r in ps["results"]] == ["not_imported"]
    assert len(calls) == 1 + len(h03["results"])  # kiểm tập sự kiện một lần, không truy vấn stage không nạp
    assert out["summary"] == {"rules": 2, "stages": 3, "stages_compared_nonempty": 2, "stages_both_empty": 0,
                              "stages_not_imported": 1, "stages_differ": 0, "rules_with_difference": [],
                              "rules_all_not_imported": 1}

    # Splunk thiếu một khóa ở stage: báo lệch, không sửa rule
    client, _ = _splunk_from_export(con, plans, tmp_path / "import", drop_key=("UTICA", SYSMON_LC, 10))
    out = C.compare_suite(con, client, plans, imported, "sha")
    assert out["summary"]["stages_differ"] == 2 and out["summary"]["rules_with_difference"] == ["H-03"]
    assert out["rules"][0]["results"][0]["only_duckdb"] == [("UTICA", SYSMON_LC, 10)]

    # Index nạp bản giữ null nhưng manifest khai bỏ null (hoặc khai sai giá trị): dừng
    C.export_events(con, tmp_path / "with_null", "sha", "cti_dev", scope=scope)
    client, _ = _splunk_from_export(con, plans, tmp_path / "with_null")
    with pytest.raises(ValueError, match="_raw khác"):
        C.compare_suite(con, client, plans, imported, "sha")
    with pytest.raises(ValueError, match="null_fields"):
        C.compare_suite(con, client, plans, {**imported, "null_fields": "yes"}, "sha")

    # Index chứa nhiều hơn phạm vi ghi trong manifest: dừng trước khi chấm
    full = C.export_events(con, tmp_path / "full", "sha", "cti_dev")
    assert full["rows"] == 9 and "scope" not in full and full["null_fields"] == "included"
    client, _ = _splunk_from_export(con, plans, tmp_path / "full")
    with pytest.raises(ValueError, match="không khớp"):
        C.compare_suite(con, client, plans, imported, "sha")
    with pytest.raises(ValueError, match="Phạm vi nạp"):
        C.compare_suite(con, client, plans, {**imported, "scope": [{"channel": "x", "event_ids": ["1); --"]}]}, "sha")
    plans[1]["index"] = "other"
    with pytest.raises(ValueError, match="cửa sổ"):
        C.compare_suite(con, client, plans, imported, "sha")
    con.close()


def test_cli_plans_many_rules_records_blocked_and_scoped_export(work, tmp_path, monkeypatch):
    from cti_hunt import splunk_cli
    monkeypatch.setattr(splunk_cli, "dataset", lambda events: {"dataset_id": "fixture", "dataset_kind": "test"})
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "ps.yml").write_text(PS_RULE, encoding="utf-8")
    (rules / "two_conditions.yml").write_text(PS_RULE.replace("condition: selection",
                                                              "condition:\n    - selection\n    - selection"),
                                              encoding="utf-8")
    common = [str(config.ROOT / "hunts/sigma/H-03.yml"), str(rules), "--events", str(work), "--index", "cti_dev",
              "--time-from", "2020-05-02T07:00:00Z", "--time-to", "2020-05-02T09:00:00Z"]
    assert splunk_cli.main(common + ["--out", str(tmp_path / "a"), "--export-events", "--send"]) == 1
    assert splunk_cli.main(common + ["--out", str(tmp_path / "b"), "--exclude-source", PS + ":4104",
                                     "--exclude-reason", "fixture"]) == 1  # loại trừ chỉ khi xuất gói
    assert splunk_cli.main(common + ["--out", str(tmp_path / "c"), "--export-events",
                                     "--exclude-source", PS + ":4104"]) == 1  # thiếu lý do
    assert not any((tmp_path / d).exists() for d in "abc")
    assert splunk_cli.main(common + ["--out", str(tmp_path / "d"), "--export-events",
                                     "--exclude-source", PS + ":4104", "--exclude-reason", "fixture"]) == 0
    plan = json.loads((tmp_path / "d/plan.json").read_text(encoding="utf-8"))
    assert [Path(p["rule"]).name for p in plan["plans"]] == ["H-03.yml", "ps.yml"]
    assert [Path(b["rule"]).name for b in plan["blocked"]] == ["two_conditions.yml"]
    assert "một condition" in plan["blocked"][0]["error"]
    manifest = json.loads((tmp_path / "d/import/import_manifest.draft.json").read_text(encoding="utf-8"))
    assert manifest["rows"] == 5 and manifest["scope"] == [{"channel": SYSMON_LC, "event_ids": [1]}]
    assert manifest["excluded_sources"] == [{"channel": PS, "event_id": 4104, "reason": "fixture"}]
    assert manifest["operator"] == "" and manifest["license_checked"] is False
    assert manifest["null_fields"] == "omitted"


def test_cli_dataset_refuses_paths_outside_work_and_dev_data(tmp_path):
    from cti_hunt import splunk_cli
    with pytest.raises(ValueError):
        splunk_cli.dataset(tmp_path)


@pytest.mark.parametrize("value, blocked", [('"wmi\\r\\nprvse"', True), ('"wmi\\nprvse"', True), ("'wmiprvse'", False)])
def test_multiline_sigma_value_blocks_spl_plan_instead_of_false_divergence(work, tmp_path, value, blocked):
    # Kiểm chỉ đọc 1/10: contains có CRLF khớp ở DuckDB nhưng không khớp ở Splunk.
    rule = tmp_path / "multiline.yml"
    rule.write_text(f"""title: Multiline fixture
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|contains: {value}
  condition: selection
""", encoding="utf-8")
    import yaml
    loaded = yaml.safe_load(rule.read_text(encoding="utf-8"))["detection"]["selection"]["ParentImage|contains"]
    assert ("\r" in loaded or "\n" in loaded) == blocked
    con = connect(work)
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    catalog = duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    args = (rule, catalog, columns, "cti_dev", "2020-05-02T07:00:00Z", "2020-05-02T09:00:00Z")
    try:
        if blocked:
            with pytest.raises(ValueError, match="xuống dòng"):
                C.plans(*args)
        else:
            assert all("\n" not in s["spl"] and "\r" not in s["spl"] for s in C.plans(*args)["stages"])
    finally:
        con.close()


def test_single_line_allows_command_breaks_but_not_quoted_breaks():
    assert C.single_line('A="x"\n| regex B="y"') == 'A="x"\n| regex B="y"'
    assert C.single_line('A="x\\"y" B=z') == 'A="x\\"y" B=z'
    for query in ('A="x\r\ny"', "A='x\ny'", 'A="x\\\ny"'):
        with pytest.raises(ValueError, match="xuống dòng"):
            C.single_line(query)
