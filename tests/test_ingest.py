import duckdb

from cti_hunt.data.ingest import column_names


def q(work, sql):
    return duckdb.connect().execute(sql.replace("EV", f"read_parquet('{(work / 'events.parquet').as_posix()}')")).fetchall()


def test_channel_host_time(work):
    rows = dict(((r[0], r[1]), r[2:]) for r in q(work, "SELECT ev_channel, ev_rec, ev_host, CAST(ev_ts AS VARCHAR), ev_ts_src FROM EV"))
    # Sysmon dùng UtcTime (giữ mili giây); nguồn khác EventTime + 4h
    assert rows[("microsoft-windows-sysmon/operational", 10)][0] in ("UTICA", "NEWYORK")
    ts = dict(((r[0], r[1], r[2]), (r[3], r[4])) for r in q(work,
              "SELECT ev_host, ev_channel, ev_rec, CAST(ev_ts AS VARCHAR), ev_ts_src FROM EV"))
    assert ts[("UTICA", "microsoft-windows-sysmon/operational", 10)] == ("2020-05-02 07:59:09.928", "UtcTime")
    assert ts[("UTICA", "microsoft-windows-powershell/operational", 10)] == ("2020-05-02 08:02:03", "EventTime+4h")


def test_security_both_spellings_normalized(work):
    assert q(work, "SELECT count(*) FROM EV WHERE ev_channel = 'security' AND ev_eid = 4688") == [(2,)]


def test_eid1_needs_channel(work):
    assert q(work, "SELECT count(*) FROM EV WHERE ev_eid = 1") == [(6,)]
    assert q(work, "SELECT count(*) FROM EV WHERE ev_eid = 1 AND ev_channel = 'microsoft-windows-sysmon/operational'") == [(5,)]


def test_original_fields_kept_and_case_collisions_renamed(work):
    cols = {r[0] for r in q(work, "DESCRIBE SELECT * FROM EV")}
    assert {"ParentImage", "Image", "ScriptBlockText", "@timestamp", "IpAddress", "Ipaddress__2"} <= cols
    assert q(work, "SELECT IpAddress, Ipaddress__2 FROM EV WHERE ev_rec = 21") == [("10.0.0.1", "10.0.0.2")]


def test_manifest_clean(work):
    import json
    m = json.loads((work / "ingest_manifest.json").read_text(encoding="utf-8"))
    assert m["problems"] == [] and m["rows"] == 9 and m["ev_ts_null"] == 0


def test_column_names_prefix_guard():
    cols, renamed = column_names(["ev_host", "Image"])
    assert dict(cols)["ev_host"] == "src_ev_host" and renamed == {"ev_host": "src_ev_host"}
