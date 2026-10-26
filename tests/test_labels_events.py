import pytest

from cti_hunt.data.store import connect
from cti_hunt.labels import events

from .conftest import LABEL_KEYS, SYSMON, write_labels


def test_join_with_bom_and_normalization(con_labeled):
    con, s = con_labeled
    assert s["problems"] == [] and s["unmatched"] == 0
    assert s["per_step"] == {"14.B": 1, "16.C": 1, "16.D": 1}
    assert con.execute("SELECT count(buoc), count(*) FROM labeled").fetchone() == (3, 9)


def test_same_record_number_other_channel_not_labeled(con_labeled):
    con, _ = con_labeled
    # UTICA có RecordNumber 10 ở Sysmon, System và PowerShell; chỉ hai dòng được gán
    got = con.execute("SELECT ev_channel, buoc FROM labeled WHERE ev_host='UTICA' AND ev_rec=10 ORDER BY 1").fetchall()
    assert got == [("microsoft-windows-powershell/operational", "16.C"),
                   ("microsoft-windows-sysmon/operational", "14.B"), ("system", None)]


def test_unmatched_and_duplicates_reported(work, tmp_path):
    con = connect(work)
    p = write_labels(tmp_path / "bad.csv", [("utica", SYSMON, 10, "14.B"), ("utica", SYSMON, 10, "14.B"),
                                             ("nashua", SYSMON, 999, "20.B")])
    s = events.attach(con, p, LABEL_KEYS, "buoc", expected_rows=3)
    assert s["duplicate_keys"] == 1 and s["unmatched"] == 1 and len(s["problems"]) == 2


def test_wrong_key_columns_lists_real_header(work, tmp_path):
    con = connect(work)
    p = write_labels(tmp_path / "l.csv", [])
    with pytest.raises(events.LabelJoinError, match="record_number"):
        events.attach(con, p, {"ev_host": "Hostname", "ev_channel": "channel", "ev_rec": "record_number"}, "buoc")
