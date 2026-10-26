"""E1: nạp bộ OTRF phát triển bằng `ingest-dev` và ràng buộc với `agent start --dataset-kind otrf_dev`."""
import hashlib
import io
import json
import tarfile
import zipfile

import duckdb
import pytest

from cti_hunt import cli
from cti_hunt.agent import dev_data
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import ContractA, SourceSpan, TTP

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def ev(host, channel, eid, rec, event_time, **fields):
    return {"Hostname": host, "Channel": channel, "EventID": eid, "RecordNumber": rec, "EventTime": event_time,
            **fields}


def events(offset_h=4, host="WS5.lab.local"):
    """Định dạng nxlog của OTRF: EventTime giờ địa phương, Sysmon có thêm UtcTime."""
    utc = ["2020-09-21 00:00:00.500", "2020-09-21 00:00:01.200"]
    local = [f"2020-09-20 {24 - offset_h:02d}:00:0{i}" for i in (0, 1)]
    return [
        ev(host, SYSMON, 1, 100, local[0], UtcTime=utc[0], ParentImage=r"C:\Windows\System32\services.exe",
           Image=r"C:\Windows\System32\svchost.exe"),
        ev(host, SYSMON, 10, 101, local[1], UtcTime=utc[1]),
        ev("DC1.lab.local", "Security", 4688, 500, local[1], NewProcessName=r"C:\Windows\System32\sc.exe"),
    ]


def ndjson(rows) -> bytes:
    return ("\n".join(json.dumps(r) for r in rows) + "\n").encode("utf-8")


def make_zip(path, rows, name="bo_thu_2020-09-21.json"):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(name, ndjson(rows))
    return path


def test_ingest_zip_writes_identified_dataset(tmp_path, capsys):
    src = make_zip(tmp_path / "bo_thu.zip", events())
    out = tmp_path / "dev" / "otrf-thu"
    assert cli.main(["ingest-dev", str(src), "--id", "otrf-thu", "--out", str(out)]) == 0
    m = json.loads((out / "ingest_manifest.json").read_text(encoding="utf-8"))
    assert m["dataset_kind"] == "otrf_dev" and m["dataset_id"] == "otrf-thu" and m["problems"] == []
    assert m["source_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert m["members"] == [{"ten": "bo_thu_2020-09-21.json", "sha256": hashlib.sha256(ndjson(events())).hexdigest(),
                             "bytes": len(ndjson(events()))}]
    assert m["e1"]["may"] == ["DC1", "WS5"] and m["e1"]["lech_gio"] == 4
    assert m["e1"]["kiem_lech_gio"]["cap_sysmon"] == 2 and m["e1"]["kiem_lech_gio"]["sai_so_max_giay"] <= 1
    assert not (out / ".src").exists()                     # tệp ghép tạm đã xóa, chỉ giữ SHA256
    ts = duckdb.connect().execute(f"SELECT ev_host, CAST(ev_ts AS VARCHAR) FROM read_parquet('{(out / 'events.parquet').as_posix()}') "
                                  "WHERE ev_channel = 'security'").fetchall()
    assert ts == [("DC1", "2020-09-21 00:00:01")]          # EventTime + 4h = UTC
    assert f"--dataset-sha256 {m['source_sha256']}" in capsys.readouterr().out


def test_tar_gz_with_several_members(tmp_path):
    src = tmp_path / "bo_thu.tar.gz"
    with tarfile.open(src, "w:gz") as tf:
        for i, rows in enumerate((events()[:2], events()[2:])):
            data = ndjson(rows)
            info = tarfile.TarInfo(f"phan_{i}.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    m = dev_data.ingest_dev(src, "otrf-tar", tmp_path / "out")
    assert m["rows"] == 3 and [x["ten"] for x in m["members"]] == ["phan_0.json", "phan_1.json"]


def test_winter_offset_needs_explicit_flag_and_is_verified(tmp_path):
    src = make_zip(tmp_path / "bo_dong.zip", events(offset_h=5))
    out = tmp_path / "out"
    with pytest.raises(dev_data.DevDatasetError, match=r"không phải 4h.*quan sát được.*: 5.*--offset-hours"):
        dev_data.ingest_dev(src, "otrf-dong", out)
    assert not out.exists()                                # lỗi thì không để lại events.parquet dở
    m = dev_data.ingest_dev(src, "otrf-dong", out, offset_hours=5)
    assert m["e1"]["lech_gio"] == 5


@pytest.mark.parametrize("rows, match", [
    (events(host="UTICA.dmevals.local"), "E1: có máy trùng tập đánh giá.*UTICA"),
    ([{k: v for k, v in r.items() if k != "RecordNumber"} for r in events()], "thiếu giá trị khóa"),
    (events() + [events()[0]], "không duy nhất"),
    ([{k: v for k, v in r.items() if k not in ("EventTime", "UtcTime")} for r in events()], "không có thời điểm"),
])
def test_refuses_unusable_dataset(tmp_path, rows, match):
    out = tmp_path / "out"
    with pytest.raises(dev_data.DevDatasetError, match=match):
        dev_data.ingest_dev(make_zip(tmp_path / "bo.zip", rows), "otrf-x", out)
    assert not out.exists()


def test_refuses_evaluation_source_and_protected_dirs(tmp_path):
    ds = load_cfg("dataset")
    src = make_zip(tmp_path / "bo.zip", events())
    renamed = tmp_path / ds["raw"]["path"].split("/")[-1]
    renamed.write_bytes(ndjson(events()))
    with pytest.raises(dev_data.DevDatasetError, match="tập đánh giá APT29"):
        dev_data.ingest_dev(renamed, "otrf-x", tmp_path / "a")
    for bad in (ROOT / ds["work_dir"], ROOT / ds["work_dir"] / "otrf-x", ROOT / "data" / "labels" / "otrf-x"):
        with pytest.raises(dev_data.DevDatasetError, match="E1"):
            dev_data.ingest_dev(src, "otrf-x", bad)
    assert not (ROOT / ds["work_dir"] / "otrf-x").exists()
    used = tmp_path / "da_co"
    used.mkdir()
    (used / "x.txt").write_text("x", encoding="utf-8")
    with pytest.raises(dev_data.DevDatasetError, match="thư mục mới"):
        dev_data.ingest_dev(src, "otrf-x", used)
    with pytest.raises(dev_data.DevDatasetError, match="mã bộ dữ liệu"):
        dev_data.ingest_dev(src, "../thoat", tmp_path / "b")


def test_agent_start_binds_to_ingest_dev_manifest(tmp_path, work, capsys):
    src = make_zip(tmp_path / "bo.zip", events())
    out = tmp_path / "dev"
    sha = dev_data.ingest_dev(src, "otrf-thu", out)["source_sha256"]
    dev_data.check_manifest(out, "otrf-thu", sha.upper())
    with pytest.raises(dev_data.DevDatasetError, match="--dataset-id"):
        dev_data.check_manifest(out, "otrf-khac", sha)
    with pytest.raises(dev_data.DevDatasetError, match="--dataset-sha256"):
        dev_data.check_manifest(out, "otrf-thu", "0" * 64)
    with pytest.raises(dev_data.DevDatasetError, match="không do `ingest-dev` nạp"):
        dev_data.check_manifest(work, "otrf-thu", sha)     # fixture nạp bằng ingest thường
    ca = tmp_path / "ca.json"
    ca.write_text(ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", behavior_description="Mô tả tự soạn",
        source_span=SourceSpan(segment_id="TU-001", text="Câu tự soạn."), confidence=0.9)]).model_dump_json(),
        encoding="utf-8")
    run = tmp_path / "luot"
    capsys.readouterr()
    assert cli.main(["agent", "start", "--mode", "pipeline", "--contract-a", str(ca), "--events", str(out),
                     "--dataset-kind", "otrf_dev", "--dataset-id", "otrf-thu", "--dataset-sha256", "0" * 64,
                     "--out", str(run)]) == 1
    assert "--dataset-sha256 khác SHA256" in capsys.readouterr().out and not run.exists()
