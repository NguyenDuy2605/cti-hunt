"""Cổng bộ nhãn tham chiếu: MANIFEST khớp VÀ file nhãn đúng SHA256 khai trong cấu hình (Silver v1, 21/09/2026)."""
import hashlib
from types import SimpleNamespace

import pytest

from cti_hunt import cli, integrity

GOOD = b"silver v1 bytes"


def _rp(d, sha):
    return {"labels_kind": "silver", "labels_frozen_dir": str(d), "labels_frozen_xlsx": "nhan.xlsx",
            "labels_frozen_sha256": sha, "labels_xlsx_working": str(d / "khong_co.xlsx")}


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    d = tmp_path / "silver_v1"
    d.mkdir()
    (d / "nhan.xlsx").write_bytes(GOOD)
    rp = _rp(d, hashlib.sha256(GOOD).hexdigest())
    monkeypatch.setattr(cli, "_rp", lambda: rp)
    return d, rp


def freeze(d):
    return cli.cmd_freeze(SimpleNamespace(directory=str(d), overwrite=False))


def test_freeze_then_gate_passes(frozen):
    d, rp = frozen
    with pytest.raises(integrity.NotFrozenError):
        cli._labels_gate(rp)                                  # chưa có MANIFEST
    assert freeze(d) == 0
    cli._labels_gate(rp)
    assert cli._labels_xlsx_default(rp) == d / "nhan.xlsx"     # segments / check-labels đọc bản đóng băng
    assert freeze(d) == 1                                      # không ghi đè


def test_freeze_refuses_wrong_file_or_extra_files(frozen):
    d, rp = frozen
    (d / "nhan.xlsx").write_bytes(b"ban khac")
    assert freeze(d) == 1 and not (d / integrity.MANIFEST_NAME).exists()
    (d / "nhan.xlsx").write_bytes(GOOD)
    (d / "ghi_chu.txt").write_text("x")
    assert freeze(d) == 1 and not (d / integrity.MANIFEST_NAME).exists()


def test_gate_catches_edit_after_freeze_and_wrong_config_hash(frozen):
    d, rp = frozen
    assert freeze(d) == 0
    (d / "nhan.xlsx").write_bytes(GOOD + b"!")
    with pytest.raises(integrity.NotFrozenError, match="thay đổi"):
        cli._labels_gate(rp)
    (d / "nhan.xlsx").write_bytes(GOOD)
    with pytest.raises(integrity.NotFrozenError, match="SHA256"):
        cli._labels_gate({**rp, "labels_frozen_sha256": "0" * 64})
