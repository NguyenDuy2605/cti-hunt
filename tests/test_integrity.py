import pytest

from cti_hunt import integrity

README = """NHÃN V1
SHA256:
{h}  a.csv
Quy tắc: không sửa file.
"""


def test_readme_manifest_and_tamper(tmp_path):
    (tmp_path / "a.csv").write_text("x", encoding="utf-8")
    h = integrity.sha256_file(tmp_path / "a.csv")
    (tmp_path / "README.txt").write_text(README.format(h=h), encoding="utf-8")
    assert integrity.parse_manifest(README.format(h=h)) == {"a.csv": h}
    assert all(r["ok"] for r in integrity.verify_dir(tmp_path, tmp_path / "README.txt"))
    (tmp_path / "a.csv").write_text("y", encoding="utf-8")
    assert not integrity.verify_dir(tmp_path, tmp_path / "README.txt")[0]["ok"]


def test_require_frozen_gate(tmp_path):
    with pytest.raises(integrity.NotFrozenError, match="Chưa đóng băng"):
        integrity.require_frozen(tmp_path)
    (tmp_path / "gan_nhan_report.xlsx").write_bytes(b"abc")
    integrity.write_manifest(tmp_path)
    integrity.require_frozen(tmp_path)
    (tmp_path / "gan_nhan_report.xlsx").write_bytes(b"abd")
    with pytest.raises(integrity.NotFrozenError, match="thay đổi"):
        integrity.require_frozen(tmp_path)
