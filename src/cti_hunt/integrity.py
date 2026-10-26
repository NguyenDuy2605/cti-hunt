"""Toàn vẹn dữ liệu và đóng băng.

Hai việc:
1. Kiểm tra file khớp SHA256 đã ghi (nhan_v1/README.txt, MANIFEST.sha256). Định dạng dòng giống
   `sha256sum`: "<64 hex>  <tên file>", nên đọc được thẳng từ README của nhãn v1.
2. Cổng chặn (require_frozen): code nào đọc 3 report đánh giá và sinh nhãn (regex IOC, prompt TTP)
   phải gọi hàm này trước. Chưa đóng băng bộ nhãn tham chiếu thì không chạy — tránh việc nhìn đầu ra hệ thống
   rồi mới gán nhãn (đo vòng tròn).
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

MANIFEST_NAME = "MANIFEST.sha256"
_LINE = re.compile(r"^\s*([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def parse_manifest(text: str) -> dict[str, str]:
    """Trả {tên file: sha256}. Bỏ qua mọi dòng không đúng định dạng (README có văn bản khác)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            out[m.group(2)] = m.group(1).lower()
    return out


def verify_dir(directory: Path, manifest_file: Path) -> list[dict]:
    expected = parse_manifest(manifest_file.read_text(encoding="utf-8"))
    if not expected:
        raise ValueError(f"Không tìm thấy dòng SHA256 nào trong {manifest_file}")
    rows = []
    for name, exp in expected.items():
        p = directory / name
        actual = sha256_file(p) if p.exists() else None
        rows.append({"file": name, "expected": exp, "actual": actual,
                     "ok": actual == exp, "missing": actual is None})
    return rows


def write_manifest(directory: Path, exclude: tuple[str, ...] = (MANIFEST_NAME, ".gitkeep")) -> Path:
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name not in exclude)
    if not files:
        raise ValueError(f"{directory} không có file nào để đóng băng")
    lines = [f"# Đóng băng lúc {datetime.now().isoformat(timespec='seconds')}. Không sửa file trong thư mục này."]
    lines += [f"{sha256_file(p)}  {p.relative_to(directory).as_posix()}" for p in files]
    out = directory / MANIFEST_NAME
    out.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))    # LF cả trên Windows (write_text đổi sang CRLF)
    return out


class NotFrozenError(RuntimeError):
    pass


def require_frozen(directory: Path) -> None:
    manifest = directory / MANIFEST_NAME
    if not manifest.exists():
        raise NotFrozenError(
            f"Chưa đóng băng: không có {manifest}. Khâu này đọc report đánh giá và sinh nhãn, "
            "chỉ được chạy sau khi bộ nhãn tham chiếu đã đóng băng (lệnh `freeze`). "
            "Trong lúc chờ, phát triển và thử trên fixture hoặc report ngoài tập đánh giá."
        )
    bad = [r for r in verify_dir(directory, manifest) if not r["ok"]]
    if bad:
        names = ", ".join(r["file"] for r in bad)
        raise NotFrozenError(f"Nhãn đóng băng đã bị thay đổi hoặc thiếu file: {names}")
