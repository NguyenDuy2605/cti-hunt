"""Nạp prompt theo phiên bản. File prompt chia mục bằng dòng `## TÊN_MỤC` (SYSTEM, USER, REPAIR...).

Hash của file ghi vào log mỗi lần chạy; sửa prompt thì tạo file phiên bản mới, không sửa tại chỗ.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path


def load_sections(path: Path, required: tuple[str, ...] = ("SYSTEM", "USER")) -> dict:
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"^## ([A-Z_]+)\s*$", text, flags=re.M)
    sections = {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}
    missing = [r for r in required if r not in sections]
    if missing:
        raise ValueError(f"{path} thiếu mục {missing}")
    return {"sections": sections, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "path": path.as_posix()}


def fill(template: str, **values: str) -> str:
    for k, v in values.items():
        template = template.replace("{" + k + "}", v)
    return template
