"""Nạp cấu hình. Mọi đường dẫn trong configs/*.yaml là tương đối với gốc repo."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, root: Path = ROOT) -> dict[str, Any]:
    with open(root / "configs" / f"{name}.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve(p: str | Path, root: Path = ROOT) -> Path:
    p = Path(p)
    return p if p.is_absolute() else root / p


def telemetry_catalog(version: str = "v1", root: Path = ROOT) -> Path:
    """Danh mục ③ theo phiên bản (N2 §4): v1 = tuyến A (`telemetry_catalog`), v2 = tuyến B
    (`telemetry_catalog_v2`). Hai con trỏ tách nhau nên khóa mốc v2 không làm lệch mốc tuyến A."""
    if version not in ("v1", "v2"):
        raise ValueError("phien_ban phải là v1 hoặc v2")
    return resolve(load("dataset", root)["telemetry_catalog_v2" if version == "v2" else "telemetry_catalog"], root)


def agent_config(version: str = "v1", root: Path = ROOT) -> dict:
    """Separate runtime selection; v1 files/payloads retain their pinned values."""
    if version not in ("v1", "v2"):
        raise ValueError("phien_ban phải là v1 hoặc v2")
    cfg = load("agent" if version == "v1" else "agent_v2", root)
    if version == "v2":
        from .filter_approval import POLICY, FilterReviewError
        policy = yaml.safe_load(resolve(cfg["filter_policy"], root).read_text(encoding="utf-8"))
        if policy != {"policy": POLICY, "sample_limit": 5, "scope": "hunt_run_revision", "require_complete_batch": True}:
            raise FilterReviewError("cấu hình policy không khớp thiết kế đã chốt")
        cfg["filter_policy_id"] = POLICY
    return cfg
