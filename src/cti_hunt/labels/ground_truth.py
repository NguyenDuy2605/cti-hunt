"""Ground truth 24 bước Scenario 2 (v3 §3.5) và mức phủ của report đầu vào.

Mức phủ gộp của một bước = mức cao nhất trong các report: co > mot_phan > mo_ho > khong.
Cách gộp này tái lập đúng bảng "Độ phủ 5 bước trong scope" của v3 (2 rõ, 3 một phần).
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

LEVELS = ["khong", "mo_ho", "mot_phan", "co"]
REPORT_COLS = {"PS": "poshspy_mo_ta", "MS": "microsoft_mo_ta", "SY": "symantec_mo_ta"}


@dataclass
class Step:
    substep: str
    ten: str
    ky_thuat: str
    scope: str                               # trong | mot_phan | lien_ke | ngoai
    coverage: dict[str, str] = field(default_factory=dict)   # {PS|MS|SY: muc}

    def combined(self, reports: list[str] | None = None) -> str:
        vals = [v for k, v in self.coverage.items() if reports is None or k in reports]
        return max(vals, key=LEVELS.index) if vals else "khong"


def load(path: Path) -> list[Step]:
    steps = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cov = {k: (row.get(col) or "khong").strip() or "khong" for k, col in REPORT_COLS.items()}
            for k, v in cov.items():
                if v not in LEVELS:
                    raise ValueError(f"{row['substep']}: giá trị '{v}' ở cột {REPORT_COLS[k]} không hợp lệ")
            steps.append(Step(row["substep"].strip(), row["ten"], row["ky_thuat_moi"],
                              row["scope"].strip(), cov))
    return steps


def in_scope(steps: list[Step]) -> list[Step]:
    return [s for s in steps if s.scope == "trong"]
