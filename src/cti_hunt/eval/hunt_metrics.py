"""Chỉ số chính (v3 §6.1). Hàm thuần, không đụng DuckDB, để test được bằng số tay.

- FPR = FP / (FP + TN). Mẫu số chỉ gồm sự kiện CÙNG nguồn log (channel + EventID) và cùng khoảng
  thời gian với giả thuyết — không phải 587.286.
- Luôn báo kèm FP tuyệt đối và precision.
- Sự kiện của kẻ tấn công ở bước NGOÀI scope (vd 14.B) vẫn là dương tính thật ở mức sự kiện, không
  phải FP; chỉ không được tính vào recall theo bước.
- TP recall theo bước: một bước được tính là phát hiện nếu còn ít nhất một sự kiện của bước đó sau lọc.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field

from ..labels.ground_truth import Step

# "Có mô tả trong report" = mức gộp co hoặc mot_phan (v3 §3.5: trần đầu vào 2 rõ + 3 một phần).
# mo_ho được báo riêng trong phần theo mức, không tính là có mô tả. Đổi ở đây nếu v3 đổi.
DESCRIBED_LEVELS = ("co", "mot_phan")


@dataclass
class StageResult:
    stage: str
    hits: int
    attacker_events: int
    fp: int
    tn: int
    fpr: float | None
    precision: float | None
    steps: dict[str, int] = field(default_factory=dict)     # bước -> số sự kiện còn lại
    removed: int = 0                                        # chỉ với bước lọc
    removed_attacker: int = 0                               # mục tiêu = 0 (v3 §6.2)
    removed_attacker_steps: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def stage_metrics(stage: str, hit_steps: list[str | None], negatives_in_scope: int,
                  removed_steps: list[str | None] | None = None) -> StageResult:
    """hit_steps: bước của từng sự kiện còn lại (None = hợp lệ). negatives_in_scope = FP + TN."""
    fp = sum(1 for s in hit_steps if s is None)
    attacker = len(hit_steps) - fp
    removed_steps = removed_steps or []
    rm_att = [s for s in removed_steps if s is not None]
    return StageResult(
        stage=stage, hits=len(hit_steps), attacker_events=attacker, fp=fp,
        tn=negatives_in_scope - fp, fpr=_ratio(fp, negatives_in_scope),
        precision=_ratio(attacker, len(hit_steps)),
        steps=dict(sorted(Counter(s for s in hit_steps if s is not None).items())),
        removed=len(removed_steps), removed_attacker=len(rm_att),
        removed_attacker_steps=dict(sorted(Counter(rm_att).items())),
    )


def step_recall(detected: set[str], steps: list[Step], steps_with_log: set[str],
                independent_reports: list[str]) -> dict:
    scoped = [s for s in steps if s.scope == "trong"]

    def block(reports: list[str] | None) -> dict:
        described = [s for s in scoped if s.combined(reports) in DESCRIBED_LEVELS]
        practical = [s for s in described if s.substep in steps_with_log]
        by_level = {}
        for s in scoped:
            lv = s.combined(reports)
            d = by_level.setdefault(lv, {"buoc": [], "phat_hien": []})
            d["buoc"].append(s.substep)
            if s.substep in detected:
                d["phat_hien"].append(s.substep)

        def frac(group):
            got = sorted(s.substep for s in group if s.substep in detected)
            return {"phat_hien": len(got), "mau_so": len(group), "buoc_phat_hien": got,
                    "buoc_bo_sot": sorted(s.substep for s in group if s.substep not in detected)}
        return {"tuyet_doi": frac(scoped), "tran_dau_vao": frac(described),
                "tran_thuc_te": frac(practical), "theo_muc_phu": by_level}

    return {"tat_ca_report": block(None),
            "report_doc_lap": {"reports": independent_reports, **block(independent_reports)},
            "buoc_ngoai_scope_bat_duoc": sorted(detected - {s.substep for s in scoped})}
