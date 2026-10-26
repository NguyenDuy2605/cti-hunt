"""Local, advisory query breadth. Counts are never repair feedback or verdicts."""
from fractions import Fraction

# Quy ước cảnh báo phát triển, kiểm trên OTRF: docs/METHODOLOGY.md.
WARNING_RATIO = Fraction(95, 100)


def summarize(scope: int, candidates: int) -> dict:
    if type(scope) is not int or type(candidates) is not int or not 0 <= candidates <= scope:
        raise ValueError("Số ứng viên/phạm vi phải là số nguyên, 0 ≤ ứng viên ≤ phạm vi")
    ratio = Fraction(candidates, scope) if scope else None
    return {"scope": scope, "candidates": candidates,
            "ratio": float(ratio) if ratio is not None else None,
            "broad": ratio is not None and ratio >= WARNING_RATIO}


def from_observation(observation: dict) -> dict:
    counts = {row["stage"]: row["hits"] for row in observation["stages"]}
    return {"hunt_id": observation["hunt_id"],
            **summarize(counts["pham_vi"], counts["ung_vien"]),
            "remaining": observation["stages"][-1]["hits"]}
