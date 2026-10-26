"""Procedure example ATT&CK v19.2 cho khâu ② v2 (N3): trích, loại trừ chống rò đáp án, làm sạch câu.

Procedure example = quan hệ `uses` từ nhóm/phần mềm/campaign tới kỹ thuật còn hiệu lực, có mô tả.
Loại khỏi cả kho truy xuất lẫn dữ liệu phát triển:
- câu trích từ 3 report đánh giá, nhận theo tên nguồn tham chiếu;
- câu của chủ thể liên quan APT29: nhóm G0016, phần mềm nhóm dùng, campaign gắn với nhóm và phần mềm campaign dùng.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .catalog import _ext_id
from ..stages.s1_ingest import digest

EVAL_REFERENCE_SOURCES = (
    "Microsoft Deep Dive Solorigate January 2021",
    "Microsoft Analyzing Solorigate Dec 2020",
    "Microsoft 365 Defender Solorigate",
    "Microsoft Internal Solorigate Investigation Blog",
    "Symantec RAINDROP January 2021",
    "FireEye POSHSPY April 2017",
)
APT29_GROUP = "G0016"
ACTOR_TYPES = ("intrusion-set", "malware", "tool", "campaign")
SOFTWARE_TYPES = ("malware", "tool")

LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]*)\)")
TECHNIQUE_LINK = re.compile(r"attack\.mitre\.org/techniques/", re.I)
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:[./]\d{3})?\b")
CITATION = re.compile(r"\(Citation:[^)]*\)")
TAG = re.compile(r"</?[A-Za-z][^>]*>")


def _active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def clean_text(text: str) -> tuple[str, bool]:
    """Bỏ trích dẫn, URL, thẻ HTML và mã kỹ thuật; trả (câu sạch, câu gốc có link/mã kỹ thuật không)."""
    leaked = bool(TECHNIQUE_LINK.search(text) or TECHNIQUE_ID.search(LINK.sub(r"\1", text)))
    out = CITATION.sub(" ", text)
    out = LINK.sub(lambda m: m.group(1), out)
    out = TAG.sub("", out)
    out = TECHNIQUE_ID.sub("", out)
    return re.sub(r"\s+", " ", out).strip(), leaked


def apt29_actors(objects: list[dict]) -> dict[str, dict]:
    """stix id → chủ thể liên quan APT29: nhóm, phần mềm nhóm dùng, campaign gắn với nhóm, phần mềm campaign dùng."""
    by_id = {o["id"]: o for o in objects}
    group = [o for o in objects if o.get("type") == "intrusion-set" and _ext_id(o) == APT29_GROUP]
    if len(group) != 1:
        raise ValueError(f"STIX cần đúng một nhóm {APT29_GROUP}")
    group = group[0]
    rels = [o for o in objects if o.get("type") == "relationship"]

    def targets(sources: set[str]) -> set[str]:
        return {r["target_ref"] for r in rels if r.get("relationship_type") == "uses" and r["source_ref"] in sources
                and by_id.get(r["target_ref"], {}).get("type") in SOFTWARE_TYPES}

    campaigns = {r["source_ref"] for r in rels if r.get("relationship_type") == "attributed-to"
                 and r["target_ref"] == group["id"] and by_id.get(r["source_ref"], {}).get("type") == "campaign"}
    actors = {group["id"]: "nhom"}
    actors.update({s: "phan_mem_nhom" for s in targets({group["id"]})})
    actors.update({c: "campaign_gan_nhom" for c in campaigns})
    actors.update({s: "phan_mem_campaign" for s in targets(campaigns) if s not in actors})
    return {sid: {"id": _ext_id(by_id[sid]), "name": by_id[sid].get("name", ""), "vai_tro": role}
            for sid, role in actors.items()}


def load(stix_path: Path) -> dict:
    """Mọi procedure example có mô tả, kèm lý do loại trừ (rỗng = được dùng)."""
    raw = Path(stix_path).read_bytes()
    objects = json.loads(raw)["objects"]
    by_id = {o["id"]: o for o in objects}
    actors = apt29_actors(objects)
    procedures = []
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or not o.get("description"):
            continue
        tech, src = by_id.get(o["target_ref"]), by_id.get(o["source_ref"])
        if not tech or tech.get("type") != "attack-pattern" or not src or src.get("type") not in ACTOR_TYPES:
            continue
        if not (_active(o) and _active(tech) and _active(src)):
            continue
        citations = sorted({r["source_name"] for r in o.get("external_references", [])
                            if r.get("source_name") and r["source_name"] != "mitre-attack"})
        reasons = []
        if set(citations) & set(EVAL_REFERENCE_SOURCES):
            reasons.append("trich_report_danh_gia")
        if src["id"] in actors:
            reasons.append("chu_the_apt29")
        text, leaked = clean_text(o["description"])
        procedures.append({"id": o["id"], "technique_id": _ext_id(tech), "technique_name": tech.get("name", ""),
                           "windows": "Windows" in (tech.get("x_mitre_platforms") or []),
                           "source_id": _ext_id(src), "source_type": src["type"], "citations": citations,
                           "text": text, "co_link_hoac_ma_ky_thuat": leaked, "loai_tru": reasons})
    procedures.sort(key=lambda p: p["id"])
    return {"stix_sha256": digest(raw), "procedures": procedures,
            "chu_the_apt29": sorted(actors.values(), key=lambda a: (a["vai_tro"], a["id"] or ""))}


def summary(data: dict) -> dict:
    procs = data["procedures"]
    kept = [p for p in procs if not p["loai_tru"]]
    return {"tong": len(procs), "ky_thuat": len({p["technique_id"] for p in procs}),
            "trich_report_danh_gia": sum("trich_report_danh_gia" in p["loai_tru"] for p in procs),
            "chu_the_apt29": sum("chu_the_apt29" in p["loai_tru"] for p in procs),
            "loai_tru_hop": sum(bool(p["loai_tru"]) for p in procs), "con_lai": len(kept),
            "con_lai_windows": sum(p["windows"] for p in kept)}
