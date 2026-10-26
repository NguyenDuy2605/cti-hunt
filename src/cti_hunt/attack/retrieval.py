"""Deterministic BM25 over active ATT&CK definitions, never report/label examples.

Mặc định chỉ đánh chỉ mục định nghĩa kỹ thuật. Khâu ② v2 (N3) có thể thêm procedure example đã loại trừ, truyền
tường minh qua `procedures`; câu ví dụ chỉ dùng để chấm điểm, không trả về trong kết quả tìm.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

from .catalog import _ext_id
from ..stages.s1_ingest import digest

STOP = set("a an the of in on to for with and or is are was were be been by as at from that this it its can may will using used use into their they these which also not".split())


def tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[\w]+", text.lower()) if len(t) > 1 and t not in STOP]


class TechniqueIndex:
    def __init__(self, documents: list[dict], source_sha256: str, examples: dict[str, list[str]] | None = None):
        self.documents = sorted(documents, key=lambda d: d["technique_id"])
        if not self.documents:
            raise ValueError("Kho ATT&CK không có kỹ thuật còn hiệu lực")
        self.source_sha256 = source_sha256
        examples = examples or {}
        self.example_count = sum(len(examples.get(d["technique_id"], [])) for d in self.documents)
        self.counts = [Counter(tokens(" ".join([d["name"], d["name"], d["description"],
                                                *examples.get(d["technique_id"], [])])))
                       for d in self.documents]
        self.lengths = [sum(c.values()) for c in self.counts]
        self.average = sum(self.lengths) / len(self.lengths) or 1
        self.df = Counter(t for c in self.counts for t in c)

    @classmethod
    def from_stix(cls, path: Path, procedures: list[dict] | None = None):
        """`procedures`: procedure example ĐÃ loại trừ (id, technique_id, text); None = chỉ định nghĩa."""
        raw = path.read_bytes()
        docs = []
        for o in json.loads(raw)["objects"]:
            if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            tid = _ext_id(o)
            if not tid or not o.get("description"):
                continue
            docs.append({"technique_id": tid, "name": o.get("name", ""),
                         "description": re.sub(r"\(Citation:[^)]*\)", "", o["description"]),
                         "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                     if p.get("kill_chain_name") == "mitre-attack"]})
        examples: dict[str, list[str]] = {}
        for p in sorted(procedures or [], key=lambda p: p["id"]):
            examples.setdefault(p["technique_id"], []).append(p["text"])
        index = cls(docs, digest(raw), examples)
        index.procedure_ids_sha256 = hashlib.sha256(
            "\n".join(sorted(p["id"] for p in procedures or [])).encode("utf-8")).hexdigest()
        return index

    def search(self, query: str, k: int = 8) -> list[dict]:
        if not 1 <= k <= 30:
            raise ValueError("top-k phải từ 1 đến 30")
        terms = set(tokens(query))
        scores = []
        for doc, counts, length in zip(self.documents, self.counts, self.lengths):
            score = 0.0
            for term in terms & counts.keys():
                df, tf = self.df[term], counts[term]
                idf = math.log(1 + (len(self.documents) - df + 0.5) / (df + 0.5))
                score += idf * tf * 2.5 / (tf + 1.5 * (0.25 + 0.75 * length / self.average))
            if score > 0:
                scores.append((score, doc))
        return [{**doc, "description": doc["description"][:2400], "retrieval_score": round(score, 6)}
                for score, doc in sorted(scores, key=lambda row: (-row[0], row[1]["technique_id"]))[:k]]
