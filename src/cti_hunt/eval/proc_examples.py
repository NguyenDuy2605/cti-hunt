"""Tập phát triển khâu ② v2 từ procedure example và đo recall@k của truy xuất BM25 (N3 §3.2, §2.1).

- Tập phát triển lấy từ câu KHÔNG bị loại trừ (N3 §3.1), chỉ kỹ thuật có nền tảng Windows, phân tầng theo kỹ thuật
  (vòng lần lượt qua các kỹ thuật), seed cố định; tách 400 câu chỉnh / 200 câu giữ lại.
- Câu của tập phát triển bị bỏ khỏi kho truy xuất, nếu không truy xuất sẽ tìm lại chính câu đó.
- Chấm: một câu một mã đúng (nhãn của ATT&CK). Câu gốc có link/mã kỹ thuật được gắn cờ để báo riêng.
"""
from __future__ import annotations

import hashlib
import json
import random

SEED = 20261001
SIZE = 600
HELD_OUT = 200
K = 15
BATCH = 10


def build_dev_set(procedures: list[dict], size: int = SIZE, held_out: int = HELD_OUT,
                  seed: int = SEED) -> list[dict]:
    if not 0 < held_out < size:
        raise ValueError("Số câu giữ lại phải nằm giữa 0 và cỡ tập")
    by_tech: dict[str, list[dict]] = {}
    for p in sorted(procedures, key=lambda p: p["id"]):
        if not p["loai_tru"] and p["windows"] and p["text"]:
            by_tech.setdefault(p["technique_id"], []).append(p)
    rng = random.Random(seed)
    techniques = sorted(by_tech)
    rng.shuffle(techniques)
    for t in techniques:
        rng.shuffle(by_tech[t])
    chosen, depth = [], 0
    while len(chosen) < size:
        layer = [by_tech[t][depth] for t in techniques if depth < len(by_tech[t])]
        if not layer:
            raise ValueError(f"Không đủ câu: cần {size}, có {len(chosen)}")
        chosen.extend(layer[:size - len(chosen)])
        depth += 1
    return [{"id": p["id"], "technique_id": p["technique_id"], "text": p["text"],
             "co_link_hoac_ma_ky_thuat": p["co_link_hoac_ma_ky_thuat"],
             # rải đều câu giữ lại theo thứ tự chọn, đúng `held_out` câu
             "tap": "giu_lai" if (i + 1) * held_out // size > i * held_out // size else "chinh"}
            for i, p in enumerate(chosen)]


def dev_set_jsonl(items: list[dict]) -> str:
    return "".join(json.dumps(i, ensure_ascii=False, sort_keys=True) + "\n" for i in items)


def dev_set_manifest(items: list[dict], stix_sha256: str, seed: int = SEED) -> dict:
    text = dev_set_jsonl(items)
    out = {"stix_sha256": stix_sha256, "seed": seed, "jsonl_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
           "so_cau": len(items), "so_ky_thuat": len({i["technique_id"] for i in items})}
    for tap in ("chinh", "giu_lai"):
        rows = [i for i in items if i["tap"] == tap]
        out[tap] = {"so_cau": len(rows), "so_ky_thuat": len({i["technique_id"] for i in rows}),
                    "co_link_hoac_ma_ky_thuat": sum(i["co_link_hoac_ma_ky_thuat"] for i in rows)}
    return out


def index_procedures(procedures: list[dict], dev_items: list[dict]) -> list[dict]:
    """Kho truy xuất: câu không bị loại trừ và không thuộc tập phát triển."""
    dev_ids = {i["id"] for i in dev_items}
    return [p for p in procedures if not p["loai_tru"] and p["id"] not in dev_ids and p["text"]]


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def _hit(item: dict, found: list[str]) -> dict:
    gold = item["technique_id"]
    return {"id": item["id"], "dung_ma": gold in found,
            "cung_ky_thuat_cha": any(_parent(t) == _parent(gold) for t in found),
            "co_link_hoac_ma_ky_thuat": item["co_link_hoac_ma_ky_thuat"]}


def _summary(rows: list[dict]) -> dict:
    def part(sub):
        n = len(sub)
        return {"so_cau": n, "dung_ma": sum(r["dung_ma"] for r in sub),
                "cung_ky_thuat_cha": sum(r["cung_ky_thuat_cha"] for r in sub),
                "recall_dung_ma": round(sum(r["dung_ma"] for r in sub) / n, 4) if n else None,
                "recall_cung_cha": round(sum(r["cung_ky_thuat_cha"] for r in sub) / n, 4) if n else None}
    return {"tat_ca": part(rows), "khong_link_ma": part([r for r in rows if not r["co_link_hoac_ma_ky_thuat"]]),
            "co_link_ma": part([r for r in rows if r["co_link_hoac_ma_ky_thuat"]])}


def dev_segments(items: list[dict]) -> list[dict]:
    """Mỗi câu thành một 'đoạn văn' để chạy qua đúng khâu ② (lô = `batch` câu)."""
    return [{"ma_doan": f"DEV-{n:04d}", "report": "DEV", "loai": "đoạn văn", "van_ban": i["text"], "cau_id": i["id"]}
            for n, i in enumerate(items, start=1)]


def score_dev(items: list[dict], segments: list[dict], ttps: list) -> dict:
    """Recall = mã đúng có trong đầu ra của câu đó; precision trên số mã đầu ra (giới hạn dưới, N3 §3.2)."""
    predicted: dict[str, set[str]] = {}
    for t in ttps:
        predicted.setdefault(t.source_span.segment_id, set()).add(t.technique_id)
    rows = []
    for item, seg in zip(items, segments):
        found = predicted.get(seg["ma_doan"], set())
        gold = item["technique_id"]
        rows.append({"id": item["id"], "dung_ma": gold in found,
                     "cung_ky_thuat_cha": any(_parent(t) == _parent(gold) for t in found),
                     "so_ma_dau_ra": len(found), "ma_dung_trong_dau_ra": int(gold in found),
                     "co_link_hoac_ma_ky_thuat": item["co_link_hoac_ma_ky_thuat"]})

    def part(sub):
        n, out = len(sub), sum(r["so_ma_dau_ra"] for r in sub)
        hits = sum(r["dung_ma"] for r in sub)
        return {"so_cau": n, "dung_ma": hits, "cung_ky_thuat_cha": sum(r["cung_ky_thuat_cha"] for r in sub),
                "so_ma_dau_ra": out, "recall": round(hits / n, 4) if n else None,
                "precision_gioi_han_duoi": round(sum(r["ma_dung_trong_dau_ra"] for r in sub) / out, 4) if out else None}
    return {"tat_ca": part(rows), "khong_link_ma": part([r for r in rows if not r["co_link_hoac_ma_ky_thuat"]]),
            "co_link_ma": part([r for r in rows if r["co_link_hoac_ma_ky_thuat"]]), "theo_cau": rows}


def retrieval_recall(index, items: list[dict], k: int = K, batch: int = BATCH) -> dict:
    """recall@k theo từng câu và theo lô `batch` câu ghép (giống cách khâu ② truy xuất theo lô đoạn)."""
    per_sentence = [_hit(i, [d["technique_id"] for d in index.search(i["text"], k)]) for i in items]
    per_batch = []
    for start in range(0, len(items), batch):
        group = items[start:start + batch]
        found = [d["technique_id"] for d in index.search(" ".join(i["text"] for i in group), k)]
        per_batch.extend(_hit(i, found) for i in group)
    return {"k": k, "lo": batch, "theo_cau": _summary(per_sentence), "theo_lo": _summary(per_batch)}
