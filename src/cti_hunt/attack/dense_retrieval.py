"""Truy xuất kỹ thuật ATT&CK theo nghĩa (embedding) và gộp với BM25 bằng Reciprocal Rank Fusion.

Cùng kho với ``retrieval.TechniqueIndex``: chỉ định nghĩa kỹ thuật còn hiệu lực, không câu ví dụ của report hay nhãn.
Định nghĩa dài hơn giới hạn của mô hình nên được cắt thành khúc theo câu; điểm của một kỹ thuật là điểm khúc cao nhất.

Hai cách lưu vector cho cùng một chỉ mục:
- ``DenseIndex.search``: nhân ma trận numpy (tìm chính xác, đủ nhanh với vài nghìn vector);
- ``SqliteVecStore``: bảng ``vec0`` của sqlite-vec trong một tệp SQLite, cũng tìm chính xác; kết quả phải trùng numpy.

Bộ mã hóa là một hàm ``list[str] -> np.ndarray`` (vector đã chuẩn hóa độ dài 1). ``load_encoder`` dựng hàm đó từ
sentence-transformers; test dùng bộ mã hóa giả nên không cần tải mô hình.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Sequence
from pathlib import Path

import numpy as np

Encoder = Callable[[list[str]], np.ndarray]

# Tiền tố truy vấn/văn bản lấy theo thẻ mô hình (model card) của từng mô hình; không chỉnh theo kết quả đo.
MODELS = {
    "bge-base": {"name": "BAAI/bge-base-en-v1.5", "revision": "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
                 "query_prefix": "Represent this sentence for searching relevant passages: ", "passage_prefix": ""},
    "e5-base": {"name": "intfloat/e5-base-v2", "revision": "f52bf8ec8c7124536f0efb74aca902b2995e5bcd",
                "query_prefix": "query: ", "passage_prefix": "passage: "},
}
RRF_K = 60        # hằng số của Cormack và cộng sự (2009); không chỉnh
RRF_DEPTH = 30    # mỗi bảng xếp hạng đem gộp lấy 30 kỹ thuật đầu (trần của TechniqueIndex.search)
# Cấu hình khâu ② dùng khi bật cách lai: đúng cấu hình đã chọn trên đề luyện và đo trên đề thi (docs/METHODOLOGY.md §2.4).
LAI_MODEL, LAI_CHUNK = "e5-base", 300


def default_cache_dir() -> Path:
    """Bộ đệm vector của kho định nghĩa; đặt ``CTI_EMBED_CACHE`` để đổi chỗ."""
    import os

    from .. import config
    return Path(os.environ.get("CTI_EMBED_CACHE") or config.resolve("data/work/embedding_cache"))

_SENT = re.compile(r"(?<=[.!?])\s+")


def chunk_text(text: str, max_words: int) -> list[str]:
    """Gom câu liền nhau thành khúc ≤ ``max_words`` từ; một câu dài hơn trần thì cắt theo từ."""
    if max_words < 1:
        raise ValueError("max_words phải ≥ 1")
    chunks, cur = [], []
    for sent in (s for s in _SENT.split(text.strip()) if s):
        words = sent.split()
        while len(words) > max_words:
            if cur:
                chunks.append(" ".join(cur))
                cur = []
            chunks.append(" ".join(words[:max_words]))
            words = words[max_words:]
        if cur and len(cur) + len(words) > max_words:
            chunks.append(" ".join(cur))
            cur = []
        cur += words
    if cur:
        chunks.append(" ".join(cur))
    return chunks


def load_encoder(model_key: str, cache_folder: str | None = None, batch_size: int = 32) -> Encoder:
    """Bộ mã hóa thật, ghim đúng revision; chạy CPU."""
    from sentence_transformers import SentenceTransformer

    spec = MODELS[model_key]
    model = SentenceTransformer(spec["name"], revision=spec["revision"], device="cpu", cache_folder=cache_folder)

    def encode(texts: list[str]) -> np.ndarray:
        return np.asarray(model.encode(texts, batch_size=batch_size, normalize_embeddings=True,
                                       show_progress_bar=False), dtype=np.float32)
    return encode


class DenseIndex:
    def __init__(self, documents: Sequence[dict], encoder: Encoder, model_key: str, chunk_words: int,
                 cache_dir: Path | None = None, spec: dict | None = None):
        self.spec = spec or MODELS[model_key]
        self.model_key, self.chunk_words, self.encoder = model_key, chunk_words, encoder
        self.documents = sorted(documents, key=lambda d: d["technique_id"])
        if not self.documents:
            raise ValueError("Kho ATT&CK không có kỹ thuật còn hiệu lực")
        self.chunks: list[str] = []
        self.starts: list[int] = []          # khúc đầu tiên của từng kỹ thuật (khúc xếp liền nhau theo kỹ thuật)
        self.chunk_tech: list[int] = []
        for i, d in enumerate(self.documents):
            self.starts.append(len(self.chunks))
            for part in chunk_text(d["description"], chunk_words) or [""]:
                self.chunks.append(f"{d['name']}: {part}".strip())
                self.chunk_tech.append(i)
        self.key = hashlib.sha256(json.dumps(
            {"model": self.spec["name"], "revision": self.spec.get("revision"),
             "passage_prefix": self.spec["passage_prefix"], "chunk_words": chunk_words, "chunks": self.chunks},
            ensure_ascii=False).encode("utf-8")).hexdigest()
        self.matrix = self._embed_chunks(cache_dir)

    def _embed_chunks(self, cache_dir: Path | None) -> np.ndarray:
        path = cache_dir / f"{self.model_key}_{self.chunk_words}_{self.key[:16]}.npy" if cache_dir else None
        if path and path.exists():
            m = np.load(path)
            if m.shape[0] == len(self.chunks):
                return m
        m = self.encoder([self.spec["passage_prefix"] + c for c in self.chunks]).astype(np.float32)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            np.save(path, m)
        return m

    @property
    def max_chunks_per_technique(self) -> int:
        ends = self.starts[1:] + [len(self.chunks)]
        return max(e - s for s, e in zip(self.starts, ends))

    def embed_queries(self, queries: list[str]) -> np.ndarray:
        return self.encoder([self.spec["query_prefix"] + q for q in queries]).astype(np.float32)

    def _rank(self, technique_scores: np.ndarray, k: int) -> list[dict]:
        order = np.lexsort((np.arange(len(technique_scores)), -technique_scores))[:k]
        return [{"technique_id": self.documents[i]["technique_id"], "name": self.documents[i]["name"],
                 "tactics": self.documents[i].get("tactics", []),
                 "retrieval_score": round(float(technique_scores[i]), 6)} for i in order]

    def search_vectors(self, qvecs: np.ndarray, k: int = 8) -> list[list[dict]]:
        if not 1 <= k <= 30:
            raise ValueError("top-k phải từ 1 đến 30")
        sims = qvecs @ self.matrix.T                                    # cosine vì mọi vector đã chuẩn hóa
        per_tech = np.maximum.reduceat(sims, self.starts, axis=1)      # điểm kỹ thuật = khúc cao nhất
        return [self._rank(row, k) for row in per_tech]

    def search_many(self, queries: list[str], k: int = 8) -> list[list[dict]]:
        return self.search_vectors(self.embed_queries(queries), k) if queries else []

    def search(self, query: str, k: int = 8) -> list[dict]:
        return self.search_many([query], k)[0]


class SqliteVecStore:
    """Lưu các khúc và vector của một ``DenseIndex`` vào tệp SQLite (bảng ``vec0`` của sqlite-vec)."""

    def __init__(self, path: Path | str):
        import sqlite_vec

        self.conn = sqlite3.connect(str(path))
        self.conn.enable_load_extension(True)
        sqlite_vec.load(self.conn)
        self.conn.enable_load_extension(False)

    def write(self, index: DenseIndex) -> None:
        dim = index.matrix.shape[1]
        c = self.conn
        c.executescript("DROP TABLE IF EXISTS meta; DROP TABLE IF EXISTS chunks; DROP TABLE IF EXISTS vec_chunks;")
        c.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("CREATE TABLE chunks (id INTEGER PRIMARY KEY, technique_id TEXT, name TEXT, tactics TEXT, text TEXT)")
        c.execute(f"CREATE VIRTUAL TABLE vec_chunks USING vec0(embedding float[{dim}] distance_metric=cosine)")
        c.executemany("INSERT INTO meta VALUES (?, ?)",
                      [("index_key", index.key), ("model", index.spec["name"]), ("chunk_words", str(index.chunk_words)),
                       ("max_chunks_per_technique", str(index.max_chunks_per_technique))])
        rows = []
        for cid, (text, ti) in enumerate(zip(index.chunks, index.chunk_tech), start=1):
            d = index.documents[ti]
            rows.append((cid, d["technique_id"], d["name"], json.dumps(d.get("tactics", [])), text))
        c.executemany("INSERT INTO chunks VALUES (?, ?, ?, ?, ?)", rows)
        c.executemany("INSERT INTO vec_chunks(rowid, embedding) VALUES (?, ?)",
                      [(cid, index.matrix[cid - 1].tobytes()) for cid in range(1, len(index.chunks) + 1)])
        c.commit()

    def meta(self, key: str) -> str:
        return self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()[0]

    def search_vector(self, qvec: np.ndarray, k: int = 8) -> list[dict]:
        """Tìm chính xác: lấy đủ k × (số khúc lớn nhất của một kỹ thuật) khúc gần nhất thì chắc chắn gặp k kỹ thuật
        đầu, vì điểm kỹ thuật là điểm khúc cao nhất của nó."""
        if not 1 <= k <= 30:
            raise ValueError("top-k phải từ 1 đến 30")
        n = min(k * int(self.meta("max_chunks_per_technique")),
                self.conn.execute("SELECT count(*) FROM chunks").fetchone()[0])
        rows = self.conn.execute(
            "SELECT c.technique_id, c.name, c.tactics, v.distance FROM vec_chunks v JOIN chunks c ON c.id = v.rowid "
            "WHERE v.embedding MATCH ? AND k = ? ORDER BY v.distance",
            (np.asarray(qvec, dtype=np.float32).tobytes(), n)).fetchall()
        best: dict[str, tuple[float, str, str]] = {}
        for tid, name, tactics, dist in rows:
            score = 1.0 - dist
            if tid not in best or score > best[tid][0]:
                best[tid] = (score, name, tactics)
        ranked = sorted(best.items(), key=lambda kv: (-round(kv[1][0], 6), kv[0]))[:k]
        return [{"technique_id": t, "name": n, "tactics": json.loads(ta), "retrieval_score": round(s, 6)}
                for t, (s, n, ta) in ranked]


def rrf(rankings: Sequence[Sequence[str]], k: int = 8, k_const: int = RRF_K, depth: int = RRF_DEPTH) -> list[dict]:
    """Reciprocal Rank Fusion: điểm = Σ 1 / (k_const + hạng), hạng tính từ 1; bằng điểm thì theo mã kỹ thuật."""
    score: dict[str, float] = {}
    for ranking in rankings:
        for rank, tid in enumerate(ranking[:depth], start=1):
            score[tid] = score.get(tid, 0.0) + 1.0 / (k_const + rank)
    ranked = sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
    return [{"technique_id": t, "retrieval_score": round(s, 6)} for t, s in ranked]
