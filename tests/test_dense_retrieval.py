"""Truy xuất theo embedding: cắt khúc, điểm khúc cao nhất, bộ nhớ đệm, sqlite-vec trùng numpy, RRF. Không tải mô hình."""
import hashlib
import re

import numpy as np
import pytest

from cti_hunt.attack.dense_retrieval import DenseIndex, SqliteVecStore, chunk_text, rrf

SPEC = {"name": "gia", "revision": "0", "query_prefix": "q: ", "passage_prefix": "p: "}


class FakeEncoder:
    """Túi từ băm vào 64 chiều, chuẩn hóa độ dài 1; đếm số văn bản đã mã hóa."""

    def __init__(self):
        self.seen = 0

    def __call__(self, texts):
        self.seen += len(texts)
        out = np.zeros((len(texts), 64), dtype=np.float32)
        for i, t in enumerate(texts):
            for w in re.findall(r"[a-z]+", t.lower()):
                if w in {"q", "p"}:
                    continue
                out[i, int(hashlib.md5(w.encode()).hexdigest(), 16) % 64] += 1
            n = np.linalg.norm(out[i])
            out[i] = out[i] / n if n else out[i]
        return out


DOCS = [
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"],
     "description": "Adversaries may dump credentials. " + "Filler words here. " * 20 + "Memory of lsass process."},
    {"technique_id": "T1059", "name": "Command Interpreter", "tactics": ["execution"],
     "description": "Adversaries may abuse shells such as powershell and cmd."},
    {"technique_id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"],
     "description": "Adversaries may log into remote services such as rdp and ssh."},
]


def test_chunk_text_packs_sentences_and_splits_long_ones():
    assert chunk_text("One two. Three four. Five.", 4) == ["One two. Three four.", "Five."]
    assert chunk_text("a b c d e f g", 3) == ["a b c", "d e f", "g"]
    assert chunk_text("", 5) == []
    with pytest.raises(ValueError):
        chunk_text("x", 0)


def test_best_chunk_decides_score_even_late_in_description():
    idx = DenseIndex(DOCS, FakeEncoder(), "gia", chunk_words=12, spec=SPEC)
    assert idx.max_chunks_per_technique > 1
    assert idx.search("lsass process memory", 1)[0]["technique_id"] == "T1003"
    assert idx.search("powershell cmd shells", 1)[0]["technique_id"] == "T1059"
    assert [r["technique_id"] for r in idx.search("rdp ssh remote", 3)][0] == "T1021"


def test_ties_break_by_technique_id_and_k_range():
    idx = DenseIndex(DOCS, FakeEncoder(), "gia", chunk_words=50, spec=SPEC)
    res = idx.search("", 3)                                 # vector 0: mọi điểm bằng 0
    assert [r["technique_id"] for r in res] == ["T1003", "T1021", "T1059"]
    with pytest.raises(ValueError):
        idx.search("x", 31)


def test_cache_reused_and_keyed_by_chunking(tmp_path):
    enc = FakeEncoder()
    a = DenseIndex(DOCS, enc, "gia", chunk_words=12, cache_dir=tmp_path, spec=SPEC)
    first = enc.seen
    b = DenseIndex(DOCS, enc, "gia", chunk_words=12, cache_dir=tmp_path, spec=SPEC)
    assert enc.seen == first and np.array_equal(a.matrix, b.matrix)
    c = DenseIndex(DOCS, enc, "gia", chunk_words=50, cache_dir=tmp_path, spec=SPEC)
    assert enc.seen > first and c.key != a.key


def test_sqlite_vec_store_matches_numpy(tmp_path):
    pytest.importorskip("sqlite_vec")
    idx = DenseIndex(DOCS, FakeEncoder(), "gia", chunk_words=12, spec=SPEC)
    store = SqliteVecStore(tmp_path / "vec.sqlite")
    store.write(idx)
    for q in ["lsass process memory", "powershell shells", "remote rdp", "adversaries may"]:
        qv = idx.embed_queries([q])
        want = idx.search_vectors(qv, 3)[0]
        got = store.search_vector(qv[0], 3)
        assert [r["technique_id"] for r in got] == [r["technique_id"] for r in want]
        assert [r["retrieval_score"] for r in got] == pytest.approx([r["retrieval_score"] for r in want], abs=1e-5)


def test_rrf_sums_reciprocal_ranks():
    res = rrf([["A", "B", "C"], ["B", "C", "D"]], k=4, k_const=60)
    assert [r["technique_id"] for r in res] == ["B", "C", "A", "D"]
    assert res[0]["retrieval_score"] == pytest.approx(1 / 62 + 1 / 61, abs=1e-6)
    assert [r["technique_id"] for r in rrf([["X"], ["Y"]], k=2)] == ["X", "Y"]   # bằng điểm: theo mã
    assert rrf([["A", "B"]], k=5, depth=1) == [{"technique_id": "A", "retrieval_score": round(1 / 61, 6)}]
