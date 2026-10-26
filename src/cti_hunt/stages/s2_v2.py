"""Dựng tùy chọn khâu ② v2 (N3) từ configs/llm_v2.yaml: kho BM25 khớp đúng bản đã chuẩn bị, prompt lượt kiểm, mô tả.

Kho BM25 = định nghĩa kỹ thuật + procedure example không bị loại trừ và không thuộc tập phát triển. Hash tập phát
triển và danh sách câu trong kho phải khớp manifest của `scripts/n3_chuan_bi.py`, nếu không thì dừng.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .. import config, integrity
from ..attack import procedures as P
from ..attack.catalog import _ext_id
from ..attack.retrieval import TechniqueIndex
from ..eval import proc_examples as D
from . import s2_ttp


def load_dev_set(chuan_bi_dir: Path) -> tuple[list[dict], dict]:
    manifest = json.loads((chuan_bi_dir / "tap_phat_trien.manifest.json").read_text(encoding="utf-8"))
    path = chuan_bi_dir / "tap_phat_trien.jsonl"
    if integrity.sha256_file(path) != manifest["jsonl_sha256"]:
        raise ValueError("Tập phát triển khác SHA256 trong manifest; không dùng")
    items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return items, manifest


def descriptions(stix_path: Path) -> dict[str, str]:
    out = {}
    for o in json.loads(Path(stix_path).read_bytes())["objects"]:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            tid = _ext_id(o)
            if tid and o.get("description"):
                out[tid] = re.sub(r"\(Citation:[^)]*\)", "", o["description"])
    return out


def build(cfg: dict, root: Path = config.ROOT) -> tuple[s2_ttp.V2Options, list[dict], dict]:
    """Trả (tùy chọn v2, tập phát triển, manifest tập). Kiểm STIX v19.2 và khớp kho với manifest đã chuẩn bị."""
    attack = config.load("reports", root)["attack"]
    stix = config.resolve(attack["stix_path"], root)
    if integrity.sha256_file(stix) != attack["stix_sha256"]:
        raise ValueError("STIX ATT&CK không khớp SHA256 đã ghim (R14)")
    chuan_bi = config.resolve(cfg["chuan_bi_dir"], root)
    dev, manifest = load_dev_set(chuan_bi)
    data = P.load(stix)
    index = TechniqueIndex.from_stix(stix, procedures=D.index_procedures(data["procedures"], dev))
    index_manifest = json.loads((chuan_bi / "chi_muc_bm25.manifest.json").read_text(encoding="utf-8"))
    if index.procedure_ids_sha256 != index_manifest["procedure_ids_sha256"]:
        raise ValueError("Kho BM25 dựng lại khác manifest đã chuẩn bị; không dùng")
    verify_prompt = s2_ttp.load_prompt(config.resolve(cfg["verify_prompt_file"], root))
    options = s2_ttp.V2Options(index=index, verify_prompt=verify_prompt, descriptions=descriptions(stix),
                               per_segment=int(cfg["ung_vien_moi_doan"]), desc_chars=int(cfg["ky_tu_mo_ta"]))
    return options, dev, manifest
