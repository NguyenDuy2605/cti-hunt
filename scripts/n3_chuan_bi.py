"""N3 — phần không gọi API: loại trừ procedure example, tập phát triển, kho BM25 và recall@k trên tập chỉnh.

Không gọi mô hình, không đọc nhãn sự kiện hay Silver v1. Chỉ đo truy xuất trên 400 câu chỉnh; 200 câu giữ lại chưa
được chạm tới cho đến khi khóa v2 (N3 §3.3).
"""
import argparse
import json
from pathlib import Path

from cti_hunt import config, integrity
from cti_hunt.attack import procedures as P
from cti_hunt.attack.retrieval import TechniqueIndex
from cti_hunt.eval import proc_examples as D


def write(path: Path, data) -> str:
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=1) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return integrity.sha256_file(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=config.ROOT / "data/dev/n3/chuan_bi_v1")
    a = ap.parse_args()
    if a.out.exists():
        raise SystemExit("Thư mục kết quả đã tồn tại; dùng tên mới")
    attack = config.load("reports")["attack"]
    stix = config.resolve(attack["stix_path"])
    if integrity.sha256_file(stix) != attack["stix_sha256"]:
        raise SystemExit("STIX ATT&CK không khớp SHA256 đã ghim (R14)")

    data = P.load(stix)
    stats = P.summary(data)
    dev = D.build_dev_set(data["procedures"])
    tune = [i for i in dev if i["tap"] == "chinh"]
    kept = D.index_procedures(data["procedures"], dev)
    with_examples = TechniqueIndex.from_stix(stix, procedures=kept)
    definitions_only = TechniqueIndex.from_stix(stix)

    a.out.mkdir(parents=True)
    exclusion = {"quy_tac": "docs/METHODOLOGY.md", "nguon_report_danh_gia": list(P.EVAL_REFERENCE_SOURCES),
                 "chu_the_apt29": data["chu_the_apt29"], "thong_ke": stats,
                 "cau_bi_loai": [{"id": p["id"], "technique_id": p["technique_id"], "source_id": p["source_id"],
                                  "ly_do": p["loai_tru"]} for p in data["procedures"] if p["loai_tru"]]}
    hashes = {"loai_tru.json": write(a.out / "loai_tru.json", exclusion),
              "tap_phat_trien.jsonl": write(a.out / "tap_phat_trien.jsonl", D.dev_set_jsonl(dev))}
    manifest = D.dev_set_manifest(dev, data["stix_sha256"])
    hashes["tap_phat_trien.manifest.json"] = write(a.out / "tap_phat_trien.manifest.json", manifest)
    index_manifest = {"stix_sha256": with_examples.source_sha256, "so_ky_thuat": len(with_examples.documents),
                      "so_cau_vi_du": with_examples.example_count,
                      "procedure_ids_sha256": with_examples.procedure_ids_sha256,
                      "loai_khoi_kho": "câu bị loại trừ (N3 §3.1) và 600 câu của tập phát triển"}
    hashes["chi_muc_bm25.manifest.json"] = write(a.out / "chi_muc_bm25.manifest.json", index_manifest)
    recall = {"tap": "chinh", "so_cau": len(tune),
              "dinh_nghia_va_vi_du": D.retrieval_recall(with_examples, tune),
              "chi_dinh_nghia": D.retrieval_recall(definitions_only, tune),
              "ghi_chu": "Không đo trên 200 câu giữ lại trước khi khóa v2. k = 15 đã duyệt; không chọn k theo số này."}
    hashes["truy_xuat_tap_chinh.json"] = write(a.out / "truy_xuat_tap_chinh.json", recall)
    write(a.out / "SHA256SUMS", "".join(f"{h}  {n}\n" for n, h in sorted(hashes.items())))

    print(json.dumps({"thong_ke": stats, "tap_phat_trien": manifest, "chi_muc": index_manifest}, ensure_ascii=False, indent=1))
    for name in ("dinh_nghia_va_vi_du", "chi_dinh_nghia"):
        for mode in ("theo_cau", "theo_lo"):
            s = recall[name][mode]
            print(name, mode, {k: (v["dung_ma"], v["cung_ky_thuat_cha"], v["so_cau"]) for k, v in s.items()})


if __name__ == "__main__":
    main()
