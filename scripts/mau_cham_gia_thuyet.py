"""Phiếu chấm chất lượng giả thuyết ④ thang 1–5 (v3.2 §6.2) — chỉ đọc lượt đã lưu, không nhãn, không gọi API.

Hai bước, người chấm là người vận hành (agent không chấm, không điền phiếu):

1. `--tao <thư mục mới>`: rút mẫu ngẫu nhiên có hạt giống từ mọi giả thuyết đã lên phiếu ◆ của các lượt được tính
   (cả approved lẫn rejected), chia tầng theo (tuyến, chế độ). Ghi `phieu_cham.yaml` (mã M01…, nội dung giả thuyết và
   câu nguồn, thứ tự xáo trộn; **không** có lượt, quyết định ◆ hay kết quả săn) và `khoa_mau.json` (mã → lượt, vòng,
   giả thuyết, quyết định ◆, SHA256 nội dung). Người chấm chỉ mở phiếu, không mở khóa trước khi chấm xong.
2. `--tong-hop <thư mục>`: kiểm phiếu (đủ điểm 1–5, nội dung không bị sửa), ghép khóa, ghi `tong_hop.md`/`.json`:
   phân bố điểm theo tầng và theo quyết định ◆.

    .venv/Scripts/python.exe -X utf8 scripts/mau_cham_gia_thuyet.py --tao ../workspace/cham_gia_thuyet_01
    .venv/Scripts/python.exe -X utf8 scripts/mau_cham_gia_thuyet.py --tong-hop ../workspace/cham_gia_thuyet_01
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tong_hop_chi_so_khau as T  # noqa: E402

PHIEU, KHOA, TONG_HOP = "phieu_cham.yaml", "khoa_mau.json", "tong_hop"
SEED = 20261010
N_TANG = 5
NOI_DUNG = ("hanh_vi", "pham_vi", "thoi_gian", "nguon_log", "rang_buoc", "pivot", "cau_nguon")

THANG = """Thang 1–5 (chấm cả giả thuyết, đối chiếu câu nguồn và nguồn log; không đoán giả thuyết có bắt được gì):
5 — Bám đúng câu nguồn, không thêm chi tiết; hành vi thành điều kiện cụ thể trên trường của nguồn log đã chọn; nguồn
    log/EID ghi được đúng cơ chế; phạm vi và thời gian rõ. Viết được truy vấn ngay, không phải đoán.
4 — Như 5 nhưng có một điểm mơ hồ nhỏ (thiếu một trường phân biệt, thời gian để "toàn bộ log" dù câu nguồn có mốc);
    vẫn viết được truy vấn đúng ý câu nguồn.
3 — Đúng hướng và đúng nguồn log, nhưng điều kiện quá chung (cả một lớp sự kiện) hoặc người viết truy vấn phải tự thêm
    giả định quan trọng.
2 — Lỗi đáng kể: thêm tình tiết không có trong câu nguồn, nguồn log/EID không ghi được hành vi, hoặc hành vi chỉ gắn
    lỏng với câu nguồn.
1 — Không kiểm chứng được: sai cơ chế, không bám nguồn, hoặc không chuyển thành truy vấn được.
Ghi `diem` là số nguyên 1–5; `ghi_chu` tùy chọn (nên ghi khi chấm 1–3). Không sửa các trường khác."""


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _content(h: dict) -> dict:
    ev = h.get("evidence") or {}
    rb = h.get("rang_buoc")
    return {"hanh_vi": h.get("behavior", ""), "pham_vi": h.get("scope", ""), "thoi_gian": h.get("timeframe", ""),
            "nguon_log": f"{ev.get('data_source', '')} EID {ev.get('event_ids', [])} · trường {ev.get('key_fields', [])}",
            "rang_buoc": json.dumps(rb, ensure_ascii=False, sort_keys=True) if rb else "",
            "pivot": f"{h['pivot_kind']}={h['pivot_value']}" if h.get("pivot_kind") else "",
            "cau_nguon": [f"[{s.get('segment_id') or '?'}] {s.get('text', '')}" for s in h.get("source_spans") or []]}


def collect(root: Path = T.ROOT) -> list[dict]:
    """Mọi giả thuyết đã lên phiếu ◆ ở lượt được tính, kèm quyết định (chỉ cho khóa)."""
    out = []
    for run in T.discover(root):
        if not run["tinh"]:
            continue
        for rd in T._rounds(run["path"]):
            hyp, appr = rd / "hypotheses.json", rd / "approval_log.json"
            if not (hyp.exists() and appr.exists()):
                continue
            decisions = T._json(appr).get("quyet_dinh") or {}
            for h in T._json(hyp):
                out.append({"tang": f"{run['tuyen']}/{run['mode']}", "luot": f"{run['tuyen']}/{run['mode']}/{run['id']}",
                            "vong": rd.name, "hypothesis_id": h["hypothesis_id"],
                            "quyet_dinh": (decisions.get(h["hypothesis_id"]) or {}).get("quyet_dinh", ""),
                            "noi_dung": _content(h)})
    return out


def sample(items: list[dict], n: int, seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    by: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by[it["tang"]].append(it)
    picked = [it for tang in sorted(by) for it in rng.sample(by[tang], min(n, len(by[tang])))]
    rng.shuffle(picked)
    return picked


def create(out: Path, n: int = N_TANG, seed: int = SEED, root: Path = T.ROOT) -> int:
    if out.exists():
        raise SystemExit(f"{out} đã có; tạo phiếu ở thư mục mới (không ghi đè phiếu đang chấm)")
    picked = sample(collect(root), n, seed)
    out.mkdir(parents=True)
    form = {"nguoi_cham": "", "muc": [{"ma": f"M{i:02d}", **it["noi_dung"], "diem": None, "ghi_chu": ""}
                                      for i, it in enumerate(picked, start=1)]}
    header = "".join(f"# {x}\n" for x in THANG.splitlines()) + "\n"
    key = {"seed": seed, "n_moi_tang": n,
           "muc": {f"M{i:02d}": {k: it[k] for k in ("tang", "luot", "vong", "hypothesis_id", "quyet_dinh")}
                   | {"noi_dung_sha256": _sha(it["noi_dung"])} for i, it in enumerate(picked, start=1)}}
    (out / PHIEU).write_text(header + yaml.safe_dump(form, allow_unicode=True, sort_keys=False, width=110),
                             encoding="utf-8")
    (out / KHOA).write_text(json.dumps(key, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(picked)


def _stats(xs: list[int]) -> dict:
    return {"n": len(xs), "trung_binh": round(statistics.mean(xs), 2) if xs else None,
            "trung_vi": statistics.median(xs) if xs else None, "phan_bo": {d: xs.count(d) for d in range(1, 6)}}


def summarize(folder: Path) -> dict:
    form = yaml.safe_load((folder / PHIEU).read_text(encoding="utf-8"))
    key = json.loads((folder / KHOA).read_text(encoding="utf-8"))["muc"]
    if not str(form.get("nguoi_cham") or "").strip():
        raise SystemExit("phiếu chưa ghi nguoi_cham")
    rows = form.get("muc") or []
    if sorted(r["ma"] for r in rows) != sorted(key):
        raise SystemExit("danh sách mã trong phiếu khác khóa mẫu")
    by_tang, by_qd, all_ = defaultdict(list), defaultdict(list), []
    for r in rows:
        k = key[r["ma"]]
        if _sha({c: r.get(c) for c in NOI_DUNG}) != k["noi_dung_sha256"]:
            raise SystemExit(f"{r['ma']}: nội dung giả thuyết trong phiếu đã bị sửa")
        d = r.get("diem")
        if isinstance(d, bool) or not isinstance(d, int) or not 1 <= d <= 5:
            raise SystemExit(f"{r['ma']}: diem phải là số nguyên 1–5")
        by_tang[k["tang"]].append(d)
        by_qd[k["quyet_dinh"] or "khong_ro"].append(d)
        all_.append(d)
    return {"nguoi_cham": form["nguoi_cham"], "tat_ca": _stats(all_),
            "theo_tang": {t: _stats(v) for t, v in sorted(by_tang.items())},
            "theo_quyet_dinh": {q: _stats(v) for q, v in sorted(by_qd.items())},
            "ghi_chu_diem_thap": [{"ma": r["ma"], "diem": r["diem"], "ghi_chu": r.get("ghi_chu", ""),
                                  **{k: key[r["ma"]][k] for k in ("luot", "hypothesis_id", "quyet_dinh")}}
                                 for r in rows if r["diem"] <= 3]}


def markdown(s: dict) -> str:
    def line(name, st):
        pb = " · ".join(f"{d}: {st['phan_bo'][d]}" for d in range(1, 6))
        return f"| {name} | {st['n']} | {st['trung_binh']} | {st['trung_vi']} | {pb} |"
    L = [f"# Chấm chất lượng giả thuyết ④ thang 1–5 — người chấm: {s['nguoi_cham']}", "",
         "| Nhóm | n | Trung bình | Trung vị | Phân bố |", "|---|---|---|---|---|", line("Tất cả", s["tat_ca"])]
    L += [line(t, st) for t, st in s["theo_tang"].items()]
    L += ["", "Theo quyết định ◆ (người chấm không thấy quyết định khi chấm):", "",
          "| Quyết định | n | Trung bình | Trung vị | Phân bố |", "|---|---|---|---|---|"]
    L += [line(q, st) for q, st in s["theo_quyet_dinh"].items()]
    L += ["", "Mục chấm 1–3:", ""]
    L += [f"- {r['ma']} ({r['luot']} {r['hypothesis_id']}, ◆ {r['quyet_dinh']}): {r['diem']} — {r['ghi_chu'] or '—'}"
          for r in s["ghi_chu_diem_thap"]] or ["- không có"]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tao", type=Path)
    g.add_argument("--tong-hop", type=Path)
    ap.add_argument("--n", type=int, default=N_TANG, help="số giả thuyết mỗi tầng (tuyến, chế độ)")
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args(argv)
    if a.tao:
        n = create(a.tao, a.n, a.seed)
        print(f"{n} giả thuyết → {a.tao / PHIEU}; khóa {a.tao / KHOA} (không mở trước khi chấm xong)")
        return 0
    s = summarize(a.tong_hop)
    (a.tong_hop / f"{TONG_HOP}.json").write_text(json.dumps(s, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = markdown(s)
    (a.tong_hop / f"{TONG_HOP}.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
