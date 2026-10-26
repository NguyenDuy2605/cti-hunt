"""So sánh các lượt sinh rule hướng 2 (vd qwen2.5:7b với qwen2.5:14b) theo giao thức ``docs/METHODOLOGY.md`` §4, không nhãn.

Mỗi lượt là một thư mục ``huong2_sinh_rule.py chay`` (``ky_thuat/<mã>/ket_qua.json``, ``hunts/*.yaml``), kèm tùy chọn một
thư mục chấm ``huong2_cham.py`` (lấy ``theo_hunt.csv`` để biết hunt khớp bao nhiêu sự kiện trên toàn bộ 664 bộ — số này không
dùng nhãn). Báo cho từng lượt:

- ④: số giả thuyết giữ, số mục thô, số mục bị phép kiểm loại (mục thô trừ giả thuyết giữ) và số mã lỗi theo lý do
  (``khau4.ma_sua``; một mục có thể mang nhiều mã), số lần đầu ra hỏng;
- ⑤: rule hợp lệ lần đầu và sau sửa, rule không hợp lệ theo loại lỗi cuối (``kind`` của lỗi, hoặc hết ``num_predict``);
- rule qua kiểm tĩnh nhưng mọi hunt của nó khớp 0 sự kiện ở mọi bộ (câu hỏi 3);
- token; thời gian chạy ước tính từ ``xong.json`` (bỏ quãng nghỉ trên 15 phút, như giữa lượt thử và lượt chạy đủ).

Hai lượt trở lên: so cặp theo kỹ thuật chạy ở cả hai lượt (có rule hợp lệ; có hunt khớp ≥ 1 sự kiện), McNemar chính xác.

    python scripts/so_sanh_sinh_rule.py --luot 7b=<sinh_rule>[,<thư mục chấm>] --luot 14b=<sinh_rule_14b>[,<thư mục chấm>]
        [--nhom <uu_tien_L1_v4.json>] --out <tệp json>
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

from cti_hunt.eval.thong_ke import mcnemar_exact


def loai_loi_khau5(r: dict) -> str | None:
    """Loại lỗi của một lần sinh rule không hợp lệ: hết num_predict, đầu ra hỏng khác, hoặc ``kind`` của lỗi cuối."""
    if r.get("hop_le"):
        return None
    hong = r.get("dau_ra_hong") or ""
    if hong:
        return "het_num_predict" if "num_predict" in hong else "dau_ra_hong"
    loi = r.get("loi_cuoi") or []
    return (loi[-1].get("kind") if loi and isinstance(loi[-1], dict) else None) or "khong_ro"


def doc_luot(sinh: Path, cham: Path | None) -> dict:
    """Đọc một lượt; trả về tổng hợp và bảng theo kỹ thuật."""
    khop = {}
    if cham:
        for r in csv.DictReader(open(cham / "theo_hunt.csv", encoding="utf-8")):
            if "he_thong" in r["cach"].split(";"):
                khop[r["hunt"]] = int(r["khop"])
    t = collections.Counter()
    ly_do_4, loi_5, trang_thai = collections.Counter(), collections.Counter(), collections.Counter()
    luc, theo_kt = [], {}
    for f in sorted(sinh.glob("ky_thuat/*/ket_qua.json")):
        d = f.parent
        k = json.loads(f.read_text(encoding="utf-8"))
        trang_thai[k["trang_thai"].split(":")[0]] += 1
        if (d / "xong.json").exists():
            luc.append(dt.datetime.strptime(json.loads((d / "xong.json").read_text(encoding="utf-8"))["luc"], "%Y-%m-%d %H:%M:%S"))
        k4 = k.get("khau4")
        if isinstance(k4, dict):
            if "dau_ra_hong" in k4:
                t["khau4_dau_ra_hong"] += 1
            else:
                t["khau4_goi"] += 1
                t["muc_tho"] += k4.get("so_muc_tho", 0)
                ly_do_4.update(k4.get("ma_sua") or {})
                for x in ("input_tokens", "output_tokens"):
                    t[f"khau4_{x}"] += (k4.get("token") or {}).get(x, 0)
        hyps = k.get("gia_thuyet") or []
        t["gia_thuyet"] += len(hyps)
        # Hunt của lượt: id hunt → mã giả thuyết (tệp hunt ghi tên theo id; khóa nguon_gia_thuyet nếu có).
        hunt_cua = collections.defaultdict(list)
        for h in sorted((d / "hunts").glob("*.yaml")):
            spec = yaml.safe_load(h.read_text(encoding="utf-8"))
            hid = spec["id"]
            hunt_cua[hid.split("__")[0]].append(hid)
        hop_le = khop_duoc = 0
        for r in k.get("khau5") or []:
            t["khau5_lan"] += 1
            for x in ("input_tokens", "output_tokens"):
                t[f"khau5_{x}"] += (r.get("token") or {}).get(x, 0)
            if r.get("hop_le"):
                hop_le += 1
                t["rule_hop_le"] += 1
                t["rule_hop_le_lan_dau" if r.get("hop_le_lan_dau") else "rule_hop_le_sau_sua"] += 1
                hs = hunt_cua.get(r["hypothesis_id"], [])
                if cham:
                    if hs and all(khop.get(h, 0) == 0 for h in hs):
                        t["rule_hop_le_khop_0"] += 1
                    elif hs:
                        khop_duoc += 1
            else:
                loi_5[loai_loi_khau5(r)] += 1
        theo_kt[k["goc"]] = {"chay": k["trang_thai"] == "xong", "gia_thuyet": len(hyps), "rule_hop_le": hop_le,
                             "rule_khop_duoc": khop_duoc}
    t["ky_thuat_co_gia_thuyet"] = sum(1 for v in theo_kt.values() if v["gia_thuyet"])
    t["ky_thuat_co_rule_hop_le"] = sum(1 for v in theo_kt.values() if v["rule_hop_le"])
    luc.sort()
    nghi = [(luc[i + 1] - luc[i]).total_seconds() / 60 for i in range(len(luc) - 1)]
    out = {"thu_muc": str(sinh), "cham": str(cham) if cham else None, "so_ky_thuat": len(theo_kt),
           "trang_thai": dict(trang_thai), **dict(t),
           # Một mục bị loại có thể mang nhiều mã lỗi, nên tổng mã lỗi có thể lớn hơn số mục bị loại.
           "khau4_muc_bi_loai": t["muc_tho"] - t["gia_thuyet"], "khau4_ma_loi": dict(ly_do_4.most_common()),
           "khau5_khong_hop_le_theo_loai": dict(loi_5.most_common()),
           "phut_giua_xong_dau_va_xong_cuoi": round((luc[-1] - luc[0]).total_seconds() / 60, 1) if luc else None,
           "phut_nghi_dai_nhat": round(max(nghi), 1) if nghi else None,
           # Ước tính thời gian chạy: bỏ các quãng nghỉ trên 15 phút (vd giữa lượt chạy thử và lượt chạy đủ).
           "phut_chay_uoc_tinh": round(sum(x for x in nghi if x <= 15), 1) if nghi else None}
    if cham:
        out["ky_thuat_co_rule_khop_duoc"] = sum(1 for v in theo_kt.values() if v["rule_khop_duoc"])
    return {"tong": out, "theo_ky_thuat": theo_kt}


def so_cap(a: dict, b: dict, chi_so: str, nhom: set | None = None) -> dict:
    """McNemar theo kỹ thuật chạy được ở cả hai lượt (và thuộc ``nhom`` nếu có): có chỉ số > 0 hay không."""
    ks = [k for k in sorted(set(a) & set(b)) if a[k]["chay"] and b[k]["chay"] and (nhom is None or k in nhom)]
    p = sum(1 for k in ks if a[k][chi_so] and not b[k][chi_so])
    q = sum(1 for k in ks if b[k][chi_so] and not a[k][chi_so])
    return {"so_ky_thuat": len(ks), "chi_thu_nhat": p, "chi_thu_hai": q, "ca_hai": sum(1 for k in ks if a[k][chi_so] and b[k][chi_so]),
            "p": mcnemar_exact(p, q)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--luot", action="append", required=True, help="tên=thư_mục_sinh_rule[,thư_mục_chấm]")
    ap.add_argument("--nhom", help="JSON có khóa 'ky_thuat' (vd 57 kỹ thuật có nhãn): báo thêm phần so cặp trong nhóm này")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    luot = {}
    for s in a.luot:
        ten, _, duong = s.partition("=")
        sinh, _, cham = duong.partition(",")
        luot[ten] = doc_luot(Path(sinh), Path(cham) if cham else None)
    nhom = set(json.loads(Path(a.nhom).read_text(encoding="utf-8"))["ky_thuat"]) if a.nhom else None
    kq = {"giao_thuc": "docs/METHODOLOGY.md", "luot": {k: v["tong"] for k, v in luot.items()},
          "so_cap": {}}
    ten = list(luot)
    for i in range(len(ten)):
        for j in range(i + 1, len(ten)):
            x, y = luot[ten[i]]["theo_ky_thuat"], luot[ten[j]]["theo_ky_thuat"]
            for cs in ("rule_hop_le", "rule_khop_duoc"):
                kq["so_cap"][f"{ten[i]}_vs_{ten[j]}__{cs}"] = so_cap(x, y, cs)
                if nhom:
                    kq["so_cap"][f"{ten[i]}_vs_{ten[j]}__{cs}__nhom"] = so_cap(x, y, cs, nhom)
    Path(a.out).write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
    for k, v in kq["luot"].items():
        print(f"{k}: {v['so_ky_thuat']} kỹ thuật · ④ {v.get('khau4_goi', 0)} lời gọi, {v.get('gia_thuyet', 0)} giả thuyết giữ, "
              f"{v['khau4_muc_bi_loai']} mục bị loại (mã lỗi {v['khau4_ma_loi']}) · ⑤ hợp lệ {v.get('rule_hop_le', 0)}/"
              f"{v.get('khau5_lan', 0)} (lần đầu {v.get('rule_hop_le_lan_dau', 0)}, sau sửa {v.get('rule_hop_le_sau_sua', 0)}) · "
              f"không hợp lệ {v['khau5_khong_hop_le_theo_loai']} · hợp lệ mà khớp 0 sự kiện: {v.get('rule_hop_le_khop_0', '—')}")
    for k, v in kq["so_cap"].items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
