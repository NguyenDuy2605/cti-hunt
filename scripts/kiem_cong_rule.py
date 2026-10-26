"""Kiểm cổng giữ/bỏ/rút gọn rule trên một lượt v2 đã xong — chỉ đọc, không nhãn, không API.

Với mỗi gói lọc của lượt: tính lại mục đối chiếu bằng mã hiện hành và so với manifest đã băm; phiếu rule có đúng các
rule có mục; log duyệt khớp phiếu; rule bị bỏ không có tệp hunt hiệu lực, có trong `rule_bi_bo` của vòng và trong mục
"bị chặn trước thực thi" của hunt record. Gói có bản sửa (10/10, rút gọn rule): không thực thi, bản sửa trỏ đúng gói và
đúng các mục đã chọn; bản sửa: tính lại phép rút gọn từ rule của gói trước phải ra đúng rule đã lưu, hunt record ghi việc
rút gọn. Không đánh giá rule đúng/sai (việc đó rà tay).

    python scripts/kiem_cong_rule.py <thư mục lượt>
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

from cti_hunt import filter_approval as F, integrity
from cti_hunt.contracts import ContractB
from cti_hunt.stages import rule_fidelity


def _revised(rd: Path, m: dict, form: dict) -> dict:
    """Gói đã có bản sửa: không thực thi; bản sửa trỏ về đúng gói này và đúng các mục người duyệt chọn rút gọn."""
    rev = F._read(rd / F.REVISION)
    new = rd.parent / rev["ban_sua"]
    prov = F._read(new / F.MANIFEST)["context"].get("ban_sua_cua") or {}
    return {"khong_thuc_thi": not (rd / F.EFFECTIVE).exists() and not (rd / "execution_receipt.json").exists(),
            "ban_sua_khop": (rev["manifest_ban_sua_sha256"] == integrity.sha256_file(new / F.MANIFEST)
                             and prov.get("goi") == rd.name
                             and prov.get("manifest_sha256") == integrity.sha256_file(rd / F.MANIFEST)),
            "rut_gon_khop_phieu": prov.get("rut_gon") == F.shortened(rd),
            "phieu_du_quyet_dinh": all(r["quyet_dinh"] in ("giu", "bo", "rut_gon") for r in form["rule"])
                                   and any(r["quyet_dinh"] == "rut_gon" for r in form["rule"])}


def _rebuilt(rd: Path, m: dict, record: str) -> dict:
    """Bản sửa: rule rút gọn = phép rút gọn (chỉ xóa) trên rule của gói trước; hunt record ghi từng lần rút gọn."""
    prov = m["context"].get("ban_sua_cua")
    if not prov:
        return {}
    old = {s["id"]: s for s in F._read(rd.parent / prov["goi"] / F.MANIFEST)["specs"]}
    new = {s["id"]: s for s in m["specs"]}
    same = all(rule_fidelity.shorten_rule(old[c["id"]]["sigma_context"]["rule"],
                                          ContractB.model_validate(old[c["id"]]["sigma_context"]["binding"]), c["bo_muc"])
               == new[c["id"]]["sigma_context"]["rule"] for c in prov["rut_gon"])
    kept = all(new[i] == old[i] for i in new if i not in {c["id"] for c in prov["rut_gon"]})
    return {"rut_gon_tai_lap": same, "rule_khac_giu_nguyen": kept,
            "record_ghi_rut_gon": all(f"{c['hypothesis_id']} ({c['id']}, gói {prov['goi']}): bỏ " in record
                                      for c in prov["rut_gon"])}


def _packet(run: Path, rd: Path, record: str) -> dict:
    m = F._read(rd / F.MANIFEST)
    row = {"goi": rd.relative_to(run).as_posix(), "bat_cong": "doi_chieu_rule" in m, "so_rule": len(m["specs"]),
           "ban_sua": (rd / F.REVISION).exists()}
    if not row["bat_cong"]:
        return row
    rows = m["doi_chieu_rule"]
    form_path = rd / F.RULE_FORM
    form = F.load_rule_form(rd) if form_path.exists() else {"rule": [], "nguoi_duyet": ""}
    row.update(
        so_rule_co_muc=len(rows), so_muc=sum(len(r["doi_chieu"]) for r in rows),
        quyet_dinh=[{"id": r["id"], "hypothesis_id": r["hypothesis_id"], "quyet_dinh": r["quyet_dinh"],
                     "ly_do": r["ly_do"], "bo_muc": r.get("bo_muc", []),
                     "muc": [(i["truong"], i["kind"], i["gia_tri"]) for i in r["doi_chieu"]]}
                    for r in form["rule"]])
    common = {
        # Mục trong manifest phải là đúng kết quả của phép đối chiếu trên các draft của gói.
        "tinh_lai_khop": F._grounding_rows(m["specs"]) == rows,
        "phieu_dung_danh_sach": [r["id"] for r in form["rule"]] == [r["id"] for r in rows]
                                and form_path.exists() == bool(rows),
        **_rebuilt(rd, m, record)}
    if row["ban_sua"]:
        row["kiem"] = {**common, **_revised(rd, m, form)}
        return row
    log = F._read(rd / "approval_log.json")
    blocked = {r["id"]: r for r in form["rule"] if r["quyet_dinh"] == "bo"}
    effective = [yaml.safe_load(Path(p).read_text(encoding="utf-8"))["id"]
                 for p in F._read(rd / F.EFFECTIVE)["files"]]
    row["kiem"] = {
        **common,
        "phieu_du_quyet_dinh": all(r["quyet_dinh"] in ("giu", "bo") for r in form["rule"]),
        "log_khop": not rows or (log.get("phieu_rule_sha256") == integrity.sha256_file(form_path)
                                 and log.get("quyet_dinh_rule") == form["rule"]
                                 and log.get("nguoi_duyet_rule") == form["nguoi_duyet"]),
        "hieu_luc_dung": sorted(effective) == sorted(s["id"] for s in m["specs"] if s["id"] not in blocked),
        "record_ghi_rule_bo": all(f"{b['hypothesis_id']}: người duyệt bỏ rule {k}" in record
                                  for k, b in blocked.items())}
    row["_bo"] = sorted(blocked)
    return row


def check(run: Path) -> dict:
    run = Path(run).resolve()
    record = (run / "hunt_record.md").read_text(encoding="utf-8")
    packets, rounds = [], {}
    for rd in sorted(run.glob("round_*/filter_review/r*")):
        row = _packet(run, rd, record)
        bo = row.pop("_bo", None)
        if bo is not None or not row["ban_sua"]:              # gói đã có bản sửa: quyết định của nó không thực thi
            rounds.setdefault(rd.parent.parent, set()).update(bo or [])
        packets.append(row)
    # Mỗi vòng: rule bị bỏ ở gói được thực thi của vòng = `rule_bi_bo` mà bước thực thi ghi.
    rule_bi_bo = {}
    for rnd, ids in rounds.items():
        path = rnd / "agent_execute.json"
        logged = {b["hunt_id"] for b in json.loads(path.read_text(encoding="utf-8")).get("rule_bi_bo") or []} \
            if path.exists() else set()
        rule_bi_bo[rnd.name] = logged == ids
    on = [p for p in packets if p["bat_cong"]]
    return {"luot": run.name, "so_goi": len(packets), "so_goi_bat_cong": len(on),
            "so_goi_ban_sua": sum(p["ban_sua"] for p in packets),
            "so_rule": sum(p["so_rule"] for p in packets if not p["ban_sua"]),
            "so_rule_co_muc": sum(p["so_rule_co_muc"] for p in on), "so_muc": sum(p["so_muc"] for p in on),
            "so_giu": sum(q["quyet_dinh"] == "giu" for p in on for q in p["quyet_dinh"]),
            "so_bo": sum(q["quyet_dinh"] == "bo" for p in on for q in p["quyet_dinh"]),
            "so_rut_gon": sum(q["quyet_dinh"] == "rut_gon" for p in on for q in p["quyet_dinh"]),
            "rule_bi_bo_khop_vong": rule_bi_bo,
            # Không rule nào có mục thì các kiểm trên đúng một cách tầm thường: cổng chưa được thử trên lượt này.
            "kich_hoat": any(p["so_rule_co_muc"] for p in on),
            "dat": bool(on) and all(all(p["kiem"].values()) for p in on) and all(rule_bi_bo.values()),
            "goi": packets}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    result = check(parser.parse_args(argv).run_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["dat"] else 1


if __name__ == "__main__":
    sys.exit(main())
