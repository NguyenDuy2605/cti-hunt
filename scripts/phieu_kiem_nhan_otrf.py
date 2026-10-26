"""Phiếu kiểm mù nhãn dòng tiến trình OTRF (15/10): người duyệt xem sự kiện, không thấy nhãn của script, ghi tấn công / bình
thường / không chắc; sau đó so với nhãn để tính tỷ lệ khớp. Không gọi API, không đọc nhãn APT29.

Mẫu: mỗi bộ 3 sự kiện nhãn tấn công + 3 sự kiện nhãn bình thường **khó** (cùng máy, cùng kênh với sự kiện tấn công, trong
khoảng hoạt động tấn công nới thêm 5 phút mỗi bên); hạt giống ngẫu nhiên cố định. Mã mục đánh sau khi trộn nên không lộ
nhãn. Mỗi mục kèm tiến trình gây ra sự kiện (Sysmon 1 cùng ProcessGuid, nếu có) như người phân tích vẫn tra. Phiếu và đáp
án ghi ngoài repo.

    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_nhan_otrf.py tao --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
    .venv/Scripts/python.exe -X utf8 scripts/phieu_kiem_nhan_otrf.py cham --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_co_nhan_otrf as m  # noqa: E402
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402

FIELDS = ("Image", "ParentImage", "CommandLine", "ParentCommandLine", "SourceImage", "TargetImage", "GrantedAccess",
          "ImageLoaded", "TargetFilename", "TargetObject", "Details", "EventType", "PipeName", "QueryName",
          "DestinationIp", "DestinationPort", "DestinationHostname", "SourceIp", "Consumer", "Filter", "Destination",
          "Query", "Operation", "ScriptBlockText", "Payload", "ContextInfo", "HostApplication", "NewProcessName",
          "ParentProcessName", "ProcessName", "TaskName", "TaskContent", "ServiceName", "ServiceFileName", "ImagePath",
          "ObjectName", "ShareName", "RelativeTargetName", "LogonType", "IpAddress", "TargetUserName",
          "SubjectUserName", "User", "Name")
CONTEXT = ("Image", "CommandLine", "ParentImage", "ParentCommandLine", "User")
SEED = 20261015
SYS = "microsoft-windows-sysmon/operational"


def _key(r) -> tuple:
    return str(r["ev_host"]), str(r["ev_channel"]), str(r["ev_rec"])


def tao(a) -> int:
    from datetime import datetime, timedelta
    rnd = random.Random(SEED)
    picked = []
    for ds in base.DATASETS:
        attack, _ = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        want = [c for c in FIELDS + ("ProcessGuid", "SourceProcessGUID") if c in cols]
        sel = ", ".join(f'"{c}"' for c in dict.fromkeys(want))
        rows = con.execute(f"SELECT ev_host, ev_channel, ev_rec, ev_eid, ev_ts, {sel} FROM events").fetchall()
        names = ["ev_host", "ev_channel", "ev_rec", "ev_eid", "ev_ts"] + list(dict.fromkeys(want))
        recs = [dict(zip(names, r)) for r in rows if str(r[1]) in m.LABELED]
        procs = {r["ProcessGuid"]: r for r in recs if r["ev_channel"] == SYS and str(r["ev_eid"]) == "1"
                 and r.get("ProcessGuid")}
        att = [r for r in recs if _key(r) in attack]
        hosts, chans = {r["ev_host"] for r in att}, {r["ev_channel"] for r in att}
        ts = [r["ev_ts"] for r in att if isinstance(r["ev_ts"], datetime)]
        lo, hi = (min(ts) - timedelta(minutes=5), max(ts) + timedelta(minutes=5)) if ts else (None, None)
        hard = [r for r in recs if _key(r) not in attack and r["ev_host"] in hosts and r["ev_channel"] in chans
                and lo is not None and isinstance(r["ev_ts"], datetime) and lo <= r["ev_ts"] <= hi]
        benign = hard or [r for r in recs if _key(r) not in attack]
        for label, pool in (("tan_cong", att), ("binh_thuong", benign)):
            for r in rnd.sample(pool, min(3, len(pool))):
                guid = r.get("ProcessGuid") or r.get("SourceProcessGUID")
                ctx = procs.get(guid) if guid else None
                picked.append((ds, label, r, ctx))
    rnd.shuffle(picked)
    items, key = [], {}
    for i, (ds, label, r, ctx) in enumerate(picked, 1):
        iid = f"K{i:02d}"
        key[iid] = {"bo": ds, "nhan_script": label, "khoa": list(_key(r))}
        item = {"id": iid, "bo_log": ds, "may": r["ev_host"], "kenh": r["ev_channel"], "eid": r["ev_eid"],
                "thoi_diem": str(r["ev_ts"])[:19],
                "truong": {k: str(v)[:300] for k, v in r.items() if k in FIELDS and v not in (None, "")}}
        if ctx is not None and ctx is not r:
            item["tien_trinh_gay_ra"] = {k: str(ctx[k])[:300] for k in CONTEXT if ctx.get(k) not in (None, "")}
        item.update({"quyet_dinh": "", "ghi_chu": ""})
        items.append(item)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    head = ("# Phiếu kiểm mù nhãn OTRF. Mỗi bộ OTRF ghi một cuộc mô phỏng tấn công bằng công cụ Empire (tên bộ = kỹ thuật).\n"
            "# Với mỗi sự kiện: quyet_dinh = tan_cong (do kẻ tấn công gây ra) | binh_thuong | khong_chac. Không cần ghi chú.\n")
    (out / "phieu_kiem_nhan_otrf.yaml").write_text(head + yaml.safe_dump({"nguoi_kiem": "", "su_kien": items},
                                                                         allow_unicode=True, sort_keys=False, width=200),
                                                   encoding="utf-8")
    (out / "dap_an_khong_mo.json").write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Đã ghi {len(items)} sự kiện vào {out / 'phieu_kiem_nhan_otrf.yaml'}")
    return 0


def _process_evidence(x: dict) -> bool:
    """Mục có thông tin tiến trình gây ra sự kiện: đợt 1 `tien_trinh_gay_ra`; đợt 2 chuỗi tiến trình theo GUID có ít nhất một
    tiến trình thấy được, hoặc danh sách lần chạy cùng PID có ít nhất một lần chạy được tạo trong bộ."""
    if x.get("tien_trinh_gay_ra"):
        return True
    chain = (x.get("chuoi_tien_trinh_gay_ra") or []) + (x.get("chuoi_tien_trinh_cha") or [])
    if any(c.get("Image") for c in chain):
        return True
    return any(c.get("Image") for c in x.get("moi_lan_chay_mang_pid_nay") or [])


def _evidence_kind(x: dict) -> str:
    kinds = []
    if x.get("tien_trinh_gay_ra") or x.get("chuoi_tien_trinh_gay_ra") or x.get("chuoi_tien_trinh_cha"):
        kinds.append("chuỗi tiến trình")
    if x.get("moi_lan_chay_mang_pid_nay"):
        kinds.append("lần chạy cùng PID")
    if x.get("lenh_ma_hoa_da_giai_ma") or any(c.get("lenh_ma_hoa_da_giai_ma") for c in
                                              (x.get("chuoi_tien_trinh_gay_ra") or []) + (x.get("chuoi_tien_trinh_cha") or [])
                                              + (x.get("moi_lan_chay_mang_pid_nay") or [])):
        kinds.append("lệnh mã hóa đã giải mã")
    return " + ".join(kinds) or "chỉ trường của sự kiện"


def cham(a) -> int:
    out = Path(a.out)
    form = yaml.safe_load((out / "phieu_kiem_nhan_otrf.yaml").read_text(encoding="utf-8"))
    key = json.loads((out / "dap_an_khong_mo.json").read_text(encoding="utf-8"))
    done = [x for x in form["su_kien"] if x["quyet_dinh"] in ("tan_cong", "binh_thuong", "khong_chac")]
    sure = [x for x in done if x["quyet_dinh"] != "khong_chac"]
    agree = sum(x["quyet_dinh"] == key[x["id"]]["nhan_script"] for x in sure)
    by = {}
    for x in sure:
        k = (key[x["id"]]["nhan_script"], x["quyet_dinh"])
        by[f"script {k[0]} / người {k[1]}"] = by.get(f"script {k[0]} / người {k[1]}", 0) + 1
    # 15/10: chia theo nhãn script, theo kênh và theo việc phiếu có tiến trình gây ra hay không, để thấy mục "không chắc"
    # dồn vào đâu (nhãn của loại sự kiện nào chưa được người kiểm xác nhận).
    def split(group) -> dict:
        t: dict = {}
        for x in done:
            g = t.setdefault(group(x), {"quyet_duoc": 0, "khong_chac": 0, "khop": 0})
            if x["quyet_dinh"] == "khong_chac":
                g["khong_chac"] += 1
            else:
                g["quyet_duoc"] += 1
                g["khop"] += x["quyet_dinh"] == key[x["id"]]["nhan_script"]
        return dict(sorted(t.items()))
    res = {"da_cham": len(done), "khong_chac": len(done) - len(sure), "khop": agree, "tren": len(sure),
           "ty_le_khop": round(agree / len(sure), 4) if sure else None, "bang": by,
           "theo_nhan_script": split(lambda x: key[x["id"]]["nhan_script"]),
           "theo_kenh": split(lambda x: f"{x['kenh']} {x['eid']}"),
           # 15/10: đợt 2 ghi bằng chứng ở trường khác (chuỗi tiến trình, mọi lần chạy cùng PID, lệnh mã hóa đã giải mã); bản
           # trước chỉ đọc `tien_trinh_gay_ra` của đợt 1 nên mọi mục đợt 2 bị xếp "không".
           "theo_co_tien_trinh_gay_ra": split(lambda x: "có" if _process_evidence(x) else "không"),
           "theo_loai_bang_chung": split(_evidence_kind),
           "lech": [{"id": x["id"], **key[x["id"]], "nguoi": x["quyet_dinh"], "ghi_chu": x.get("ghi_chu", "")}
                    for x in sure if x["quyet_dinh"] != key[x["id"]]["nhan_script"]]}
    (out / "ket_qua_cham.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "lech"}, ensure_ascii=False))
    for d in res["lech"]:
        print("  lệch:", d)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("viec", choices=("tao", "cham"))
    ap.add_argument("--nhan")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    return tao(a) if a.viec == "tao" else cham(a)


if __name__ == "__main__":
    sys.exit(main())
