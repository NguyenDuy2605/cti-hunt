"""Câu hỏi 2, hướng 2: hệ thống sinh rule cho từng kỹ thuật của Splunk attack_data theo đúng chuỗi ③ → ④ → ⑤, không người duyệt.

Giao thức đặt trước: ``docs/METHODOLOGY.md``. Không đọc nhãn sự kiện,
không đưa lệnh Atomic, rule SigmaHQ hay phần phát hiện của ATT&CK cho mô hình.

- ``chuan-bi --danh-sach <danh sách .json> --out <thư mục>``: dựng Contract A cho từng kỹ thuật từ câu ``uses`` của ATT&CK
  v19.2 (tối đa 10 câu, chọn bằng hạt giống 20261016), ghi ``dau_vao.json`` kèm thứ tự chạy đã trộn. Không cần dữ liệu log.
- ``chay --dau-vao <dau_vao.json> --parquet <thư mục bộ đã nạp> --out <thư mục> [--model …] [--so-ky-thuat N] [--gia-lap]``:
  hồ sơ ③ dựng từ hợp mọi bộ, ④ ``s4_hypothesis.generate``, mã đặt ``approved``, ⑤ ``s5_rule.generate_rule``; ghi giả thuyết,
  rule, hunt spec và nhật ký mỗi kỹ thuật. Chạy lại thì bỏ qua kỹ thuật đã xong. ``--gia-lap``: client giả (không cần Ollama).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import random
import re
import sys
import time
from pathlib import Path

import duckdb
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from pilot_llm_cuc_bo import LocalOllama, guard, model_info  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.adapters import duckdb_sigma  # noqa: E402
from cti_hunt.attack.catalog import AttackCatalog  # noqa: E402
from cti_hunt.contracts import TTP, ContractA, SourceSpan  # noqa: E402
from cti_hunt.llm import providers  # noqa: E402
from cti_hunt.llm.prompting import load_sections  # noqa: E402
from cti_hunt.stages import s3_telemetry, s4_hypothesis, s5_rule  # noqa: E402

HAT_GIONG, TOI_DA_CAU, MO_TA_TOI_DA = 20261016, 10, 600
DATASET_ID = "attack_data_aafa53e"
RX_LINK = re.compile(r"\[([^\]]+)\]\(https?://[^)]*\)")
RX_CIT = re.compile(r"\s*\(Citation:[^)]*\)")
RX_CODE = re.compile(r"</?code>")
STIX = "data/attack/enterprise-attack-19.2.json"


def lam_sach(s: str) -> str:
    return " ".join(RX_CODE.sub("", RX_CIT.sub("", RX_LINK.sub(r"\1", s or ""))).split())


def _ext(o: dict) -> str | None:
    return next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)


def chuan_bi(danh_sach: Path, out: Path) -> int:
    stix = json.loads(config.resolve(STIX).read_text(encoding="utf-8"))
    cat = AttackCatalog.from_stix(config.resolve(STIX))
    by_id = {o["id"]: o for o in stix["objects"]}
    tech: dict[str, dict] = {}
    for o in stix["objects"]:
        if o.get("type") == "attack-pattern" and _ext(o):
            cur = tech.get(_ext(o))
            if cur is None or (cur.get("revoked") and not o.get("revoked")):
                tech[_ext(o)] = o
    cau: dict[str, list[tuple[str, str]]] = {}
    for o in stix["objects"]:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        t = by_id.get(o.get("target_ref", ""))
        if t and t.get("type") == "attack-pattern" and _ext(t) and o.get("description"):
            cau.setdefault(_ext(t), []).append((o["id"], lam_sach(o["description"])))
    d = json.loads(danh_sach.read_text(encoding="utf-8"))
    goc = sorted({k for c in d["tep"] for k in c["ky_thuat"]})
    thu_tu = list(goc)
    random.Random(HAT_GIONG).shuffle(thu_tu)
    items = []
    for i, T in enumerate(thu_tu, 1):
        r = cat.resolve(T)
        item = {"thu_tu": i, "goc": T, "trang_thai_ma": r.status, "hien_hanh": r.final}
        if not r.final:
            items.append({**item, "bo_qua": "mã chỉ còn ngừng dùng, không có mã thay thế"})
            continue
        o = tech[r.final]
        phase = next((p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"), "")
        tactic = cat.tactics.get(phase, phase)
        ds = sorted(cau.get(r.final, []))
        chon = sorted(random.Random(HAT_GIONG).sample(ds, TOI_DA_CAU)) if len(ds) > TOI_DA_CAU else ds
        texts = [t for _, t in chon] or [lam_sach(o.get("description", ""))[:MO_TA_TOI_DA]]
        rid = "AD-" + T.replace(".", "-")
        ca = ContractA(report_id=rid, title=f"ATT&CK {r.final} {o.get('name', '')}", ttps=[
            TTP(tactic=tactic, technique_id=r.final, technique_name=o.get("name", ""), behavior_description=t,
                source_span=SourceSpan(text=t, segment_id=f"{rid}-{n:04d}")) for n, t in enumerate(texts, 1)])
        items.append({**item, "ten": o.get("name", ""), "tactic": tactic, "so_cau_tong": len(ds), "so_cau_chon": len(chon),
                      "dung_mo_ta": not chon, "quan_he_chon": [rid_ for rid_, _ in chon],
                      "contract_a": json.loads(ca.model_dump_json())})
    out.mkdir(parents=True, exist_ok=True)
    (out / "dau_vao.json").write_text(json.dumps({"giao_thuc": "docs/METHODOLOGY.md",
                                                 "danh_sach": str(danh_sach), "commit_attack_data": d["commit"],
                                                 "hat_giong": HAT_GIONG, "toi_da_cau": TOI_DA_CAU, "ky_thuat": items},
                                                ensure_ascii=False, indent=1), encoding="utf-8")
    bo = [x for x in items if "bo_qua" in x]
    print(f"{len(items)} kỹ thuật; bỏ qua {len(bo)} {[x['goc'] for x in bo]}; dùng mô tả thay câu: "
          f"{sum(1 for x in items if x.get('dung_mo_ta'))}; 5 đầu: {[x['goc'] for x in items[:5]]}")
    return 0


class GiaLap4:
    """Client giả cho ④: một giả thuyết trỏ dòng TTP đầu, nguồn log đầu tiên của danh mục (chỉ để kiểm đường ống)."""
    model_id = "gia-lap"

    def __init__(self):
        self.input = None

    def complete_json(self, system, user, json_schema, log=None) -> dict:
        i = self.input
        src = i["mapping"]["sources"][0]
        return {"items": [{"ttp_refs": [i["ref"]], "behavior": "giả lập: hành vi của kỹ thuật", "scope": "mọi máy",
                           "timeframe": "toàn bộ log", "data_source": src["channel"], "event_ids": src["event_ids"][:1],
                           "key_fields": list(src.get("key_fields") or [])[:2], "extra_techniques": [],
                           "priority": "trung_binh", "rationale": i["ttp"].behavior_description[:80],
                           "required_operations": [], "rang_buoc": None}]}


class GiaLap5:
    """Client giả cho ⑤: rule chọn một giá trị không có thật trên trường khóa đầu tiên của giả thuyết."""
    model_id = "gia-lap"

    def __init__(self, ls_catalog):
        self.ls_catalog, self.h = ls_catalog, None

    def complete_json(self, system, user, json_schema, log=None) -> dict:
        ls = s5_rule.logsources_for(self.h, self.ls_catalog)[0]
        field = self.h.evidence.key_fields[0]
        rule = {"title": "gia lap", "status": "experimental", "logsource": {k: v for k, v in ls.items() if k != "key"},
                "detection": {"selection": {f"{field}|contains": "gia_lap_khong_khop"}, "condition": "selection"},
                "level": "low"}
        return {"rule_yaml": yaml.safe_dump(rule, allow_unicode=True, sort_keys=False), "note": "giả lập"}


def mo_hop(parquet: Path):
    files = sorted(glob.glob(str(parquet / "*" / "events.parquet")))
    if not files:
        raise SystemExit(f"không thấy events.parquet nào trong {parquet}")
    con = duckdb.connect()
    lst = "[" + ", ".join("'" + f.replace("\\", "/").replace("'", "''") + "'" for f in files) + "]"
    con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet({lst}, union_by_name=true)")
    return con, len(files)


def xep_thu_tu(items: list[dict], uu_tien: list[str] | None) -> list[dict]:
    """Kỹ thuật trong ``uu_tien`` chạy trước, rồi tới phần còn lại; trong mỗi nhóm giữ nguyên thứ tự đã trộn của ``dau_vao``.
    Mỗi kỹ thuật chạy độc lập (nhiệt độ 0, seed 0), nên thứ tự chỉ quyết định phần nào xong trước nếu lượt bị dừng."""
    if not uu_tien:
        return list(items)
    uu = set(uu_tien)
    return [x for x in items if x["goc"] in uu] + [x for x in items if x["goc"] not in uu]


def r5_loi_500(goc: str, hypothesis_id: str, e: Exception, cho_phep) -> dict:
    """Lỗi Ollama ở ⑤: mặc định nổi lên (dừng, chạy lại đúng lệnh — giao thức 09 §3). Chỉ với kỹ thuật người vận hành chỉ định qua
    ``--loi-500-la-hong`` và chỉ với HTTP 500 thì tính là đầu ra hỏng của giả thuyết đó (lệch giao thức 24, đã duyệt:
    trên PC, một lời gọi sửa của T1547.009 làm Ollama trả 500 ở đúng cùng chỗ hai lần liền vì nhiệt độ 0)."""
    if goc not in (cho_phep or ()) or "HTTP Error 500" not in str(e):
        raise e
    return {"hypothesis_id": hypothesis_id, "hop_le": False, "dau_ra_hong": ("loi_ollama_500_lap_lai: " + str(e))[:300],
            "hunt_specs": [], "rule_yaml": None}


def chay(a) -> int:
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    D = json.loads(Path(a.dau_vao).read_text(encoding="utf-8"))
    cfg = config.agent_config("v2")
    p4 = load_sections(config.resolve(cfg["prompt_khau4"]))
    p5 = load_sections(config.resolve(cfg["prompt_khau5"]), ("SYSTEM", "USER", "REPAIR"))
    ls_catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset")["logsource_catalog"]))
    cat = AttackCatalog.from_stix(config.resolve(STIX))
    with guard():
        con, n_bo = mo_hop(Path(a.parquet))
        catalog = s3_telemetry.load_catalog(config.telemetry_catalog("v2"))
        profile = s3_telemetry.build_profile(con, catalog, DATASET_ID)
        telemetry = s3_telemetry.apply_profile(catalog, profile)
        out.mkdir(parents=True, exist_ok=True)
        _, prof_sha = s3_telemetry.write_profile(profile, out)
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        info = {"model": "gia-lap"} if a.gia_lap else model_info(a.model)
        if a.gia_lap:
            llm4, llm5 = GiaLap4(), GiaLap5(ls_catalog)
        else:
            llm4 = llm5 = LocalOllama(a.model, a.num_ctx, a.num_predict, a.timeout)
        (out / "cau_hinh_luot.json").write_text(json.dumps({
            "giao_thuc": D["giao_thuc"], "mo_hinh": info, "num_ctx": a.num_ctx, "num_predict": a.num_predict,
            "prompt_khau4": p4["path"], "prompt_khau4_sha256": p4["sha256"], "prompt_khau5": p5["path"],
            "prompt_khau5_sha256": p5["sha256"], "so_bo_du_lieu": n_bo, "ho_so_sha256": prof_sha,
            "danh_muc": str(config.telemetry_catalog("v2")), "giao_thuc_luot": a.giao_thuc,
            "uu_tien": ([a.uu_tien, hashlib.sha256(Path(a.uu_tien).read_bytes()).hexdigest()] if a.uu_tien else None),
            "loi_500_la_hong": getattr(a, "loi_500_la_hong", None) or None},
            ensure_ascii=False, indent=1), encoding="utf-8")
        uu_tien = json.loads(Path(a.uu_tien).read_text(encoding="utf-8"))["ky_thuat"] if a.uu_tien else None
        thu_tu = xep_thu_tu(D["ky_thuat"], uu_tien)
        items = thu_tu[: a.so_ky_thuat] if a.so_ky_thuat else thu_tu
        t0 = time.monotonic()
        for it in items:
            tdir = out / "ky_thuat" / it["goc"]
            if (tdir / "xong.json").exists():
                continue
            tdir.mkdir(parents=True, exist_ok=True)
            kq = {"goc": it["goc"], "hien_hanh": it.get("hien_hanh"), "thu_tu": it["thu_tu"]}
            if "bo_qua" in it:
                kq["trang_thai"] = "bo_qua: " + it["bo_qua"]
            else:
                ca = ContractA.model_validate(it["contract_a"])
                inputs, gaps = s4_hypothesis.select_inputs(ca, telemetry)
                kq["so_ttp_vao_khau4"], kq["so_ttp_not_huntable"] = len(inputs), len(gaps)
                hyps, kq["khau4"] = [], None
                if not inputs:
                    kq["trang_thai"] = "khong_san_duoc: danh mục ③ không có nguồn log thu thập được cho kỹ thuật này"
                else:
                    if a.gia_lap:
                        llm4.input = inputs[0]
                    try:
                        r4 = s4_hypothesis.generate(ca, telemetry, llm4, p4, cfg, cat, tdir / "khau4", anchors=[],
                                                    coverage=None)
                        hyps = [h.model_copy(update={"status": "approved"}) for h in r4["hypotheses"]]
                        kq["khau4"] = r4["log"]
                    except providers.BadOutputError as e:
                        kq["khau4"] = {"dau_ra_hong": str(e)[:300]}
                    kq["gia_thuyet"] = [{**json.loads(h.model_dump_json()), "tu_dong_duyet_benchmark": True} for h in hyps]
                    kq["khau5"] = []
                    for h in hyps:
                        if a.gia_lap:
                            llm5.h = h
                        try:
                            r5 = s5_rule.generate_rule(h, llm5, p5, ls_catalog, int(cfg["max_repair_attempts"]), columns,
                                                       con, tdir / "khau5", filter_policy=cfg["filter_policy_id"],
                                                       stop_repair_on_empty_source=bool(cfg.get("dung_sua_khi_nguon_rong")))
                        except providers.BadOutputError as e:
                            r5 = {"hypothesis_id": h.hypothesis_id, "hop_le": False, "dau_ra_hong": str(e)[:300],
                                  "hunt_specs": [], "rule_yaml": None}
                        except providers.TransportError as e:
                            r5 = r5_loi_500(it["goc"], h.hypothesis_id, e, getattr(a, "loi_500_la_hong", None))
                            kq["lech_giao_thuc"] = ("lỗi Ollama HTTP 500 lặp lại ở ⑤ tính là đầu ra hỏng của giả thuyết đó "
                                                    "")
                        if r5.get("hop_le"):
                            (tdir / "rules").mkdir(exist_ok=True)
                            (tdir / "rules" / f"{h.hypothesis_id}.yml").write_text(r5["rule_yaml"], encoding="utf-8")
                            (tdir / "hunts").mkdir(exist_ok=True)
                            for spec in r5["hunt_specs"]:
                                (tdir / "hunts" / f"{spec['id']}.yaml").write_text(
                                    yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8")
                        kq["khau5"].append({k: r5.get(k) for k in ("hypothesis_id", "hop_le", "hop_le_lan_dau", "so_lan_sua",
                                                                    "dau_ra_hong", "token")}
                                           | {"so_hunt": len(r5.get("hunt_specs") or []),
                                              "loi_cuoi": (r5.get("lan_thu") or [{}])[-1].get("loi")})
                    kq["trang_thai"] = "xong"
            (tdir / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
            (tdir / "xong.json").write_text(json.dumps({"luc": time.strftime("%Y-%m-%d %H:%M:%S")}), encoding="utf-8")
            so_rule = sum(1 for x in kq.get("khau5") or [] if x.get("hop_le"))
            print(f"[{it['thu_tu']:3d}] {it['goc']:12s} {kq['trang_thai'][:40]:40s} giả thuyết {len(kq.get('gia_thuyet') or [])}"
                  f" · rule hợp lệ {so_rule} · {(time.monotonic() - t0) / 60:.1f} phút", flush=True)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("chuan-bi")
    p.add_argument("--danh-sach", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("chay")
    p.add_argument("--dau-vao", required=True)
    p.add_argument("--parquet", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--model", default="qwen2.5:7b-instruct")
    p.add_argument("--so-ky-thuat", type=int)
    p.add_argument("--uu-tien", help="JSON có khóa 'ky_thuat': mã gốc chạy trước (giao thức 24); thứ tự trong nhóm giữ nguyên")
    p.add_argument("--giao-thuc", help="giao thức của lượt chạy này, ghi vào cau_hinh_luot.json (mặc định chỉ ghi giao thức 09)")
    p.add_argument("--loi-500-la-hong", nargs="*", default=[], metavar="MA",
                   help="mã gốc: HTTP 500 của Ollama ở ⑤ tính là đầu ra hỏng thay vì dừng (lệch giao thức 24, chỉ khi người vận hành duyệt)")
    p.add_argument("--num-ctx", type=int, default=16384)
    p.add_argument("--num-predict", type=int, default=8192)
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--gia-lap", action="store_true")
    a = ap.parse_args(argv)
    return chuan_bi(Path(a.danh_sach), Path(a.out)) if a.lenh == "chuan-bi" else chay(a)


if __name__ == "__main__":
    raise SystemExit(main())
