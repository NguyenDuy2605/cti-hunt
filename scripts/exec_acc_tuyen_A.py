"""Execution accuracy khâu ⑤ theo G0(c) cho mọi hunt đã thực thi của tuyến A (pipeline + agent), không dùng nhãn.

1. Ghim SigmaHQ (commit, cây con sạch, manifest) và lập bản ghi chọn chuẩn chỉ từ metadata rule và giả thuyết đã
   duyệt; ghi bản ghi trước mọi phép so.
2. Hunt thường: đưa nguyên tệp SigmaHQ đã chọn vào `exec-acc`. Hunt pivot: chuẩn biên dịch rồi khóa cùng thực thể
   bằng `s8_pivot.bind_spec` (G0(c) §2.2). Không có SigmaHQ thì dùng nhánh A H-03 nếu cùng kỹ thuật và nguồn, còn không
   ghi "không có chuẩn".
3. Gom kết quả `exec-acc` (độ khớp với bộ chuẩn, không phải TP recall/FPR).
"""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path

import yaml

from cti_hunt import config
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.cli import main as cli_main
from cti_hunt.contracts import ContractB
from cti_hunt.data.store import connect
from cti_hunt.eval import g0c
from cti_hunt.hunt import runner
from cti_hunt.stages import s8_pivot

ROOT = config.ROOT
TUYEN_A = ROOT / "data/eval/apt29_day2/tuyen_A"
NHANH_A = ROOT / "hunts/manual/H-03.yaml"


def rel(p: Path) -> str:
    return Path(p).resolve().relative_to(ROOT).as_posix()


def sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write_json(path: Path, data) -> str:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8", newline="\n")
    return sha(path)


def generated_hunts() -> list[dict]:
    out = []
    for mode in ("pipeline", "agent"):
        for run in sorted(p for p in (TUYEN_A / mode).iterdir() if p.is_dir()):
            for rnd in sorted(run.glob("round_*")):
                if not (rnd / "hunts").is_dir():
                    continue
                approved = [ContractB.model_validate(x) for x in
                            json.loads((rnd / "hypotheses_da_duyet.json").read_text(encoding="utf-8"))]
                for hunt in sorted((rnd / "hunts").glob("*.yaml")):
                    spec = runner.load_spec(hunt)
                    hyp = [h for h in approved if h.hypothesis_id == spec["hypothesis_id"]]
                    assert len(hyp) == 1, hunt
                    rule = rnd / "rules" / f"{spec['hypothesis_id']}.yml"
                    assert rule.exists(), rule
                    out.append({"mode": mode, "run": run.name, "round": rnd.name, "hunt": hunt, "spec": spec,
                                "hyp": hyp[0], "rule": rule,
                                "logsource": (yaml.safe_load(rule.read_text(encoding="utf-8")) or {}).get("logsource") or {}})
    return out


def lock_clause(hyp: ContractB, columns: set[str]) -> str:
    """Ràng buộc tài khoản đúng như bind_spec sinh, để đối chiếu với hunt sinh."""
    probe = s8_pivot.bind_spec({"id": "probe", "scope": {"channel": "x", "event_ids": [1]},
                                "candidates": "X", "filters": []}, hyp, columns)["candidates"]
    assert probe.startswith("(X) AND (") and probe.endswith(")")
    return probe[len("(X) AND ("):-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=None, help="mặc định exec_acc_g0c (v1) hoặc exec_acc_g0c_v2 (v2)")
    ap.add_argument("--quy-tac", choices=g0c.RULE_VERSIONS, default="v1",
                    help="v2: thu EID của chuẩn về EID hunt sinh khi là tập con cùng channel (docs/METHODOLOGY.md)")
    ap.add_argument("--sigmahq", type=Path, default=ROOT / "data/work/sigmahq")
    ap.add_argument("--subtree", default="rules/windows")
    a = ap.parse_args()
    a.out = a.out or TUYEN_A / ("exec_acc_g0c" if a.quy_tac == "v1" else "exec_acc_g0c_v2")
    if a.out.exists():
        raise SystemExit("Thư mục kết quả đã tồn tại; dùng tên mới")

    pin, manifest = g0c.pin_sigmahq(a.sigmahq, a.subtree)
    if not pin["commit"] or pin["clean"] is not True:
        raise SystemExit(f"SigmaHQ chưa ghim được (commit/cây con không sạch): {pin}")
    metas, parse_errors = g0c.index_rules(a.sigmahq, a.subtree)
    h03 = runner.load_spec(NHANH_A)

    entries, gen_list = [], generated_hunts()
    for g in gen_list:
        spec, hyp = g["spec"], g["hyp"]
        selected = g0c.select(metas, g["logsource"], hyp.linked_ttps)
        basis = "sigmahq" if selected else "khong_co_chuan"
        if not selected and set(hyp.linked_ttps) & set(h03["linked_ttps"]) and \
                (str(spec["scope"]["channel"]).lower(), sorted(spec["scope"]["event_ids"])) == \
                (str(h03["scope"]["channel"]).lower(), sorted(h03["scope"]["event_ids"])):
            basis = "nhanh_A"
        entries.append({
            "mode": g["mode"], "run": g["run"], "round": g["round"], "hypothesis_id": hyp.hypothesis_id,
            "hunt_file": rel(g["hunt"]), "hunt_sha256": spec["_sha256"],
            "rule_file": rel(g["rule"]), "rule_sha256": sha(g["rule"]),
            "linked_ttps_gia_thuyet": list(hyp.linked_ttps), "linked_ttps_hunt": spec.get("linked_ttps"),
            "logsource_rule_sinh": g["logsource"],
            "pham_vi": {"channel": spec["scope"]["channel"], "event_ids": spec["scope"]["event_ids"],
                        "hosts": spec["scope"].get("hosts") or [], "time_from": spec["scope"].get("time_from"),
                        "time_to": spec["scope"].get("time_to")},
            "pivot": {"kind": hyp.pivot_kind, "value": hyp.pivot_value} if hyp.origin == "pivot" else None,
            "co_so": basis,
            "chuan_sigmahq": [{k: m[k] for k in ("relative_path", "id", "title", "sha256", "status", "logsource",
                                                 "techniques")} for m in selected],
            "chuan_nhanh_A": {"file": rel(NHANH_A), "sha256": sha(NHANH_A)} if basis == "nhanh_A" else None,
            "ly_do": {"sigmahq": "stable/test, cùng (product, category, service), tag kỹ thuật trùng chính xác mã giả thuyết",
                      "nhanh_A": "không có SigmaHQ đủ tiêu chí; H-03 cùng kỹ thuật và cùng channel/EID",
                      "khong_co_chuan": "không có SigmaHQ đủ tiêu chí và nhánh A không cùng kỹ thuật/nguồn"}[basis],
        })

    a.out.mkdir(parents=True)
    (a.out / "sigmahq_manifest.sha256").write_text(manifest, encoding="utf-8", newline="\n")
    record = {"kind": "G0-c-ban-ghi-chon-chuan", "quy_tac": "docs/METHODOLOGY.md",
              "quy_tac_pham_vi": a.quy_tac,
              "sigmahq": pin, "sigmahq_loi_doc": parse_errors, "sigmahq_so_rule_doc_duoc": len(metas),
              "chon_truoc_khi_xem_ket_qua_hunt": False,
              "ghi_chu_thoi_diem": ("Lập 01/10 sau khi đã có kết quả có nhãn tuyến A. Việc chọn chỉ dùng metadata "
                                    "(status, logsource, tag) và mã kỹ thuật của giả thuyết đã duyệt, theo quy tắc cơ "
                                    "học; không đọc số khớp, nhãn hay kết quả hunt."),
              "hunt": entries}
    record_sha = write_json(a.out / "ban_ghi_chon.json", record)
    print(f"Bản ghi chọn: {len(entries)} hunt, sha256 {record_sha}")

    con = connect(ROOT / "data/work")
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    con.close()
    catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset")["logsource_catalog"]))
    (a.out / "ket_qua").mkdir()
    (a.out / "chuan_pivot").mkdir()
    gens = {e["hunt_file"]: g for e, g in zip(entries, gen_list)}
    log = io.StringIO()
    results = []
    for e in entries:
        g = gens[e["hunt_file"]]
        tag = f"{e['mode']}_{e['run']}_{e['round']}_{e['hypothesis_id']}"
        row = {k: e[k] for k in ("mode", "run", "round", "hypothesis_id", "hunt_file", "co_so", "pivot")}
        row["so_chuan"] = len(e["chuan_sigmahq"]) or (1 if e["co_so"] == "nhanh_A" else 0)
        if e["co_so"] == "khong_co_chuan":
            results.append({**row, "so_duoc": False, "ly_do": "không có chuẩn"})
            continue
        sources = [a.sigmahq / m["relative_path"] for m in e["chuan_sigmahq"]] or [NHANH_A]
        if e["pivot"] is None:
            refs = sources
        else:
            refs, missing = [], []
            for i, src in enumerate(sources):
                if src == NHANH_A:
                    base = {k: v for k, v in runner.load_spec(NHANH_A).items() if not k.startswith("_")}
                    probe = {"scope": {**g["spec"]["scope"], "hosts": [], "time_from": None, "time_to": None}}
                    same = g0c.narrow_reference(base, probe, a.quy_tac)
                    specs, notes = ([s8_pivot.bind_spec(same, g["hyp"], columns)] if same is not None else []), []
                else:
                    specs, notes = g0c.pivot_reference_specs(src, catalog, columns, g["spec"]["scope"], g["hyp"],
                                                             a.quy_tac)
                if not specs:
                    missing.append(f"{rel(src)}: không có hunt cùng channel/EID sau biên dịch; {notes}")
                    continue
                for j, s in enumerate(specs):
                    if g["hyp"].pivot_kind == "may":
                        assert s["scope"]["hosts"] == g["spec"]["scope"]["hosts"], tag
                    else:
                        lock = lock_clause(g["hyp"], columns)
                        assert s["candidates"].endswith(f"AND ({lock})"), tag
                        assert g["spec"]["candidates"].endswith(f"AND ({lock})"), tag
                    s = {k: v for k, v in s.items() if not k.startswith("_")}
                    s["id"] = f"CHUAN-{i:02d}-{j}__{Path(src).stem}"
                    s["nguon_chuan"] = {"file": rel(src), "sha256": sha(src),
                                        "rang_buoc": f"bind_spec pivot {e['pivot']['kind']}={e['pivot']['value']}"}
                    path = a.out / "chuan_pivot" / f"{tag}__{i:02d}_{j}.yaml"
                    path.write_text(yaml.safe_dump(s, allow_unicode=True, sort_keys=False), encoding="utf-8",
                                    newline="\n")
                    refs.append(path)
            if missing:
                results.append({**row, "so_duoc": False,
                                "ly_do": "rule chuẩn không có hunt cùng phạm vi: " + " | ".join(missing)})
                continue
        out_json = a.out / "ket_qua" / f"{tag}.json"
        argv = ["exec-acc", str(refs[0]), str(g["hunt"]), *sum((["--ref-extra", str(r)] for r in refs[1:]), []),
                "--out", str(out_json), "--quy-tac", a.quy_tac]
        with contextlib.redirect_stdout(log):
            cli_main(argv)
        res = json.loads(out_json.read_text(encoding="utf-8"))
        assert len(res) == 1, out_json
        res = res[0]
        row.update(so_duoc=res["so_duoc"], ly_do=res.get("ly_do"), ket_qua=rel(out_json))
        if res["so_duoc"]:
            row["giai_doan"] = {st: {k: c[k] for k in ("chuan", "sinh", "chung", "chi_chuan", "chi_sinh",
                                                          "jaccard", "precision", "recall")}
                                for st, c in res["giai_doan"].items()}
        results.append(row)
    (a.out / "exec_acc.log").write_text(log.getvalue(), encoding="utf-8", newline="\n")
    summary = {"ban_ghi_chon_sha256": record_sha, "sigmahq": pin, "quy_tac_pham_vi": a.quy_tac, "ket_qua": results}
    print(f"Đã ghi {rel(a.out)}/tong_hop.json, sha256 {write_json(a.out / 'tong_hop.json', summary)}")
    count = lambda pred: sum(1 for r in results if pred(r))
    print(f"hunt {len(results)} · có chuẩn SigmaHQ {count(lambda r: r['co_so'] == 'sigmahq')} · "
          f"nhánh A {count(lambda r: r['co_so'] == 'nhanh_A')} · không có chuẩn {count(lambda r: r['co_so'] == 'khong_co_chuan')}"
          f" · so được {count(lambda r: r['so_duoc'])}")


if __name__ == "__main__":
    main()
