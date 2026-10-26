"""Local v2 filter review operations. These commands never instantiate an LLM."""
from pathlib import Path
import json

from . import config, filter_approval as F


def register(sub):
    parser = sub.add_parser("filter-review", help="Phiếu lọc v2: preview, áp phiếu, chạy không nhãn, audit và SPL; không API")
    actions = parser.add_subparsers(dest="filter_action", required=True)
    p = actions.add_parser("prepare", help="Phát phiếu từ rule đã lưu và giả thuyết đã duyệt")
    p.add_argument("--rule", type=Path, required=True)
    p.add_argument("--hypothesis-dir", type=Path, required=True)
    p.add_argument("--hypothesis-id", required=True)
    p.add_argument("--events", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    for action in ("inspect", "finalize", "execute", "audit", "cancel"):
        p = actions.add_parser(action)
        p.add_argument("review_dir", type=Path)
        p.add_argument("--events", type=Path, required=action in ("execute", "audit"))
        if action in ("execute", "audit"):
            p.add_argument("--out", type=Path, required=True)
        if action == "cancel":
            p.add_argument("--nguoi-xac-nhan", required=True)
            p.add_argument("--ly-do", required=True)
    p = actions.add_parser("spl", help="Xuất SPL từ hunt hiệu lực, gồm đúng các nhóm approved")
    p.add_argument("hunt", type=Path)
    p.add_argument("--index", required=True)
    p.add_argument("--out", type=Path, required=True)
    parser.set_defaults(fn=main)


def main(a):
    from .data.store import connect
    from .hunt import runner
    con = None
    try:
        action = a.filter_action
        if action == "spl":
            from .adapters.splunk_sigma import convert_effective
            result = convert_effective(runner.load_spec(a.hunt), a.index)
            if a.out.exists():
                raise ValueError("đầu ra đã tồn tại; dùng tệp mới")
            F._write(a.out, result)
            print(f"Đã xuất {a.out}; chưa truy vấn Splunk")
            return 0
        events = a.events
        if events:
            from .agent.session import check_dataset
            check_dataset(events)
            con = connect(events)
        if action == "prepare":
            from . import approval
            from .adapters import duckdb_sigma
            from .agent.session import tracked_files
            from .stages import s5_rule
            approval.verify_saved_review(a.hypothesis_dir)
            hyps = [h for h in approval.load_hypotheses(a.hypothesis_dir / approval.APPROVED_FILE)
                    if h.hypothesis_id == a.hypothesis_id and h.status == "approved"]
            if len(hyps) != 1 or a.out.exists():
                raise ValueError("cần đúng giả thuyết approved và thư mục đầu ra mới")
            cfg = config.agent_config("v2")
            from .llm.prompting import load_sections
            prompt = load_sections(config.resolve(cfg["prompt_khau5"]), ("SYSTEM", "USER", "REPAIR"))
            ds = config.load("dataset")
            catalog = duckdb_sigma.load_catalog(config.resolve(ds["logsource_catalog"]))
            cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
            errors, specs = s5_rule.validate_rule(a.rule.read_text(encoding="utf-8"), hyps[0], catalog, cols, con,
                                                filter_policy=F.POLICY,
                                                candidate_regex_policy=s5_rule.candidate_policy(prompt))
            if errors:
                raise ValueError("; ".join(e.message for e in errors))
            deps = [config.resolve(p) for p in tracked_files(version="v2")]
            deps += [a.rule, *[a.hypothesis_dir / p for p in
                              (approval.HYP_FILE, approval.REVIEW_FILE, approval.APPROVED_FILE, approval.LOG_FILE)]]
            F.bind(con, a.out, dependencies=deps)
            rd = F.prepare(con, specs, a.out, a.out / "filter_review/r01", context={"kind": "stored_rule_prepare"})
            print(f"Phiếu lọc: {rd / F.FORM}; chưa thực thi")
            return 0
        rd = a.review_dir.resolve()
        if action == "cancel":
            print(F.cancel(rd, a.nguoi_xac_nhan, a.ly_do))
        elif action == "inspect":
            m, form = F.validate_form(rd, con=con, complete=False)
            result = {"review_kind": "filter", "form": form,
                      "preview": F._read(rd / "preview.json")}
            if (rd / F.RULE_FORM).exists():
                result["rule_form"] = F.validate_rule_form(rd, m, complete=False)
            if con:
                result["decision_preview"] = F.decision_preview(rd, con)
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        elif action == "finalize":
            for p in F.finalize(rd, con=con):
                print(p)
        elif action in ("execute", "audit"):
            from .replay import effective_packet
            result = effective_packet(rd, con, a.out, audit=action == "audit")
            print(f"Đã ghi {a.out}; {result['kind']}")
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Chặn phiếu lọc: {exc}")
        return 1
    finally:
        if con is not None:
            con.close()
