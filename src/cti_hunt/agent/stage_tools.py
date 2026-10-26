"""Công cụ thật của graph D10 trên fixture/OTRF phát triển, chỉ truy vấn events.

Mô hình được tiêm vào (dựng ở agent/session.py). Hết lượt ghi `agent_dev_record.json` (nhật ký phát triển) và
`hunt_record.md` (khâu ⑨ bản vận hành, không nhãn). Chỉ số đánh giá có nhãn do người vận hành đo riêng bằng `hunt` trên các
thư mục `round_*/hunts`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import duckdb
import yaml

from .. import approval
from ..contracts import ContractA, ContractB
from ..hunt import runner
from ..hunt.observe import run_unlabeled, unlabeled_result
from ..stages import (execution_semantics, rule_variant, s2_ioc, s2_ioc_sweep, s4_hypothesis, s5_rule, s7_rarity, s8_pivot, s8_triage,
                      s9_record)
from .graph import AgentState, Decision
from .chi_phi import run_cost
from .limits import hypothesis_budget


class StageTools:
    """Nối ④, ⑤, ⑥ không nhãn và ⑧ vào graph; các file vòng nằm dưới review_root."""

    def __init__(self, contract_a: ContractA, telemetry: dict, logsource_catalog: dict,
                 con: duckdb.DuckDBPyConnection, cfg: dict, llm_hypotheses, llm_rules,
                 prompt_hypotheses: dict, prompt_pivot: dict, prompt_rules: dict,
                 review_root: Path, *, dataset_kind: str, dataset_id: str,
                 dataset_sha256: str = "", attack_catalog=None, filter_dependencies: list[Path] = ()):
        # danh_gia: APT29 day 2, chỉ tới đây sau khi session.start đã kiểm mốc cố định (agent/moc.py).
        if dataset_kind not in ("fixture", "otrf_dev", "danh_gia") or not dataset_id.strip():
            raise ValueError("E1: chỉ fixture, OTRF phát triển hoặc tập đánh giá sau mốc cố định, có mã định danh")
        if dataset_kind in ("otrf_dev", "danh_gia") and not re.fullmatch(r"[0-9a-fA-F]{64}", dataset_sha256):
            raise ValueError("E1: dữ liệu OTRF cần SHA256 để kiểm tập dữ liệu")
        self.ca = contract_a
        self.telemetry = telemetry
        self.logsource_catalog = logsource_catalog
        self.con = con
        self.cfg = cfg
        self.llm_hypotheses = llm_hypotheses
        self.llm_rules = llm_rules
        self.prompt_hypotheses = prompt_hypotheses
        self.prompt_pivot = prompt_pivot
        self.prompt_rules = prompt_rules
        self.review_root = Path(review_root)
        self.dataset = {"kind": dataset_kind, "id": dataset_id, "sha256": dataset_sha256}
        self.attack_catalog = attack_catalog
        if cfg.get("filter_policy_id"):
            from .. import filter_approval
            filter_approval.bind(con, self.review_root, dependencies=filter_dependencies)
        # 15/10: ưu tiên khoảng trống — TTP chưa có rule cộng đồng mức cao được săn trước; chỉ metadata SigmaHQ, không nhãn.
        self.coverage = None
        if cfg.get("khoang_trong_rule_cong_dong"):
            from .. import config as _config
            from ..stages import community_rules
            if _config.resolve(cfg.get("rule_cong_dong_root") or community_rules.SIGMAHQ).is_dir():
                channels = {r[0] for r in con.execute("SELECT DISTINCT ev_channel FROM events").fetchall()}
                self.coverage = community_rules.coverage(
                    community_rules.techniques(contract_a), channels,
                    cfg.get("rule_cong_dong_root") or community_rules.SIGMAHQ)

    def initial_state(self) -> AgentState:
        """Chỉ đưa TTP huntable/partial trong Contract A cho planner."""
        inputs, _ = s4_hypothesis.select_inputs(self.ca, self.telemetry, self.coverage,
                                                skip_covered=bool(self.cfg.get("chi_san_khoang_trong")))
        return {"report_id": self.ca.report_id,
                "remaining_refs": [i["ref"] for i in inputs],
                "techniques": [{"ref": i["ref"], "technique_id": i["ttp"].technique_id,
                                "tactic": i["ttp"].tactic,
                                "behavior_description": i["ttp"].behavior_description,
                                "relevance_score": i["score"],
                                "relevance_components": i["score_components"]} for i in inputs],
                "observations": [], "eligible_pivots": [], "rarity_summary": {},
                "pivot_depth": 0, "queries_reserved": 0, "history": [],
                "generated_ids": [], "approved_files": []}

    def _all_hypotheses(self, state: AgentState) -> list[ContractB]:
        return [h for p in state.get("approved_files") or [] for h in approval.load_hypotheses(Path(p))]

    def _executed_hypotheses(self, state: AgentState) -> list[ContractB]:
        ids = {f["hypothesis_id"] for f in state.get("executed_specs") or []}
        return [h for h in self._all_hypotheses(state) if h.hypothesis_id in ids and h.status == "approved"]

    def propose(self, state: AgentState, decision: Decision, run_dir: Path) -> list[ContractB]:
        if state["report_id"] != self.ca.report_id:
            raise ValueError("report_id của graph khác Contract A")
        if decision.action == "hunt":
            allowed = {i["ref"] for i in s4_hypothesis.select_inputs(self.ca, self.telemetry)[0]}
            if not set(decision.ttp_refs) <= allowed:
                raise ValueError("TTP được chọn không huntable/partial trong Contract A")
            
            remaining_budget = hypothesis_budget(state, self.cfg)['remaining']
            if remaining_budget <= 0:
                raise ValueError("đã hết ngân sách tổng số giả thuyết độc lập (N5)")
            effective_max_per_round = min(int(self.cfg["max_hypotheses_per_round"]), remaining_budget)
            
            cfg_copy = self.cfg.copy()
            cfg_copy["max_hypotheses_per_round"] = effective_max_per_round
            
            subset = self.ca.model_copy(update={"ttps": [self.ca.ttps[r] for r in decision.ttp_refs]})
            result = s4_hypothesis.generate(subset, self.telemetry, self.llm_hypotheses,
                                            self.prompt_hypotheses, cfg_copy, self.attack_catalog, run_dir,
                                            anchors=self._executed_hypotheses(state) if self.cfg.get("sinh_rang_buoc") else [],
                                            coverage=self.coverage)
            prefix = re.compile(rf"^{re.escape(self.ca.report_id)}-H(\d+)$")
            next_index = 1 + max((int(m.group(1)) for hid in state.get("generated_ids") or []
                                  if (m := prefix.fullmatch(hid))), default=0)
            hyps = [h.model_copy(update={"hypothesis_id": f"{self.ca.report_id}-H{next_index + i:02d}"})
                    for i, h in enumerate(result["hypotheses"])]
            meta = {"selected_ttp_refs": decision.ttp_refs, "khau4": result["log"], "dataset": self.dataset}
        elif decision.action == "pivot":
            targets = {(p.loai, p.gia_tri) for p in decision.pivot_targets}
            selected = [p for p in state.get("eligible_pivots") or [] if (p["loai"], p["gia_tri"]) in targets]
            plan = {"selected": selected, "source_depth": state.get("pivot_depth", 0),
                    "triage": {"pivot": {"de_xuat": selected}}}
            result = s8_pivot.generate_round(self.ca, self.telemetry, self._all_hypotheses(state),
                                             plan, self.llm_hypotheses, self.prompt_pivot, self.cfg,
                                             self.attack_catalog, run_dir,
                                             anchors=self._executed_hypotheses(state) if self.cfg.get("sinh_rang_buoc") else [])
            hyps = result["hypotheses"]
            meta = {"selected_pivots": selected, "khau4": result["log"], "dataset": self.dataset}
        else:
            return []
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "agent_proposal.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return hyps

    def _rarity(self, specs: list[dict]) -> dict | None:
        rarity_cfg = self.cfg["rarity"]
        return s7_rarity.score(self.con, specs,
                               window_seconds=int(rarity_cfg["recon_window_seconds"]),
                               entropy_threshold=float(rarity_cfg["entropy_threshold"])) if specs else None

    def execute(self, state: AgentState, approved: list[ContractB]) -> dict:
        if self.cfg.get("filter_policy_id"):
            from .. import filter_approval as filters
            rd = Path(state["filter_review_dir"])
            packet = filters.verify_packet(rd, con=self.con)
            files = filters.finalize(rd, con=self.con)
            executed_at = filters.utcnow().isoformat()
            depth = approved[0].pivot_depth
            blocked = filters.blocked_rules(rd)
            kept = [s for s in packet["specs"] if s["id"] not in blocked]   # cùng thứ tự với tệp hiệu lực
            spec_files = [{"path": str(p), "hypothesis_id": s["hypothesis_id"], "pivot_depth": depth}
                          for p, s in zip(files, kept, strict=True)]
            result = self._execute_specs(state, spec_files, packet["context"]["rule_log"],
                                         depth, packet["context"]["budget_exhausted"],
                                         rule_bi_bo=[{"hunt_id": k, **v} for k, v in blocked.items()],
                                         rule_rut_gon=filters.revision_chain(rd))
            filters.receipt(rd, con=self.con, executed_at=executed_at)
            return result
        spec_files, rule_log, depth, exhausted = self._generate_rules(state, approved)
        return self._execute_specs(state, spec_files, rule_log, depth, exhausted)

    def prepare_rules(self, state: AgentState, approved: list[ContractB]) -> dict:
        """⑤ is completed and checkpointed before the separate filter interrupt."""
        from .. import filter_approval as filters
        run_dir = Path(state["review_dir"])
        approval.verify_saved_review(run_dir)
        rd = run_dir / "filter_review" / "r01"
        if (rd / filters.MANIFEST).exists():
            filters.verify_packet(rd, con=self.con)
            return {"filter_review_dir": str(rd)}
        drafts, rule_log, depth, exhausted = self._generate_rules(state, approved)
        paths = [run_dir / approval.HYP_FILE, run_dir / approval.REVIEW_FILE,
                 run_dir / approval.APPROVED_FILE, run_dir / approval.LOG_FILE]
        paths += list((run_dir / "rules_draft").glob("*.yml"))
        meta = self.review_root / "run_meta.json"
        if meta.exists():
            paths.append(meta)
        # 09/10: rule có mục đối chiếu (⑤ tự thêm giá trị/regex) phải được người duyệt giữ/bỏ; chỉ khi cấu hình bật,
        # nên context của các lượt cũ không đổi.
        filters.prepare(self.con, drafts, self.review_root, rd,
                        context={"rule_log": rule_log, "budget_exhausted": exhausted, "pivot_depth": depth,
                                 **({"doi_chieu_rule": True} if self.cfg.get("duyet_rule_doi_chieu") else {}),
                                 **({"do_rong_rule": True} if self.cfg.get("duyet_rule_do_rong") else {})},
                        dependencies=paths)
        return {"filter_review_dir": str(rd)}

    def revise_rules(self, state: AgentState) -> dict:
        """10/10: người duyệt chọn rút gọn rule → phát bản sửa của gói (r01 → r02 …), 0 lời gọi mô hình.
        Rule rút gọn chỉ bỏ đúng các mục đã chọn và đi lại kiểm tĩnh/biên dịch như rule ⑤; rule khác giữ nguyên draft.
        Mọi quyết định lọc/rule của bản sửa do người duyệt điền lại; gói cũ bị khóa, không thực thi được."""
        from .. import filter_approval as filters
        rd = Path(state["filter_review_dir"])
        filters.validate_form(rd, con=self.con)
        plan = filters.revision_specs(self.con, rd)
        # Bản sửa gắn với đúng gói và phiếu đã quyết: sửa phiếu cũ sau đó thì bản sửa không qua verify_packet.
        filters.prepare(self.con, plan["specs"], self.review_root, plan["new_dir"], context=plan["context"],
                        dependencies=plan["dependencies"])
        filters.mark_revised(rd, plan["new_dir"])
        return {"filter_review_dir": str(plan["new_dir"])}

    def _generate_rules(self, state: AgentState, approved: list[ContractB]) -> tuple:
        run_dir = Path(state["review_dir"])
        cols = {r[0] for r in self.con.execute("DESCRIBE events").fetchall()}
        spec_files, rule_log = [], []
        depth = approved[0].pivot_depth
        exhausted = ""                  # hết ngân sách giữa lô: các giả thuyết còn lại không gọi ⑤
        anchors = self._anchors(state, approved)
        for h in approved:
            if exhausted:
                result = s5_rule.budget_skipped(h, exhausted)
            else:
                result = s5_rule.generate_rule(h, self.llm_rules, self.prompt_rules,
                                               self.logsource_catalog, int(self.cfg["max_repair_attempts"]),
                                               cols, self.con, run_dir,
                                               **({"filter_policy": self.cfg["filter_policy_id"]} if self.cfg.get("filter_policy_id") else {}),
                                               **({"stop_repair_on_empty_source": True}
                                                  if self.cfg.get("dung_sua_khi_nguon_rong") else {}),
                                               **({"anchors": anchors} if anchors else {}))
                exhausted = s5_rule.budget_exhausted(result)
            rule_log.append(result)
            if not result["hop_le"]:
                continue
            rules_dir = run_dir / ("rules_draft" if self.cfg.get("filter_policy_id") else "rules")
            rules_dir.mkdir(exist_ok=True)
            if self.cfg.get("filter_policy_id"):
                (rules_dir / f"{h.hypothesis_id}.yml").write_bytes(result["rule_yaml"].encode("utf-8"))
            else:
                (rules_dir / f"{h.hypothesis_id}.yml").write_text(result["rule_yaml"], encoding="utf-8")
            if self.cfg.get("filter_policy_id"):
                spec_files.extend(result["hunt_specs"])
                continue
            (run_dir / "hunts").mkdir(exist_ok=True)
            for spec in result["hunt_specs"]:
                path = run_dir / "hunts" / f"{h.hypothesis_id}__{spec['id'].split('__')[-1]}.yaml"
                path.write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8")
                spec_files.append({"path": str(path), "hypothesis_id": h.hypothesis_id, "pivot_depth": depth})
        return spec_files, rule_log, depth, exhausted

    @staticmethod
    def _anchors(state: AgentState, approved: list[ContractB]) -> dict[str, str]:
        """Tập sự kiện cuối của giả thuyết neo, chỉ từ hunt đã chạy ở vòng trước của chính lượt này."""
        wanted = {h.rang_buoc.moc_neo.gia_thuyet for h in approved if h.rang_buoc and h.rang_buoc.moc_neo}
        found: dict[str, list[dict]] = {}
        for f in state.get("executed_specs") or []:
            if f.get("hypothesis_id") in wanted:
                found.setdefault(f["hypothesis_id"], []).append(runner.load_spec(Path(f["path"])))
        return {hid: execution_semantics.anchor_sql(specs) for hid, specs in found.items()}

    def _execute_specs(self, state: AgentState, spec_files: list[dict], rule_log: list[dict], depth: int, exhausted: str,
                       rule_bi_bo: list[dict] | None = None, rule_rut_gon: list[dict] | None = None) -> dict:
        run_dir = Path(state["review_dir"])
        # Đọc lại từ tệp để spec mang đúng SHA256 của tệp mà `hunt` sẽ chạy khi đo (khâu ⑦/⑨ khớp theo hash).
        specs = [runner.load_spec(Path(f["path"])) for f in spec_files]
        observations = [run_unlabeled(self.con, spec) for spec in specs]
        # ⑦ và ⑧ tính trên MỌI hunt cùng độ sâu đã chạy, không chỉ lô này: một vòng săn từ report có thể phải
        # chia nhiều lô vì trần giả thuyết D7, và tương quan chéo giữa các lô vẫn phải thấy được.
        peers = [runner.load_spec(Path(f["path"])) for f in state.get("executed_specs") or []
                 if f["pivot_depth"] == depth]
        rarity = self._rarity(peers + specs)
        rarity_summary = {"so_su_kien": rarity["so_su_kien"], "top": rarity["su_kien"][:5]} if rarity else {}
        already = {(p["loai"], p["gia_tri"]) for h in state.get("history") or []
                   for p in h["decision"].get("pivot_targets") or []}
        tri = s8_triage.triage(self.con, peers + specs, self.cfg, pivot_depth=depth,
                              queries_used=state.get("queries_reserved", 0), already_pivoted=already)
        (run_dir / "agent_execute.json").write_text(json.dumps({"dataset": self.dataset,
            "khau5": {"prompt": self.prompt_rules.get("path"),
                       "prompt_sha256": self.prompt_rules.get("sha256"),
                       "model": getattr(self.llm_rules, "model_id", "?")},
            "rules": [{"hypothesis_id": r["hypothesis_id"], "hop_le": r["hop_le"],
                       "so_lan_sua": r["so_lan_sua"], "token": r.get("token"),
                       "loi": r['lan_thu'][-1]['loi']} for r in rule_log],
            "observations": observations, "rarity_summary": rarity_summary, "triage": tri,
            **({"rule_bi_bo": rule_bi_bo} if rule_bi_bo else {}),
            **({"rule_rut_gon": rule_rut_gon} if rule_rut_gon else {})},
            ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return {"observations": observations, "rarity_summary": rarity_summary,
                "eligible_pivots": tri["pivot"]["ung_vien_du_dieu_kien"], "spec_files": spec_files,
                "budget_exhausted": exhausted}

    def _execution_issues(self, state):
        issues = []
        for approved_file in state.get('approved_files') or []:
            path = Path(approved_file).parent / 'agent_execute.json'
            if path.exists():
                data = json.loads(path.read_text(encoding='utf-8'))
                issues.extend({'hypothesis_id': r['hypothesis_id'], 'issues': r.get('loi') or []}
                              for r in data['rules'] if not r['hop_le'])
                # Rule hợp lệ nhưng người duyệt bỏ tại cổng (đối chiếu ⑤): chưa thực thi, không phải 0 sự kiện.
                issues.extend({'hypothesis_id': b['hypothesis_id'],
                               'issues': [{'kind': 'nguoi_duyet_bo_rule',
                                           'message': f"người duyệt bỏ rule {b['hunt_id']} tại cổng lọc: {b['ly_do']}"}]}
                              for b in data.get('rule_bi_bo') or [])
        return issues

    def _shortened_rules(self, state) -> list[dict]:
        """Rule đã chạy sau khi người duyệt rút gọn (bỏ đúng các mục đối chiếu đã chọn), theo thứ tự vòng."""
        found = []
        for approved_file in state.get('approved_files') or []:
            path = Path(approved_file).parent / 'agent_execute.json'
            if path.exists():
                found.extend(json.loads(path.read_text(encoding='utf-8')).get('rule_rut_gon') or [])
        return found

    def ioc_sweep(self) -> dict:
        """Khâu quét IOC (14/10): IOC mạnh của Contract A trên ``events``; không nhãn, không gọi mô hình."""
        from .. import config
        rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
        return s2_ioc_sweep.sweep(s2_ioc_sweep.plan(self.ca, rules), self.con,
                                  exclude_accounts=(self.cfg.get("triage") or {}).get("exclude_accounts"))

    def community_run(self) -> dict | None:
        """Công cụ lai (15/10): rule SigmaHQ mức high/critical có tag trùng TTP của report, chạy trên ``events`` của lượt.
        Rule cộng đồng không qua cổng duyệt giả thuyết; kết quả là ứng viên cho người săn rà, như hunt hệ thống. Không nhãn."""
        if not self.cfg.get("rule_cong_dong_trong_luot"):
            return None
        if not hasattr(self, "_community"):
            from .. import config as _config
            from ..stages import community_rules
            root = self.cfg.get("rule_cong_dong_root") or community_rules.SIGMAHQ
            self._community = (community_rules.run(self.con, self.ca, root, levels=community_rules.HIGH)
                               if _config.resolve(root).is_dir() else None)
        return self._community

    def rule_variants(self, specs: list[dict]) -> list[dict]:
        """Biến thể mức kỹ thuật (14/10) của rule v2 đã chạy: chỉ đếm trên ``events``, không chạy trong lượt, không nhãn."""
        rows = rule_variant.compare([s for s in specs if not s.get("bien_the")], self.con)
        for r in rows:
            r.pop("spec")
        return rows

    def hunt_record(self, state: AgentState) -> str:
        """Khâu ⑨ bản vận hành cho cả lượt: chạy lại mọi hunt đã thực thi trên ``events``, không nhãn."""
        specs = [runner.load_spec(Path(f["path"])) for f in state.get("executed_specs") or []]
        results = [unlabeled_result(self.con, spec) for spec in specs]
        tri = None
        if specs:
            tri = s8_triage.triage(self.con, specs, self.cfg)
            # Hết lượt thì không còn đề xuất pivot; pivot đã chạy nằm trong nhật ký vòng (pivot_log).
            tri["pivot"] = {"de_xuat": [], "ung_vien_du_dieu_kien": [], "chua_xet": [], "da_pivot_truoc": [],
                            "ly_do_dung": ""}
        verb = {"hunt": "săn", "pivot": "pivot", "stop": "dừng"}
        pivot_log = [{"vong": i, "hypothesis_id": ", ".join(h.get("generated_ids") or []) or "—",
                      "pivot_depth": h.get("pivot_depth", ""), "selected": h.get("selected") or [],
                      "ly_do_dung": f"{verb[h['decision']['action']]}: {h['decision']['reason']}"
                                    + (f" — không sinh được giả thuyết: {h['het_ngan_sach']}"
                                       if h.get('het_ngan_sach') else "")
                                    + (f" — mô hình từ chối ④, không gọi lại: {h['mo_hinh_tu_choi']}"
                                       if h.get('mo_hinh_tu_choi') else "")
                                    + (f" — planner chọn dừng khi còn {h['dung_do_planner']['ttp_con_lai']} TTP chưa săn, "
                                       f"{h['dung_do_planner']['pivot_du_dieu_kien']} pivot đủ điều kiện; "
                                       "bộ chặn bằng mã chưa kích hoạt"
                                       if (h.get('dung_do_planner') or {}).get('ttp_con_lai')
                                       or (h.get('dung_do_planner') or {}).get('pivot_du_dieu_kien') else "")}
                     for i, h in enumerate(state.get("history") or [], start=1)]
        md = s9_record.render(self.ca, self.telemetry, self._all_hypotheses(state), results,
                              pivot_log=pivot_log, triage=tri, rarity=self._rarity(specs))
        blocked = self._execution_issues(state)
        if blocked:
            md += '\n\n## Giả thuyết bị chặn trước thực thi\n\n'
            md += 'Các mục dưới đây chưa được kiểm chứng bằng truy vấn, không phải kết quả 0 sự kiện.\n\n'
            for item in blocked:
                messages = '; '.join(str(i.get('message', i.get('kind', ''))) for i in item['issues'])
                md += f"- {item['hypothesis_id']}: {messages}\n"
        shortened = self._shortened_rules(state)
        if shortened:
            md += '\n\n## Rule người duyệt rút gọn trước thực thi\n\n'
            md += 'Rule do ⑤ sinh đã bị người duyệt bỏ đúng các điều kiện dưới đây (chỉ xóa, không thêm) rồi mới chạy.\n\n'
            for c in shortened:
                parts = '; '.join(f"{i['truong']} = {i['gia_tri']} (khối {i['khoi']})" for i in c['bo_muc'])
                md += f"- {c['hypothesis_id']} ({c['id']}, gói {c['goi']}): bỏ {parts} — {c['ly_do']}\n"
        if self.ca.iocs:
            md += "\n\n" + s2_ioc_sweep.render(self.ioc_sweep())
        if self.coverage:
            from ..stages import community_rules
            md += "\n\n" + community_rules.render_coverage(self.coverage)
        community = self.community_run()
        if community is not None:
            from ..stages import community_rules
            skipped = sorted(t for t, v in (self.coverage or {}).items() if v["muc"] == "cao") \
                if self.cfg.get("chi_san_khoang_trong") else []
            md += "\n\n" + community_rules.render(
                community, "### Rule cộng đồng đã chạy trong lượt (SigmaHQ mức high/critical theo TTP)")
            if skipped:
                md += ("\n\nChế độ chỉ săn khoảng trống: " + str(len(skipped)) + " TTP đã có rule cộng đồng mức cao không "
                       "đưa vào ④ (" + ", ".join(t.upper() for t in skipped) + ").")
        ran = [s for s in specs if s.get("bien_the")]
        if ran:
            md += '\n\n### Rule chạy bằng biến thể mức kỹ thuật (người duyệt chọn)\n\n'
            for s in ran:
                md += f"- {s.get('hypothesis_id', '')} (`{s['id']}`): {s['bien_the']['mo_ta']}\n"
        variants = self.rule_variants(specs)
        if variants:
            md += "\n\n" + rule_variant.render(variants)
        path = self.review_root / "hunt_record.md"
        path.write_text(md, encoding="utf-8")
        return str(path)

    def record(self, state: AgentState) -> str:
        self.review_root.mkdir(parents=True, exist_ok=True)
        path = self.review_root / "agent_dev_record.json"
        record = {"report_id": self.ca.report_id, "dataset": self.dataset,
                  "agent_config": self.cfg, "planner": state.get("planner_meta") or {},
                  "history": state.get("history") or [],
                  "observations": state.get("observations") or [],
                  "rarity_summary": state.get("rarity_summary") or {},
                  "queries_reserved": state.get("queries_reserved", 0),
                  "approved_files": state.get("approved_files") or [],
                  "executed_specs": state.get("executed_specs") or [],
                  "execution_issues": self._execution_issues(state),
                  "hunt_record": self.hunt_record(state),
                  "ioc_sweep": self.ioc_sweep() if self.ca.iocs else None,
                  "khoang_trong_rule_cong_dong": self.coverage,
                  "rule_cong_dong_trong_luot": self.community_run(),
                  "chi_san_khoang_trong": bool(self.cfg.get("chi_san_khoang_trong")),
                  "bien_the_rule": self.rule_variants([runner.load_spec(Path(f["path"]))
                                                       for f in state.get("executed_specs") or []]),
                  # N5 (02/10): chi phí từ nhật ký API của chính lượt; đối soát cuối vẫn bằng sổ ngân sách.
                  "chi_phi_api_luot": run_cost(self.review_root),
                  "kind": "development_only_unlabeled"}
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)
