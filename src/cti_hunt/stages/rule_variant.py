"""Biến thể mức kỹ thuật cho rule khâu ⑤ (configs/bien_the_rule.yaml).

Rule ⑤ bám câu nguồn: nó bắt đúng thủ tục report mô tả, nhưng trượt khi kẻ tấn công khác dùng cùng kỹ thuật với phần tải
khác (đo trên 7 kịch bản OTRF: rule WMI, WinRM đòi `rundll32` như Raindrop, còn Empire chạy `powershell`). Mô-đun này dựng,
bằng quy tắc xác định, một biến thể giữ "vết cơ chế" của kỹ thuật và nới "phần tải":

- tạo tiến trình: tiến trình cha thuộc danh sách vết cơ chế (WmiPrvSE, wsmprovhost…) thì giữ cha, thay tiến trình con cụ
  thể bằng nhóm trình thông dịch/LOLBin, bỏ điều kiện dòng lệnh;
- nội dung script PowerShell: chỉ giữ tên cmdlet (Động-từ-Danh-từ, động từ của Get-Verb), bỏ đường dẫn, tên tệp, regex;
- WMI subscription: giữ trường loại sự kiện, bỏ mọi điều kiện nội dung (Query, Destination, Consumer…).

Loại rule khác không có biến thể. Khối lọc (`filter_*`) của rule gốc không mang sang: biến thể là rule mới, mục lọc phải qua
duyệt lại. Không gọi mô hình, không dùng kết quả truy vấn hay nhãn; người duyệt quyết dùng rule gốc hay biến thể.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

from ..adapters.duckdb_sigma import compile_text, load_catalog
from .. import config

VERSION = "bien_the_ky_thuat_v1"
CONFIG = "configs/bien_the_rule.yaml"
_ORLIKE = re.compile(r"\bor\b|\b1 of\b|\ball of\b", re.I)
_FILTER = re.compile(r"^filter", re.I)


def load_config(path: str | Path = CONFIG) -> dict:
    cfg = yaml.safe_load(config.resolve(path).read_text(encoding="utf-8"))
    if cfg.get("version") != VERSION:
        raise ValueError(f"{path}: version phải là {VERSION}")
    return cfg


def _base(key: str) -> tuple[str, list[str]]:
    field, *mods = key.split("|")
    return field, mods


def _values(v) -> list:
    return list(v) if isinstance(v, list) else [v]


def _blocks(detection: dict) -> tuple[list[tuple[str, dict]], list[str], str]:
    """(các cặp trường–giá trị của khối dương, tên khối lọc, điều kiện)."""
    cond = detection.get("condition")
    cond = cond[0] if isinstance(cond, list) and len(cond) == 1 else cond
    if not isinstance(cond, str):
        raise ValueError("rule có nhiều condition")
    pos, filters = [], []
    for name, body in detection.items():
        if name == "condition":
            continue
        if _FILTER.match(name):
            filters.append(name)
            continue
        for item in _values(body):
            if not isinstance(item, dict):
                raise ValueError(f"khối {name} có từ khóa không gắn trường")
            pos.extend((k, v) for k, v in item.items())
    return pos, filters, cond


def _exe(value) -> str:
    return str(value).replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _dedupe(items) -> list:
    seen, out = set(), []
    for x in items:
        if x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out


# Mỗi hàm dưới trả danh sách khối (các khối nối bằng AND) sao cho biến thể chọn ít nhất mọi sự kiện rule gốc chọn: chỉ bỏ
# điều kiện hoặc bỏ phương án trong điều kiện "tất cả", không thu hẹp điều kiện "một trong".

def _process(pos, cfg) -> tuple[list[dict] | None, str]:
    parents = [(k, v) for k, v in pos if _base(k)[0] == "ParentImage"]
    if not parents:
        return None, "rule tạo tiến trình không có điều kiện tiến trình cha"
    mech = cfg["tien_trinh_cha_co_che"]
    names = sorted({_exe(x) for _, v in parents for x in _values(v)})
    if any(n not in mech for n in names):
        return None, f"tiến trình cha {names} không thuộc danh sách vết cơ chế"
    dropped = sorted({_base(k)[0] for k, _ in pos if _base(k)[0] != "ParentImage"})
    # Tiến trình con của rule gốc (so đuôi) giữ trong nhóm để biến thể không hẹp hơn rule gốc.
    own = [_exe(x) for k, v in pos if k == "Image|endswith" for x in _values(v)]
    children = _dedupe(list(cfg["tien_trinh_con"]) + own)
    sel = {k: v for k, v in parents}
    sel["Image|endswith"] = ["\\" + x for x in children]
    return [sel], (f"giữ tiến trình cha {', '.join(names)}; tiến trình con thay bằng nhóm {len(children)} "
                   f"trình thông dịch/LOLBin; bỏ điều kiện {', '.join(dropped) or '(không có)'}")


def _script(pos, cfg) -> tuple[list[dict] | None, str]:
    verbs = "|".join(sorted(cfg["dong_tu_powershell"], key=len, reverse=True))
    rx = re.compile(rf"(?<![\w-])((?:{verbs})-[A-Za-z]+)(?![\w-])", re.I)
    blocks, kept, dropped = [], [], 0
    for k, v in pos:
        f, mods = _base(k)
        if f not in ("ScriptBlock", "ScriptBlockText", "Payload") or "re" in mods:
            dropped += 1
            continue
        found = [rx.findall(str(x)) for x in _values(v)]
        if "all" in mods:
            # "phải có tất cả": bỏ phần tải, giữ cmdlet.
            cmd = _dedupe(c for fs in found for c in fs)
            dropped += sum(1 for x, fs in zip(_values(v), found) if [c.lower() for c in fs] != [str(x).strip().lower()])
            if cmd:
                blocks.append({f"{f}|contains|all": cmd})
        elif all(found):
            # "một trong": chỉ giữ khi mọi phương án đều là cmdlet; nếu không, bỏ cả điều kiện.
            cmd = _dedupe(c for fs in found for c in fs)
            blocks.append({f"{f}|contains": cmd if len(cmd) > 1 else cmd[0]})
        else:
            dropped += 1
            continue
        kept += cmd
    if not blocks:
        return None, "nội dung script không có tên cmdlet để giữ"
    return blocks, f"chỉ giữ cmdlet {', '.join(_dedupe(kept))}; bỏ {dropped} điều kiện nội dung khác"


def _wmi(pos, cfg, eids) -> tuple[list[dict] | None, str]:
    keep = set(cfg["truong_loai_wmi"])
    sel = {k: v for k, v in pos if _base(k)[0] in keep}
    dropped = sorted({_base(k)[0] for k, _ in pos if _base(k)[0] not in keep})
    if not sel:
        sel = {"EventID": list(eids)}
    return [sel], f"giữ loại sự kiện WMI; bỏ điều kiện nội dung {', '.join(dropped) or '(không có)'}"


def variant_rule(rule: dict, eids: list[int], cfg: dict) -> tuple[dict | None, str]:
    """Trả (rule Sigma biến thể, mô tả) hoặc (None, lý do không có biến thể)."""
    ls = rule.get("logsource") or {}
    kind = ls.get("category") or ls.get("service")
    try:
        pos, filters, cond = _blocks(rule["detection"])
    except ValueError as e:
        return None, str(e)
    orlike = bool(_ORLIKE.search(cond.replace(" of filter", " of_filter")))
    if kind == "process_creation":
        if orlike:
            return None, "điều kiện có nhánh OR, chưa hỗ trợ"
        blocks, note = _process(pos, cfg)
    elif kind in ("ps_script", "ps_module"):
        if orlike:
            return None, "điều kiện có nhánh OR, chưa hỗ trợ"
        blocks, note = _script(pos, cfg)
    elif kind == "wmi_event":
        blocks, note = _wmi(pos, cfg, eids)
    else:
        return None, f"loại nguồn {kind} chưa có quy tắc biến thể"
    if blocks is None:
        return None, note
    conds = sorted((k, repr(v)) for b in blocks for k, v in b.items())
    if not filters and conds == sorted((k, repr(v)) for k, v in pos):
        return None, "rule đã ở mức kỹ thuật (biến thể trùng rule gốc)"
    if filters:
        note += f"; không mang {len(filters)} khối lọc"
    out = {k: copy.deepcopy(v) for k, v in rule.items() if k in ("title", "logsource", "tags", "level")}
    out["title"] = f"{rule.get('title', '')} — biến thể mức kỹ thuật"
    if len(blocks) == 1:
        out["detection"] = {"selection": blocks[0], "condition": "selection"}
    else:
        out["detection"] = {**{f"selection_{i}": b for i, b in enumerate(blocks, start=1)},
                            "condition": "all of selection_*"}
    return out, note


def variant_spec(spec: dict, cfg: dict, catalog: dict | None = None) -> tuple[dict | None, str]:
    """Từ hunt spec đã chạy (có sigma_context.rule) dựng hunt spec của biến thể trên cùng nguồn log."""
    ctx = spec.get("sigma_context") or {}
    rule, source = ctx.get("rule"), ctx.get("source")
    if not rule or not source:
        return None, "hunt spec không có rule Sigma gốc"
    var, note = variant_rule(rule, spec["scope"]["event_ids"], cfg)
    if var is None:
        return None, note
    catalog = catalog if catalog is not None else load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    hunts, skipped = compile_text(yaml.safe_dump(var, allow_unicode=True, sort_keys=False), catalog)
    match = [h for h in hunts if h.source == source]
    if not match:
        return None, f"biến thể không biên dịch được cho nguồn {source}: {[s.ly_do for s in skipped]}"
    out = match[0].to_hunt_spec()
    out.update(id=f"{spec['id']}__bien_the", linked_ttps=list(spec.get("linked_ttps") or []),
               bien_the={"version": VERSION, "tu_rule": spec["id"], "mo_ta": note,
                         "rule": var})
    return out, note


def _is_root(spec: dict) -> bool:
    """Hunt gốc: không gắn thực thể pivot, không ràng buộc nhiều sự kiện (biến thể của chúng phải giữ ràng buộc, chưa hỗ trợ)."""
    b = (spec.get("sigma_context") or {}).get("binding") or {}
    sc = spec.get("scope") or {}
    return not (b.get("pivot_value") or spec.get("rang_buoc") or sc.get("hosts") or sc.get("time_from"))


def _count(con, spec: dict, filters: list[dict]) -> tuple[int, int]:
    from ..hunt import runner
    scope = runner._scope_where(spec["scope"])
    where = [scope, f"({spec['candidates']})"] + [f"({f['where']}) IS NOT TRUE" for f in filters]
    total = con.execute(f"SELECT count(*) FROM events WHERE {scope}").fetchone()[0]
    kept = con.execute(f"SELECT count(*) FROM events WHERE {' AND '.join(where)}").fetchone()[0]
    return total, kept


def compare(specs: list[dict], con, cfg: dict | None = None) -> list[dict]:
    """Rule gốc và biến thể trên cùng bộ log: số sự kiện trong phạm vi nguồn, gốc giữ (sau mục lọc đã áp), biến thể giữ.
    Chỉ đếm, không nhãn; người duyệt đọc để quyết có nên dùng biến thể."""
    cfg = cfg if cfg is not None else load_config()
    catalog = load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    rows = []
    for spec in specs:
        if not _is_root(spec):
            continue
        var, note = variant_spec(spec, cfg, catalog)
        if var is None:
            continue
        try:
            total, kept = _count(con, spec, spec.get("filters") or [])
            _, var_kept = _count(con, var, [])
        except Exception as e:  # noqa: BLE001 — cột thiếu ở bộ này: báo, không đoán
            total = kept = var_kept = None
            note += f"; không đếm được: {type(e).__name__}"
        rows.append({"hunt": spec["id"], "hypothesis_id": spec.get("hypothesis_id", ""), "mo_ta": note,
                     "pham_vi": total, "goc": kept, "bien_the": var_kept, "spec": var})
    return rows


def render(rows: list[dict]) -> str:
    out = ["### Biến thể mức kỹ thuật của rule (chỉ để xem)", "",
           "Rule ⑤ bám thủ tục trong report. Biến thể giữ vết cơ chế của kỹ thuật, nới phần tải (configs/bien_the_rule.yaml, "
           f"{VERSION}); chưa chạy trong lượt, chưa qua duyệt. Số là số sự kiện trên bộ log của lượt, không nhãn.", "",
           "| Hunt | Biến thể | Trong phạm vi | Rule gốc giữ | Biến thể giữ |", "|---|---|---:|---:|---:|"]
    for r in rows:
        hid = f"{r['hypothesis_id']} · " if r["hypothesis_id"] else ""
        cell = lambda v: "—" if v is None else str(v)  # noqa: E731
        out.append(f"| {hid}`{r['hunt']}` | {r['mo_ta']} | {cell(r['pham_vi'])} | {cell(r['goc'])} | {cell(r['bien_the'])} |")
    out += ["", "Biến thể giữ nhiều hơn rule gốc chưa phải phát hiện: phần thêm có thể là hoạt động bình thường. Muốn dùng thì "
            "chạy hunt spec của biến thể (lệnh rule-variants) và qua duyệt như rule mới."]
    return "\n".join(out)
