"""G0(c): chọn rule chuẩn SigmaHQ theo metadata cho execution accuracy khâu ⑤ (docs/METHODOLOGY.md).

Chỉ đọc metadata rule (status, logsource, tag ATT&CK) và mã kỹ thuật của giả thuyết đã duyệt. Không đọc kết quả hunt,
số khớp, nhãn hay điểm. Không mở rộng cha/con, không chọn theo tactic, không dùng mã kỹ thuật do rule sinh thêm.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import yaml

from ..adapters import duckdb_sigma
from ..hunt import runner
from ..stages import s8_pivot

STATUSES = ("stable", "test")
LOGSOURCE_KEYS = ("product", "category", "service")
TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rule_files(root: Path, subtree: str) -> list[Path]:
    return sorted((root / subtree).rglob("*.yml"), key=lambda p: p.relative_to(root).as_posix())


def pin_sigmahq(root: Path, subtree: str = "rules/windows") -> tuple[dict, str]:
    """Ghim bản SigmaHQ: commit, cây con có sạch không, manifest `sha256  đường-dẫn-POSIX` của từng tệp."""
    root = Path(root)
    files = _rule_files(root, subtree)
    manifest = "".join(f"{_sha256(f.read_bytes())}  {f.relative_to(root).as_posix()}\n" for f in files)

    def git(*args: str) -> str | None:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--", subtree) if commit else None
    return {"root": root.as_posix(), "subtree": subtree, "commit": commit,
            "clean": None if status is None else status == "",
            "files": len(files), "manifest_sha256": _sha256(manifest.encode("utf-8"))}, manifest


def rule_meta(path: Path, root: Path) -> dict:
    data = Path(path).read_bytes()
    docs = [d for d in yaml.safe_load_all(data.decode("utf-8")) if d is not None]
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise ValueError(f"cần đúng một YAML mapping, tệp có {len(docs)} tài liệu")
    doc = docs[0]
    tags = [str(t).strip().lower() for t in doc.get("tags") or []]
    logsource = doc.get("logsource") or {}
    return {"relative_path": Path(path).relative_to(root).as_posix(), "sha256": _sha256(data),
            "id": doc.get("id"), "title": doc.get("title"),
            "status": str(doc.get("status") or "").strip().lower(),
            "logsource": {k: logsource[k] for k in LOGSOURCE_KEYS if logsource.get(k) is not None},
            "tags": tags,
            "techniques": sorted({m.group(1) for t in tags if (m := TECHNIQUE_TAG.fullmatch(t))})}


def index_rules(root: Path, subtree: str = "rules/windows") -> tuple[list[dict], list[dict]]:
    """Metadata mọi rule trong cây con; tệp không đọc được ghi vào danh sách lỗi, không bỏ im lặng."""
    root = Path(root)
    metas, errors = [], []
    for f in _rule_files(root, subtree):
        try:
            metas.append(rule_meta(f, root))
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
            errors.append({"relative_path": f.relative_to(root).as_posix(), "loi": f"{type(exc).__name__}: {exc}"})
    return metas, errors


def logsource_key(logsource: dict | None) -> tuple[str, ...]:
    """Cùng logsource = cùng product, category, service; trường vắng coi là rỗng (G0(c) §2.1 mục 3)."""
    logsource = logsource or {}
    return tuple(str(logsource.get(k) or "").strip().lower() for k in LOGSOURCE_KEYS)


def select(metas: list[dict], logsource: dict, hypothesis_ttps: list[str]) -> list[dict]:
    """Mọi rule stable/test cùng logsource, có tag kỹ thuật trùng chính xác ít nhất một mã của giả thuyết."""
    wanted = {str(t).strip().lower() for t in hypothesis_ttps}
    key = logsource_key(logsource)
    return [m for m in metas
            if m["status"] in STATUSES and logsource_key(m["logsource"]) == key and wanted & set(m["techniques"])]


RULE_VERSIONS = ("v1", "v2")


def narrow_reference(ref: dict, gen: dict, rule_version: str = "v1") -> dict | None:
    """Phạm vi chuẩn dùng để so với một hunt sinh; None nếu không so được.

    v1 (G0(c) 26/9): chuẩn phải cùng đúng phạm vi (channel, tập EID, máy, thời gian).
    v2 (đề xuất trong docs/METHODOLOGY.md): cùng channel, máy, thời gian, và tập EID của hunt sinh là
    tập con của tập EID chuẩn (tập rỗng = mọi EID của channel) thì thu phạm vi EID của chuẩn về đúng tập đó. Chỉ phạm
    vi đổi; logic phát hiện (`candidates`, `filters`) của chuẩn giữ nguyên. Ghi lại phạm vi gốc để truy vết.
    """
    if rule_version not in RULE_VERSIONS:
        raise ValueError("quy tắc G0(c) phải là v1 hoặc v2")
    rs, gs = ref["scope"], gen["scope"]
    rest = lambda s: (str(s["channel"]).lower(), tuple(sorted(h.upper() for h in s.get("hosts") or [])),
                      s.get("time_from") or None, s.get("time_to") or None)
    ref_eids = {int(e) for e in rs.get("event_ids") or []}
    gen_eids = {int(e) for e in gs.get("event_ids") or []}
    if rest(rs) != rest(gs):
        return None
    if ref_eids == gen_eids:
        return ref
    if rule_version == "v1" or not gen_eids or (ref_eids and not gen_eids <= ref_eids):
        return None
    narrowed = {**ref, "scope": {**rs, "event_ids": sorted(gen_eids)},
                "g0c_v2_thu_hep_eid": {"chuan_goc": sorted(ref_eids) or "mọi EID", "theo_hunt_sinh": sorted(gen_eids)}}
    return narrowed


def pivot_reference_specs(rule_path: Path, catalog: dict, columns: set[str], gen_scope: dict,
                          hypothesis, rule_version: str = "v1") -> tuple[list[dict], list[str]]:
    """Chuẩn cho hunt pivot phải mang cùng ràng buộc pivot (G0(c) §2.2).

    Biên dịch rule chuẩn như khâu ⑤, giữ các hunt cùng channel và đúng tập EID của hunt sinh (v1: không tự thu hẹp EID
    của chuẩn; v2: thu hẹp theo `narrow_reference`), rồi khóa thực thể bằng chính `s8_pivot.bind_spec` mà khâu ⑤ đã
    dùng cho hunt sinh.
    """
    hunts, skipped = duckdb_sigma.compile_rule(Path(rule_path), catalog, columns)
    probe = {"scope": {**gen_scope, "hosts": [], "time_from": None, "time_to": None}}
    specs = []
    for h in hunts:
        spec = h.to_hunt_spec()
        unbound = narrow_reference(spec, probe, rule_version)   # ràng buộc máy/tài khoản pivot gắn sau, như hunt sinh
        if unbound is None:
            continue
        spec = s8_pivot.bind_spec(unbound, hypothesis, columns)
        runner.validate(spec)
        specs.append(spec)
    return specs, [f"{s.source}: {s.ly_do}" for s in skipped]
