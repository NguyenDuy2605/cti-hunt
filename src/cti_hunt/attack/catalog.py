"""Danh mục ATT&CK Enterprise từ file STIX đúng phiên bản cố định (v19.2, quy tắc R14).

Dùng cho: kiểm tra hình thức file nhãn (lệnh check-labels), khâu ② (loại mã không tồn tại, v3 §7),
và bước quy đổi mã bị thu hồi trước khi đo (đếm tỷ lệ mã thu hồi trên đầu ra thô trước).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Technique:
    tid: str
    name: str
    tactics: list[str] = field(default_factory=list)      # shortname: persistence, lateral-movement...
    revoked: bool = False
    deprecated: bool = False
    stix_id: str = ""


@dataclass
class Resolution:
    input: str
    status: str            # ok | revoked | deprecated | unknown
    final: str | None      # mã dùng khi đo (mã thay thế nếu bị thu hồi)
    name: str | None = None


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def tactic_key(name: str) -> str:
    """'Lateral Movement' -> 'lateral-movement' (khớp x_mitre_shortname)."""
    return "-".join(name.strip().lower().replace("&", "and").split())


class AttackCatalog:
    def __init__(self, techniques: dict[str, Technique], revoked_by: dict[str, str],
                 tactics: dict[str, str], version: str | None):
        self.techniques = techniques
        self.revoked_by = revoked_by          # tid cũ -> tid thay thế
        self.tactics = tactics                # shortname -> tên hiển thị
        self.version = version

    @classmethod
    def from_stix(cls, path: Path) -> "AttackCatalog":
        bundle = json.loads(path.read_text(encoding="utf-8"))
        objs = bundle["objects"]
        by_stix = {o["id"]: o for o in objs}
        techniques: dict[str, Technique] = {}
        for o in objs:
            if o.get("type") != "attack-pattern":
                continue
            tid = _ext_id(o)
            if not tid:
                continue
            t = Technique(tid, o.get("name", ""),
                          [p["phase_name"] for p in o.get("kill_chain_phases", [])
                           if p.get("kill_chain_name") == "mitre-attack"],
                          bool(o.get("revoked")), bool(o.get("x_mitre_deprecated")), o["id"])
            cur = techniques.get(tid)
            if cur is None or (cur.revoked and not t.revoked):   # ưu tiên bản còn hiệu lực
                techniques[tid] = t
        revoked_by = {}
        for o in objs:
            if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
                src, dst = by_stix.get(o["source_ref"]), by_stix.get(o["target_ref"])
                if src and dst and src.get("type") == dst.get("type") == "attack-pattern":
                    s, d = _ext_id(src), _ext_id(dst)
                    if s and d:
                        revoked_by[s] = d
        tactics = {o["x_mitre_shortname"]: o["name"] for o in objs if o.get("type") == "x-mitre-tactic"}
        version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), None)
        return cls(techniques, revoked_by, tactics, version)

    def resolve(self, tid: str) -> Resolution:
        tid = tid.strip().upper()
        t = self.techniques.get(tid)
        if t is None:
            return Resolution(tid, "unknown", None)
        if t.revoked:
            cur, seen = tid, set()
            while cur in self.revoked_by and cur not in seen:     # thu hồi nối tiếp
                seen.add(cur)
                cur = self.revoked_by[cur]
            final = self.techniques.get(cur)
            return Resolution(tid, "revoked", cur if cur != tid else None, final.name if final else None)
        if t.deprecated:
            return Resolution(tid, "deprecated", None, t.name)
        return Resolution(tid, "ok", tid, t.name)
