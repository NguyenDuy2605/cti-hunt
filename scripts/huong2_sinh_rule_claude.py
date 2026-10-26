"""Câu hỏi 2, hướng 2, phương án (b): sinh rule bằng Claude Sonnet 5 cho một mẫu ngẫu nhiên kỹ thuật có nhãn L1, cùng chuỗi
③ → ④ → ⑤ và cùng đầu vào như lượt 7B/14B (``huong2_sinh_rule.py``), không người duyệt.

Giao thức đặt trước: ``docs/METHODOLOGY.md``. Script này **không sửa** ``huong2_sinh_rule.py``
(giao thức 24 ghim băm của nó), chỉ dùng lại hàm của nó. Không đọc nhãn sự kiện.

- ``chuan-bi`` (0 API, agent chạy được): kiểm băm hồ sơ ③ đã lưu của lượt 7B; khung mẫu = kỹ thuật L1 có ít nhất một TTP vào ④;
  trộn khung bằng hạt giống ghi trong giao thức, lấy 25 kỹ thuật đầu; dựng sẵn yêu cầu ④ của từng kỹ thuật đúng như sẽ gửi
  (thân HTTP, chưa gửi) và băm; dự toán tiền từ các lời gọi ④/⑤ cùng mô hình đã chạy trước đây.
- ``chay`` mặc định chỉ kiểm (0 API): mọi băm còn khớp, dựng lại yêu cầu ④ phải trùng gói, đọc sổ ngân sách chỉ đọc.
- ``chay --send --cap-usd X``: **chỉ người vận hành chạy**. Gọi ④⑤ qua sổ ngân sách chung (giữ tiền trước mỗi lời gọi), thêm trần riêng
  của gói; chạy kỹ thuật theo thứ tự đã trộn tới khi đủ mẫu hoặc chạm trần. Yêu cầu ④ khác gói thì dừng trước khi gửi.
  Mô hình từ chối hoặc trả đầu ra hỏng: ghi lại, không gọi lại (D11-săn). Lỗi mạng: dừng; đối soát sổ rồi chạy lại đúng lệnh,
  kỹ thuật dở dang được cất sang ``_bi_ngat/`` và chạy lại từ đầu, chi phí lần dở vẫn tính.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Callable

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import huong2_sinh_rule as hsr  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.adapters import duckdb_sigma  # noqa: E402
from cti_hunt.attack.catalog import AttackCatalog  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.llm import budget, providers  # noqa: E402
from cti_hunt.llm.prompting import load_sections  # noqa: E402
from cti_hunt.stages import s3_telemetry, s4_hypothesis, s5_rule  # noqa: E402

GIAO_THUC = "docs/METHODOLOGY.md"
HO_SO_SHA = "e959ab5563c985fcce40f54232e92b69a92d3792e38b99e1a3cc634968aa5bfd"   # hồ sơ ③ của lượt 7B và 14B
HAT_GIONG_MAU = 20261019
SO_MAU = 25
TRAN_GOI_TOI_DA = Decimal("5.00")      # người vận hành cho tối đa khoảng 5 USD cho phần mở rộng đề tài (16/10)
DU_PHONG_KY_THUAT = Decimal("0.70")    # chỉ bắt đầu kỹ thuật mới khi gói còn đủ giữ trước ④ rồi một lời gọi ⑤
DU_PHONG_LOI_GOI = Decimal("0.40")     # chặn trên khoản giữ trước của một lời gọi (32.000 token ra ≈ 0,32 USD + phần vào)
TEP_CAU_HINH = ("configs/agent_v2.yaml", "configs/llm_hunt.yaml", "configs/telemetry_catalog_v2_2.yaml",
                "configs/logsource_catalog.yaml", "configs/dataset.yaml")


def sha_tep(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def sha_ma_nguon() -> str:
    """Băm gộp mọi tệp ``src/cti_hunt/**/*.py`` (như cổng E2): mã khâu ③④⑤, adapter, sổ ngân sách đổi thì gói không còn hợp lệ."""
    h = hashlib.sha256()
    root = config.ROOT / "src" / "cti_hunt"
    for p in sorted(root.rglob("*.py")):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def chuan_hoa(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha_payload(payload: dict) -> str:
    return hashlib.sha256(chuan_hoa(payload).encode("utf-8")).hexdigest()


def phan_dem(payload: dict) -> dict:
    """Phần thân được đếm token (như ``budget.guarded_request``)."""
    return {k: payload[k] for k in ("model", "system", "messages", "tools", "tool_choice") if k in payload}


def chon_mau(khung: list[str], hat_giong: int = HAT_GIONG_MAU, so: int = SO_MAU) -> list[str]:
    """Trộn khung (đã sắp theo mã) bằng hạt giống, lấy ``so`` kỹ thuật đầu. Thứ tự trả về là thứ tự chạy."""
    import random
    thu_tu = sorted(khung)
    random.Random(hat_giong).shuffle(thu_tu)
    return thu_tu[:so]


class _DaBat(Exception):
    pass


class BatYeuCau:
    """Client giả: ghi lại system/user/lược đồ của lời gọi rồi dừng, không gửi gì."""

    def __init__(self, model_id: str):
        self.model_id, self.bat = model_id, None

    def complete_json(self, system, user, json_schema, log=None):
        self.bat = (system, user, json_schema)
        raise _DaBat()


class SaiYeuCau(RuntimeError):
    """Yêu cầu ④ dựng lúc chạy khác yêu cầu đã dựng sẵn trong gói: dừng trước khi gửi."""


class ClientGoi:
    """Bọc client Anthropic thật: kiểm yêu cầu ④ trùng gói và trần riêng của gói trước mỗi lời gọi.

    ``da_chi()`` trả số USD gói đã chi theo sổ chung (chi đã biết hiện tại trừ chi đã biết lúc gói bắt đầu; mọi chi khác trên sổ
    trong lúc đó cũng bị tính, theo hướng bảo thủ)."""

    def __init__(self, inner, da_chi: Callable[[], Decimal], tran: Decimal):
        self.inner, self.da_chi, self.tran = inner, da_chi, tran
        self.model_id = inner.model_id
        self.mong_doi: str | None = None
        self.so_loi_goi = 0
        self.su_kien: list[dict] = []     # token của mọi lời gọi đã gửi, kể cả lời gọi lỗi sau khi gửi (đầu ra hỏng)

    def complete_json(self, system, user, json_schema, log=None):
        payload = self.inner.build_payload(system, user, json_schema)
        if self.mong_doi is not None:
            mong, self.mong_doi = self.mong_doi, None
            if sha_payload(payload) != mong:
                raise SaiYeuCau(f"yêu cầu ④ dựng lúc chạy có băm {sha_payload(payload)[:12]}…, gói ghi {mong[:12]}…; "
                                "chưa gửi. Dựng lại gói bằng chuan-bi")
        chi = self.da_chi()
        if chi + DU_PHONG_LOI_GOI > self.tran:
            raise budget.BudgetExhausted(f"trần gói {self.tran} USD: gói đã chi {chi} USD, cần chừa {DU_PHONG_LOI_GOI} USD "
                                         "cho một lời gọi; chưa gửi")
        self.so_loi_goi += 1

        def ghi(e):
            self.su_kien.append(dict(e))
            if log is not None:
                log(e)
        return self.inner.complete_json(system, user, json_schema, ghi)


def chi_phi_usd(events: list[dict], model: str = "claude-sonnet-5") -> float:
    ir, ore = budget.RATES[model]
    return sum((e.get("input_tokens") or 0) * ir + (e.get("output_tokens") or 0) * ore for e in events) / budget.SCALE


# ------------------------------------------------------------------------------------------------------------------ chuẩn bị
@dataclass
class MoiTruong:
    cfg: dict
    p4: dict
    p5: dict
    ls_catalog: dict
    cat: AttackCatalog
    telemetry: dict
    llm_cfg: dict
    tham_chieu: dict = field(default_factory=dict)


def nap_moi_truong(ho_so: Path) -> MoiTruong:
    cfg = config.agent_config("v2")
    p4 = load_sections(config.resolve(cfg["prompt_khau4"]))
    p5 = load_sections(config.resolve(cfg["prompt_khau5"]), ("SYSTEM", "USER", "REPAIR"))
    profile = json.loads(Path(ho_so).read_text(encoding="utf-8"))
    if s3_telemetry.profile_sha256(profile) != HO_SO_SHA:
        raise SystemExit(f"hồ sơ ③ {ho_so} không khớp băm của lượt 7B/14B ({HO_SO_SHA[:12]}…)")
    catalog = s3_telemetry.load_catalog(config.telemetry_catalog("v2"))
    return MoiTruong(cfg=cfg, p4=p4, p5=p5,
                     ls_catalog=duckdb_sigma.load_catalog(config.resolve(config.load("dataset")["logsource_catalog"])),
                     cat=AttackCatalog.from_stix(config.resolve(hsr.STIX)),
                     telemetry=s3_telemetry.apply_profile(catalog, profile), llm_cfg=config.load("llm_hunt"))


def client_that(llm_cfg: dict):
    """Client Anthropic dựng từ ``configs/llm_hunt.yaml`` (chỉ để dựng thân yêu cầu khi chuẩn bị; gửi chỉ ở ``--send``)."""
    c = providers.from_config(llm_cfg)
    if not isinstance(c, providers.AnthropicClient):
        raise SystemExit("configs/llm_hunt.yaml không trỏ tới Anthropic")
    return c


def dung_yeu_cau_khau4(it: dict, mt: MoiTruong, thu_muc: Path) -> tuple[dict, int]:
    """Thân HTTP của lời gọi ④ cho một kỹ thuật, dựng bằng đúng ``s4_hypothesis.generate``; trả (payload, số TTP vào ④)."""
    ca = ContractA.model_validate(it["contract_a"])
    inputs, _ = s4_hypothesis.select_inputs(ca, mt.telemetry)
    bat = BatYeuCau(mt.llm_cfg["model"])
    try:
        s4_hypothesis.generate(ca, mt.telemetry, bat, mt.p4, mt.cfg, mt.cat, thu_muc, anchors=[], coverage=None)
    except _DaBat:
        pass
    if bat.bat is None:
        raise SystemExit(f"{it['goc']}: không có TTP nào vào ④, không thuộc khung mẫu")
    system, user, schema = bat.bat
    return client_that(mt.llm_cfg).build_payload(system, user, schema), len(inputs)


def khung_mau(D: dict, uu_tien: list[str], mt: MoiTruong) -> tuple[list[str], dict]:
    """Kỹ thuật L1 (danh sách ưu tiên của giao thức 24) có ít nhất một TTP vào ④ với hồ sơ ③ này."""
    theo_goc = {x["goc"]: x for x in D["ky_thuat"]}
    khung, loai = [], {}
    for g in sorted(uu_tien):
        it = theo_goc.get(g)
        if it is None or "bo_qua" in it:
            loai[g] = "không có trong dau_vao hoặc mã chỉ còn ngừng dùng"
            continue
        inputs, _ = s4_hypothesis.select_inputs(ContractA.model_validate(it["contract_a"]), mt.telemetry)
        if inputs:
            khung.append(g)
        else:
            loai[g] = "khong_san_duoc: danh mục ③ không có nguồn log thu thập được"
    return khung, loai


def dau_vao_bam(a, ho_so: Path) -> dict:
    return {"giao_thuc": [GIAO_THUC, sha_tep(config.resolve(GIAO_THUC))],
            "script": sha_tep(Path(__file__)), "script_huong2_sinh_rule": sha_tep(Path(hsr.__file__)),
            "ma_nguon_src": sha_ma_nguon(),
            "dau_vao": [str(a.dau_vao), sha_tep(a.dau_vao)], "uu_tien": [str(a.uu_tien), sha_tep(a.uu_tien)],
            "ho_so": [str(ho_so), sha_tep(ho_so)], "tom_tat_nap": sha_tep(Path(a.parquet) / "tom_tat_nap.json"),
            "cau_hinh": {t: sha_tep(config.resolve(t)) for t in TEP_CAU_HINH}}


def lich_su(goc_lich_su: list[str]) -> dict:
    """Lời gọi ④ (prompt v6, Sonnet 5) và ⑤ đã chạy trước đây, để dự toán: mỗi lời gọi ④ có số ký tự phần được đếm token, token
    vào/ra, số TTP vào, số giả thuyết; mỗi giả thuyết có ⑤ là danh sách (token vào, token ra) của các lời gọi ⑤ của nó."""
    k4, k5 = [], []
    mt_schema = s4_hypothesis.output_model(config.agent_config("v2")).model_json_schema()
    c = None
    for root in goc_lich_su:
        for p in sorted(glob.glob(str(Path(root) / "**" / "agent_proposal.json"), recursive=True)):
            try:
                d = json.loads(Path(p).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            log = (d.get("khau4") if isinstance(d, dict) else None) or {}
            ev = log.get("api_events") or []
            if "khau4_gia_thuyet_v6" not in str(log.get("prompt")) or log.get("model") != "claude-sonnet-5" or len(ev) != 1:
                continue
            req = Path(p).parent / "request.json"
            if not req.exists():
                continue
            r = json.loads(req.read_text(encoding="utf-8"))
            c = c or client_that(config.load("llm_hunt"))
            ky_tu = len(chuan_hoa(phan_dem(c.build_payload(r["system"], r["user"], mt_schema))))
            k4.append({"tep": str(Path(p).parent), "ky_tu": ky_tu, "vao": ev[0]["input_tokens"],
                       "ra": ev[0]["output_tokens"], "so_ttp": log.get("so_ttp_dau_vao"), "so_gt": log.get("so_gia_thuyet")})
            k5f = Path(p).parent / "khau5_requests.jsonl"
            if k5f.exists():
                theo_gt: dict = {}
                for line in k5f.read_text(encoding="utf-8").splitlines():
                    x = json.loads(line)
                    theo_gt.setdefault(x.get("hypothesis_id"), []).extend(
                        [(e.get("input_tokens") or 0, e.get("output_tokens") or 0) for e in x.get("api_events") or []])
                k5 += list(theo_gt.values())
    return {"khau4": k4, "khau5": k5}


def _pv(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))] if xs else 0.0


def du_toan(yeu_cau: dict[str, dict], ls: dict, lan: int = 20000, hat_giong: int = 20261019) -> dict:
    """Dự toán tổng USD bằng mô phỏng lấy mẫu lại từ lịch sử: mỗi kỹ thuật bốc một lời gọi ④ cùng nhóm số TTP (token ra, số
    giả thuyết, tỷ lệ token/ký tự của chính lời gọi đó áp lên số ký tự yêu cầu đã dựng), mỗi giả thuyết bốc một giả thuyết ⑤
    đã chạy (mọi lời gọi ⑤ của nó, kể cả sửa). Báo trung vị và phân vị 90 của tổng; ``yeu_cau`` = {goc: {ky_tu, so_ttp}}."""
    import random
    k4, k5 = ls["khau4"], ls["khau5"]
    if not k4 or not k5:
        raise SystemExit("không có lời gọi ④/⑤ lịch sử để dự toán")
    ir, ore = budget.RATES["claude-sonnet-5"]

    def nhom(n):
        return "1-4" if n <= 4 else ("5-7" if n <= 7 else "8-10")

    theo_nhom = {}
    for x in k4:
        theo_nhom.setdefault(nhom(x["so_ttp"] or 0), []).append(x)
    usd5 = [sum(v * ir + r * ore for v, r in g) / budget.SCALE for g in k5]
    rng = random.Random(hat_giong)
    ds = [(y["ky_tu"], theo_nhom.get(nhom(y["so_ttp"])) or k4) for y in yeu_cau.values()]
    tong, tong4 = [], []
    for _ in range(lan):
        t4 = t5 = 0.0
        for ky_tu, h in ds:
            x = rng.choice(h)
            t4 += (ky_tu * x["vao"] / x["ky_tu"] * ir + x["ra"] * ore) / budget.SCALE
            t5 += sum(rng.choice(usd5) for _ in range(x["so_gt"] or 0))
        tong.append(t4 + t5)
        tong4.append(t4)
    ti_le = [x["vao"] / x["ky_tu"] for x in k4]
    return {"so_loi_goi_khau4_lich_su": len(k4), "so_gia_thuyet_khau5_lich_su": len(k5),
            "so_loi_goi_khau5_lich_su": sum(len(g) for g in k5), "lan_mo_phong": lan, "hat_giong": hat_giong,
            "token_moi_ky_tu_min_trung_vi_max": [round(min(ti_le), 4), round(_pv(ti_le, 0.5), 4), round(max(ti_le), 4)],
            "usd_khau5_moi_gia_thuyet_trung_vi_p90": [round(_pv(usd5, 0.5), 4), round(_pv(usd5, 0.9), 4)],
            "khau4_theo_nhom_so_ttp": {k: {"so_loi_goi": len(v), "ra_trung_vi": _pv([x["ra"] for x in v], 0.5),
                                           "ra_p90": _pv([x["ra"] for x in v], 0.9),
                                           "gia_thuyet_trung_vi": _pv([x["so_gt"] or 0 for x in v], 0.5),
                                           "gia_thuyet_p90": _pv([x["so_gt"] or 0 for x in v], 0.9)}
                                       for k, v in sorted(theo_nhom.items())},
            "nhom_cua_ky_thuat": {g: nhom(y["so_ttp"]) for g, y in yeu_cau.items()},
            "tong_usd": {"trung_vi": round(_pv(tong, 0.5), 3), "p90": round(_pv(tong, 0.9), 3),
                         "p99": round(_pv(tong, 0.99), 3), "khau4_trung_vi": round(_pv(tong4, 0.5), 3)},
            "trung_binh_moi_ky_thuat": round(sum(tong) / lan / max(1, len(ds)), 4)}


def chuan_bi(a) -> int:
    goi = Path(a.goi)
    if goi.exists() and any(goi.iterdir()):
        raise SystemExit(f"{goi} đã có tệp: dựng gói mới ở thư mục mới, không ghi đè")
    ho_so = Path(a.ho_so)
    mt = nap_moi_truong(ho_so)
    D = json.loads(Path(a.dau_vao).read_text(encoding="utf-8"))
    uu_tien = json.loads(Path(a.uu_tien).read_text(encoding="utf-8"))["ky_thuat"]
    khung, loai = khung_mau(D, uu_tien, mt)
    mau = chon_mau(khung)
    theo_goc = {x["goc"]: x for x in D["ky_thuat"]}
    yeu_cau = {}
    for g in mau:
        tm = goi / "yeu_cau" / g
        payload, n_in = dung_yeu_cau_khau4(theo_goc[g], mt, tm / "khau4")
        (tm / "khau4_payload.json").write_text(chuan_hoa(payload), encoding="utf-8")
        yeu_cau[g] = {"sha256": sha_payload(payload), "ky_tu": len(chuan_hoa(phan_dem(payload))), "so_ttp": n_in}
    dt = du_toan(yeu_cau, lich_su(a.lich_su or []))
    (goi / "du_toan.json").write_text(json.dumps(dt, ensure_ascii=False, indent=1), encoding="utf-8")
    man = {"giao_thuc": GIAO_THUC, "luc": time.strftime("%Y-%m-%d %H:%M:%S"), "bam": dau_vao_bam(a, ho_so),
           "hat_giong": HAT_GIONG_MAU, "so_mau": SO_MAU, "khung": khung, "loai_khoi_khung": loai, "mau": mau,
           "yeu_cau_khau4": yeu_cau, "mo_hinh": client_that(mt.llm_cfg).describe(),
           "prompt_khau4": [mt.p4["path"], mt.p4["sha256"]], "prompt_khau5": [mt.p5["path"], mt.p5["sha256"]],
           "du_toan_usd": dt["tong_usd"]}
    (goi / "goi.json").write_text(json.dumps(man, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"khung {len(khung)} kỹ thuật (loại {sorted(loai)}); mẫu {len(mau)}: {mau}")
    print(f"dự toán: trung vị {dt['tong_usd']['trung_vi']} USD, p90 {dt['tong_usd']['p90']} USD "
          f"(mô phỏng từ {dt['so_loi_goi_khau4_lich_su']} lời gọi ④ và {dt['so_loi_goi_khau5_lich_su']} lời gọi ⑤ đã chạy)")
    return 0


# ---------------------------------------------------------------------------------------------------------------------- chạy
def _chi_bam(v):
    """Bỏ đường dẫn, chỉ giữ mã băm: cùng tệp gõ bằng ``\\`` hay ``/``, tương đối hay tuyệt đối vẫn là một."""
    return v[1] if isinstance(v, list) else v


def kiem_goi(goi: dict, a, ho_so: Path) -> list[str]:
    hien = dau_vao_bam(a, ho_so)
    return [k for k, v in goi["bam"].items() if _chi_bam(hien.get(k)) != _chi_bam(v)]


def doc_so_chi_doc(path: Path) -> dict:
    con = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        limit = con.execute("SELECT limit_usd FROM settings WHERE id=1").fetchone()[0]
        known, held = con.execute("SELECT COALESCE(SUM(charged),0), "
                                  "COALESCE(SUM(CASE WHEN charged IS NULL THEN reserved ELSE 0 END),0) FROM requests").fetchone()
        n = con.execute("SELECT count(*) FROM requests").fetchone()[0]
    finally:
        con.close()
    return {"so_request": n, "han_muc": budget.usd(limit), "da_chi": budget.usd(known), "dang_giu": budget.usd(held),
            "con_lai": budget.usd(limit - known - held)}


@dataclass
class BoiCanh:
    out: Path
    client: ClientGoi
    tran: Decimal
    da_chi: Callable[[], Decimal]
    tao_gia_thuyet: Callable          # (it, tdir) -> (hyps đã đặt approved, log ④); có thể ném lỗi của client
    tao_rule: Callable                # (h, tdir) -> kết quả s5_rule.generate_rule
    yeu_cau: dict                     # {goc: sha256 payload ④}
    ghi: Callable[[dict], None] = print


def cat_ky_thuat_do_dang(out: Path, goc: str) -> Path | None:
    tdir = out / "ky_thuat" / goc
    if not tdir.exists() or (tdir / "xong.json").exists():
        return None
    dich = out / "_bi_ngat" / f"{goc}__{time.strftime('%Y%m%d-%H%M%S')}"
    dich.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(tdir), str(dich))
    return dich


def chay_mot(it: dict, bc: BoiCanh) -> str:
    """Một kỹ thuật. Trả 'xong' hoặc 'dung_ngan_sach'. Lỗi mạng và yêu cầu sai gói ném ra ngoài (kỹ thuật để dở)."""
    tdir = bc.out / "ky_thuat" / it["goc"]
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "bat_dau.json").write_text(json.dumps({"luc": time.strftime("%Y-%m-%d %H:%M:%S")}), encoding="utf-8")
    kq = {"goc": it["goc"], "hien_hanh": it.get("hien_hanh"), "thu_tu_dau_vao": it["thu_tu"], "gia_thuyet": [],
          "khau5": [], "khau4": None}
    t0, n0 = time.monotonic(), len(bc.client.su_kien)
    bc.client.mong_doi = bc.yeu_cau[it["goc"]]
    trang_thai = "xong"
    try:
        hyps, kq["khau4"] = bc.tao_gia_thuyet(it, tdir)
    except budget.BudgetExhausted as e:
        kq["khau4"] = {"dung_ngan_sach": str(e)}
        hyps, trang_thai = [], "dung_ngan_sach"
    except providers.RefusalError as e:
        kq["khau4"] = {"tu_choi": str(e)[:300]}
        hyps = []
    except providers.BadOutputError as e:
        kq["khau4"] = {"dau_ra_hong": str(e)[:300]}
        hyps = []
    finally:
        bc.client.mong_doi = None
    kq["gia_thuyet"] = [{**json.loads(h.model_dump_json()), "tu_dong_duyet_benchmark": True} for h in hyps]
    for h in hyps:
        if trang_thai != "xong":
            break
        try:
            r5 = bc.tao_rule(h, tdir)
        except providers.BadOutputError as e:
            r5 = {"hypothesis_id": h.hypothesis_id, "hop_le": False, "dau_ra_hong": str(e)[:300], "hunt_specs": [],
                  "rule_yaml": None}
        if r5.get("lan_thu") and s5_rule.budget_exhausted(r5):
            trang_thai = "dung_ngan_sach"
        if r5.get("hop_le"):
            (tdir / "rules").mkdir(exist_ok=True)
            (tdir / "rules" / f"{h.hypothesis_id}.yml").write_text(r5["rule_yaml"], encoding="utf-8")
            (tdir / "hunts").mkdir(exist_ok=True)
            for spec in r5["hunt_specs"]:
                (tdir / "hunts" / f"{spec['id']}.yaml").write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False),
                                                                   encoding="utf-8")
        kq["khau5"].append({k: r5.get(k) for k in ("hypothesis_id", "hop_le", "hop_le_lan_dau", "so_lan_sua", "dau_ra_hong",
                                                    "token")}
                           | {"so_hunt": len(r5.get("hunt_specs") or []),
                              "api_events": [e for x in r5.get("lan_thu") or [] for e in x.get("api_events") or []],
                              "loi_cuoi": (r5.get("lan_thu") or [{}])[-1].get("loi")})
    ev = bc.client.su_kien[n0:]
    kq.update(trang_thai=trang_thai, so_loi_goi=len(ev), usd_theo_token=round(chi_phi_usd(ev), 6),
              giay=round(time.monotonic() - t0, 1))
    (tdir / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    if trang_thai == "xong":
        (tdir / "xong.json").write_text(json.dumps({"luc": time.strftime("%Y-%m-%d %H:%M:%S")}), encoding="utf-8")
    bc.ghi({"goc": it["goc"], "trang_thai": trang_thai, "gia_thuyet": len(hyps),
            "rule_hop_le": sum(1 for x in kq["khau5"] if x.get("hop_le")), "usd": kq["usd_theo_token"], "giay": kq["giay"]})
    return trang_thai


def chay_vong(mau: list[dict], bc: BoiCanh) -> dict:
    """Chạy theo thứ tự mẫu; bỏ qua kỹ thuật đã xong; cất kỹ thuật dở dang; dừng khi chạm trần gói."""
    bi_ngat, ly_do_dung = [], "het_mau"
    for it in mau:
        d = cat_ky_thuat_do_dang(bc.out, it["goc"])
        if d is not None:
            bi_ngat.append(str(d))
        if (bc.out / "ky_thuat" / it["goc"] / "xong.json").exists():
            continue
        if bc.da_chi() + DU_PHONG_KY_THUAT > bc.tran:
            ly_do_dung = "tran_goi"
            break
        if chay_mot(it, bc) != "xong":
            ly_do_dung = "tran_goi"
            break
    xong = [it["goc"] for it in mau if (bc.out / "ky_thuat" / it["goc"] / "xong.json").exists()]
    return {"ly_do_dung": ly_do_dung, "ky_thuat_xong": xong, "bi_ngat_lan_nay": bi_ngat}


def chay(a) -> int:
    goi_dir = Path(a.goi)
    goi = json.loads((goi_dir / "goi.json").read_text(encoding="utf-8"))
    ho_so = Path(a.ho_so)
    sai = kiem_goi(goi, a, ho_so)
    if sai:
        raise SystemExit(f"gói không còn khớp ({', '.join(sai)}): dựng gói mới bằng chuan-bi trước khi gửi")
    mt = nap_moi_truong(ho_so)
    D = json.loads(Path(a.dau_vao).read_text(encoding="utf-8"))
    theo_goc = {x["goc"]: x for x in D["ky_thuat"]}
    mau = [theo_goc[g] for g in goi["mau"]]
    with tempfile.TemporaryDirectory() as tmp:
        for it in mau:
            payload, _ = dung_yeu_cau_khau4(it, mt, Path(tmp) / it["goc"])
            if sha_payload(payload) != goi["yeu_cau_khau4"][it["goc"]]["sha256"]:
                raise SystemExit(f"{it['goc']}: yêu cầu ④ dựng lại khác gói; dừng")
    so = budget.configured_path()
    print(f"gói khớp: {len(mau)} kỹ thuật, yêu cầu ④ dựng lại trùng gói. Sổ (chỉ đọc): {doc_so_chi_doc(so)}")
    print(f"dự toán gói: {goi['du_toan_usd']}")
    if not a.send:
        print("chưa gửi gì (thiếu --send)")
        return 0

    tran = Decimal(str(a.cap_usd))
    if not Decimal("0") < tran <= TRAN_GOI_TOI_DA:
        raise SystemExit(f"--cap-usd phải trong (0; {TRAN_GOI_TOI_DA}]")
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    if not os.environ.get(mt.llm_cfg["api_key_env"]):
        raise SystemExit(f"chưa đặt biến môi trường {mt.llm_cfg['api_key_env']}")
    out.mkdir(parents=True, exist_ok=True)
    ledger = budget.Ledger(so)
    st = ledger.status()
    if st["pending"]:
        raise SystemExit("sổ còn yêu cầu chưa rõ chi phí: đối soát Console (api-budget resolve) trước")
    ns_path = out / "ngan_sach_goi.json"
    ns = json.loads(ns_path.read_text(encoding="utf-8")) if ns_path.exists() else {
        "da_chi_luc_bat_dau": st["known_cost_usd"], "lan_chay": []}
    ns["lan_chay"].append({"luc": time.strftime("%Y-%m-%d %H:%M:%S"), "tran_usd": str(tran), "so_luc_nay": st})
    ns_path.write_text(json.dumps(ns, ensure_ascii=False, indent=1), encoding="utf-8")
    goc_chi = Decimal(ns["da_chi_luc_bat_dau"])

    def da_chi() -> Decimal:
        return Decimal(ledger.status()["known_cost_usd"]) - goc_chi

    lock = out / "dang_chay.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise SystemExit(f"{lock} đã có: một lượt khác đang chạy, hoặc lượt trước dừng đột ngột (xem api-budget status, "
                         "rồi xóa tệp khóa bằng tay)")
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    try:
        con, n_bo = hsr.mo_hop(Path(a.parquet))
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        inner = client_that(mt.llm_cfg)
        client = ClientGoi(inner, da_chi, tran)
        (out / "cau_hinh_luot.json").write_text(json.dumps({
            "giao_thuc": GIAO_THUC, "goi": str(goi_dir), "goi_sha256": sha_tep(goi_dir / "goi.json"),
            "mo_hinh": inner.describe(), "prompt_khau4": goi["prompt_khau4"], "prompt_khau5": goi["prompt_khau5"],
            "so_bo_du_lieu": n_bo, "ho_so_sha256": HO_SO_SHA, "danh_muc": str(config.telemetry_catalog("v2")),
            "mau": goi["mau"]}, ensure_ascii=False, indent=1), encoding="utf-8")
        cfg = mt.cfg

        def tao_gia_thuyet(it, tdir):
            ca = ContractA.model_validate(it["contract_a"])
            r4 = s4_hypothesis.generate(ca, mt.telemetry, client, mt.p4, cfg, mt.cat, tdir / "khau4", anchors=[],
                                        coverage=None)
            return [h.model_copy(update={"status": "approved"}) for h in r4["hypotheses"]], r4["log"]

        def tao_rule(h, tdir):
            return s5_rule.generate_rule(h, client, mt.p5, mt.ls_catalog, int(cfg["max_repair_attempts"]), columns, con,
                                         tdir / "khau5", filter_policy=cfg["filter_policy_id"],
                                         stop_repair_on_empty_source=bool(cfg.get("dung_sua_khi_nguon_rong")))

        def ghi(x):
            with open(out / "nhat_ky.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps({"luc": time.strftime("%Y-%m-%d %H:%M:%S"), **x}, ensure_ascii=False) + "\n")
            print(f"{x['goc']:12s} {x['trang_thai']:15s} giả thuyết {x['gia_thuyet']} · rule hợp lệ {x['rule_hop_le']}"
                  f" · {x['usd']} USD · {x['giay']} giây · gói đã chi {da_chi()} USD", flush=True)

        bc = BoiCanh(out=out, client=client, tran=tran, da_chi=da_chi, tao_gia_thuyet=tao_gia_thuyet, tao_rule=tao_rule,
                     yeu_cau={g: v["sha256"] for g, v in goi["yeu_cau_khau4"].items()}, ghi=ghi)
        try:
            kq = chay_vong(mau, bc)
        except (providers.LLMError, budget.BudgetError, SaiYeuCau) as e:
            # Lỗi mạng, sổ có yêu cầu chưa rõ chi phí, hay yêu cầu ④ khác gói: kỹ thuật đang chạy để dở, lần sau được cất
            # sang _bi_ngat/ và chạy lại. Đối soát sổ trước (api-budget status).
            kq = {"ly_do_dung": f"loi: {type(e).__name__}: {str(e)[:300]}",
                  "ky_thuat_xong": [it["goc"] for it in mau if (out / "ky_thuat" / it["goc"] / "xong.json").exists()]}
        kq.update(so_loi_goi_lan_nay=client.so_loi_goi, goi_da_chi_usd=str(da_chi()), so_cuoi=ledger.status())
        (out / "tong_ket.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"dừng: {kq['ly_do_dung']}; xong {len(kq['ky_thuat_xong'])}/{len(mau)} kỹ thuật; gói đã chi {kq['goi_da_chi_usd']} USD")
    finally:
        lock.unlink(missing_ok=True)
    return 2 if kq["ly_do_dung"].startswith("loi") else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    for ten in ("chuan-bi", "chay"):
        p = sub.add_parser(ten)
        p.add_argument("--dau-vao", required=True, type=Path)
        p.add_argument("--uu-tien", required=True, type=Path)
        p.add_argument("--ho-so", required=True, help="ho_so_du_lieu.json của lượt 7B (băm phải là " + HO_SO_SHA[:12] + "…)")
        p.add_argument("--parquet", required=True, help="thư mục 664 bộ attack_data đã nạp")
        p.add_argument("--goi", required=True, help="thư mục gói (chuan-bi tạo mới; chay đọc)")
    sub.choices["chuan-bi"].add_argument("--lich-su", nargs="*", help="thư mục lượt cũ để dự toán (agent_proposal.json)")
    p = sub.choices["chay"]
    p.add_argument("--out", required=True)
    p.add_argument("--send", action="store_true", help="gọi API thật (chỉ người vận hành)")
    p.add_argument("--cap-usd", help=f"trần riêng của gói, tối đa {TRAN_GOI_TOI_DA} USD")
    a = ap.parse_args(argv)
    if a.lenh == "chay" and a.send and not a.cap_usd:
        ap.error("--send cần --cap-usd")
    return chuan_bi(a) if a.lenh == "chuan-bi" else chay(a)


if __name__ == "__main__":
    raise SystemExit(main())
