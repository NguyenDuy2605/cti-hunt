"""Câu hỏi 1, phần IOC, B: mô hình mở chạy cục bộ (Ollama) gán "IOC thật hay không" cho ứng viên của bộ rút, theo cách LANCE.

LANCE (Froudakis và cộng sự, 2025): regex tìm hết chuỗi đúng dạng; LLM đọc đoạn văn quanh chuỗi rồi gán IOC/không phải IOC
kèm lý do. Ở đây (ghi trước khi chạy, 16/10):
- ứng viên = bộ rút của hệ thống, bốn loại lõi (``goi_ioc_19.json`` do ``ioc_19_report.py chuan-bi`` ghi);
- văn bản chia cửa sổ 8.000 ký tự, chồng nhau 50%, cắt ở khoảng trắng (như LANCE); mỗi cửa sổ gửi các ứng viên xuất hiện
  trong nó (so trên văn bản đã đưa về dạng thật, chữ thường), tối đa 40 ứng viên mỗi lời gọi;
- prompt ``prompts/ioc_phan_loai_v1.md`` (băm ghi vào kết quả), không dùng đáp án hay ví dụ lấy từ 19 report;
- gộp phiếu theo ứng viên: IOC nếu số cửa sổ nói IOC ≥ số cửa sổ nói không (hòa tính là IOC); không có phiếu = thiếu nhãn,
  khi chấm tính là không phải IOC;
- nhiệt độ 0, seed 0; ``guard()`` chặn mọi kết nối ngoài 127.0.0.1 và chặn client Claude/OpenAI.

    python scripts/ioc_phan_loai_mo_hinh_mo.py --goi <goi_ioc_19.json> --model qwen2.5:7b-instruct --out <thư mục ngoài data/>
    thêm --gia-lap để kiểm đường ống (client giả nói mọi ứng viên là IOC), --so-report N để chạy thử N report đầu
Chạy lại cùng lệnh thì dùng lại các lời gọi đã có (``cache/``). Chấm: ``ioc_19_report.py cham-llm``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))
from pilot_llm_cuc_bo import LocalOllama, guard, model_info  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.llm import providers  # noqa: E402
from cti_hunt.stages import s2_ioc  # noqa: E402

PROMPT = "prompts/ioc_phan_loai_v1.md"
CUA_SO, CHONG, TOI_DA_UNG_VIEN = 8000, 4000, 40


class Nhan(BaseModel):
    value: str
    is_ioc: bool
    reason: str


class LoNhan(BaseModel):
    labels: list[Nhan]


def cua_so(text: str) -> list[tuple[int, str]]:
    out, start = [], 0
    while start < len(text):
        end = min(start + CUA_SO, len(text))
        if end < len(text):
            cut = text.rfind(" ", start + CUA_SO // 2, end)
            end = cut if cut > start else end
        out.append((start, text[start:end]))
        if end >= len(text):
            break
        nxt = end - CHONG
        sp = text.find(" ", nxt)
        start = sp + 1 if 0 <= sp < end else max(nxt, start + 1)
    return out


class GiaLap:
    model_id = "gia-lap"

    def complete_json(self, system, user, json_schema, log=None) -> dict:
        vals = [line.split(": ", 1)[1] for line in user.splitlines() if line.startswith("- ") and ": " in line]
        return {"labels": [{"value": v, "is_ioc": True, "reason": "giả lập"} for v in vals]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--goi", required=True)
    ap.add_argument("--model", default="qwen2.5:7b-instruct")
    ap.add_argument("--out", required=True)
    ap.add_argument("--so-report", type=int)
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--num-predict", type=int, default=4096)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--gia-lap", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    (out / "cache").mkdir(parents=True, exist_ok=True)
    G = json.loads(Path(a.goi).read_text(encoding="utf-8"))
    rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
    system = config.resolve(PROMPT).read_text(encoding="utf-8")
    schema = LoNhan.model_json_schema()
    reports = G["report"][: a.so_report] if a.so_report else G["report"]
    with guard():
        info = {"model": "gia-lap"} if a.gia_lap else model_info(a.model)
        client = GiaLap() if a.gia_lap else LocalOllama(a.model, a.num_ctx, a.num_predict, a.timeout)
        nhan, thong_ke, t0 = {}, {"loi_goi": 0, "loi_goi_cache": 0, "lo_hong": 0, "giay": 0.0}, time.monotonic()
        for r in reports:
            text = r["van_ban"]
            phieu: dict[str, list[dict]] = {}
            for start, win in cua_so(text):
                low = s2_ioc.refang(win, rules["defang"])[0].lower()
                cands = [u for u in r["ung_vien"] if u["gia_tri"] in low]
                for i in range(0, len(cands), TOI_DA_UNG_VIEN):
                    chunk = cands[i:i + TOI_DA_UNG_VIEN]
                    user = (f"Report: {r['report']}\n\nText:\n<<<\n{win}\n>>>\n\nIndicators to label (type: value):\n"
                            + "\n".join(f"- {u['loai']}: {u['gia_tri']}" for u in chunk))
                    key = hashlib.sha256(((info.get("digest") or info.get("name") or info["model"]) + system + user).encode("utf-8")).hexdigest()
                    cpath = out / "cache" / f"{key}.json"
                    if cpath.exists():
                        raw = json.loads(cpath.read_text(encoding="utf-8"))
                        thong_ke["loi_goi_cache"] += 1
                    else:
                        t1 = time.monotonic()
                        events: list[dict] = []
                        try:
                            raw = {"ket_qua": client.complete_json(system, user, schema, log=events.append), "events": events}
                        except providers.BadOutputError as e:
                            raw = {"ket_qua": {"labels": []}, "events": events, "lo_hong": str(e)[:300]}
                            thong_ke["lo_hong"] += 1
                        raw["giay"] = round(time.monotonic() - t1, 1)
                        cpath.write_text(json.dumps(raw, ensure_ascii=False, indent=1), encoding="utf-8")
                        thong_ke["loi_goi"] += 1
                        thong_ke["giay"] += raw["giay"]
                    by_val = {}
                    for lab in (raw["ket_qua"] or {}).get("labels", []):
                        by_val.setdefault(str(lab.get("value", "")).strip().lower(), lab)
                    for u in chunk:
                        lab = by_val.get(u["gia_tri"])
                        if lab is not None:
                            phieu.setdefault(f"{u['loai']}|{u['gia_tri']}", []).append(
                                {"cua_so": start, "is_ioc": bool(lab.get("is_ioc")), "reason": lab.get("reason", "")})
            nhan[r["report"]] = {k: {"la_ioc": sum(p["is_ioc"] for p in v) >= sum(not p["is_ioc"] for p in v),
                                     "phieu": v} for k, v in phieu.items()}
            print(f"{r['report']}: {len(r['ung_vien'])} ứng viên, có nhãn {len(nhan[r['report']])}, "
                  f"đã gọi {thong_ke['loi_goi']} (cache {thong_ke['loi_goi_cache']}), "
                  f"{(time.monotonic() - t0) / 60:.1f} phút", flush=True)
            (out / "nhan_llm.json").write_text(json.dumps(
                {"mo_hinh": info, "prompt": PROMPT, "prompt_sha256": hashlib.sha256(system.encode("utf-8")).hexdigest(),
                 "cua_so": CUA_SO, "chong": CHONG, "thong_ke": thong_ke, "nhan": nhan}, ensure_ascii=False, indent=1),
                encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
