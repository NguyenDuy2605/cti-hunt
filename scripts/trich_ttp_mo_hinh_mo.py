"""Trích TTP bằng mô hình mở chạy trên máy (Ollama), cùng đường trích report của hệ thống (``s2_report``), 0 USD API.

Câu hỏi 1, phần TTP (``docs/METHODOLOGY.md/``): đo một LLM mở chạy cục bộ trên cùng report, cùng prompt
(``prompts/report_extract_v1.md``), cùng 8 gợi ý BM25 mỗi đoạn, cùng kiểm câu trích như lượt Claude của report mới.

An toàn: dùng ``guard()`` của ``pilot_llm_cuc_bo.py`` (chặn mọi kết nối ngoài 127.0.0.1 và chặn dựng client Claude/OpenAI);
mô hình phải có sẵn cục bộ (``model_info``). Không đọc nhãn sự kiện, không ghi vào ``data/``.

Lô hỏng: mô hình trả JSON sai/bị cắt (``BadOutputError``) thì lô đó tính là **không có TTP** và được ghi vào
``lo_hong.jsonl`` để báo riêng (như giao thức khâu ②: lô thất bại tách khỏi chất lượng đọc). Lỗi kết nối Ollama thì dừng,
chạy lại cùng lệnh để tiếp tục (``s2_report.run`` dùng lại các lô đã có phản hồi).

Thứ tự report (ghi trước khi chạy, 16/10):
- ``--bo cu``: 4 report đã có lượt Claude, Volt Typhoon trước (cùng đường trích với lượt Claude), rồi POSHSPY, Raindrop,
  Solorigate (lượt Claude của ba report này đi đường v1 không có gợi ý BM25: so với chúng là so khác đường trích).
- ``--bo mo_rong``: 30 report của bộ mở rộng theo đúng thứ tự trộn của giao thức (``thu_tu``).

    python scripts/trich_ttp_mo_hinh_mo.py kiem --model qwen2.5:7b-instruct
    python scripts/trich_ttp_mo_hinh_mo.py do-toc-do --model qwen2.5:7b-instruct --so-lo 2 --out <thư mục ngoài data/>
    python scripts/trich_ttp_mo_hinh_mo.py chay --model qwen2.5:7b-instruct --bo cu --out <thư mục ngoài data/>
    thêm --gia-lap để kiểm đường ống bằng client giả trả rỗng (không cần Ollama)
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS  # noqa: E402
from do_ttp_mitre import STIX  # noqa: E402
from pilot_llm_cuc_bo import LocalOllama, guard, model_info  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.llm import providers  # noqa: E402
from cti_hunt.stages import s1_ingest, s2_ioc, s2_report  # noqa: E402

PROMPT = "prompts/report_extract_v1.md"
BO_MO_RONG = Path("../workspace/bo_mo_rong_16-10")  # mặc định trên laptop; PC dùng --bo-mo-rong
THU_TU_CU = ["Volt Typhoon (Microsoft)", "POSHSPY (FireEye)", "Raindrop (Symantec)", "Solorigate (Microsoft)"]


class GiaLap:
    """Client giả: trả rỗng ngay, để kiểm đường ống mà không cần Ollama."""
    model_id = "gia-lap"

    def describe(self) -> dict:
        return {"model": self.model_id}

    def complete_json(self, system, user, json_schema, log=None) -> dict:
        (log or (lambda _: None))({"gia_lap": True, "giay": 0})
        return {"items": []}


class BenTrong:
    """Bọc client: lô có đầu ra hỏng thành rỗng và ghi lại; lỗi kết nối thì để nổi lên (dừng, chạy lại để tiếp tục).

    ``su_kien`` giữ bản đủ mọi sự kiện của lượt này: ``s2_report`` ghi ``usage_*.json`` qua ``providers.event_recorder``,
    hàm đó chỉ giữ khóa trong ``SAFE_EVENT_KEYS`` nên mất ``giay`` và ``lo_hong`` (thấy trên PC 17/10: giây ra null, lô hỏng
    luôn 0). Dòng ``lo_hong.jsonl`` ghi kèm ``report`` để đếm theo report, kể cả qua các lần chạy lại."""

    def __init__(self, inner, lo_hong: Path, report: str | None = None):
        self.inner, self.lo_hong, self.report = inner, lo_hong, report
        self.model_id = inner.model_id
        self.su_kien: list[dict] = []

    def complete_json(self, system, user, json_schema, log=None) -> dict:
        def ghi(event: dict) -> None:
            self.su_kien.append(event)
            (log or (lambda _: None))(event)
        try:
            return self.inner.complete_json(system, user, json_schema, log=ghi)
        except providers.BadOutputError as e:
            event = {"lo_hong": str(e)[:300], "luc": time.strftime("%Y-%m-%d %H:%M:%S"), "report": self.report}
            ghi(event)
            with open(self.lo_hong, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            return {"items": []}


def danh_sach(bo: str, bo_mo_rong: Path = BO_MO_RONG) -> list[tuple[str, Path]]:
    if bo == "cu":
        return [(name, config.resolve(REPORTS[name][0])) for name in THU_TU_CU]
    log = json.loads((bo_mo_rong / "nhat_ky_tai.json").read_text(encoding="utf-8"))
    return [(e["ma"], bo_mo_rong / "bundles" / e["ma"]) for e in sorted(log, key=lambda e: e["thu_tu"])
            if e["ket_qua"] == "nhan"]


def so_lo(bundle: Path) -> int:
    _, requests = s2_report.prepare(bundle, config.resolve(STIX), config.resolve(PROMPT), {})
    return len(requests)


def llm_cfg(a) -> dict:
    # Ghi vào meta/fingerprint của lượt: đổi tham số thì không tiếp tục lượt cũ được.
    return {"provider": "ollama_cuc_bo", "model": a.model, "num_ctx": a.num_ctx, "num_predict": a.num_predict,
            "temperature": 0, "seed": 0, "gia_lap": a.gia_lap}


def client(a, out: Path, report: str | None = None):
    inner = GiaLap() if a.gia_lap else LocalOllama(a.model, a.num_ctx, a.num_predict, a.timeout)
    return BenTrong(inner, out / "lo_hong.jsonl", report)


def chay_mot(name: str, bundle: Path, a, out: Path, segments=None) -> dict:
    run_dir = out / name.split(" (")[0].lower().replace(" ", "_").replace("/", "_")
    cl = client(a, out, name)
    t0 = time.monotonic()
    meta = s2_report.run(bundle, config.resolve(STIX), config.resolve(PROMPT), llm_cfg(a), run_dir,
                         s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml")), send=True,
                         resume=run_dir.exists(), llm=cl, accept_partial=True,
                         segments_selected=segments)
    giay = time.monotonic() - t0
    calls = []  # token: mọi lần gọi đã lưu của report, kể cả các lần chạy trước
    for p in sorted(run_dir.glob("usage_*.json")):
        calls.extend(json.loads(p.read_text(encoding="utf-8")))
    # Lô hỏng: theo report trong lo_hong.jsonl (dòng ghi trước bản sửa 18/10 không có ``report`` nên không được đếm).
    lo_hong = out / "lo_hong.jsonl"
    hong = sum(1 for x in (lo_hong.read_text(encoding="utf-8").splitlines() if lo_hong.exists() else [])
               if x.strip() and json.loads(x).get("report") == name)
    return {"report": name, "thu_muc": str(run_dir), "trang_thai": meta.get("status"), "lo": meta.get("batches"),
            "ttp_giu": meta.get("accepted_ttp"), "lo_hong": hong, "giay_lan_nay": round(giay, 1),
            "token_vao": sum(c.get("input_tokens") or 0 for c in calls),
            "token_ra": sum(c.get("output_tokens") or 0 for c in calls),
            # Giây: chỉ các lời gọi của lần chạy này (lô đã có phản hồi được dùng lại, không gọi).
            "giay_moi_loi_goi": [c["giay"] for c in cl.su_kien if c.get("giay") is not None]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("lenh", choices=["kiem", "do-toc-do", "chay"])
    ap.add_argument("--model", default="qwen2.5:7b-instruct")
    ap.add_argument("--bo", choices=["cu", "mo_rong"], default="cu")
    ap.add_argument("--so-report", type=int, help="chỉ chạy N report đầu theo thứ tự đã ghi")
    ap.add_argument("--so-lo", type=int, default=2, help="do-toc-do: số lô đầu của report nhỏ nhất")
    ap.add_argument("--out", help="thư mục kết quả (ngoài data/)")
    ap.add_argument("--num-ctx", type=int, default=32768)
    ap.add_argument("--num-predict", type=int, default=8192)
    ap.add_argument("--timeout", type=int, default=7200, help="giây chờ tối đa mỗi lời gọi (CPU chậm)")
    ap.add_argument("--gia-lap", action="store_true", help="client giả trả rỗng, không cần Ollama")
    ap.add_argument("--bo-mo-rong", default=str(BO_MO_RONG), help="thư mục bộ 30 report (có nhat_ky_tai.json, bundles/)")
    a = ap.parse_args(argv)
    mo_rong = Path(a.bo_mo_rong)

    with guard():
        if a.lenh == "kiem":
            if not a.gia_lap:
                print(json.dumps(model_info(a.model), ensure_ascii=False, indent=1))
            for bo in ("cu", "mo_rong"):
                ds = [(n, so_lo(b)) for n, b in danh_sach(bo, mo_rong)]
                print(f"\n--bo {bo}: {len(ds)} report, {sum(x for _, x in ds)} lô")
                for n, x in ds:
                    print(f"  {n}: {x} lô")
            return 0
        if not a.out:
            raise SystemExit("cần --out (thư mục ngoài data/)")
        out = Path(a.out)
        if "cti-hunt/data" in out.resolve().as_posix().lower():
            raise SystemExit("không ghi vào data/ của repo")
        out.mkdir(parents=True, exist_ok=True)
        info = {"model": a.model} if a.gia_lap else model_info(a.model)
        if a.lenh == "do-toc-do":
            ds = sorted(((so_lo(b), n, b) for n, b in danh_sach("mo_rong", mo_rong)), key=lambda x: (x[0], x[1]))
            lo, name, bundle = ds[0]
            _, requests = s2_report.prepare(bundle, config.resolve(STIX), config.resolve(PROMPT), {})
            units = [t for r in requests[:a.so_lo] for t in json.loads(r["user"])["targets"]]
            segs = list(dict.fromkeys(u["segment_id"] for u in units))
            r = chay_mot(f"toc_do_{name}", bundle, a, out, segments=segs)
            g = [x for x in r["giay_moi_loi_goi"] if x]
            moi_lo = sum(g) / len(g) if g else None
            tong = {bo: sum(so_lo(b) for _, b in danh_sach(bo, mo_rong)) for bo in ("cu", "mo_rong")}
            bao_cao = {"mo_hinh": info, "report": name, "lo_da_chay": r["lo"], "giay_moi_lo": moi_lo, **r,
                       "uoc_tinh_gio": {bo: (round(n * moi_lo / 3600, 1) if moi_lo else None) for bo, n in tong.items()},
                       "tong_lo": tong}
            (out / "do_toc_do.json").write_text(json.dumps(bao_cao, ensure_ascii=False, indent=1), encoding="utf-8")
            print(json.dumps({k: v for k, v in bao_cao.items() if k != "giay_moi_loi_goi"}, ensure_ascii=False, indent=1))
            return 0
        ds = danh_sach(a.bo, mo_rong)[: a.so_report] if a.so_report else danh_sach(a.bo, mo_rong)
        tong_ket = []
        for name, bundle in ds:
            print(f"== {name} ({so_lo(bundle)} lô) bắt đầu {time.strftime('%H:%M:%S')}", flush=True)
            r = chay_mot(name, bundle, a, out)
            tong_ket.append(r)
            (out / f"tong_ket_{a.bo}.json").write_text(json.dumps({"mo_hinh": info, "report": tong_ket},
                                                                  ensure_ascii=False, indent=1), encoding="utf-8")
            print(f"   xong: {r['trang_thai']}, giữ {r['ttp_giu']} TTP, lô hỏng {r['lo_hong']}, "
                  f"{r['giay_lan_nay'] / 60:.0f} phút", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
