"""E1: nạp một bộ OTRF phát triển (tách biệt APT29 day 2) thành events.parquet riêng cho graph D10.

Dùng lại `data.ingest` (cùng cột dẫn xuất `ev_*`, giữ mọi trường gốc), rồi kiểm chặt trước khi cho graph dùng:

- không phải tệp nguồn của tập đánh giá (tên, SHA256 của gói và của từng tệp JSON bên trong), không ghi vào thư
  mục làm việc của tập đánh giá, không đọc/ghi trong data/labels;
- không có máy nào trùng máy của tập đánh giá (`dataset.yaml` → `raw.hosts`);
- mọi sự kiện có đủ khóa (máy, channel, RecordNumber), khóa không trùng, và có thời điểm `ev_ts`;
- lệch giờ EventTime → UTC đúng: kiểm trên các sự kiện Sysmon có cả `UtcTime` lẫn `EventTime`. Bộ OTRF không cùng
  một lệch giờ (bộ ghi mùa hè EDT lệch 4h, mùa đông EST lệch 5h), nên lệch giờ là tham số có kiểm, không đoán.

Lỗi thì xóa thư mục vừa ghi: không để lại events.parquet dở cho graph dùng nhầm.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import re
import shutil
import tarfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

import duckdb

from .. import config, integrity
from ..data.ingest import ingest

DATASET_KIND = "otrf_dev"
# Sai số cho phép giữa UtcTime và EventTime + lệch giờ. Log thật lệch vài chục giây (thời điểm ghi); sai một giờ
# (nhầm EDT/EST) thì vượt xa ngưỡng này.
MAX_RESIDUAL_S = 15 * 60


class DevDatasetError(ValueError):
    pass


@contextmanager
def _open_members(src: Path):
    """Các tệp .json trong gói (zip, tar.gz) hoặc chính tệp .json. Đọc từng tệp, không giải nén theo đường dẫn gói."""
    name = src.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(src) as zf:
            yield [(i.filename, lambda i=i: zf.open(i)) for i in zf.infolist()
                   if not i.is_dir() and i.filename.lower().endswith(".json")]
    elif name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(src, "r:gz") as tf:
            yield [(m.name, lambda m=m: tf.extractfile(m)) for m in tf.getmembers()
                   if m.isfile() and m.name.lower().endswith(".json")]
    elif name.endswith(".json"):
        yield [(src.name, lambda: open(src, "rb"))]
    else:
        raise DevDatasetError(f"{src.name}: chỉ nhận .zip, .tar.gz, .tgz hoặc .json")


def _extract(src: Path, dest: Path) -> list[dict]:
    """Ghép mọi tệp .json của gói thành một tệp JSON lines; trả SHA256 và số byte của từng tệp gốc."""
    members = []
    with _open_members(src) as found, open(dest, "wb") as out:
        for name, opener in found:
            h, n, last = hashlib.sha256(), 0, b"\n"
            with opener() as f:
                while block := f.read(1 << 20):
                    h.update(block)
                    out.write(block[len(codecs.BOM_UTF8):] if n == 0 and block.startswith(codecs.BOM_UTF8) else block)
                    n, last = n + len(block), block[-1:]
            if last != b"\n":
                out.write(b"\n")
            members.append({"ten": name, "sha256": h.hexdigest(), "bytes": n})
    if not members:
        raise DevDatasetError(f"{src.name}: không có tệp .json nào")
    return members


def _inside(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def _checks(parquet: Path, sysmon_channel: str, time_cfg: dict, eval_hosts: set[str]) -> tuple[dict, list[str]]:
    con = duckdb.connect()
    ev = f"read_parquet('{parquet.as_posix()}')"
    cols = {r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {ev}").fetchall()}
    hosts = {h for (h,) in con.execute(f"SELECT DISTINCT ev_host FROM {ev} WHERE ev_host IS NOT NULL").fetchall()}
    problems = []
    overlap = sorted(hosts & eval_hosts)
    if overlap:
        problems.append(f"E1: có máy trùng tập đánh giá APT29 day 2: {', '.join(overlap)}")
    null_ts = con.execute(f"SELECT count(*) FROM {ev} WHERE ev_ts IS NULL").fetchone()[0]
    if null_ts:
        problems.append(f"{null_ts} sự kiện không có thời điểm (thiếu {time_cfg['other_field']}/"
                        f"{time_cfg['sysmon_field']} hoặc sai định dạng)")
    sf, of, off = time_cfg["sysmon_field"], time_cfg["other_field"], int(time_cfg["other_offset_hours"])
    n_pairs, max_res, hours = 0, None, []
    if {sf, of} <= cols:
        pair = (f"epoch(TRY_STRPTIME(\"{sf}\", '%Y-%m-%d %H:%M:%S.%g')) - "
                f"epoch(TRY_STRPTIME(\"{of}\", '%Y-%m-%d %H:%M:%S'))")
        pairs = f"SELECT {pair} AS d FROM {ev} WHERE ev_channel = '{sysmon_channel}'"
        n_pairs, max_res = con.execute(
            f"SELECT count(d), max(abs(d - {off} * 3600)) FROM ({pairs}) WHERE d IS NOT NULL").fetchone()
        hours = [r[0] for r in con.execute(
            f"SELECT round(d / 3600) h FROM ({pairs}) WHERE d IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC").fetchall()]
    if not n_pairs:
        problems.append(f"không kiểm được lệch giờ: không có sự kiện Sysmon nào có cả {sf} và {of}")
    elif max_res > MAX_RESIDUAL_S:
        problems.append(f"lệch giờ {of} → UTC không phải {off}h: sai số tới {max_res:.0f} giây trên {n_pairs} "
                        f"sự kiện Sysmon; lệch quan sát được (giờ, nhiều nhất trước): "
                        f"{', '.join(f'{h:g}' for h in hours)} — chạy lại với --offset-hours nếu đúng")
    check = {"may": sorted(hosts), "may_tap_danh_gia": sorted(eval_hosts), "lech_gio": off,
             "kiem_lech_gio": {"cap_sysmon": n_pairs,
                               "sai_so_max_giay": None if max_res is None else round(max_res, 3),
                               "nguong_giay": MAX_RESIDUAL_S}}
    return check, problems


def ingest_dev(src: Path, dataset_id: str, out_dir: Path, *, offset_hours: int | None = None,
               root: Path = config.ROOT) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", dataset_id or ""):
        raise DevDatasetError("mã bộ dữ liệu chỉ gồm chữ, số, '.', '_', '-' (tối đa 80 ký tự)")
    ds = config.load("dataset", root)
    src, out_dir = Path(src).resolve(), Path(out_dir).resolve()
    labels = config.resolve("data/labels", root).resolve()
    work = config.resolve(ds["work_dir"], root).resolve()
    raw = config.resolve(ds["raw"]["path"], root)
    eval_sha = str(ds["raw"]["sha256"]).lower()
    eval_hosts = {str(h).upper() for h in ds["raw"].get("hosts") or []}
    if not eval_hosts:
        raise DevDatasetError("configs/dataset.yaml thiếu raw.hosts (máy của tập đánh giá) — không kiểm được E1")
    if _inside(src, labels) or _inside(out_dir, labels):
        raise DevDatasetError("E1: không đọc/ghi trong data/labels")
    if _inside(out_dir, work):
        raise DevDatasetError(f"E1: không ghi vào {ds['work_dir']} (thư mục làm việc của tập đánh giá)")
    if not src.is_file():
        raise DevDatasetError(f"Không thấy {src}")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise DevDatasetError(f"{out_dir} đã có nội dung — mỗi bộ dữ liệu một thư mục mới")
    stop = DevDatasetError("E1: đây là tệp nguồn của tập đánh giá APT29 day 2")
    if src.name.lower() == raw.name.lower():
        raise stop
    src_sha = integrity.sha256_file(src)
    if src_sha == eval_sha:
        raise stop

    off = int(ds["time"]["other_offset_hours"] if offset_hours is None else offset_hours)
    time_cfg = {**ds["time"], "other_offset_hours": off}
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / ".src"
    try:
        tmp.mkdir()
        joined = tmp / f"{dataset_id}.json"
        members = _extract(src, joined)
        if any(m["sha256"] == eval_sha for m in members):
            raise stop
        manifest = ingest(joined, out_dir, sysmon_channel=ds["sysmon_channel"], time_cfg=time_cfg,
                          event_key=ds["event_key"], threads=ds.get("ingest_threads", 2))
        check, problems = _checks(out_dir / "events.parquet", ds["sysmon_channel"], time_cfg, eval_hosts)
        problems = manifest["problems"] + problems
        if problems:
            raise DevDatasetError("Bộ dữ liệu không dùng được cho graph D10:\n  - " + "\n  - ".join(problems))
        manifest.update({"source": src.as_posix(), "dataset_kind": DATASET_KIND, "dataset_id": dataset_id,
                         "source_sha256": src_sha, "members": members, "e1": check})
        (out_dir / "ingest_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                                     encoding="utf-8")
    except BaseException:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return manifest


def check_manifest(events_dir: Path, dataset_id: str, dataset_sha256: str, root: Path = config.ROOT) -> None:
    """`agent start --dataset-kind otrf_dev`: bộ dữ liệu phải do `ingest-dev` nạp, đúng mã và đúng SHA256 khai báo."""
    path = Path(events_dir) / "ingest_manifest.json"
    m = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if m.get("dataset_kind") != DATASET_KIND:
        raise DevDatasetError(f"E1: {events_dir} không do `ingest-dev` nạp (manifest thiếu dataset_kind=otrf_dev)")
    if m.get("dataset_id") != dataset_id:
        raise DevDatasetError(f"E1: --dataset-id {dataset_id!r} khác mã trong manifest {m.get('dataset_id')!r}")
    if str(m.get("source_sha256") or "").lower() != (dataset_sha256 or "").lower():
        raise DevDatasetError("E1: --dataset-sha256 khác SHA256 tệp nguồn ghi trong manifest")
    eval_hosts = {str(h).upper() for h in config.load("dataset", root)["raw"].get("hosts") or []}
    overlap = sorted(set(m.get("hosts") or {}) & eval_hosts)
    if overlap:
        raise DevDatasetError(f"E1: có máy trùng tập đánh giá APT29 day 2: {', '.join(overlap)}")
