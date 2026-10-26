"""scripts/mau_cham_gia_thuyet.py: phiếu chấm mù thang 1–5 trên cây lượt tự dựng (không dữ liệu thật, không nhãn)."""
import importlib.util
import json

import pytest
import yaml

from cti_hunt import config


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("mau_cham_gia_thuyet_test", config.ROOT / "scripts/mau_cham_gia_thuyet.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _hyp(hid, text):
    return {"hypothesis_id": hid, "behavior": text, "scope": "mọi máy", "timeframe": "toàn bộ log",
            "evidence": {"data_source": "microsoft-windows-sysmon/operational", "event_ids": [1],
                         "key_fields": ["Image"]},
            "source_spans": [{"segment_id": "SY-001", "text": "câu nguồn: a  b\\c"}], "pivot_kind": None}


def _run(root, tuyen, mode, rid, n):
    run = root / tuyen / mode / rid
    rd = run / "round_01"
    rd.mkdir(parents=True)
    (run / "run_meta.json").write_text(json.dumps({"bat_dau": "2026-10-08T09:00:00"}), encoding="utf-8")
    hyps = [_hyp(f"{rid}-H{i:02d}", f"hành vi {rid} {i}") for i in range(1, n + 1)]
    (rd / "hypotheses.json").write_text(json.dumps(hyps, ensure_ascii=False), encoding="utf-8")
    dec = {h["hypothesis_id"]: {"quyet_dinh": "approved" if i % 2 else "rejected", "ly_do": ""}
           for i, h in enumerate(hyps)}
    (rd / "approval_log.json").write_text(json.dumps({"quyet_dinh": dec}, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "eval"
    _run(r, "tuyen_A", "pipeline", "SY_01", 3)
    _run(r, "tuyen_A", "agent", "SY_01", 8)
    _run(r, "tuyen_B_v3", "agent", "SY_03", 4)        # phụ lục: không vào mẫu
    return r


def test_tao_phieu_mu_chia_tang_va_bo_phu_luc(mod, root, tmp_path):
    out = tmp_path / "cham"
    assert mod.create(out, n=5, root=root) == 3 + 5
    form = yaml.safe_load((out / mod.PHIEU).read_text(encoding="utf-8"))
    key = json.loads((out / mod.KHOA).read_text(encoding="utf-8"))["muc"]
    assert [m["ma"] for m in form["muc"]] == [f"M{i:02d}" for i in range(1, 9)]
    for m in form["muc"]:
        assert set(m) == {"ma", *mod.NOI_DUNG, "diem", "ghi_chu"} and m["diem"] is None
    text = (out / mod.PHIEU).read_text(encoding="utf-8")
    assert "SY_01-H" not in text and "approved" not in text and "tuyen_A" not in text   # phiếu không lộ lượt/quyết định
    assert {k["tang"] for k in key.values()} == {"tuyen_A/pipeline", "tuyen_A/agent"}
    assert not any("SY_03" in k["luot"] for k in key.values())
    with pytest.raises(SystemExit):
        mod.create(out, root=root)                                     # không ghi đè phiếu đang chấm
    again = tmp_path / "cham2"
    mod.create(again, n=5, root=root)
    assert json.loads((again / mod.KHOA).read_text(encoding="utf-8"))["muc"] == key   # cùng hạt giống, cùng mẫu


def _fill(out, mod, score=lambda i: 4, who="Nguyễn Hoàng người vận hành"):
    p = out / mod.PHIEU
    form = yaml.safe_load(p.read_text(encoding="utf-8"))
    form["nguoi_cham"] = who
    for i, m in enumerate(form["muc"]):
        m["diem"] = score(i)
    p.write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return form


def test_tong_hop_theo_tang_va_quyet_dinh(mod, root, tmp_path):
    out = tmp_path / "cham"
    mod.create(out, n=5, root=root)
    _fill(out, mod, score=lambda i: 1 + i % 5)
    s = mod.summarize(out)
    assert s["tat_ca"]["n"] == 8 and sum(s["tat_ca"]["phan_bo"].values()) == 8
    assert set(s["theo_tang"]) == {"tuyen_A/agent", "tuyen_A/pipeline"}
    assert set(s["theo_quyet_dinh"]) == {"approved", "rejected"}
    assert all(r["diem"] <= 3 for r in s["ghi_chu_diem_thap"])
    md = mod.markdown(s)
    assert "| Tất cả | 8 |" in md and "người chấm: Nguyễn Hoàng người vận hành" in md
    assert mod.main(["--tong-hop", str(out)]) == 0 and (out / "tong_hop.md").exists()


@pytest.mark.parametrize("bad", ["thieu_diem", "diem_ngoai_thang", "sua_noi_dung", "thieu_nguoi_cham"])
def test_tong_hop_tu_choi_phieu_sai(mod, root, tmp_path, bad):
    out = tmp_path / "cham"
    mod.create(out, n=5, root=root)
    form = _fill(out, mod, who="" if bad == "thieu_nguoi_cham" else "người vận hành")
    if bad == "thieu_diem":
        form["muc"][0]["diem"] = None
    elif bad == "diem_ngoai_thang":
        form["muc"][0]["diem"] = 6
    elif bad == "sua_noi_dung":
        form["muc"][0]["hanh_vi"] += " (sửa)"
    (out / mod.PHIEU).write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")
    with pytest.raises(SystemExit):
        mod.summarize(out)
