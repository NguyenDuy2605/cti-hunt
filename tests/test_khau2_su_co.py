"""Giao thức 29/9 — xử lý sự cố ở khâu ②: lô hỏng, refusal, lỗi mạng, chạy tiếp.

Dùng mô hình giả và máy chủ giả; không gọi API thật (docs/METHODOLOGY.md §4.4).
"""
import json
import urllib.error

import pytest

from cti_hunt.llm import providers as P
from cti_hunt.stages import s2_ttp


# ---------- lỗi mạng ở tầng vận chuyển ----------

class _FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code, body=b"loi", headers=None):
        super().__init__("http://x", code, "loi", headers or {}, None)
        self._body = body

    def read(self):
        return self._body


def _post_voi(monkeypatch, ket_qua):
    """ket_qua: danh sách Exception hoặc dict; mỗi lần gọi lấy một phần tử."""
    con_lai = list(ket_qua)
    da_goi = []

    def gia(req, timeout=None):
        da_goi.append(1)
        x = con_lai.pop(0)
        if isinstance(x, Exception):
            raise x
        class R:
            def __enter__(self_): return self_
            def __exit__(self_, *a): return False
            def read(self_): return json.dumps(x).encode("utf-8")
        return R()

    monkeypatch.setattr(P.urllib.request, "urlopen", gia)
    return da_goi


def test_http_400_khong_thu_lai(monkeypatch):
    """Sai tham số thì gọi lại vẫn hỏng y hệt — dừng ngay."""
    da_goi = _post_voi(monkeypatch, [_FakeHTTPError(400, b'{"error":"temperature khong duoc ho tro"}')])
    cho = []
    with pytest.raises(P.TransportError, match="400"):
        P._post("http://x", {}, {}, sleep=cho.append)
    assert len(da_goi) == 1 and cho == []


@pytest.mark.parametrize("code", [401, 404])
def test_loi_khong_dang_thu_lai(monkeypatch, code):
    da_goi = _post_voi(monkeypatch, [_FakeHTTPError(code)])
    with pytest.raises(P.TransportError):
        P._post("http://x", {}, {}, sleep=lambda _: None)
    assert len(da_goi) == 1


def test_5xx_thu_lai_ba_lan_roi_bao_loi(monkeypatch):
    da_goi = _post_voi(monkeypatch, [_FakeHTTPError(503) for _ in range(3)])
    cho, nhat_ky = [], []
    with pytest.raises(P.TransportError, match="3 lần thử"):
        P._post("http://x", {}, {}, sleep=cho.append, log=nhat_ky.append)
    assert len(da_goi) == 3
    assert cho == [2, 8]                       # giãn dần, lần cuối không chờ nữa
    assert len(nhat_ky) == 3 and nhat_ky[-1]["thu_lai"] is False


def test_429_ton_trong_retry_after_roi_thanh_cong(monkeypatch):
    err = _FakeHTTPError(429, headers={"retry-after": "7"})
    da_goi = _post_voi(monkeypatch, [err, {"ok": True}])
    cho = []
    assert P._post("http://x", {}, {}, sleep=cho.append) == {"ok": True}
    assert cho == [7] and len(da_goi) == 2      # máy chủ bảo chờ 7s thì nghe theo


def test_timeout_thu_lai(monkeypatch):
    da_goi = _post_voi(monkeypatch, [TimeoutError("het gio"), {"ok": True}])
    cho = []
    assert P._post("http://x", {}, {}, sleep=cho.append) == {"ok": True}
    assert len(da_goi) == 2 and cho == [2]


# ---------- lô hỏng / refusal ở tầng khâu ② ----------

SEGS = [{"ma_doan": f"TU-{i:03d}", "report": "TU", "loai": "đoạn văn",
         "van_ban": "Nhóm tấn công dùng công cụ quản trị để chạy lệnh từ xa."} for i in range(1, 5)]
PROMPT = {"path": "p.md", "sha256": "a" * 64, "system": "SYS",
          "user": "{report_id}\n{segments}"}
MOT_MUC = {"items": [{"segment_id": "TU-001", "technique_id": "T1047", "tactic": "Lateral Movement",
                      "quote": "", "confidence": 0.9}]}


class _Catalog:
    """Danh mục ATT&CK tối giản: các test ở đây đo cách xử lý sự cố, không đo phần tra mã."""
    version = "19.2"
    tactics = {"lateral-movement": "Lateral Movement"}
    techniques: dict = {}

    def resolve(self, tid):
        from types import SimpleNamespace
        return SimpleNamespace(status="ok", final=tid.strip().upper(), name="Ten", tactics=set())


def _chay(responses, tmp_path, batch_size=2, **kw):
    """Trả (ttps, log, llm) để test đọc cho gọn."""
    llm = P.MockClient(responses=list(responses))
    ttps, log = s2_ttp.extract_report("TU", SEGS, llm, _Catalog(), PROMPT, batch_size,
                                      run_dir=tmp_path, **kw)
    return ttps, log, llm


def test_lo_hong_duoc_goi_lai_dung_mot_lan(tmp_path):
    """Lần 1 không ra JSON dùng được, lần 2 được -> giữ kết quả, ghi vào log là đã gọi lại."""
    ttps, log, llm = _chay([P.BadOutputError("không có khối tool_use"), MOT_MUC, MOT_MUC], tmp_path)
    assert len(llm.calls) == 3                          # lô 1 gọi hai lần, lô 2 gọi một lần
    assert log["su_co"]["lo_goi_lai"] and log["su_co"]["lo_that_bai"] == []
    assert log["ma_sua"].get("lo_that_bai") is None
    assert len(ttps) >= 1


def test_lo_hong_hai_lan_thi_ghi_that_bai(tmp_path):
    ttps, log, llm = _chay([P.BadOutputError("hỏng"), P.BadOutputError("vẫn hỏng"), MOT_MUC], tmp_path)
    assert len(llm.calls) == 3
    tb = log["su_co"]["lo_that_bai"]
    assert len(tb) == 1 and tb[0]["segment_ids"] == ["TU-001", "TU-002"]
    assert log["ma_sua"]["lo_that_bai"] == 1


def test_json_hop_le_nhung_rong_thi_khong_goi_lai(tmp_path):
    """Ít hay không có TTP là kết quả, không phải lỗi -> tuyệt đối không gọi lại."""
    _, log, llm = _chay([{"items": []}, {"items": []}], tmp_path)
    assert len(llm.calls) == 2
    assert log["su_co"]["lo_goi_lai"] == [] and log["su_co"]["lo_that_bai"] == []


def test_sai_luoc_do_tinh_la_lo_hong(tmp_path):
    """JSON hợp lệ nhưng không đúng lược đồ cũng là lô hỏng (strict không phủ khối text)."""
    _, log, llm = _chay([{"items": [{"thieu_truong_bat_buoc": 1}]}, MOT_MUC, MOT_MUC], tmp_path)
    assert len(llm.calls) == 3 and len(log["su_co"]["lo_goi_lai"]) == 1


def test_refusal_that_bai_ngay_khong_goi_lai(tmp_path):
    _, log, llm = _chay([P.RefusalError("loại 'cyber'"), MOT_MUC], tmp_path)
    assert len(llm.calls) == 2                          # lô 1 chỉ gọi MỘT lần rồi bỏ
    assert log["su_co"]["lo_goi_lai"] == []
    assert "refusal" in log["su_co"]["lo_that_bai"][0]["ly_do"]


def test_loi_mang_khong_bi_nuot_ma_dung_ca_lan_chay(tmp_path):
    """TransportError phải nổi lên tới CLI để dừng và cho chạy tiếp, không tính là lô hỏng."""
    with pytest.raises(P.TransportError):
        _chay([P.TransportError("mất mạng")], tmp_path)


# ---------- chạy tiếp ----------

def test_lo_da_co_ket_qua_khong_bao_gio_goi_lai(tmp_path):
    da_co = s2_ttp.doc_lo_da_co(tmp_path)
    assert da_co == {}
    (tmp_path / "responses.jsonl").write_text(
        json.dumps({"report": "TU", "batch": 0, "lan": 1, "raw": MOT_MUC}, ensure_ascii=False) + "\n"
        + json.dumps({"report": "TU", "batch": 1, "lan": 1, "loi": "BadOutputError: hỏng"},
                     ensure_ascii=False) + "\n", encoding="utf-8")
    da_co = s2_ttp.doc_lo_da_co(tmp_path)
    assert set(da_co["TU"]) == {0}                      # lô lỗi KHÔNG được coi là đã xong

    _, log, llm = _chay([MOT_MUC], tmp_path, da_co=da_co["TU"])
    assert len(llm.calls) == 1                          # chỉ gọi lô còn thiếu
    assert log["ma_sua"]["lo_dung_lai_tu_lan_truoc"] == 1
