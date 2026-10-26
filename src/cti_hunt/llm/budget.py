"""Sổ chi phí cục bộ dùng chung, không lưu prompt, phản hồi hay khóa API.

Giữ tiền trước mỗi HTTP sinh nội dung; chỉ trả phần dư khi có usage. Token counting là ước tính,
nên dự phòng input +10% +256 token và toàn bộ max_tokens. Đây không phải giới hạn billing của nhà cung cấp.
Mất phản hồi/usage thì giữ khoản dự phòng và chặn lượt tiếp theo cho tới khi người vận hành đối chiếu Console.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .. import config

RATE_VERSION = "anthropic-sonnet5-opus55-2026-10-01"
# micro-USD/token, giá chuẩn không cache/batch/fast mode, không có bậc giá ngữ cảnh dài.
# Sonnet 5 kiểm từ tài liệu Anthropic 26/9; Opus 5.5 (khâu ② v2, N3) kiểm 01/10/2026: 4 / 20 USD mỗi triệu token.
RATES = {"claude-sonnet-5": (2, 10), "claude-opus-5-5": (4, 20)}
SCALE = 1_000_000
COUNT_TIMEOUT_GIAY = 60   # đếm token thường trả về trong vài giây; 3 lần thử giới hạn chờ khoảng 3 phút


class BudgetError(RuntimeError):
    pass


class BudgetExhausted(BudgetError):
    """Hạn mức còn lại không đủ giữ trước cho lời gọi: chưa gửi yêu cầu sinh nội dung, chưa phát sinh chi phí.
    Chỉ lỗi này được graph xử lý như điểm dừng; lỗi sau khi đã gửi (usage, pending) vẫn dừng lượt như cũ."""


def min_reserve(model: str, max_tokens: int) -> int | None:
    """Khoản giữ trước nhỏ nhất của một lời gọi: input 0 token + biên 256 token, toàn bộ max_tokens."""
    if model not in RATES:
        return None
    ir, ore = RATES[model]
    return 256 * ir + int(max_tokens) * ore


def money(value: str, *, allow_zero: bool = False) -> int:
    try:
        n = Decimal(str(value)) * SCALE
        if not n.is_finite() or n != n.to_integral_value() or n < 0 or (n == 0 and not allow_zero):
            raise ValueError
        if n > 1_000_000 * SCALE:
            raise ValueError
        return int(n)
    except (InvalidOperation, ValueError):
        raise BudgetError("USD phải là số dương hữu hạn, tối đa 6 chữ số thập phân (chi phí đối soát có thể bằng 0)")


def usd(value: int) -> str:
    return f"{Decimal(value) / SCALE:.6f}"


def configured_path() -> Path:
    paths = [config.resolve(config.load(name)["budget_ledger"]).resolve()
             for name in ("llm_hunt", "agent_planner")]
    if paths[0] != paths[1]:
        raise BudgetError("④⑤ và planner phải dùng cùng budget_ledger")
    return paths[0]


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def db(self):
        if not self.path.is_file():
            raise BudgetError("Chưa đặt ngân sách. người vận hành chạy: python -m cti_hunt api-budget init --usd <số USD cho phép>")
        con = None
        try:
            con = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)
            with con:
                yield con
        except sqlite3.Error as exc:
            raise BudgetError(f"Không đọc/ghi được sổ ngân sách: {type(exc).__name__}; chưa gửi thêm yêu cầu") from exc
        finally:
            if con is not None:
                con.close()

    def init(self, amount: str) -> dict:
        limit = money(amount)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.open("xb").close()  # không ghi đè/reset sổ cũ
        except FileExistsError:
            raise BudgetError("Sổ ngân sách đã tồn tại; dùng status hoặc set-limit, không khởi tạo lại")
        with self.db() as con:
            con.executescript("""
                CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), limit_usd INTEGER NOT NULL);
                CREATE TABLE requests (id TEXT PRIMARY KEY, created TEXT DEFAULT CURRENT_TIMESTAMP,
                    model TEXT NOT NULL, rate_version TEXT NOT NULL, reserved INTEGER NOT NULL,
                    charged INTEGER, input_tokens INTEGER, output_tokens INTEGER, state TEXT NOT NULL);
                CREATE TABLE audit (created TEXT DEFAULT CURRENT_TIMESTAMP, action TEXT, detail TEXT);
            """)
            con.execute("INSERT INTO settings VALUES (1, ?)", (limit,))
            self._audit(con, "init", {"limit_usd": usd(limit)})
        return self.status()

    @staticmethod
    def _audit(con, action: str, detail: dict):
        con.execute("INSERT INTO audit(action, detail) VALUES (?, ?)",
                    (action, json.dumps(detail, ensure_ascii=False)))

    @staticmethod
    def _state(con):
        row = con.execute("SELECT limit_usd FROM settings WHERE id=1").fetchone()
        if row is None:
            raise BudgetError("Sổ ngân sách thiếu hạn mức; dừng trước khi gọi API")
        known, held = con.execute("SELECT COALESCE(SUM(charged),0), "
                                 "COALESCE(SUM(CASE WHEN charged IS NULL THEN reserved ELSE 0 END),0) "
                                 "FROM requests").fetchone()
        pending = con.execute("SELECT id, model, reserved FROM requests WHERE charged IS NULL ORDER BY created, id").fetchall()
        return row[0], known, held, pending

    def status(self) -> dict:
        with self.db() as con:
            con.execute("BEGIN")
            limit, known, held, pending = self._state(con)
            return {"ledger": str(self.path), "limit_usd": usd(limit), "known_cost_usd": usd(known),
                    "reserved_usd": usd(held), "remaining_usd": usd(limit - known - held),
                    "pending": [{"id": rid, "model": model, "reserved_usd": usd(reserved)}
                                for rid, model, reserved in pending]}

    def require_ready(self):
        status = self.status()
        if status["pending"]:
            raise BudgetError("Có yêu cầu đang chạy hoặc chưa rõ chi phí; xem api-budget status, đối soát trước khi gọi tiếp")
        if Decimal(status["remaining_usd"]) <= 0:
            raise BudgetExhausted("Đã hết hạn mức API cục bộ")

    def reserve(self, model: str, amount: int) -> str:
        if amount <= 0:
            raise BudgetError("Khoản dự phòng phải lớn hơn 0")
        with self.db() as con:
            con.execute("BEGIN IMMEDIATE")
            limit, known, held, pending = self._state(con)
            if pending:
                raise BudgetError("Có yêu cầu đang chạy/chưa rõ chi phí; không gửi thêm")
            if amount > limit - known - held:
                raise BudgetExhausted(f"Không đủ ngân sách: cần dự phòng {usd(amount)} USD, "
                                  f"còn {usd(limit - known - held)} USD. Chưa gửi yêu cầu sinh nội dung")
            rid = uuid.uuid4().hex
            con.execute("INSERT INTO requests(id, model, rate_version, reserved, state) VALUES (?, ?, ?, ?, 'pending')",
                        (rid, model, RATE_VERSION, amount))
            return rid

    def settle(self, rid: str, model: str, usage: dict):
        if not isinstance(usage, dict):
            raise BudgetError("API không trả usage hợp lệ; giữ khoản dự phòng để đối soát")
        values = [usage.get(k) for k in ("input_tokens", "output_tokens")]
        if any(type(v) is not int or v < 0 for v in values):
            raise BudgetError("API không trả usage hợp lệ; giữ khoản dự phòng để đối soát")
        if any(usage.get(k, 0) for k in ("cache_creation_input_tokens", "cache_read_input_tokens")):
            raise BudgetError("Usage có cache ngoài biểu giá hiện tại; giữ khoản dự phòng để đối soát")
        inp, out = values
        ir, ore = RATES[model]
        with self.db() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute("UPDATE requests SET charged=?, input_tokens=?, output_tokens=?, state='usage' "
                              "WHERE id=? AND model=? AND charged IS NULL", (inp * ir + out * ore, inp, out, rid, model))
            if cur.rowcount != 1:
                raise BudgetError("Không tìm thấy khoản dự phòng chưa quyết toán")

    def set_limit(self, amount: str) -> dict:
        limit = money(amount)
        with self.db() as con:
            con.execute("BEGIN IMMEDIATE")
            old, known, held, pending = self._state(con)
            if pending or limit < known + held:
                raise BudgetError("Phải đối soát yêu cầu chưa rõ chi phí; hạn mức không được thấp hơn số đã dùng")
            con.execute("UPDATE settings SET limit_usd=? WHERE id=1", (limit,))
            self._audit(con, "set_limit", {"old_usd": usd(old), "new_usd": usd(limit)})
        return self.status()

    def resolve(self, rid: str, amount: str, note: str) -> dict:
        cost = money(amount, allow_zero=True)
        if not note.strip():
            raise BudgetError("Cần ghi căn cứ đối soát từ Console")
        with self.db() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute("UPDATE requests SET charged=?, state='manual' WHERE id=? AND charged IS NULL", (cost, rid))
            if cur.rowcount != 1:
                raise BudgetError("Không có yêu cầu chưa quyết toán với ID này")
            self._audit(con, "resolve", {"id": rid, "cost_usd": usd(cost), "note": note.strip()})
        return self.status()


def guarded_request(client, payload: dict, headers: dict, log=None) -> dict:
    from . import providers
    if client.model_id not in RATES or client.base_url.rstrip("/") != "https://api.anthropic.com":
        raise BudgetError(f"Chặn ngân sách chỉ có biểu giá {', '.join(sorted(RATES))} trên API Anthropic chuẩn; "
                          "chưa gửi yêu cầu")
    request_cap = money(client.request_budget_usd) if client.request_budget_usd is not None else None
    if request_cap is not None and min_reserve(client.model_id, payload["max_tokens"]) > request_cap:
        raise BudgetExhausted("Khoản giữ trước tối thiểu vượt trần riêng; chưa đếm token hay sinh nội dung")
    ledger = Ledger(client.budget_ledger)
    ledger.require_ready()
    count_payload = {k: payload[k] for k in ("model", "system", "messages", "tools", "tool_choice")}
    # R1 (09/10): đếm token miễn phí, chưa giữ tiền → thử lại như lỗi mạng/429/5xx thường (400/401 vẫn dừng ngay),
    # với thời gian chờ ngắn. Một lần TLS treo ở đây từng làm vỡ cả lượt. Lời gọi sinh nội dung bên dưới vẫn 1 lần.
    count = providers._post(f"{client.base_url}/v1/messages/count_tokens", count_payload, headers,
                            timeout=min(client.timeout, COUNT_TIMEOUT_GIAY), retries=providers.RETRY_LAN)
    n = count.get("input_tokens")
    if type(n) is not int or n < 0:
        raise BudgetError("Token counting không trả số hợp lệ; chưa gửi yêu cầu sinh nội dung")
    # Token counting là ước tính: thêm 10% +256 token, không dự đoán output/thinking thấp hơn max_tokens.
    ir, ore = RATES[client.model_id]
    reserved = ((n * 110 + 99) // 100 + 256) * ir + payload["max_tokens"] * ore
    if request_cap is not None and reserved > request_cap:
        raise BudgetExhausted(f"Cần dự phòng {usd(reserved)} USD, vượt trần riêng {usd(request_cap)} USD; "
                              "chưa gửi yêu cầu sinh nội dung")
    rid = ledger.reserve(client.model_id, reserved)
    # Một HTTP sinh nội dung, không retry tự động khi mất phản hồi. Pending tồn tại cả khi tiến trình bị ngắt.
    data = providers._post(f"{client.base_url}/v1/messages", payload, headers,
                           timeout=client.timeout, retries=1, log=log)
    ledger.settle(rid, client.model_id, data.get("usage") or {})
    return data
