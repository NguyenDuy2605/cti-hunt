"""Adapter mô hình ngôn ngữ. Chỉ dùng thư viện chuẩn để không phải cài thêm gói.

Khâu ② chỉ phụ thuộc giao diện LLMClient; thêm nhà cung cấp mới = thêm một lớp ở đây, không đụng s2_ttp.

HAI KIỂU API CỦA ANTHROPIC (tài liệu đọc 23–26/09/2026, `_sampling_removed`):

- `legacy` — Claude 4.6 trở xuống và Haiku 4.5: nhận `temperature`, ép lược đồ bằng
  `tool_choice: {type: tool}` (buộc gọi công cụ).
- `modern` — họ Claude 5 (kể cả Fable/Mythos) và Opus 4.7 trở lên: adapter không gửi
  `temperature`/`top_p`/`top_k`, dùng `effort` và `strict: true` + `tool_choice: {type: auto}`.
  Opus 5.5 luôn bật thinking, từ chối forced tool use; Sonnet 5 bật adaptive thinking mặc định và
  từ chối tham số lấy mẫu khác mặc định. Không suy rằng mọi model đều cấm tắt thinking.
  Adapter giữ thinking mặc định cho cả hai; thinking chiếm chỗ trong `max_tokens`.

Từ chối vì bộ phân loại an toàn (`stop_reason: "refusal"`) được coi là THẤT BẠI của lần chạy:
không thử lại, không bật fallback sang mô hình khác — làm vậy là phá quy tắc ghim mô hình.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

TOOL_NAME = "emit_extraction"

# Với tool_choice=auto, phải nói rõ trong prompt khi nào dùng công cụ (tài liệu Anthropic).
# Đây là chi tiết vận chuyển, không phải định nghĩa nhiệm vụ, nên để ở đây chứ không sửa file prompt;
# nội dung được ghi vào meta.json của lần chạy qua describe().
TOOL_HINT = f'Return the result by calling the tool "{TOOL_NAME}". Do not answer in prose.'


class LLMError(RuntimeError):
    pass


class TransportError(LLMError):
    """Lỗi mạng hoặc HTTP. Đã thử lại đủ số lần (hoặc là lỗi không đáng thử lại, vd 400).
    Giao thức 29/9: dừng lần chạy, giữ nguyên các lô đã xong, chạy tiếp bằng `ttp --resume`."""


class RefusalError(LLMError):
    """Bộ phân loại an toàn từ chối. KHÔNG gọi lại, KHÔNG chuyển mô hình khác."""


class BadOutputError(LLMError):
    """Không có tool_use VÀ khối text không ra JSON dùng được. Lô này được gọi lại tối đa MỘT lần."""


# Lỗi mạng: thử lại 3 lần, giãn dần. 400 là lỗi yêu cầu (sai tham số) nên dừng ngay — thử lại vô ích.
RETRY_LAN = 3
RETRY_CHO = (2, 8, 32)

# Trường được ghi vào nhật ký của khâu ④⑤, vòng pivot và planner: token, stop_reason, thử lại. Không ghi thân lỗi
# HTTP (`loi`) do nhà cung cấp trả.
SAFE_EVENT_KEYS = ("lan", "http", "thu_lai", "cho_giay", "stop_reason", "input_tokens", "output_tokens", "max_tokens")


def event_recorder():
    """(danh sách sự kiện, hàm ghi) để truyền vào `complete_json(..., log=...)`."""
    events: list[dict] = []

    def record(event: dict) -> None:
        events.append({k: event[k] for k in SAFE_EVENT_KEYS if k in event})
    return events, record


def token_totals(events: list[dict]) -> dict:
    return {"input_tokens": sum(e.get("input_tokens") or 0 for e in events),
            "output_tokens": sum(e.get("output_tokens") or 0 for e in events)}


def _post(url: str, payload: dict, headers: dict, timeout: int = 180,
          retries: int = RETRY_LAN, sleep=time.sleep, log=None) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"content-type": "application/json", **headers})
    ghi = log if log is not None else (lambda _: None)
    for lan in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            if e.code == 400:                    # sai tham số hoặc hết credit: gọi lại vẫn hỏng y hệt
                ghi({"lan": lan, "http": e.code, "thu_lai": False, "loi": body})
                raise TransportError(f"HTTP 400 (không thử lại — sai tham số, hoặc vấn đề tài khoản "
                                     f"như hết credit; đọc kỹ thông điệp): {body}") from e
            if e.code != 429 and e.code < 500:   # 401/403/404: khóa sai, không có quyền…
                ghi({"lan": lan, "http": e.code, "thu_lai": False, "loi": body})
                raise TransportError(f"HTTP {e.code} (không thử lại): {body}") from e
            cho = _retry_after(e) or RETRY_CHO[min(lan, len(RETRY_CHO)) - 1]
            ghi({"lan": lan, "http": e.code, "thu_lai": lan < retries, "cho_giay": cho, "loi": body})
            if lan == retries:
                raise TransportError(f"HTTP {e.code} sau {retries} lần thử: {body}") from e
            sleep(cho)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            cho = RETRY_CHO[min(lan, len(RETRY_CHO)) - 1]
            ghi({"lan": lan, "http": None, "thu_lai": lan < retries, "cho_giay": cho, "loi": str(e)})
            if lan == retries:
                raise TransportError(f"gọi {url} thất bại sau {retries} lần thử: {e}") from e
            sleep(cho)
    raise TransportError(f"gọi {url} thất bại sau {retries} lần thử")      # không tới được


def _retry_after(e) -> float | None:
    """Máy chủ bảo chờ bao lâu thì nghe theo (chỉ nhận dạng số giây)."""
    try:
        v = (e.headers or {}).get("retry-after")
        return float(v) if v is not None and str(v).strip().replace(".", "", 1).isdigit() else None
    except Exception:
        return None


def _parse_json(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```")[1].removeprefix("json").strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError as e:
        raise BadOutputError(f"đầu ra không phải JSON hợp lệ: {e}; 200 ký tự đầu: {t[:200]}") from e


def _sampling_removed(model_id: str) -> bool:
    """Nhóm dùng payload modern (không gửi tham số lấy mẫu): họ Claude 5, Fable/Mythos,
    và Opus 4.7 trở lên. Tên lạ (gateway nội bộ) coi như đời cũ, giữ hành vi sẵn có."""
    m = model_id.lower()
    if "fable" in m or "mythos" in m:
        return True
    mm = re.search(r"claude-(?:opus|sonnet|haiku)-(\d+)(?:-(\d+))?", m)
    if not mm:
        return False
    major, minor = int(mm.group(1)), int(mm.group(2) or 0)
    return major >= 5 or (major == 4 and minor >= 7)


def strict_schema(schema: dict) -> dict:
    """Bản sao cho strict tool use: additionalProperties=false và MỌI trường bắt buộc ở mọi object, bỏ `default`.

    Probe 25/9 trên claude-opus-5-5: lược đồ khâu ② để 15 trường tùy chọn thì API trả 400 "Schema is too complex"
    (mỗi trường tùy chọn làm ngữ pháp strict phình ra). Prompt các khâu đã ghi giá trị rỗng cho từng trường ("", [],
    "khong_ro") nên bắt buộc mọi trường không đổi nghĩa; model pydantic giữ default để kiểm phản hồi như cũ."""
    def walk(node):
        if isinstance(node, dict):
            out = {k: walk(v) for k, v in node.items() if k != "default"}
            # Anthropic strict grammar does not support numeric/string bounds.
            # Keep them in the ORIGINAL Pydantic schema for local validation,
            # and communicate them as descriptions in the transport copy only.
            unsupported = set()
            if node.get("type") in ("number", "integer"):
                unsupported = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"}
            elif node.get("type") == "string":
                unsupported = {"minLength", "maxLength"}
            elif node.get("type") == "array":
                unsupported = {"maxItems", "uniqueItems"}
                if node.get("minItems", 0) not in (0, 1):
                    unsupported.add("minItems")
            removed = {k: out.pop(k) for k in sorted(unsupported) if k in out}
            if removed:
                out["description"] = (out.get("description", "") + " Constraints validated locally: "
                                      + json.dumps(removed, ensure_ascii=False)).strip()
            if isinstance(node.get("properties"), dict):
                out["properties"] = {k: walk(v) for k, v in node["properties"].items()}
                out["required"] = list(node["properties"])
            if out.get("type") == "object" or "properties" in out:
                out.setdefault("additionalProperties", False)
            return out
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node
    return walk(schema)


@dataclass
class MockClient:
    """Dùng cho test và --dry-run: trả sẵn từng phản hồi theo thứ tự gọi."""
    responses: list[dict] = field(default_factory=list)
    model_id: str = "mock"
    calls: list[tuple[str, str]] = field(default_factory=list)

    def complete_json(self, system: str, user: str, json_schema: dict, log=None) -> dict:
        self.calls.append((system, user))
        if not self.responses:
            return {"items": []}
        r = self.responses.pop(0)
        if isinstance(r, Exception):          # dựng tình huống lỗi trong test
            raise r
        return r

    def describe(self) -> dict:
        return {"model": self.model_id, "kieu_api": "mock"}


@dataclass
class AnthropicClient:
    model_id: str
    api_key_env: str = "LLM_API_KEY"
    base_url: str = "https://api.anthropic.com"
    temperature: float = 0
    max_output_tokens: int = 4096
    effort: str = ""                  # low | medium | high | xhigh | max (chỉ kiểu modern)
    timeout: int = 180                # giây; max_tokens rộng thì phải nới, nếu không đứt giữa chừng
    budget_ledger: str | None = None  # ④⑤/planner; ② v1 giữ nguyên đường gọi cũ
    request_budget_usd: str | None = None  # optional reservation cap for a single development probe

    @property
    def kieu_api(self) -> str:
        return "modern" if _sampling_removed(self.model_id) else "legacy"

    def build_payload(self, system: str, user: str, json_schema: dict) -> dict:
        """Thân yêu cầu. Tách riêng để test được mà không gọi API thật."""
        modern = self.kieu_api == "modern"
        tool = {"name": TOOL_NAME, "description": "Trả kết quả rút trích",
                "input_schema": strict_schema(json_schema) if modern else json_schema}
        payload = {"model": self.model_id, "max_tokens": self.max_output_tokens,
                   "system": f"{system}\n\n{TOOL_HINT}" if modern else system,
                   "messages": [{"role": "user", "content": user}], "tools": [tool]}
        if modern:
            tool["strict"] = True                        # forced tool use bị từ chối -> auto + strict
            payload["tool_choice"] = {"type": "auto"}
            if self.effort:                              # thinking luôn bật; effort là núm duy nhất
                payload["output_config"] = {"effort": self.effort}
        else:
            payload["temperature"] = self.temperature
            payload["tool_choice"] = {"type": "tool", "name": TOOL_NAME}
        return payload

    def describe(self) -> dict:
        """Tham số thực gửi đi, để ghi vào meta.json của lần chạy (chạy lại được)."""
        modern = self.kieu_api == "modern"
        out = {"model": self.model_id, "kieu_api": self.kieu_api,
                "max_output_tokens": self.max_output_tokens, "timeout_giay": self.timeout,
                "temperature": None if modern else self.temperature,
                "effort": (self.effort or "mac_dinh_cua_mo_hinh") if modern else None,
                "tool_choice": "auto" if modern else "tool",
                "strict_tool_use": modern,
                "system_them": TOOL_HINT if modern else ""}
        if self.budget_ledger:
            out["budget_guard"] = {"ledger": self.budget_ledger, "generation_attempts": 1,
                                   "input_margin_percent": 10, "input_margin_tokens": 256}
            if self.request_budget_usd is not None:
                out["budget_guard"]["request_budget_usd"] = self.request_budget_usd
        return out

    def complete_json(self, system: str, user: str, json_schema: dict, log=None) -> dict:
        if self.request_budget_usd is not None and not self.budget_ledger:
            raise LLMError("Trần riêng cần sổ ngân sách; chưa gửi yêu cầu")
        key = os.environ.get(self.api_key_env)
        if not key:
            raise LLMError(f"chưa đặt biến môi trường {self.api_key_env}")
        payload = self.build_payload(system, user, json_schema)
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        if self.budget_ledger:
            from .budget import guarded_request
            data = guarded_request(self, payload, headers, log)
        else:
            data = _post(f"{self.base_url}/v1/messages", payload, headers, timeout=self.timeout, log=log)
        if log is not None:            # ghi stop_reason + số token của TỪNG lô, kể cả lô thành công
            u = data.get("usage") or {}
            log({"stop_reason": data.get("stop_reason"),
                 "output_tokens": u.get("output_tokens"), "input_tokens": u.get("input_tokens"),
                 "max_tokens": self.max_output_tokens})
        return read_response(data)


def read_response(data: dict) -> dict:
    """Đọc phản hồi Anthropic theo `type` của từng khối; bỏ qua khối thinking."""
    stop = data.get("stop_reason")
    if stop == "refusal":
        det = data.get("stop_details") or {}
        raise RefusalError(f"mô hình từ chối vì bộ phân loại an toàn (loại {det.get('category')!r}): "
                           "ghi là thất bại của lần chạy, KHÔNG chạy lại và KHÔNG chuyển mô hình khác")
    blocks = data.get("content", [])
    for block in blocks:
        if block.get("type") == "tool_use":
            return block["input"]
    for block in blocks:                        # tool_choice=auto: có thể trả JSON trong khối text
        if block.get("type") == "text" and (block.get("text") or "").strip():
            return _parse_json(block["text"])
    if stop == "max_tokens":
        raise BadOutputError("phản hồi bị cắt vì chạm max_tokens (thinking cũng tiêu token) — "
                             "tăng max_output_tokens hoặc hạ effort")
    raise BadOutputError(f"phản hồi không có khối tool_use (stop_reason={stop!r})")


@dataclass
class OpenAICompatibleClient:
    """OpenAI, Azure OpenAI, vLLM, gateway nội bộ — cùng endpoint /chat/completions."""
    model_id: str
    api_key_env: str = "LLM_API_KEY"
    base_url: str = "https://api.openai.com/v1"
    temperature: float = 0
    max_output_tokens: int = 4096

    def describe(self) -> dict:
        return {"model": self.model_id, "kieu_api": "openai_compatible",
                "temperature": self.temperature, "max_output_tokens": self.max_output_tokens}

    def complete_json(self, system: str, user: str, json_schema: dict, log=None) -> dict:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise LLMError(f"chưa đặt biến môi trường {self.api_key_env}")
        data = _post(f"{self.base_url}/chat/completions", {
            "model": self.model_id, "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "extraction", "schema": json_schema}},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }, {"authorization": f"Bearer {key}"}, log=log)
        return _parse_json(data["choices"][0]["message"]["content"])


def from_config(cfg: dict):
    p = (cfg.get("provider") or "mock").lower()
    common = {"api_key_env": cfg.get("api_key_env", "LLM_API_KEY"),
              "temperature": cfg.get("temperature", 0),
              "max_output_tokens": cfg.get("max_output_tokens", 4096)}
    if p == "mock":
        return MockClient()
    if p == "anthropic":
        from .. import config
        return AnthropicClient(cfg["model"], base_url=cfg.get("base_url") or "https://api.anthropic.com",
                               effort=cfg.get("effort", ""),
                               budget_ledger=str(config.resolve(cfg["budget_ledger"])) if cfg.get("budget_ledger") else None,
                               timeout=int(cfg.get("request_timeout_giay", 180)), **common)
    if p == "openai_compatible":
        return OpenAICompatibleClient(cfg["model"], base_url=cfg.get("base_url") or "https://api.openai.com/v1", **common)
    raise LLMError(f"provider không biết: {p}")
