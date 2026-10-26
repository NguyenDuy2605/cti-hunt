"""Adapter mô hình: hai kiểu API của Anthropic, đọc phản hồi, xử lý từ chối.

Không gọi API thật — chỉ dựng thân yêu cầu và phản hồi giả (docs/METHODOLOGY.md §4.4).
"""
import pytest

from cti_hunt.llm import providers as P

SCHEMA = {"type": "object", "properties": {
    "items": {"type": "array", "items": {"$ref": "#/$defs/Item"}}},
    "required": ["items"],
    "$defs": {"Item": {"type": "object", "properties": {"segment_id": {"type": "string"}},
                       "required": ["segment_id"]}}}


@pytest.mark.parametrize("model, modern", [
    ("claude-opus-5-5", True), ("claude-opus-5", True), ("claude-sonnet-5", True),
    ("claude-opus-4-8", True), ("claude-opus-4-7", True), ("claude-fable-5-1", True),
    ("claude-opus-4-6", False), ("claude-sonnet-4-6", False),
    ("claude-haiku-4-5-20251001", False), ("mo-hinh-noi-bo", False),
])
def test_api_style_is_detected_from_the_model_name(model, modern):
    """Tham số lấy mẫu bị bỏ từ họ Claude 5 và Opus 4.7; tên lạ giữ hành vi đời cũ."""
    assert P.AnthropicClient(model).kieu_api == ("modern" if modern else "legacy")


@pytest.mark.parametrize("model, effort", [("claude-opus-5-5", "high"), ("claude-sonnet-5", "high"),
                                          ("claude-sonnet-5", "medium")])
def test_modern_payload_drops_temperature_and_never_forces_the_tool(model, effort):
    """②, ④⑤ và planner: auto + strict + effort, không gửi tham số lấy mẫu."""
    c = P.AnthropicClient(model, effort=effort, max_output_tokens=16000)
    p = c.build_payload("SYS", "USER", SCHEMA)
    assert "temperature" not in p and "thinking" not in p
    assert p["tool_choice"] == {"type": "auto"}
    assert p["model"] == model and p["output_config"] == {"effort": effort}
    assert p["tools"][0]["strict"] is True
    assert p["max_tokens"] == 16000
    assert P.TOOL_HINT in p["system"]                      # auto -> phải nói rõ khi nào gọi công cụ
    sch = p["tools"][0]["input_schema"]
    assert sch["additionalProperties"] is False            # điều kiện của strict tool use
    assert sch["$defs"]["Item"]["additionalProperties"] is False
    assert SCHEMA.get("additionalProperties") is None      # không sửa schema gốc


def test_strict_schema_makes_every_field_required_and_drops_defaults():
    """Probe 25/9: 15 trường tùy chọn -> HTTP 400 "Schema is too complex". Lược đồ gửi đi không còn trường tùy chọn."""
    from cti_hunt.stages import s2_ttp, s4_hypothesis
    for model in (s2_ttp.ExtractionBatch, s4_hypothesis.LLMHypothesisBatch):
        original = model.model_json_schema()
        sent = P.strict_schema(original)
        objects = []

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("properties"), dict):
                    objects.append(node)
                    for v in node["properties"].values():
                        walk(v)
                for k, v in node.items():
                    assert k != "default"
                    if k != "properties":
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(sent)
        assert objects and all(o["required"] == list(o["properties"]) and o["additionalProperties"] is False
                               for o in objects)
        assert model.model_json_schema() == original                      # không sửa schema gốc
    kept = P.strict_schema({"type": "object", "properties": {"default": {"type": "string", "default": ""}}})
    assert kept["properties"] == {"default": {"type": "string"}} and kept["required"] == ["default"]


def test_legacy_payload_keeps_temperature_and_forced_tool():
    c = P.AnthropicClient("claude-haiku-4-5-20251001", temperature=0)
    p = c.build_payload("SYS", "USER", SCHEMA)
    assert p["temperature"] == 0
    assert p["tool_choice"] == {"type": "tool", "name": P.TOOL_NAME}
    assert "strict" not in p["tools"][0] and "output_config" not in p
    assert p["system"] == "SYS"


def test_describe_records_what_was_actually_sent():
    d = P.AnthropicClient("claude-opus-5-5", effort="high").describe()
    assert d["kieu_api"] == "modern" and d["temperature"] is None and d["effort"] == "high"
    assert d["strict_tool_use"] is True
    assert P.AnthropicClient("claude-opus-5-5").describe()["effort"] == "mac_dinh_cua_mo_hinh"


def test_refusal_is_a_failed_run_not_a_retry():
    """stop_reason=refusal: báo lỗi kèm loại, không thử lại, không chuyển mô hình khác."""
    data = {"stop_reason": "refusal", "stop_details": {"type": "refusal", "category": "cyber"},
            "content": []}
    with pytest.raises(P.LLMError) as e:
        P.read_response(data)
    assert "cyber" in str(e.value) and "KHÔNG chạy lại" in str(e.value)


def test_response_is_read_by_block_type_skipping_thinking():
    data = {"stop_reason": "tool_use", "content": [
        {"type": "thinking", "thinking": ""},
        {"type": "tool_use", "name": P.TOOL_NAME, "input": {"items": [{"segment_id": "SY-001"}]}}]}
    assert P.read_response(data) == {"items": [{"segment_id": "SY-001"}]}


def test_json_in_a_text_block_is_accepted_when_the_model_skips_the_tool():
    """tool_choice=auto nên mô hình có thể trả thẳng JSON."""
    data = {"stop_reason": "end_turn", "content": [
        {"type": "thinking", "thinking": ""}, {"type": "text", "text": '{"items": []}'}]}
    assert P.read_response(data) == {"items": []}


def test_truncated_response_names_max_tokens():
    with pytest.raises(P.LLMError, match="max_tokens"):
        P.read_response({"stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": ""}]})


def test_from_config_passes_effort_through():
    c = P.from_config({"provider": "anthropic", "model": "claude-opus-5-5", "effort": "high",
                       "max_output_tokens": 16000, "temperature": 0})
    assert isinstance(c, P.AnthropicClient) and c.effort == "high"
