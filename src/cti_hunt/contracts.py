"""Data contract giữa các khâu (v3 §4.5). Lịch chốt: Contract A T5 24/9, Contract B tuần 4.

Hai điểm cần quyết khi chốt Contract A (đánh dấu ĐỀ XUẤT, chưa có trong v3):
1. source_span.segment_id: mã đoạn trong DoanVan (vd SY-014). Khâu ② đọc đúng các đoạn đó, nên
   có mã đoạn thì truy vết ngược và so với bộ nhãn tham chiếu theo đoạn là tra thẳng, không phải khớp chuỗi.
2. Giá trị "không rõ": v3 ghi "report không nêu thì để trống"; file nhãn theo R6 ghi 'khong_ro' cho
   tool và execution_path. Khi đo, hai cách này được coi là tương đương (eval.extraction_metrics).
"""
from __future__ import annotations

from typing import Annotated, Literal
from datetime import timezone

from pydantic import AwareDatetime, BaseModel, Field, model_serializer, model_validator

Truong = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]    # tên cột events, đưa vào SQL dạng "..."


class SourceSpan(BaseModel):
    section: str = ""
    page: int = 0
    text: str = ""
    segment_id: str | None = None          # ĐỀ XUẤT (1)


class IOC(BaseModel):
    type: str
    value: str
    context: str = ""
    validated: bool = False
    source_span: SourceSpan = Field(default_factory=SourceSpan)


class TTPContext(BaseModel):
    tool: str = ""
    execution_path: Literal["local", "remote", ""] = ""
    source_role: str = ""
    target_role: str = ""
    account_type: str = ""
    preceded_by: list[str] = Field(default_factory=list)
    command_example: str = ""


class TTP(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str = ""
    behavior_description: str = ""
    context: TTPContext = Field(default_factory=TTPContext)
    source_span: SourceSpan
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class ContractA(BaseModel):
    """Đầu ra khâu ②, đầu vào khâu ③."""
    report_id: str
    title: str = ""
    published_date: str = ""
    source_url: str = ""
    actors: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    ttps: list[TTP] = Field(default_factory=list)


class Evidence(BaseModel):
    data_source: str = Field(min_length=1)          # MỘT channel: mẫu số FPR tính theo nguồn log (v3 §6.1)
    event_ids: list[int] = Field(min_length=1)
    key_fields: list[str] = Field(min_length=1)


class ExecutionWindow(BaseModel):
    """Explicit, reviewed UTC interval [start, end); never inferred from prose."""
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode='after')
    def validate_interval(self):
        if self.start >= self.end:
            raise ValueError('execution_window cần start < end')
        self.start = self.start.astimezone(timezone.utc)
        self.end = self.end.astimezone(timezone.utc)
        return self


class DemKhacNhau(BaseModel):
    """distinct_count: giữ sự kiện khi trong ±cua_so_giay quanh nó, cùng giá trị các trường `theo`, tập ứng viên có ít
    nhất `toi_thieu` giá trị `truong` khác nhau."""
    truong: Truong
    theo: list[Truong] = Field(min_length=1)
    cua_so_giay: int = Field(gt=0, le=86400)
    toi_thieu: int = Field(ge=2)


class MocNeo(BaseModel):
    """event_sequence/relative_time: giữ sự kiện xảy ra sau một sự kiện cuối của giả thuyết neo (đã chạy ở vòng trước),
    không quá `trong_vong_giay`, trùng giá trị các trường `cung`."""
    gia_thuyet: str = Field(min_length=1)
    trong_vong_giay: int = Field(gt=0, le=7 * 86400)
    cung: list[Truong] = Field(min_length=1)


class CapTruong(BaseModel):
    ung_vien: Truong
    nguon: Truong


class VangMat(BaseModel):
    """absence: giữ sự kiện khi KHÔNG có sự kiện nào của nguồn (channel, event_ids) khớp các cặp trường trong
    `truoc_giay` giây trước nó. Trường khớp phía ứng viên rỗng thì không chứng minh được vắng mặt: không giữ."""
    channel: str = Field(min_length=1)
    event_ids: list[int] = Field(min_length=1)
    khop: list[CapTruong] = Field(min_length=1)
    truoc_giay: int = Field(gt=0, le=86400)


class RangBuoc(BaseModel):
    """Ràng buộc nhiều sự kiện do mã thực thi (đề xuất v2 đã duyệt, phương án B); người duyệt thấy ở ◆."""
    dem_khac_nhau: DemKhacNhau | None = None
    moc_neo: MocNeo | None = None
    vang_mat: VangMat | None = None

    @model_validator(mode="after")
    def check_any(self):
        if not (self.dem_khac_nhau or self.moc_neo or self.vang_mat):
            raise ValueError("rang_buoc cần ít nhất một loại")
        return self


class ContractB(BaseModel):
    """Đầu ra khâu ④, đầu vào khâu ⑤. Thiếu nguồn log / mã sự kiện / tên trường thì không hợp lệ (v3 §4.2)."""
    hypothesis_id: str = Field(min_length=1)
    behavior: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    timeframe: str = Field(min_length=1)
    evidence: Evidence
    linked_ttps: list[str] = Field(min_length=1)
    source_spans: list[SourceSpan] = Field(default_factory=list)
    priority: str = ""
    status: Literal["pending_review", "approved", "rejected"] = "pending_review"
    origin: Literal["telemetry_mapping", "pivot"] = "telemetry_mapping"
    pivot_depth: int = 0
    pivot_kind: Literal["may", "tai_khoan"] | None = None
    pivot_value: str = ""
    required_operations: list[Literal['distinct_count', 'event_sequence', 'absence']] = Field(default_factory=list)
    execution_window: ExecutionWindow | None = None
    rang_buoc: RangBuoc | None = None

    @model_serializer(mode="wrap")
    def _omit_empty_constraint(self, handler):
        # Không có ràng buộc thì JSON giữ đúng byte như trước: phiếu ◆ và gói duyệt lọc cũ băm theo nội dung này.
        data = handler(self)
        if isinstance(data, dict) and data.get("rang_buoc", 0) is None:
            del data["rang_buoc"]
        return data

    @model_validator(mode="after")
    def check_pivot(self):
        if self.origin == "pivot" and (self.pivot_depth < 1 or not self.pivot_kind or not self.pivot_value.strip()):
            raise ValueError("giả thuyết pivot cần độ sâu, loại và giá trị thực thể")
        if self.origin == "telemetry_mapping" and (self.pivot_depth != 0 or self.pivot_kind or self.pivot_value):
            raise ValueError("giả thuyết từ report không được mang ràng buộc pivot")
        return self
