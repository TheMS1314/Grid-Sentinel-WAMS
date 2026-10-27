from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict, field_validator


class Measurement(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    timestamp: datetime
    values: dict[str, float | None]

    @field_validator('values')
    @classmethod
    def bound_meter_values(cls, values: dict[str, float | None]):
        # Current model consumes 60 meter fields. A small margin permits
        # forward-compatible supplementary columns without unbounded parsing.
        if len(values) > 96:
            raise ValueError('Each observation permits at most 96 measurement fields')
        if any(not key or len(key) > 128 for key in values):
            raise ValueError('Measurement names must be 1..128 characters')
        return values


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_name: str = Field(default='Manual upload', min_length=1, max_length=120)
    records: list[Measurement] = Field(min_length=1, max_length=1000)

    @field_validator('source_name')
    @classmethod
    def nonblank_source_name(cls, source_name: str):
        if not source_name.strip():
            raise ValueError('source_name must not be blank')
        return source_name.strip()


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    timestamp: datetime
    kind: str
    score: float | None
    identity_name: str | None
    reason: str | None


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    source_name: str
    observation_count: int
    review_count: int
    abstention_count: int
    max_score: float
    duration_seconds: float
    model_id: str


class AnalysisDetail(AnalysisSummary):
    findings: list[FindingOut]
