from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AlertStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    INVESTIGATED = "investigated"
    CLOSED = "closed"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    COMPLETE = "complete"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class EnrichmentVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class AgentRef(BaseModel):
    id: str
    name: str
    ip: str


class MitreRef(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str


class Alert(BaseModel):
    alert_id: UUID
    source_alert_id: str
    source_system: str
    rule_id: str
    rule_description: str
    rule_level: int
    rule_groups: list[str] = Field(default_factory=list)
    mitre: list[MitreRef] | None = None
    timestamp: datetime
    ingested_at: datetime
    agent: AgentRef
    manager_name: str
    location: str
    full_log: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    src_user: str | None = None
    dst_user: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    raw_json: dict[str, Any]
    status: AlertStatus = AlertStatus.NEW


class EnrichmentResult(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str
    provider_id: str
    queried_at: datetime
    verdict: EnrichmentVerdict
    score: float = Field(ge=0, le=100)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    cache_expires_at: datetime
    error: str | None = None


class InvestigationStep(BaseModel):
    step_name: str
    action: str
    tool_used: str | None = None
    input: dict[str, Any] | None = None
    output_summary: str
    timestamp: datetime


class RiskAssessment(BaseModel):
    severity: Severity
    confidence: Confidence
    rationale: str


class ModelMetadata(BaseModel):
    model_name: str
    model_version: str
    prompt_version: str


class Report(BaseModel):
    report_id: UUID
    alert_id: UUID
    generated_at: datetime
    alert_summary: str
    investigation_timeline: list[InvestigationStep] = Field(default_factory=list)
    enrichment_findings: list[EnrichmentResult] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_actions_freeform_experimental: list[str] | None = None
    uncertainty_notes: str = ""
    status: ReportStatus = ReportStatus.DRAFT
    model_metadata: ModelMetadata
