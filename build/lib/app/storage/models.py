from datetime import datetime
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel


class AlertRecord(SQLModel, table=True):
    __tablename__ = "alerts"

    alert_id: str = Field(primary_key=True)
    source_alert_id: str
    source_system: str
    rule_id: str
    rule_description: str
    rule_level: int
    rule_groups: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    mitre: list[dict[str, Any]] | None = Field(default=None, sa_column=Column(JSON))
    timestamp: datetime
    ingested_at: datetime
    agent: dict[str, Any] = Field(sa_column=Column(JSON))
    manager_name: str
    location: str
    full_log: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    src_user: str | None = None
    dst_user: str | None = None
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    raw_json: dict[str, Any] = Field(sa_column=Column(JSON))
    status: str = Field(default="new", index=True)


class ReportRecord(SQLModel, table=True):
    __tablename__ = "reports"

    report_id: str = Field(primary_key=True)
    alert_id: str = Field(index=True)
    generated_at: datetime
    alert_summary: str
    investigation_timeline: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    enrichment_findings: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    risk_assessment: dict[str, Any] = Field(sa_column=Column(JSON))
    recommended_actions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recommended_actions_freeform_experimental: list[str] | None = Field(default=None, sa_column=Column(JSON))
    uncertainty_notes: str = ""
    status: str = Field(default="draft")
    model_metadata: dict[str, Any] = Field(sa_column=Column(JSON))
