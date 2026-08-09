from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas import Alert


class SearchQuery(BaseModel):
    field: str
    operator: Literal["eq", "contains", "range", "terms"]
    value: Any
    time_range: tuple[datetime, datetime] | None = None


class SearchResult(BaseModel):
    alerts: list[Alert]
    total_count: int


class AgentContext(BaseModel):
    id: str
    name: str
    ip: str
    os_platform: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    status: str
    last_keep_alive: datetime | None = None


class RuleMetadata(BaseModel):
    rule_id: str
    description: str
    level: int
    groups: list[str] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)
