from enum import Enum

from pydantic import BaseModel


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
