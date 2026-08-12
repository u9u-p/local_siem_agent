from enum import Enum

from pydantic import BaseModel

from app.schemas import IndicatorType


class IndicatorCandidate(BaseModel):
    type: IndicatorType
    value: str


class ExtractedIndicators(BaseModel):
    candidates: list[IndicatorCandidate]


class PatternType(str, Enum):
    BRUTE_FORCE = "brute_force"
    SCANNING = "scanning"
    LATERAL_MOVEMENT = "lateral_movement"
    NONE = "none"
    OTHER = "other"


class SearchTemplate(str, Enum):
    SAME_SRC_IP_24H = "same_src_ip_24h"
    SAME_RULE_ID_HOST = "same_rule_id_host"
    SAME_DST_HOST = "same_dst_host"
    NONE_NEEDED = "none_needed"


class CorrelationDecision(BaseModel):
    pattern_type: PatternType
    follow_up_query: SearchTemplate


class OpenValueSearchProposal(BaseModel):
    search_value: str


class RecommendedAction(str, Enum):
    DISABLE_OR_RESET_ACCOUNT = "Disable or reset credentials for the affected user account"
    BLOCK_SOURCE_IP = "Block the source IP at the network perimeter"
    ISOLATE_HOST = "Isolate the affected host from the network pending investigation"
    ESCALATE_TO_IR = "Escalate to the incident response / Tier 2 team"
    REVIEW_AUTH_LOGS_WIDER_WINDOW = "Review authentication logs for this account over a wider time window"
    VERIFY_EXPECTED_SOURCE = "Verify whether the source IP/user is a known, expected service account or automation"
    RUN_AV_EDR_SCAN = "Run an antivirus/EDR scan on the affected host"
    REVIEW_FIM_BASELINE = "Review file integrity monitoring output for unauthorized changes on the affected host"
    PATCH_VULNERABLE_SOFTWARE = "Patch or update the vulnerable software identified for this host"
    NOTIFY_ASSET_OWNER = "Notify the asset owner of the affected host or agent"
    ROTATE_EXPOSED_CREDENTIALS = "Rotate any credentials or secrets that may have been exposed"
    REVIEW_FIREWALL_SEGMENTATION = "Review firewall/network segmentation rules for the affected subnet"
    CORRELATE_WIDER_ENVIRONMENT = "Correlate this indicator against the wider environment beyond this alert's time window"
    PRESERVE_EVIDENCE = "Preserve logs and evidence for the affected host pending further investigation"
    MONITOR_NO_ACTION = "No immediate action needed — monitor for recurrence"
    ESCALATE_TO_HUMAN_ANALYST = "Escalate to a human analyst for manual review"


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class DraftReportCanonical(BaseModel):
    alert_summary: str
    rationale: str
    recommended_actions: list[RecommendedAction]


class DraftReportExperimental(BaseModel):
    recommended_actions_freeform: list[str]
    triage_verdict: TriageVerdict
    triage_rationale: str


class ClaimAudit(BaseModel):
    claim: str
    supported: bool
    correction: str | None = None


class SelfCheckResult(BaseModel):
    audits: list[ClaimAudit]
