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
