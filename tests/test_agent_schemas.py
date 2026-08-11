import pytest
from pydantic import ValidationError

from app.agent.schemas import (
    CorrelationDecision,
    ExtractedIndicators,
    IndicatorCandidate,
    OpenValueSearchProposal,
    PatternType,
    SearchTemplate,
)
from app.schemas import IndicatorType


def test_indicator_candidate_holds_type_and_value():
    candidate = IndicatorCandidate(type=IndicatorType.IP, value="203.0.113.5")
    assert candidate.type == IndicatorType.IP
    assert candidate.value == "203.0.113.5"


def test_extracted_indicators_holds_a_list_of_candidates():
    result = ExtractedIndicators(
        candidates=[
            IndicatorCandidate(type=IndicatorType.IP, value="203.0.113.5"),
            IndicatorCandidate(type=IndicatorType.DOMAIN, value="evil.test"),
        ]
    )
    assert len(result.candidates) == 2


def test_extracted_indicators_defaults_to_empty_list():
    result = ExtractedIndicators(candidates=[])
    assert result.candidates == []


def test_pattern_type_has_five_members():
    assert {p.value for p in PatternType} == {
        "brute_force", "scanning", "lateral_movement", "none", "other",
    }


def test_search_template_has_four_members():
    assert {t.value for t in SearchTemplate} == {
        "same_src_ip_24h", "same_rule_id_host", "same_dst_host", "none_needed",
    }


def test_correlation_decision_requires_pattern_type_and_follow_up_query():
    decision = CorrelationDecision(pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED)
    assert decision.pattern_type == PatternType.BRUTE_FORCE
    assert decision.follow_up_query == SearchTemplate.NONE_NEEDED


def test_correlation_decision_rejects_unknown_pattern_type():
    with pytest.raises(ValidationError):
        CorrelationDecision(pattern_type="not_a_real_pattern", follow_up_query=SearchTemplate.NONE_NEEDED)


def test_open_value_search_proposal_holds_a_search_value():
    proposal = OpenValueSearchProposal(search_value="admin@evil.test")
    assert proposal.search_value == "admin@evil.test"
