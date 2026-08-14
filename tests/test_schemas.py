import pytest
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from pydantic import ValidationError

from app.schemas import (
    AgentRef,
    Alert,
    AlertStatus,
    Confidence,
    EnrichmentVerdict,
    IndicatorType,
    MitreRef,
    ReportStatus,
    Severity,
)


def test_alert_status_members():
    assert {s.value for s in AlertStatus} == {"new", "in_progress", "investigated", "closed"}


def test_report_status_members():
    assert {s.value for s in ReportStatus} == {"draft", "complete", "needs_human_review"}


def test_severity_members():
    assert {s.value for s in Severity} == {"low", "medium", "high", "critical"}


def test_confidence_members():
    assert {s.value for s in Confidence} == {"low", "medium", "high"}


def test_indicator_type_members():
    assert {s.value for s in IndicatorType} == {"ip", "domain", "url", "file_hash", "email"}


def test_enrichment_verdict_members():
    assert {s.value for s in EnrichmentVerdict} == {"malicious", "suspicious", "clean", "unknown"}


def test_agent_ref_requires_all_fields():
    agent = AgentRef(id="001", name="web-01", ip="10.0.0.5")
    assert agent.id == "001"
    with pytest.raises(ValidationError):
        AgentRef(id="001", name="web-01")


def test_mitre_ref_requires_all_fields():
    ref = MitreRef(tactic="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application")
    assert ref.technique_id == "T1190"
    with pytest.raises(ValidationError):
        MitreRef(tactic="Initial Access", technique_id="T1190")


from app.schemas import CommandDecodeResult, DecodedSegment, ProcessExecutionFields


def test_process_execution_fields_all_optional():
    fields = ProcessExecutionFields()
    assert fields.command_line is None
    assert fields.process_hashes is None


def test_decoded_segment_requires_encoding_original_decoded():
    segment = DecodedSegment(encoding="base64", original="Zm9v", decoded="foo")
    assert segment.encoding == "base64"
    with pytest.raises(ValidationError):
        DecodedSegment(encoding="not_a_real_encoding", original="Zm9v", decoded="foo")


def test_command_decode_result_defaults_empty_segments():
    result = CommandDecodeResult(command_line="powershell.exe -enc AAA")
    assert result.decoded_segments == []
    assert result.parent_command_line is None


def _make_alert(**overrides: Any) -> Alert:
    defaults: dict[str, Any] = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Nov 10 12:00:00 web-01 sshd[123]: Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_alert_defaults_status_to_new():
    alert = _make_alert()
    assert alert.status == AlertStatus.NEW
    assert alert.rule_groups == []
    assert alert.data == {}
    assert alert.mitre is None


def test_alert_rejects_non_integer_rule_level():
    with pytest.raises(ValidationError):
        _make_alert(rule_level="not-a-number")


def test_alert_accepts_optional_network_fields():
    alert = _make_alert(source_ip="203.0.113.5", source_port=51820)
    assert alert.source_ip == "203.0.113.5"
    assert alert.destination_ip is None


def test_alert_process_defaults_to_none():
    alert = _make_alert()
    assert alert.process is None


def test_alert_accepts_process_execution_fields():
    alert = _make_alert(process=ProcessExecutionFields(command_line="powershell.exe -enc AAA"))
    assert alert.process.command_line == "powershell.exe -enc AAA"


from app.schemas import (
    Confidence,
    EnrichmentResult,
    EnrichmentVerdict,
    IndicatorType,
    InvestigationStep,
    ModelMetadata,
    Report,
    ReportStatus,
    RiskAssessment,
    Severity,
)


def _make_report(**overrides: Any) -> Report:
    defaults: dict[str, Any] = dict(
        report_id=uuid4(),
        alert_id=uuid4(),
        generated_at=datetime.now(timezone.utc),
        alert_summary="Repeated SSH login failures from an external IP against a single host.",
        risk_assessment=RiskAssessment(severity=Severity.MEDIUM, confidence=Confidence.HIGH, rationale="3 failed logins in 5 minutes from an unrecognised IP."),
        model_metadata=ModelMetadata(model_name="qwen2.5-7b-instruct", model_version="q4_0", prompt_version="v1"),
    )
    defaults.update(overrides)
    return Report(**defaults)


def test_enrichment_result_requires_score_in_range():
    result = EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.SUSPICIOUS,
        score=42.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    assert result.raw_response == {}
    with pytest.raises(ValidationError):
        EnrichmentResult(
            indicator_type=IndicatorType.IP,
            indicator_value="203.0.113.5",
            provider_id="abuseipdb",
            queried_at=datetime.now(timezone.utc),
            verdict=EnrichmentVerdict.SUSPICIOUS,
            score=142.0,
            cache_expires_at=datetime.now(timezone.utc),
        )


def test_report_defaults():
    report = _make_report()
    assert report.status == ReportStatus.DRAFT
    assert report.investigation_timeline == []
    assert report.enrichment_findings == []
    assert report.recommended_actions_freeform_experimental is None
    assert report.uncertainty_notes == ""


def test_report_triage_experimental_fields_default_to_none():
    report = _make_report()
    assert report.triage_verdict_experimental is None
    assert report.triage_rationale_experimental is None


def test_report_command_analysis_defaults_to_none():
    report = _make_report()
    assert report.command_analysis is None


def test_report_accepts_command_analysis():
    analysis = CommandDecodeResult(
        command_line="powershell.exe -enc AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami")],
    )
    report = _make_report(command_analysis=analysis)
    assert report.command_analysis.decoded_segments[0].decoded == "whoami"


def test_report_accepts_nested_investigation_step_and_enrichment_finding():
    step = InvestigationStep(
        step_name="correlate",
        action="run_canonical_searches",
        output_summary="12 related alerts found for this src_ip in 24h",
        timestamp=datetime.now(timezone.utc),
    )
    finding = EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.SUSPICIOUS,
        score=42.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    report = _make_report(investigation_timeline=[step], enrichment_findings=[finding])
    assert report.investigation_timeline[0].step_name == "correlate"
    assert report.enrichment_findings[0].verdict == EnrichmentVerdict.SUSPICIOUS
