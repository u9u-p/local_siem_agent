import pytest
from pydantic import ValidationError

from app.schemas import (
    AgentRef,
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
