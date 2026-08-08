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
