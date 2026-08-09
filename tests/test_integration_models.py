from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.schemas import AgentRef, Alert


def _make_alert(**overrides):
    defaults = dict(
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
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_search_query_accepts_valid_operators():
    for operator in ("eq", "contains", "range", "terms"):
        query = SearchQuery(field="rule.level", operator=operator, value=5)
        assert query.operator == operator


def test_search_query_rejects_invalid_operator():
    with pytest.raises(ValidationError):
        SearchQuery(field="rule.level", operator="fuzzy", value=5)


def test_search_result_holds_alerts_and_total_count():
    alert = _make_alert()
    result = SearchResult(alerts=[alert], total_count=42)
    assert result.alerts[0].rule_id == "5710"
    assert result.total_count == 42


def test_agent_context_requires_core_fields_optional_os_fields():
    context = AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active")
    assert context.os_platform is None
    assert context.last_keep_alive is None


def test_rule_metadata_mitre_is_flat_string_list():
    metadata = RuleMetadata(
        rule_id="5710",
        description="sshd: Attempt to login using a non-existent user",
        level=5,
        groups=["authentication_failed"],
        mitre_technique_ids=["T1110"],
    )
    assert metadata.mitre_technique_ids == ["T1110"]


def test_rule_metadata_defaults_groups_and_mitre_to_empty_list():
    metadata = RuleMetadata(rule_id="5710", description="x", level=5)
    assert metadata.groups == []
    assert metadata.mitre_technique_ids == []
