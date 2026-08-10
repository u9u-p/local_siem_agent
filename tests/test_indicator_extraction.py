from datetime import datetime, timezone
from uuid import uuid4

from app.agent.indicator_extraction import extract_and_validate, extract_candidates
from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, URLIndicator
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
        full_log="",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


_SAMPLE_LOG = (
    "Invalid user admin from 203.0.113.5 fetched "
    "http://malicious-example.test/payload.exe with sha256 "
    + ("a" * 64)
    + " referencing evil-domain.test seen also at 999.999.999.999"
)


def test_extract_candidates_finds_ip_hash_url_and_domain():
    candidates = extract_candidates(_SAMPLE_LOG)

    assert "203.0.113.5" in candidates
    assert "http://malicious-example.test/payload.exe" in candidates
    assert "a" * 64 in candidates
    assert "evil-domain.test" in candidates
    assert "999.999.999.999" in candidates


def test_extract_and_validate_discards_invalid_candidates_and_counts_correctly():
    alert = _make_alert(full_log=_SAMPLE_LOG)

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 6
    assert validated_count == 5
    values_by_type = {(type(i), i.value) for i in validated}
    assert (IPIndicator, "203.0.113.5") in values_by_type
    assert (HashIndicator, "a" * 64) in values_by_type
    assert (URLIndicator, "http://malicious-example.test/payload.exe") in values_by_type
    assert (DomainIndicator, "evil-domain.test") in values_by_type
    assert (DomainIndicator, "malicious-example.test") in values_by_type


def test_extract_and_validate_returns_empty_for_alert_with_no_indicators():
    alert = _make_alert(full_log="nothing interesting here")

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert validated == []
    assert candidate_count == 0
    assert validated_count == 0


def test_extract_and_validate_scans_string_values_in_data_field():
    alert = _make_alert(
        full_log="no indicators in the log line",
        data={"extra_ip": "198.51.100.7", "count": 3},
    )

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 1
    assert validated_count == 1
    assert validated[0].value == "198.51.100.7"


def test_extract_and_validate_deduplicates_identical_indicators():
    alert = _make_alert(full_log="203.0.113.5 contacted 203.0.113.5 again")

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 2
    assert validated_count == 1
    assert validated[0].value == "203.0.113.5"
