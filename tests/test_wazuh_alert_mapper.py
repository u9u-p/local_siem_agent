from app.integration.wazuh_connector import wazuh_source_to_alert

# Verbatim example alert from docs.wazuh.com/current/user-manual/ruleset/mitre.html,
# confirming the rule.mitre.{tactic,id,technique} parallel-array shape.
MITRE_EXAMPLE_SOURCE = {
    "agent": {"ip": "172.20.10.3", "name": "Windows11", "id": "002"},
    "manager": {"name": "wazuh-server"},
    "data": {},
    "rule": {
        "firedtimes": 4,
        "mail": False,
        "level": 10,
        "description": "PsExec service running as NT AUTHORITY\\SYSTEM has been created on Windows11",
        "groups": ["windows", "sysmon"],
        "mitre": {
            "technique": ["Windows Service"],
            "id": ["T1543.003"],
            "tactic": ["Persistence", "Privilege Escalation"],
        },
        "id": "110011",
    },
    "location": "EventChannel",
    "decoder": {"name": "windows_eventchannel"},
    "id": "1694607138.3688437",
    "timestamp": "2023-10-16T12:12:18.684+0000",
}

# A syslog/sshd-shaped alert with no MITRE mapping and populated network/user fields.
SYSLOG_EXAMPLE_SOURCE = {
    "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
    "manager": {"name": "wazuh-manager"},
    "data": {"srcip": "203.0.113.5", "srcport": "61658", "srcuser": "root"},
    "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["authentication_failed", "syslog"],
        "id": "5710",
    },
    "location": "/var/log/auth.log",
    "full_log": "Jul 12 15:32:41 ip-10-0-1-175 sshd[21746]: Invalid user admin from 203.0.113.5 port 61658 ssh2",
    "id": "1699999999.123456",
    "timestamp": "2026-08-10T09:00:00.000+0000",
}


def test_maps_mitre_parallel_arrays_into_mitre_ref_list():
    alert = wazuh_source_to_alert(MITRE_EXAMPLE_SOURCE)

    assert alert.source_alert_id == "1694607138.3688437"
    assert alert.rule_id == "110011"
    assert alert.rule_level == 10
    assert alert.agent.id == "002"
    assert alert.agent.name == "Windows11"
    assert alert.mitre is not None
    assert len(alert.mitre) == 1
    # tactic is an independent, non-parallel list (all tactics the rule maps to), so
    # every tactic is attached to each technique rather than being zipped positionally
    assert alert.mitre[0].tactic == "Persistence, Privilege Escalation"
    assert alert.mitre[0].technique_id == "T1543.003"
    assert alert.mitre[0].technique_name == "Windows Service"


def test_maps_syslog_alert_with_no_mitre_and_network_fields():
    alert = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert alert.source_alert_id == "1699999999.123456"
    assert alert.rule_id == "5710"
    assert alert.mitre is None
    assert alert.source_ip == "203.0.113.5"
    assert alert.source_port == 61658
    assert alert.src_user == "root"
    assert alert.destination_ip is None
    assert alert.full_log.startswith("Jul 12 15:32:41")
    assert alert.manager_name == "wazuh-manager"
    assert alert.source_system == "wazuh"


def test_mapper_generates_a_fresh_alert_id_and_ingested_at_each_call():
    first = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)
    second = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert first.alert_id != second.alert_id
    assert first.raw_json == SYSLOG_EXAMPLE_SOURCE
