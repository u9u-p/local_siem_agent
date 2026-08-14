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

# A Sysmon Event ID 1 (process creation) alert, with an encoded PowerShell command line.
SYSMON_PROCESS_CREATION_SOURCE = {
    "agent": {"ip": "172.20.10.5", "name": "WIN-DESKTOP01", "id": "003"},
    "manager": {"name": "wazuh-manager"},
    "data": {
        "win": {
            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {
                "utcTime": "2026-08-13 10:15:00.000",
                "processId": "4820",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "parentProcessId": "3344",
                "parentImage": "C:\\Windows\\explorer.exe",
                "parentCommandLine": "C:\\Windows\\explorer.exe",
                "hashes": "MD5=44D88612FEA8A8F36DE82E1278ABB02F,SHA256=" + "a" * 64,
                "user": "WIN-DESKTOP01\\alice",
            },
        }
    },
    "rule": {
        "level": 12,
        "description": "Sysmon - Process creation via encoded PowerShell command",
        "groups": ["windows", "sysmon"],
        "id": "92009",
    },
    "location": "EventChannel",
    "full_log": "",
    "id": "1700000000.987654",
    "timestamp": "2026-08-13T10:15:00.000+0000",
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


def test_mapper_derives_a_stable_alert_id_from_the_source_alert_id():
    """alert_id is the alerts-table primary key, so re-pulling the same Wazuh alert
    must produce the same id for save_raw_alert to reject it as a duplicate."""
    first = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)
    second = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert first.alert_id == second.alert_id
    assert first.raw_json == SYSLOG_EXAMPLE_SOURCE


def test_different_source_alerts_get_different_ids():
    other = {**SYSLOG_EXAMPLE_SOURCE, "id": "1699999999.999999"}

    assert wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE).alert_id != wazuh_source_to_alert(other).alert_id


WINDOWS_LOGON_SOURCE = {
    "id": "1699999999.222222",
    "timestamp": "2026-07-31T06:12:09.000+08:00",
    "rule": {"id": "100061", "description": "Windows: successful logon", "level": 3, "groups": ["windows"]},
    "agent": {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1"},
    "manager": {"name": "wazuh-manager"},
    "location": "/var/ossec/logs/sample-logs/windows_security_fp.json",
    "full_log": "{}",
    "data": {
        "win": {
            "system": {"eventID": "4624", "providerName": "Microsoft-Windows-Security-Auditing"},
            "eventdata": {"targetUserName": "mrahman", "ipAddress": "100.72.44.19", "logonType": "3"},
        }
    },
}


def test_windows_logon_source_ip_falls_back_to_win_eventdata():
    """Windows events have no data.srcip; without the fallback source_ip is None and
    the SAME_SRC_IP_24H correlation is skipped for every 4624/4625."""
    alert = wazuh_source_to_alert(WINDOWS_LOGON_SOURCE)

    assert alert.source_ip == "100.72.44.19"


def test_explicit_srcip_wins_over_win_eventdata():
    source = {**WINDOWS_LOGON_SOURCE, "data": {**WINDOWS_LOGON_SOURCE["data"], "srcip": "10.0.0.1"}}

    assert wazuh_source_to_alert(source).source_ip == "10.0.0.1"


def test_source_ip_is_none_when_neither_field_present():
    source = {**WINDOWS_LOGON_SOURCE, "data": {}}

    assert wazuh_source_to_alert(source).source_ip is None


SYSMON_NETWORK_SOURCE = {
    "id": "1699999999.333333",
    "timestamp": "2026-07-30T09:16:44.112+00:00",
    "rule": {"id": "100074", "description": "Sysmon: PowerShell network connection", "level": 12, "groups": ["sysmon"]},
    "agent": {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1"},
    "manager": {"name": "wazuh-manager"},
    "location": "/var/ossec/logs/sample-logs/endpoint_alerts_sample.json",
    "full_log": "{}",
    "data": {
        "win": {
            "system": {"eventID": "3", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"destinationIp": "185.220.101.47", "destinationPort": "443"},
        }
    },
}


def test_sysmon_destination_falls_back_to_win_eventdata():
    """The TP chain pivots on the C2 address; without this the SAME_DST_HOST
    correlation is skipped for every Sysmon network-connection alert."""
    alert = wazuh_source_to_alert(SYSMON_NETWORK_SOURCE)

    assert alert.destination_ip == "185.220.101.47"
    assert alert.destination_port == 443


def test_maps_sysmon_process_creation_fields():
    alert = wazuh_source_to_alert(SYSMON_PROCESS_CREATION_SOURCE)

    assert alert.process is not None
    assert alert.process.command_line == "powershell.exe -EncodedCommand SQBFAFgA"
    assert alert.process.parent_command_line == "C:\\Windows\\explorer.exe"
    assert alert.process.process_name == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert alert.process.parent_process_name == "C:\\Windows\\explorer.exe"
    assert alert.process.process_id == "4820"
    assert alert.process.parent_process_id == "3344"
    assert alert.process.process_hashes == "MD5=44D88612FEA8A8F36DE82E1278ABB02F,SHA256=" + "a" * 64


def test_process_is_none_for_non_sysmon_alert():
    alert = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert alert.process is None
