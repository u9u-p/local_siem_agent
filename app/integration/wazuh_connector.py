from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas import AgentRef, Alert, MitreRef


def wazuh_source_to_alert(source: dict[str, Any]) -> Alert:
    rule = source.get("rule", {})
    mitre_raw = rule.get("mitre") or {}
    mitre = [
        MitreRef(tactic=tactic, technique_id=technique_id, technique_name=technique_name)
        for tactic, technique_id, technique_name in zip(
            mitre_raw.get("tactic", []), mitre_raw.get("id", []), mitre_raw.get("technique", [])
        )
    ] or None

    agent = source.get("agent", {})
    data = source.get("data", {})

    return Alert(
        alert_id=uuid4(),
        source_alert_id=source["id"],
        source_system="wazuh",
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description", ""),
        rule_level=rule.get("level", 0),
        rule_groups=rule.get("groups", []),
        mitre=mitre,
        timestamp=datetime.fromisoformat(source["timestamp"]),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id=agent.get("id", ""), name=agent.get("name", ""), ip=agent.get("ip", "")),
        manager_name=source.get("manager", {}).get("name", ""),
        location=source.get("location", ""),
        full_log=source.get("full_log", ""),
        source_ip=data.get("srcip"),
        source_port=int(data["srcport"]) if data.get("srcport") else None,
        destination_ip=data.get("dstip"),
        destination_port=int(data["dstport"]) if data.get("dstport") else None,
        src_user=data.get("srcuser"),
        dst_user=data.get("dstuser"),
        data=data,
        raw_json=source,
    )
