from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from app.integration.auth import BasicAuthStrategy, JWTBearerAuthStrategy
from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
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


class WazuhConnector:
    def __init__(
        self,
        indexer_url: str,
        indexer_username: str,
        indexer_password: str,
        manager_url: str,
        manager_username: str,
        manager_password: str,
        verify_ssl: bool = False,
    ) -> None:
        self._indexer_client = httpx.Client(base_url=indexer_url, verify=verify_ssl, timeout=10.0)
        self._indexer_auth = BasicAuthStrategy(indexer_username, indexer_password)
        self._manager_client = httpx.Client(base_url=manager_url, verify=verify_ssl, timeout=10.0)
        self._manager_auth = JWTBearerAuthStrategy(self._manager_client, manager_username, manager_password)

    def _manager_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = self._manager_auth.get_headers()
        response = self._manager_client.request(method, path, headers=headers, **kwargs)
        if response.status_code == 401:
            self._manager_auth.refresh()
            headers = self._manager_auth.get_headers()
            response = self._manager_client.request(method, path, headers=headers, **kwargs)
        return response

    def health_check(self) -> bool:
        try:
            indexer_response = self._indexer_client.get(
                "/_cluster/health", headers=self._indexer_auth.get_headers()
            )
            if indexer_response.status_code != 200:
                return False
            manager_response = self._manager_request("GET", "/agents", params={"limit": 1})
            return manager_response.status_code == 200
        except httpx.HTTPError:
            return False

    def pull_alerts(self, since: datetime, until: datetime | None = None, limit: int = 500) -> list[Alert]:
        must: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": since.isoformat()}}}]
        if until is not None:
            must[0]["range"]["timestamp"]["lte"] = until.isoformat()
        body = {"query": {"bool": {"filter": must}}, "size": limit}
        response = self._indexer_client.post(
            "/wazuh-alerts-*/_search", json=body, headers=self._indexer_auth.get_headers()
        )
        response.raise_for_status()
        hits = response.json()["hits"]["hits"]
        return [wazuh_source_to_alert(hit["_source"]) for hit in hits]

    def search(self, query: SearchQuery) -> SearchResult:
        operator_clause: dict[str, Any]
        if query.operator == "eq":
            operator_clause = {"term": {query.field: query.value}}
        elif query.operator == "contains":
            operator_clause = {"match": {query.field: query.value}}
        elif query.operator == "range":
            operator_clause = {"range": {query.field: query.value}}
        else:  # "terms"
            operator_clause = {"terms": {query.field: query.value}}

        filter_clauses: list[dict[str, Any]] = []
        if query.time_range is not None:
            since, until = query.time_range
            filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

        body = {"query": {"bool": {"must": [operator_clause], "filter": filter_clauses}}}
        response = self._indexer_client.post(
            "/wazuh-alerts-*/_search", json=body, headers=self._indexer_auth.get_headers()
        )
        response.raise_for_status()
        payload = response.json()
        alerts = [wazuh_source_to_alert(hit["_source"]) for hit in payload["hits"]["hits"]]
        return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])

    def get_agent_context(self, agent_id: str) -> AgentContext:
        response = self._manager_request("GET", "/agents", params={"agents_list": agent_id})
        response.raise_for_status()
        item = response.json()["data"]["affected_items"][0]
        os_info = item.get("os", {})
        return AgentContext(
            id=item["id"],
            name=item["name"],
            ip=item["ip"],
            os_platform=os_info.get("platform"),
            os_version=os_info.get("version"),
            agent_version=item.get("version"),
            status=item["status"],
            last_keep_alive=item.get("lastKeepAlive"),
        )

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        response = self._manager_request("GET", "/rules", params={"rule_ids": rule_id})
        response.raise_for_status()
        item = response.json()["data"]["affected_items"][0]
        return RuleMetadata(
            rule_id=str(item["id"]),
            description=item["description"],
            level=item["level"],
            groups=item.get("groups", []),
            mitre_technique_ids=item.get("mitre", []),
        )
