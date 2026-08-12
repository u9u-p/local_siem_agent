import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from app.integration.auth import BasicAuthStrategy, JWTBearerAuthStrategy
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.schemas import AgentRef, Alert, MitreRef

logger = logging.getLogger(__name__)

# search() takes no size parameter (the SIEMConnector Protocol fixes its signature),
# so it uses the same default cap as pull_alerts' limit rather than OpenSearch's
# silent default of 10.
_SEARCH_DEFAULT_SIZE = 500

_INDEX_PATH = "/wazuh-alerts-*/_search"


def wazuh_source_to_alert(source: dict[str, Any]) -> Alert:
    rule = source.get("rule", {})
    mitre_raw = rule.get("mitre") or {}
    # rule.mitre.id and rule.mitre.technique are parallel (one entry per technique);
    # rule.mitre.tactic is an independent list — the union of all tactics the rule maps
    # to — so a specific tactic cannot be attributed to a specific technique from this
    # data. Zip only the genuinely parallel pair and attach every tactic to each ref.
    technique_ids = mitre_raw.get("id", [])
    technique_names = mitre_raw.get("technique", [])
    tactics_str = ", ".join(mitre_raw.get("tactic", []))
    mitre = [
        MitreRef(tactic=tactics_str, technique_id=technique_id, technique_name=technique_name)
        for technique_id, technique_name in zip(technique_ids, technique_names)
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


def _map_hits(hits: list[dict[str, Any]]) -> list[Alert]:
    """Map Indexer hits to Alerts, skipping (and logging) any malformed document.

    wazuh_source_to_alert is deliberately strict; degradation is handled here so one
    bad document cannot discard an entire batch.
    """
    alerts: list[Alert] = []
    for hit in hits:
        try:
            alerts.append(wazuh_source_to_alert(hit["_source"]))
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "skipping malformed Wazuh alert document (id=%r): %s",
                hit.get("_id") if isinstance(hit, dict) else None,
                exc,
            )
    return alerts


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

    # --- internal request helpers -------------------------------------------------

    def _manager_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            headers = self._manager_auth.get_headers()
            response = self._manager_client.request(method, path, headers=headers, **kwargs)
            if response.status_code == 401:
                self._manager_auth.refresh()
                headers = self._manager_auth.get_headers()
                response = self._manager_client.request(method, path, headers=headers, **kwargs)
        except httpx.RequestError as exc:
            raise SIEMConnectorError("unreachable", str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            # the token handshake in JWTBearerAuthStrategy.refresh() itself failed
            raise SIEMConnectorError("auth_failed", str(exc)) from exc
        except (ValueError, KeyError) as exc:
            # non-JSON or unexpectedly-shaped token response
            raise SIEMConnectorError("auth_failed", f"malformed authentication response: {exc}") from exc
        return response

    @staticmethod
    def _manager_payload(response: httpx.Response, description: str) -> dict[str, Any]:
        if response.status_code == 401:
            raise SIEMConnectorError(
                "auth_failed",
                f"{description} returned HTTP 401 after a token refresh and retry: {response.text[:200]}",
            )
        if not 200 <= response.status_code < 300:
            raise SIEMConnectorError(
                "bad_response", f"{description} returned HTTP {response.status_code}: {response.text[:200]}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise SIEMConnectorError("bad_response", f"{description} returned a non-JSON body: {exc}") from exc

    def _indexer_search(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._indexer_client.post(
                _INDEX_PATH, json=body, headers=self._indexer_auth.get_headers()
            )
        except httpx.RequestError as exc:
            raise SIEMConnectorError("unreachable", str(exc)) from exc
        if not 200 <= response.status_code < 300:
            raise SIEMConnectorError(
                "bad_response", f"indexer search returned HTTP {response.status_code}: {response.text[:200]}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise SIEMConnectorError("bad_response", f"indexer search returned a non-JSON body: {exc}") from exc

    # --- SIEMConnector surface ----------------------------------------------------

    def health_check(self) -> bool:
        try:
            indexer_response = self._indexer_client.get(
                "/_cluster/health", headers=self._indexer_auth.get_headers()
            )
            if indexer_response.status_code != 200:
                return False
            manager_response = self._manager_request("GET", "/agents", params={"limit": 1})
            return manager_response.status_code == 200
        except (SIEMConnectorError, httpx.HTTPError, ValueError, KeyError):
            return False

    def pull_alerts(self, since: datetime, until: datetime | None = None, limit: int = 500) -> list[Alert]:
        # UNVERIFIED against a live instance — see design spec §6; if this returns zero alerts unexpectedly, confirm the real field name first
        must: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": since.isoformat()}}}]
        if until is not None:
            must[0]["range"]["timestamp"]["lte"] = until.isoformat()
        body = {
            "query": {"bool": {"filter": must}},
            "size": limit,
            "sort": [{"timestamp": {"order": "asc"}}],
        }
        payload = self._indexer_search(body)
        return _map_hits(payload["hits"]["hits"])

    def search(self, query: SearchQuery) -> SearchResult:
        must_clauses: list[dict[str, Any]] = []
        for clause in query.clauses:
            if clause.operator == "eq":
                must_clauses.append({"term": {clause.field: clause.value}})
            elif clause.operator == "contains":
                must_clauses.append({"match": {clause.field: clause.value}})
            elif clause.operator == "range":
                must_clauses.append({"range": {clause.field: clause.value}})
            else:  # "terms"
                must_clauses.append({"terms": {clause.field: clause.value}})

        filter_clauses: list[dict[str, Any]] = []
        if query.time_range is not None:
            since, until = query.time_range
            # Confirmed against a live Wazuh 4.14.x instance during Phase 3 — "timestamp" is the real field name.
            filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

        body = {
            "query": {"bool": {"must": must_clauses, "filter": filter_clauses}},
            "size": _SEARCH_DEFAULT_SIZE,
        }
        payload = self._indexer_search(body)
        alerts = _map_hits(payload["hits"]["hits"])
        return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])

    def get_agent_context(self, agent_id: str) -> AgentContext:
        response = self._manager_request("GET", "/agents", params={"agents_list": agent_id})
        payload = self._manager_payload(response, f"agent lookup for {agent_id!r}")
        items = payload.get("data", {}).get("affected_items", [])
        if not items:
            # Wazuh answers an unknown agent with HTTP 200 and an empty affected_items
            raise SIEMConnectorError("not_found", f"agent {agent_id!r} not found")
        item = items[0]
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
        payload = self._manager_payload(response, f"rule lookup for {rule_id!r}")
        items = payload.get("data", {}).get("affected_items", [])
        if not items:
            # Wazuh answers an unknown rule with HTTP 200 and an empty affected_items
            raise SIEMConnectorError("not_found", f"rule {rule_id!r} not found")
        item = items[0]
        return RuleMetadata(
            rule_id=str(item["id"]),
            description=item["description"],
            level=item["level"],
            groups=item.get("groups", []),
            mitre_technique_ids=item.get("mitre", []),
        )
