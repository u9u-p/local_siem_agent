from datetime import timedelta

from app.agent.schemas import SearchTemplate
from app.integration.models import SearchClause, SearchQuery
from app.schemas import Alert

CANONICAL_SEARCH_WINDOW = timedelta(hours=24)


def build_canonical_queries(alert: Alert) -> dict[SearchTemplate, SearchQuery | None]:
    window = (alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp)
    queries: dict[SearchTemplate, SearchQuery | None] = {}

    if alert.source_ip:
        queries[SearchTemplate.SAME_SRC_IP_24H] = SearchQuery(
            clauses=[SearchClause(field="source_ip", operator="eq", value=alert.source_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_SRC_IP_24H] = None

    queries[SearchTemplate.SAME_RULE_ID_HOST] = SearchQuery(
        clauses=[
            SearchClause(field="rule_id", operator="eq", value=alert.rule_id),
            SearchClause(field="agent.id", operator="eq", value=alert.agent.id),
        ],
        time_range=window,
    )

    if alert.destination_ip:
        queries[SearchTemplate.SAME_DST_HOST] = SearchQuery(
            clauses=[SearchClause(field="destination_ip", operator="eq", value=alert.destination_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_DST_HOST] = None

    return queries
