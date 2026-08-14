from datetime import timedelta

from app.agent.schemas import SearchTemplate
from app.integration.models import SearchClause, SearchQuery
from app.schemas import Alert

CANONICAL_SEARCH_WINDOW = timedelta(hours=24)

# Attribute paths whose cardinality across a correlated set discriminates between
# pattern types a bare match count cannot — e.g. one source IP across many destination
# ports reads as scanning, while many attempts at one user on one host reads as brute force.
_CARDINALITY_FIELDS = {
    "source ips": "source_ip",
    "source users": "src_user",
    "destination hosts": "destination_ip",
    "destination ports": "destination_port",
    "target users": "dst_user",
}


def distinct_value_counts(alerts: list[Alert]) -> dict[str, int]:
    """Count distinct non-empty values per correlation-relevant field across `alerts`.

    Emptiness is truthiness, not `is not None`, so a decoder that emits `""` is treated as
    absent — matching `_lacks_typed_context`, which gates on the same fields. This also
    drops `destination_port == 0`, which is reserved and never a real destination.
    """
    return {
        label: len({value for a in alerts if (value := getattr(a, attr))})
        for label, attr in _CARDINALITY_FIELDS.items()
    }


def build_canonical_queries(alert: Alert) -> dict[SearchTemplate, SearchQuery | None]:
    window = (alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp)
    queries: dict[SearchTemplate, SearchQuery | None] = {}

    if alert.source_ip:
        queries[SearchTemplate.SAME_SRC_IP_24H] = SearchQuery(
            clauses=[SearchClause(field="data.srcip", operator="eq", value=alert.source_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_SRC_IP_24H] = None

    queries[SearchTemplate.SAME_RULE_ID_HOST] = SearchQuery(
        clauses=[
            SearchClause(field="rule.id", operator="eq", value=alert.rule_id),
            SearchClause(field="agent.id", operator="eq", value=alert.agent.id),
        ],
        time_range=window,
    )

    if alert.destination_ip:
        queries[SearchTemplate.SAME_DST_HOST] = SearchQuery(
            clauses=[SearchClause(field="data.dstip", operator="eq", value=alert.destination_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_DST_HOST] = None

    if alert.process and alert.process.command_line:
        queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = SearchQuery(
            clauses=[SearchClause(
                field="data.win.eventdata.commandLine", operator="eq", value=alert.process.command_line
            )],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = None

    return queries
