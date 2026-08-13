import re

from pydantic import ValidationError

from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, Indicator, URLIndicator
from app.schemas import Alert

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")

_VALIDATORS = (IPIndicator, HashIndicator, DomainIndicator, URLIndicator)


def extract_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in (_URL_RE, _IPV4_RE, _HASH_RE, _DOMAIN_RE):
        candidates.extend(pattern.findall(text))
    return candidates


def extract_and_validate(alert: Alert, extra_texts: list[str] | None = None) -> tuple[list[Indicator], int, int]:
    text_sources = [alert.full_log] + [v for v in alert.data.values() if isinstance(v, str)] + list(extra_texts or [])
    raw_candidates: list[str] = []
    for text in text_sources:
        raw_candidates.extend(extract_candidates(text))

    seen: set[tuple[type, str]] = set()
    validated: list[Indicator] = []
    for candidate in raw_candidates:
        for indicator_cls in _VALIDATORS:
            try:
                indicator = indicator_cls(value=candidate)
            except ValidationError:
                continue
            key = (type(indicator), indicator.value)
            if key not in seen:
                seen.add(key)
                validated.append(indicator)
            break
    return validated, len(raw_candidates), len(validated)
