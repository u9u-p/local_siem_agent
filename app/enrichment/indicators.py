import ipaddress
import re
import urllib.parse

from pydantic import BaseModel, field_validator

from app.schemas import IndicatorType


class IPIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.IP
    value: str

    @field_validator("value")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        # ipaddress rejects leading zeros, trailing garbage/whitespace and wrong octet
        # counts, and returns a canonical string — important once indicator_value
        # becomes part of a cache key.
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError as exc:
            raise ValueError(f"not a valid IPv4 address: {v}") from exc


_HASH_PATTERNS = {
    32: re.compile(r"^[0-9a-fA-F]{32}$"),   # MD5
    40: re.compile(r"^[0-9a-fA-F]{40}$"),   # SHA1
    64: re.compile(r"^[0-9a-fA-F]{64}$"),   # SHA256
}

_DOMAIN_RE = re.compile(
    r"\A(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}\Z"
)


class HashIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.FILE_HASH
    value: str

    @field_validator("value")
    @classmethod
    def _validate_hash(cls, v: str) -> str:
        pattern = _HASH_PATTERNS.get(len(v))
        if pattern is None or not pattern.match(v):
            raise ValueError(f"not a valid MD5/SHA1/SHA256 hash: {v}")
        return v.lower()


class DomainIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.DOMAIN
    value: str

    @field_validator("value")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"not a valid domain name: {v}")
        return v.lower()


class URLIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.URL
    value: str

    @field_validator("value")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if any(c in v for c in "\t\r\n"):
            raise ValueError(f"URL contains control characters: {v!r}")
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"not a valid http(s) URL: {v}")
        return v


Indicator = IPIndicator | HashIndicator | DomainIndicator | URLIndicator
