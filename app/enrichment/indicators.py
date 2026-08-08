import ipaddress

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


Indicator = IPIndicator
