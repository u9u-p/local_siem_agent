import re

from pydantic import BaseModel, field_validator

from app.schemas import IndicatorType

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class IPIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.IP
    value: str

    @field_validator("value")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        if not _IPV4_RE.match(v):
            raise ValueError(f"not a valid IPv4 address: {v}")
        octets = v.split(".")
        if not all(0 <= int(o) <= 255 for o in octets):
            raise ValueError(f"not a valid IPv4 address: {v}")
        return v


Indicator = IPIndicator
