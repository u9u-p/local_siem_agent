import pytest
from pydantic import ValidationError

from app.enrichment.indicators import IPIndicator
from app.schemas import IndicatorType


def test_valid_ipv4_indicator():
    indicator = IPIndicator(value="192.168.1.1")
    assert indicator.value == "192.168.1.1"
    assert indicator.indicator_type == IndicatorType.IP


def test_rejects_non_numeric_value():
    with pytest.raises(ValidationError):
        IPIndicator(value="abc.def.ghi.jkl")


def test_rejects_too_few_octets():
    with pytest.raises(ValidationError):
        IPIndicator(value="1.2.3")


def test_rejects_out_of_range_octet():
    with pytest.raises(ValidationError):
        IPIndicator(value="256.1.1.1")


def test_rejects_trailing_newline():
    with pytest.raises(ValidationError):
        IPIndicator(value="192.168.1.1\n")


def test_rejects_leading_zero_octet():
    with pytest.raises(ValidationError):
        IPIndicator(value="01.02.03.04")


def test_rejects_empty_string():
    with pytest.raises(ValidationError):
        IPIndicator(value="")


def test_rejects_ipv6_address():
    with pytest.raises(ValidationError):
        IPIndicator(value="::1")
