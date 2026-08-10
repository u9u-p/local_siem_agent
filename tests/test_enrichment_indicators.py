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


from app.enrichment.indicators import DomainIndicator, HashIndicator, URLIndicator


def test_accepts_valid_md5_sha1_sha256_hashes():
    assert HashIndicator(value="a" * 32).value == "a" * 32
    assert HashIndicator(value="a" * 40).value == "a" * 40
    assert HashIndicator(value="a" * 64).value == "a" * 64


def test_hash_indicator_lowercases_value():
    indicator = HashIndicator(value="A" * 32)
    assert indicator.value == "a" * 32
    assert indicator.indicator_type == IndicatorType.FILE_HASH


def test_rejects_wrong_length_hash():
    with pytest.raises(ValidationError):
        HashIndicator(value="a" * 31)


def test_rejects_non_hex_hash():
    with pytest.raises(ValidationError):
        HashIndicator(value="g" * 32)


def test_accepts_valid_domain():
    indicator = DomainIndicator(value="example.com")
    assert indicator.value == "example.com"
    assert indicator.indicator_type == IndicatorType.DOMAIN


def test_domain_indicator_lowercases_value():
    assert DomainIndicator(value="EXAMPLE.COM").value == "example.com"


def test_accepts_subdomain():
    assert DomainIndicator(value="sub.example.co.uk").value == "sub.example.co.uk"


def test_rejects_malformed_domain():
    with pytest.raises(ValidationError):
        DomainIndicator(value="not a domain!")


def test_rejects_domain_starting_with_hyphen():
    with pytest.raises(ValidationError):
        DomainIndicator(value="-example.com")


def test_rejects_domain_with_trailing_newline():
    with pytest.raises(ValidationError):
        DomainIndicator(value="example.com\n")


def test_accepts_valid_https_url():
    indicator = URLIndicator(value="https://example.com/path")
    assert indicator.value == "https://example.com/path"
    assert indicator.indicator_type == IndicatorType.URL


def test_accepts_valid_http_url():
    assert URLIndicator(value="http://example.com").value == "http://example.com"


def test_rejects_non_http_scheme():
    with pytest.raises(ValidationError):
        URLIndicator(value="ftp://example.com")


def test_rejects_url_without_host():
    with pytest.raises(ValidationError):
        URLIndicator(value="https://")


def test_rejects_url_with_embedded_newline():
    with pytest.raises(ValidationError):
        URLIndicator(value="https://exa\nmple.com/x")


def test_rejects_url_with_embedded_carriage_return():
    with pytest.raises(ValidationError):
        URLIndicator(value="https://example.com/a\r\nX-Evil: 1")
