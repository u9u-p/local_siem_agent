import pytest

from app.llm.errors import LLMClientError


def test_llm_client_error_carries_kind_and_message():
    error = LLMClientError("unreachable", "connection refused")
    assert error.kind == "unreachable"
    assert str(error) == "connection refused"


def test_llm_client_error_is_an_exception():
    with pytest.raises(LLMClientError):
        raise LLMClientError("validation_failed", "schema validation failed after one retry")
