import json

import httpx
import pytest
import respx
from pydantic import BaseModel

from app.llm.client import LLMClient
from app.llm.errors import LLMClientError
from app.llm.ollama_client import OllamaClient

BASE_URL = "https://fake-ollama.test/v1/"


class Verdict(BaseModel):
    label: str
    confidence: str


def _chat_completion_response(parsed_content: str, finish_reason: str = "stop") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "qwen3.5:9b",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": parsed_content, "refusal": None},
                    "finish_reason": finish_reason,
                }
            ],
        },
    )


def test_ollama_client_satisfies_llm_client_protocol():
    assert isinstance(OllamaClient(base_url=BASE_URL, model="qwen3.5:9b"), LLMClient)


@respx.mock
def test_generate_structured_returns_parsed_object_on_first_attempt():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "malicious"
    assert result.confidence == "high"


@respx.mock
def test_generate_structured_retries_once_after_non_conforming_first_attempt():
    route = respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("not valid json at all"),
            _chat_completion_response('{"label": "clean", "confidence": "low"}'),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "clean"
    assert route.call_count == 2


@respx.mock
def test_retry_prompt_carries_original_prompt_and_the_validation_error():
    route = respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response('{"label": "malicious"}'),
            _chat_completion_response('{"label": "clean", "confidence": "low"}'),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    client.generate_structured("classify this alert", Verdict)

    assert route.call_count == 2
    retry_body = json.loads(route.calls[1].request.content)
    retry_prompt = retry_body["messages"][0]["content"]
    assert "classify this alert" in retry_prompt
    assert "did not match the required schema" in retry_prompt
    # The actual pydantic failure detail must reach the model, not just a placeholder.
    assert "confidence" in retry_prompt.split("classify this alert", 1)[1]


@respx.mock
def test_generate_structured_raises_validation_failed_after_retry_also_fails():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response("still not valid json")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "validation_failed"


@respx.mock
def test_generate_structured_retries_after_truncation():
    call_count = {"n": 0}

    def _side_effect(request):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _chat_completion_response("", finish_reason="length")
        return _chat_completion_response('{"label": "clean", "confidence": "low"}')

    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=_side_effect)
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "clean"
    assert call_count["n"] == 2


def _refusal_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-2",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "qwen3.5:9b",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": None, "refusal": "I cannot help with that."},
                    "finish_reason": "stop",
                }
            ],
        },
    )


@respx.mock
def test_generate_structured_raises_unreachable_on_connection_error():
    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "unreachable"


@respx.mock
def test_generate_structured_raises_model_not_found_on_404():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=httpx.Response(404, json={"error": {"message": "model 'qwen3.5:9b' not found"}})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "model_not_found"


@respx.mock
def test_generate_structured_raises_generation_failed_on_server_error():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=httpx.Response(500, json={"error": {"message": "internal server error"}})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "generation_failed"
    assert "500" in str(exc_info.value)


@respx.mock
def test_generate_structured_raises_timeout_on_client_timeout():
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=httpx.ReadTimeout("timed out waiting for the model")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "timeout"


@respx.mock
def test_generate_structured_raises_generation_failed_on_refusal_without_retry():
    route = respx.post(f"{BASE_URL}chat/completions").mock(return_value=_refusal_response())
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "generation_failed"
    assert route.call_count == 1


@respx.mock
def test_health_check_returns_true_when_models_list_succeeds():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(200, json={"object": "list", "data": []})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.health_check() is True


@respx.mock
def test_health_check_returns_false_on_connection_error():
    respx.get(f"{BASE_URL}models").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.health_check() is False


@respx.mock
def test_model_available_returns_true_when_configured_model_is_pulled():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "qwen3.5:9b", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is True


@respx.mock
def test_model_available_returns_false_when_configured_model_is_not_pulled():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "llama3:8b", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is False


@respx.mock
def test_model_available_returns_false_on_connection_error():
    respx.get(f"{BASE_URL}models").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is False
