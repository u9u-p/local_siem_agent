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


def _chat_completion_response(
    parsed_content: str,
    finish_reason: str = "stop",
    prompt_tokens: int = 120,
    completion_tokens: int = 40,
    include_usage: bool = True,
    reasoning: str | None = None,
) -> httpx.Response:
    message = {"role": "assistant", "content": parsed_content, "refusal": None}
    if reasoning is not None:
        # Ollama returns the reasoning trace as a non-standard sibling of `content`;
        # the OpenAI SDK surfaces it through model_extra rather than a typed field.
        message["reasoning"] = reasoning
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "qwen3.5:9b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }
    if include_usage:
        body["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    return httpx.Response(200, json=body)


def test_ollama_client_satisfies_llm_client_protocol():
    assert isinstance(OllamaClient(base_url=BASE_URL, model="qwen3.5:9b"), LLMClient)


@respx.mock
def test_generate_structured_returns_parsed_object_on_first_attempt():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict, "build_test_prompt").value

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

    result = client.generate_structured("classify this", Verdict, "build_test_prompt").value

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

    client.generate_structured("classify this alert", Verdict, "build_test_prompt")

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
        client.generate_structured("classify this", Verdict, "build_test_prompt")
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

    result = client.generate_structured("classify this", Verdict, "build_test_prompt").value

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
        client.generate_structured("classify this", Verdict, "build_test_prompt")
    assert exc_info.value.kind == "unreachable"


@respx.mock
def test_generate_structured_raises_model_not_found_on_404():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=httpx.Response(404, json={"error": {"message": "model 'qwen3.5:9b' not found"}})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")
    assert exc_info.value.kind == "model_not_found"


@respx.mock
def test_generate_structured_raises_generation_failed_on_server_error():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=httpx.Response(500, json={"error": {"message": "internal server error"}})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")
    assert exc_info.value.kind == "generation_failed"
    assert "500" in str(exc_info.value)


@respx.mock
def test_generate_structured_raises_timeout_on_client_timeout():
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=httpx.ReadTimeout("timed out waiting for the model")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")
    assert exc_info.value.kind == "timeout"


@respx.mock
def test_generate_structured_raises_generation_failed_on_refusal_without_retry():
    route = respx.post(f"{BASE_URL}chat/completions").mock(return_value=_refusal_response())
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")
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


@respx.mock
def test_reasoning_effort_is_omitted_when_not_configured():
    """Default must stay unset: sending an effort the server does not recognise, or
    overriding a model's own default, would silently change every candidate's
    behaviour in the benchmark."""
    route = respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "benign", "confidence": "low"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert "reasoning_effort" not in json.loads(route.calls[0].request.content)


@respx.mock
def test_reasoning_effort_is_sent_when_configured():
    """Reasoning length, not throughput, dominates wall clock for reasoning models —
    gpt-oss:20b emits 428 characters of reasoning at low against 3698 at high — so
    the benchmark axis is (model x reasoning effort)."""
    route = respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "benign", "confidence": "low"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="gpt-oss:20b", reasoning_effort="low")

    client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert json.loads(route.calls[0].request.content)["reasoning_effort"] == "low"


@respx.mock
def test_model_available_resolves_an_untagged_name_to_latest():
    """`ollama run mistral-small3.2` works, but the API lists it as
    `mistral-small3.2:latest`. Exact matching made model_available() false for every
    untagged name, which runs the whole pipeline as stubs and marks each report
    NEEDS_HUMAN_REVIEW without anything naming the cause."""
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "mistral-small3.2:latest", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="mistral-small3.2")

    assert client.model_available() is True


@respx.mock
def test_model_available_does_not_match_a_different_tag_of_the_same_model():
    """Resolving bare names must not degrade into matching on the repository alone:
    gemma4:12b and gemma4:latest are different models with different footprints."""
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "gemma4:latest", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="gemma4:12b")

    assert client.model_available() is False


@respx.mock
def test_generate_structured_returns_response_with_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    response = client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert response.value.label == "malicious"
    call = response.call
    assert call.prompt_ref == "build_test_prompt"
    assert call.prompt == "classify this"
    assert call.attempts == 1
    assert call.retried is False
    assert call.raw_response is None
    assert call.parsed_output == {"label": "malicious", "confidence": "high"}
    assert call.prompt_tokens == 120
    assert call.completion_tokens == 40
    assert call.error_kind is None
    assert call.latency_ms >= 0


@respx.mock
def test_call_record_reports_none_tokens_when_backend_omits_usage():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response(
            '{"label": "clean", "confidence": "low"}', include_usage=False
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.prompt_tokens is None
    assert call.completion_tokens is None
    # The rest of the record is unaffected by a backend that does not report usage.
    assert call.attempts == 1
    assert call.parsed_output == {"label": "clean", "confidence": "low"}


@respx.mock
def test_call_record_captures_the_reasoning_trace():
    """completion_tokens counts the JSON only; the reasoning is where the output went.

    Measured on gemma4:12b: 1,608 characters of reasoning reported as 18 completion
    tokens. Without this the record would claim a 40-token call that in fact generated
    several hundred tokens' worth of text.
    """
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response(
            '{"label": "malicious", "confidence": "high"}',
            reasoning="The source IP appears in three prior alerts, so this is not isolated.",
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.reasoning == "The source IP appears in three prior alerts, so this is not isolated."


@respx.mock
def test_call_record_reasoning_is_none_for_a_model_that_does_not_emit_one():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "clean", "confidence": "low"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.reasoning is None


@respx.mock
def test_call_record_sums_tokens_across_the_retry_and_keeps_the_bad_response():
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("not valid json at all", prompt_tokens=100, completion_tokens=10),
            _chat_completion_response(
                '{"label": "malicious", "confidence": "high"}', prompt_tokens=150, completion_tokens=30
            ),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.attempts == 2
    assert call.retried is True
    # The prompt stored is the original; the retry prompt is that text plus a fixed suffix.
    assert call.prompt == "classify this"
    assert "not valid json at all" in call.raw_response
    assert call.prompt_tokens == 250
    assert call.completion_tokens == 40


@respx.mock
def test_timeout_error_carries_a_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=httpx.TimeoutException("too slow"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    call = exc_info.value.call
    assert call is not None
    assert call.error_kind == "timeout"
    assert call.prompt_ref == "build_test_prompt"
    assert call.prompt == "classify this"
    assert call.attempts == 1
    assert call.parsed_output is None
    assert call.latency_ms >= 0


@respx.mock
def test_validation_failure_after_retry_carries_a_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response("still not json")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    call = exc_info.value.call
    assert call is not None
    assert call.error_kind == "validation_failed"
    assert call.attempts == 2
    assert call.retried is True
    assert call.prompt_tokens == 240  # 120 per attempt, both attempts reached the model


def _content_filter_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "qwen3.5:9b",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": None, "refusal": None},
                "finish_reason": "content_filter",
            }],
            "usage": {"prompt_tokens": 9, "completion_tokens": 1, "total_tokens": 10},
        },
    )


@respx.mock
def test_content_filter_error_becomes_llm_client_error_with_a_record():
    """openai.ContentFilterFinishReasonError is raised from raw.parse() (the content
    step), not the HTTP round-trip — it must still be caught and mapped, and it must
    still carry a record, exactly like every other failure path.

    Unlike LengthFinishReasonError/pydantic.ValidationError (which return None and
    let generate_structured retry once), this is not a "retry with a hint" case, so
    it raises immediately: one attempt, no retry.
    """
    respx.post(f"{BASE_URL}chat/completions").mock(return_value=_content_filter_response())
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert exc_info.value.kind == "generation_failed"
    call = exc_info.value.call
    assert call is not None
    assert call.prompt_ref == "build_test_prompt"
    assert call.error_kind == "generation_failed"
    assert call.attempts == 1
    assert call.retried is False
    # Usage is read before the content parse is attempted, so even this hard failure
    # is measured rather than silently costing nothing.
    assert call.prompt_tokens == 9
    assert call.completion_tokens == 1


@respx.mock
def test_second_calls_failure_does_not_carry_first_calls_raw_response():
    """One OllamaClient instance serves every call of an investigation. A failure's
    raw_response must come from that call's own attempts only — never a previous,
    unrelated call's discarded output left over on shared client state."""
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("call A's bad output, attempt 1"),
            _chat_completion_response("call A's bad output, attempt 2"),
            httpx.TimeoutException("too slow"),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as first_exc_info:
        client.generate_structured("prompt A", Verdict, "call_a")
    assert first_exc_info.value.kind == "validation_failed"

    with pytest.raises(LLMClientError) as second_exc_info:
        client.generate_structured("prompt B", Verdict, "call_b")

    call = second_exc_info.value.call
    assert call is not None
    assert call.error_kind == "timeout"
    assert call.prompt_ref == "call_b"
    assert call.attempts == 1


def _malformed_usage_response(parsed_content: str) -> httpx.Response:
    """A body whose `usage` object fails `CompletionUsage.model_validate` — missing
    the required `completion_tokens`/`total_tokens` fields entirely."""
    message = {"role": "assistant", "content": parsed_content, "refusal": None}
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "qwen3.5:9b",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": "not-a-number"},
    }
    return httpx.Response(200, json=body)


@respx.mock
# The malformed usage block is the whole point of this test, and pydantic warns when the
# openai SDK serialises it. Filtered here rather than fixed, so `pytest -q` stays pristine.
@pytest.mark.filterwarnings("ignore::UserWarning")
def test_generate_structured_degrades_gracefully_when_usage_is_malformed():
    """A regression test: pre-branch code parsed a body with usage={"prompt_tokens": 5}
    fine. HEAD raises pydantic.ValidationError out of CompletionUsage.model_validate,
    which is neither an openai.OpenAIError nor an LLMClientError, so it escapes
    generate_structured entirely rather than degrading to an unmeasured call."""
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_malformed_usage_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    response = client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert response.value.label == "malicious"
    assert response.call.prompt_tokens is None
    assert response.call.completion_tokens is None


@respx.mock
def test_call_record_keeps_tokens_unmeasured_once_an_earlier_attempt_lacked_usage():
    """Mixed case for _CallTally.add_usage's `if self.prompt_tokens is not None` guard:
    attempt 1 has no usage (poisons the tally to None), attempt 2 (the retry) does
    report usage. The poisoned tally must stay None rather than the second attempt's
    real numbers overwriting it — a partial sum is not a smaller sum, it is unknown."""
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("not valid json at all", include_usage=False),
            _chat_completion_response(
                '{"label": "malicious", "confidence": "high"}', prompt_tokens=150, completion_tokens=30
            ),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.attempts == 2
    assert call.prompt_tokens is None
    assert call.completion_tokens is None


@respx.mock
def test_call_record_captures_reasoning_when_both_attempts_fail_to_parse():
    """The self-check call that forces a fallback default (both attempts fail) is
    exactly the call with the least other information recorded — raw_response only
    holds the second attempt's failure text, and prompt only the first attempt's
    text. Without reading reasoning from the raw body, this call carries no model
    output at all. reasoning must survive even though raw.parse() raises on every
    attempt."""
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response(
                "still not json", reasoning="First attempt's reasoning trace."
            ),
            _chat_completion_response(
                "still not json either", reasoning="Second attempt's reasoning trace."
            ),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    call = exc_info.value.call
    assert call is not None
    # Last attempt wins, per spec §1.1.
    assert call.reasoning == "Second attempt's reasoning trace."
