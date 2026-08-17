from pydantic import BaseModel

from app.llm.client import LLMCallRecord, LLMClient, LLMResponse


class _EchoResult(BaseModel):
    text: str


class _FakeLLMClient:
    def __init__(self, available: bool = True):
        self._available = available

    def generate_structured(self, prompt, schema, prompt_ref):
        return LLMResponse(
            value=schema(text=prompt),
            call=LLMCallRecord(prompt_ref=prompt_ref, prompt=prompt, attempts=1, latency_ms=0),
        )

    def health_check(self) -> bool:
        return True

    def model_available(self) -> bool:
        return self._available

    def model_name(self) -> str:
        return "fake-model:test"


def test_fake_client_satisfies_llm_client_protocol():
    client: LLMClient = _FakeLLMClient()
    response = client.generate_structured("hello", _EchoResult, "stub_ref")
    assert response.value.text == "hello"
    assert response.call.prompt_ref == "stub_ref"
    assert client.health_check() is True
    assert client.model_available() is True
    assert isinstance(client, LLMClient)
