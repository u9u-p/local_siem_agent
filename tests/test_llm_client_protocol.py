from pydantic import BaseModel

from app.llm.client import LLMClient


class _EchoResult(BaseModel):
    text: str


class _FakeLLMClient:
    def __init__(self, available: bool = True):
        self._available = available

    def generate_structured(self, prompt, schema):
        return schema(text=prompt)

    def health_check(self) -> bool:
        return True

    def model_available(self) -> bool:
        return self._available

    def model_name(self) -> str:
        return "fake-model:test"


def test_fake_client_satisfies_llm_client_protocol():
    client: LLMClient = _FakeLLMClient()
    result = client.generate_structured("hello", _EchoResult)
    assert result.text == "hello"
    assert client.health_check() is True
    assert client.model_available() is True
    assert isinstance(client, LLMClient)
