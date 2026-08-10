from pydantic import BaseModel

from app.llm.client import LLMClient


class _EchoResult(BaseModel):
    text: str


class _FakeLLMClient:
    def generate_structured(self, prompt, schema):
        return schema(text=prompt)

    def health_check(self) -> bool:
        return True


def test_fake_client_satisfies_llm_client_protocol():
    client: LLMClient = _FakeLLMClient()
    result = client.generate_structured("hello", _EchoResult)
    assert result.text == "hello"
    assert client.health_check() is True
