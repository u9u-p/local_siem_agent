import httpx
import respx
from pydantic import BaseModel

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


@respx.mock
def test_generate_structured_returns_parsed_object_on_first_attempt():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "malicious"
    assert result.confidence == "high"
