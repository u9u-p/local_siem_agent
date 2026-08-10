import httpx
import respx
from openai import OpenAI


@respx.mock
def test_respx_intercepts_openai_sdk_chat_completions_call():
    respx.post("https://fake-ollama.test/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "qwen3.5:9b",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hello"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )
    )
    client = OpenAI(base_url="https://fake-ollama.test/v1", api_key="ollama")

    completion = client.chat.completions.create(
        model="qwen3.5:9b",
        messages=[{"role": "user", "content": "hi"}],
    )

    assert completion.choices[0].message.content == "hello"
