import pytest
from pydantic import BaseModel

from app.config import Settings
from app.llm.ollama_client import OllamaClient


class _SmokeTestSchema(BaseModel):
    answer: str


@pytest.fixture
def live_client():
    settings = Settings()
    client = OllamaClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    if not client.health_check():
        pytest.skip(f"Ollama not reachable at {settings.llm_base_url} — skipping live LLMClient test")
    if not client.model_available():
        pytest.skip(
            f"Ollama is reachable but model {settings.llm_model!r} is not pulled "
            "— skipping live LLMClient test"
        )
    return client


def test_live_generate_structured_returns_valid_object(live_client):
    response = live_client.generate_structured(
        "Respond with a JSON object containing one field, 'answer', set to the string 'ok'.",
        _SmokeTestSchema,
        "test_live_generate_structured_returns_valid_object",
    )

    assert isinstance(response.value, _SmokeTestSchema)
    assert isinstance(response.value.answer, str)
