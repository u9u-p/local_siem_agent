import openai
from openai import OpenAI
from pydantic import BaseModel

from app.llm.errors import LLMClientError

_RETRY_NOTE = (
    "\n\nYour previous response did not match the required format. "
    "Previous response: {previous!r}\n\n"
    "Please respond again with valid JSON matching the required schema."
)


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout_seconds: float = 120.0) -> None:
        self._client = OpenAI(base_url=base_url, api_key="ollama", timeout=timeout_seconds)
        self._model = model
        self._last_raw_content: str | None = None

    def generate_structured(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        result = self._attempt(prompt, schema)
        if result is not None:
            return result

        retry_prompt = prompt + _RETRY_NOTE.format(previous=self._last_raw_content)
        result = self._attempt(retry_prompt, schema)
        if result is not None:
            return result

        raise LLMClientError("validation_failed", "schema validation failed after one retry")

    def _attempt(self, prompt: str, schema: type[BaseModel]) -> BaseModel | None:
        completion = self._client.beta.chat.completions.parse(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            response_format=schema,
            temperature=0,
        )
        message = completion.choices[0].message
        if message.parsed is not None:
            return message.parsed
        self._last_raw_content = message.content
        return None

    def health_check(self) -> bool:
        raise NotImplementedError("added in Task 8")
