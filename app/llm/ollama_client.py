import openai
import pydantic
from openai import OpenAI

from app.llm.client import T
from app.llm.errors import LLMClientError

_RETRY_NOTE = (
    "\n\nYour previous response did not match the required format. "
    "Previous response: {previous!r}\n\n"
    "Please respond again with valid JSON matching the required schema."
)


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_seconds: float = 120.0,
        reasoning_effort: str | None = None,
    ) -> None:
        # max_retries=0: the SDK otherwise retries a timeout twice on its own, so one
        # slow call costs 3x timeout_seconds of wall clock while this class believes it
        # made a single attempt. Retry-on-invalid-schema is handled in
        # generate_structured; a local Ollama on localhost does not need transport retries.
        self._client = OpenAI(
            base_url=base_url, api_key="ollama", timeout=timeout_seconds, max_retries=0
        )
        self._model = model
        # Left unset by default so each model keeps its own default. For reasoning
        # models this dominates latency far more than throughput does: gpt-oss:20b
        # emits 428 characters of reasoning at "low" against 3698 at "high" on the
        # same prompt, and qwen3.5:9b spends 98% of its output reasoning. Ollama
        # honours it on the OpenAI-compatible endpoint; there is no Modelfile
        # equivalent (both `think` and `reasoning_effort` are rejected as unknown
        # parameters), so it has to be sent per request.
        self._reasoning_effort = reasoning_effort
        self._last_raw_content: str | None = None

    def generate_structured(self, prompt: str, schema: type[T]) -> T:
        result = self._attempt(prompt, schema)
        if result is not None:
            return result

        retry_prompt = prompt + _RETRY_NOTE.format(previous=self._last_raw_content)
        result = self._attempt(retry_prompt, schema)
        if result is not None:
            return result

        raise LLMClientError("validation_failed", "schema validation failed after one retry")

    def _attempt(self, prompt: str, schema: type[T]) -> T | None:
        try:
            completion = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format=schema,
                temperature=0,
                **({"reasoning_effort": self._reasoning_effort} if self._reasoning_effort else {}),
            )
        except openai.LengthFinishReasonError:
            self._last_raw_content = "(truncated — response exceeded the token limit)"
            return None
        except pydantic.ValidationError as exc:
            # This installed openai SDK version raises ValidationError directly from
            # .parse() for any content that fails schema validation (invalid JSON
            # syntax, or valid JSON missing required fields) rather than swallowing
            # it into message.parsed=None — treat it as a non-conforming attempt.
            self._last_raw_content = f"(response did not match the required schema: {exc})"
            return None
        # Order matters below: each subclass must be caught before its parent —
        # APITimeoutError < APIConnectionError, NotFoundError < APIStatusError,
        # and OpenAIError last as the catch-all for the rest of the SDK hierarchy.
        except openai.APITimeoutError as exc:
            raise LLMClientError("timeout", str(exc)) from exc
        except openai.APIConnectionError as exc:
            raise LLMClientError("unreachable", str(exc)) from exc
        except openai.NotFoundError as exc:
            raise LLMClientError("model_not_found", str(exc)) from exc
        except openai.APIStatusError as exc:
            raise LLMClientError("generation_failed", f"HTTP {exc.status_code}: {exc}") from exc
        except openai.OpenAIError as exc:
            raise LLMClientError("generation_failed", str(exc)) from exc

        message = completion.choices[0].message
        if message.refusal is not None:
            raise LLMClientError("generation_failed", f"model refused: {message.refusal}")
        if message.parsed is not None:
            return message.parsed
        self._last_raw_content = message.content
        return None

    def health_check(self) -> bool:
        try:
            self._client.models.list()
            return True
        except openai.OpenAIError:
            return False

    def model_available(self) -> bool:
        try:
            models = self._client.models.list()
        except openai.OpenAIError:
            return False
        return any(model.id == self._model for model in models.data)
