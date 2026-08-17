import time
from dataclasses import dataclass

import openai
import pydantic
from openai import OpenAI
from openai.types.completion_usage import CompletionUsage

from app.llm.client import LLMCallRecord, LLMResponse, T
from app.llm.errors import LLMClientError

_RETRY_NOTE = (
    "\n\nYour previous response did not match the required format. "
    "Previous response: {previous!r}\n\n"
    "Please respond again with valid JSON matching the required schema."
)


@dataclass
class _CallTally:
    """What accumulated across the attempts of one logical call."""

    attempts: int = 0
    prompt_tokens: int | None = 0
    completion_tokens: int | None = 0
    # Last attempt wins: on a retry the earlier trace led to output that failed
    # validation, and that output is already kept in raw_response.
    reasoning: str | None = None
    # The most recent attempt's non-conforming raw output, if any. Lives on the
    # tally rather than the client: one OllamaClient instance is reused across a
    # whole investigation's seven calls, and instance-level state here previously
    # let one call's discarded output get stamped onto a later, unrelated call's
    # failure record as if it were that call's own.
    raw_content: str | None = None

    def add_usage(self, usage) -> None:
        # One attempt without usage poisons the total: a sum missing an unknown term is
        # not a smaller sum, it is an unknown sum.
        if usage is None:
            self.prompt_tokens = None
            self.completion_tokens = None
            return
        if self.prompt_tokens is not None:
            self.prompt_tokens += usage.prompt_tokens
            self.completion_tokens += usage.completion_tokens


def _as_llm_client_error(exc: openai.OpenAIError) -> LLMClientError:
    """Map an openai SDK exception to the LLMClientError kind it represents.

    Shared by both exception sites in `_attempt` — the HTTP round-trip and the
    content parse — so the subclass-before-parent ordering lives in exactly one
    place and cannot drift between the two call sites: APITimeoutError <
    APIConnectionError, NotFoundError < APIStatusError, and OpenAIError last as the
    catch-all for the rest of the SDK hierarchy. That catch-all is also what covers
    ContentFilterFinishReasonError and APIResponseValidationError — both raised from
    the content-parse step, both subclasses of OpenAIError, neither warranting a
    dedicated LLMClientError kind of its own.
    """
    if isinstance(exc, openai.APITimeoutError):
        return LLMClientError("timeout", str(exc))
    if isinstance(exc, openai.APIConnectionError):
        return LLMClientError("unreachable", str(exc))
    if isinstance(exc, openai.NotFoundError):
        return LLMClientError("model_not_found", str(exc))
    if isinstance(exc, openai.APIStatusError):
        return LLMClientError("generation_failed", f"HTTP {exc.status_code}: {exc}")
    return LLMClientError("generation_failed", str(exc))


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

    def generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]:
        started = time.monotonic()
        tally = _CallTally()
        try:
            result = self._attempt(prompt, schema, tally)
            if result is not None:
                return LLMResponse(
                    value=result,
                    call=self._record(prompt_ref, prompt, tally, started, parsed=result),
                )

            first_bad = tally.raw_content
            retry_prompt = prompt + _RETRY_NOTE.format(previous=first_bad)
            result = self._attempt(retry_prompt, schema, tally)
            if result is not None:
                return LLMResponse(
                    value=result,
                    call=self._record(
                        prompt_ref, prompt, tally, started, parsed=result, raw_response=first_bad
                    ),
                )
            raise LLMClientError("validation_failed", "schema validation failed after one retry")
        except LLMClientError as exc:
            # Every raise site funnels through here, so no failure path can escape
            # unmeasured — including the validation_failed raised just above. Reading
            # tally.raw_content (not client state) means a failure here can only ever
            # carry this call's own attempts, never a previous call's leftovers.
            if exc.call is None:
                exc.call = self._record(
                    prompt_ref, prompt, tally, started,
                    raw_response=tally.raw_content, error_kind=exc.kind,
                )
            raise

    def _record(
        self, prompt_ref: str, prompt: str, tally: _CallTally, started: float,
        parsed=None, raw_response: str | None = None, error_kind: str | None = None,
    ) -> LLMCallRecord:
        return LLMCallRecord(
            prompt_ref=prompt_ref,
            prompt=prompt,
            retried=tally.attempts > 1,
            raw_response=raw_response,
            reasoning=tally.reasoning,
            parsed_output=parsed.model_dump(mode="json") if parsed is not None else None,
            attempts=tally.attempts,
            prompt_tokens=tally.prompt_tokens,
            completion_tokens=tally.completion_tokens,
            latency_ms=int((time.monotonic() - started) * 1000),
            error_kind=error_kind,
        )

    def _attempt(self, prompt: str, schema: type[T], tally: _CallTally) -> T | None:
        tally.attempts += 1
        try:
            # with_raw_response defers schema validation: it hands back the raw HTTP
            # response before attempting to parse `content` against `schema`. That
            # matters because .parse() validates content and raises pydantic.ValidationError
            # from deep inside the SDK for a non-conforming response, discarding the
            # completion object (usage included) before we ever see it — which would make
            # every attempt that fails schema validation invisible to token accounting,
            # even though it consumed the model's output and cost real tokens.
            raw = self._client.beta.chat.completions.with_raw_response.parse(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format=schema,
                temperature=0,
                **({"reasoning_effort": self._reasoning_effort} if self._reasoning_effort else {}),
            )
        except openai.OpenAIError as exc:
            raise _as_llm_client_error(exc) from exc

        usage_data = raw.http_response.json().get("usage")
        tally.add_usage(CompletionUsage.model_validate(usage_data) if usage_data else None)

        try:
            completion = raw.parse()
        except openai.LengthFinishReasonError:
            tally.raw_content = "(truncated — response exceeded the token limit)"
            return None
        except pydantic.ValidationError as exc:
            # This installed openai SDK version raises ValidationError directly from
            # .parse() for any content that fails schema validation (invalid JSON
            # syntax, or valid JSON missing required fields) rather than swallowing
            # it into message.parsed=None — treat it as a non-conforming attempt.
            tally.raw_content = f"(response did not match the required schema: {exc})"
            return None
        except openai.OpenAIError as exc:
            # Covers ContentFilterFinishReasonError and APIResponseValidationError
            # among others — unlike the two soft failures above, these are not
            # "retry with a hint" cases, so this raises (hard failure) rather than
            # returning None.
            raise _as_llm_client_error(exc) from exc

        message = completion.choices[0].message
        # Ollama returns the reasoning trace as a non-standard field, so the SDK parks
        # it in model_extra rather than a typed attribute. Read both: a future SDK that
        # types it would otherwise silently stop being captured.
        tally.reasoning = getattr(message, "reasoning", None) or (message.model_extra or {}).get("reasoning")
        if message.refusal is not None:
            raise LLMClientError("generation_failed", f"model refused: {message.refusal}")
        if message.parsed is not None:
            return message.parsed
        tally.raw_content = message.content
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
        # Ollama resolves a bare repository name to its :latest tag — `ollama run
        # mistral-small3.2` works — but lists it as "mistral-small3.2:latest". Exact
        # matching therefore reported every untagged name as unavailable, which runs
        # the whole pipeline as stubs and marks each report NEEDS_HUMAN_REVIEW with
        # nothing naming the cause. Resolve the same way Ollama does, and no further:
        # gemma4:12b must still not be satisfied by gemma4:latest.
        wanted = self._model if ":" in self._model else f"{self._model}:latest"
        return any(model.id == wanted for model in models.data)

    def model_name(self) -> str:
        return self._model
