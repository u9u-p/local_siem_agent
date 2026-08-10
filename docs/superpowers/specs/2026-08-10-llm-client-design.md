# LLMClient (Phase 4a) Design

**Date:** 10 Aug 2026
**Parent design:** `CLAUDE.md` §1.4 (Agentic Analyst depends on an `LLMClient` Protocol), §4.2 (prompting/hallucination-mitigation rules), §6 (tech stack — Ollama, OpenAI-compatible API, JSON-schema-constrained output)
**Roadmap:** Phase 4a of the Agentic Analyst subsystem (see `ROADMAP.md`) — the first of 4 sub-phases, built before the state graph skeleton (4b) since even a stubbed skeleton needs this Protocol's real shape.
**Depends on:** nothing else in the codebase (self-contained).

---

## Context

CLAUDE.md names Ollama as the LLM backend and calls out its "OpenAI-compatible API, native JSON-schema-constrained output" as part of the rationale (§6). This document works out the concrete `LLMClient` Protocol and its `OllamaClient` implementation, verified against Ollama's actual documented API (not assumed) — both its native `/api/generate` mechanism and its OpenAI-compatible `/v1/chat/completions` layer were researched; **the OpenAI-compatible path was chosen**, via the official `openai` Python SDK's `client.beta.chat.completions.parse()` helper, because it is Ollama's own documented and demonstrated pattern for exactly this use case (single prompt in, one validated Pydantic object out), and it directly matches CLAUDE.md §6's stated reason for choosing Ollama in the first place.

Decisions confirmed in brainstorming:

1. **No real Ollama instance available yet.** Build mock-first — the `openai` SDK is itself built on `httpx`, so `respx` can still intercept at the transport layer underneath it, same testing pattern as Enrichment/Integration. A skippable real-instance smoke test is included for whenever Ollama is actually running.
2. **Retry-once-on-validation-failure logic lives inside `OllamaClient`, generically** — not duplicated across the 6+ future state-graph call sites. Callers only supply their own step-specific safe default when catching the typed error after both attempts fail.
3. **Target model: `qwen3.5:9b`** (confirmed real and pullable — `ollama.com/library/qwen3.5:9b`, 9.65B params, Q4_K_M, 6.6GB). This **supersedes** CLAUDE.md §6's older Qwen2.5/Llama-3.1 recommendation, which predates this model's release; §6's table should be updated once this design is approved.
4. **File location:** `app/llm/` — a new top-level package parallel to `app/integration/`, `app/enrichment/`, `app/storage/`, signaling shared infrastructure rather than agent-specific code.

---

## 1. Researched Ollama API facts (cited, not assumed)

| Fact | Detail | Source |
|---|---|---|
| OpenAI-compat base URL | `http://localhost:11434/v1/` | docs.ollama.com/api/openai-compatibility |
| SDK pointing pattern | `OpenAI(base_url="http://localhost:11434/v1/", api_key="ollama")` — key is required by the SDK but ignored by Ollama | Ollama's own documented instruction, same page |
| Structured output support | `response_format` supported on `/v1/chat/completions`; Ollama's own blog features `client.beta.chat.completions.parse(response_format=SomePydanticModel)` as the recommended pattern | ollama.com/blog/structured-outputs |
| `.parse()` result shape | `completion.choices[0].message` has `.parsed` (the validated Pydantic instance, or `None`) and `.refusal` (a string if the model explicitly refused) | same, Ollama's own sample code |
| Known engine limitation | Recursive/self-referencing Pydantic models are not supported; deeply `$ref`-nested schemas have reported issues — keep schemas flat | github.com/ollama/ollama#7993 (native and compat paths equally affected) |
| Exception on truncation | `openai.LengthFinishReasonError` — generation was cut off (`finish_reason="length"`) before a complete object was produced | openai SDK exception hierarchy, demonstrated in Ollama's own sample |
| Connection failure | `openai.APIConnectionError` (Ollama daemon unreachable — no HTTP response at all) | openai SDK exception hierarchy |
| Model not found | `openai.NotFoundError` (HTTP 404 — model not pulled) | openai SDK exception hierarchy |
| No documented timeout guidance | Ollama documents `keep_alive` (how long a model stays loaded in memory) but no recommended client-side request timeout. **Gap, not an oversight** — pick a generous default (this design uses 120s) and revisit once real step prompts are measured against `qwen3.5:9b`. | absence confirmed across docs.ollama.com and github.com/ollama/ollama/blob/main/docs/api.md |

---

## 2. File Structure

```
app/llm/
  __init__.py
  errors.py          # LLMClientError(kind, message)
  client.py          # LLMClient Protocol
  ollama_client.py   # OllamaClient implementation
```

`app/config.py` gains three new `Settings` fields: `llm_base_url: str = "http://localhost:11434/v1/"`, `llm_model: str = "qwen3.5:9b"`, `llm_timeout_seconds: float = 120.0`.

New dependency: `openai` (the official Python SDK) — added to `pyproject.toml`'s main dependencies (not dev-only; `OllamaClient` is production code).

---

## 3. Typed Errors

```python
# app/llm/errors.py
class LLMClientError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed"
        super().__init__(message)
```

Same single-class-with-`kind`-discriminator shape as `EnrichmentError` (`app/enrichment/errors.py`) and `SIEMConnectorError` (`app/integration/errors.py`) — a convention this codebase has now established three times over; the Agentic Analyst's future call sites can rely on the same pattern from every module they depend on.

---

## 4. `LLMClient` Protocol

```python
# app/llm/client.py
from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
```

---

## 5. `OllamaClient`

```python
# app/llm/ollama_client.py (sketch — full code finalized in the implementation plan)
import openai
from openai import OpenAI
from pydantic import BaseModel

from app.llm.errors import LLMClientError

_RETRY_NOTE = "\n\nYour previous response did not match the required format. Previous response: {previous!r}\n\nPlease respond again with valid JSON matching the required schema."


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout_seconds: float = 120.0) -> None:
        self._client = OpenAI(base_url=base_url, api_key="ollama", timeout=timeout_seconds)
        self._model = model

    def generate_structured(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        result = self._attempt(prompt, schema)
        if result is not None:
            return result

        # retry once, with the previous (non-conforming) content appended for context
        retry_prompt = prompt + _RETRY_NOTE.format(previous=self._last_raw_content)
        result = self._attempt(retry_prompt, schema)
        if result is not None:
            return result

        raise LLMClientError("validation_failed", "schema validation failed after one retry")

    def _attempt(self, prompt: str, schema: type[BaseModel]) -> BaseModel | None:
        try:
            completion = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format=schema,
                temperature=0,
            )
        except openai.APIConnectionError as exc:
            raise LLMClientError("unreachable", str(exc)) from exc
        except openai.NotFoundError as exc:
            raise LLMClientError("model_not_found", str(exc)) from exc
        except openai.LengthFinishReasonError:
            self._last_raw_content = "(truncated — response exceeded the token limit)"
            return None

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
```

A refusal (`message.refusal` set) is treated as terminal, not retried — the model explicitly declined to answer, and retrying the identical prompt is unlikely to change that. Only "produced something, but it didn't parse/validate, or got truncated" triggers the one retry.

---

## 6. Testing

- **`OllamaClient` unit tests** (respx-mocked at the `httpx` transport layer, since `openai`'s SDK is itself `httpx`-based): success on first attempt; success on retry (first response non-conforming, second valid); both attempts fail → `LLMClientError("validation_failed")`; connection failure → `"unreachable"`; model not found → `"model_not_found"`; refusal → `"generation_failed"` without a retry attempt; truncation (`LengthFinishReasonError`) triggers the retry path.
- **`health_check()`**: `models.list()` succeeds → `True`; connection failure → `False`.
- **Real-instance smoke test** (`tests/test_ollama_client_live.py`, skippable): mirrors the Wazuh pattern — skips unless Ollama is actually reachable at `llm_base_url` (a cheap `health_check()`-style probe, not a full generation call, to decide skip/run) and `qwen3.5:9b` is pulled; if configured, exercises one real `generate_structured()` call against a small schema.

---

## Open Items for the Implementation Plan

1. The exact retry-prompt wording (`_RETRY_NOTE`) is a first draft — fine to refine during implementation/testing, not load-bearing for the design.
2. `respx`'s ability to intercept the `openai` SDK's internal `httpx` client should be confirmed with a real passing test early in the plan (first task), not assumed — this is a new integration point (SDK-wrapping-httpx) this codebase hasn't exercised before.
3. CLAUDE.md §6's model recommendation row should be updated to `qwen3.5:9b` once this design is approved — a small doc fix, bundled with this plan's first commit rather than a separate task.
