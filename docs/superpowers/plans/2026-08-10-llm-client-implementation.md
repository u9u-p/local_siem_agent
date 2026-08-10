# LLMClient (Phase 4a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `LLMClient` Protocol and its `OllamaClient` implementation — the foundational infrastructure Phase 4b's state-graph skeleton and every later LLM-calling step depend on. Single prompt in, one validated Pydantic object out, with a generic retry-once-on-validation-failure and a typed error boundary.

**Architecture:** `OllamaClient` wraps the official `openai` Python SDK pointed at Ollama's OpenAI-compatible endpoint (`http://localhost:11434/v1/`), using `client.beta.chat.completions.parse(response_format=schema)` — Ollama's own documented pattern for Pydantic-in/Pydantic-out. A refusal is terminal (no retry); a non-conforming or truncated response triggers exactly one retry with the previous content appended for context; if that also fails, a typed `LLMClientError("validation_failed", ...)` is raised. Connection and model-not-found failures map to their own `kind`s. This mirrors the `EnrichmentError`/`SIEMConnectorError` convention already used twice in this codebase.

**Tech Stack:** Python 3.11+, `openai` SDK (new), `respx` (existing, verified to intercept the SDK's underlying `httpx` transport — proven in Task 1 before anything else depends on it).

## Global Constraints

- Python >= 3.11 (existing project constraint).
- New dependency: `openai` (production, not dev-only — `OllamaClient` is production code). Exact version range decided in Task 1.
- No new Ollama instance is available in this environment — every unit test is `respx`-mocked; the one real-instance test is skippable and must not block or hang when Ollama isn't reachable.
- Target model is `qwen3.5:9b` (confirmed real and pullable, per the design spec) — this supersedes CLAUDE.md §6/§8's older Qwen2.5/Llama-3.1 recommendation; Task 2 updates those three references so CLAUDE.md doesn't drift from what's actually built.
- Retry-once-on-validation-failure logic lives generically inside `OllamaClient` — never duplicated per call site.
- A model refusal (`message.refusal` set) is terminal — never retried.
- Recursive/self-referencing Pydantic schemas are unsupported by Ollama's structured-output engine (a known limitation, not a bug to work around in code) — keep this plan's own test schemas flat, and note it for future call sites.
- TDD: every method/model gets a failing test before implementation.
- Commit after each task.

---

### Task 1: Add `openai` dependency and verify respx can intercept its HTTP calls

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/test_openai_sdk_respx_integration.py`

**Interfaces:**
- Produces: confirmation (via a real passing test) that `respx.mock` intercepts HTTP calls made by the `openai` SDK — a risk item the design spec explicitly flagged as needing verification, not assumption, before any later task builds on it.

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, change:

```toml
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlalchemy>=2.0,<3",  # imported directly for IntegrityError; also a sqlmodel dep
    "sqlmodel>=0.0.16,<0.1",
    "httpx>=0.27,<1",
]
```

to:

```toml
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlalchemy>=2.0,<3",  # imported directly for IntegrityError; also a sqlmodel dep
    "sqlmodel>=0.0.16,<0.1",
    "httpx>=0.27,<1",
    "openai>=1.50,<2",
]
```

- [ ] **Step 2: Install**

```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

- [ ] **Step 3: Write the spike test**

```python
# tests/test_openai_sdk_respx_integration.py
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
```

- [ ] **Step 4: Run and confirm it passes**

```bash
pytest tests/test_openai_sdk_respx_integration.py -v
```

Expected: PASS (1 test). If this fails, STOP — this is a foundational assumption every later task in this plan depends on; do not proceed until it's resolved (e.g. respx version compatibility with the `openai` SDK's HTTP client construction).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/test_openai_sdk_respx_integration.py
git commit -m "chore: add openai dependency, verify respx intercepts its HTTP calls"
```

---

### Task 2: LLM config settings + update CLAUDE.md's model recommendation

**Files:**
- Modify: `app/config.py`
- Modify: `.env.example`
- Modify: `tests/test_config.py`
- Modify: `CLAUDE.md`

**Interfaces:**
- Produces: `Settings.llm_base_url: str = "http://localhost:11434/v1/"`, `.llm_model: str = "qwen3.5:9b"`, `.llm_timeout_seconds: float = 120.0` — consumed by Task 5 (`OllamaClient` construction) and Task 9 (real-instance smoke test).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_settings_llm_fields_have_expected_defaults():
    settings = Settings(_env_file=None)
    assert settings.llm_base_url == "http://localhost:11434/v1/"
    assert settings.llm_model == "qwen3.5:9b"
    assert settings.llm_timeout_seconds == 120.0


def test_settings_llm_fields_env_override(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:9999/v1/")
    monkeypatch.setenv("LLM_MODEL", "some-other-model:latest")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "30")
    settings = Settings(_env_file=None)
    assert settings.llm_base_url == "http://localhost:9999/v1/"
    assert settings.llm_model == "some-other-model:latest"
    assert settings.llm_timeout_seconds == 30.0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_config.py -v
```

Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'llm_base_url'`

- [ ] **Step 3: Write minimal implementation**

In `app/config.py`, change:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_manager_url: str | None = None
    wazuh_manager_username: str | None = None
    wazuh_manager_password: str | None = None
    wazuh_verify_ssl: bool = False
```

to:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_manager_url: str | None = None
    wazuh_manager_username: str | None = None
    wazuh_manager_password: str | None = None
    wazuh_verify_ssl: bool = False
    llm_base_url: str = "http://localhost:11434/v1/"
    llm_model: str = "qwen3.5:9b"
    llm_timeout_seconds: float = 120.0
```

In `.env.example`, change:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
ABUSEIPDB_API_KEY=
WAZUH_INDEXER_URL=
WAZUH_INDEXER_USERNAME=
WAZUH_INDEXER_PASSWORD=
WAZUH_MANAGER_URL=
WAZUH_MANAGER_USERNAME=
WAZUH_MANAGER_PASSWORD=
WAZUH_VERIFY_SSL=false
```

to:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
ABUSEIPDB_API_KEY=
WAZUH_INDEXER_URL=
WAZUH_INDEXER_USERNAME=
WAZUH_INDEXER_PASSWORD=
WAZUH_MANAGER_URL=
WAZUH_MANAGER_USERNAME=
WAZUH_MANAGER_PASSWORD=
WAZUH_VERIFY_SSL=false
LLM_BASE_URL=http://localhost:11434/v1/
LLM_MODEL=qwen3.5:9b
LLM_TIMEOUT_SECONDS=120
```

In `CLAUDE.md`, update the three references to the superseded model recommendation:

Change (§6 Tech Stack Recommendation table):
```
| Model | Qwen2.5-7B/14B-Instruct or Llama-3.1-8B-Instruct, Q4/Q5 quantised | strong structured-output/instruction-following at a size that leaves headroom in 24GB unified memory; left as a recommendation since the requirements doc leaves it undecided — validate against actual step prompts (§4) during implementation |
```
to:
```
| Model | `qwen3.5:9b` (Q4_K_M) | Confirmed pullable via Ollama's library; chosen as the Phase 4a implementation target — see `docs/superpowers/specs/2026-08-10-llm-client-design.md`. Supersedes the original Qwen2.5/Llama-3.1 recommendation, which predates this model's release |
```

Change (§4.2 rule 6):
```
6. **Model/context sizing.** With 6–7 calls per alert, each bounded to structured JSON rather than raw logs or transcripts, the 7B end of the §6 recommendation (Qwen2.5-7B-Instruct, Q4/Q5) should hold up for most steps; reserve 14B as a fallback specifically for Risk Assessment and Draft-A if 7B's classification accuracy or prose grounding proves weak in testing. Small, bounded prompts also keep per-call latency low enough that 6–7 sequential calls per alert stay practical on a single MacBook Pro without concurrent generation.
```
to:
```
6. **Model/context sizing.** With 6–7 calls per alert, each bounded to structured JSON rather than raw logs or transcripts, `qwen3.5:9b` (§6) should hold up for most steps; revisit model choice specifically for Risk Assessment and Draft-A if its classification accuracy or prose grounding proves weak in testing. Small, bounded prompts also keep per-call latency low enough that 6–7 sequential calls per alert stay practical on a single MacBook Pro without concurrent generation.
```

Change (§8 Open Questions and Assumptions):
```
- **LLM model** is a recommendation only (Qwen2.5/Llama-3.1 class, 7–14B, quantised) since the requirements doc leaves it undecided — validate against real step prompts (§4) during implementation.
```
to:
```
- **LLM model** is now decided: `qwen3.5:9b` (Q4_K_M), per Phase 4a's implementation — validate against real step prompts (§4) as later phases build them; revisit if classification accuracy or prose grounding proves weak.
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_config.py -v
```

Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add app/config.py .env.example tests/test_config.py CLAUDE.md
git commit -m "feat: add LLM connection settings, update CLAUDE.md model recommendation to qwen3.5:9b"
```

---

### Task 3: Typed LLMClientError

**Files:**
- Create: `app/llm/__init__.py`
- Create: `app/llm/errors.py`
- Test: `tests/test_llm_errors.py`

**Interfaces:**
- Produces: `LLMClientError(kind: str, message: str)` — consumed by Tasks 6, 7, 8.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_errors.py
import pytest

from app.llm.errors import LLMClientError


def test_llm_client_error_carries_kind_and_message():
    error = LLMClientError("unreachable", "connection refused")
    assert error.kind == "unreachable"
    assert str(error) == "connection refused"


def test_llm_client_error_is_an_exception():
    with pytest.raises(LLMClientError):
        raise LLMClientError("validation_failed", "schema validation failed after one retry")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p app/llm
touch app/llm/__init__.py
pytest tests/test_llm_errors.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.llm.errors'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/llm/errors.py
class LLMClientError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed"
        super().__init__(message)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_llm_errors.py -v
```

Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/llm/__init__.py app/llm/errors.py tests/test_llm_errors.py
git commit -m "feat: add typed LLMClientError"
```

---

### Task 4: `LLMClient` Protocol

**Files:**
- Create: `app/llm/client.py`
- Test: `tests/test_llm_client_protocol.py`

**Interfaces:**
- Produces: `LLMClient(Protocol)` with `generate_structured(prompt: str, schema: type[T]) -> T` and `health_check() -> bool` — the contract `OllamaClient` (Tasks 5-8) must satisfy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_client_protocol.py
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_llm_client_protocol.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.llm.client'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/llm/client.py
from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_llm_client_protocol.py -v
```

Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add app/llm/client.py tests/test_llm_client_protocol.py
git commit -m "feat: add LLMClient Protocol"
```

---

### Task 5: `OllamaClient` — construction and happy-path `generate_structured`

**Files:**
- Create: `app/llm/ollama_client.py`
- Test: `tests/test_ollama_client.py`

**Interfaces:**
- Consumes: `LLMClientError` (Task 3).
- Produces: `OllamaClient(base_url, model, timeout_seconds=120.0)` with `.generate_structured(prompt, schema)` implemented for the first-attempt-succeeds case (`.health_check()` and the retry/error paths raise `NotImplementedError` until Tasks 6-8) — consumed by Tasks 6-9.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ollama_client.py
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.llm.ollama_client'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/llm/ollama_client.py
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add app/llm/ollama_client.py tests/test_ollama_client.py
git commit -m "feat: implement OllamaClient construction and happy-path generate_structured"
```

---

### Task 6: `OllamaClient` — retry-once logic

**Files:**
- Modify: `app/llm/ollama_client.py`
- Modify: `tests/test_ollama_client.py`

**Interfaces:**
- Produces: verified retry-once behavior — a non-conforming or truncated first attempt triggers exactly one retry; both failing raises `LLMClientError("validation_failed", ...)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_ollama_client.py`:

```python
import openai


@respx.mock
def test_generate_structured_retries_once_after_non_conforming_first_attempt():
    route = respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("not valid json at all"),
            _chat_completion_response('{"label": "clean", "confidence": "low"}'),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "clean"
    assert route.call_count == 2


@respx.mock
def test_generate_structured_raises_validation_failed_after_retry_also_fails():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response("still not valid json")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "validation_failed"


@respx.mock
def test_generate_structured_retries_after_truncation():
    call_count = {"n": 0}

    def _side_effect(request):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _chat_completion_response("", finish_reason="length")
        return _chat_completion_response('{"label": "clean", "confidence": "low"}')

    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=_side_effect)
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    result = client.generate_structured("classify this", Verdict)

    assert result.label == "clean"
    assert call_count["n"] == 2
```

Add the necessary imports at the top of `tests/test_ollama_client.py`:

```python
import pytest

from app.llm.errors import LLMClientError
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: FAIL — `test_generate_structured_retries_once_after_non_conforming_first_attempt` fails because the SDK's `.parse()` raises a parsing/validation error on non-conforming JSON instead of the client catching it and retrying; `test_generate_structured_retries_after_truncation` fails because `openai.LengthFinishReasonError` is not yet caught.

- [ ] **Step 3: Write minimal implementation**

Replace `_attempt` in `app/llm/ollama_client.py`:

```python
    def _attempt(self, prompt: str, schema: type[BaseModel]) -> BaseModel | None:
        try:
            completion = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format=schema,
                temperature=0,
            )
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: PASS (4 tests). If `message.parsed` is not `None` for non-conforming JSON in your installed `openai` SDK version (i.e. the SDK silently coerces or the mocked response's `content` doesn't actually fail Pydantic validation the way expected), adjust the mocked JSON in `test_generate_structured_retries_once_after_non_conforming_first_attempt`/`test_generate_structured_raises_validation_failed_after_retry_also_fails` to a string that genuinely cannot parse as the `Verdict` schema (e.g. missing required fields), and re-verify.

- [ ] **Step 5: Commit**

```bash
git add app/llm/ollama_client.py tests/test_ollama_client.py
git commit -m "feat: add retry-once logic to OllamaClient.generate_structured"
```

---

### Task 7: `OllamaClient` — connection, model-not-found, and refusal error mapping

**Files:**
- Modify: `app/llm/ollama_client.py`
- Modify: `tests/test_ollama_client.py`

**Interfaces:**
- Produces: `openai.APIConnectionError` → `LLMClientError("unreachable", ...)`; `openai.NotFoundError` → `LLMClientError("model_not_found", ...)`; a model refusal → `LLMClientError("generation_failed", ...)` without retrying.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_ollama_client.py`:

```python
def _refusal_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-2",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "qwen3.5:9b",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": None, "refusal": "I cannot help with that."},
                    "finish_reason": "stop",
                }
            ],
        },
    )


@respx.mock
def test_generate_structured_raises_unreachable_on_connection_error():
    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "unreachable"


@respx.mock
def test_generate_structured_raises_model_not_found_on_404():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=httpx.Response(404, json={"error": {"message": "model 'qwen3.5:9b' not found"}})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "model_not_found"


@respx.mock
def test_generate_structured_raises_generation_failed_on_refusal_without_retry():
    route = respx.post(f"{BASE_URL}chat/completions").mock(return_value=_refusal_response())
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict)
    assert exc_info.value.kind == "generation_failed"
    assert route.call_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: FAIL — connection errors and 404s currently propagate as raw `openai` exceptions instead of `LLMClientError`.

- [ ] **Step 3: Write minimal implementation**

Update the import line at the top of `app/llm/ollama_client.py` (it already imports `openai`, no change needed there), and wrap the `.parse()` call in `_attempt`:

```python
    def _attempt(self, prompt: str, schema: type[BaseModel]) -> BaseModel | None:
        try:
            completion = self._client.beta.chat.completions.parse(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                response_format=schema,
                temperature=0,
            )
        except openai.LengthFinishReasonError:
            self._last_raw_content = "(truncated — response exceeded the token limit)"
            return None
        except openai.APIConnectionError as exc:
            raise LLMClientError("unreachable", str(exc)) from exc
        except openai.NotFoundError as exc:
            raise LLMClientError("model_not_found", str(exc)) from exc

        message = completion.choices[0].message
        if message.refusal is not None:
            raise LLMClientError("generation_failed", f"model refused: {message.refusal}")
        if message.parsed is not None:
            return message.parsed
        self._last_raw_content = message.content
        return None
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/llm/ollama_client.py tests/test_ollama_client.py
git commit -m "feat: map connection/model-not-found/refusal errors to LLMClientError"
```

---

### Task 8: `OllamaClient.health_check`

**Files:**
- Modify: `app/llm/ollama_client.py`
- Modify: `tests/test_ollama_client.py`

**Interfaces:**
- Produces: `health_check()` fully implemented, completing the `LLMClient` Protocol contract.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_ollama_client.py`:

```python
@respx.mock
def test_health_check_returns_true_when_models_list_succeeds():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(200, json={"object": "list", "data": []})
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.health_check() is True


@respx.mock
def test_health_check_returns_false_on_connection_error():
    respx.get(f"{BASE_URL}models").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.health_check() is False
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: FAIL — `NotImplementedError: added in Task 8`

- [ ] **Step 3: Write minimal implementation**

Replace the `health_check` method body in `app/llm/ollama_client.py`:

```python
    def health_check(self) -> bool:
        try:
            self._client.models.list()
            return True
        except openai.OpenAIError:
            return False
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ollama_client.py -v
```

Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add app/llm/ollama_client.py tests/test_ollama_client.py
git commit -m "feat: implement OllamaClient.health_check"
```

---

### Task 9: Real-instance smoke test

**Files:**
- Create: `tests/test_ollama_client_live.py`

**Interfaces:**
- Consumes: `Settings` (Task 2), `OllamaClient` (Tasks 5-8) — no new production code, this task only adds a skippable test file.

- [ ] **Step 1: Write the test**

```python
# tests/test_ollama_client_live.py
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
    return client


def test_live_generate_structured_returns_valid_object(live_client):
    result = live_client.generate_structured(
        "Respond with a JSON object containing one field, 'answer', set to the string 'ok'.",
        _SmokeTestSchema,
    )

    assert isinstance(result, _SmokeTestSchema)
    assert isinstance(result.answer, str)
```

- [ ] **Step 2: Run the full test suite**

```bash
source .venv/bin/activate
pytest -v
```

Expected: `test_live_generate_structured_returns_valid_object` SKIPPED unless Ollama is actually running at `llm_base_url` with `qwen3.5:9b` pulled; every other test in the repo (Foundation + Enrichment + Integration + this plan's Tasks 1-8) PASSES.

- [ ] **Step 3: Commit**

```bash
git add tests/test_ollama_client_live.py
git commit -m "test: add skippable real-instance smoke test for OllamaClient"
```
