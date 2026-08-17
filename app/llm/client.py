from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMCallRecord(BaseModel):
    """One `generate_structured` call, not one HTTP attempt.

    The schema retry means a single logical call can hit the model twice; token counts
    and latency are summed across attempts so a report's totals match what the machine
    actually spent.
    """

    prompt_ref: str
    prompt: str
    retried: bool = False
    # Only populated when an attempt failed to parse — on a clean first attempt the
    # parsed object is the faithful record and the raw text adds nothing.
    raw_response: str | None = None
    # The last attempt's reasoning trace. Measured on gemma4:12b, this is the bulk of
    # what the model generates and `usage` does not count a token of it: 1,608
    # characters of reasoning were reported as 18 completion tokens. Kept for the
    # last attempt only — a failed attempt's reasoning led to output already preserved
    # in raw_response.
    reasoning: str | None = None
    parsed_output: dict[str, Any] | None = None
    attempts: int
    # None when the backend does not report usage; never 0, which would read as
    # "measured, and it was free".
    prompt_tokens: int | None = None
    # Counts the structured content only, NOT the reasoning trace. Not a cost or
    # throughput figure — use latency_ms for that.
    completion_tokens: int | None = None
    latency_ms: int
    error_kind: str | None = None


class LLMResponse(BaseModel, Generic[T]):
    value: T
    call: LLMCallRecord


@runtime_checkable
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]: ...
    def health_check(self) -> bool: ...
    def model_available(self) -> bool: ...
    # A method rather than an attribute, matching the rest of this Protocol and
    # keeping isinstance() checks against it well-defined.
    def model_name(self) -> str: ...
