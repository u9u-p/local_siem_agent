from app.llm.client import LLMCallRecord


class LLMClientError(Exception):
    def __init__(self, kind: str, message: str, call: LLMCallRecord | None = None):
        # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed" | "timeout"
        self.kind = kind
        # A failed call still costs wall-clock time and tokens; without this the most
        # expensive calls in a run (timeouts) would be the only ones never measured.
        self.call = call
        super().__init__(message)
