class LLMClientError(Exception):
    def __init__(self, kind: str, message: str):
        # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed" | "timeout"
        self.kind = kind
        super().__init__(message)
