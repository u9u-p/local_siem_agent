class LLMClientError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed"
        super().__init__(message)
