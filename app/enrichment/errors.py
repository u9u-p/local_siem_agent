class EnrichmentError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "rate_limited" | "auth_failed" | "not_found" | "timeout"
        super().__init__(message)
