class EnrichmentError(Exception):
    def __init__(self, kind: str, message: str):
        # "rate_limited" | "auth_failed" | "not_found" | "timeout"
        # | "network_error" | "http_error" | "bad_response"
        self.kind = kind
        super().__init__(message)
