class SIEMConnectorError(Exception):
    def __init__(self, kind: str, message: str):
        # "not_found" | "unreachable" | "auth_failed" | "bad_response"
        self.kind = kind
        super().__init__(message)
