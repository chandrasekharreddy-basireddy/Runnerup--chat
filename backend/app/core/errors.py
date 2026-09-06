"""Error taxonomy.

Two rules encoded here:

1. Authorization failures return 404, not 403, for resources the caller cannot see.
   Telling someone "403 on conversation X" confirms conversation X exists, which is an
   enumeration oracle. They get the same answer as for a conversation that never existed.
2. Client-facing detail strings are stable machine codes with no internal specifics.
   The interesting context goes to the structured log under the request id.
"""
from fastapi import HTTPException, status


class AppError(HTTPException):
    code = "error"

    def __init__(self, detail: str | None = None, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail or self.code)


class NotAuthenticated(AppError):
    code = "not_authenticated"
    def __init__(self, detail=None):
        super().__init__(detail or self.code, status.HTTP_401_UNAUTHORIZED)


class PermissionDenied(AppError):
    """Use only when the caller is already known to see the resource."""
    code = "permission_denied"
    def __init__(self, detail=None):
        super().__init__(detail or self.code, status.HTTP_403_FORBIDDEN)


class NotVisible(AppError):
    """The caller may not know whether this exists. Indistinguishable from a 404."""
    code = "not_found"
    def __init__(self, detail=None):
        super().__init__(detail or self.code, status.HTTP_404_NOT_FOUND)


class ValidationFailed(AppError):
    code = "invalid_request"
    def __init__(self, detail=None):
        super().__init__(detail or self.code, status.HTTP_422_UNPROCESSABLE_ENTITY)


class RateLimited(AppError):
    code = "rate_limited"
    def __init__(self, retry_after: int = 60):
        super().__init__(self.code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.headers = {"Retry-After": str(retry_after)}


class AccountUnavailable(AppError):
    code = "account_unavailable"
    def __init__(self, detail=None):
        super().__init__(detail or self.code, status.HTTP_403_FORBIDDEN)
