"""统一的认证/授权失败原因定义（类型定义，骨架阶段）。"""
from __future__ import annotations

import enum


class Reason(str, enum.Enum):
    """可区分的失败原因码，用于日志与响应体。"""

    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    SOURCE_LOCKED = "source_locked"
    UNAUTHENTICATED = "unauthenticated"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    SESSION_NOT_FOUND = "session_not_found"
    FORBIDDEN = "forbidden"
    CSRF_MISSING = "csrf_missing"
    CSRF_INVALID = "csrf_invalid"
    CSRF_CROSS_SESSION = "csrf_cross_session"


class AuthError(Exception):
    """携带原因码与 HTTP 状态码的领域异常。"""

    def __init__(self, reason: Reason, status_code: int, detail: str = "") -> None:
        self.reason = reason
        self.status_code = status_code
        self.detail = detail or reason.value
        super().__init__(self.detail)
