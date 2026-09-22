"""统一错误类型。

每种安全结论对应一个稳定、可区分的 code，便于客户端与测试断言；
HTTP 状态码与 code 解耦：例如“未认证”与“权限不足”都是 403 系，
但 code 不同；账号/来源锁定使用 429 + 独立 code。
"""
from __future__ import annotations

#: 未认证（无有效会话）
NOT_AUTHENTICATED = "not_authenticated"
#: 权限不足（已认证但缺少所需权限）
FORBIDDEN = "forbidden"
#: 会话已撤销或已过期
SESSION_INVALID = "session_invalid"
#: CSRF 令牌缺失
CSRF_MISSING = "csrf_missing"
#: CSRF 令牌与会话不匹配 / 无效
CSRF_INVALID = "csrf_invalid"
#: 凭证错误
INVALID_CREDENTIALS = "invalid_credentials"
#: 账号维度失败次数过多，处于锁定期
ACCOUNT_LOCKED = "account_locked"
#: 来源维度失败次数过多，处于锁定期
SOURCE_LOCKED = "source_locked"
#: 资源不存在（越权时同样返回该结论以避免暴露资源是否存在）
NOT_FOUND = "not_found"
#: 请求参数错误
BAD_REQUEST = "bad_request"


class AuthError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def to_payload(self) -> dict[str, object]:
        return {"error": {"code": self.code, "message": self.message}}


def not_authenticated() -> AuthError:
    return AuthError(NOT_AUTHENTICATED, "authentication required", 401)


def forbidden() -> AuthError:
    return AuthError(FORBIDDEN, "permission denied", 403)


def session_invalid() -> AuthError:
    return AuthError(SESSION_INVALID, "session expired or revoked", 401)


def csrf_missing() -> AuthError:
    return AuthError(CSRF_MISSING, "CSRF token is required for state-changing requests", 403)


def csrf_invalid() -> AuthError:
    return AuthError(CSRF_INVALID, "CSRF token is invalid or bound to another session", 403)


def invalid_credentials() -> AuthError:
    return AuthError(INVALID_CREDENTIALS, "invalid username or password", 401)


def account_locked(retry_after: int) -> AuthError:
    return AuthError(
        ACCOUNT_LOCKED,
        f"account locked due to repeated failures; retry after {retry_after}s",
        429,
    )


def source_locked(retry_after: int) -> AuthError:
    return AuthError(
        SOURCE_LOCKED,
        f"source locked due to repeated failures; retry after {retry_after}s",
        429,
    )


def not_found() -> AuthError:
    return AuthError(NOT_FOUND, "resource not found", 404)


def bad_request(message: str) -> AuthError:
    return AuthError(BAD_REQUEST, message, 400)
