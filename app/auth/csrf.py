"""与当前会话绑定的 CSRF 校验。

- 令牌随会话创建/轮换而生成，因此天然不可跨会话复用。
- 缺失与错误给出不同 code（csrf_missing / csrf_invalid），原因可区分。
- 使用常量时间比较，避免时序侧信道。
"""
from __future__ import annotations

import hmac

from app.errors import csrf_invalid, csrf_missing
from app.models import SessionRecord

#: 状态变更请求提交 CSRF 令牌的请求头名称。
CSRF_HEADER = "X-CSRF-Token"


def require_csrf(session: SessionRecord, presented_token: str | None) -> None:
    if presented_token is None or presented_token == "":
        raise csrf_missing()
    if not hmac.compare_digest(session.csrf_token, presented_token):
        raise csrf_invalid()
