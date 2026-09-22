"""口令散列与令牌生成工具。"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 120_000


def hash_password(password: str, *, salt: str | None = None) -> str:
    """PBKDF2-HMAC-SHA256 散列，格式：salt_hex$hash_hex。"""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS
    )
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """常数时间比较校验口令；格式异常时视为不匹配。"""
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hash_password(password, salt=salt)
    return hmac.compare_digest(candidate, stored)


def new_token() -> str:
    """生成 URL 安全的随机令牌（会话标识 / CSRF 令牌）。"""
    return secrets.token_urlsafe(32)
