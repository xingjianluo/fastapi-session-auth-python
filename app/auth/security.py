"""密码哈希、会话/令牌随机标识生成、种子账号与角色权限表。"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from app.config import Settings
from app.models import Account, Role

#: 角色 -> 权限集合；默认拒绝，未列出的权限一律不放行。
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset(
        {
            "resource:read",
            "resource:write",
            "admin:users",
        }
    ),
    Role.EDITOR: frozenset(
        {
            "resource:read",
            "resource:write",
        }
    ),
    Role.VIEWER: frozenset(
        {
            "resource:read",
        }
    ),
}


def _pbkdf2(password: str, salt: bytes, settings: Settings) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, settings.pbkdf2_iterations
    )


def hash_password(password: str, settings: Settings) -> str:
    salt = os.urandom(16)
    digest = _pbkdf2(password, salt, settings)
    return f"pbkdf2_sha256${settings.pbkdf2_iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, account: Account, settings: Settings) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = account.password_hash.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    expected = bytes.fromhex(digest_hex)
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        int(iterations),
    )
    return hmac.compare_digest(expected, candidate)


def new_session_id(settings: Settings) -> str:
    return secrets.token_urlsafe(settings.session_id_bytes)


def new_csrf_token(settings: Settings) -> str:
    return secrets.token_urlsafe(settings.csrf_token_bytes)


def seed_accounts(settings: Settings) -> dict[str, Account]:
    """本地演示账号：admin / editor / viewer，密码与用户名相同。"""
    seeds = {
        "admin": {Role.ADMIN},
        "editor": {Role.EDITOR},
        "viewer": {Role.VIEWER},
    }
    accounts: dict[str, Account] = {}
    for username, roles in seeds.items():
        accounts[username] = Account(
            username=username,
            password_hash=hash_password(username, settings),
            roles=set(roles),
        )
    return accounts
