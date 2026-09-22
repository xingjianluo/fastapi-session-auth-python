"""基于角色的访问控制。

- 默认拒绝：账号未显式具备的权限一律不放行。
- 权限在每次请求时从账号最新角色即时推导，角色变更后既有会话立即生效，
  不缓存、不沿用旧授权结果。
"""
from __future__ import annotations

from app.auth.security import ROLE_PERMISSIONS
from app.models import Account


def permissions_of(account: Account) -> frozenset[str]:
    perms: set[str] = set()
    for role in account.roles:
        perms.update(ROLE_PERMISSIONS.get(role, frozenset()))
    return frozenset(perms)


def has_permission(account: Account, permission: str) -> bool:
    return permission in permissions_of(account)
