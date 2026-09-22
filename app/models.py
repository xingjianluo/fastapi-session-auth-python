"""领域模型：账号、会话、防护记录。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


@dataclass
class Account:
    username: str
    password_hash: str
    roles: set[Role] = field(default_factory=set)


@dataclass
class SessionRecord:
    sid: str
    username: str
    csrf_token: str
    created_at: float
    expires_at: float
    revoked: bool = False


@dataclass
class FailureRecord:
    failures: int = 0
    locked_until: float = 0.0
