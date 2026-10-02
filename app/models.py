"""核心数据模型。"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class Role(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


@dataclass
class User:
    username: str
    password_hash: str
    role: Role = Role.USER
    # 角色版本号：每次权限变化 +1，用于触发既有会话的标识轮换。
    role_version: int = 0


@dataclass
class Session:
    session_id: str
    username: str
    csrf_token: str
    created_at: float
    expires_at: float
    # 创建/最近一次轮换时观察到的角色版本号。
    role_version: int = 0
    # 最近一次受保护访问时间（滑动续期的基准）。
    last_activity_at: float = 0.0
    # 从本次登录算起的绝对到期上限：滑动续期不得越过它。
    absolute_expires_at: float = 0.0
