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
    # 空闲截止：每次受保护访问向后滑动（续期），不操作则自然到期。
    expires_at: float
    # 绝对截止：自本次登录（会话沿袭链起点）算起的硬上限，续期不得越过。
    absolute_expires_at: float = 0.0
    # 最近一次受保护活动时间（用于多端会话列表展示）。
    last_seen_at: float = 0.0
    # 创建/最近一次轮换时观察到的角色版本号。
    role_version: int = 0
