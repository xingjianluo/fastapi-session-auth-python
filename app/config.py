"""全局配置（阈值、会话有效期等）。

可通过环境变量覆盖，便于测试锁定期自动恢复等场景。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Settings:
    session_ttl_seconds: int = 1800          # 会话有效期
    csrf_token_bytes: int = 32               # CSRF 令牌随机字节数
    session_id_bytes: int = 32               # 会话标识随机字节数
    max_failures: int = 5                    # 触发锁定的失败次数阈值
    lockout_seconds: int = 300               # 锁定期时长
    pbkdf2_iterations: int = 200_000         # PBKDF2 迭代次数


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def get_settings() -> Settings:
    defaults = Settings()
    overrides = {
        f.name: _env_int(f"AUTH_{f.name.upper()}", getattr(defaults, f.name))
        for f in fields(defaults)
    }
    return Settings(**overrides)
