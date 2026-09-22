# FastAPI 会话认证与授权

基于 FastAPI 的本地可运行会话认证 / 授权 / 防护演示。内存实现、线程安全，
所有失败结论在各入口下统一为 `{reason, detail}` 结构，可区分、可解释。

## 本地运行

```bash
uv sync
uv run fastapi dev main.py        # 或 uv run uvicorn main:app --reload
```

种子账号：`admin/admin-pass`（admin）、`alice/alice-pass`、`bob/bob-pass`（user）。

## 本地验证

```bash
uv run pytest            # 全部测试，实时打印关键状态与判定依据日志
```

手工验证示例：

```bash
# 登录（响应设置 session Cookie，并返回 csrf_token）
curl -i -c jar.txt -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'

# 受保护读取
curl -b jar.txt localhost:8000/auth/me

# 状态变更需携带 X-CSRF-Token（取登录响应中的 csrf_token）
curl -b jar.txt -X POST localhost:8000/auth/logout -H "X-CSRF-Token: <token>"
```

## 会话与令牌生命周期

1. **签发**：`POST /auth/login` 校验凭证后签发全新随机会话标识
   （HttpOnly Cookie）与独立的 CSRF 令牌（响应体返回）。
   每次登录都是全新标识，避免会话固定。
2. **使用**：受保护请求凭 `session` Cookie 解析会话；
   会话在 TTL（默认 1800s）内有效，过期返回 `401 session_expired`。
3. **轮换**：用户角色/权限变化（`role_version` 自增）后，该用户下一次
   认证请求会**原子轮换**会话标识：旧标识立即立墓碑失效，新标识通过
   `Set-Cookie` 下发，新 CSRF 令牌通过 `X-CSRF-Token` 响应头下发。
   轮换当次请求允许沿用上一代 CSRF 令牌一次（客户端尚未拿到新令牌），
   之后重放上一代令牌返回 `403 csrf invalid`。
4. **撤销**：`POST /auth/logout` 撤销当前会话；管理员可
   `POST /admin/revoke` 撤销某用户全部会话。已撤销/已轮换的标识复用
   一律返回 `401 session_revoked`，不会被再接受。
5. **CSRF 令牌**：与所属会话绑定、不跨会话复用。状态变更请求
   （logout / admin 写操作）必须携带 `X-CSRF-Token`：
   缺失 `403 csrf_missing`；无效 `403 csrf_invalid`；
   属于其他会话 `403 csrf_cross_session`。

## 权限判定顺序

每个受保护请求按以下顺序判定，任一环节失败即拒绝并给出可区分原因：

1. **会话解析**：无标识/未知标识 `401 unauthenticated`；
   已撤销或已轮换 `401 session_revoked`；过期 `401 session_expired`。
2. **权限变化轮换**：会话的 `role_version` 落后于用户当前值时原子轮换。
3. **CSRF 校验**（仅状态变更端点）：见上。
4. **角色判定**：默认拒绝。角色按请求时刻的用户记录实时判定
   （不缓存授权结果），角色变更后既有会话立即按新权限判定：
   未认证 `401 unauthenticated`，已认证但角色不足 `403 forbidden`。
   越权响应不携带任何资源内容，不暴露受保护资源是否存在。

## 暴力破解防护与锁定策略

- **双维度计数**：按账号与来源（客户端 IP）分别累计失败次数，
  任一维度达到阈值（默认 5 次）即进入锁定期（默认 60s）。
- **原子悲观计数**：开始登录尝试时在同一把锁内完成
  “锁定检查 + 失败计数 + 达阈锁定”，并发失败请求不会丢计数、
  不会超额放行；登录成功即清零该账号与来源的计数。
- **可区分原因**：账号锁定 `429 account_locked`，
  来源锁定 `429 source_locked`，凭证错误 `401 invalid_credentials`。
- **自动恢复**：锁定期满后计数与锁定状态自动清除，
  正常请求即可通过，不会被长期拒绝。

## 测试覆盖

`tests/test_auth.py` 覆盖：并发登录（会话标识/CSRF 唯一）、
同一会话并发受保护请求（无状态丢失）、并发失败计数（不丢失、不超阈）、
撤销后复用、会话过期、缺失/无效/跨会话 CSRF、上一代令牌单次沿用与重放拒绝、
账号锁定与自动恢复、来源锁定、角色升降级后既有会话即时按新权限判定
（含越权不泄露资源内容）。测试日志实时打印关键状态与判定依据。

## 目录结构

```
app/
  errors.py     # 失败原因码与领域异常
  models.py     # User / Session / Role
  security.py   # PBKDF2 口令散列、随机令牌
  store.py      # 线程安全用户/会话存储（墓碑、轮换）
  ratelimit.py  # 双维度失败计数与锁定
  service.py    # 登录/登出/解析/轮换/CSRF 判定
  deps.py       # FastAPI 依赖：认证→轮换→CSRF→角色
main.py         # 路由装配与统一错误处理
tests/          # 并发与防护测试
```
