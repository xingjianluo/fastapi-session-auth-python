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

# 受保护读取（每次访问都会滑动续期，可用 /auth/sessions 观察到期时间变化）
curl -b jar.txt localhost:8000/auth/me

# 查看本人当前全部有效会话（登录时间/最近活动/权限/current 标记）
curl -b jar.txt localhost:8000/auth/sessions

# 只撤掉其中指定一条（其余会话不受影响；需携带 CSRF 令牌）
curl -b jar.txt -X DELETE localhost:8000/auth/sessions/<session_id> \
  -H "X-CSRF-Token: <token>"

# 状态变更需携带 X-CSRF-Token（取登录响应中的 csrf_token）
curl -b jar.txt -X POST localhost:8000/auth/logout -H "X-CSRF-Token: <token>"
```

## 会话与令牌生命周期

1. **签发**：`POST /auth/login` 校验凭证后签发全新随机会话标识
   （HttpOnly Cookie）与独立的 CSRF 令牌（响应体返回）。
   每次登录都是全新标识，避免会话固定。
2. **使用与续期**：受保护请求凭 `session` Cookie 解析会话。
   会话采用**滑动续期 + 绝对上限**：
   - 每次受保护访问成功后，到期时间自动顺延一个 TTL
     （`session_ttl`，默认 1800s）；续期在会话存储的同一把锁内
     原子完成，同一会话的并发访问不会丢状态、不会把到期时间改乱。
   - 续期不得越过**绝对上限**（`session_absolute_ttl`，默认 28800s）：
     从本次登录算起，无论是否持续活动，到达上限即到期；
     权限变化触发的会话轮换也继承原登录的绝对上限，不会借此续命。
   - 长时间没有操作的会话不触发续期，按原方式在滑动窗口后自然到期，
     返回 `401 session_expired`。
3. **轮换**：用户角色/权限变化（`role_version` 自增）后，该用户下一次
   认证请求会**原子轮换**会话标识：旧标识立即立墓碑失效，新标识通过
   `Set-Cookie` 下发，新 CSRF 令牌通过 `X-CSRF-Token` 响应头下发。
   轮换当次请求允许沿用上一代 CSRF 令牌一次（客户端尚未拿到新令牌），
   之后重放上一代令牌返回 `403 csrf invalid`。
   **即使本次请求最终以错误告终（如越权 403），新会话标识与新 CSRF
   令牌也会随错误响应一并下发**——被拒的是这次操作，会话本身仍然有效。
4. **撤销**：`POST /auth/logout` 撤销当前会话；`DELETE /auth/sessions/{id}`
   撤销本人指定的某一条会话（多端管理，见下）；管理员可
   `POST /admin/revoke` 撤销某用户全部会话。已撤销/已轮换的标识复用
   一律返回 `401 session_revoked`，与自然过期（`session_expired`）
   可区分，不会被再接受。
5. **CSRF 令牌**：与所属会话绑定、不跨会话复用。状态变更请求
   （logout / 撤销会话 / admin 写操作）必须携带 `X-CSRF-Token`：
   缺失 `403 csrf_missing`；无效 `403 csrf_invalid`；
   属于其他会话 `403 csrf_cross_session`。

## 多端会话管理

同一账号可同时在多台设备登录，每次登录都是独立会话（独立标识与
CSRF 令牌），互不挤占。

- **可见范围**：`GET /auth/sessions` 只列出**本人**当前仍有效的会话，
  每条包含登录时间（`created_at`）、最近活动时间（`last_activity_at`）、
  滑动到期时间、绝对上限、按请求时刻实时判定的权限（`role`），
  以及 `current` 标记（哪一条是当前请求所用会话）。看不到他人会话。
- **单条撤销**：`DELETE /auth/sessions/{session_id}`（需 CSRF 令牌）
  只撤掉指定的那一条，其余会话照常可用、完全不受影响。
  被撤掉的标识立墓碑，后续任何请求返回 `401 session_revoked`，
  与自然过期可区分。目标不存在或不属于本人时一律返回
  `404 session_not_found`，不泄露他人会话是否存在。
- **权限变化即时生效**：用户权限被调整（尤其降权）后，既有会话立即
  按新权限判定。带着它去做没权限的操作会得到 `403 forbidden`
  （响应不携带任何资源内容），但**会话本身不受影响**：接着看自己的
  信息、看会话列表、正常登出都不需要重新登录。

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
- **确认失败计数**：开始登录尝试时在同一把锁内原子完成锁定检查；
  只有口令确认错误才（同样在同一把锁内）原子计数并达阈锁定。
  并发失败不丢计数、不超阈放行；而一批设备并发地拿**正确口令**
  登录（如批量上线自检）不产生任何失败计数——每条都成功、各自拿到
  独立会话，不会被防护误伤，即使它们来自同一来源。
- **共享状态**：计数与锁定状态是服务整体共享的单例（挂在应用状态上），
  所有请求命中同一份状态，无法靠每个请求各起一份绕过。
- **可区分原因**：账号锁定 `429 account_locked`，
  来源锁定 `429 source_locked`，凭证错误 `401 invalid_credentials`。
- **自动恢复**：锁定期满后计数与锁定状态自动清除，
  正常请求即可通过，不会被长期拒绝。

## 测试覆盖

`tests/test_auth.py` 覆盖：并发登录（会话标识/CSRF 唯一）、
同一会话并发受保护请求（无状态丢失）、并发失败计数（不丢失、不超阈）、
撤销后复用、会话过期、缺失/无效/跨会话 CSRF、上一代令牌单次沿用与重放拒绝、
账号锁定与自动恢复、来源锁定、角色升降级后既有会话即时按新权限判定
（含越权不泄露资源内容）。

`tests/test_sessions.py` 覆盖：持续活动滑动续期且不超过绝对上限、
停止活动后自然到期、同一会话并发访问下续期算术正确且状态不丢、
多端会话列表（登录时间/最近活动/权限/current）、单条撤销且其余会话
不受影响（被撤标识复用为 `session_revoked`，与自然过期可区分）、
撤销的归属与 CSRF 边界、降权后越权被拒（不泄露资源）但会话仍可用
（信息/会话列表/登出正常）。

`tests/test_protection.py` 覆盖：一批设备并发正确口令登录全部成功且
各自独立会话（防护不误伤）、混合并发下正确登录不消耗失败额度而错误
口令仍累计到阈值并被拦、锁定期满自动恢复、防护状态服务整体共享
（跨客户端累计到同一份计数）。

测试日志实时打印关键状态与判定依据（`log_cli` 已开启）。

## 目录结构

```
app/
  errors.py     # 失败原因码与领域异常
  models.py     # User / Session / Role（含续期与绝对上限字段）
  security.py   # PBKDF2 口令散列、随机令牌
  store.py      # 线程安全用户/会话存储（墓碑、轮换、滑动续期、多端列表）
  ratelimit.py  # 双维度确认失败计数与锁定（服务整体共享）
  service.py    # 登录/登出/解析/轮换/CSRF 判定/单条撤销
  deps.py       # FastAPI 依赖：认证→轮换→CSRF→角色
main.py         # 路由装配与统一错误处理（错误响应也下发轮换结果）
tests/          # 并发、续期、多端与防护测试
```
