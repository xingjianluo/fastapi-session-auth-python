# FastAPI 会话认证与授权（本地可运行）

基于内存存储实现的一套完整会话安全能力：本地账号登录/登出、会话轮换与撤销、
会话绑定的 CSRF 防护、账号+来源双维度暴力破解锁定、基于角色的即时访问控制。
所有安全结论都以稳定、可区分的错误码返回，各入口判定一致、可解释。

## 快速开始

```bash
uv sync                       # 安装依赖（含 pytest）
uv run uvicorn main:app --reload
# 健康检查
curl http://127.0.0.1:8000/health
```

种子账号（用户名即密码，仅用于本地演示）：

| 账号   | 角色   | 权限 |
|--------|--------|------|
| admin  | admin  | resource:read, resource:write, admin:users |
| editor | editor | resource:read, resource:write |
| viewer | viewer | resource:read |

登录成功后返回 `csrf_token`，并通过 HttpOnly Cookie 下发会话标识 `sid`。

```bash
# 登录
curl -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"editor","password":"editor"}' -c cj.txt
# 读（GET 不需要 CSRF）
curl localhost:8000/resources/public-note -b cj.txt
# 写（POST/PUT 必须带与会话绑定的 CSRF 令牌）
curl -X PUT localhost:8000/resources/demo -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: <登录返回的 csrf_token>" -d '{"content":"hello"}' -b cj.txt
```

## 接口一览

| 方法 | 路径 | 要求 |
|------|------|------|
| POST | `/auth/login` | 公开；受暴力破解锁定保护 |
| POST | `/auth/logout` | 有效会话 + CSRF |
| GET  | `/auth/me` | 有效会话 |
| GET  | `/resources/{name}` | resource:read |
| PUT  | `/resources/{name}` | resource:write + CSRF |
| POST | `/admin/roles?username=` | admin:users + CSRF |
| POST | `/admin/sessions/revoke` | admin:users + CSRF |

## 会话与令牌生命周期

```
登录成功 ──► 生成全新 sid + 全新 csrf_token（登录即轮换，杜绝会话固定）
权限变化 ──► 自身：就地轮换 sid+csrf，旧 sid 立即失效，Set-Cookie 下发新 sid
            他人：撤销其全部既有会话，重新登录后按新角色授权
主动登出/管理员撤销 ──► 会话标记 revoked，立即不可再用
到达 TTL ──► 会话过期并在下次访问时清除
```

- `sid` 存于 HttpOnly、SameSite=Strict 的 Cookie；CSRF 令牌在响应体中返回，
  由前端在状态变更请求头 `X-CSRF-Token` 中携带。
- CSRF 令牌从属于具体会话：每个会话独立生成，常量时间比较，**不可跨会话复用**；
  会话轮换后旧令牌随之失效。
- 会话数据受全局锁保护，并发请求读到的始终是最新状态：撤销即时生效，
  并发写不会丢失。

## 权限判定顺序（每个受保护入口一致）

1. **会话解析**：无 Cookie → `not_authenticated`(401)；已撤销/过期 →
   `session_invalid`(401)。
2. **CSRF 校验**（仅状态变更请求）：缺失 → `csrf_missing`(403)；
   与会话不匹配/错误 → `csrf_invalid`(403)。
3. **权限判定**：从账号**当前**角色即时推导权限（不缓存旧结果），默认拒绝，
   不足 → `forbidden`(403)。
4. **资源访问**：先授权后取资源；越权时无论资源是否存在一律 403，
   **不暴露资源是否存在**；授权通过后不存在才返回 `not_found`(404)。

登录入口顺序不同：先查账号/来源锁定 → 再校验凭证 → 失败计数或成功建会话。

## 错误码（可区分、跨入口一致）

| code | 状态码 | 含义 |
|------|--------|------|
| not_authenticated | 401 | 未携带会话 |
| session_invalid | 401 | 会话已撤销或已过期 |
| forbidden | 403 | 已认证但权限不足（或越权探测资源） |
| csrf_missing | 403 | 状态变更请求缺少 CSRF 令牌 |
| csrf_invalid | 403 | CSRF 令牌错误或属于其他会话 |
| invalid_credentials | 401 | 用户名/密码错误（用户不存在同码，防枚举） |
| account_locked | 429 | 账号维度失败过多，锁定中 |
| source_locked | 429 | 来源维度失败过多，锁定中 |
| not_found | 404 | 授权通过后资源不存在 |
| bad_request | 400 | 请求体/参数非法 |

## 暴力破解防护与锁定策略

- **双维度计数**：按“账号”和“来源（对端主机）”分别累计失败次数。
- 默认阈值 `AUTH_MAX_FAILURES=5`，锁定 `AUTH_LOCKOUT_SECONDS=300` 秒；
  任一维度达阈值即锁定。
- 锁定原因可区分：账号锁返回 `account_locked`，仅来源锁返回 `source_locked`；
  两者同时命中时优先报告账号锁。响应体中的 message 给出剩余秒数。
- 锁定期为**滑动窗口**：期内继续失败会延长锁定；锁定期满计数自动清零，
  正常请求立即恢复，不会被长期拒绝。
- 计数与锁定判定在同一把锁内原子完成：并发失败不会丢计数、不会超额放行。
- 登录成功清零两维度计数；用户不存在与密码错误返回相同结论，避免账号枚举。
- 阈值/时长可用环境变量 `AUTH_MAX_FAILURES`、`AUTH_LOCKOUT_SECONDS` 等覆盖。

## 本地验证（测试）

```bash
uv run pytest -q              # 全部用例（含并发场景与判定日志）
uv run pytest -s              # 同时查看 INFO 级关键状态与判定依据
```

覆盖要点：

- 并发登录（20 个独立会话、sid/令牌唯一）与并发受保护写（64 个并发请求不丢状态）；
- 会话撤销 / 登出后复用旧标识 → `session_invalid`，批量撤销立即全量生效；
- CSRF 缺失 vs 无效可区分、令牌跨会话复用被拒、轮换后旧令牌失效；
- 角色降级后既有会话**即时**按新权限判定、旧授权不沿用；越权访问存在/不存在
  资源结论一致（不暴露存在性）；
- 并发错误登录计数精确、阈值处即锁、锁定期满自动恢复；
- 日志在每次关键判定时打印会话、角色、权限集合、要求权限与 allow/deny 结论。

## 目录结构

```
app/
  config.py             # 配置（阈值/TTL，环境变量覆盖）
  errors.py             # 统一错误类型与可区分错误码
  models.py             # Account / SessionRecord / FailureRecord / Role
  deps.py               # 依赖容器（测试可重置隔离）
  routes.py             # HTTP 路由与统一判定流水线
  main.py               # 应用入口与异常处理
  auth/
    security.py         # PBKDF2 密码哈希、随机标识、角色权限表、种子账号
    store.py            # 线程安全内存存储
    sessions.py         # 会话创建/轮换/解析/撤销
    csrf.py             # 会话绑定 CSRF 校验
    bruteforce.py       # 双维度计数与锁定
    rbac.py             # 即时角色权限推导（默认拒绝）
tests/                  # pytest 用例（认证/CSRF/RBAC/防护/并发）
```
