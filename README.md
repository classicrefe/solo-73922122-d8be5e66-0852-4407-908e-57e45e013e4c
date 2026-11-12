# 内网门户公告 · 单进程 HTTP 缓存代理（含管理登录与退出收尾）

FastAPI + httpx 实现的单进程 HTTP 缓存代理与配套演示环境。代理只服务
`GET /notices/{id}` 一个业务接口，上游固定为随环境启动的本地上游服务；
管理接口 `/proxy/*` 全部纳入登录认证、固定 Origin 校验与“退出等待写操作
收尾（drain）”机制。

## 目录结构

```
.
├── proxy/
│   ├── app.py            # 代理主应用：路由、转发、合并、认证/Origin/drain
│   ├── sessions.py       # 内存会话注册表、写操作登记与退出 drain 状态机
│   ├── cachestore.py     # 内存缓存 + 同键在途合并 + 代际（epoch）清除
│   ├── policy.py         # Cache-Control 解析与缓存资格判定
│   └── static/index.html # 演示页（浏览器入口，原生 JS，无外链依赖）
├── upstream/app.py       # 本地上游：公开/个人切换、延迟、500、配置提交延迟、审计
├── scripts/
│   ├── run-local.sh      # 无 Docker 时本地启动（uvicorn 双进程）
│   ├── stop-local.sh
│   ├── verify.py         # 端到端行为验证（92 项断言，仅用 stdlib）
│   └── test_units.py     # 单元测试（策略 + 存储 + 会话/drain，24 项）
├── Dockerfile            # 代理与上游共用同一镜像
├── docker-compose.yml    # 一键环境（仅代理发布宿主端口 8000）
└── requirements.txt
```

## 快速启动

### 方式一：Docker Compose（推荐交付形态）

```bash
docker compose up --build
# 浏览器入口：http://localhost:8000/
# 默认管理口令：admin123（可用环境变量覆盖，见下）
```

- `proxy`：唯一对外服务，宿主端口 `8000`，上游固定指向
  `http://upstream:8001`；
- `upstream`：**不发布宿主端口**（仅 `expose` 到 compose 内部网络），
  宿主机与外部无法直连，所有管理/审计操作必须经代理鉴权后转发；
- 两个服务均为单 uvicorn 进程、内存态，重启即复位；均带 `/healthz`。

可覆盖的启动配置（compose 与 run-local.sh 均支持）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_PASSWORD` | `admin123` | 管理口令；未配置时代理拒绝启动 |
| `ADMIN_ALLOWED_ORIGIN` | `http://localhost:8000` | 管理 POST 允许的固定 Origin |
| `ADMIN_TIMEOUT_SECONDS` | `8` | 上游管理写超时，超出判定回执不明 |
| `UPSTREAM_TIMEOUT_SECONDS` | `15` | 公告 GET 转发超时 |
| `UPSTREAM_BASE` | `http://upstream:8001` | 固定上游地址 |

### 方式二：本地直接运行（无 Docker）

```bash
pip install -r requirements.txt
scripts/run-local.sh            # 默认 :8000 代理 / :8001 上游
# 浏览器入口：http://127.0.0.1:8000/  （本地 Origin 默认 http://127.0.0.1:8000）
scripts/stop-local.sh           # 停止
```

### 验证

```bash
# 单元测试（无需启动服务）
python3 -I scripts/test_units.py

# 端到端（先启动服务，端口可用 PROXY_ADDR / UPSTREAM_ADDR 覆盖）
PROXY_ADDR=127.0.0.1:8000 \
ADMIN_ALLOWED_ORIGIN=http://127.0.0.1:8000 \
  python3 -I scripts/verify.py

# compose 内运行（上游无宿主端口，验证流量全部走代理）
docker compose exec proxy python3 -I scripts/verify.py
```

## 管理安全模型

| 需求 | 实现位置与行为 |
| --- | --- |
| 凭启动配置口令登录 | `POST /proxy/login`，口令来自 `ADMIN_PASSWORD`，`hmac.compare_digest` 恒定时间比较；缺失口令进程拒绝启动 |
| 随机 HttpOnly 会话 Cookie，Path=/proxy，重启失效 | `secrets.token_urlsafe(32)` 生成不透明令牌，仅存进程内存；`Set-Cookie: proxy_admin_sid=...; HttpOnly; Path=/proxy; SameSite=Strict`，无 max-age/Expires；新进程无旧令牌 |
| 除登录外全部 /proxy 接口须认证 | `require_session` 依赖统一校验；无/伪造/失效 Cookie 一律 401 |
| 管理 POST 校验固定 Origin | `require_origin` 依赖：Origin 缺失或与 `ADMIN_ALLOWED_ORIGIN` 不符一律 403（含登录接口） |
| 退出先拒绝该会话新管理请求 | `logout` 首先把会话置为 `draining`，`begin_op` 与 `require_session` 立即拒绝该会话的一切新请求 |
| 等先前获准的写操作结束才返回成功 | 写操作登记到会话 `active_ops` 并在独立 `asyncio.Task` 执行；drain `gather` 全部在途任务进入终态 |
| 重复退出共享等待 | 同一 drain `Future`/`Task`，并发与重复 logout 返回同一结果对象 |
| 操作或退出请求断连仍继续收尾 | 写任务脱离路由生命周期，路由取消不影响写任务；drain 在后台运行，断连后再次退出可拿到同一结果 |
| 写超时/回执不明时退出显示未完成 | 上游写超时/传输异常标记 `ambiguous`（客户端收 504）；drain 结果 `status=incomplete` 并列出操作，会话保持禁用（closed），绝不报成功 |
| 其他会话与公告访问不受等待影响 | drain 只作用于当前会话；其他会话管理请求与 `GET /notices/*` 全程可用 |
| 管理 Cookie 不发往上游、不触发身份绕过 | 转发前 `strip_admin_cookie` 剔除；`_is_personal` 判定时忽略管理 Cookie（携带它仍走缓存而非 BYPASS） |
| 上游不发布宿主端口 | compose 中 upstream 仅 `expose`，无 `ports` 映射 |

### 退出响应语义

```json
{
  "status": "completed | incomplete",
  "session_id": "令牌前缀（仅展示用）",
  "waited_operations": [{"id": 1, "kind": "upstream.config", "status": "completed|ambiguous", "note": "..."}],
  "incomplete_operations": [ /* 仅 ambiguous 时非空 */ ],
  "detail": "..."
}
```

- `completed`：全部被等待的写操作拿到明确终态（成功或上游明确回执的失败）；
- `incomplete`：存在超时/传输异常等回执不明操作，会话保持禁用，需人工核对
  上游真实状态后重新登录处理。

## 上游的延迟配置能力

`POST /proxy/upstream/config`（转发到上游 `/admin/config`）支持：

- `config_delay_ms`：持久化的配置提交延迟（上游默认配置的一部分）；
- `delay_ms`：仅本次提交生效的单次延迟，不持久化；
- 延迟发生在配置真正写入之前，因此代理超时后上游仍可能在稍后实际生效，
  正好用于演示“回执不明但最终生效”。

## 缓存行为规则（保持基线语义）

| 需求 | 实现 |
| --- | --- |
| 仅代理 `GET /notices/{id}`，上游固定 | 单一路由；其他路径 404、非 GET 405 |
| 缓存按公告 ID + Accept-Language 区分 | `CacheStore.make_key`，语言取请求头原始值 |
| 业务 Cookie / Authorization 直连，不读写缓存、不参与合并 | `_is_personal` 判定（忽略管理 Cookie），标记 `X-Cache: BYPASS` |
| 仅 200 + public + 合法非负整数 max-age、无 private/no-store、无 Set-Cookie 可缓存 | `policy.cache_eligibility` |
| 过期不复用 | 单调时钟判定，`lookup` 命中过期条目立即剔除 |
| 同键并发未命中只请求上游一次 | leader/wait + 同一 `asyncio.Future` |
| 一个等待者断开不影响其他人 | 上游请求在独立屏蔽任务中执行 |
| 失败不缓存且结束所有等待 | 传输异常/5xx 走 `fail_all`，全部收 502 `X-Cache: ERROR` |
| 按公告清除全部语言、旧在途不回填、清除后不复用旧在途 | generation（epoch）+ `purged` 标记 |

## 演示页使用指引（http://localhost:8000/）

1. **⓪ 管理登录与退出**：输入口令登录；两个一键演示：
   - “慢配置期间退出”：自动提交 6 秒延迟配置并立即发起两次退出，可观察
     会话先禁用（新管理请求 401）、两个退出共享同一次等待、公告访问不受影响；
   - “上游写超时后退出”：提交超过管理超时的配置，代理返回 504 ambiguous，
     退出结果为 incomplete 且会话保持禁用，稍后可重新登录核对上游实际生效结果；
2. **① 公告请求**：无需登录即可访问，用于验证 drain 期间业务不受影响；
3. **② 清除缓存 / ③ 上游控制**：登录后可用，均为受追踪的管理写操作；
   上游控制支持设置持久的“配置提交延迟”；
4. **⑤ 代理状态 / ⑥ 上游审计**：登录后可刷新；上游审计的 Cookie/Auth 列
   可直接核对管理 Cookie 从未到达上游。

### 手工验证要点

- 未登录访问任何 `/proxy/*`：401；管理 POST 不带/带错 Origin：403；
- 慢配置期间退出：退出耗时≈配置延迟，返回 completed；重复退出同时结束；
- 写超时后退出：返回 incomplete，该会话之后任何请求仍 401；
- 写操作发起后立即断开客户端：退出仍等待其在后台完成，配置最终生效；
- 仅携带管理 Cookie 请求公告：`X-Cache` 为 MISS/HIT 而非 BYPASS，上游审计
  `has_cookie=false`；
- `docker compose` 下宿主机无法访问 upstream 的 8001 端口。

## 设计说明与边界

- 单进程内存会话与缓存，不跨进程共享；进程重启全部失效，符合运维定位；
- 会话 Cookie 未设 `Secure`（本地 http 演示）；置于 https 反代后应开启；
- 上游 5xx 按失败处理（502、不缓存、结束等待）；4xx 为成功送达但不可缓存；
- 管理写的“明确失败”（上游回执 4xx/5xx）与“回执不明”（超时/传输异常）
  严格区分：只有后者会让退出变成 incomplete。
