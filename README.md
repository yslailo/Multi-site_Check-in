# Multi-site_Check-in

多站点 New API 自动签到（tabitoken / gorouter / api.justwoker.icu 等）。

GitHub OAuth 登录的账号无需账密：只需在站点控制台生成一次「系统访问令牌」，之后每日自动签到全自动。

站点启用 Cloudflare Turnstile 人机验证时，自动切换「**浏览器拿令牌 + 页面内提交**」混合模型，并可选**代理池多节点并发探测**，无需人工介入。

## 工作原理

```
GET  /api/user/self              验证凭据 + 记录签到前余额
GET  /api/user/checkin?month=…   查询状态：今日已签 → 跳过
POST /api/user/checkin           执行签到
GET  /api/user/self              交叉验证（奖励字段缺失时用余额差确认，绝不谎报成功）
```

- 认证：`Authorization: Bearer <access_token>` + `New-Api-User: <user_id>`
- 站点返回 Cloudflare/WAF 页面时自动识别分类：可解挑战 / IP 被封 / 站点 5xx
- 额度换算：`quota ÷ 500000 = 美元`

### Turnstile 混合模型（签到被拒时自动触发）

```
POST /api/user/checkin           → 「Turnstile token 为空」
GET  /api/status                 → 取 turnstile_site_key
反检测浏览器（见下方浏览器策略）   → 打开站点页面，注入 Turnstile widget，
                                   自动签发 / 元素级点击复选框，等待令牌
页面内 fetch POST checkin?turnstile=<token>   → 令牌与提交同浏览器环境，
                                   UA/TLS/出口 IP 完全一致
```

关键技术点（本地 + CI 实测沉淀）：

- **screenX 主世界补丁**：CF 会丢弃「跨域 iframe 内 `screenX < ~120`」的点击事件（CDP 派发事件在 iframe 内 screenX 退化为小值），补丁经 `add_init_script` 在导航前注入并覆盖所有 frame，把可疑小值改写为合理屏幕坐标（移植自 shield-bypass，MIT）
- **Patchright**：反检测 Playwright fork，C++ 层剔除自动化标志，evaluate 走 isolated world，规避 Runtime.enable / webdriver 检测
- **元素级可信点击**：`frame_locator` 探测 checkbox 可见性后 force click，100ms 轮询令牌，失败自动重试（≤3 次）
- 全程只消费 Cloudflare 正常签发的令牌，不伪造、不绕过

### 代理池模式（可选，CI 机房 IP 被拒时的解法）

配置 Clash 订阅池 URL（Secret `PROXY_POOL_URL`）后启用：

```
拉取最新池 yaml（池子每日更新，每次运行重新拉取）
  → mihomo group delay 一次测活全部节点，按延迟排序
  → K 个并发 worker（默认 3）：各自独立 mihomo 实例钉死单节点 + 独立浏览器探测
  → 首个出令牌的节点独占提交签到（claim 机制），成功即全局停止
  → 失败节点分类统计：600010 拒绝 / 静默惩罚 / 探测超时 / 环境异常
```

- 令牌绑定签发出口 IP，因此 solve 与 submit 在同一 worker 同一节点内完成
- 探测阶段不发签到请求，只有胜者节点 POST 一次（避免多 IP 打同一账号）
- 同一轮运行多站点共享预筛结果，胜出后其他 worker 立即收工

## 使用方法

### 第一步：采集凭据（每站 3 分钟，一次性）

1. 浏览器正常 GitHub 登录站点
2. 按 F12 打开控制台 → Console 标签
3. 粘贴 `collector.js` 全部内容并回车 → 自动输出 `user_id`
4. 打开站点控制台 → **个人设置 → 生成系统访问令牌**，复制 `access_token`

### 第二步：配置

复制 `ACCOUNTS.example.json` 为 `ACCOUNTS.json`，填入采集到的凭据：

```json
{
  "accounts": [
    {
      "name": "tabitoken",
      "base_url": "https://tabitoken.com",
      "user_id": "12345",
      "access_token": "生成的系统访问令牌",
      "enabled": true
    },
    {
      "name": "gorouter",
      "base_url": "https://gorouter.app",
      "user_id": "67890",
      "access_token": "生成的系统访问令牌",
      "turnstile": "auto",
      "browser": "auto",
      "enabled": true
    }
  ]
}
```

> `user_id` + `access_token` 必须同时提供（缺任一报 `need_config`）。
> `turnstile`: `auto`（默认，签到被拒时自动浏览器求解）/ `off`（关闭）。
> `browser`: `auto`（默认，真实 Chrome+Patchright 优先，Camoufox 兜底）/ `chrome` / `camoufox`。

### 第三步：本地运行（可选验证）

```bash
pip install -r requirements.txt
python checkin.py --validate    # 只探测认证，不签到
python checkin.py               # 执行签到
python checkin.py --name gorouter    # 只跑一个站
```

本地跑 Turnstile 站点无需额外准备（自动用系统 Chrome）；若要走 Camoufox 兜底需先 `python -m camoufox fetch`。Windows 本地默认有头求解，`CHECKIN_HEADLESS` 可覆盖。

### 第四步：GitHub Actions 自动运行

1. 仓库 **Settings → Secrets and variables → Actions → New repository secret**
2. 添加 `ACCOUNTS`：整个 `ACCOUNTS.json` 的内容（JSON 文本）
3. 可选：`TG_BOT_TOKEN` / `TG_CHAT_ID`（Telegram 通知）、`CHECKIN_PROXY`（出站代理）
4. 可选：`PROXY_POOL_URL`（订阅池 URL，配置后 Turnstile 站点自动多节点并发过盾）
5. 前往 **Actions** 启用 workflow，手动触发测试，后续每天会自动运行

运行结果会写入 Step Summary 表格（站点 / 状态 / 说明 / 获得 / 余额）。

### 代理池相关环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `CHECKIN_PROXY_POOL` | 未设置 | Clash 订阅池 URL（CI 用 Secret `PROXY_POOL_URL` 注入） |
| `CHECKIN_POOL_CONCURRENCY` | `3` | 并发探测 worker 数（每 worker 一个浏览器 + mihomo，注意 runner 内存） |
| `CHECKIN_POOL_MAX_NODES` | `24` | 单次运行最多探测的节点数 |
| `CHECKIN_POOL_BUDGET_S` | `900` | 池探测总时间预算（秒） |
| `MIHOMO_BIN` | `mihomo` | mihomo 内核路径（CI 的 workflow 会自动安装） |

### 收敛请求 / 限流相关环境变量

同一站点多个账号连跑时，出口 IP 易被站点风控限流（表现为 `network_error`：超时/连接被断，或 429/5xx）。以下变量用于**压低请求密度、尊重服务端限流**（非绕过）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `CHECKIN_SITE_DELAY_MIN` | `20` | 同一 `base_url` 相邻账号之间的最小随机间隔（秒） |
| `CHECKIN_SITE_DELAY_MAX` | `45` | 最大随机间隔（秒）；设为 `0` 关闭间隔 |
| `CHECKIN_SHARD_TOTAL` | `1` | 分片总数，把站点拆到多次运行；`>1` 时启用分片 |
| `CHECKIN_SHARD_INDEX` | `0` | 当前分片下标，范围 `[0, CHECKIN_SHARD_TOTAL)` |

网络层重试为指数退避 + 抖动，且会读取响应头 `Retry-After`（限流时优先听从）；`429/502/503/504` 视为瞬时限流可重试。有奖励字段时不再额外请求余额接口（用「签到前余额 + 本次奖励」推导），进一步减少请求数。

## 状态说明

| 状态 | 含义 | 处理 |
|---|---|---|
| `success` | 签到成功，奖励已确认 | 无 |
| `already_done` | 今日已签，自动跳过 | 无 |
| `need_config` | 缺 user_id 或 access_token | 补全配置 |
| `need_login` | 令牌失效（401） | 重新生成系统访问令牌 |
| `need_verification` | Turnstile 求解失败 / WAF 拦截 | 检查日志中失败分类（600010=IP 被拒、rendered=信誉惩罚）；配置代理池或住宅代理 |
| `not_open` | 站点未开放签到 | 无（站点侧问题） |
| `network_error` | 临时网络失败 / 站点 5xx / 限流（超时·连接被断·429） | 已自动退避重试；仍失败则下次运行重试，或调大 `CHECKIN_SITE_DELAY_*` / 用分片分摊 |
| `error` | 业务拒绝或结果无法确认 | 查看日志详情 |

## 安全

- `ACCOUNTS.json` 已被 `.gitignore` 忽略，只通过 GitHub Secret 传递

## 安全研究工具箱：lucky_wheel/

`lucky_wheel/` 是并入本仓库的**幸运大转盘 API 授权渗透测试工具包**（本地工具目录，已 `.gitignore`），与 `shield-bypass/`、`CloudflareBypassForScraping/` 等同为本地对照实现，不入库。

针对目标 `https://hjmapi.923578.xyz` 的 `/api/user/lucky-wheel*`，一条命令覆盖从侦察到漏洞复现的全流程：

```bash
cd lucky_wheel
pip install h2                      # 仅 h2 / h2multi 子命令需要

# 配置（六选一）：config.json token / LW_TOKEN / --token / --browser 浏览器会话 / --auto 账密 / --accounts 长效令牌
python lucky_wheel.py info                                  # 读取转盘状态（remaining/draws_today/daily_limit）
python lucky_wheel.py --browser h2 -n 100                   # ★ 浏览器会话自动取 JWT + 并发复现，零手填零密码
python lucky_wheel.py h2 -n 100                             # ★ HTTP/2 单连接 100 stream 并发（TOCTOU 复现，规避 429）
python lucky_wheel.py info                                  # 复核：draws_today > daily_limit
python lucky_wheel.py probe                                 # 限次/鉴权绕过探针（20 变体）
python lucky_wheel.py auth                                  # JWT 签名校验测试
python lucky_wheel.py jwt-crack --wordlist wordlists/jwt_common.txt
```

| 能力组 | 子命令 |
|---|---|
| 并发打点 | `race`（线程） / `burst`（裸 socket） / `h2`（推荐） / `h2multi` |
| 侦察 | `probe` / `auth` / `routes` / `tls` / `replay` |
| JWT 离线分析 | `jwt-decode` / `jwt-crack` / `jwt-none` / `jwt-forge` |

工具包自带 `README.md`、`REPORT.md`（含已确认的 TOCTOU 限次绕过漏洞与修复建议）、`evidence/`（并发复现证据）、`poc/`（模块化版本，与统一 CLI 等价）。仅用于已授权目标的自有账号测试。

