# 生产核查结论 + 风险打分 / 人机验证加固

## 1. 目标

1. 固化 2026-10-24 / 10-25 生产日志核查结论，明确哪些请求是 WAF 处理错误、哪些是上游问题。
2. 把“设备风险 / 伪造指纹 / IP 风险”从客户端自报改为**服务端可校验的风险标签 + 分值**。
3. 挑战链路可观测、可计分、可联动封禁，并修复挑战页自锁死循环。
4. 统一事件 `score` 语义，避免把“攻击分”“QPS”“封禁次数”混在一个字段里。
5. 给出图片滑动轨迹认证的可行边界与实现方案（本期只做设计与接口预留，不实现滑块 UI）。

## 2. 生产核查结论（已确认）

### 2.1 数据集

- 主机：10.0.0.31，systemd `homewaf`。
- 二进制：`/opt/homewaf/bin/homewaf`，构建于 2026-10-24 07:12:47 UTC；服务启动于 07:14:03 UTC。
- 日志：`/opt/homewaf/data/logs/{access,security,error,upstream}/`。
- 数据库：`/opt/homewaf/data/homewaf.db`（已复制到 `/tmp/homewaf-prod/homewaf.db`）。

### 2.2 状态码分布

| 日期 | 200 | 403 | 400 | 404 | 500 | 204 | 101 | 0 |
|---|---|---|---|---|---|---|---|---|
| 10-24 | 57541 | 57 | 8 | 4 | 0 | 0 | 3 | 1 |
| 10-25 | 24326 | 1 | 0 | 1 | 1 | 1 | 5 | 3 |

### 2.3 处理错误的请求（WAF 侧）

**A. FireHOL 订阅误伤内网/回环（已随 07:14 部署修复）**

- 57 个 403 与 `security.2026-10-24.log` 58 条记录一一对应，原因只有两种：
  - `黑名单规则 feed:pub-firehol-l1:22:global` → 对应条目 `10.0.0.0/8`
  - `黑名单规则 feed:pub-firehol-l1:1489:global` → 对应条目 `127.0.0.0/8`
- 客户端：`10.0.0.31`、`10.0.0.29`、`127.0.0.1`，全部是内网/回环自测与健康检查。
- 时间分布：05:08（43 条）、06:55（8 条）、06:59 / 07:04 / 07:13（各 2 条）。
- 最后一条 07:13:20，服务 07:14:03 重启后 `security.2026-10-25.log` **不存在**，即 0 条安全事件。
- 结论：`crates/acl/src/lib.rs` 中“内网 IP 跳过 `feed_deny`”的修复已生效，**无需再改**。后续需要的是回归验证，而不是代码变更。

**B. 扫描器被原样放行（真实缺口）**

- `home.niao.fun` 8 条 400：请求序列固定为 `/` → `/favicon.ico` → `/robots.txt` → `/sitemap.xml`，相邻间隔 1 秒；客户端 IPv6 在同一 `/64` 内轮换。
- `upstream.2026-10-24.log` 中对应 `req` 均为 `status=400`、`error=""`，说明 WAF 正常转发，400 由上游 `10.0.0.26:80` 产生。
- 结论：WAF 没有把“同 /64 内 1 秒间隔顺序探测敏感路径”识别为扫描，也没有把上游 4xx 计入风险。这是风险打分要补的能力。

**C. WebSocket 被 60s 读超时终止**

- `error.2026-10-24.log`：`Fail to proxy: Downstream ReadTimedout ... timeout: 60s ... GET /websocket?type=main, Host: fn.niao.fun`。
- `error.2026-10-25.log`：多条 `GET /websocket` 同类错误，另有 4 条 `TLSHandshakeFailure ... tls handshake eof`（客户端主动断开）。
- 根因：`crates/proxy/src/server.rs` 使用 `Server::new(None)`，采用 pingora 默认 `upstream_read_timeout = 60s`；长连接空闲超过 60s 即被判超时。
- 结论：需要可配置的上游读超时（默认放宽到 300s），而不是让所有 WebSocket 死在 60s。

### 2.4 非 WAF 问题（上游原样返回）

| 请求 | 状态 | 上游 | 说明 |
|---|---|---|---|
| `home.niao.fun /` 等 4 条 ×2 轮 | 400 | 10.0.0.26:80 | 上游拒绝，WAF 透传 |
| `fn.niao.fun /sac/rpcproxy/v1/new-user-guide/status` | 403 | 10.0.0.4:5666 | 上游 403 |
| `fn.niao.fun /p/api/v1/ai-smart-rec/categories` | 500 | 10.0.0.4:5666 | 上游 500，耗时 3.3s |
| `fn.niao.fun /license/v1/device/logo` | 404 | 10.0.0.4:5666 | 资源不存在 |
| `fn.niao.fun /p/api/v1/...` 流式接口 | 0 | 10.0.0.4:5666 | 客户端关闭 H2 流 / 连接重置，属正常中断 |
| `error.2026-10-24.log` `status: 500, GET /` | — | — | 403 写响应时 Broken pipe，不是真 500 |

### 2.5 真实 IP 还原现状

- `real_ip.header_priority[0] = "xxxxxxx-Real-Forwarded-For"`，`trusted_proxies` 含 `2408:8752:0:5:2::/64`。
- 81123 / 81958 条请求的 `ip_source` 是该头；`direct_ip` 全部落在 `2408:8752:0:5:2::/64` 内。
- 客户端 IP 去重后仅 52 个，多为移动网络 IPv6。
- 判定：该头由受信回源网关写入，外部直连因源地址不在 `trusted_proxies` 而不会采信，**当前不构成 X-Forwarded-For 伪造入口**。但内网 `10.0.0.0/8` 也在 `trusted_proxies`，内网客户端可伪造该头，属可接受风险，本期不改。

### 2.6 挑战与事件现状

- `challenge = {enabled:false, difficulty:4, ttl:1800s}`；`ratelimit.enabled=false`。
- 事件表：`detect/block` 97（sum 7040, max 210）、`acl/block` 86（score 全 0）、`ban/ban` 68（sum 4620）、`ban/block` 21（score 1）、`detect/log` 8；**challenge 0 条**。
- `bans` 表为空（历史封禁均已过期）。
- 结论：挑战功能在现网从未启用，失败/通过均无落库，无法评估效果。

## 3. 现网打分机制（基线，不改动语义）

```text
严重度: low=10 / medium=25 / high=50 / critical=80
score          = 所有命中严重度之和
blocking_score = 仅 action=Block 且该分类 mode=Block 的命中之和
blocked        = !observe && (immediate || blocking_score >= block_threshold)
block_threshold = 显式配置 || preset(Lenient 40 / Balanced 25 / Strict 10) || 50
自动封禁: 600s 窗口按 IP 累加 blocking_score；>= trigger_score(默认50) 触发
         时长档位 300s → 1800s → 7200s → 86400s；IPv6 按 /64 聚合
```

保留上述检测链路不变；风险打分是**叠加维度**，不替换规则分。

## 4. 设计

### 4.1 统一风险标签

新增 `crates/proxy/src/risk.rs`。

```rust
pub enum RiskTag {
    AutomationReported,   // wd/cdp 自报为 1                    100 hard
    FingerprintForged,    // 客户端 fp 与服务端重算不一致        100 hard
    FingerprintMissing,   // 挑战回传缺失 sig/fp                  60 hard
    FingerprintReplay,    // 同一 fp 短时间跨多个 IP              50 hard
    HeadlessUa,           // UA 含 HeadlessChrome / PhantomJS 等   30
    UaChMismatch,         // UA 与 Sec-CH-UA / Accept-Language 矛盾 20
    ChallengeFailed,      // 单次挑战失败                         15
    CcBurst,              // CC 触发一次                          10
    SliderFailed,         // 滑块轨迹校验失败                     25（本期仅定义）
}
```

- `weight()` 返回上表分值；`hard()` 为 `AutomationReported / FingerprintForged / FingerprintMissing / FingerprintReplay`。
- `RiskAssessment { tags: Vec<RiskTag>, score: u32, hard: bool }`。
- `RiskLevel::Normal(<30) / Challenge(30..60) / Block(>=60)`，阈值来自 `ChallengeConfig`。

`RiskTable`（进程内，`Mutex<HashMap<IpAddr, (u32, u64)>>`，600s 窗口）：
- `add(ip, score)`：窗口外先清零再累加。
- `level(ip, cfg)`：返回 `RiskLevel`。
- `bump_replay(fp, ip)`：`HashMap<String, (HashSet<IpAddr>, u64)>`，同一 fp 在 600s 内出现 ≥3 个 IP 记 `FingerprintReplay`。

### 4.2 服务端权威指纹

现状：`fp` 只做 16 位 hex 格式校验，内容完全由客户端决定。

改为：
1. 挑战页把采集到的信号按固定顺序拼成 `sig`（pipe 分隔），随回调一起提交：
   `wd|cdp|screen.width|screen.height|colorDepth|timeZone|language|hardwareConcurrency|deviceMemory|platform|plugins.length|canvasHash|webglHash`
2. 服务端用与页面一致的公式重算：
   `fp = sha256("homewaf-fp-v2|" + app + "|" + sig)[0..16]`
3. 与回传 `fp` 比对，不一致 → `FingerprintForged`（hard）。
4. `env` 中的 `wd/cdp` 必须与 `sig` 前两位一致，否则 → `FingerprintForged`。
5. PoW 输入改为服务端重算的 `fp`，客户端提交的 `fp` 不再参与证明。

限制说明：脚本仍可伪造 `sig` 并算出合法 `fp`，这是无服务端挑战的固有限制；本设计消除的是“fp 与信号脱钩、可随意填 16 位 hex”这一最低成本绕过。更强的服务端信号（JA4/JA3、HTTP/2 指纹、UA-CH 一致性）列入后续，不在本期。

### 4.3 挑战令牌 v2

`TokenPayload` 增加：
- `k: u8`：签发时的风险等级（0 Normal / 1 Challenge / 2 Block）。
- `s: bool`：是否要求滑块（本期恒 false，为滑块预留）。
- `x: Option<u16>`：滑块缺口坐标（本期 None）。

`TOKEN_VERSION` 由 1 升到 2；旧 token 直接 `Malformed`，无需兼容（TTL 30 分钟，重启后密钥也会变）。

`ChallengeService` 新增：
- `attempts: Mutex<HashMap<IpAddr, (u64, u32)>>`，1 分钟窗口最多 5 次失败，超出直接 429。
- `record_failure(ip, now) -> bool`（是否超额）。
- `reset_failures(ip)`：验证成功后清零。

### 4.4 处置矩阵

| 风险等级 | 已有挑战 Cookie | 处置 |
|---|---|---|
| Normal | 任意 | 正常流程 |
| Challenge | 否 | 下发挑战页（403） |
| Challenge | 是 | 放行，但事件带标签 |
| Block | 否 | 直接 403，并 `bans.record(ip, 50)` |
| Block | 是 | 仍 403（hard 标签不因 Cookie 豁免） |

软标签只累积 `RiskTable` 并影响是否挑战；只有 hard 标签或 `Block` 等级进入 `BanTable`，避免共享 NAT 被误封。

### 4.5 事件语义

新增 `events.risk_tags TEXT NOT NULL DEFAULT ''`（逗号分隔 tag 名）。

各 kind 的 `score` 固定语义：

| kind | score |
|---|---|
| detect | 规则严重度之和（不变） |
| ratelimit | 实测 QPS（不变，展示层注明） |
| challenge | 本次风险评估分（0–100） |
| ban / ban-block | 触发封禁时的累计分（不再用 offenses） |
| acl | 0（规则型处置，无数值风险） |

管理面事件列表按 kind 显示不同列名：`风险分` / `QPS` / `累计分`，并把 `risk_tags` 展示为标签。

### 4.6 滑块轨迹方案（本期只设计，不实现 UI）

结论：滑块只能作为**升级处置**，不能作为安全边界。

- 触发：`RiskLevel::Challenge` 且风险分 30–59；≥60 直接拒绝。
- 校验项（全部服务端算）：轨迹点数 ≥20、总时长 300–8000ms、x 单调性（允许 ≤2 次回退）、速度方差下限、至少 1 次停顿、终点误差 ≤4px、`pointer/mouse/touch` 事件类型前后一致、一次性哈希防重放。
- 缺口坐标由服务端生成并 HMAC 进 token（`x` 字段），客户端不可见真值；图片由服务端预生成池 + 每张带随机噪点/旋转/缩放，避免模板匹配。
- 不引入第三方验证码；图片生成用本地静态资源池，避免运行时图像库依赖。

本期只落 `k/s/x` 三个字段与 `SliderFailed` 标签，页面不渲染滑块。

## 5. 具体改动

### 5.1 新增 `crates/proxy/src/risk.rs`

- `RiskTag` / `RiskAssessment` / `RiskLevel` / `RiskTable` / `assess_request()`。
- `crates/proxy/src/lib.rs` 增加 `mod risk;` 与必要 `pub use`。

### 5.2 `crates/proxy/src/challenge.rs`

- `TOKEN_VERSION = 2`。
- `TokenPayload` 增加 `k/s/x`，序列化保持紧凑。
- `Solution` 增加 `sig: &'a str`。
- 新增 `fp_from_signals(app, sig) -> Option<String>`（sig 长度上限 512、字段数固定 13）。
- `verify()`：
  1. 原有签名/版本/过期/绑定校验；
  2. `fp_from_signals` 重算，与 `sol.fp` 比对；
  3. `env` 与 `sig[0..2]` 一致性；
  4. 用服务端 fp 做 `proof_ok`；
  5. 防重放不变。
- 新增错误：`FingerprintForged`、`SignalsMissing`。
- `issue()` 增加 `level: RiskLevel` 参数，写入 `k`。
- `render_page()`：注入 `app`、输出 `sig`、按服务端公式算 `fp`；新增 `deviceMemory`、`platform`、`plugins.length`。
- 单测：伪造 fp、env 与 sig 不一致、缺 sig、v2 token 往返、滑块字段透传。

### 5.3 `crates/proxy/src/server.rs`

- `WafProxy` 增加 `risks: RiskTable`，构造处初始化。
- `handle_challenge_callback`：
  - 成功：`record_security_event(Challenge, ..., score=risk.score, action="pass", risk_tags)`；`reset_failures`。
  - 失败：写 `Challenge` 事件 `action="fail"`，`score` 取对应 tag 权重；`risks.add(ip, weight)`；hard 或 Block → `bans.record`；`record_failure` 超额返回 429。
- `issue_challenge`：写 `Challenge` 事件 `action="issue"`，带等级与分数。
- 自定义规则 `Challenge` 分支：`uri_path == CHALLENGE_PATH` 时跳过整段自定义规则求值，修复挑战页被规则再次挑战的死循环。
- `require_challenge` 条件追加 `|| risks.level(ip) == Challenge`。
- 自定义规则 `Deny`：`risks.add(ip, 25)`。
- CC 命中：`risks.add(ip, 10)`。
- 自动封禁事件 `score` 改为累计分（`outcome.score`），不再传 `status.offenses`。
- `Server::new(None)` → `Server::new(Some(opts))`，`opts.upstream_read_timeout` 取配置（默认 300s）。

### 5.4 `crates/store/src/lib.rs`

- `Event` 增加 `risk_tags: String` 与 `with_risk_tags()`。
- `migrate()`：`CREATE TABLE events` 增加列；`ensure_column(&conn, "events", "risk_tags", "TEXT NOT NULL DEFAULT ''")`。
- `insert_event` 与所有 `SELECT`/行映射补 `risk_tags`。

### 5.5 `crates/config/src/model.rs`

- `ChallengeConfig` 增加（均带 `#[serde(default)]`）：
  - `slider: bool = false`
  - `risk_challenge_threshold: u32 = 30`
  - `risk_block_threshold: u32 = 60`
- `ServerConfig` 增加 `upstream_read_timeout: Duration = 300s`。
- `configs/example.yaml` 同步示例。

### 5.6 `crates/admin/static/index.html`

- 事件表增加“风险标签”列；`score` 列按 `kind` 显示不同表头。
- 系统设置「人机验证」增加滑块开关与两个阈值输入。
- 保存时沿用现有 settings 写入路径，不新增接口。

## 6. 验收

1. `cargo test --workspace` 通过；新增 challenge 单测覆盖伪造 fp / 信号缺失 / v2 token。
2. `cargo clippy --workspace --all-targets -- -D warnings` 无告警。
3. 本地构造：
   - 带合法 fp 的挑战通过；
   - 篡改 `sig` → 403 且事件 `risk_tags` 含 `fingerprint_forged`；
   - 同一 fp 换 3 个 IP → 出现 `fingerprint_replay`；
   - `/.homewaf/challenge` 命中自定义 Challenge 规则时不再被二次挑战；
   - 5 次失败后第 6 次返回 429。
4. 生产回归：
   - 部署后 `/opt/homewaf/data/logs/security/` 不再出现 `feed:pub-firehol-l1:22|1489`；
   - 事件表出现 `challenge` 记录且 `score != 0`；
   - `GET /websocket` 不再 60s 断开（观察 10 分钟）；
   - 事件列表能显示风险标签。

## 7. 不在本期范围

- 滑块 UI 与图片池实现（仅设计 + token 字段预留）。
- JA4/JA3、HTTP/2 指纹、ASN/GeoIP 机房判定。
- 内网客户端伪造 `xxxxxxx-Real-Forwarded-For` 的加固。
- 上游 4xx 反哺扫描识别（需上游日志与 WAF 事件做离线关联，单独评估）。
