# 任务清单

> 严格按顺序执行；每项完成即更新状态。生产部署放在最后，需单独确认。

## [x] T1 风险模型模块
- 文件：`crates/proxy/src/risk.rs`（新增）、`crates/proxy/src/lib.rs`
- 内容：
  - `RiskTag` 枚举 + `weight()` + `hard()` + `as_str()`
  - `RiskAssessment { tags, score, hard }`
  - `RiskLevel { Normal, Challenge, Block }`，阈值由 `ChallengeConfig` 传入
  - `RiskTable`：600s 窗口聚合、`add`、`level`、`bump_replay`
- 验收：`cargo test -p homewaf-proxy risk::` 覆盖窗口衰减、阈值边界、replay 判定。

## [x] T2 挑战令牌 v2 + 服务端重算指纹
- 文件：`crates/proxy/src/challenge.rs`
- 内容：
  - `TOKEN_VERSION = 2`；`TokenPayload` 增 `k/s/x`
  - `Solution` 增 `sig`
  - `fp_from_signals(app, sig) -> Option<String>`
  - `verify()` 增加 fp 重算比对、env/sig 一致性、用服务端 fp 校验 PoW
  - 新错误 `FingerprintForged` / `SignalsMissing`
  - `issue()` 增加 `level` 参数
  - `render_page()` 输出 `app`、`sig`，按同一公式算 `fp`，补 `deviceMemory/platform/plugins.length`
- 验收：新增单测全绿；旧 v1 token 返回 `Malformed`。

## [x] T3 挑战失败限速
- 文件：`crates/proxy/src/challenge.rs`、`crates/proxy/src/server.rs`
- 内容：
  - `ChallengeService.attempts`（1 分钟 5 次失败）
  - `record_failure(ip, now) -> bool`、`reset_failures(ip)`
  - 回调失败超额返回 429
- 验收：单测模拟 6 次失败，第 6 次返回超额；成功一次后计数清零。

## [x] T4 服务端集成风险处置
- 文件：`crates/proxy/src/server.rs`
- 内容：
  - `WafProxy` 增 `risks: RiskTable`
  - 挑战 issue/pass/fail 三类事件落库，`score` 为风险分
  - hard 标签 / Block 等级 → `bans.record`
  - `require_challenge` 追加风险等级判断
  - 自定义规则 `Deny` → `risks.add(ip, 25)`；CC → `risks.add(ip, 10)`
  - `ban` 事件 `score` 改为累计分
  - `uri_path == CHALLENGE_PATH` 时跳过自定义规则求值（修复自锁）
- 验收：本地起服务，构造自定义 Challenge 规则命中 `/.homewaf/challenge`，回调能正常完成、不再二次挑战。

## [x] T5 存储风险标签
- 文件：`crates/store/src/lib.rs`
- 内容：
  - `Event.risk_tags` + `with_risk_tags`
  - `migrate()` 建表列 + `ensure_column`
  - `insert_event`、查询与行映射补齐
- 验收：老库（含现有 events）启动不报错；新事件能读回 `risk_tags`。

## [x] T6 配置与示例
- 文件：`crates/config/src/model.rs`、`configs/example.yaml`
- 内容：
  - `ChallengeConfig` 增 `slider=false`、`risk_challenge_threshold=30`、`risk_block_threshold=60`
  - `ServerConfig` 增 `upstream_read_timeout=300s`
- 验收：`cargo test -p homewaf-config`；缺失字段的旧配置能正常反序列化。

## [x] T7 WebSocket 读超时
- 文件：`crates/proxy/src/server.rs`
- 内容：`Server::new(None)` → `Server::new(Some(opts))`，`opts.upstream_read_timeout` 读取配置。
- 验收：本地起 WS 服务，空闲 90s 不被断开；普通 HTTP 不受影响。

## [x] T8 管理面展示
- 文件：`crates/admin/static/index.html`
- 内容：
  - 事件表增“风险标签”列
  - `score` 表头按 kind 显示“风险分 / QPS / 累计分”
  - 人机验证设置增滑块开关与两个阈值
- 验收：页面加载无 JS 报错；阈值保存后 settings 表中 `challenge` 出现新字段。

## [x] T9 全量校验
- 命令：
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
- 验收：全部通过。

## T10 生产部署与回归
- 前置：用户确认。
- 步骤：
  1. `cargo build --release --target x86_64-unknown-linux-gnu`
  2. `scp target/x86_64-unknown-linux-gnu/release/homewaf root@10.0.0.31:/opt/homewaf/bin/homewaf.new`
  3. 备份现有二进制，替换，`systemctl restart homewaf`
  4. 回归：
     - `security/` 不再出现 FireHOL 内网误伤；
     - 事件表出现 `challenge` 且 `score != 0`；
     - `/websocket` 空闲 90s 不断；
     - 管理面事件列表可见风险标签。
- 回滚：恢复 `/opt/homewaf/bin/homewaf.bak.*` 后重启。

## [x] T11 提交
- 用户确认后：`git add` 指定文件 → 提交（不推送，除非用户明确要求）。
