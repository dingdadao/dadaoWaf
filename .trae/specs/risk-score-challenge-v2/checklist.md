# 验收清单

## 风险模型
- [x] `RiskTag` 九个标签权重与 hard 标记符合 spec 4.1
- [x] `RiskTable` 600s 窗口过期后分数归零，阈值边界 Normal/Challenge/Block 正确
- [x] 同一指纹 600s 内出现第 3 个 IP 时触发 `FingerprintReplay`
- [x] 配置写反（block <= challenge）时自动归一化为 challenge + 1

## 挑战链路
- [x] 令牌 v2 携带 `k/s/x`，旧 v1 令牌返回 `Malformed`
- [x] 服务端按 13 段 `sig` 重算指纹，与回传 `fp` 不一致返回 `FingerprintForged`
- [x] `env` 的 wd/cdp 与 `sig` 前两位不一致返回 `FingerprintForged`
- [x] 缺少 `sig`/`fp` 返回 `SignalsMissing` 或 `BadFingerprint`
- [x] PoW 使用服务端重算指纹校验
- [x] 1 分钟内第 6 次失败返回 429，验证成功后计数清零

## 服务端处置
- [x] `WafProxy` 持有 `RiskTable`，hard 标签或 Block 等级写入 `BanTable`
- [x] 挑战 issue/pass/fail 三类事件落库，`score` 为风险分并带 `risk_tags`
- [x] `require_challenge` 与风险 Challenge 等级都能触发挑战页
- [x] 自定义 `Deny` 累加 25 分，CC 命中累加 10 分
- [x] `/.homewaf/challenge` 跳过自定义规则求值，不会二次挑战
- [x] 自动封禁事件 `score` 使用累计分而非 offenses
- [x] 上游读超时取自配置并作用到 `HttpPeer`

## 存储与配置
- [x] `events.risk_tags` 列存在，旧库启动不报错，新事件能读回标签
- [x] `challenge.slider/risk_challenge_threshold/risk_block_threshold` 有默认值
- [x] `server.upstream_read_timeout` 有默认值且 `example.yaml` 已同步

## 管理面
- [x] 事件列表展示风险标签，分数列表头按 kind 区分
- [x] 人机验证设置含滑块开关与两个风险阈值，保存后写入 settings

## 工程校验
- [x] `cargo fmt --all -- --check` 通过
- [x] `cargo clippy --workspace --all-targets -- -D warnings` 通过
- [x] `cargo test --workspace` 全部通过
