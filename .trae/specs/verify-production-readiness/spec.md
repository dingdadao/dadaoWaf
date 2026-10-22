# 生产环境验收测试 Spec

## Why
生产环境（10.0.0.31）已部署，需要以资深测试 / 安全测试 / 性能测试的视角完成功能、安全、性能三项验收，
发现缺陷立即修复并复测，全部达标后重新部署并输出生产测试报告随代码提交。

## What Changes
- 修复上游连接失败不重试的问题：`fail_to_connect` 按应用 `retry` 配置显式 `set_retry(true)`（坏上游 + 好上游场景应稳定 200）
- 修复 Header 类检测规则永不触发的问题：`InspectionInput.headers` 传入请求头（排除 host/cookie/user-agent/content-length）
- 复测 D1（健康检查期望）、D2（监听地址展示）、D3（运算符路由）、D4（非法配置回滚）、D5（重试）、D6（CRLF 拒绝）、D7（注入规则）
- 安全用例在临时禁用雷池同步来的“局域网白名单”规则后执行，执行完恢复
- 性能复测：持续压测 50k 请求不再出现 503「无可用上游」突发
- 新增 `docs/production-test-report.md`，补充 `docs/dev-log.md`

## Impact
- Affected specs: 代理重试、应用层检测
- Affected code: `crates/proxy/src/server.rs`、`crates/proxy/src/upstream.rs`、`crates/admin/src/leichi.rs`、
  `crates/config/src/validate.rs`、`crates/detect/src/rule.rs`

## ADDED Requirements
### Requirement: 连接失败按应用策略重试
系统 SHALL 在上游连接失败时，若应用 `retry.enabled`、命中 `connect_error`、方法在 `retry.methods` 内且未超过 `retry.attempts`，
改用同应用内另一上游重试，而不是直接返回 502。

#### Scenario: 坏上游 + 好上游
- **WHEN** 应用有两个上游，其中一个端口未监听，客户端 GET 请求
- **THEN** 请求最终返回 200，且访问日志中上游为可用的那个

### Requirement: Header 类规则可命中
系统 SHALL 将请求头（除 host/cookie/user-agent/content-length）纳入检测，使 `Target::Header` 规则可生效。

#### Scenario: Log4j JNDI 藏在自定义头
- **WHEN** 请求头 `X-Api-Version: ${jndi:ldap://127.0.0.1/a}` 发往受保护应用
- **THEN** 返回 403 并写入安全事件

## MODIFIED Requirements
### Requirement: 检测白名单语义
雷池同步的白名单自定义规则命中时，请求完全跳过应用层检测（含 body），仅记录 debug 日志。
验收测试需临时停用该规则，测试后恢复启用。

## REMOVED Requirements
无
