# 应用声明端口的热监听 Spec

## Why

应用配置里的 `listen_ports` 目前只参与路由匹配，代理进程从不真正绑定这些端口。
部署只绑 `--listen`（80）与 `--tls-listen`（443），因此公网回源到自定义端口（如 5667）时，
流量要么被别的服务接走，要么直接 connection refused——应用规则完全没机会命中。

同时端口推导只看 Host 头：`Host` 不带端口时按 TLS 与否猜成 443/80，
在自定义端口（5667）下必然猜错，导致声明了 `listen_ports=[5667]` 的应用也匹配不上。

目标：**应用声明了哪些端口，WAF 就监听哪些端口，且改配置后无需重启。**

## What Changes

- `crates/proxy/src/server.rs`
  1. 新增纯函数 `port_of_addr(&str) -> Option<u16>`：从 `[::]:5667` / `0.0.0.0:5667` 之类地址取端口。
  2. 新增纯函数 `app_declared_ports(&[Application]) -> BTreeMap<u16, bool>`：
     遍历**已启用**应用的非空 `listen_ports`，`bool` 表示该端口是否需要 TLS
     （该端口上任一应用 `tls.mode != TlsMode::Off` 即为 TLS；全部 `Off` 才是明文）。
  3. 新增 `struct NeverShutdown`（`impl pingora::server::ShutdownSignalWatch`，`recv()` 永久 pending）：
     动态端口的 Server 实例不参与进程信号处理，随主进程一起退出。
  4. 新增 `fn spawn_listener_server(state, ports: Vec<(u16, bool)>)`：
     独立线程内 `Server::new(None)` → 一个 `http_proxy_service` → 对每个端口
     `add_tcp("[::]:{port}")`（明文）或 `add_tls_with_settings`（TLS，证书解析器复用
     `crate::tls::SniResolver`，每次握手读当前状态，证书热生效）→ `server.run(RunArgs { shutdown_signal: Box::new(NeverShutdown) })`。
     不调用 `bootstrap()`（`upgrade=true` 才会去接管 fd，这里不需要）。
  5. 新增 `fn spawn_dynamic_port_watcher(state, reserved: BTreeSet<u16>, interval)`：
     每 `interval` 计算一次 `app_declared_ports`，对「未绑定且未被静态监听覆盖」的端口先
     `std::net::TcpListener::bind("[::]:{port}")` 探测（成功立刻 drop），成功才
     `spawn_listener_server` 并记入已绑定集合；失败 `warn` 并在下一轮重试。已绑定端口不回收。
  6. `run()`：静态监听器添加完之后、`server.run_forever()` 之前启动 watcher，
     `reserved` = `settings.listen` ∪ `settings.tls_listen` 的端口，`interval` = `settings.watch_interval`。
  7. `request_filter` 端口推导修正（当前 432-433 行）：
     `extract_port(&raw_host).or(session.server_addr().map(|a| a.port())).unwrap_or(if is_tls {443} else {80})`。
     `Session` 通过 `Deref<Target = HttpSession>` 暴露 `server_addr()`。

- `docs/functional-spec.md`：新增一条验收要求（AC-14）描述热监听行为。

## Impact

- Affected specs: 应用路由（`listen_ports` 语义）、TLS 终止
- Affected code: `crates/proxy/src/server.rs`、`docs/functional-spec.md`
- 不改配置模型、不改数据库结构、不改 `Router` 的端口匹配语义

## ADDED Requirements

### Requirement: 应用声明端口必须被监听

系统 SHALL 监听所有已启用应用 `listen_ports` 的并集（显式排除已被
`server.listen` / `server.tls_listen` 覆盖的端口），并在热重载后自动为新出现的端口建立监听。

#### Scenario: 新增自定义端口
- **WHEN** 某应用配置 `listen_ports=[5667]` 并触发配置重载
- **THEN** 进程在 2 秒内开始在 `[::]:5667` 监听，日志输出 `listen = [::]:5667, mode = https`

#### Scenario: 端口已被占用
- **WHEN** 声明的端口已被本机其他进程占用
- **THEN** 记录 warn 日志，主监听（80/443）不受影响，watcher 继续重试

#### Scenario: 删除端口
- **WHEN** 应用从 `listen_ports` 中移除某个已绑定端口
- **THEN** 该端口保持监听直到进程重启（本次不实现热卸载，日志提示需重启）

### Requirement: 端口实际落地端口优先于 Host 头

系统 SHALL 在 Host 头未携带端口时，用连接实际到达的本地端口做 `listen_ports` 匹配。

#### Scenario: 端口映射回源
- **WHEN** 公网 443 映射到源站 5667，客户端请求行无端口、`Host: fn.niao.fun`
- **THEN** 按端口 5667 匹配应用，命中配置了 `listen_ports=[5667]` 的应用而不是返回 403

### Requirement: 每端口的明文/TLS 判定

系统 SHALL 按端口聚合：该端口上有任一应用 `tls.mode != Off` 则按 TLS 监听，全部 `Off` 才按明文监听。

#### Scenario: 混合声明
- **WHEN** 端口 8080 上应用 A 为 `auto`、应用 B 为 `off`
- **THEN** 8080 按 TLS 监听，B 的应用级 TLS 关闭语义仍由路由/策略层处理

### Requirement: 保存应用时校验监听端口占用

系统 SHALL 在保存应用（新建/编辑）时校验 `listen_ports`：

- 80/443 是程序默认的静态监听端口，所有应用共享，重复声明不算冲突；
- 管理面端口不可被应用占用；
- 其他端口若已被其他应用声明，或已被系统其他进程 LISTEN（Linux 读 `/proc/net/tcp{,6}` 的状态 0A），
  保存失败并给出明确提示，不等到运行时静默绑不上。

#### Scenario: 与其他应用抢端口
- **WHEN** 应用 B 保存时声明 `listen_ports=[5667]`，而应用 A 已声明 5667
- **THEN** 保存失败，提示「端口 5667 已被应用 `A` 占用，请换一个端口」

#### Scenario: 与系统进程抢端口
- **WHEN** 应用声明 8006，而主机上已有其他进程监听 8006
- **THEN** 保存失败，提示「端口 8006 已被系统其他进程占用，请换一个端口」

#### Scenario: 编辑应用自身
- **WHEN** 应用 A 编辑后仍保留自己原先声明的端口（监听器还在本进程手里）
- **THEN** 保存成功，不误报端口冲突

## MODIFIED Requirements

无（`Router::resolve` 的匹配逻辑保持不变：未声明端口仍接受任意端口）。

## REMOVED Requirements

无

## 方案选择（最小影响）

先明确「中断」从哪里来：80/443 已经在监听，**唯一的变化是新增端口**，
而新增端口在公网映射生效前本来就没有流量。因此按下面顺序取代价最小者：

| 方案 | 中断 | 复杂度 | 说明 |
| --- | --- | --- | --- |
| A. 进程内独立 Server，只绑新增端口 | 0 | 中 | 80/443 不受影响；新增端口起来即可用 |
| B. 进程级热重启（exit 后 systemd 拉起） | 1~3 秒全站 | 低 | 存在停止→启动的空窗，且旧进程未完全退出时会 EADDRINUSE |
| C. SO_REUSEPORT 滚动升级 / fd 交接 | 0 | 高 | nginx/HAProxy 的常规做法，需要改 unit 或自管多进程与排空 |

结论：主方案取 **A**。理由——它只影响「本来还没流量的端口」，等价于零中断；
而 B 为了加一个监听端口会打断全部线上流量，与「最小影响」相悖，仅作退化路径。
C 在单机、systemd `Restart=always` 的现网形态下收益不足以抵消复杂度，本次不做。

**常规最小影响做法**（供对照）：成熟网关在运行时改监听，主流是
「worker 进程继承/共享监听 fd（SO_REUSEPORT 或 fd 交接）+ 新进程就绪后旧进程排空退出」，
即不用停服、也不靠重启。本方案 A 是它的轻量替代：监听集合只会追加，旧监听器从不重建。

**退化路径**：若实测发现同进程内第二个 Pingora `Server` 不稳定（线程/运行时冲突），
watcher 在检测到端口集合变化时改为 `std::process::exit(0)`，依赖生产 unit 已有的
`Restart=always` + `RestartSec=3` 自动拉起，中断约 1~3 秒。该路径需在实测后二选一，
不允许两套同时生效。

## Out of Scope

- 已绑定端口的热卸载
- 每端口独立证书绑定（继续走 SNI 解析器）
- 管理面端口（9443，独立线程监听，不纳入代理动态监听）
- SO_REUSEPORT 滚动升级 / 自管 worker 排空（方案 C）

## Verification

1. `CARGO_NET_OFFLINE=true ~/.cargo/bin/cargo clippy --all-targets` 与 `cargo test` 通过
   （新增单测：`port_of_addr` 变体、`app_declared_ports` 的 TLS/明文聚合与禁用应用过滤、端口推导回退顺序）。
2. 交叉编译部署到 10.0.0.31（`zigbuild` + scp 到 `/opt/homewaf/homewaf.new`，stop → mv → start）。
3. 生产实测：给应用配置 `listen_ports=[5667]` → 2 秒内 `ss -lntp | grep 5667` 有 homewaf；
   `curl -k --resolve fn.niao.fun:5667:10.0.0.31 https://fn.niao.fun:5667/` 命中应用（非 403 unknown-host）。
4. 回归：80/443 正常，IP 直连仍 403 且落 ACL 事件。
5. 告知用户：仍需在 iKuai 把 WAN 5667 指向 `10.0.0.31:5667`，公网链路才真正打通。

## 风险

- 一个进程内出现多个 Pingora `Server` 实例属非官方推荐用法；本方案用 `NeverShutdown`
  与不调用 `bootstrap()` 规避信号与 fd 接管副作用。若实测线程/运行时异常，按上文
  「方案选择」的退化路径改为 `process::exit(0)`，由 systemd `Restart=always` 拉起，
  中断约 1~3 秒；两条路径实测后二选一。
