# Tasks: 应用声明端口的热监听

## 1. 端口推导修正
- [x] `crates/proxy/src/server.rs` `request_filter`：新增 `resolve_request_port(host, local_port, is_tls)`，
      Host 带端口优先 → 连接实际落地端口 → 按 TLS 猜测
- [x] 单测：`host_port_wins_over_local_port`、`falls_back_to_local_port_when_host_has_none`、
      `falls_back_to_scheme_default_without_local_port`

## 2. 声明端口聚合
- [x] 新增 `port_of_addr(&str) -> Option<u16>`
- [x] 新增 `app_declared_ports(apps: &[Application]) -> BTreeMap<u16, bool>`
  - 只取 `enabled == true` 且 `!listen_ports.is_empty()`
  - `bool` = 端口上存在 `tls.mode != TlsMode::Off` 的应用
- [x] 单测：TLS/明文聚合、禁用应用被过滤、`port_of_addr` 变体

## 3. 动态监听
- [x] 新增 `NeverShutdown`（`impl pingora::server::ShutdownSignalWatch`，`recv()` 用 `std::future::pending()`）
- [x] 新增 `spawn_listener_server(state, ports)`：独立线程、独立 `Server::new(None)`、
      一个 `http_proxy_service`、`[::]:port` 绑定，TLS 端口复用 `SniResolver` + `NoTlsCallbacks`，
      `alpn` 按 `settings.tls.alpn` 决定是否 `enable_h2`
- [x] 新增 `spawn_dynamic_port_watcher(state, reserved, interval)`：
      循环 → `app_declared_ports` 去掉 `reserved` 与已绑定 → 新端口 `TcpListener::bind` 探测 →
      成功则记录并 spawn，失败 warn（只报一次）下轮重试
- [x] `run()` 中静态监听器之后启动 watcher（`reserved` 来自 `settings.listen`/`tls_listen` 的端口）
- [x] 集成测试 `watcher_binds_declared_ports_and_hot_adds`：先绑 p1，再替换状态追加 p2，
      断言 p1 不受影响、p2 被热监听

## 4. 文档
- [x] `docs/functional-spec.md` 增加 AC-25（声明端口热监听 + 端口回退）与 AC-26（端口被占用）
- [x] `docs/functional-spec.md` 增加 AC-27~29：保存应用时的端口占用校验

## 4.1 保存时端口校验（追加需求）
- [x] `crates/admin/src/lib.rs` 新增 `addr_port` / `parse_proc_listen` / `os_listen_ports` / `check_listen_ports`
- [x] `validate_app` 接入校验：80/443 共享放行、管理端口拒绝、其他应用占用拒绝、`/proc` 系统占用拒绝
- [x] 编辑自身时跳过「自己原先声明的端口」误报
- [x] 单测 6 个：proc 解析、地址取端口、默认端口共享、应用占用、系统占用、自身端口、管理端口

## 5. 验证
- [x] `cargo clippy -p homewaf-proxy --all-targets -- -D warnings` 无告警
- [x] `cargo test -p homewaf-proxy --lib` 128 passed
- [x] `cargo test -p homewaf-admin --lib` 83 passed
- [x] 交叉编译 x86_64-unknown-linux-gnu，部署到 10.0.0.31（备份库 `homewaf.db.bak-*`）
- [x] 生产：`ss -lntp` 显示 homewaf 持有 `[::]:5667`（日志 `listen=[::]:5667 mode="https"`），
      `curl https://fn.niao.fun:5667/`（Host 无端口）返回 200 且日志 `app_id="lei-1"`
- [x] 生产：5667 证书校验通过（不带 `-k` 返回 200），80/443 回归 200，IP 直连仍 403，未声明端口 9000 不可连
- [x] 多 Server 同进程运行稳定：重启后主服务 + 动态监听服务均正常，无 panic、无线程异常
- [x] 端到端（生产机临时实例 + 默认 admin/admin，用完即删）：
      `8006`→400 系统占用、`19445`→400 管理面、`18082`→200 静态共享、`5667`→400 系统占用
- [x] 修正 `AdminState.admin_addr`：管理端口取命令行实际生效值，避免热重载后 `server.admin` 被数据库配置覆盖导致漏判
