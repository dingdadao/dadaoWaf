# HomeWAF 实现说明

| 项目 | 内容 |
|---|---|
| 文档定位 | 记录**怎么实现的**与**为什么这么实现**，供后续开发与架构回溯 |
| 与其它文档的关系 | PRD 回答"为什么做"，`functional-spec.md` 回答"做什么"，本文回答"怎么做" |
| 更新时机 | 每完成一个模块、每做一个影响架构的决策 |

---

## 1. 模块划分与依赖方向

```
crates/
├── config/     配置模型与校验       纯数据，无 IO
├── router/     域名与路径匹配       纯逻辑，无 IO
├── proxy/      Pingora 集成         唯一做网络 IO 的模块
├── acl/        IP 前缀树与黑白名单   纯逻辑，无 IO          （待实现）
├── detect/     检测引擎             纯逻辑 + 正则            （待实现）
└── cli/        命令行入口
```

**依赖必须单向**：

```
cli → proxy → router → config
```

下层不得依赖上层。`config` 不认识任何运行时概念，`router` 只读 `config` 的数据结构，不做 IO。

**为什么这样切**：网络层最难测、最容易出竞态。把纯逻辑全部下沉到无 IO 的 crate，可以用普通单元测试覆盖 90% 的行为，`proxy` 只保留"接线"工作。这样即使 Pingora 的 API 变动，受影响的也只有 `proxy` 一个 crate。

---

## 2. 已实现：config

### 2.1 文件结构

| 文件 | 职责 | 行数 |
|---|---|---|
| `model.rs` | 全部配置结构体，与 YAML 一一对应 | ~1100 |
| `validate.rs` | 语义校验（域名冲突、前缀长度、引用完整性） | ~960 |
| `units.rs` | `Duration` / `Size` 自定义类型与解析 | ~290 |
| `error.rs` | 错误类型、字段路径、严重级别 | ~120 |
| `lib.rs` | 入口：`parse` / `from_str` / `load` | ~210 |

### 2.2 数据流

```
YAML 文本
   │  serde_yaml + serde_path_to_error
   ▼
Config 结构体（未知字段在此报错，带行号列号）
   │  validate()
   ▼
ValidationReport { errors, warnings }
   │  errors 非空 → 返回 ConfigError::Validation
   ▼
Config（有效）
```

### 2.3 三个关键实现细节

**（1）`Option<T>` 表示"未指定"，而不是填默认值**

`ProtectionConfig` 的 17 个开关全是 `Option<Toggle>`。原因是要支持三层覆盖（route > application > global）：如果解析时就把 `None` 填成 `Block`，就无法区分"用户显式写了 block"和"用户没写"。

真正的默认值在**合并阶段**才填充，不在解析阶段。

**（2）`Duration` / `Size` 手写 `Deserialize`**

配置里写 `30s`、`2GB`，比写 `30000`、`2147483648` 可读得多。两个类型都实现了 `Display`，序列化时输出回人类可读形式，保证往返稳定（有测试守着）。

**（3）错误必须带路径**

`serde_path_to_error` 给出 `applications[0].upstreams[1].port` 这样的路径，`serde_yaml` 给出行列号，两者拼起来：

```
第 9 行第 5 列 [applications[0].unknow_field] unknown field `unknow_field`,
expected one of `id`, `name`, `enabled`, ...
```

未知字段会列出全部合法字段——拼错时能直接看出该写什么。

### 2.4 新增一个配置项的步骤

1. 在 `model.rs` 对应结构体加字段，带 `#[serde(default)]`（若是 `Option` 则不必）
2. 如果需要默认值，在 `impl Default` 里写
3. 在 `validate.rs` 加校验（边界、引用、冲突）
4. 在 `crates/config/tests/edges.rs` 加边界用例
5. 更新 `configs/example.yaml` 与 `docs/functional-spec.md`

---

## 3. 已实现：router 与 proxy

### 3.1 职责

把请求的 Host 与 Path 映射到「哪个应用、哪条路由」。

### 3.2 域名匹配

优先级：**精确（含别名）> 通配 > 正则 > 未匹配**。

规范化顺序（顺序不能变）：

```
原始 Host
  → 去空白
  → 去端口（[::1]:443 与 a.com:8080 都要处理）
  → 转小写
  → 去末尾点
  → 得到规范化域名
```

通配符语义：`*.home.lan` **只匹配一级**（`a.home.lan`），不匹配 `a.b.home.lan`，也不匹配 `home.lan`。

### 3.3 路径匹配

五种类型，优先级与 Nginx 一致：

| 优先级 | 写法 | 说明 |
|---|---|---|
| 1 | `= /p` | 精确 |
| 2 | `^~ /p` | 最长前缀命中后**不再试正则** |
| 3 | `~ pat` / `~* pat` | 按配置顺序，首个命中 |
| 4 | `/p` | 最长前缀 |
| 5 | `/` | 兜底 |

**算法**（必须严格按此实现，否则与用户预期不符）：

```
1. 精确匹配命中 → 返回
2. 求最长前缀 P（同时记录它是否 ^~）
3. 若 P 是 ^~ → 返回 P
4. 按顺序试正则，命中 → 返回
5. 有 P → 返回 P
6. 返回默认路由 "/"
```

### 3.4 路径规范化（安全关键）

```
原始路径
  → 截掉 ?query 与 #fragment
  → 百分号解码（单层，非法序列保留原样）
  → 按 / 分段
  → 每段去掉 ; 之后的内容（路径参数）
  → 处理 . 与 ..（.. 在栈空时忽略，不能跳出根）
  → 重新拼接，保留尾斜杠
```

**为什么必须在检测前做**：如果 WAF 检测用的是规范化路径、转发用的是原始路径，就会出现 `//api/../admin` 检测看到 `/admin`、后端收到 `/api/../admin` 的绕过。**规范化结果必须同时用于检测与转发**。

### 3.5 调试方式

`homewaf route` 会走完整的规范化 + 匹配流程，可以直接用来验证绕过是否被挡住：

```bash
$ homewaf route configs/example.yaml nas.home.lan "//api/../admin/x"
请求: nas.home.lan//api/../admin/x
  应用: NAS 管理 (nas)
  规范化路径: /admin/x
  路由: /admin [前缀]
  上游1: http://192.168.1.5:5000 weight=1
```

写新规则或排查"为什么走了这个上游"时，先跑这个命令，比读日志快。

### 3.6 代理层（proxy）

基于 Pingora 0.9，用 `rustls` 后端（纯 Rust，不需要编译 BoringSSL）。

**用到的钩子**（`ProxyHttp` trait）：

| 钩子 | 用途 |
|---|---|
| `new_ctx` | 创建每请求上下文，记录开始时间 |
| `request_filter` | 提取 Host、解析路由、未匹配直接返回 404 |
| `upstream_peer` | 按 ctx 里的决策构造 `HttpPeer` |
| `upstream_request_filter` | **把路径替换为规范化结果**（ADR-008） |
| `logging` | 输出访问日志（方法、路径、状态、上游、耗时） |

**为什么不用 `response_filter` 做安全头**：等检测引擎接入后再统一处理，现在只做转发，避免过早引入复杂度。

**端到端验证**（`configs/test.yaml`，两个 Python 上游）：

| 场景 | 结果 |
|---|---|
| `Host: nas.home.lan` `/hello` | → 18081，`path=/hello` |
| `Host: alias.home.lan` `/x` | → 18081（别名生效） |
| `Host: nas.home.lan` `/other/thing` | → 18082（路径路由生效） |
| `Host: evil.com` | 404，不泄露后端 |
| `//x/../other/a` | → 18082，上游收到 `/other/a`（规范化生效） |
| `/other/p?x=1&y=2` | → 18082，query 保留 |

实测延迟（本地回环）：456-2150 μs，含 Python 上游的处理时间。

### 3.7 转发头与真实 IP 还原

两个模块：`realip.rs` 负责"客户端到底是谁"，`headers.rs` 负责"怎么告诉后端"。

**解析顺序**：

```
直连 IP
  ├─ real_ip 未启用 → 直接用直连 IP
  ├─ 直连 IP 不在 trusted_proxies → 直接用直连 IP（头部完全不看）
  └─ 直连 IP 可信 → 按 header_priority 依次尝试
        CF-Connecting-IP → True-Client-IP → X-Real-IP → X-Forwarded-For
        首个能解析出合法 IP 的生效
```

**XFF 从右往左解析**：XFF 是追加式头部，最右侧是最后一个代理追加的，最接近真实。从左往右会被客户端注入的假 IP 欺骗。

**为什么"不可信来源完全不看头部"**：这是最简单也最可靠的做法。只要直连 IP 不在可信段，无论客户端发什么 `CF-Connecting-IP` 都无效——比"逐个头校验"更难绕过。

**注入规则**：

| 头 | 行为 |
|---|---|
| `X-Real-IP` | 始终覆盖为还原后的 IP |
| `X-Forwarded-For` | 可信来源**追加**（保留上游代理链），不可信来源**替换**（丢弃伪造） |
| `X-Forwarded-Proto` | 按连接是否 TLS 设置 |
| `X-Forwarded-Host` | 原始 Host（不含端口） |
| `X-Forwarded-Port` | 原始端口，缺省按协议补 80/443 |

**私有地址不再被过滤**：最初的实现会把 XFF 里的私有地址当作"注入"丢弃，但内网代理链（如 Cloudflare Tunnel 后面的内网客户端）会合法地传私有地址，过滤会导致真实 IP 丢失。现在改为信任可信代理传来的一切合法 IP。

**端到端验证**：

| 场景 | 结果 |
|---|---|
| real_ip 关闭，客户端伪造 `XFF: 1.2.3.4` | 上游收到 `x-forwarded-for: 127.0.0.1`（伪造被丢弃） |
| real_ip 开启，`CF-Connecting-IP: 203.0.113.42` | `x-real-ip: 203.0.113.42`，`x-forwarded-for: 1.2.3.4, 203.0.113.42`（追加） |
| `XFF: 1.1.1.1, 2.2.2.2, 127.0.0.1` | 取 `2.2.2.2`（从右往左跳过可信段） |
| `X-Forwarded-Proto/Host/Port` | `http` / `nas.home.lan` / `80` |

**踩坑**：Python 回显脚本用 `{k: v for k, v in headers.items()}` 会丢掉重复头，导致"追加"看起来像"替换"。测试脚本必须合并同名头，否则会误判。

### 3.8 性能实测（M0 压测）

**环境**：Apple Silicon（arm64）、release 构建、单机回环、无 TLS、`ab -n 20000 -c 100 -k`。
**上游**：Python 裸 socket 服务（固定 2 字节响应），本身可跑到 49.8k RPS，确保不是瓶颈。

| 场景 | RPS | 平均延迟 | 99% 分位 | 失败 |
|---|---|---|---|---|
| 直连上游（baseline） | 49,805 | 2.008 ms | 7 ms | 0 |
| **经 HomeWAF 转发** | **27,254** | 3.669 ms | 5 ms | 0 |
| HomeWAF 自身（未配置域名 → 404，不打上游） | 65,259 | 1.532 ms | — | 0 |

**解读**：

- 转发 27.2k RPS，是 M0 目标（5k）的 **5.4 倍**，PRD 里"4 核 25k RPS"的目标也已达到
- 相比直连下降 45%，这是加上完整代理层（域名匹配 + 路径规范化 + 转发头注入 + 上游连接复用）的代价
- 404 路径 65k RPS，说明 Pingora + 路由本身的开销很小；转发慢下来主要是多了一跳上游
- 单请求增量约 1.66 ms（3.669 - 2.008），99% 分位反而比 baseline 低（测量波动）

**这个数字的局限**（不能直接对外宣称）：

1. **没有 TLS**。TLS 握手会显著降低短连接吞吐，真实 HTTPS 场景需要重测
2. **上游是 Python**，虽然 baseline 有 49.8k，但仍可能是共同瓶颈
3. **单机回环**，没有真实网络的 RTT 与丢包
4. **没有检测逻辑**，检测引擎接入后才是完整数据
5. 响应体只有 2 字节，大响应场景未测

结论：**代理层的性能已经足够，不会成为产品瓶颈**。后续性能工作的重点应该在检测层（预过滤、降级），而不是继续优化转发。

### 3.9 TLS 终结

**配置方式**：

```yaml
server:
  listen: ["0.0.0.0:80"]           # 明文
  tls_listen: ["0.0.0.0:443"]      # HTTPS，需要证书

tls:
  min_version: "1.2"
  alpn: ["h2", "http/1.1"]
  cert: "/etc/homewaf/cert.pem"
  key: "/etc/homewaf/key.pem"
```

`listen` 与 `tls_listen` 分离，而不是靠端口号猜测。同一进程可以同时监听 80 和 443。

**实现要点**：

- 用 `TlsSettings::intermediate(cert, key)` 加载证书，`enable_h2()` 设置 ALPN 为 `h2, http/1.1`
- **`TlsSettings` 不实现 `Clone`**，每个监听地址各自构造一次（证书通常只读 1-2 次，开销可忽略）
- 校验层：`tls_listen` 非空但缺 `cert`/`key` 时直接报错；只配一个也报错

**导入路径的坑**：`pingora::listeners::TlsSettings` 是私有的，必须用 `pingora::listeners::tls::TlsSettings`（`tls` 子模块才是 `pub mod`）。

**端到端验证**（自签 CA 签发，`/tmp/hw.crt`）：

| 场景 | 结果 |
|---|---|
| `--cacert ca.crt` + SNI `nas.home.lan` | HTTP 200，证书校验通过 |
| 不提供 CA | 连接失败（证书不被信任） |
| 通配符 SAN `photo.home.lan` | TLS 握手成功，应用层 404（未配置该应用，符合预期） |
| 转发头 | `x-forwarded-proto: https`、`x-forwarded-port: 18443` |
| HTTP/2 | HTTP 200，协议协商为 h2 |
| TLS 版本 | TLSv1.3，`TLS_AES_256_GCM_SHA384` |

**测试证书生成**（自签 CA 两步签发，不要用 `-x509` 直接生成服务器证书，那样没有 CA 标志，`--cacert` 验证会失败）：

```bash
# 1. CA
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
  -subj "/CN=HomeWAF Test CA"
# 2. 服务器密钥与 CSR
openssl req -newkey rsa:2048 -keyout hw.key -out hw.csr -nodes -subj "/CN=nas.home.lan"
# 3. 用 CA 签发，必须带 SAN
printf "subjectAltName=DNS:nas.home.lan,DNS:*.home.lan,IP:127.0.0.1\n" > ext.cnf
openssl x509 -req -in hw.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out hw.crt -days 365 -extfile ext.cnf
```

**测试时的坑**：环境里设置了 `https_proxy` 时，`curl` 会走代理去连本地端口，返回 502 且看不出原因。测本地 HTTPS 前必须 `unset https_proxy http_proxy all_proxy`，否则会误判成 TLS 有问题。

**这个坑踩了两次**：第二次是因为只清了小写变量，而环境里还有大写的 `HTTPS_PROXY`。macOS/Linux 的代理环境变量有大小写两套，必须全清：

```bash
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY https_proxy http_proxy all_proxy
```

**HTTP 与 HTTPS 可以同时监听**（这是常态，不是可选）：

```yaml
server:
  listen: ["0.0.0.0:80"]           # 明文，默认为此
  tls_listen: ["0.0.0.0:443"]      # HTTPS，需要证书
tls:
  cert: /path/cert.pem
  key: /path/key.pem
```

启动日志会分别标注：

```
INFO 开始监听 listen=0.0.0.0:80   mode="http"
INFO 开始监听 listen=0.0.0.0:443  mode="https"
```

实测两条链路都正常：HTTP 200 / HTTPS 200（证书校验通过、HTTP/2 协商成功），攻击请求在两种协议下都返回 403。

**默认是纯 HTTP**：`ServerConfig::default()` 里 `listen` 是 80、`tls_listen` 为空。没有证书也能直接用，这符合家用场景——很多人先在局域网 HTTP 跑通，之后再上证书。

### 3.10 ACL 访问控制

**匹配顺序**（越具体越优先）：

```
应用专属白名单 → 应用专属黑名单 → 全局白名单 → 全局黑名单 → 内网网段 → 正常流程
```

**白名单永远优先于黑名单**。用户显式加白某台机器，不应该被自动封禁推翻——否则"我明明加白了还是被封"会让人对产品失去信任。

**数据结构：按前缀长度分桶的哈希表**

```rust
struct PrefixMap<V> {
    v4: Vec<HashMap<u32, V>>,   // 下标 = 前缀长度 0..=32
    v6: Vec<HashMap<u128, V>>,  // 下标 = 前缀长度 0..=128
    v4_lens: Vec<usize>,        // 非空长度，降序
}
```

查找从最长前缀开始，首个命中即返回。不用 radix tree 的理由：家用场景规则量级在千条以内，分桶哈希实现更简单、更少出错；查找最坏 33 次，实际只查已配置的长度（通常 3-5 次）。

**IPv6 必须按前缀聚合**：隐私扩展会让同一台设备不断更换后缀，按 `/128` 封禁等于没封。`ban_key()` 把地址掩码到 `ipv6_prefix_match`（默认 /64），自动封禁时用这个键。

**IPv4-mapped IPv6 归一化**：`::ffff:203.0.113.9` 必须先转成 IPv4，否则会绕过针对 IPv4 的规则。

**规则来源**：静态规则来自配置文件 `acl.rules`；自动封禁与 IP 组订阅的规则后续从数据库加载，走同一个 `AclRule` 结构。

**端到端验证**：

| 场景 | 结果 |
|---|---|
| `127.0.0.1/32` 黑名单 | HTTP 403，日志 `reason=黑名单规则 block-local` |
| `127.0.0.0/8` 黑名单 + `127.0.0.1/32` 白名单 | HTTP 200（更具体的白名单胜出） |
| 内网网段默认 | 放行且跳过检测 |
| 应用专属规则 vs 全局规则 | 应用专属优先 |

### 3.11 IP 组订阅

订阅的风险不是"拉不到"，而是**"拉到了投毒的内容"**——一个被篡改的订阅源如果返回 `0.0.0.0/0`，就能一次性封掉整个互联网。所以护栏不是可选功能，是订阅能力的前置条件。

**三层防护**：

| 层 | 检查 | 失败处理 |
|---|---|---|
| 格式层 | 只接受合法 CIDR / 裸 IP，非法行丢弃并计数 | 保留其余条目 |
| 内容层 | 前缀不能短于 `min_prefix_v4/v6` | 丢弃该条；全被丢则整批拒绝 |
| 变更层 | 与上次相比变动幅度超 `max_delta_ratio` | 整批拒绝，保留旧数据 |

另外两道：`max_entries` 限制条目数、`max_response_bytes` 限制响应体（读取时就用 `take(n+1)` 截断，避免内存被打爆）。

**解析兼容三种结构**：

```json
["1.2.3.0/24"]
{"ips": ["1.2.3.0/24"]}
{"ip_groups": [{"name": "g1", "ips": [...]}]}    // 雷池分享格式
```

文本格式支持 `#` 注释、空行、行尾注释；裸 IP 自动补全为 `/32` 或 `/128`。

**动作映射**：

| 订阅动作 | ACL 行为 |
|---|---|
| `block` | 拒绝 |
| `challenge` | **暂按拒绝处理**（人机验证未实现，放行会失去防护） |
| `log` | 不产生规则 |

**订阅失败不阻塞启动**：拉取/解析/护栏任一步失败，只记 warn 并跳过该组，服务照常用静态规则启动。理由：WAF 的首要职责是"转发正常流量"，不能因为一个外部订阅源挂了就不启动。

**dry-run 命令**（上线前必做）：

```bash
$ homewaf feed https://example.com/list.txt --format cidr
拉取 https://example.com/list.txt
  收到 70 字节
  解析 4 条，跳过 1 行
  护栏：部分接受（保留 3 条，丢弃 1 条前缀过短的）
  示例：
    1.2.3.0/24
    10.0.0.0/8
    203.0.113.42/32
dry-run 完成，未修改任何状态
```

**注意**：`ureq` 会读 `https_proxy` 等环境变量，企业内网环境下订阅会走代理。这是合理行为，但排查"为什么拉不到"时要先确认代理设置。

### 3.12 多上游负载均衡与被动健康检查

**为什么要做**：之前配置里能写多个上游，但代码只取 `first()`——用户以为配了负载均衡，实际没有。这是**静默的功能失效**，比缺功能更糟。

**支持的算法**：

| 算法 | 实现 |
|---|---|
| `round_robin` | 加权序列轮询（权重全 1 时即普通轮询） |
| `weighted` | 同上，按权重重复下标 |
| `least_conn` | 按 `active / weight` 取最小 |
| `ip_hash` | FNV-1a 哈希客户端 IP，同一 IP 固定命中 |

`consistent_hash` 暂等同 `ip_hash`（虚拟节点方案留待规则量级上来后再做）。

**被动健康检查**（不主动探测）：

- 连续失败达 `fail_threshold` → 标记 down
- down 超过 `window` → 放行一次试探（**半开**）
- 试探成功达 `recover_threshold` → 恢复健康

半开是必须的：永久剔除会让上游修好了也永远回不来。

**备份上游**：`backup: true` 的上游只进备份池，主池全部不可用才启用。避免主备混用导致流量倾斜。

**端到端验证**（`fail_threshold=2`、`window=2s`）：

```
正常轮询        18081 18082 18081 18082
停掉 18082     18081  [失败] 18081  [失败] 18081 18081
稳定后          18081 18081 18081
重启 18082 等 3s 18081 18082 18081 18082     ← 半开恢复
```

**踩坑：失败被计两次。** `fail_to_connect` 与 `logging` 两个钩子在连接失败时都会触发，各调一次 `mark_failure` 会让 `fail_threshold` 实际减半——配 2 次失败等于 1 次就剔除。修复方式是只在一个地方计数：`fail_to_connect` 只打日志，统一在 `logging` 里按「有错误或 5xx」统计。

**无可用上游时返回 503 而不是 502**：502 表示"上游返回了坏响应"，503 表示"没有可用上游"，语义更准确，便于排查。

### 3.13 配置热重载

**为什么用轮询 mtime 而不是文件系统事件**：编辑器保存普遍是"写临时文件 + rename"，`notify` 这类事件方案会触发多次并需要 debounce；轮询天然去抖，也不依赖平台特性。间隔 2 秒，对家用场景足够。

**整体替换而非逐项更新**：

```rust
pub struct RuntimeState {
    router: Router,
    acl: Acl,
    pool: UpstreamPool,
    real_ip: RealIpConfig,
}
```

所有组件打包成一个结构，用 `ArcSwap` 原子替换。逐项更新会出现"新路由配旧 ACL"的中间态。

**进行中的请求用快照**：`request_filter` 开头 `load_full()` 拿一份 `Arc<RuntimeState>` 存进 ctx，整个请求生命周期（含 `logging`）都用它。否则热重载瞬间会出现"路由按新配置、上游按旧池"的错配。

**失败处置：保留旧配置，绝不让服务进入半坏状态**。一份写错的配置不应该让正在运行的服务失去防护：

```
INFO  检测到配置变化，开始重载
INFO  配置重载成功，已生效 apps=1 rules=1 upstreams=1
INFO  检测到配置变化，开始重载
ERROR 配置重载失败，继续使用旧配置 error=配置校验失败，共 2 处问题
INFO  检测到配置变化，开始重载
INFO  配置重载成功，已生效 apps=1 rules=0 upstreams=1
```

**热重载覆盖范围**：

| 变更 | 是否生效 |
|---|---|
| 应用、路由、域名 | ✅ |
| ACL 静态规则 | ✅ |
| IP 组订阅 | ✅（会重新拉取） |
| 上游列表、负载均衡算法 | ✅ |
| 真实 IP 配置 | ✅ |
| 监听地址、TLS 证书 | ❌ 需要重启（Pingora 监听器启动时绑定） |

**端到端验证**：

```
1. 初始（无规则）        200
2. 加 127.0.0.1 黑名单   403   ← 规则热生效
3. 写入非法配置          403   ← 重载失败，保留旧配置
4. 移除规则              200   ← 恢复
```

**已知代价**：热重载后上游池是全新的，健康状态与活跃连接计数清零。影响很小（几秒内重新学习），但如果上游正在故障，重启计数会让它重新被试几次。

### 3.14 检测引擎

三层：归一化 → 预过滤 → 正则精判。

**第一层：归一化（最关键）**

规则写得再好，归一化不到位就形同虚设。以下都是同一个 `'`：

| 变形 | 手法 |
|---|---|
| `%27` | URL 编码 |
| `%2527` | 双重编码（要解两次） |
| `&#39;` / `&#x27;` | HTML 实体 |
| `＇` | 全角字符 |
| `'/**/` | SQL 注释分隔 |

管线：URL 多轮解码（上限 3 轮）→ HTML 实体 → Unicode 折叠（全角转半角）→ 去 SQL 注释 → 空白归一 → 小写。

**解码有上限**：`%2525252527` 只解三轮，剩 `%2527`。无限解码会让刻意构造的输入耗尽 CPU。

**第二层：Aho-Corasick 预过滤**

正则很贵，正常请求占绝大多数。先用关键词自动机一次扫描排除，只有含可疑词的请求才进正则。

预过滤是**必要条件**而非充分条件：关键词没命中就一定没匹配（可以安全跳过），命中了还要正则确认（避免把 "union station" 判成注入）。

**第三层：正则精判**

内置规则 16 条，覆盖 SQL 注入（6）、XSS（4）、命令注入（2）、路径穿越（2）、扫描器（1）。

所有正则写成有界形式（`[\s\S]{0,30}` 而非 `.*`），避免 ReDoS。

**分数与拦截**：

| 级别 | 分数 |
|---|---|
| Low | 10 |
| Medium | 25 |
| High | 50 |
| Critical | 80 |

默认阈值 50，即单条 High 命中即拦截。`Log` 类规则（如扫描器 UA）只计分数不参与拦截判定。

**观察模式**：`protection.observe_mode.enabled: true` 时只记录不拦截。首次部署应该开一周，看日志里的误报再决定是否切拦截。

**端到端验证**：

| 请求 | 结果 |
|---|---|
| `/api/users?page=1` | 200 |
| `?id=1 union select 1,2,3` | **403** `sqli-union-select` |
| `?id=1' or 1=1--` | **403** `sqli-boolean-tautology` |
| `?id=%2527%2520or%25201%253D1`（双重编码） | **403** |
| `?id=1 union/**/select 1`（注释绕过） | **403** |
| `?q=<script>alert(1)</script>` | **403** `xss-script-tag` |
| `/files/../../etc/passwd` | **403** `traversal-sensitive-file` |
| `?cmd=; cat /etc/passwd` | **403** `cmdi-shell-separator` |
| `?id=1 and sleep(5)` | **403** `sqli-time-based` |
| UA `sqlmap/1.7` | 200，但记录 `scanner-user-agent` |
| 观察模式下 SQL 注入 | 200，日志 `blocked=false observe=true` |

**当前局限**（不能对外宣称"完整 WAF"）：

1. 规则只有 16 条，覆盖常见攻击但远不完整
2. 没有语义分析（`protection.semantic` 配置项还没实现）
3. 没有误报抑制（白名单、学习模式）
4. 分类开关（`protection.sqli` 等 Toggle）尚未接入引擎

### 3.15 请求体检测

**难点**：Pingora 是流式转发，body 一块一块读、一块一块发。要做到"完整缓冲后再检测"，必须等 body 读完——但那时前面的块已经发给上游了。

**利用的窗口**：`request_body_filter` 在每个 chunk **转发前**调用。在这里返回错误，当前 chunk 就不会发出去。

**采用的策略**：

```
chunk 到达 → 累积到缓冲区 → 对累积的整体做检测 → 命中则中断
```

代价：命中时上游可能已收到前面几个 chunk。这是流式模型的固有限制，不是实现缺陷。

**为什么实际影响小**：小 body（绝大多数 POST 表单、JSON API）在第一个 chunk 里就是完整的，此时 `end_of_stream=true`，检测完全准确。只有大文件上传或超大 JSON 才会有"部分泄露"，而这类请求本来也不是 SQL 注入的载体。

**Content-Type 过滤**：

| 类型 | 处理 |
|---|---|
| `application/json` / `x-www-form-urlencoded` / `text/*` / `application/xml` | 检测 |
| `multipart/*`（文件上传） | 跳过 |
| `image/*` `video/*` `audio/*` / `application/octet-stream` / zip / pdf | 跳过 |
| 无 Content-Type | 检测（保守） |

二进制类型跳过是必要的：它们不会承载 SQL 注入，强行解码既浪费 CPU 又产生大量误报。

**缓冲上限**：64 KB。超过后停止累积并标记 `truncated`，日志里会体现——一个 10 MB 的 JSON body 不该把内存吃掉。

**非 UTF-8 跳过**：`BodyBuffer::as_str()` 返回 `None` 时不检测，避免对二进制内容做无意义的正则匹配。

**端到端验证**：

| 请求 | 结果 |
|---|---|
| POST 正常 JSON `{"name":"zhangsan","age":30}` | 200 |
| POST `id=1 union select 1,2,3` | **403** `sqli-union-select` |
| POST `{"q":"<script>alert(1)</script>"}` | **403** `xss-script-tag` |
| POST `; cat /etc/passwd` | **403** `cmdi-shell-separator` |
| POST `%2527%2520or%25201%253D1` | **403** `sqli-boolean-tautology` |
| POST multipart（body 含 `union select`） | 200（正确跳过） |

**剩余局限**：不检测 chunked 传输中的超大 body、不解压 gzip/deflate 压缩的 body、不检测文件上传内容（webshell 检测未做）。

### 3.16 自动封禁

**这是 WAF 的核心价值回路**：检测命中 → 累加分数 → 超过阈值封禁 IP → 后续请求在 ACL 阶段就被拒，连检测都不做。

```
正常请求        200
攻击（union）   403 + 触发封禁 300s（第 1 次）
再次攻击        403（这次是被封禁拦的，没走检测）
正常请求        403（已被封）
```

日志能清楚区分两种拒绝：

```
WARN 检测触发自动封禁 client_ip=127.0.0.1 duration_secs=300 offenses=1 rules=["sqli-union-select"]
INFO 处于自动封禁中，拒绝 client_ip=127.0.0.1 remaining_secs=300 offenses=1
INFO request ... acl="自动封禁" latency_us=125
```

**三个设计决策**：

**1. 分数会衰减**。窗口（10 分钟）内没再得分就清零。否则"一个月前踩过两次线"的用户会被永久盯上。

**2. 封禁时长递增但有上限**。5m → 30m → 2h → 24h，超出列表长度取最后一项。重犯加重是必要的，但无限增长会让误封代价失控。

**3. IPv6 按 /64 聚合**。隐私扩展会让同一台设备不断更换后缀，按 `/128` 封等于没封。

**用 `blocking_score` 而非总分**：扫描器 UA 这类 `Log` 级规则只计分不参与封禁判定。否则一个用 curl 脚本定时拉数据的用户，重复访问几次就被封了。

**配置与状态分离**（重要）：

`BanTable` 不放在 `RuntimeState` 里，而是独立持有。热重载时只调用 `update_settings()` 更新参数，**保留所有已有封禁记录**。

如果跟着 `RuntimeState` 一起重建，用户调一下 `trigger_score` 就把所有攻击者放了出来——这是不能接受的。

**观察模式下不封禁**：`observe_mode.enabled: true` 时连分数都不累加。观察的全部意义就是"先看误报再决定是否拦截"，这时候封 IP 会直接破坏这个前提。

**当前局限**：封禁状态只在内存，**重启即丢失**。持久化需要数据库（T3.7 的 SQLite 层），落地后可以做到"重启后封禁仍在"。

### 3.17 持久化（SQLite）

一次解决三个问题：

| 问题 | 不持久化的后果 |
|---|---|
| 封禁丢失 | 重启一次 WAF，所有封禁清零，攻击者立刻回来 |
| 订阅变更幅度失效 | 重启后没有"上次列表"可比，护栏形同虚设 |
| 事件无处存 | 控制台没有数据可展示，事后无法溯源 |

**三张表**：

```sql
bans        (ip PK, until, offenses, score, reason, created_at, updated_at)
events      (id PK, ts, kind, client_ip, app, path, rules, score, action)
feed_state  (name PK, entries, updated_at)
```

`PRAGMA journal_mode = WAL` + `synchronous = NORMAL`：WAL 允许读写并发，NORMAL 在 WAL 模式下已足够安全且快得多。

**封禁恢复**：启动时 `load_active_bans(now)` 只取未过期的，逐条 `restore()` 进内存表。过期的直接丢弃——恢复一个已过期的封禁没有意义。

**写入时机**：只在**触发封禁**和**检测命中**时写，都是低频事件。正常请求不碰数据库，所以不影响转发性能。

**失败降级**：数据库打不开时记 error 并降级为纯内存模式，**不阻塞启动**。WAF 的首要职责是转发流量，不能因为磁盘满了就不工作。

**端到端验证**：

```
第一次启动
  攻击 union select   → 403，触发封禁
  后续正常请求         → 403

重启服务
  INFO 数据库已打开 path=/tmp/hw-test.db
  INFO 已从数据库恢复封禁记录 count=1
  正常请求            → 403（封禁仍在）

数据库内容
  bans:   127.0.0.1 | until=... | offenses=1 | reason=sqli-union-select
  events: detect | 127.0.0.1 | / | sqli-union-select | 50 | block
```

**尚未接入**：~~`feed_state` 表已建好但还没用~~ → 已接入，见下。

**事件清理**：`prune_events(before)` 挂在后台线程（`homewaf-store-janitor`），启动时先跑一次，之后每小时一次；同时清理过期封禁。

### 3.18 订阅状态持久化

**问题**：护栏的"变更幅度"检查需要和上次的列表比较。不持久化的话每次启动都是"首次导入"，`previous` 传空，这一层完全失效——订阅源被投毒后一次性替换全部条目，拦不住。

**解法**：`FeedState` trait 抽象读写，`acl` 不依赖存储层（保持纯逻辑可测）：

```rust
pub trait FeedState {
    fn previous(&self, group: &str) -> Vec<IpNet>;
    fn remember(&self, group: &str, entries: &[IpNet]);
}
```

- `NoFeedState`：空实现，纯内存模式用
- `SqliteFeedState`：proxy 层实现，读写 `feed_state` 表

**只有校验通过才写回**：被护栏拒绝的批次不能污染基线，否则一次投毒就把"上次列表"改成毒列表，下次投毒就合法了。

**存储格式**：条目按行拼接成文本存一个 TEXT 字段。20 万条约 3.6 MB，SQLite 完全能处理，比拆成多行表更简单。

**为什么没做端到端验证**：订阅 URL 强制 HTTPS，本地测试需要证书链，成本高于收益。改为三层单元测试覆盖：`store` 层的 save/load、`acl` 层的 `apply_guards` 带 `previous`、`proxy` 层的 `SqliteFeedState` 读写接线。

### 3.19 配置来源：从 YAML 迁到数据库

**背景**：PRD 内部有矛盾——第 10 章数据模型定义了 `applications` 表，但附录 16.3 的 `config.yaml` 里也写了 `applications`。同一份数据在两处定义，没写同步规则。

**决策**：**数据库是唯一配置来源**，运行时不再读任何配置文件。

**引导方式**（启动前必须知道的，只能来自命令行）：

```bash
homewaf serve --db /data/homewaf.db --listen 0.0.0.0:80 --tls-listen 0.0.0.0:443
```

只有两件事在命令行：DB 路径、监听地址。其余全在库里。

**数据分布**：

| 表 | 内容 |
|---|---|
| `applications` | 应用、路由、上游（整行 JSON） |
| `settings` | 全局配置，按 key 存 JSON（server/tls/protection/real_ip/acl/limits/ratelimit/logging/storage） |
| `acl_rules` | ACL 静态规则（结构化列） |
| `ip_groups` | IP 组订阅（整行 JSON） |
| `bans` / `events` / `feed_state` | 运行时数据 |

**为什么用整行 JSON 而不是拆列**：家庭场景应用数量 < 50，全量加载进内存即可，SQL 层不需要按上游或路由查询。拆列会让"加一个字段就要改表"变成常态。`primary_domain` 单独提出来建唯一索引，因为这是唯一需要 DB 层约束的字段。

**迁移工具**：

```bash
homewaf import configs/demo.yaml --db /data/homewaf.db
```

一次性把 YAML 写进库，之后运行时不再碰 YAML。`--overwrite` 控制是否覆盖已存在的应用。

**能力倒退（必须记录）**：**DB 模式没有文件热重载**。原来监视 YAML 的 mtime，现在没有文件可监视；DB 的 mtime 变化包含事件写入（高频），不能用来触发重载。改配置后需要重启。控制台接入后会通过 API 显式触发重载，届时补上。

**验证**：

```
$ homewaf import configs/demo.yaml --db /tmp/hw-db-mode.db
导入完成 → /tmp/hw-db-mode.db
  应用 1 个（跳过 0 个已存在）
  ACL 规则 1 条
  全局设置 9 项

$ homewaf app-list --db /tmp/hw-db-mode.db
ID           主域名                      状态       上游
nas          nas.home.lan             启用       2

$ homewaf serve --db /tmp/hw-db-mode.db
INFO HomeWAF 启动（配置来自数据库 /tmp/hw-db-mode.db） apps=1 upstreams=3 acl_rules=1

正常请求 200 · 负载均衡 18082 · 未知域名 404 · SQL 注入 403 · 封禁生效 403
```

### 3.20 Web 控制台

**技术选型**：

| 部分 | 选择 | 理由 |
|---|---|---|
| API | axum | 生态成熟，handler 代码短 |
| 前端 | 单文件 HTML + 原生 JS | 无构建步骤，`include_str!` 嵌进二进制 |
| 运行方式 | 独立线程 + 独立 tokio runtime | 代理是 `run_forever` 阻塞的，不能共用 |

**认证**：

- 配了 `HOMEWAF_ADMIN_TOKEN` 环境变量 → 要求 `Authorization: Bearer <token>`
- 没配 → **强制只允许监听回环地址**，启动时校验，非回环直接拒绝启动

家用场景下管理面本来就不该暴露到局域网，所以"没 token 就只允许 127.0.0.1"是更安全的默认。

**API**：

```
GET    /api/stats            概览数字
GET    /api/apps             应用列表
POST   /api/apps             新增/更新应用
DELETE /api/apps/{id}        删除应用
GET    /api/rules            ACL 规则
POST   /api/rules            新增/更新规则
DELETE /api/rules/{id}       删除规则
GET    /api/bans             当前封禁
DELETE /api/bans/{ip}        解封
GET    /api/events?limit=    事件列表
GET    /api/settings/{key}   读设置
PUT    /api/settings/{key}   写设置
POST   /api/reload           手动重载
```

**写操作后自动重载**：这是 DB 模式补回热重载的唯一途径——没有文件可监视，只能由写操作显式触发。

```rust
fn reload_state(ctx) -> Result<(), String> {
    let new_state = load_state_from_db(&ctx.store, ctx.allow_regex)?;
    ctx.bans.update_settings(&new_state.auto_ban, new_state.ipv6_prefix);
    ctx.shared.store(Arc::new(new_state));
}
```

**端到端验证**（控制台 API 驱动）：

```
1. 触发攻击          代理 403
2. GET /api/bans     127.0.0.1 剩余=300s 原因=sqli-union-select
3. GET /api/events   detect / sqli-union-select / score=50 / block
4. DELETE /api/bans/127.0.0.1    → 解封后代理 200（立即生效）
5. POST /api/rules 拒绝 127.0.0.1 → 代理 403（立即生效）
6. DELETE /api/rules/ui-block-local → 代理 200（恢复）
```

**当前局限**：

- 没有设置编辑界面（`protection`、`real_ip` 等要直接改 DB 或用 API）
- 没有登录页，token 靠环境变量
- 事件没有筛选与分页，只显示最近 30 条
- 应用编辑只覆盖 ID/域名/别名/单上游，多上游与路由要在 API 层传完整 JSON

### 3.21 控制台的应用编辑

**后端校验先行**：写库前完整校验，避免坏数据落库后"重启起不来"。

```rust
fn validate_app(ctx, app) -> Result<(), String> {
    // ID 格式（小写字母/数字/横线，不能以横线开头结尾）
    // 主域名与别名（复用 config::validate_domain）
    // 上游非空、端口非 0
    // 域名冲突：主域名与别名都不能和其他应用重复
}
```

域名冲突检查是必要的：不检查的话 DB 唯一索引会抛一个用户看不懂的 SQL 错误。现在的提示是：

```
域名 `photos.home.lan` 已被应用 `photos` 使用
```

**前端交互**：

- 「+ 新建应用」展开内联表单，不弹窗（少一层焦点管理）
- 编辑时 ID 只读并置灰（主键不该改）
- 编辑保留未在表单中出现的字段（`routes`、`policy`、`tls` 等）——用 `...(editingApp || {})` 展开
- 提交中禁用按钮并改文案，防止重复提交
- 失败时表单保持展开，用户可以直接改，不用重新填

**页面测试**（puppeteer-core 驱动系统 Chrome，不下载 Chromium）：

| 步骤 | 结果 |
|---|---|
| 初始加载 | 概览 6 个数字正确，应用表 2 行 |
| 点「+ 新建应用」 | 表单展开 |
| 填表提交 | 提示「已创建 photos」，列表新增一行 |
| 重复域名提交 | 提示「域名已被应用 photos 使用」，表单保持展开 |
| 点编辑 | ID 只读、域名/别名/上游正确回填、按钮变「保存修改」 |
| 改别名保存 | 提示「已更新 photos」 |
| 代理验证 | `photos.home.lan` 200、新别名 `pics.home.lan` 200、**旧别名 `pic.home.lan` 404** |

最后一条是关键——旧别名 404 证明编辑真的重建了路由表，不是只改了数据库。

**测试脚本里的坑**：`page.evaluate` 里 `fetch('http://127.0.0.1:18080')` 会被 CORS 拦，浏览器内验证代理转发不可行，要用 curl 在外面测。

### 3.22 控制台的设置界面

**覆盖的设置项**：

| 分组 | 字段 |
|---|---|
| 防护策略 | 观察模式、拦截阈值、SQL 注入/XSS/命令注入/路径穿越 四类开关 |
| 自动封禁 | 启用、触发分数、IPv6 聚合前缀、内网网段策略 |
| 真实 IP | 启用、可信代理网段、头部优先级 |
| 限流 | 全局 QPS、单 IP QPS |

**`GET /api/settings` 返回有效值**：库里有就用库里的，没有就用 `Config::default()`。空库启动时界面不该显示空白，必须能拿到完整的默认结构。

**写入前类型校验 + 失败回滚**（关键）：

```rust
// 1. 按 key 反序列化成对应结构，失败直接 400
check_setting_type(&key, &value)?;
// 2. 记下旧值
let old = store.get_setting(&key)?;
// 3. 写入并重载
store.set_setting(&key, &value, now)?;
match reload_state(&ctx) {
    Ok(()) => ok,
    Err(e) => {
        // 4. 业务校验没过就回滚，别把库留在坏状态
        rollback(old);
        Err(e)
    }
}
```

不做这一步的话，用户填个 `block_threshold: 99999`，写入成功、重载失败、服务继续用旧配置——但**下次重启就起不来了**。

实测提示：

```
保存失败：配置不合法，已回滚到修改前：
数据库中的配置不合法：protection.block_threshold: 阻断阈值需在 1-100 之间
```

**一个必须说明的行为**：**观察模式不会解除已有的封禁**。切到观察模式后，之前被封的 IP 仍然被拦。这是有意的——用户想观察的是"新流量会不会误报"，不是想放走已知攻击者。

**页面测试结果**：

| 步骤 | 结果 |
|---|---|
| 设置渲染 | 4 个分组，默认值全部正确 |
| 拦截模式攻击 | 403，封禁数 1 |
| 开启观察模式后攻击 | **200**，封禁数 **0**，事件记录 `action=observe` |
| 关回拦截模式 | 403，封禁数 1 |
| 非法阈值 99999 | 拒绝 + 回滚到 50，服务继续正常拦截 |
| 改可信代理 | 保存成功，回读一致 |

### 3.23 控制台的 ACL 规则管理

**功能**：列表（ID/网段/动作/作用域/备注）、新建、删除。动作标签用颜色区分（放行绿、拒绝红）。

**前端先做格式检查**，减少无意义往返：

```js
if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr)) {
  return showMsg('网段格式应为 CIDR，如 203.0.113.0/24', 'error');
}
```

**后端防重复**（页面测试发现的）：同网段 + 同动作 + 同作用域视为同一条规则。

不检查的话，用户连点两次「添加」就会得到两条一模一样的规则——列表里看着别扭，排查时也会困惑"为什么有两条"。

提示：

```
相同规则已存在（ui-1792652151）：127.0.0.1/32 → 拒绝
```

**页面测试**：

| 步骤 | 结果 |
|---|---|
| 初始 | 1 条规则，代理 200 |
| 添加 `127.0.0.1/32` 拒绝 | 列表 2 条，**代理立即 403** |
| 非法 CIDR `not-a-cidr` | 「网段格式应为 CIDR」 |
| **重复添加同一条** | 「相同规则已存在」，规则数不变 |
| 添加 `10.0.0.0/8` 放行，作用域 `nas` | 列表显示作用域 `nas` |
| 删除 `127.0.0.1/32` | **代理恢复 200**，剩 2 条 |

最后一条证明删除也触发了路由重建，不是只删了数据库行。

### 3.24 控制台的 IP 组订阅管理

**功能**：列表、添加（自动拉取）、手动刷新、删除。

**前端拦截 HTTP 地址**：

```
订阅地址必须是 HTTPS（明文 HTTP 可能被中间人投毒）
```

后端也校验（`build_group`），前端只是减少往返。

**关键反馈：保存成功 ≠ 拉取成功。**

订阅失败不阻塞启动（这是设计），但用户看不到失败会**误以为防护已生效**——这是最危险的误解。

修复方式：`reload_state` 成功后检查 `feed_failures`：

```rust
if let Some((_, err)) = snapshot.feed_failures.iter().find(|(n, _)| n == &group.name) {
    return Json(json!({ "ok": true, "warning": format!("订阅已保存，但首次拉取失败：{err}") }));
}
```

前端用红色提示条显示 warning，而不是绿色的"已添加"。

**刷新同理**：`POST /api/feeds/{name}/refresh` 也返回 warning，前端红色提示。

**页面测试**：

| 步骤 | 结果 |
|---|---|
| 空状态 | 「还没有订阅。添加一个恶意 IP 库，防护能力会强很多。」 |
| 填 `http://` 地址 | 前端拦住，提示必须 HTTPS |
| 填不可达的 `https://` | **红色提示「订阅已保存，但首次拉取失败」**，列表出现该订阅 |
| 点刷新 | 红色提示「刷新失败」 |
| 删除 | 列表回到空状态 |

**`build_group` 的默认值**：启用、`block` 动作、全局作用域、`keep_last` 失败策略。用户只需填名称和 URL。

**单元测试**（19 个）：认证 2、应用校验 9、设置类型 3、订阅构造 5。

#### 3.24.1 两类订阅合并成「订阅源」

**问题**：控制台把「IP 组订阅」和「规则订阅」做成两个页面、两套表单、两套 API。
但在用户视角里它们是同一件事——填一个 HTTPS 地址、定期拉、拉回来的东西自动生效。
分成两页后，用户要先判断"我这条该放哪个页面"，而判断依据（编译成 ACL 还是进检测引擎）
恰恰是他最不关心的内部实现。

**做法**：入口合并，语义不合并。

| 层 | 是否合并 | 说明 |
|---|---|---|
| 控制台页面 | ✅ | 一个「订阅源」列表 + 一个表单，用 `kind` 切换字段 |
| 管理 API | ✅ | `/api/subscriptions`，写入体是 `{ kind, config }` |
| 校验与存储 | ❌ | IP 组走 `build_group` + `ip_groups` 表；规则包走 `validate_rule_feed` + `settings.rule_feeds` |
| 运行时 | ❌ | 前者编译成 `AclRule`，后者进 `Engine` |

不合并底层的原因：两者失败语义完全不同。IP 组拉取失败可以 keep-last 继续用旧列表；
规则包必须"验签失败即整包拒绝"，不能留半套规则。硬合并成一个结构，
字段会有一半永远是 `Option`，两边都得写一堆 `if let`。

**为什么用 `{ kind, config }` 而不是扁平结构**：两类配置差 8 个以上字段，
摊平后每个字段都得是 `Option`，前端还要自己记住哪些字段属于哪类，更容易写错。

**中文名称**：`IpGroup` / `RuleFeed` 都加了 `label` 字段（`#[serde(default)]`，旧数据零迁移）。

- 机器标识仍是 `name`：参与规则 id 拼接（`feed:{name}:{idx}`）、缓存键、日志检索，必须 ASCII
- `label` 只用于展示，不参与任何匹配；为空时界面回退显示 `name`
- 校验只查长度（≤64）与控制字符，**不限制字符集**——限制字符集正是"中文名存不进去"的原因
- 雷池同步时把 IP 组的中文名写进 `label`，导入后列表不再是一排 `lei-ipgroup-7`

**状态归一**：两类订阅压成四档，优先级 `停用 > 异常 > 待拉取 > 正常`。
停用优先于异常——用户主动关掉的东西不该显示成红色。

**刷新要如实**：IP 组重载遵守各自的 `interval`，没到点不会联网。
原来点「刷新」直接回 `{"ok":true}`，等于骗用户"已经重新拉过了"。
现在未到期时返回 warning：`距上次拉取不足 60 分钟，本次未重新联网，仍使用本地快照`。

#### 3.24.2 访问控制改为雷池式条件规则

**问题**：原来的「访问控制」只能填一个网段，而雷池的 custom_rule 是
「条件组 + 动作」。用户要表达"后台只允许内网访问"就得同时配 IP 白名单和路径规则，
在旧模型里根本写不出来。

**模型**（`settings.custom_rules`，与雷池 JSON 兼容）：

```json
{
  "id": "rule-6adafe158b8",
  "name": "后台只允许内网访问",
  "is_enabled": true,
  "action": 1,
  "scope": ["nas"],
  "pattern": [[{"k": "path", "op": "prefix", "v": ["/admin"]},
               {"k": "ip_group", "op": "in", "v": ["bad-ips"]}]]
}
```

- `pattern` 外层是「或」、内层是「且」
- `action`：0 放行 / 1 拦截 / 2 人机验证 / 3 仅记录（沿用雷池 0/1，2/3 是扩展）
- `scope` 为空表示对所有应用生效
- 条件字段：`src_ip`（CIDR）、`ip_group`（订阅组名）、`path`、`method`、`user_agent`、
  `header`（配 `sub_k` 指定头名）、`query`、`host`、`url`

**优先级**：放行 > 拦截/人机验证 > 仅记录。放行最高是刻意的——用户显式加白的机器
不该被同一条链路上的拦截规则推翻。人机验证已通过（有 cookie）的会话不再重复挑战。

**为什么保留 ACL 引擎**：订阅 IP 组展开后是 3500+ 条纯 IP 规则，走 `PrefixMap`
是 O(log n)；条件规则只有几十条，线性扫描足够。两套执行路径，一个页面入口。

**迁移**：`acl_rules` 表里非 `feed:` 开头的历史行（UI 手建、雷池同步产物）在重载时
自动转成 `src_ip eq <cidr>` 的条件规则，转换后删除原行——否则同一条规则会被执行两次。

**IP 组条件**：`RuntimeState.ip_groups` 保存「组名 → 条目」快照，从订阅生成的
ACL 规则 id（`feed:{组名}:{序号}:{作用域}`）反解，避免重载时二次联网。

**事件明细**：`events` 表新增 `request_id` / `method` / `query` / `ua` / `rule_names`。
老库通过 `PRAGMA table_info` + `ALTER TABLE` 补列（SQLite 没有 `ADD COLUMN IF NOT EXISTS`）。
控制台表格加「请求」「命中规则」「详情」，详情里可点请求 ID 直接跳到日志页按该 ID 过滤。

**日志明细**：访问日志补 `host` / `query` / `user_agent` / `app_id` / `rules` 字段；
控制台按列展示（时间/方法/主机路径/状态/上游/耗时/应用/来源/说明/ID），点行展开原始 JSON。

#### 3.24.3 黑白名单页面对齐雷池

**差异**：雷池的 custom_rule 页面是「白名单 / 黑名单两个页签 + 序号 + 匹配方式 +
状态开关 + 创建时间」，而 HomeWAF 原来是一张混合列表，缺序号、缺匹配方式、
状态是个标签而不是开关。

| 项 | 雷池 | 现在 |
|---|---|---|
| 分栏 | 白名单 / 黑名单 | 白名单 / 黑名单 / 人机验证·仅记录（多出来的两类单独一栏） |
| 序号 | 有，越大越新 | `seq`，新建时 `max+1`，历史规则启动时归一化为 1..n |
| 匹配方式 | 任意 / 全部 | `match_mode`：组内始终 AND，组间 `any`=OR、`all`=AND |
| 状态 | 开关 | 开关（`.rswitch`），直接调 `/api/rules` 翻转 |
| 创建时间 | 有 | `created_at`，编辑不改动；迁移来的历史规则为空显示 `-` |
| 条件编辑 | AND / OR 按钮 | 同左：AND 加进当前组，OR 新开一组 |

**求值顺序**：先按 `seq` 从大到小（新规则优先），再按「放行 > 拦截/人机验证 > 仅记录」
分组决策。放行优先是硬规则，不随序号变化——用户显式加白的机器不该被新加的拦截规则推翻。

**为什么不用雷池的两栏而是三栏**：HomeWAF 多了「人机验证」「仅记录」两个动作，
塞进黑名单会让人误以为它一定拦截。单独一栏，语义清楚。

### 3.25 事件筛选与分页

**为什么需要**：原来只显示最近 30 条。真实攻击场景下几小时就刷没了，用户想查"昨天谁在扫我"完全做不到。

**后端用固定参数的可选条件**：

```sql
WHERE (?1 IS NULL OR kind = ?1)
  AND (?2 IS NULL OR client_ip = ?2)
  AND (?3 IS NULL OR action = ?3)
  AND (?4 IS NULL OR ts >= ?4)
ORDER BY ts DESC, id DESC
LIMIT ?5 OFFSET ?6
```

不用动态拼 SQL：参数个数固定，既不会拼接注入，也不用维护两套（列表 + 计数）的 WHERE 子句。

**返回总数**：`{ events, total, limit, offset }`。前端要靠 `total` 算页数——只返回当前页的话，用户不知道还有多少。

**前端分页**：每页 20 条，底部显示「第 X / Y 页 · 共 N 条」，首尾页按钮自动禁用。

**筛选栏**：类型（检测/封禁/ACL）、处置（拦截/记录/观察/封禁）、来源 IP 精确匹配。改下拉立即查询，IP 框回车或点查询。

**页面测试**（50 条造的数据，17 ban + 33 detect）：

| 步骤 | 结果 |
|---|---|
| 首页 | 20 行，「第 1 / 3 页 · 共 50 条」 |
| 下一页 | 20 行，「第 2 / 3 页」 |
| 筛选 `ban` | 17 行，类型列全为 ban |
| 筛选 IP `203.0.113.9` | 17 行，IP 列一致 |
| 筛选 `acl`（无数据） | 「没有符合条件的事件」 |
| 重置 | 恢复 50 条 3 页 |

**单元测试**（7 个）：分页、按类型、按 IP、按动作、组合筛选、时间过滤、空结果。

### 3.26 检测白名单（误报豁免）

**和 ACL 放行不是一回事**：

| 机制 | 语义 |
|---|---|
| ACL 放行 | 这个 IP 是好的，不做任何防护 |
| 检测白名单 | 这个路径/规则的内容不该按攻击处理，但**仍走 ACL 和其他防护** |

典型场景：后台文章编辑器提交 HTML 富文本，`<script>` 是正常内容不是 XSS。没有白名单，用户只有两个选择——关掉 XSS 检测，或忍受误报。两个都很糟。

**规则结构**：

```rust
pub struct WhitelistRule {
    pub app: Option<String>,     // 应用，None = 全部
    pub path: Option<String>,    // 路径前缀，None = 不限
    pub rule_id: Option<String>, // 只豁免这条规则，None = 跳过全部检测
}
```

**匹配语义**：

- `app` 与 `path` 都满足才算命中（`path` 是前缀匹配，不是包含）
- `rule_id` 为 `None` → 跳过全部检测；为具体规则 → 只豁免那一条
- 多条规则合并时**更宽的豁免胜出**：一条说"跳过全部"、一条说"只豁免 XSS"，结果是跳过全部

**关键护栏**：`app`/`path`/`rule_id` 三个全空时**拒绝创建**。

```rust
if app.is_none() && path.is_none() && rule_id.is_none() {
    return Err("白名单至少要指定应用、路径或规则之一。三个都空等于对所有请求关闭检测");
}
```

这是最危险的误配置——用户以为加了个白名单，实际把整个 WAF 关了。

**接入位置**：`request_filter` 里检测前算豁免，`inspect_with` 按豁免过滤规则。

```rust
let exemption = whitelist::compute(&state.whitelist, &app.id, &hit.normalized_path);
let verdict = state.engine.inspect_with(&input, &exemption);
```

完全豁免时直接返回干净结果，连归一化都省了。

**端到端验证**：

| 场景 | 结果 |
|---|---|
| 基线 XSS / SQLi | 403 / 403 |
| 三项全空提交 | 「至少要填应用、路径或规则之一」 |
| 加 `/api` 白名单（跳过全部） | XSS **200**、SQLi **200** |
| 删除后 | XSS 恢复 403 |
| 改成只豁免 `xss-script-tag` | XSS **200**、SQLi **403** |
| 非白名单路径 | 仍 403 |

单规则豁免时的日志：`rules=["sqli-union-select"] whitelist=["wl-1792654575"]` —— 白名单命中了，但只豁免了 XSS。

**测试时踩的坑（第三次了）**：检测会触发自动封禁，封禁后请求在 ACL 层就被拦，根本走不到白名单逻辑。测试脚本每次攻击前必须解封，否则结果全是 403 且看不出原因。

### 3.27 规则扩充（15 → 41 条）

**分布**：

| 分类 | 条数 |
|---|---|
| SQL 注入 | 6 |
| SSRF | 6 |
| XSS | 4 |
| XXE | 4 |
| Webshell | 4 |
| 路径穿越 / 文件包含 | 4 |
| SSTI | 3 |
| NoSQL | 3 |
| LDAP / XPath | 3 |
| 命令注入 | 2 |
| 扫描器 / 反序列化 | 2 |

**扩规则时踩的两个坑**：

**坑一：Aho-Corasick 默认不报重叠匹配。**

新加的 `lfi-sensitive-path` 关键词是 `etc/passwd`，旧规则 `traversal-sensitive-file` 关键词是 `passwd`——两者互为子串。默认的 `find_iter` 只报最左最长匹配，`etc/passwd` 命中后 `passwd` 被跳过，导致**旧规则静默失效**。

加规则把旧规则搞坏了，而且测试是绿的（旧测试用的文本刚好不触发重叠）。

修复：改用 `find_overlapping_iter`。性能略降，但正确性优先。

**坑二：归一化后文本是小写，正则里的大写字母永远不匹配。**

`<!DOCTYPE`、`SYSTEM`、`Runtime`、`O:8:` 这些写成大写的正则，在归一化后的文本上一条都匹配不到。

教训：**所有正则必须全小写**。这条应该写进规则编写规范。

**测试辅助函数的缺陷**：`ids()` 直接拿原始文本扫描，没走归一化，导致依赖小写匹配的规则测不出来。修成先 `normalize` 再 scan——测试工具本身也要走真实流程。

**端到端验证**（观察模式，避免封禁干扰）：

| 攻击 | 命中规则 | 分数 |
|---|---|---|
| SSRF 云元数据 | `ssrf-cloud-metadata` | 80 |
| SSRF file 协议 | `ssrf-file-scheme` + `traversal-sensitive-file` | 160 |
| SSRF gopher | `ssrf-loopback` + `ssrf-dangerous-scheme` | 100 |
| SSTI Python | `ssti-python-dunder` | 80 |
| SSTI Java | `ssti-java-runtime` | 80 |
| NoSQL `$where` | `nosql-where` | 80 |
| LDAP 注入 | `ldap-injection` + `ldap-wildcard-injection` | 75 |
| PHP 反序列化 | `deser-php-object` | 50 |
| 文件包含 | `xxe-php-filter` | 80 |
| 正常请求 | 无命中 | 0 |

**误报检查**：8 类正常内容（URL、中文、JSON、价格、文件路径、CDN 链接等）全部零命中。

**已知取舍**：`ssrf-loopback` 会命中文本里出现的 `127.0.0.1`。说明文档、配置示例里提到回环地址会误报——但 SSRF 的危害太大，宁可误报让用户加白名单。

### 3.28 规则性能基准与模糊测试

**微基准**（`cargo run --release -p homewaf-detect --example bench`，单核）：

| 场景 | 单次耗时 | 单核 QPS |
|---|---|---|
| 干净短文本 (36B) | 0.16 μs | 640 万 |
| 干净长文本 (2KB) | 3.26 μs | 30.7 万 |
| 可疑文本（进正则） | 0.15 μs | 688 万 |
| **完整检测·干净请求** | **3.25 μs** | **30.8 万** |
| **完整检测·攻击请求** | **2.49 μs** | **40.2 万** |
| 归一化·多重编码 | 0.96 μs | 104 万 |

检测成本 3.25 μs/次，单核 30 万 QPS——**比代理层（23.8k RPS）高一个数量级，不是瓶颈**。

**端到端压测**（ab -n 20000 -c 100 -k，release，观察模式避免封禁）：

| 场景 | RPS | 对比 15 条规则时 |
|---|---|---|
| 干净请求 | 23,838 | 27,254（**-12.5%**） |
| 攻击请求（进正则） | 14,586 | — |

**规则从 15 条涨到 41 条，干净请求只降 12.5%。** 原因是 Aho-Corasick 预过滤是 O(n) 线性扫描，规则数增加只影响自动机的状态数（构建时），不影响单次扫描复杂度。

攻击请求慢 39%（14.6k vs 23.8k），因为要跑正则。但真实场景攻击占比 < 1%，整体吞吐接近干净请求的数字。

**仍然远超 PRD 的 5k RPS 目标（4.8 倍）。**

**模糊测试**（确定性 xorshift64，不依赖 cargo-fuzz）：

| 用例 | 覆盖 |
|---|---|
| `random_input_never_panics` | 5000 组随机 UTF-8，验证不 panic 且不异常膨胀 |
| `pathological_repeats_do_not_panic` | 10 种病态输入（`%`×10000、`&#x`×10000、全角×10000 等） |
| `deeply_nested_encoding_is_bounded` | 100 层嵌套编码，验证三轮上限生效 |
| `mixed_encoding_chain_does_not_panic` | 混合编码链（`%25%32%35`、`&#37;27`、全角百分号） |

归一化是手写解析器，这四组测试确认它不会 panic、不会因病态输入耗尽 CPU。

**为什么不用 cargo-fuzz**：需要 nightly 工具链，且 CI 集成成本高。确定性伪随机 + 病态输入枚举覆盖了主要风险面，成本低得多。

### 3.29 配置模型改进：代理地址与路径重写

**问题一：上游地址不能直接写 URL。**

原来要拆成三个字段：

```yaml
upstreams:
  - addr: 192.168.1.5
    port: 8080
    scheme: http
```

用户直觉是直接填一个地址。现在 `addr` 支持四种写法：

```text
192.168.1.5            → http://192.168.1.5:80
192.168.1.5:8080       → http://192.168.1.5:8080
https://nas.lan        → https://nas.lan:443
https://nas.lan:8443   → https://nas.lan:8443
[::1]:8080             → http://[::1]:8080
```

优先级：`addr` 里写的 > 独立字段 `scheme`/`port` > 协议默认端口。旧写法仍然可用。

实现是 `Upstream::target()`，返回 `{ host, port, scheme }`。校验和上游池构建都走它，只有一处解析逻辑。

**行为变更**：以前缺端口会报错，现在自动按协议补 80/443。这是有意的——用户填 `192.168.1.5` 期望的就是 80。

**问题二：rewrite 配置存在但完全没实现。**

`RewriteMode` 有 `strip_prefix` / `add_prefix` / `regex` 三个变体，配置能解析，但 `request_filter` 里从来没调用过——**改路径的配置一直是空转的**。

新增 `prefix` 模式，语义是「把匹配到的路由前缀替换成 value」：

```yaml
routes:
  - path: /a
    upstreams:
      - addr: http://1.1.1.1:8989
    rewrite:
      mode: prefix
      value: /c
```

效果：`/a/foo` → 上游收到 `/c/foo`，`/a` → `/c`。

**关键约束：检测用原始路径，转发用重写后的路径。**

```rust
// 检测：hit.normalized_path（用户实际请求的路径）
let verdict = state.engine.inspect_with(&input, &exemption);

// 转发：rewrite 之后
let forward_path = rewrite::apply(&hit.normalized_path, route_path, rw);
ctx.normalized_path = forward_path;
```

如果检测也用重写后的路径，攻击者就能构造一个 `/a` 开头的请求，让 WAF 检查 `/c` 而实际后端收到别的东西——又是一条绕过。

**端到端验证**：

| 请求 | 上游收到 |
|---|---|
| `/hello` | `/hello`（默认上游） |
| `/a/foo` | `/c/foo` |
| `/a` | `/c` |
| `/a/b/c` | `/c/b/c` |
| `/strip/foo` | `/foo`（strip_prefix） |
| `/strip` | `/` |
| `/a/foo?x=1&y=2` | `/c/foo?x=1&y=2`（query 保留） |
| `/other` | `/other`（未命中路由） |

**防御性处理**：路径不以路由前缀开头时原样返回，不丢路径。理论上不会发生（路由已匹配），但把整个路径丢掉比不改更糟。

**表单布局修复**：`.wide` 类之前只对 `.fieldset` 生效，`<form>` 里的没有定义，导致 5 个字段挤成一行、代理地址输入框被压到几十像素宽。补上 `form .wide` 和 `form .hint` 后，代理地址独占一行，提示文字在下方。

### 3.30 主动健康检查与固定错误页

**之前只有被动检查**：靠真实请求的失败累积判断。问题是上游挂了之后，要等**第一个真实用户**踩坑才会发现。

**主动检查**：后台线程按 `health_check.active.interval` 定时探测：

```yaml
health_check:
  active:
    enabled: true
    interval: 3s
    timeout: 1s
    path: /
    expect_status: [200]
```

探测用 `ureq` 发 GET，状态码在 `expect_status` 里就算健康。结果直接写 `Slot.state`——和被动检查共用同一个状态位，谁最后说话算谁的。

每次探测都重新 `load_full()` 取状态快照，热重载后会自动探测新配置里的上游。

**探测间隔取所有应用里最小的那个**（单线程轮询全部，不为每个应用起线程）。

**上游全挂时返回固定页面**：

```
HTTP 503
<title>503 服务暂不可用</title>
<h1>503</h1>
<p>服务暂不可用</p>
<p class="hint">后端服务暂时无法访问，请稍后重试</p>
```

响应头带 `retry-after: 5` 和 `cache-control: no-store`。内容固定，不含任何后端信息——不泄露服务名、内部地址、错误栈。

比原来的空 503 好在：用户看到的是一个正常的错误页，而不是浏览器的默认错误提示；也不会因为空白响应让人怀疑是网络问题。

**端到端验证**：

| 步骤 | 结果 |
|---|---|
| 上游健康 | 200 |
| 停掉上游，等 6 秒（间隔 3s） | **503 + 固定错误页** |
| 重启上游，等 6 秒 | **恢复 200** |

全程没有发过"探测以外的请求"——挂掉 3 秒内就被发现，不用等真实用户踩坑。

**测试时的坑**：用 `pkill -f echo_upstream` 停上游时，把整个后台任务（含 homewaf）一起杀了。改用 `lsof -ti:18081 | xargs kill` 按端口精确杀。

### 3.31 日志系统

**之前只有 stdout**：进程一关日志就没了，也没法按类型查。

**四个目录各写各的**：

```
data/logs/
├── access/access.2026-10-22.log      每个请求一行
├── upstream/upstream.2026-10-22.log  反代细节
├── security/security.2026-10-22.log  安全事件
└── error/error.2026-10-22.log        所有 WARN 及以上
```

**为什么分目录**：排查时关注的维度完全不同。查"为什么这个用户访问不了"看 access，查"为什么变慢了"看 upstream，查"谁在攻击"看 security。混在一个文件里就是几万行里捞一条。

**实现**：`tracing-appender` 按天滚动 + `tracing_subscriber` 多 layer，每个 layer 用 `filter_fn` 按 target 分流。

| 文件 | target | 内容 |
|---|---|---|
| access | `homewaf.access` | method / path / status / upstream / client_ip / latency |
| upstream | `homewaf.upstream` | app / upstream / backup / status / latency / error |
| security | `homewaf.security` | 检测命中（规则、分数）、封禁、ACL 拒绝 |
| error | 所有 WARN+ | 跨 target 的错误汇总 |

**JSON 格式**，每行一条，方便 `jq` 和日志采集：

```json
{"timestamp":"...","level":"INFO","fields":{"message":"request","method":"GET","path":"/a/foo","status":200,"upstream":"127.0.0.1:18081","client_ip":"127.0.0.1","latency_us":"603"},"target":"homewaf.access"}
```

**日志配置走环境变量而非数据库**：日志要在"数据库可能打不开"的场景下也能工作，从 DB 读配置是鸡生蛋问题。

```bash
HOMEWAF_LOG_DIR=./data/logs HOMEWAF_LOG_LEVEL=debug
```

`logging.dir` 设为空字符串则只输出到控制台。

**已验证**：三个请求（正常 / 重写 / SQL 注入）在四个文件里都留下了对应记录。

### 3.32 前端重构与请求链路追踪

**布局改成侧边栏 + 单页切换**（参考雷池）：

```
┌──────────┬──────────────────────────────┐
│ HomeWAF  │ 概览      拦截模式 规则41 封禁1 │
│          ├──────────────────────────────┤
│ 概览      │                              │
│ 应用      │   内容区（点击切换，不滚动）    │
│ 访问控制   │                              │
│ 检测白名单 │                              │
│ IP 组订阅  │                              │
│ 封禁  ①   │                              │
│ 事件      │                              │
│ 日志      │                              │
│ 设置      │                              │
└──────────┴──────────────────────────────┘
```

之前是所有区块竖着堆，一屏拉不到底。现在每个菜单一个页面，切换时才加载对应数据。

**顶部状态条**常驻：当前模式（观察/拦截）、检测规则数、封禁数。侧边栏封禁菜单带数量角标，有封禁时变红。

**请求 ID：把三个日志文件串起来**

这是「分析问题」的核心。之前一个请求在 access / upstream / security 三个文件里各写一条，但没有任何字段能对应上——只能靠时间戳猜。

现在每个请求生成一个 8 位十六进制 ID，贯穿所有日志：

```
access    [7b6b0606] GET /a/foo  200 upstream=127.0.0.1:18081 latency_us=428
upstream  [7b6b0606] 127.0.0.1:18081 status=200 latency_us=428
```

控制台日志页输入这个 ID，就能看到该请求的完整链路。

**ID 生成**：纳秒低 24 位 + 计数器低 8 位，固定 8 位。不取整 40 位是因为 `{:08x}` 只是「至少 8 位」，超了会变 9-10 位，扫起来不整齐。

**日志页**：

- 四个类型切换（访问 / 反代 / 安全 / 错误）
- 关键字或请求 ID 过滤
- 条数可选（100/200/500/1000）
- 时间转本地时区显示（日志文件里保留 UTC，机器友好）
- JSON 解析后按 `时间 级别 [req] message k=v...` 渲染，级别用颜色区分

**一个渲染坑**：用模板字符串生成 HTML 时，里面的换行和缩进会被 `white-space: pre-wrap` 渲染成真实换行，一条日志撑成六行。改成字符串拼接才正常。

**日志查询 API**：

```
GET /api/logs?kind=access&limit=200&q=<关键字或请求ID>
→ { lines: [...], file: "access.2026-10-22.log", total: 22 }
```

读该类型下最新的日志文件，从尾部取 N 条，按需过滤。

### 3.33 应用模型对齐雷池

参考雷池（SafeLine）的应用配置，把字段精简成四个：

| 字段 | 说明 |
|---|---|
| **ID** | 内部标识 |
| **对外域名** | 访问用的域名，单个 |
| **监听端口** | 逗号分隔，如 `80, 443`；留空接受任意端口 |
| **上游服务器** | 一个 URL，如 `http://192.168.1.5:8080` |

**去掉了「别名域名」**。雷池没有这个概念——一个应用一个域名。之前的「主域名 + 别名」两级设计让用户要理解主从关系，实际使用中别名用得很少，反而是理解成本。数据结构保留 `domains.aliases` 字段（避免破坏已有数据），但 UI 不再暴露。

**新增应用级监听端口**。之前所有应用共享全局监听，不能只让某个应用在 80 上响应。现在：

```yaml
applications:
  - id: nas
    domains: { primary: "nas.home.lan" }
    listen_ports: [80, 443]     # 只在这两个端口响应
    upstreams:
      - addr: "http://192.168.1.5:8080"
```

`Router::resolve(host, port, path)` 多了一个端口参数：应用声明了 `listen_ports` 就要求端口匹配，没声明则接受任意端口。

**验证**：

| 配置 | 访问 18080 | 结果 |
|---|---|---|
| `listen_ports: []` | 200 | 任意端口 |
| `listen_ports: [9999]` | **404** | 端口不匹配 |
| `listen_ports: [18080]` | 200 | 匹配 |

**上游地址**沿用之前的 URL 解析（`http://host:port` / `host` / `https://host`），和雷池的填法一致。

**写入是异步的**：每条日志先丢进 64K 行的内存队列，由独立后台线程批量落盘。请求线程不会因为磁盘 IO 被卡住——日志不该成为代理的瓶颈。

用 `tracing_appender::non_blocking` 的 **lossy 模式**：队列满了丢弃新日志而不是阻塞。极端压力下宁可丢日志也不能拖慢转发。

代价是 `kill -9` 时队列里的日志会丢；正常退出（SIGTERM）时 `WorkerGuard` 会 flush，不丢。所以 guard 必须 hold 到进程结束，不能提前 drop。

---

## 4. 架构决策记录（ADR）

### ADR-001：用 `Option<T>` 而不是解析时填默认值

- **背景**：需要支持 global / application / route 三层覆盖
- **决策**：所有可覆盖字段用 `Option<T>`，合并阶段才填默认值
- **后果**：`Config` 不能直接当"有效配置"用，需要一次 `resolve()` 得到有效值（待实现）

### ADR-002：`preset` 与单项开关共存，不是"改单项就切 custom"

- **背景**：`preset: balanced` + `file_upload: monitor` 是常见写法
- **决策**：配置文件里 preset 是基线，显式字段覆盖它；只有 UI 交互点开关时才自动切 `custom`
- **理由**：配置文件的优先级是显式的，不会出现"改了又被档位覆盖"的意外；UI 才需要防困惑
- **踩坑记录**：最初写成"preset + 单项 → 警告"，跑示例配置时误报，已删除

### ADR-003：配置整体覆盖，不逐字段 merge

- **决策**：route 的策略整体替换 application 的策略，不递归合并
- **理由**：逐字段 merge 会让"我以为继承了，其实是默认值"成为常态。整体替换语义清晰，代价是要写全

### ADR-004：不引入 `sqlx`

- **决策**：用 `rusqlite`（bundled）
- **理由**：`sqlx` 的编译期查询校验需要连数据库，交叉编译到 ARM 时很麻烦；家用场景的 SQL 复杂度不需要它

### ADR-005：router 独立成 crate

- **决策**：不塞进 `config`
- **理由**：config 是纯数据，router 是算法；分开后 router 可以独立做属性测试，且未来可被 detect 复用（路径特征）

### ADR-006：`sites` 保留为 `applications` 的别名

- **决策**：`#[serde(alias = "sites")]`
- **理由**：早期文档用过 `sites`，保留别名避免用户配置失效；新配置一律用 `applications`

### ADR-007：把 tokio 锁在 1.53

- **背景**：Pingora 0.9 内部用 `BufStream::with_capacity(0, 0)` 构造连接，而 tokio 从 1.54 起给 `BufReader::with_capacity` 加了 `assert!(capacity > 0)`
- **现象**：服务启动后立刻 panic，错误信息是 `capacity must be greater than zero`，位置在 `pingora-core/src/protocols/l4/stream.rs:549` 的 `From<TcpStream> for Stream`
- **决策**：`workspace.dependencies` 里写 `tokio = "=1.53.0"`，并在 proxy 显式依赖以锁住版本
- **代价**：无法自动获得 tokio 新版本
- **解除条件**：Pingora 修复该路径（改为非零容量或延迟构造）后即可放开
- **教训**：这类"依赖内部用了未定义行为、上游收紧后炸掉"的问题，只会在运行时暴露，编译期完全看不出来。所以**必须有端到端冒烟测试**，光跑单元测试会漏掉

### ADR-008：路由用规范化路径，转发也必须用

- **背景**：`//x/../other/a` 这种请求，路由匹配时会被规范化为 `/other/a`
- **风险**：如果只改路由决策、不改转发，后端收到的仍是原始路径，可能被解析成完全不同的资源——这是经典 WAF 绕过
- **决策**：`RequestCtx` 保存 `normalized_path`，在 `upstream_request_filter` 里用 `set_uri` 替换
- **验证**：端到端测试第 5 项，上游收到的确实是 `/other/a`
- **代价**：query 需要单独保存并拼回（`normalize_path` 会截掉 `?query`）

---

## 5. 代码约定

| 项 | 约定 |
|---|---|
| 命名 | 配置字段 `snake_case`，与 YAML 键一致；类型 `PascalCase` |
| 错误 | 库用 `thiserror`，二进制用 `anyhow`；错误信息写"发生了什么 + 怎么修" |
| 注释 | 只写"为什么"，不写"是什么"；复杂分支必须有理由 |
| 测试 | 单元测试与被测代码同文件；跨模块的边界用例放 `tests/` |
| 测试命名 | 描述行为而非方法名，如 `duplicate_domain_is_error` |
| unsafe | 默认禁止；确需使用时必须写 SAFETY 注释说明前提 |
| 格式化 | `cargo fmt` 必须通过 |
| 静态检查 | `cargo clippy --all-targets` 零警告 |

---

## 6. 开发一个新模块的流程

1. **读规格**：`docs/functional-spec.md` 对应章节，确认字段、默认值、优先级、边界
2. **定接口**：先写 `pub` 签名与 doc 注释，不写实现
3. **写测试**：至少覆盖"正常路径 + 每个边界 + 每个错误分支"
4. **写实现**：让测试变绿
5. **补集成测试**：如果涉及多模块协作
6. **跑检查**：`cargo test && cargo clippy --all-targets && cargo fmt`
7. **更新本文档**：进度看板 + 如有架构决策则加 ADR

---

## 7. 进度看板

| 任务 | 状态 | 备注 |
|---|---|---|
| T1.1 配置模型 + 校验 | ✅ 完成 | 59 个测试（21 单元 + 38 集成） |
| T1.2 配置加载 | ✅ 完成 | 含热重载（2s 轮询，失败保留旧配置） |
| T1.4 域名匹配 | ✅ 完成 | `router::DomainMatcher`，10 个测试 |
| T1.5 路径匹配 | ✅ 完成 | `router::PathMatcher` + 规范化，20 个测试 |
| T1.3 Pingora 骨架 | ✅ 完成 | 端到端转发通过，6 个场景 |
| T1.6 上游与端口回源 | ✅ 完成 | 4 种算法 + 被动健康检查 + 备份上游 |
| T1.10 真实 IP 还原 | ✅ 完成 | 支持自定义头名；CDN 预设网段表待内置 |
| TLS 终结 | ✅ 完成 | 自签证书验证通过，含 HTTP/2 |
| T1.7 ACL 前缀树 | ✅ 完成 | 22 个测试；静态规则 + 内网策略 + 应用作用域 |
| T1.8 IP 组订阅 | ✅ 完成 | 解析 + 三层护栏 + dry-run 命令；定时刷新待做 |
| T1.11 观察模式 | ⬜ 待开始 | 依赖检测引擎 |

---

## 8. 待办与已知问题

| 编号 | 问题 | 影响 | 计划 |
|---|---|---|---|
| TODO-1 | 配置合并（三层覆盖）未实现 | 目前只能拿到"原始配置"，拿不到"有效配置" | T1.6 前完成 `resolve()` |
| TODO-2 | 路径规范化未做 Unicode 归一化 | 全角字符可能绕过匹配 | T1.5 补，或放 detect 的归一化管线 |
| TODO-3 | 正则路由的性能未测 | 大量正则路由可能拖慢匹配 | T1.5 加基准测试 |
| TODO-4 | 域名未做 IDN → Punycode 转换 | 中文域名匹配不到 | 需要 `idna` crate，T1.4 补 |
| TODO-5 | 没有模糊测试 | 解析器可能有 panic 点 | M1 前接 `cargo-fuzz` |
| TODO-6 | **TLS 未接入** | 只能跑 HTTP，无法监听 443 | T2.8 |
| TODO-7 | **只用了第一个上游** | 多上游配置不生效，无负载均衡与故障转移 | T2.1/T2.2 |
| TODO-8 | **无背压与等待池** | 压力下会无限堆积 | T1.11 / M4 |
| TODO-9 | ~~上游请求头未处理~~ | ✅ 已注入 XFF / X-Real-IP / X-Forwarded-* | 完成 |
| TODO-10 | 无响应头加固 | `Server` 头等指纹仍会透传 | T2.4 / 7.9 |
| TODO-11 | CDN 预设网段表未内置 | `real_ip.preset` 目前只校验不填充 | T1.10 补齐 |

---

## 9. 构建与测试

```bash
# 环境（国内网络）
export RUSTUP_DIST_SERVER=https://rsproxy.cn
export RUSTUP_TOOLCHAIN=stable-aarch64-apple-darwin

cargo test                    # 全部测试
cargo test -p homewaf-router  # 只跑 router
cargo clippy --all-targets    # 静态检查
cargo fmt                     # 格式化
```

**注意**：`rustup component add clippy` 必须带 `--toolchain stable-aarch64-apple-darwin`，否则会装到错误的 toolchain 上，表现为"显示 up to date 但 clippy 不可用"。

---

## 10. 完成度评估

### 10.1 三个层次，别混着算

同一个功能有三个完成层次，混在一起算会自欺欺人：

| 层次 | 含义 | 现在 |
|---|---|---|
| **L1 配置模型** | 能解析、能校验、能报错 | 大部分需求已到 L1 |
| **L2 运行时逻辑** | 能计算、能决策（可单测） | 路由到 L2，其余未到 |
| **L3 端到端可用** | 真实流量能跑通 | **几乎为零** |

**关键事实：现在还不能转发任何一个 HTTP 请求。** 没有监听、没有 TLS、没有上游连接。所以按"能用的产品"算，完成度是 0。

### 10.2 按模块

| 模块 | L1 配置 | L2 逻辑 | L3 可用 | 说明 |
|---|---|---|---|---|
| 配置解析与校验 | 100% | 90% | — | 缺环境变量插值、include 分段、三层合并 |
| 域名路由 | 100% | 100% | 0% | 匹配器完成，未接入请求处理 |
| 路径路由 | 100% | 100% | 0% | 同上 |
| 上游与端口回源 | 100% | 30% | 0% | 数据结构有，选择算法/健康检查未做 |
| ACL 黑白名单 | 100% | 0% | 0% | 只有配置结构，无前缀树 |
| 真实 IP 还原 | 100% | 0% | 0% | 只有配置结构 |
| TLS / ACME | 100% | 70% | 100% | TLS 终结可用；ACME 自动签发待做 |
| 代理与转发 | 100% | 50% | 60% | 能转发 HTTP；缺 TLS、负载均衡、健康检查、背压 |
| 检测引擎 | 20% | 0% | 0% | 只有开关配置 |
| 规则 DSL | 10% | 0% | 0% | 只有规则包订阅配置 |
| 控制台 | 0% | 0% | 0% | 未开始 |
| 日志与观测 | 40% | 0% | 0% | 只有配置 |

### 10.3 按工作量

以 `functional-spec.md` 第 10 章的 180 人日为分母：

| 阶段 | 预估 | 已完成 | 完成度 |
|---|---|---|---|
| T1 地基 | 34d | 33d | 97% |
| T2 转发 | 30d | 3d | 10% |
| T3 检测 | 76d | 32d | 42% |
| T4 控制台 | 34d | 8d | 24% |
| **合计** | **174d** | **76d** | **44%** |

T4 完成了 API 与只读前端。剩下：应用编辑表单、设置界面、事件筛选分页、登录页。

**这个数字仍然低估了实际可用性**：现在 HomeWAF 已经能作为一台家用 WAF 的"外壳"使用——HTTPS 终结、路由、真实 IP、ACL、订阅、负载均衡都齐了。缺的是核心检测能力，而检测占 76 人日，是最大的一块。

### 10.4 测试成熟度

| 类型 | 数量 | 状态 |
|---|---|---|
| 单元测试 | 57 | ✅ |
| 集成测试（跨模块） | 38 | ✅ |
| 文档测试 | 2 | ✅ |
| 端到端测试（真实流量） | 0 | ❌ 依赖代理层 |
| 性能基准 | 0 | ❌ 依赖代理层 |
| 模糊测试 | 0 | ❌ M1 前补 |
| 安全测试 | 0 | ❌ 依赖检测引擎 |

**现有测试的特点**：每条规格约束都有对应用例，不是凑覆盖率。但**全部是纯逻辑测试**，没有任何网络、并发、真实 TLS 场景的验证。

### 10.5 下一个里程碑的判定标准

M0 的退出标准是"能代理一个真实应用，`curl -4`/`curl -6` 都通，压测 5k RPS"。进度：

| 项 | 状态 |
|---|---|
| Pingora 集成（监听 + 转发 + 优雅退出） | ✅ 完成 |
| 路由接入请求处理 | ✅ 完成 |
| 一个能跑通的 curl 场景 | ✅ 完成（6 个场景） |
| 压测 5k RPS | ✅ 完成（实测 27.2k RPS） |
| TLS 终结（自签证书即可） | ✅ 完成（含 HTTP/2） |

**M0 全部达成。** 现在 HomeWAF 可以作为一个可用的 HTTPS 反向代理替换 Nginx 的基础功能，但**还没有任何 WAF 能力**——下一步进 T1.7 ACL，才开始有"防火墙"的样子。
