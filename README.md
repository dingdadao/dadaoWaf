# HomeWAF

用 Rust 编写的家用 Web 应用防火墙。单二进制、反向代理型、支持 IPv4/IPv6 与多域名。

> 当前状态：代理、检测、CC 防护、人机验证、IP 组订阅与规则包订阅均已可用；控制台可管理全部配置。

## 快速开始

```bash
# 编译
cargo build --release

# 启动（配置来自数据库）
./target/release/homewaf serve --db ./data/homewaf.db

# 从 YAML 导入配置（一次性迁移）
./target/release/homewaf import configs/example.yaml --db ./data/homewaf.db

# 列出数据库中的应用
./target/release/homewaf app-list --db ./data/homewaf.db

# 校验 YAML（导入前检查用）
./target/release/homewaf validate configs/example.yaml

# 调试路由
./target/release/homewaf route configs/example.yaml nas.home.lan /jellyfin/web

# 拉取并检查 IP 组订阅（dry-run）
./target/release/homewaf feed https://example.com/list.txt

# 规则包签名（自建订阅源）
./target/release/homewaf rulepack keygen --out signing.pkcs8
./target/release/homewaf rulepack sign --key signing.pkcs8 rules.json -o core.hwrule
./target/release/homewaf rulepack verify --key ed25519:... core.hwrule
```

`route` 命令会把路径规范化后再匹配，因此可以直接用它验证绕过是否被挡住：

```bash
$ homewaf route configs/example.yaml nas.home.lan "//api/../admin/x"
请求: nas.home.lan//api/../admin/x
  应用: NAS 管理 (nas)
  规范化路径: /admin/x
  路由: /admin [前缀]
  上游1: http://192.168.1.5:5000 weight=1
```

## 目录结构

```
.
├── crates/
│   ├── config/          # 配置模型、解析、校验
│   │   └── src/
│   │       ├── model.rs      # 全部配置结构体
│   │       ├── validate.rs   # 语义校验
│   │       ├── units.rs      # 时长/体积解析（30s、2GB）
│   │       └── error.rs      # 错误类型与字段路径
│   ├── router/          # 域名与路径匹配
│   │   └── src/
│   │       ├── domain.rs     # Host → 应用（精确/通配/正则）
│   │       ├── path.rs       # 路径匹配 + 规范化
│   │       └── lib.rs        # Router：组合域名与路径
│   ├── proxy/           # Pingora 集成（监听、转发）
│   │   └── src/
│   │       ├── server.rs     # ProxyHttp 实现与钩子
│   │       ├── realip.rs     # 真实 IP 还原
│   │       ├── headers.rs    # 转发头注入
│   │       └── lib.rs
│   ├── acl/             # IP 访问控制
│   │   └── src/
│   │       ├── prefix.rs     # 按前缀长度分桶的前缀集合
│   │       └── lib.rs        # 黑白名单判定
│   └── cli/             # 命令行入口
├── configs/
│   └── example.yaml     # 带注释的完整示例
├── docs/
│   ├── PRD.md                 # 产品需求文档
│   ├── functional-spec.md     # 字段级功能规格（开发依据）
│   ├── rule-ingestion.md      # 规则获取与适配设计
│   └── implementation.md      # 实现说明与架构决策记录
└── Cargo.toml           # workspace
```

## 文档索引

| 文档 | 内容 | 读者 |
|---|---|---|
| [docs/PRD.md](docs/PRD.md) | 为什么做、给谁做、架构与取舍 | 产品、架构 |
| [docs/product-spec.md](docs/product-spec.md) | **完整功能设计与 UI 规范**（对标雷池） | 产品、前端 |
| [docs/gap-analysis.md](docs/gap-analysis.md) | **功能差距统计**（已实现/部分/未实现 + 优先级） | 产品、开发 |
| [docs/functional-spec.md](docs/functional-spec.md) | 字段名、默认值、匹配顺序、边界条件 | 开发、测试 |
| [docs/implementation.md](docs/implementation.md) | 怎么实现、模块边界、架构决策记录 | 开发 |
| [docs/rule-ingestion.md](docs/rule-ingestion.md) | 规则转换与 IP 组订阅 | 开发 |

**开发以实现规格（functional-spec）为准**，PRD 与规格冲突时以规格为准并回写 PRD。
**排期看 gap-analysis**，它列了每项缺失功能的工作量。

## 设计约定

1. **未知字段报错**，不静默忽略——拼写错误导致的配置失效比启动失败更危险。
2. **所有字段有默认值**，配置可省略。
3. **三态开关**（`off` / `monitor` / `block`），不用布尔值。"开了但先不拦"是最高频诉求。
4. **配置优先级**：route > application > global，整体覆盖不逐字段合并。
5. **校验问题带字段路径**，如 `applications[0].upstreams[1].port`。

## 开发环境

- Rust 1.99+（`rust-toolchain.toml` 已固定版本）
- 国内网络使用 `rsproxy` 镜像，配置见 `.cargo/config.toml`

```bash
cargo test          # 单元测试
cargo clippy        # 静态检查
cargo fmt           # 格式化
```

## 进度

| 任务 | 状态 |
|---|---|
| T1.1 配置模型 + 校验框架 | ✅ 完成 |
| T1.2 配置加载与热重载 | ✅ 完成 |
| T1.4 应用模型与域名匹配 | ✅ 完成 |
| T1.5 路径匹配与规范化 | ✅ 完成 |
| T1.3 Pingora 集成骨架 | ✅ 完成（端到端转发通过） |
| T1.6 上游与端口回源 | ✅ 完成（4 种算法 + 健康检查 + 备份） |
| T1.10 真实 IP 还原 | ✅ 完成（支持自定义头名） |
| TLS 终结 | ✅ 完成（含 HTTP/2） |
| T1.7 ACL 前缀树 | ✅ 完成（白名单优先、IPv6 聚合） |
| T1.8 IP 组订阅 | ✅ 完成（三层护栏 + dry-run） |
| 规则包订阅 | ✅ 完成（Ed25519 验签 + 影子期 + 回退 + 自动更新 + 控制台） |
| T1.11 观察模式 | ✅ 完成（只记不拦） |
| 检测引擎（归一化 + 规则） | ✅ 完成（路径/查询/头/请求体，41 条规则 17 类） |
| 自动封禁联动 | ✅ 完成（分数衰减 + 时长递增 + IPv6 聚合） |
| SQLite 持久化 | ✅ 完成（封禁/事件/订阅状态，定期清理） |
| CC 防护 | ✅ 完成（全局 / 单 IP / URL 级滑动窗口 + 并发连接） |
| 应用级与路由级策略 | ✅ 完成（防护开关、阈值、限流、CIDR、方法、挑战） |
| 人机验证 | ✅ 完成（HMAC token + JS 工作量证明，无第三方依赖） |
| 统计与事件导出 | ✅ 完成（24 小时趋势、攻击分类、CSV 导出） |
| ACME 自动签发 | ⬜ 待开始 |

测试：494 个单元、集成与端到端测试，clippy 零警告。

**当前能力**：HTTPS 反向代理 + IP 访问控制 + 应用层检测 + 自动封禁 + CC 防护 + Web 控制台——路由、TLS 终结（含 HTTP/2）、真实 IP、转发头、IP 黑白名单、IP 组订阅、**签名规则包订阅**（Ed25519 验签、影子期、失败回退、定时更新，含离线签名工具）、多上游负载均衡，SQL 注入 / XSS / 命令注入 / 路径穿越 / 扫描器等 17 类检测（内置 41 条 + 动态规则，含请求体、编码与全角绕过识别、观察模式），检测命中自动封禁，**检测白名单**（按应用/路径/规则精确豁免误报），**应用/路由级策略覆盖**，**三层滑动窗口限流**（CC 防护默认关闭，可在控制台开启），**人机验证**（CC 超限或路由强制时下发 JS 挑战），概览趋势与攻击分类、事件 CSV 导出，配置存 SQLite（无配置文件），控制台可管理全部配置并即时生效。
**尚不能**：自动申请证书、多证书 SNI、语义分析、控制台登录、告警通知。

## 性能实测

`ab -n 20000 -c 100 -k`，release 构建，单机回环，无 TLS：

| 场景 | RPS | 平均延迟 |
|---|---|---|
| 直连上游（基线） | 49,805 | 2.008 ms |
| 经 HomeWAF 转发（41 条规则，干净请求） | **23,838** | 4.195 ms |
| 经 HomeWAF 转发（攻击请求，进正则） | 14,586 | 6.856 ms |

M0 目标 5k RPS 已达成 **4.8 倍**。规则从 15 条扩到 41 条只让干净请求降了 12.5%——Aho-Corasick 预过滤是线性扫描，规则数增加不影响单次匹配复杂度。

检测引擎本身的成本是 3.25 μs/次（单核 30 万 QPS），比代理层高一个数量级，不是瓶颈。

注意这是无 TLS、Python 上游、单机回环的条件，不能直接对外宣称。

## 本地跑一遍

**配置存在数据库里，不需要配置文件。**

```bash
# 1. 编译
cargo build --release

# 2. 从示例 YAML 导入一次（迁移用，之后不再需要）
./target/release/homewaf import configs/demo.yaml --db /tmp/homewaf.db

# 3. 确认导入结果
./target/release/homewaf app-list --db /tmp/homewaf.db

# 4. 启动（配置全部来自数据库，控制台自动开启）
./target/release/homewaf serve --db /tmp/homewaf.db

# 5. 打开控制台
open http://127.0.0.1:19443

# 5. 验证
curl -H 'Host: nas.home.lan' http://127.0.0.1:18080/hello        # 200，两个上游轮询
curl -H 'Host: evil.com' http://127.0.0.1:18080/                 # 404
curl -H 'Host: nas.home.lan' 'http://127.0.0.1:18080/?id=1%20union%20select%201'  # 403
curl -H 'Host: nas.home.lan' http://127.0.0.1:18080/hello        # 403（已被封禁）
```

封禁、事件、配置都在这一个文件里，可以直接用 sqlite3 查：

```sql
SELECT * FROM applications;  -- 应用、路由、上游
SELECT * FROM settings;      -- 全局策略
SELECT * FROM acl_rules;     -- IP 规则
SELECT * FROM bans;          -- 谁被封了、为什么
SELECT * FROM events;        -- 检测命中记录
```

监听地址可以在命令行覆盖（优先级最高）：`serve --db ... --listen 0.0.0.0:80`

## 已知问题
- **tokio 必须锁在 1.53**：1.54 起 `BufReader::with_capacity(0)` 会 panic，而 Pingora 0.9 内部会用容量 0 构造连接。见 `docs/implementation.md` ADR-007。
- `real_ip.preset` 只做校验，尚未内置 CDN 网段表（需手动填 `trusted_proxies`）。
- TLS 证书需手动准备（全局单证书），ACME 自动签发与多证书 SNI 未实现。
- 控制台没有登录页，未配置 token 时只监听回环。需要远程管理时请在 `server.admin` 配置 token 并通过反向代理加 TLS。
- 测试本地 HTTPS 前要 `unset https_proxy`，否则 curl 会走代理并返回 502。
