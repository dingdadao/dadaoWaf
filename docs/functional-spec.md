# HomeWAF 功能规格说明书（Functional Spec）

| 项目 | 内容 |
|---|---|
| 文档版本 | v0.1 |
| 日期 | 2026-10-22 |
| 定位 | 把 PRD 第 7 章的功能清单细化到**字段级、可开发、可测试** |
| 读者 | 开发、测试 |
| 与 PRD 的关系 | 本文档细化并部分修正 PRD 的配置模型；两者冲突时**以本文档为准**，并回写 PRD |

---

## 0. 阅读约定

1. 所有字段名使用 `snake_case`，与 YAML 配置键一一对应。
2. 所有字段都有默认值，配置可省略。
3. 所有时长字段接受 `30s` / `5m` / `2h` / `7d`，内部统一存秒。
4. 所有大小字段接受 `10MB` / `1GB`，内部统一存字节。
5. 标注 **【必须】** 的字段缺失时配置校验失败；其余可省略。

---

## 1. 通用约定

### 1.1 配置优先级

越具体的配置优先级越高，**不做合并，只做覆盖**（整体替换，不逐字段 merge，避免"我以为继承了其实是默认值"的困惑）：

```
route 级  >  application 级  >  global 级
```

### 1.2 三态开关

所有防护能力统一用三态，不用布尔值：

| 值 | 语义 | 典型用途 |
|---|---|---|
| `off` | 完全不检测，零开销 | 该类型确定不适用（如纯静态站点关闭 SQLi） |
| `monitor` | 检测、记录、不阻断 | 新规则上线观察期；误报排查 |
| `block` | 检测并阻断 | 生产默认 |

> **设计理由**：布尔值只有"开/关"，而"开了但先不拦"是安全产品最高频的诉求。用三态可以避免用户为了观察而关掉整个检测。

### 1.3 动作优先级

同一请求命中多条策略时，按动作优先级裁决：

```
allow (放行) > deny (阻断) > challenge (挑战) > monitor (记录) > pass (默认)
```

`allow` 优先级最高，是为了保证"白名单永远能救你"——误封自己的管理 IP 时，只有白名单能解。

### 1.4 配置校验规则

| 规则 | 行为 |
|---|---|
| 未知字段 | **报错**，不忽略（防止拼写错误导致配置静默失效） |
| 类型错误 | 报错，定位到字段路径（如 `applications[0].upstreams[1].port`） |
| 枚举值错误 | 报错，列出合法值 |
| 引用不存在 | 报错（如 route 引用了不存在的 upstream 组） |
| 语义冲突 | 警告 + 报错（如 `allow_cidr` 与 `deny_cidr` 有交集） |

---

## 2. 应用（Application）

### 2.0 为什么以"应用"为中心，而不是"站点"

用户想的是"我的相册""我的 NAS""我的 Home Assistant"，不是"vhost"。所以配置的第一层不是服务器，而是**应用**。

```
应用 Application  ← 一个对外提供的服务，一个域名
├── 域名        1 个主域名 + N 个别名
├── 上游组      1..N 个（可多端口、多主机）
└── 路由        0..N 个路径规则（可指向不同上游）
```

**这三层是正交的**：一个应用可以只有一个域名一个端口（最简单），也可以一个域名多个端口多个路径（最复杂）。复杂度由用户按需增加，不强迫。

> 配置键为 `applications`；`sites` 作为兼容别名保留（两者等价，同时出现时 `applications` 优先）。

### 2.1 应用模型

```yaml
applications:
  - id: photos                          # 【必须】唯一标识，用于 API/日志/策略引用
    name: "家庭相册"                     # 【必须】显示名
    enabled: true
    domains:
      primary: "photos.home.lan"        # 【必须】主域名，证书以此申请
      aliases: ["photo.home.lan"]       # 可选，别名（同证书覆盖）
    upstreams:                          # 【必须】默认上游组，至少一个
      - addr: 192.168.1.5
        port: 2342
    routes: []                          # 可选，路径级路由，见 4 章
    tls:
      mode: auto                        # auto | manual | off
      cert_id: null
    policy: {}                          # 覆盖全局策略，见 6 章
    created_at: 1759000000
    updated_at: 1759000000
```

**字段约束**：

| 字段 | 约束 |
|---|---|
| `id` | `[a-z0-9-]{1,32}`，全局唯一，创建后不可改 |
| `name` | 1-64 字符，仅用于显示 |
| `domains.primary` | 合法域名，不能是通配符 |
| `domains.aliases` | 最多 10 个；可以是通配符（如 `*.photos.home.lan`） |
| `upstreams` | 1-16 个；至少一个非 `backup` |

### 2.2 "一个应用一个域名"（推荐范式）

**推荐做法**：每个应用独立子域名。

```
photos.home.lan   → 相册
nas.home.lan      → NAS 管理
ha.home.lan       → Home Assistant
gitea.home.lan    → 代码仓库
```

**为什么推荐**（这不是风格问题，是四个实际约束）：

| 维度 | 一应用一域名 | 多应用共享域名靠路径 |
|---|---|---|
| **Cookie** | 天然隔离，互不覆盖 | 同名 Cookie 冲突（两个应用都设 `session` 就打架） |
| **证书** | 一张证书覆盖 primary + aliases，续期简单 | 一张证书要覆盖所有应用，任一失败全挂 |
| **策略** | 每个应用独立阈值，互不影响 | 同域名下难差异化（`/admin` 严、`/upload` 宽，配置易错） |
| **故障隔离** | A 应用上游挂了，B 不受影响 | 路径配置错误可能影响整站 |
| **统计** | 按应用聚合，数据有意义 | 所有请求混在一起，看不出哪个服务被攻击 |
| **CORS** | 跨域边界清晰 | 同源策略下混乱 |

**反模式示例**（不推荐，但技术上支持）：

```yaml
# 不推荐：所有服务挤在一个域名下
applications:
  - id: nas-all
    domains: { primary: "nas.home.lan" }
    routes:
      - { path: /jellyfin, upstreams: [{ addr: 192.168.1.5, port: 8096 }] }
      - { path: /ha, upstreams: [{ addr: 192.168.1.6, port: 8123 }] }
      - { path: /gitea, upstreams: [{ addr: 192.168.1.7, port: 3000 }] }
```

**什么时候不得不用路径**：
- 只有一个域名，且无法申请泛域名证书
- 内网没有 DNS 服务器，只能用 IP 访问
- 对端应用不支持子路径部署（如某些应用硬编码了根路径）

遇到这些情况，控制台应在创建时提示"建议为每个服务使用独立子域名"，但不阻止。

### 2.3 一个应用多个端口

两种典型用法，都支持：

**用法一：同一服务的多实例（负载均衡）**

```yaml
applications:
  - id: app
    domains: { primary: "app.home.lan" }
    upstreams:
      - { addr: 192.168.1.10, port: 8080, weight: 2 }
      - { addr: 192.168.1.11, port: 8080, weight: 1 }
      - { addr: 192.168.1.12, port: 8080, backup: true }
```

**用法二：同一应用的不同组件（不同端口）**

```yaml
applications:
  - id: app
    domains: { primary: "app.home.lan" }
    upstreams:                                  # 默认：前端
      - { addr: 192.168.1.10, port: 3000 }
    routes:
      - path: /api                              # API 走另一个端口
        upstreams: [{ addr: 192.168.1.10, port: 8080 }]
      - path: /static                           # 静态资源走 CDN 缓存端口
        upstreams: [{ addr: 192.168.1.10, port: 8081 }]
        cache: { enabled: true, ttl: 7d }
```

**端口范围**：1-65535，支持同一主机的连续端口映射（`port: 8000-8010` 表示轮询这 11 个端口），用于某些应用的多进程模型。

### 2.4 域名匹配规则

| 类型 | 语法 | 示例 | 匹配范围 |
|---|---|---|---|
| 精确 | `nas.home.lan` | `nas.home.lan` | 仅此域名 |
| 通配 | `*.home.lan` | `*.home.lan` | 一级子域，**不匹配多级**（`a.b.home.lan` 不命中） |
| 正则 | `~^api\d+\.home\.lan$` | `~^api\d+\.` | 按配置顺序，首个命中生效 |

**匹配顺序**：精确（含别名）> 通配 > 正则 > 默认应用。

**规范化规则**（匹配前统一处理）：
1. 转小写
2. 去除末尾的 `.`（`nas.home.lan.` → `nas.home.lan`）
3. 去除端口（`Host: nas.home.lan:8443` → `nas.home.lan`）
4. IDN 转 Punycode（`中文.lan` → `xn--fiq228c.lan`）
5. 非法 Host（含 `/`、空格、控制字符）→ 直接 400，不进入匹配

**未匹配任何应用**：
- 默认行为：返回 `444`（直接关闭连接，不返回任何内容，不泄露指纹）
- 可配 `default_application` 指定兜底应用（用于统一展示"未配置"页面）

### 2.5 应用状态

| 状态 | 行为 | 进入方式 |
|---|---|---|
| `enabled` | 正常服务 | 默认 |
| `disabled` | 返回 503，保留配置 | 手动禁用 |
| `draining` | 不再接受新请求，等待在途请求完成（最长 30s），然后转 disabled | 删除/重载前自动进入 |

### 2.6 域名冲突检测

配置校验时必须检测：

- 两个应用声明了完全相同的域名（含 primary 与 alias 交叉）→ **报错**
- 通配域名重叠（`*.home.lan` 与 `*.a.home.lan`）→ 警告，精确者优先
- 正则域名可能重叠 → 无法静态判定，仅警告
- 同一应用的 primary 出现在另一个应用的 aliases 中 → **报错**

### 2.7 统计与策略的应用维度

以下数据全部按 `application_id` 聚合，这是"一应用一域名"带来的直接好处：

- 访问日志（可按应用筛选）
- 攻击事件（可按应用看攻击类型分布）
- 流量统计（QPS、带宽、延迟）
- 防护策略（每应用独立档位）
- 证书（每应用独立证书或共享）

**控制台首屏按应用展示**，而不是按域名——用户看到的是"相册今天被攻击 23 次"，不是"photos.home.lan 有 23 条日志"。

---

## 3. 上游与端口回源

### 3.1 上游定义

```yaml
upstreams:
  - addr: 192.168.1.5            # 【必须】IPv4 / IPv6 / 域名 / unix:/path
    port: 5000                   # 【必须】1-65535；unix socket 时忽略
    scheme: http                 # http | https | grpc | ws | wss，默认 http
    weight: 1                    # 1-100，默认 1
    backup: false                # true 时仅在其他上游全部不可用时启用
    max_conns: 128               # 单上游最大并发连接，默认 128
    tls:                         # scheme 为 https/wss 时生效
      verify: true               # 是否校验上游证书，默认 true
      sni: null                  # 自定义 SNI，默认用 addr
      ca_file: null              # 自定义 CA
      client_cert: null          # mTLS 客户端证书
      client_key: null
```

**addr 的三种形态**：

| 形态 | 示例 | 说明 |
|---|---|---|
| IPv4 | `192.168.1.5` | 直接连接 |
| IPv6 | `fd00::5` 或 `[fd00::5]` | 方括号可选，解析时自动处理 |
| 域名 | `nas.local` | 启动时解析，失败则应用不可用并告警 |
| Unix Socket | `unix:/run/app.sock` | 仅本机，`port` 忽略 |

### 3.2 端口回源（三种模式）

这是家庭场景最常用的能力：一台 NAS 上跑着多个服务，各自监听不同端口，需要通过域名或路径分流。

#### 模式 A：单端口（最简单）

```yaml
applications:
  - id: photos
    name: "家庭相册"
    domains:
      primary: "photos.home.lan"
    upstreams:
      - addr: 192.168.1.5
        port: 2342
```

所有请求 → `192.168.1.5:2342`。

#### 模式 B：一个应用多个端口（路径映射）

```yaml
applications:
  - id: nas
    name: "NAS"
    domains:
      primary: "nas.home.lan"
    upstreams:                          # 默认上游（未匹配 route 时使用）
      - addr: 192.168.1.5
        port: 5000
    routes:
      - path: /jellyfin
        upstreams:
          - addr: 192.168.1.5
            port: 8096
        rewrite: { mode: strip_prefix }
      - path: /ha
        upstreams:
          - addr: 192.168.1.6
            port: 8123
```

#### 模式 C：多后端负载均衡（同一端口，多台机器）

```yaml
applications:
  - id: app
    name: "业务应用"
    domains:
      primary: "app.home.lan"
    lb:
      algorithm: least_conn            # round_robin | weighted | least_conn | ip_hash
      sticky: false                    # 是否会话保持
    upstreams:
      - { addr: 192.168.1.10, port: 8080, weight: 2 }
      - { addr: 192.168.1.11, port: 8080, weight: 1 }
      - { addr: 192.168.1.12, port: 8080, backup: true }
```

**端口透传（可选，P2）**：`port_mode: passthrough` 保留客户端请求的端口号转发。家庭场景几乎用不到，仅在使用非标准端口对外提供服务时需要。

### 3.3 负载均衡算法

| 算法 | 说明 | 适用 |
|---|---|---|
| `round_robin` | 轮询（默认） | 后端同构 |
| `weighted` | 加权轮询 | 后端性能不同 |
| `least_conn` | 最少连接 | 请求耗时差异大 |
| `ip_hash` | 按客户端 IP 哈希 | 需要会话保持且无共享存储 |
| `consistent_hash` | 一致性哈希（按 URL 或 Header） | 缓存友好 |

**健康检查与摘除**：
- 主动检查失败 → 立即摘除（不参与选择）
- 全部上游不可用 → 返回 502，并触发告警
- `backup: true` 的上游仅在其他全部不可用时启用

### 3.4 健康检查

```yaml
health_check:
  active:
    enabled: true
    interval: 10s
    timeout: 3s
    path: /healthz                     # 空则用 TCP 连接探测
    method: GET
    expect_status: [200, 204]
    healthy_threshold: 2               # 连续成功 N 次恢复
    unhealthy_threshold: 3             # 连续失败 N 次摘除
  passive:
    enabled: true
    fail_threshold: 5                  # 连续 5xx 达 N 次降权
    recover_threshold: 2
    window: 60s
```

**默认值原则**：家庭设备响应慢，`timeout` 不要设太小（默认 3s），`unhealthy_threshold` 不要设太小（默认 3 次），避免 NAS 偶尔卡顿就被摘除。

### 3.5 连接参数

```yaml
timeouts:
  connect: 5s                          # 建连超时
  read: 60s                            # 读响应超时（大文件下载需调大）
  write: 60s                           # 写请求超时
  idle: 75s                            # 空闲连接回收
  request: 30s                         # 单请求总预算（覆盖以上）

pool:
  max_idle_per_host: 32                # 每上游最大空闲连接
  idle_timeout: 90s
```

**大文件场景**：`read` 必须调大（建议 300s+），否则下载 4K 视频会中途断开。配置示例里 `photos` 应用就属于这类。

### 3.6 回源 Host 与 SNI

```yaml
upstream_host:
  mode: preserve                       # preserve | rewrite | upstream
  value: null                          # mode=rewrite 时必填
```

| 模式 | 行为 | 场景 |
|---|---|---|
| `preserve` | 透传客户端原始 Host | 后端按域名分流（默认） |
| `rewrite` | 改写为固定值 | 后端只认某个 Host（如 Gitea） |
| `upstream` | 用上游地址作为 Host | 后端是裸 IP 服务 |

### 3.7 重试

```yaml
retry:
  enabled: true
  attempts: 2                          # 额外重试次数，默认 2
  on: [connect_error, 502, 503, 504]   # 触发条件
  methods: [GET, HEAD, OPTIONS]        # 仅幂等方法重试
  backoff: 100ms                       # 固定退避
  budget: 5s                           # 重试总时间预算
```

**关键约束**：非幂等方法（POST/PUT/PATCH/DELETE）**默认不重试**，除非用户显式配置。重试 POST 可能导致重复下单、重复扣款——这个坑在企业环境常见，家庭场景同样（比如 NAS 的相册上传）。

### 3.8 请求头处理

```yaml
headers:
  request:
    set:                               # 覆盖或新增
      X-Real-IP: "$client_ip"
      X-Forwarded-Proto: "$scheme"
    add:                               # 追加（多值）
      X-Forwarded-For: "$client_ip"
    remove: ["X-Internal-Debug"]
  response:
    set:
      X-Content-Type-Options: "nosniff"
    remove: ["Server", "X-Powered-By"]
```

**自动添加的转发头**（可关闭）：

| 头 | 值 | 说明 |
|---|---|---|
| `X-Forwarded-For` | 追加客户端 IP | 若已存在，追加到末尾 |
| `X-Forwarded-Proto` | `http` / `https` | 让后端知道原始协议 |
| `X-Forwarded-Host` | 原始 Host | |
| `X-Real-IP` | 客户端 IP | 覆盖写入 |
| `X-Forwarded-Port` | 原始端口 | |

**安全约束**：来自不可信来源的 `X-Forwarded-For` 必须**丢弃后重建**，不能直接透传——否则攻击者可以伪造 IP 绕过 ACL。

### 3.9 真实客户端 IP 还原（CDN / 隧道 / 反向代理后）

#### 3.9.1 问题

当 HomeWAF 前面还有一层（Cloudflare、阿里云 CDN、腾讯云 CDN、Cloudflare Tunnel、frp），TCP 连接的来源 IP 是**中间节点**，不是真实用户。

如果不还原，会产生四个连锁错误：

| 影响面 | 错误后果 |
|---|---|
| **ACL** | 封禁攻击者 = 封禁整个 CDN 节点，该节点下所有正常用户一起打不开 |
| **限流** | 所有用户共享 CDN 节点的配额，一个人刷就把大家限死 |
| **GeoIP** | 地理分布全错，攻击来源分析失效 |
| **日志** | "谁在攻击我"完全无法回答 |

这是家庭场景的高频问题——很多人用 Cloudflare Tunnel 或 frp 回源，却没配真实 IP 还原，导致 WAF 形同虚设。

#### 3.9.2 配置模型

```yaml
real_ip:
  enabled: true
  trusted_proxies:                       # 【必须】只有来自这些网段的请求才解析头部
    - 173.245.48.0/20                    # Cloudflare
    - 103.21.244.0/22
    - 103.22.200.0/22
    - 103.31.4.0/22
    - 141.101.64.0/18
    - 108.162.192.0/18
    - 190.93.240.0/20
    - 188.114.96.0/20
    - 197.234.240.0/22
    - 198.41.128.0/17
    - 162.158.0.0/15
    - 104.16.0.0/13
    - 104.24.0.0/14
    - 172.64.0.0/13
    - 131.0.72.0/22
    - 2400:cb00::/32                     # Cloudflare IPv6
    - 2606:4700::/32
    - 2803:f800::/32
    - 2405:b500::/32
    - 2405:8100::/32
    - 2a06:98c0::/29
    - 2c0f:f248::/32
    - 127.0.0.1/32                       # 本机 cloudflared
    - ::1/128
  header_priority:                       # 按顺序尝试，首个有效值生效
    - CF-Connecting-IP
    - True-Client-IP
    - X-Real-IP
    - X-Forwarded-For
  max_chain_depth: 3                     # XFF 最多回溯几层
  on_untrusted_header: ignore            # ignore | reject（reject 返回 400）
  log_both: true                         # 日志同时记录直连 IP 与还原 IP
```

#### 3.9.3 各 CDN 的头部对照

| 来源 | 头部 | 值格式 | 可靠性 |
|---|---|---|---|
| Cloudflare | `CF-Connecting-IP` | 单个 IP | **最可靠**，优先使用 |
| Cloudflare | `True-Client-IP` | 单个 IP | 企业版，与上者一致 |
| Cloudflare | `X-Forwarded-For` | 逗号分隔，可能多值 | 一般，可能被客户端污染 |
| Cloudflare Tunnel | `CF-Connecting-IP` | 单个 IP | 同 Cloudflare |
| 阿里云 CDN | `Ali-CDN-Real-IP` | 单个 IP | 高 |
| 阿里云 CDN | `X-Forwarded-For` | 逗号分隔 | 一般 |
| 腾讯云 CDN | `X-Forwarded-For` | 逗号分隔 | 一般 |
| 腾讯云 CDN | `X-Real-IP` | 单个 IP | 高 |
| AWS CloudFront | `CloudFront-Viewer-Address` | `IP:port` | 高，需剥离端口 |
| Fastly | `Fastly-Client-IP` | 单个 IP | 高 |
| Vercel | `X-Real-IP` / `X-Vercel-Forwarded-For` | 单个 IP | 高 |
| 通用反代（Nginx） | `X-Real-IP` | 单个 IP | 取决于配置 |
| 通用反代（Nginx） | `X-Forwarded-For` | 逗号分隔 | 取决于配置 |

**注意**：`CloudFront-Viewer-Address` 带端口（`1.2.3.4:5678`），解析时必须剥离，否则 IP 解析失败会静默回退到直连 IP。

#### 3.9.4 解析算法（实现必须与此一致）

```
输入: 直连 IP D，请求头集合 H
1. 若 D 不在 trusted_proxies 中 → 直接返回 D（不信任任何头部），记 flag=untrusted_source
2. 按 header_priority 顺序遍历：
   a. 取头部值 V；不存在或为空 → 继续下一个
   b. 若 V 含多个值（XFF）：
      - 从右向左遍历
      - 跳过所有属于 trusted_proxies 的地址
      - 取第一个不在 trusted_proxies 中的地址
      - 若全部都是可信地址 → 取最左侧
      - 遍历深度不超过 max_chain_depth
   c. 剥离端口（IPv4:port、[IPv6]:port）
   d. 校验是否为合法 IP；非法 → 继续下一个头部
   e. 命中 → 返回该 IP，记 flag=real_ip_from:<header>
3. 所有头部都无效 → 返回 D，记 flag=no_valid_header
```

**为什么从右往左**：`X-Forwarded-For` 是追加式头部，客户端可以伪造左侧内容。最右侧是**最后一个代理追加的**，最接近真实。从左往右取会被客户端注入的假 IP 欺骗。

#### 3.9.5 防伪造

| 攻击 | 防御 |
|---|---|
| 客户端直接发 `X-Forwarded-For: 1.2.3.4` | 直连 IP 不在 trusted_proxies → 整个头部被忽略 |
| 客户端发 `CF-Connecting-IP` 伪造 | 同上；且该头只在 Cloudflare 回源时存在 |
| 多层代理下污染 XFF 左侧 | 从右往左解析，跳过可信段 |
| 私有地址注入（`XFF: 10.0.0.1`） | 解析结果若是私有地址，视为无效，回退直连 IP |
| 超长 XFF（1000 个 IP） | 限制 `max_chain_depth`，超出部分忽略 |

#### 3.9.6 下游影响

还原后的 IP 必须用于**所有**依赖客户端地址的模块：

| 模块 | 使用哪个 IP |
|---|---|
| ACL 黑白名单 | **真实 IP** |
| 限流（按 IP） | **真实 IP** |
| 自动封禁 | **真实 IP** |
| GeoIP | **真实 IP** |
| 日志 `client_ip` | **真实 IP** |
| 日志 `direct_ip` | 直连 IP（仅 `log_both: true` 时） |
| 上游 `X-Forwarded-For` | 追加**真实 IP**，不是直连 IP |

**日志双记录示例**：

```json
{
  "client_ip": "203.0.113.42",
  "client_ip_source": "cf-connecting-ip",
  "direct_ip": "172.70.85.12",
  "country": "CN",
  "asn": 4134
}
```

`client_ip_source` 记录来源，便于排查"为什么这个 IP 不对"。

#### 3.9.7 IPv6 注意事项

- Cloudflare 的 IPv6 回源段较多，必须完整配置，漏一个段就会导致部分用户 IP 还原失败
- IPv6 地址在 XFF 中可能带方括号（`[2001:db8::1]:443`），需剥离
- 真实 IP 为 IPv6 时，ACL 的 `/64` 聚合仍然生效（见 5.6）

#### 3.9.8 一键预设

控制台提供预设，避免用户手工填 20 多个网段：

```yaml
real_ip:
  preset: cloudflare        # cloudflare | aliyun-cdn | tencent-cdn | cloudfront | frp | custom
```

预设只填 `trusted_proxies` 与 `header_priority`，其余字段用默认值。用户可在此基础上修改。

---

## 4. 路径匹配与转发

### 4.1 匹配类型与优先级

配置键为 `routes`（应用的子键），每个路由的匹配语法对齐 Nginx 的 `location`，降低用户学习成本：

| 优先级 | 类型 | 语法 | 示例 | 说明 |
|---|---|---|---|---|
| 1 | 精确 | `= /path` | `= /api/health` | 完全相等才命中 |
| 2 | 前缀（终止） | `^~ /path` | `^~ /static` | 命中后**不再检查正则** |
| 3 | 正则 | `~ pattern` / `~* pattern` | `~ ^/api/v\d+/` | 按配置顺序，首个命中生效 |
| 4 | 普通前缀 | `/path` | `/static` | 取最长匹配 |
| 5 | 默认 | `/` | `/` | 兜底 |

**正则路由默认关闭**（`routes.allow_regex: false`），需要在应用级显式开启。原因：正则匹配有性能开销，且写错会导致路由错乱，家庭场景 95% 的需求用前缀匹配就够了。

### 4.2 匹配算法（实现必须与此一致）

```
输入: 规范化后的请求路径 P
1. 若有精确匹配 "= P" 的 route → 返回它
2. 记录最长普通前缀匹配 L（同时记录 ^~ 匹配 T）
3. 若存在 T（^~ 且 T 是最长前缀）→ 返回 T
4. 按配置顺序遍历正则 route，首个匹配 → 返回它
5. 若有 L → 返回 L
6. 返回 "/" 或默认上游
```

**为什么这个顺序**：与 Nginx 一致，用户已有的直觉可直接迁移。`^~` 的存在是为了给"静态资源目录"一个跳过正则的快速通道，性能更好。

### 4.3 路径规范化（匹配前执行）

| 步骤 | 说明 | 示例 |
|---|---|---|
| 1. 百分号解码 | 单层解码 | `%2Fapi` → `/api` |
| 2. 合并重复斜杠 | | `/api//v1` → `/api/v1` |
| 3. 解析 `.` 与 `..` | 不能跳出根 | `/a/../b` → `/b` |
| 4. 移除路径参数 | `;` 之后的部分 | `/a;jsessionid=x` → `/a` |
| 5. 尾斜杠 | 默认保留（不自动合并） | `/api/` ≠ `/api` |

**安全要求**：规范化必须在**检测之前**完成，且必须与转发使用**同一份**规范化结果。否则会出现"检测看的是 A，后端收到的是 B"的绕过（这是经典 WAF 绕过手法）。

### 4.4 路径重写

```yaml
# 位于 application 下
routes:
  - path: /jellyfin
    rewrite:
      mode: strip_prefix               # strip_prefix | add_prefix | regex
      value: ""                        # strip 时移除的前缀，默认等于 path
      # mode=add_prefix 时 value 为要添加的前缀
      # mode=regex 时使用 regex/replacement
    regex: null
    replacement: null
```

示例：`/jellyfin/web/index.html` + `strip_prefix: /jellyfin` → `/web/index.html` 转发给上游。

**注意**：重写后要重新做一次路径规范化与安全检查，防止重写产生穿越（如 `strip_prefix` 后出现 `../`）。

### 4.5 方法限制

```yaml
routes:
  - path: /api
    allow_methods: [GET, POST, PUT, DELETE]
```

未列出的方法 → 405，带 `Allow` 头。

### 4.6 route 级策略覆盖

每个 route 可以覆盖应用级的任意策略，这是实现"管理后台从严、相册从宽"的关键：

```yaml
routes:
  - path: /admin
    policy:
      preset: strict                   # 更严格
      require_auth: totp
      allow_cidr: ["192.168.1.0/24", "fd00::/8"]
      observe_mode: { enabled: false } # 管理后台不观察，直接阻断
  - path: /upload
    policy:
      preset: lenient                  # 更宽松
      max_body_size: 2GB
      fail_policy: open                # 检测超时放行，避免中断上传
      protection:
        file_upload: monitor           # 只记录不拦
```

---

## 5. 访问控制（手动黑白名单）

### 5.1 条目模型

```rust
pub struct IpRule {
    pub id: u64,                 // 自增
    pub ip: IpNet,               // 单 IP 或 CIDR，IPv4/IPv6 统一
    pub action: IpAction,        // Allow | Deny | Challenge | Monitor
    pub scope: RuleScope,        // Global | Application(app_id) | AppPath(app_id, path)
    pub reason: String,          // 【必须】人类可读原因，用于审计
    pub source: RuleSource,      // Manual | Auto | Feed(name) | Import
    pub priority: i32,           // 数字越大越优先，默认 0
    pub expires_at: Option<i64>, // None = 永久
    pub created_at: i64,
    pub created_by: String,      // "admin" / "system" / "feed:chaitin"
    pub hit_count: u64,          // 命中计数（用于评估有效性）
    pub last_hit_at: Option<i64>,
}
```

### 5.2 手动添加

**API**：
```
POST /api/v1/acl/rules
{
  "ip": "203.0.113.0/24",
  "action": "deny",
  "scope": { "type": "application", "application_id": "nas" },
  "reason": "持续扫描 /admin",
  "expires_in": "7d"
}
```

**字段校验**：

| 字段 | 规则 |
|---|---|
| `ip` | 合法 IPv4/IPv6/CIDR；单 IP 自动转 `/32` 或 `/128` |
| `action` | 枚举 |
| `scope` | 全局 / 应用 / 应用+路径 |
| `reason` | 必填，1-256 字符 |
| `expires_in` | `1m` - `365d`，或 `never` |

**IPv6 特殊处理**：
- 单 IPv6 地址默认按 `/128` 存储，但**匹配时可按配置聚合到 /64**（`ipv6_prefix_match: 64`）
- 原因：IPv6 地址隐私扩展导致同一用户频繁换地址，逐地址封禁无效
- 默认值：`/64`（与家庭宽带分配一致）

### 5.3 批量导入

**支持格式**：

| 格式 | 示例 |
|---|---|
| 纯文本 | 每行一个 IP/CIDR，`#` 开头为注释 |
| CSV | `ip,action,reason,expires` |
| JSON | 数组，元素同 API 结构 |

**导入约束**：
- 单次最多 10,000 条
- 文件最大 5MB
- 必须选择 `action`（CSV/JSON 中未指定时使用）
- 冲突策略：`skip`（默认）/ `overwrite` / `error`

**导入报告**：
```
导入完成：成功 9,842 条，跳过 120 条（已存在），失败 38 条
失败原因：非法 IP 格式 31 条，前缀过长 7 条
[下载失败明细]
```

### 5.4 匹配顺序（实现必须严格遵循）

```
1. 查白名单（action=allow）
   命中 → 直接放行，跳过所有后续检测（包括规则引擎）
   例外：仍需记录访问日志
2. 查黑名单（action=deny）
   命中 → 直接阻断（403 / 444 可配）
3. 查挑战（action=challenge）
   命中 → 走人机验证流程
4. 查监控（action=monitor）
   命中 → 记录，但继续正常检测
5. 进入规则引擎
```

**同 action 内的优先级**：
1. `scope` 更具体的优先（site+path > site > global）
2. `priority` 数值大的优先
3. `expires_at` 更早的优先（临时规则覆盖永久规则，便于快速止血）
4. 创建时间更晚的优先

### 5.5 与自动封禁的关系

| 项 | 手动 | 自动 |
|---|---|---|
| 存储 | 同一张表 | 同一张表，`source=auto` |
| 默认时长 | 用户指定 | 5m → 30m → 2h → 24h（递增） |
| 优先级 | 高 | 低 |
| 自动解封 | 否（除非设了 expires） | 是 |
| 手动解封 | 可 | 可（且该 IP 在冷却期内不再自动封） |

**冷却机制**：手动解封一个自动封禁的 IP 后，该 IP 进入 24 小时冷却期，期间不再被自动封禁（避免"解封了立刻又被封"的循环）。

### 5.6 特殊地址处理

```yaml
acl:
  private_network:
    action: allow                    # allow | deny | normal
    cidrs:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - fd00::/8
      - 127.0.0.0/8
      - ::1/128
```

**默认 `allow`**：内网地址直接放行，不检测。理由：家庭内网设备（电视、音箱、手机）访问 NAS 不应该被 WAF 拦，而且它们经常发出奇怪的请求（老设备的 HTTP/1.0、非标准头）。

**风险提示**：如果 WAF 部署在公网侧且内网有被攻陷的设备，`allow` 会放行横向移动流量。控制台需对此配置显示警告。

### 5.7 性能与刷新

| 条目数 | 数据结构 | 查询 | 全量重建 |
|---|---|---|---|
| < 1,000 | Vec 线性 | ~1 μs | < 1 ms |
| 1k - 100k | 前缀树 | ~200 ns | < 50 ms |
| > 100k | 前缀树 + 热点缓存 | ~150 ns | 50-200 ms |

**增量更新**：单条增删直接改前缀树，不重建。批量导入（> 100 条）走"构建新树 + ArcSwap 替换"，避免长时间持锁。

---

## 6. 防护开关（按攻击类型）

### 6.1 开关矩阵

这是用户最常用的功能：能一键关掉某类检测。

```yaml
protection:
  sqli: block              # SQL 注入
  xss: block               # 跨站脚本
  cmdi: block              # 命令注入
  path_traversal: block    # 路径遍历 / LFI
  xxe: block               # XML 外部实体
  ssrf: block              # 服务端请求伪造
  ssti: block              # 模板注入
  ldap_xpath: monitor      # LDAP / XPath 注入
  nosql: monitor           # NoSQL 注入
  crlf: block              # CRLF 注入
  deserialization: monitor # 反序列化
  file_upload: block       # 恶意文件上传
  webshell: monitor        # Webshell 特征
  scanner: block           # 扫描器识别
  bruteforce: block        # 暴力破解
  cc_attack: block         # CC 攻击
  sensitive_leak: monitor  # 敏感信息泄露（响应方向）
```

### 6.2 默认值依据

| 类型 | 默认 | 理由 |
|---|---|---|
| SQLi / XSS / CMDi / 路径遍历 | `block` | 检出率高、误报低，家庭场景几乎不会误伤 |
| XXE / SSRF | `block` | 危害极大，正常业务极少需要 |
| 反序列化 | `monitor` | 误报率较高（正常 API 也会传 base64 二进制） |
| LDAP / XPath / NoSQL | `monitor` | 家庭场景少见，先观察 |
| 文件上传 | `block` | 但相册等应用建议改 `monitor` |
| Webshell | `monitor` | 响应方向检测误报高 |
| 敏感信息泄露 | `monitor` | 只记录不拦，避免影响正常业务 |

### 6.3 三态的实际行为

| 状态 | 规则加载 | 语义检测器 | 日志 | 阻断 |
|---|---|---|---|---|
| `off` | 不加载 | 不运行 | 无 | 否 |
| `monitor` | 加载 | 运行 | 记录 | 否 |
| `block` | 加载 | 运行 | 记录 | 是 |

**关键**：`off` 是真正的不加载，不是"加载了但不执行"——后者仍然消耗正则编译时间和内存。

### 6.4 灵敏度档位

档位是"批量预设"，避免用户逐项调 17 个开关。

```yaml
protection:
  preset: balanced         # lenient | balanced | strict | custom
```

| 档位 | 阻断阈值 | 语义置信度门槛 | 规则子集 | 适用 |
|---|---|---|---|---|
| `lenient` | 40 | 0.85 | 仅高危规则（约 40%） | 首次部署、怕误伤 |
| `balanced` | 25 | 0.70 | 核心规则（约 75%） | 默认 |
| `strict` | 10 | 0.55 | 全量规则 | 管理后台、确定无副作用 |
| `custom` | 用户自定 | 用户自定 | 用户自定 | 手动调过任一项后自动切换 |

**交互规则**：用户手动修改任意一项开关后，`preset` 自动变为 `custom`，并在 UI 上提示"已自定义，不再跟随档位"。

### 6.5 观察模式（Observe Mode）

#### 6.5.1 是什么

观察模式 = **全局把所有"阻断"降级为"记录"**，用于首次部署时评估误报，不影响任何真实请求。

它和三态开关的区别：

| | 单类开关 `monitor` | 观察模式 |
|---|---|---|
| 粒度 | 单个攻击类型 | 全局（或按应用/路径） |
| 用途 | 某一类规则上线观察 | 整个 WAF 首次部署、大版本升级后 |
| 配置量 | 需逐类设置 | 一个开关 |
| 退出方式 | 手动改回 `block` | 手动关闭或到期自动关闭 |

#### 6.5.2 配置

```yaml
protection:
  observe_mode:
    enabled: true
    scope: [rules, semantic]        # 观察范围，默认这两项
    auto_disable_after: 7d          # 可选，到期自动关闭并通知
```

**不在观察范围内的能力**（始终生效）：

| 能力 | 是否受观察模式影响 | 理由 |
|---|---|---|
| 规则引擎阻断 | ✅ 降级为记录 | 主要观察对象 |
| 语义引擎阻断 | ✅ 降级为记录 | 主要观察对象 |
| ACL 黑名单 | ❌ 仍然阻断 | 用户显式配置的封禁，不应被观察模式取消 |
| 限流 | ❌ 仍然限流 | 否则观察期等于裸奔，会被打挂 |
| 认证 | ❌ 仍然要求 | 同上 |
| IP 组订阅 | ❌ 按配置动作 | 用户已选择 challenge/block |

**优先级**：`observe_mode` > 单类开关的 `block` > `preset` 档位。

也就是说，即使某类设了 `block`，观察模式开启时仍只记录。

#### 6.5.3 观察期的产出

观察模式不是"什么都不做"，它要产出三个关键数字：

```
观察模式报告（运行 7 天）
════════════════════════════
总请求           1,284,392
规则命中           18,204  (1.42%)
  ├─ 若阻断会拦掉   1,203  (0.094%)
  └─ 其中疑似误报      87  (7.2% of 命中)
语义命中            3,412  (0.27%)
  ├─ 若阻断会拦掉     412  (0.032%)
  └─ 其中疑似误报      31  (7.5%)

误报 Top 3
  1. HW-2003 XSS 检测  命中 /notes/edit 的 Markdown 内容  42 次
  2. HW-1001 SQLi 检测  命中 /api/search 的搜索词          28 次
  3. HW-3010 路径遍历   命中 /files/../ 的正常下载链接      17 次

建议
  · 为上述 3 条规则添加例外后，误报率可降至 0.02%
  · 当前整体误报率 0.094%，低于 0.1% 目标，可切换到阻断模式
[一键添加例外] [切换为阻断模式] [继续观察 7 天]
```

**"若阻断会拦掉"这个数字是观察模式的核心价值**——它让用户在真正开启阻断前，就知道会影响多少请求。

#### 6.5.4 作用域

观察模式支持三层，与防护开关一致：

```yaml
protection:
  observe_mode: { enabled: true }        # 全局

applications:
  - id: photos
    policy:
      observe_mode: { enabled: false }   # 该应用不受观察模式影响，正常阻断

  - id: nas
    policy:
      observe_mode: { enabled: true }    # 该应用观察
    routes:
      - path: /admin
        policy:
          observe_mode: { enabled: false }  # 管理后台不观察，直接阻断
```

典型用法：全局观察，但管理后台立即阻断（因为它最危险，且访问者只有自己）。

#### 6.5.5 UI 要求

观察模式开启时，控制台必须**持续显示醒目横幅**，不能只在设置页可见：

```
┌──────────────────────────────────────────────────────────┐
│ ⚠ 观察模式运行中：所有检测仅记录，不阻断请求（剩余 5 天）    │
│   已记录 1,203 条本应阻断的请求  [查看报告] [立即关闭]      │
└──────────────────────────────────────────────────────────┘
```

**理由**：用户开了观察模式后忘记关，是这类产品最常见的安全事故。横幅 + 到期自动关闭是双重保险。

### 6.6 覆盖层级

```
global.protection  →  application.policy.protection  →  route.policy.protection
```

整体覆盖，不逐字段合并。

---

## 7. 规则管理与订阅更新

### 7.1 规则集分层（当前实现）

| 层 | 来源 | 更新方式 | 用户可否修改 |
|---|---|---|---|
| `builtin` | 随二进制内置 41 条 | 跟随版本升级 | 仅可开关、调阈值 |
| `feed` | 外部签名规则包 | 定时自动更新 + 手动刷新 | 仅可启用/停用订阅 |

`imported` / `user` 分层与单条规则覆盖尚未实现，当前自定义规则通过自建签名订阅包完成。

### 7.2 规则订阅配置

```yaml
rule_feeds:
  - name: official-core
    url: "https://rules.example.com/core-v1.hwrule"
    enabled: true                      # 停用后不加载、不拉取
    channel: stable                    # stable | beta | pinned
    auto_update: true
    check_interval: 24h                # 最小 60s
    update_window: "03:00-05:00"       # UTC；支持跨午夜，留空不限
    timeout: 20s                       # 1s-300s
    max_size: 4MB                      # 1KB-64MB
    headers: {}                        # 附加请求头（如 Authorization）
    require_signature: true            # 强制验签
    public_key: "ed25519:..."          # 32 字节 Ed25519 公钥
    shadow_period: 6h                  # 新载荷先只记录不拦截
    rollback_on_error: true            # 失败时沿用上次验签通过的缓存
    pinned_version: null               # channel=pinned 时必填
```

### 7.3 更新流程（实际实现）

```
到达检查时间（且处于 update_window）
  │
  ▼
拉取 ──失败──► 有缓存且 rollback_on_error ──► 使用缓存（状态 cache，记录错误）
  │                                            └─ 无缓存 ──► 不加载（状态 none）
  ▼
拆签名头 → 验签（require_signature 时必须通过）
  │ 失败 ──► 同上回退/拒绝
  ▼
解析 + 校验（格式、规则数、正则、id 冲突、内置规则冲突）
  │ 失败 ──► 同上回退/拒绝
  ▼
通道/固定版本检查（stable 不接受 beta 文档）
  │ 失败 ──► 同上回退/拒绝
  ▼
写入 SQLite 缓存 → 合并进检测引擎
  │
  ├─ 新载荷且配置了影子期 ──► 规则在 shadow_until 前只记录不拦截
  └─ 与上次载荷相同 ──► 保留原影子期（不会因定时拉取无限续期）
```

- 每个订阅整包接受或整包拒绝；跨订阅 id 冲突时后加载的整包跳过。
- 检查由控制台所在进程每 60 秒调度一次，仅重建状态时拉取到期订阅。
- 手动刷新忽略检查间隔与更新窗口，强制拉取全部启用订阅。

### 7.4 规则包格式与签名

```text
# homewaf-signature: ed25519:<base64 签名>
{"format":"homewaf-rules","version":"2026.10.1","channel":"stable","rules":[...]}
```

- 签名覆盖签名行之后的**原始字节**，任何改动都会导致验签失败。
- 文档支持 JSON 或 YAML；版本号可为字符串或数字；未知字段忽略。
- 单包最多 2000 条规则；id 不得与内置规则或其他订阅重复。
- 离线工具：

```bash
homewaf rulepack keygen --out signing.pkcs8   # 生成私钥（0600）与公钥
homewaf rulepack sign --key signing.pkcs8 rules.json -o core.hwrule
homewaf rulepack verify --key ed25519:... core.hwrule
```

### 7.5 版本与回滚

- SQLite 只保留每个订阅**最后一次验签通过**的载荷（`rule_feed_packages`）。
- 拉取/验签/解析失败时按 `rollback_on_error` 回退到该载荷；重启后同样可用。
- 状态替换走 `ArcSwap`，不会出现"新规则配旧连接池"的中间态。
- 多版本历史与一键回滚到任意版本尚未实现。

### 7.6 单条规则操作（规划）

```yaml
rule_overrides:
  - rule_id: HW-1001
    enabled: false                     # 禁用
  - rule_id: HW-2003
    score: 30                          # 调整分值
  - rule_id: HW-3001
    action: monitor                    # 降级为仅记录
```

---

## 8. 完整配置示例

```yaml
server:
  listen: ["[::]:80", "0.0.0.0:80"]              # 明文 HTTP
  tls_listen: ["[::]:443", "0.0.0.0:443"]        # HTTPS，需要 tls.cert/key
  admin:
    listen: "127.0.0.1:9443"

tls:
  min_version: "1.2"
  alpn: ["h2", "http/1.1"]
  cert: "/etc/homewaf/cert.pem"    # 全局单证书（M0）；多证书 SNI 在 T2
  key: "/etc/homewaf/key.pem"
  hsts:
    enabled: true
    max_age: 31536000
    include_subdomains: true

# 真实客户端 IP：Cloudflare Tunnel 回源
real_ip:
  enabled: true
  preset: cloudflare              # 自动填充 trusted_proxies 与 header_priority
  log_both: true                  # 日志同时记录真实 IP 与直连 IP

protection:
  preset: balanced
  observe_mode:
    enabled: false                # 首次部署建议 true，观察 7 天
    auto_disable_after: 7d
  sqli: block
  xss: block
  file_upload: monitor

acl:
  private_network:
    action: allow
  ipv6_prefix_match: 64
  auto_ban:
    enabled: true
    trigger_score: 50
    durations: ["5m", "30m", "2h", "24h"]
  rules:                              # 静态规则；白名单永远优先
    - id: allow-monitor
      cidr: 192.168.1.200/32
      action: allow
      note: "监控探针"
    - id: block-scanner
      cidr: 203.0.113.0/24
      action: deny
    - id: block-app-abuser
      cidr: 198.51.100.0/24
      action: deny
      scope: nas                      # 只对某个应用生效
      expires_at: 1790000000          # 到期自动失效

# 应用：一应用一域名
applications:
  - id: nas
    name: "NAS 管理"
    domains:
      primary: "nas.home.lan"
    upstreams:                    # 默认上游
      - { addr: 192.168.1.5, port: 5000 }
    routes:                       # 一个应用多个端口
      - path: /jellyfin
        upstreams: [{ addr: 192.168.1.5, port: 8096 }]
        rewrite: { mode: strip_prefix }
      - path: /ha
        upstreams: [{ addr: 192.168.1.6, port: 8123 }]
      - path: /admin
        policy:
          preset: strict
          require_auth: totp
          allow_cidr: ["192.168.1.0/24"]
          observe_mode: { enabled: false }

  - id: photos
    name: "家庭相册"
    domains:
      primary: "photos.home.lan"
      aliases: ["photo.home.lan"]
    upstreams:
      - { addr: 192.168.1.5, port: 2342 }
    timeouts:
      read: 300s
    policy:
      preset: lenient
      max_body_size: 2GB
      protection:
        file_upload: monitor
```

---

## 9. 错误码

| 码 | 场景 | 用户可见提示 |
|---|---|---|
| `CFG_001` | 未知字段 | 配置项 `xxx` 不存在，是否想写 `yyy`？ |
| `CFG_002` | 字段类型错误 | `applications[0].upstreams[1].port` 应为整数，实际为字符串 |
| `CFG_003` | 域名冲突 | `nas.home.lan` 同时被应用 A 和 B 声明 |
| `CFG_004` | 上游不可达 | 应用 `nas` 的上游 `192.168.1.5:5000` 连接失败 |
| `CFG_005` | ACL 冲突 | `allow` 与 `deny` 存在重叠网段 |
| `RULE_001` | 规则编译失败 | 规则 `HW-1001` 的正则第 3 行语法错误 |
| `RULE_002` | 规则包验签失败 | 规则包签名无效，已拒绝 |
| `RULE_003` | 引擎版本不兼容 | 规则包要求引擎 ≥ 1.2.0，当前 1.0.3 |
| `ACL_001` | 非法 IP | `300.1.1.1` 不是合法 IP |
| `ACL_002` | 前缀过长 | IPv4 前缀不得小于 /8 |

---

## 10. 开发任务拆分

按依赖顺序排列，可直接排期。

### 阶段一：地基（M0，4.5 周）

| 任务 | 内容 | 依赖 | 预估 |
|---|---|---|---|
| T1.1 | 配置模型定义 + 校验框架（serde + 自定义 validator） | — | 3d |
| T1.2 | 配置加载、热重载、ArcSwap 快照 | T1.1 | 2d |
| T1.3 | Pingora 集成骨架（监听 + 转发 + 优雅退出） | — | 4d |
| T1.4 | **应用模型**（Application：域名/上游/路由三层）+ 域名匹配与规范化 | T1.1 T1.3 | 3d |
| T1.5 | 路径匹配（5 种类型 + 优先级算法） | T1.4 | 3d |
| T1.6 | 上游与端口回源（单端口/路径映射/负载均衡） | T1.3 | 3d |
| T1.7 | ACL 前缀树 + 手动黑白名单 CRUD | T1.1 | 4d |
| T1.8 | IP 组订阅（拉取/护栏/diff） | T1.7 | 5d |
| T1.9 | 结构化日志 + 基础指标 | T1.3 | 2d |
| T1.10 | **真实客户端 IP 还原**（可信代理链 + 头部优先级 + 防伪造 + CDN 预设） | T1.3 | 3d |
| T1.11 | **观察模式**（全局/应用/路由三层 + 观察报告 + 到期自动关闭） | T1.5 | 2d |

### 阶段二：转发能力补全（M1，8 周）

| 任务 | 内容 | 依赖 | 预估 |
|---|---|---|---|
| T2.1 | 负载均衡（4 种算法） | T1.6 | 3d |
| T2.2 | 主动/被动健康检查 | T2.1 | 3d |
| T2.3 | 超时体系 + 重试（含幂等判断） | T1.6 | 3d |
| T2.4 | 请求/响应头改写（变量插值） | T1.6 | 3d |
| T2.5 | 路径重写（strip/add/regex） | T1.5 | 2d |
| T2.6 | WebSocket / gRPC 透传 | T1.3 | 4d |
| T2.7 | 连接池调优 + 零拷贝大文件 | T1.6 | 4d |
| T2.8 | TLS + ACME（HTTP-01/DNS-01） | T1.3 | 8d |

### 阶段三：检测与策略（M1.5 + M3）

| 任务 | 内容 | 依赖 | 预估 |
|---|---|---|---|
| T3.1 | 规则 DSL 解析 + 编译 | T1.1 | 6d |
| T3.2 | 规则匹配器（regex/contains/cidr/expr） | T3.1 | 5d |
| T3.3 | 防护开关矩阵 + 档位 | T3.1 | 3d |
| T3.4 | 异常评分 + 阈值判定 | T3.2 | 3d |
| T3.5 | 语义检测器（SQLi/XSS/CMDi/遍历/SSRF） | T3.4 | 25d |
| T3.6 | 归一化管线 | T3.5 | 4d |
| T3.7 | 规则订阅 + 灰度 + 回滚 | T3.1 | 5d |
| T3.8 | SecLang 转换器 | T3.1 | 20d |

### 阶段四：控制台（M2）

| 任务 | 内容 | 依赖 | 预估 |
|---|---|---|---|
| T4.1 | REST API 骨架 + 认证 | T1.1 | 4d |
| T4.2 | 应用管理页（域名/上游/路由三层） | T4.1 T1.4 | 5d |
| T4.3 | ACL 管理页（含批量导入） | T4.1 T1.7 | 4d |
| T4.4 | 规则管理页（开关/调参/加白） | T4.1 T3.3 | 5d |
| T4.5 | 事件详情页（证据链） | T4.1 | 4d |
| T4.6 | 仪表盘 + 实时流量 | T4.1 | 5d |
| T4.7 | 证书管理页 | T4.1 T2.8 | 3d |
| T4.8 | 订阅管理页（IP 组 + 规则包） | T4.1 T1.8 T3.7 | 4d |

**总计约 180 人日**（不含测试与文档）。

---

## 11. 关键验收用例

| 编号 | 场景 | 期望 |
|---|---|---|
| AC-01 | `nas.home.lan` 与 `photos.home.lan` 指向不同端口 | 各自路由正确，互不串流 |
| AC-02 | `/jellyfin/web` 经 strip_prefix 转发 | 上游收到 `/web`，且 `X-Forwarded-Prefix: /jellyfin` |
| AC-03 | 白名单 IP 触发 SQLi 规则 | **放行**（白名单优先级最高），但仍记日志 |
| AC-04 | 手动 deny 一个 IP 后又被自动封禁 | 保持手动规则，不被自动规则覆盖 |
| AC-05 | 手动解封自动封禁的 IP | 解封成功，24h 内不再自动封 |
| AC-06 | 关闭 `sqli` 开关 | 含 `union select` 的请求放行，且规则不加载（内存下降） |
| AC-07 | `preset: strict` 的管理后台 | 阈值 10，弱信号叠加即阻断 |
| AC-08 | IPv6 客户端换地址（同 /64） | 仍被封禁（前缀匹配生效） |
| AC-09 | 大文件下载 4K 视频 | 不断流，`read_timeout` 生效 |
| AC-10 | POST 请求上游 502 | **不重试**（非幂等），返回 502 |
| AC-11 | 规则包验签失败 | 拒绝应用，保留旧版本，告警 |
| AC-12 | 配置写错字段名 | 启动失败，提示"未知字段 xxx，是否想写 yyy" |
| AC-13 | 未配置的域名访问 | 444 断开，无任何响应 |
| AC-14 | 路径 `//api/../admin` | 规范化后匹配 `/admin` 策略，不绕过 |
| AC-15 | 内网设备访问 NAS | 默认放行，不检测 |
| AC-16 | 经 Cloudflare 访问，`CF-Connecting-IP: 203.0.113.42` | 日志 `client_ip=203.0.113.42`、`direct_ip=Cloudflare 节点`、`source=cf-connecting-ip`；ACL 与限流按 203.0.113.42 生效 |
| AC-17 | 客户端直连并伪造 `X-Forwarded-For: 1.2.3.4` | 直连 IP 不在可信段 → 头部被忽略，日志记录真实直连 IP |
| AC-18 | 多层代理，XFF 为 `1.1.1.1, 2.2.2.2, <可信CDN>` | 从右往左跳过可信段，取 2.2.2.2（不是最左的 1.1.1.1） |
| AC-19 | 一个应用配 3 个路由指向 3 个端口 | 各路径命中正确端口，未匹配路径走默认上游 |
| AC-20 | 应用别名域名 `photo.home.lan` 访问 | 与主域名 `photos.home.lan` 行为完全一致，证书覆盖两者 |
| AC-21 | 观察模式开启，触发 SQLi | 请求**放行**，记录"若阻断会拦掉"事件；ACL 与限流仍生效 |
| AC-22 | 观察模式到期（7 天） | 自动关闭并通知；若误报率 > 1% 则保持观察并告警 |
| AC-23 | 两个应用声明同一域名 | 配置校验失败，明确指出冲突的应用 |
| AC-24 | 应用 A 的 primary 出现在应用 B 的 aliases | 配置校验失败 |

---

**文档结束**
