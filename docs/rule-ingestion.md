# HomeWAF 规则获取与适配子系统设计

| 项目 | 内容 |
|---|---|
| 文档版本 | v0.1 |
| 日期 | 2026-10-22 |
| 关联文档 | `docs/PRD.md` 第 6 章、7.4 节、7.16 节 |
| 核心结论 | 不追求运行时兼容 SecLang，改为**离线转换 + 人工审核 + 回归验证** |

---

## 1. 为什么需要这个子系统

WAF 的能力上限由规则库决定，而规则库是二十年攻防对抗的沉淀。OWASP CRS 有 700 多条规则、覆盖 20 余类攻击、有完整的回归测试语料。从零开始写规则，等于把别人踩过的坑重新踩一遍，且短期内检出率必然惨不忍睹。

但"直接用别人的规则"有三个现实障碍：

1. **格式不通**：CRS 是 SecLang，我们是自研 DSL。
2. **运行时兼容不可行**：纯 Rust 的 SecLang 引擎 `parapet` 只通过 94.3% 的 CRS 回归测试，作者自己标注"不可生产部署"。走 C++ FFI 又破坏单二进制前提。
3. **规则质量参差**：CRS 默认配置误报率 17.58%（雷池公开对比数据），直接全量导入会让家庭用户第一天就想卸载。

所以正确的路径不是"兼容"，而是**"翻译 + 提炼 + 审核"**：把别人的规则当作**知识来源**，转成我们能执行、能解释、能调优的形式。

---

## 2. 三种策略对比

| 策略 | 做法 | 优点 | 缺点 | 结论 |
|---|---|---|---|---|
| **运行时兼容** | 实现 SecLang 解释器，直接加载 `.conf` | 规则零成本复用，跟随 CRS 更新 | 工作量巨大；兼容性永远差一截（那 5.7% 就是绕过）；性能受限于通用解释 | ❌ 否决 |
| **离线转换** | 解析外部规则 → 统一 IR → 我们的 DSL | 可控、可审核、失败可见；可针对我们的语义引擎做优化 | 需写转换器；覆盖率非 100% | ✅ **采用** |
| **人工重写** | 照着规则手写 DSL | 质量最高，无冗余 | 700 条规则人工重写不现实 | ⚠️ 仅用于转换失败的关键规则 |

**关键设计：转换发生在"构建/导入"时，不在"请求处理"时。** 转换产物是编译好的规则包，运行时零解析开销。这也意味着转换失败不会影响线上，只会体现在导入报告里。

---

## 3. 规则来源矩阵

按转换难度从低到高排列。**先做左边两列，它们是投入产出比最高的部分。**

| 来源 | 格式 | 转换难度 | 预期自动转换率 | 优先级 |
|---|---|---|---|---|
| **IP/CIDR 列表**（雷池 IP 组分享、Spamhaus、AWS IP ranges） | `text/plain`、JSON | 极低 | **100%** | P0 |
| **自定义简单规则** | YAML / CSV | 低 | 100% | P0 |
| **OWASP CRS** | SecLang `.conf` | 高 | 75-85%（估算，需实测） | P0 |
| **Coraza 规则集** | SecLang（CRS 兼容子集） | 高 | 同上 | P1 |
| **Naxsi 规则** | `naxsi.rules`（`MainRule` 语法） | 中 | 60-70% | P2 |
| **AWS WAF** | JSON（rate-based / byte-match / geo） | 中 | 70% | P2 |
| **Cloudflare 规则表达式** | 自定义表达式语言 | 中高 | 50% | P3 |
| **Snort / Suricata** | 规则文本（偏 L3/L4） | 高（仅 L7 部分可映射） | 30% | P3 |
| **YARA** | YARA 规则 | 低（但用途是文件扫描，非 HTTP） | 80%（映射到上传文件扫描） | P3 |
| **雷池自定义规则** | 闭源格式，需导出/逆向 | 未知 | 未知 | 观察 |

> **诚实说明**：雷池（SafeLine）的检测引擎闭源，其规则无法直接导出。它的 IP 组分享接口是公开的（本文第 8 节详述），但 HTTP 检测规则不可获取。不要在产品宣传中暗示"兼容雷池规则"。

---

## 4. 统一中间表示（IR）

N 个来源 → 1 个 IR → 1 个目标 DSL。这样加新来源只需写一个 Parser，不需要改 Mapper。

```rust
/// 规则集：一次导入的完整产物
pub struct RuleSet {
    pub meta: RuleSetMeta,           // 来源、版本、许可证、导入时间、校验和
    pub variables: Vec<VariableDecl>, // tx.* 初始化（对应 SecAction setvar）
    pub rules: Vec<Rule>,
    pub markers: Vec<Marker>,        // SecMarker，用于 skipAfter 跳转
    pub unsupported: Vec<Unsupported>, // 无法转换的条目及原因
}

pub struct RuleMeta {
    pub id: String,                  // 原规则 ID，保留可追溯
    pub name: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub tags: Vec<String>,           // 如 owasp-a03, attack-sqli
    pub references: Vec<String>,     // CVE、URL
    pub source: SourceRef,           // 来源文件 + 行号
}

pub struct Rule {
    pub meta: RuleMeta,
    pub phase: Phase,
    pub targets: Vec<Target>,
    pub transforms: Vec<Transform>,
    pub operator: Operator,
    pub actions: Vec<Action>,
    pub chain: Vec<Rule>,            // 非空表示这是一条 chain 的头部
    pub labels: Vec<String>,         // 供 skipAfter 引用
}

pub enum Target {
    /// 所有参数（query + body），支持按名称排除
    Args { include: Vec<String>, exclude: Vec<String> },
    ArgsGet,
    ArgsPost,
    ArgsJson,
    /// 指定头部；None 表示全部
    Headers { name: Option<String> },
    Cookies,
    Body,
    Uri,
    Filename,
    QueryString,
    Method,
    Protocol,
    RemoteAddr,
    /// 事务变量，用于跨规则状态传递
    Tx(String),
    /// 原始请求行
    RequestLine,
}

pub enum Transform {
    Lowercase,
    UrlDecode,
    UrlDecodeUni,          // 含 %uXXXX
    HtmlEntityDecode,
    JsDecode,
    Base64Decode,
    HexDecode,
    RemoveComments,
    RemoveWhitespace,
    CompressWhitespace,
    NormalizePath,
    NormalizePathWin,
    Trim,
    Length,
    Sha1,
    CmdLine,
}

pub enum Operator {
    Regex(String),                    // 统一编译为 Rust regex 语法
    Contains(Vec<Vec<u8>>),           // 多字面量，编译为 Aho-Corasick
    Prefix(Vec<u8>),
    Suffix(Vec<u8>),
    Eq(i64),
    GreaterThan(i64),
    LessThan(i64),
    IpMatch(Vec<IpNet>),
    /// 映射到我们的语义检测器，替代原规则的低质量正则
    SemanticSqli { min_confidence: f32 },
    SemanticXss { min_confidence: f32 },
    ValidateByteRange(Vec<(u8, u8)>),
    ValidateUrlEncoding,
    ValidateUtf8Encoding,
    DetectNullByte,
    UnconditionalMatch,
}

pub enum Action {
    Block { status: u16 },
    Deny,
    Drop,
    Allow,
    Pass,
    Log,
    NoLog,
    AuditLog,
    /// 对应 setvar:tx.score=+%{tx.critical_anomaly_score}
    Score { variable: String, delta: ScoreDelta },
    SetVar { name: String, op: VarOp, value: Expr },
    Tag(String),
    Severity(Severity),
    SkipAfter(String),
    Skip(u32),
    Capture,
    /// 对应 ctl:ruleRemoveTargetById
    RemoveTarget { rule_id: String, target: String },
}

pub enum Unsupported {
    UnknownVariable { name: String, line: usize },
    UnknownOperator { name: String, line: usize },
    UnknownTransform { name: String, line: usize },
    PcreIncompatible { pattern: String, reason: String },
    ControlFlowTooComplex { line: usize, detail: String },
    ExternalDependency { module: String, line: usize },
}
```

**IR 的设计原则**：

1. **保留可追溯性**：每条规则记住来源文件与行号，出问题能回溯到原文。
2. **显式表达"不支持"**：转换器遇到不认识的结构**必须报错并记录**，绝不静默跳过。这是从 `parapet` 的教训里学到的——静默跳过等于制造绕过。
3. **语义操作符优先**：`@detectSQLi` 不翻译成正则，直接映射到我们的语义检测器，这反而比原规则更强。

---

## 5. 转换管线

```
┌──────────┐   ┌──────────┐   ┌────────┐   ┌────────┐   ┌───────────┐
│ Fetcher  │──►│ Detector │──►│ Parser │──►│ Mapper │──►│ Validator │
│ 拉取/读文件│   │ 格式识别  │   │ 解析    │   │ IR→DSL │   │ 编译+校验  │
└──────────┘   └──────────┘   └────────┘   └────────┘   └─────┬─────┘
                                                               │
                          ┌────────────────────────────────────┘
                          ▼
                   ┌──────────────┐   ┌──────────┐   ┌──────────┐
                   │ 覆盖率报告    │──►│ 人工审核  │──►│ 规则包    │
                   │ Coverage     │   │ Review   │   │ Signed   │
                   └──────────────┘   └──────────┘   └──────────┘
```

### 5.1 Fetcher

| 输入类型 | 处理 |
|---|---|
| 本地文件 | 直接读取，限制 10MB |
| URL | HTTPS only；限制 10MB；超时 15s；禁止解析到内网（SSRF 防护） |
| Git 仓库 | 浅克隆指定目录，校验 commit hash |
| 内联文本 | API 直接提交 |

### 5.2 Detector（格式识别）

按优先级嗅探，不依赖文件扩展名：

| 特征 | 判定 |
|---|---|
| 每行匹配 `^[\d.:a-fA-F/]+$` 且能被 `IpNet` 解析 | CIDR 列表 |
| 含 `SecRule` / `SecAction` / `SecMarker` 关键字 | SecLang |
| 以 `{` 或 `[` 开头且能 JSON 解析 | JSON（进一步看字段判断是 AWS WAF 还是自定义） |
| 含 `MainRule` 且形如 `MainRule "str:..."` | Naxsi |
| 含 `alert ` / `drop ` 且含 `->` | Snort/Suricata |
| 含 `rule ` + `{` + `condition:` | YARA |

### 5.3 Parser

每种格式一个独立模块，输出 IR。**解析器必须保留原始行号**，用于报告定位。

SecLang 解析要点：
- 词法：区分引号内、转义、注释（`#` 行首）
- 语法：`SecRule VARIABLES OPERATOR [ACTIONS]`，动作以逗号分隔但引号内的逗号不分隔
- 变量修饰符：`ARGS:foo`、`ARGS|!ARGS:bar`、`REQUEST_HEADERS:User-Agent`
- 操作符否定：`!@rx`、`!@pm`
- 动作参数：`id:1`、`status:403`、`msg:'...'`、`setvar:'tx.score=+5'`

### 5.4 Mapper（IR → HomeWAF DSL）

| IR | DSL 输出 |
|---|---|
| 单条 Rule，无 chain | 一条 `rules:` 项 |
| chain（多段） | `match.all` 嵌套 |
| `Score { delta }` | `action: score` + `score: <delta>` |
| `SemanticSqli` | `semantic: sqli` + `min_confidence` |
| `Contains` 多字面量 | `contains: [...]`（运行时走 Aho-Corasick） |
| `IpMatch` | `cidr: [...]` |
| `RemoveTarget` | 生成 `exceptions` 项 |
| `SkipAfter` | 编译为规则分组 + 组内条件（见 5.6） |
| `UnconditionalMatch` | 恒真条件，仅执行动作 |

### 5.5 Validator

三步校验，任一步失败即标记该条规则不可用：

1. **语法校验**：DSL AST 结构合法
2. **正则编译**：用 `regex` crate 编译，失败则降级为 `Contains` 或标记失败
3. **语义校验**：目标变量在当前阶段是否可读（例如 `RESPONSE_BODY` 在 `request_headers` 阶段无意义）

### 5.6 难点：PCRE → Rust regex

CRS 的 273 个 `@rx` 操作符中（`parapet` 实测数据）：

| 情况 | 数量 | 处理 |
|---|---|---|
| 直接兼容 | 268 | 直接编译 |
| 需词法修复（字符类内多余转义、`{` 未转义） | 5 | 自动修复后编译 |
| 需要 lookaround / backreference | 0 | — |

**这是个好消息**：CRS 的正则实际上没有用 PCRE 独有特性。所以正则兼容不是瓶颈。

但为了防御未来规则，转换器仍需检测：
- 前瞻/后顾 `(?=)` `(?<=)` `(?!)` → 尝试 `fancy-regex`（有回溯，需限制输入长度），否则标记失败
- 反向引用 `\1` → 标记失败（无法安全转换）
- 原子组 `(?>...)` → 去掉原子组语法后尝试
- 递归 `(?R)` → 标记失败

**安全底线**：任何可能引入回溯的正则，必须在转换时用 ReDoS 检测器跑一遍（用已知的病态输入测执行时间），超过 1ms 直接拒绝。

### 5.7 难点：skipAfter 与 SecMarker

CRS 用 `SecMarker BEGIN_X` / `skipAfter:END_X` 实现"跳过一整段规则"。我们的 DSL 没有 goto。

解决方案：**规则分组 + 条件门控**。

```yaml
# 原始 SecLang
SecMarker BEGIN_HOSTCHECK
SecRule REQUEST_HEADERS:Host "!@rx ^..." "id:920170,skipAfter:END_HOSTCHECK"
...
SecMarker END_HOSTCHECK

# 转换后
- group: hostcheck
  gate:
    not:
      regex: '^...'
      target: headers.host
  rules:
    - id: HW-920170-g1
      ...
```

`gate` 不满足时整组跳过。语义等价，且更容易理解。

### 5.8 难点：setvar 与 tx 变量

CRS 的异常评分依赖 `setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}` 这类累加。

我们不需要模拟完整的 tx 变量系统，只需要识别**三种模式**：

| 模式 | 映射 |
|---|---|
| 累加评分到 `tx.anomaly_score` | `action: score`，值取增量 |
| 设置标志位 `tx.foo=1` | 规则内局部状态（同一 chain 内有效） |
| 计数 `tx.foo=+1` | `rate` 匹配器或省略（记 warning） |

超出这三种的复杂用法（如字符串拼接、条件赋值）→ 标记 `Unsupported::ControlFlowTooComplex`，进人工队列。

---

## 6. 覆盖率报告

导入完成后必须生成一份人话报告，这是"可解释"原则在规则层面的体现。

```
规则导入报告
════════════════════════════════════════
来源      OWASP CRS v4.9.0 (rules/*.conf)
时间      2026-10-22 10:30:12
────────────────────────────────────────
总条目    721
✅ 成功    578  (80.2%)
⚠️ 待确认   96  (13.3%)   ← 需人工判断语义是否等价
❌ 失败     47  ( 6.5%)

失败原因 Top 5
  1. 不支持的变量 REQUEST_HEADERS:X-Forwarded-Host   12 条
  2. 流程控制过于复杂（skipAfter 嵌套）                9 条
  3. 正则含反向引用                                   8 条
  4. 依赖外部数据文件（@pmFromFile 路径不存在）        7 条
  5. 未知转换函数 t:utf8toUnicode                     6 条

建议
  · 47 条失败规则中，有 18 条属于同一攻击类别（文件上传），
    建议用语义检测器 file_upload 覆盖，无需逐条修复。
  · 96 条待确认规则在影子模式下命中 0 次，可暂时禁用。

[查看详情] [导出 CSV] [仅导入成功的 578 条]
```

**关键指标**：
- 不只是"成功多少条"，而是"成功覆盖了哪些攻击类别"
- 按攻击类别给出覆盖率，比按规则条数更有意义

| 攻击类别 | CRS 规则数 | 转换成功 | 覆盖率 | 备注 |
|---|---|---|---|---|
| SQL 注入 | 82 | 78 | 95% | 4 条改用语义检测器 |
| XSS | 64 | 61 | 95% | |
| 路径遍历 | 38 | 38 | 100% | |
| 命令注入 | 31 | 29 | 94% | |
| 文件上传 | 45 | 27 | 60% | 失败集中在 multipart 边界处理 |
| 协议异常 | 56 | 52 | 93% | |
| 其他 | 405 | 293 | 72% | |

> 上表为基于 CRS 规则结构的**估算**，实际数字需在 M1 阶段用真实 CRS 跑一遍确定。PRD 中不承诺具体数字。

---

## 7. 规则质量分级

导入的规则不能和自研规则平起平坐，必须带来源标记与置信度。

| 级别 | 来源 | 默认状态 | 说明 |
|---|---|---|---|
| **A 自研核心** | HomeWAF 官方 | 启用，阻断 | 经过完整语料回归 |
| **B 转换已验证** | CRS 等，且通过我们的回归语料 | 启用，阻断 | 转换后跑了正负样本测试 |
| **C 转换未验证** | CRS 等，未跑回归 | **启用，仅记录** | 影子模式观察 7 天 |
| **D 人工审核** | 转换待确认项 | 禁用 | 等用户确认 |
| **E 外部订阅** | IP 组、威胁情报 | 启用，按配置动作 | 有 TTL 与变更护栏 |

**默认策略**：任何导入的规则一律先进入 C 级（仅记录），跑满 7 天且误报为 0 才升级为 B 级。这是"低误报优先"原则的具体落地。

---

## 8. IP 组订阅（对应雷池分享链接）

### 8.1 实测数据

对用户提供的链接 `https://ip-35193.rivers.chaitin.cn/api/share/ip_group/cb8cc628...?format=cidr` 的实际抓取结果：

| 项 | 值 |
|---|---|
| HTTP 状态 | 200 |
| Content-Type | `text/plain; charset=UTF-8` |
| 响应体 | 每行一个 CIDR，无 BOM、无注释、无表头 |
| 总条数 | 578 |
| IPv4 | 305 条（/16 ×1、/18 ×3、/19 ×2、/22 ×1、/23 ×25、/24 ×270、/25 ×3） |
| IPv6 | 273 条（**/28 ×1**、/62 ×3、/63 ×42、/64 ×227） |
| 重复 | 0 |
| 可合并压缩 | 0（源已聚合） |
| 覆盖地址数（IPv4） | 214,400 |

**三个直接影响设计的结论**：

1. **IPv6 占 47%**，且以 /64 为主。不支持 IPv6 的 WAF 在这类情报源上直接损失一半覆盖。这印证了 PRD 中"双栈原生"的必要性。
2. **存在超宽前缀 `240d:c010::/28`**，覆盖 2^100 个地址。如果直接应用，等于把某运营商的一大块 IPv6 空间全部封禁。**必须有前缀长度下限护栏**。
3. **数据量很小（578 条，约 12KB）**，但设计要按 10 万条准备（Spamhaus DROP 列表约 1.5 万条，某些商业情报源可达数十万）。

### 8.2 配置模型

```yaml
ip_groups:
  - name: "chaitin-shared-cb8cc628"
    enabled: true
    source:
      url: "https://ip-35193.rivers.chaitin.cn/api/share/ip_group/cb8cc6282f7f4b58abf9f48b45a1f67b?format=cidr"
      format: auto                 # auto | cidr | json | text
      interval: 6h                 # 拉取周期
      timeout: 15s
      headers: {}                  # 可加 Authorization
      etag: true                   # 支持 ETag / If-Modified-Since，省流量
    action: challenge              # block | challenge | log
    scope: []                      # 空 = 全部站点；可限定 host 列表
    expires: 24h                   # 拉取失败后旧数据的最长保留时间
    guards:
      max_entries: 200000          # 条目上限
      min_prefix_v4: 8             # 拒绝比 /8 更宽的 IPv4 段
      min_prefix_v6: 32            # 拒绝比 /32 更宽的 IPv6 段
      max_delta_ratio: 0.5         # 单次变更超过 50% 需人工确认
      max_response_bytes: 10485760 # 10MB
    on_failure: keep_last          # keep_last | empty | disable
```

### 8.3 拉取与合并流程

```
定时触发（interval）
   │
   ├─► 条件请求（If-None-Match / If-Modified-Since）
   │      └─ 304 → 跳过，不产生任何变更
   │
   ├─► 下载 → 大小校验 → 格式识别 → 解析
   │
   ├─► 规范化
   │      · strict=False（1.2.3.4/24 → 1.2.3.0/24）
   │      · IPv4-mapped IPv6 归一化为 IPv4
   │      · 去重
   │      · 合并相邻可聚合段（collapse）
   │
   ├─► 护栏校验（见 8.4）
   │      └─ 任一失败 → 拒绝应用，保留旧数据，告警
   │
   ├─► 与旧版本 diff
   │      · 新增 N 条 / 删除 M 条
   │      · 变更比例 = (N+M) / max(old,new)
   │
   ├─► 应用（构建新的前缀树，ArcSwap 原子替换）
   │
   └─► 记录审计事件（来源、条数、diff 摘要、耗时）
```

### 8.4 安全护栏（供应链防护）

订阅外部列表本质上是把**别人给的封禁决策**直接应用到自己网络上，风险极高。以下护栏是强制项，不可关闭：

| 护栏 | 阈值 | 触发行为 |
|---|---|---|
| **拒绝全网段** | `0.0.0.0/0`、`::/0` | 直接丢弃该条 + 告警 |
| **IPv4 前缀下限** | 默认 /8（可调至 /4） | 丢弃该条 + 告警 |
| **IPv6 前缀下限** | 默认 /32 | 丢弃该条 + 告警 |
| **条目数上限** | 200,000 | 整体拒绝，保留旧数据 |
| **响应体大小** | 10MB | 整体拒绝 |
| **变更幅度** | 50% | 暂停应用，转人工确认 |
| **协议** | 仅 HTTPS | 拒绝 HTTP 源 |
| **SSRF 防护** | 解析结果不得为内网/回环/链路本地 | 拒绝拉取 |
| **失败降级** | 超过 `expires` 未成功拉取 | 告警，可选择清空或继续用旧数据 |
| **首次导入** | 默认 dry-run | 报告"若应用将封禁 X 个 IP"，需确认后才生效 |

**为什么变更幅度护栏重要**：如果情报源被投毒（或运营方误操作）把整个列表换成"全网段"，没有这个护栏，你的家庭网络会在 6 小时内对外全断。这不是假设——CDN 厂商误推路由、威胁情报源误标都发生过。

### 8.5 匹配性能

| 条目数 | 数据结构 | 单次查询 | 内存 |
|---|---|---|---|
| < 1,000 | `Vec<IpNet>` 线性扫描 | ~2 μs | 32 KB |
| 1,000 - 100,000 | 基数树（IPv4）/ 分层前缀树（IPv6） | ~200 ns | 条目数 × 48 B |
| > 100,000 | 上述 + 热点缓存 | ~150 ns | 同上 |

实现建议：`ip_network_table` crate 或自研 16 字节前缀树（IPv4 与 IPv6 统一用 128 位表示，IPv4 映射到 `::ffff:0:0/96`）。578 条的数据量下，线性扫描都够用，但为了未来扩展，直接用前缀树。

**关键**：IP 组查询必须在 ACL 阶段完成，属于 O(log n) 的常数级操作，**降级时也不跳过**（见 PRD 4.4.3）。

---

## 9. 规则包格式与分发

转换产物打包成可分发、可签名、可回滚的规则包。

```
homewaf-rules-crs-4.9.0-20261022.hwrule
├── manifest.json       # 元信息、版本、来源、许可证、校验和
├── rules/
│   ├── sqli.yaml
│   ├── xss.yaml
│   └── ...
├── corpus/             # 可选：配套回归语料
└── signature.ed25519   # 对 manifest 的签名
```

```json
{
  "name": "crs",
  "version": "4.9.0",
  "converted_at": "2026-10-22T10:30:12Z",
  "source": {
    "url": "https://github.com/coreruleset/coreruleset",
    "commit": "a1b2c3d",
    "license": "Apache-2.0"
  },
  "stats": { "total": 721, "ok": 578, "review": 96, "failed": 47 },
  "min_engine_version": "1.0.0",
  "checksum": "sha256:..."
}
```

**许可证合规**：CRS 是 Apache-2.0，允许转换与再分发，但必须保留版权声明与 NOTICE。规则包里每个转换后的规则保留 `source.id` 与 `references`，满足署名要求。**这一点必须在发布前由法务确认**。

---

## 10. 实施路线

| 阶段 | 内容 | 工期 |
|---|---|---|
| **S1** | CIDR 列表订阅（含全部护栏）、格式识别、前缀树、diff 与审计 | 1.5 周 |
| **S2** | 规则 DSL 与编译器（前置依赖，属 M1） | — |
| **S3** | SecLang 词法/语法解析器 → IR | 2.5 周 |
| **S4** | IR → DSL Mapper + Validator + 覆盖率报告 | 2 周 |
| **S5** | 用真实 CRS 跑通，建立基线覆盖率，修复 Top 5 失败原因 | 2 周 |
| **S6** | 规则包格式、签名、导入 UI、人工审核队列 | 1.5 周 |
| **S7** | 其他格式（Naxsi、AWS WAF）适配 | 按需 |

**S1 可以立刻做**，不依赖任何其他模块，且能马上产生价值（IP 封禁是家庭场景最立竿见影的防护）。建议作为 M0 的第一个交付物。

---

## 11. 明确不做的事

| 不做 | 原因 |
|---|---|
| 运行时加载 `.conf` 文件 | 需要完整 SecLang 解释器，parapet 已证明不可行 |
| 承诺 100% CRS 兼容 | 那 5.7% 就是绕过所在，承诺了就是骗人 |
| 自动跟随 CRS 上游更新并直接应用 | 上游规则变更可能引入误报，必须经转换 + 影子模式 |
| 转换雷池的 HTTP 检测规则 | 引擎闭源，规则不可获取 |
| 支持 Snort/Suricata 全量规则 | 大部分是 L3/L4 特征，与 L7 WAF 模型不匹配 |
| 让用户直接编辑转换后的规则并期望上游更新时保留 | 用户修改会被下次导入覆盖，需通过 `overrides` 机制（v1.1） |

---

## 12. 对 PRD 的修订建议

| PRD 位置 | 修订 |
|---|---|
| 3.4 非目标 | "首版不承诺 CRS 兼容"保留，但补充"提供离线转换工具" |
| 6 章 | 新增 6.6 节，引用本文档 |
| 7.4 FR-ACL-011 | 拆分为 IP 组订阅的 8 条详细需求 |
| 7.16（新增） | 规则导入与转换的 12 条需求 |
| 13 里程碑 | M0 增加 S1（IP 组订阅）；M1 增加 S3-S5（SecLang 转换） |
| 16.4 待决策 | 新增：规则包是否独立分发、是否内置 CRS 转换产物 |

---

**文档结束**
