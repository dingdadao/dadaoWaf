//! 配置模型。
//!
//! 设计约束（见 `docs/functional-spec.md`）：
//! 1. 所有字段都有默认值，配置可省略
//! 2. 未知字段必须报错，不静默忽略
//! 3. 三层覆盖：route > application > global（整体替换，不逐字段 merge）

use std::collections::BTreeMap;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::units::{Duration, Size};

// ============================================================
// 根配置
// ============================================================

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub acme: AcmeConfig,
    pub real_ip: RealIpConfig,
    pub limits: LimitsConfig,
    pub protection: ProtectionConfig,
    pub acl: AclConfig,
    pub ip_groups: Vec<IpGroup>,
    pub rule_feeds: Vec<RuleFeed>,
    pub ratelimit: RateLimitConfig,
    pub challenge: ChallengeConfig,
    pub logging: LoggingConfig,
    pub storage: StorageConfig,
    /// 应用列表。`sites` 为兼容别名。
    #[serde(alias = "sites")]
    pub applications: Vec<Application>,
    /// 自定义规则。兼容雷池（长亭）的 pattern / action 0|1 格式。
    pub custom_rules: Vec<CustomRule>,
    /// 自定义检测规则（本地规则）：命中后计入检测分数，可直接拦截。
    pub custom_detect_rules: Vec<DetectRule>,
}

// ============================================================
// 自定义规则（兼容雷池 / 长亭格式）
// ============================================================

/// 一条自定义规则。
///
/// 与雷池导出的 JSON 字段保持一致：`name` / `is_enabled` / `pattern` / `action`，
/// 其中 `pattern` 是「OR 的外层 + AND 的内层」，`action` 0 为白名单、1 为黑名单。
/// `id` 是 HomeWAF 自己的标识，导入时缺失会自动生成。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "is_enabled", alias = "enabled")]
    pub enabled: bool,
    /// 处置动作：0 = 放行（白名单），1 = 拦截（黑名单），2 = 人机验证，3 = 仅记录
    ///
    /// 沿用雷池的数字编码（0/1），2/3 是 HomeWAF 的扩展。
    pub action: u8,
    /// 条件组之间的组合方式：任意（默认，组间 OR）/ 全部（组间 AND）
    ///
    /// 组内条件始终是 AND。雷池界面上这一项叫「匹配方式」。
    #[serde(default)]
    pub match_mode: MatchMode,
    /// 序号：越大越新，求值时从大到小（新的规则先匹配）
    #[serde(default)]
    pub seq: i64,
    /// 创建时间（Unix 秒）
    #[serde(default)]
    pub created_at: Option<i64>,
    /// 生效应用 id；空表示对所有应用生效
    pub scope: Vec<String>,
    /// 到期时间（Unix 秒）；`None` 表示永久
    pub expires_at: Option<i64>,
    /// 外层 OR，内层 AND
    pub pattern: Vec<Vec<RuleCondition>>,
}

/// 一条自定义检测规则（「检测黑名单」）。
///
/// 与内置检测规则走同一条匹配路径，区别只是来源是用户自己写的。
/// 用途：攻击者用了某个新特征（特定 UA、特定参数、特定 payload），
/// 等不到规则包更新，先自己加一条直接拦掉。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DetectRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// 正则，作用于归一化后的文本
    pub pattern: String,
    /// 预过滤关键词（小写）。命中任一才跑正则，为空表示每次都跑
    pub keywords: Vec<String>,
    /// 作用对象：path / query / body / header / cookie / user_agent
    pub targets: Vec<String>,
    /// 分类，用于统计与展示：sqli / xss / scanner / custom ...
    pub category: String,
    /// 分值档位：low(10) / medium(25) / high(50) / critical(80)
    pub severity: String,
    /// block / log
    pub action: String,
    pub note: String,
    pub created_at: Option<i64>,
}

impl Default for DetectRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            pattern: String::new(),
            keywords: Vec::new(),
            // 默认扫 URL 与请求体：绝大多数特征都在这里
            targets: vec!["path".to_string(), "query".to_string(), "body".to_string()],
            category: "custom".to_string(),
            // 默认 high：单条即可越过默认拦截阈值 50
            severity: "high".to_string(),
            action: "block".to_string(),
            note: String::new(),
            created_at: None,
        }
    }
}

/// 条件组之间的组合方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// 任一条件组满足即可（OR）
    #[default]
    Any,
    /// 所有条件组都要满足（AND）
    All,
}

/// 规则的处置动作。把 `u8` 收敛成枚举，避免求值路径上到处 `== 0`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleActionKind {
    /// 放行：跳过检测与自动封禁
    Allow,
    /// 直接拦截
    Deny,
    /// 人机验证
    Challenge,
    /// 只记录，不改变处置
    Log,
}

impl Default for CustomRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            // 缺省必须是拦截：漏填 action 时把恶意流量放行，比误拦严重得多
            action: 1,
            match_mode: MatchMode::Any,
            seq: 0,
            created_at: None,
            scope: Vec::new(),
            expires_at: None,
            pattern: Vec::new(),
        }
    }
}

impl CustomRule {
    /// 白名单规则：命中后跳过检测与自动封禁。
    pub fn is_whitelist(&self) -> bool {
        self.action == 0
    }

    pub fn action_kind(&self) -> RuleActionKind {
        match self.action {
            0 => RuleActionKind::Allow,
            2 => RuleActionKind::Challenge,
            3 => RuleActionKind::Log,
            _ => RuleActionKind::Deny,
        }
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|ts| ts <= now)
    }

    /// 规则是否对该应用生效。
    pub fn applies_to(&self, app: &str) -> bool {
        self.scope.is_empty() || self.scope.iter().any(|s| s == app)
    }

    /// 规则是否具备可求值的条件。
    pub fn is_effective(&self) -> bool {
        self.enabled && self.pattern.iter().any(|group| !group.is_empty())
    }
}

/// 规则条件。`k` 是字段、`op` 是算子、`v` 是候选值。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RuleCondition {
    pub k: String,
    pub op: String,
    /// 雷池导出既可能是数组也可能是单个字符串，统一读成数组
    #[serde(deserialize_with = "string_or_vec")]
    pub v: Vec<String>,
    /// 子字段，例如 `header` 条件下的头名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_k: Option<String>,
}

fn string_or_vec<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
        Num(u64),
        /// 雷池导出里可能出现 `v: null`
        Null,
    }

    Ok(match OneOrMany::deserialize(de)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
        OneOrMany::Num(n) => vec![n.to_string()],
        OneOrMany::Null => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{CustomRule, IpGroup};

    #[test]
    fn parses_ip_group_with_label_from_leichi() {
        // 雷池同步写入的 IP 组会带展示名，旧库已有这种数据，必须能继续解析。
        let json = r#"{
            "name": "lei-ipgroup-3", "label": "蜜罐捕获IP", "enabled": true,
            "source": {"url": "https://example.com/list", "format": "cidr",
                       "interval": "1h", "timeout": "15s", "headers": {}},
            "action": "block", "scope": [], "expires": "1d",
            "guards": {"max_entries": 200000, "min_prefix_v4": 8, "min_prefix_v6": 32,
                       "max_delta_ratio": 0.5, "max_response_bytes": "10MB"},
            "on_failure": "keep-last"
        }"#;
        let g: IpGroup = serde_json::from_str(json).unwrap();
        assert_eq!(g.name, "lei-ipgroup-3");
        assert_eq!(g.label, "蜜罐捕获IP");
    }

    #[test]
    fn parses_leichi_custom_rule_payload() {
        let json = r#"[{
            "name": "放行内网",
            "is_enabled": true,
            "action": 0,
            "pattern": [[
                {"k": "src_ip", "op": "eq", "v": "192.168.1.0/24"},
                {"k": "header", "sub_k": "X-Token", "op": "contain", "v": null}
            ]]
        }]"#;
        let rules: Vec<CustomRule> = serde_json::from_str(json).unwrap();
        assert_eq!(rules[0].name, "放行内网");
        assert!(rules[0].is_whitelist());
        assert_eq!(rules[0].pattern[0][0].v, vec!["192.168.1.0/24"]);
        assert!(rules[0].pattern[0][1].v.is_empty());
    }
}

/// 持久化配置。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// SQLite 文件路径。设为空字符串则纯内存运行（重启丢失封禁与事件）
    pub path: String,
    /// 事件保留天数，超期自动清理
    pub events_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: "./data/homewaf.db".to_string(),
            events_retention_days: 30,
        }
    }
}

// ============================================================
// 服务器
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// worker 线程数，0 表示按 CPU 自动
    pub workers: usize,
    /// 明文 HTTP 监听地址，如 `"[::]:80"`、`"0.0.0.0:80"`
    pub listen: Vec<String>,
    /// HTTPS 监听地址，如 `"[::]:443"`。需要配置 `tls.cert` 与 `tls.key`
    pub tls_listen: Vec<String>,
    /// 上游响应体的读超时。WebSocket 等长连接空闲超过该值会被中断，
    /// pingora 默认 60s 对心跳间隔较大的移动端连接过短。
    pub upstream_read_timeout: Duration,
    pub admin: AdminConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            workers: 0,
            // 只列 0.0.0.0：在 Linux 上 [::]:80 默认是双栈，与 0.0.0.0:80 同时监听会冲突
            listen: vec!["0.0.0.0:80".to_string()],
            tls_listen: Vec::new(),
            upstream_read_timeout: Duration::from_secs(300),
            admin: AdminConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// 管理面监听地址。默认只监听回环。
    pub listen: String,
    pub unix_socket: Option<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9443".to_string(),
            unix_socket: None,
        }
    }
}

// ============================================================
// TLS
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub min_version: TlsVersion,
    pub alpn: Vec<String>,
    /// 证书链文件（PEM）。M0 阶段为全局单证书，多证书 SNI 在 T2 实现
    pub cert: Option<String>,
    /// 私钥文件（PEM）
    pub key: Option<String>,
    pub hsts: HstsConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::V1_2,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cert: None,
            key: None,
            hsts: HstsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HstsConfig {
    pub enabled: bool,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: 31_536_000,
            include_subdomains: false,
            preload: false,
        }
    }
}

// ============================================================
// ACME
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub email: String,
    pub challenge: AcmeChallenge,
    pub provider: Option<String>,
    /// DNS 提供商凭证，值支持 `${ENV_VAR}` 插值
    pub credentials: BTreeMap<String, String>,
    pub renew_before_days: u32,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: String::new(),
            challenge: AcmeChallenge::Http01,
            provider: None,
            credentials: BTreeMap::new(),
            renew_before_days: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum AcmeChallenge {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
}

// ============================================================
// 真实客户端 IP
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RealIpConfig {
    pub enabled: bool,
    pub preset: Option<RealIpPreset>,
    /// 可信代理网段。只有来自这些网段的请求才解析转发头。
    pub trusted_proxies: Vec<IpNet>,
    /// 从订阅 IP 组补充的可信代理网段（填组名，可多选）。
    ///
    /// 云 CDN / 回源节点网段会变，靠订阅自动更新比手工维护可靠：
    /// 组的条目在重载时并入 `trusted_proxies`，两者取并集。
    #[serde(default)]
    pub trusted_proxy_groups: Vec<String>,
    pub header_priority: Vec<String>,
    pub max_chain_depth: u8,
    pub on_untrusted_header: UntrustedHeaderAction,
    /// 日志同时记录直连 IP 与还原 IP
    pub log_both: bool,
}

impl Default for RealIpConfig {
    fn default() -> Self {
        Self {
            // 默认关闭：未配置可信网段时解析头部等于允许伪造
            enabled: false,
            preset: None,
            trusted_proxies: Vec::new(),
            trusted_proxy_groups: Vec::new(),
            header_priority: default_real_ip_headers(),
            max_chain_depth: 3,
            on_untrusted_header: UntrustedHeaderAction::Ignore,
            log_both: true,
        }
    }
}

pub fn default_real_ip_headers() -> Vec<String> {
    vec![
        "CF-Connecting-IP".to_string(),
        "True-Client-IP".to_string(),
        "X-Real-IP".to_string(),
        "X-Forwarded-For".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RealIpPreset {
    Cloudflare,
    AliyunCdn,
    TencentCdn,
    Cloudfront,
    Frp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UntrustedHeaderAction {
    /// 忽略不可信来源的转发头，回退到直连 IP
    Ignore,
    /// 直接拒绝请求
    Reject,
}

// ============================================================
// 限制
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_header_size: Size,
    pub max_header_count: usize,
    pub max_body_size: Size,
    pub max_url_length: usize,
    pub queue_capacity: usize,
    pub queue_timeout: Duration,
    pub detect_budget: Duration,
    pub request_timeout: Duration,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_header_size: Size::from_bytes(32 * 1024),
            max_header_count: 100,
            max_body_size: Size::from_bytes(10 * 1024 * 1024),
            max_url_length: 8_192,
            queue_capacity: 1_024,
            queue_timeout: Duration::from_millis(200),
            detect_budget: Duration::from_millis(50),
            request_timeout: Duration::from_secs(30),
        }
    }
}

// ============================================================
// 防护开关
// ============================================================

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    /// 灵敏度档位。用户手动改任一开关后应切为 `custom`。
    pub preset: Option<Preset>,
    pub observe_mode: ObserveMode,
    pub block_threshold: Option<u32>,
    pub semantic: SemanticConfig,
    pub fail_policy: Option<FailPolicy>,

    pub sqli: Option<Toggle>,
    pub xss: Option<Toggle>,
    pub cmdi: Option<Toggle>,
    pub path_traversal: Option<Toggle>,
    pub xxe: Option<Toggle>,
    pub ssrf: Option<Toggle>,
    pub ssti: Option<Toggle>,
    pub ldap_xpath: Option<Toggle>,
    pub nosql: Option<Toggle>,
    pub crlf: Option<Toggle>,
    pub deserialization: Option<Toggle>,
    pub file_upload: Option<Toggle>,
    pub webshell: Option<Toggle>,
    pub scanner: Option<Toggle>,
    pub bruteforce: Option<Toggle>,
    pub cc_attack: Option<Toggle>,
    pub sensitive_leak: Option<Toggle>,
}

impl ProtectionConfig {
    /// 是否手动指定了任一单项开关（用于判定 preset 是否应自动切 custom）
    pub fn has_manual_toggles(&self) -> bool {
        [
            self.sqli,
            self.xss,
            self.cmdi,
            self.path_traversal,
            self.xxe,
            self.ssrf,
            self.ssti,
            self.ldap_xpath,
            self.nosql,
            self.crlf,
            self.deserialization,
            self.file_upload,
            self.webshell,
            self.scanner,
            self.bruteforce,
            self.cc_attack,
            self.sensitive_leak,
        ]
        .iter()
        .any(Option::is_some)
    }
}

/// 三态开关。不用布尔值：`monitor` 是"开了但先不拦"，这是最高频诉求。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Toggle {
    Off,
    Monitor,
    Block,
}

impl Toggle {
    pub fn is_blocking(self) -> bool {
        matches!(self, Toggle::Block)
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Toggle::Off)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Lenient,
    Balanced,
    Strict,
    Custom,
}

impl Preset {
    pub fn block_threshold(self) -> u32 {
        match self {
            Preset::Lenient => 40,
            Preset::Balanced => 25,
            Preset::Strict => 10,
            Preset::Custom => 25,
        }
    }

    pub fn min_confidence(self) -> f32 {
        match self {
            Preset::Lenient => 0.85,
            Preset::Balanced => 0.70,
            Preset::Strict => 0.55,
            Preset::Custom => 0.70,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObserveMode {
    pub enabled: bool,
    /// 到期自动关闭，如 `7d`
    pub auto_disable_after: Option<Duration>,
    /// 观察范围，默认规则与语义
    pub scope: Vec<ObserveScope>,
}

impl Default for ObserveMode {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_disable_after: None,
            scope: vec![ObserveScope::Rules, ObserveScope::Semantic],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObserveScope {
    Rules,
    Semantic,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SemanticConfig {
    pub enabled: bool,
    pub min_confidence: f32,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.70,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FailPolicy {
    /// 检测超预算则拒绝
    Closed,
    /// 检测超预算则放行并记录
    Open,
}

// ============================================================
// 访问控制
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AclConfig {
    pub private_network: PrivateNetworkConfig,
    /// IPv6 前缀匹配长度，应对隐私扩展导致的地址漂移
    pub ipv6_prefix_match: u8,
    pub auto_ban: AutoBanConfig,
    /// 静态规则。运行时还会从数据库加载自动封禁与订阅规则
    pub rules: Vec<AclRuleConfig>,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            private_network: PrivateNetworkConfig::default(),
            ipv6_prefix_match: 64,
            auto_ban: AutoBanConfig::default(),
            rules: Vec::new(),
        }
    }
}

/// 一条静态 ACL 规则。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclRuleConfig {
    /// 规则标识，写入日志便于追溯。省略时按顺序自动生成
    #[serde(default)]
    pub id: Option<String>,
    pub cidr: IpNet,
    #[serde(default)]
    pub action: AclRuleAction,
    /// 生效应用 id；省略表示全局
    #[serde(default)]
    pub scope: Option<String>,
    /// 到期时间（Unix 秒）
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AclRuleAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateNetworkConfig {
    pub action: PrivateNetworkAction,
    pub cidrs: Vec<IpNet>,
}

impl Default for PrivateNetworkConfig {
    fn default() -> Self {
        Self {
            action: PrivateNetworkAction::Allow,
            cidrs: default_private_cidrs(),
        }
    }
}

pub fn default_private_cidrs() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fd00::/8",
        "::1/128",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateNetworkAction {
    Allow,
    Deny,
    Normal,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutoBanConfig {
    pub enabled: bool,
    pub trigger_score: u32,
    pub durations: Vec<Duration>,
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trigger_score: 50,
            durations: vec![
                Duration::from_secs(300),
                Duration::from_secs(1_800),
                Duration::from_secs(7_200),
                Duration::from_secs(86_400),
            ],
        }
    }
}

// ============================================================
// IP 组订阅
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpGroup {
    /// 机器标识：只能字母/数字/`-`/`_`，参与规则 id 拼接，改名等于重建规则
    pub name: String,
    /// 中文名称，仅用于控制台展示；为空时界面回退显示 `name`
    #[serde(default)]
    pub label: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub source: IpGroupSource,
    #[serde(default)]
    pub action: IpGroupAction,
    /// 生效应用 id 列表，空表示全部
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default = "default_ipgroup_expires")]
    pub expires: Duration,
    #[serde(default)]
    pub guards: IpGroupGuards,
    #[serde(default)]
    pub on_failure: OnFailure,
}

fn default_true() -> bool {
    true
}

fn default_ipgroup_expires() -> Duration {
    Duration::from_secs(86_400)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpGroupSource {
    /// 订阅地址。`kind = aliyun_esa` 时不用填。
    #[serde(default)]
    pub url: String,
    /// 来源类型。`aliyun_esa` 表示直接调阿里云 OpenAPI 取回源网段。
    #[serde(default)]
    pub kind: IpGroupSourceKind,
    /// `kind = aliyun_esa` 时使用。
    #[serde(default)]
    pub aliyun: AliyunEsaSource,
    #[serde(default)]
    pub format: FeedFormat,
    #[serde(default = "default_feed_interval")]
    pub interval: Duration,
    #[serde(default = "default_fetch_timeout")]
    pub timeout: Duration,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// IP 组订阅的来源类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpGroupSourceKind {
    /// 普通 HTTPS 列表（chaitin、Spamhaus、FireHOL 等）
    #[default]
    Http,
    /// 阿里云 ESA「源站防护」回源网段（OpenAPI `GetOriginProtection`）
    AliyunEsa,
}

/// 阿里云 ESA 源站防护的接入参数。
///
/// ESA 的回源网段只从控制台复制或走 OpenAPI，没有公开订阅地址，
/// 所以这里保存调用凭据，由 HomeWAF 自己按周期拉取形成订阅。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct AliyunEsaSource {
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub access_key_secret: String,
    /// 站点 ID，可从 ESA 控制台的站点概览或 ListSites 接口获取。
    #[serde(default)]
    pub site_id: String,
    #[serde(default = "default_esa_region")]
    pub region: String,
}

fn default_esa_region() -> String {
    "cn-hangzhou".to_string()
}

fn default_feed_interval() -> Duration {
    Duration::from_secs(6 * 3_600)
}

fn default_fetch_timeout() -> Duration {
    Duration::from_secs(15)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedFormat {
    #[default]
    Auto,
    Cidr,
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpGroupAction {
    /// 放行：订阅命中后跳过检测与封禁（用于白名单 IP 组）
    Allow,
    Block,
    #[default]
    Challenge,
    Log,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpGroupGuards {
    pub max_entries: usize,
    pub min_prefix_v4: u8,
    pub min_prefix_v6: u8,
    pub max_delta_ratio: f32,
    pub max_response_bytes: Size,
}

impl Default for IpGroupGuards {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            min_prefix_v4: 8,
            min_prefix_v6: 32,
            max_delta_ratio: 0.5,
            max_response_bytes: Size::from_bytes(10 * 1024 * 1024),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnFailure {
    #[default]
    KeepLast,
    Empty,
    Disable,
}

// ============================================================
// 规则包订阅
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFeed {
    /// 机器标识：只能字母/数字/`-`/`_`，用于规则来源标记与缓存键
    pub name: String,
    /// 中文名称，仅用于控制台展示；为空时界面回退显示 `name`
    #[serde(default)]
    pub label: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub channel: FeedChannel,
    #[serde(default = "default_true")]
    pub auto_update: bool,
    #[serde(default = "default_rule_check_interval")]
    pub check_interval: Duration,
    pub update_window: Option<String>,
    #[serde(default = "default_rule_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_rule_max_size")]
    pub max_size: Size,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_true")]
    pub require_signature: bool,
    pub public_key: Option<String>,
    pub shadow_period: Option<Duration>,
    #[serde(default = "default_true")]
    pub rollback_on_error: bool,
    pub pinned_version: Option<String>,
}

fn default_rule_check_interval() -> Duration {
    Duration::from_secs(86_400)
}

fn default_rule_timeout() -> Duration {
    Duration::from_secs(20)
}

fn default_rule_max_size() -> Size {
    Size::from_bytes(4 * 1024 * 1024)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedChannel {
    #[default]
    Stable,
    Beta,
    Pinned,
}

// ============================================================
// 限流
// ============================================================

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// CC 防护总开关。默认关闭：它会改变正常大流量场景的行为，
    /// 不能因为升级固件就让用户的内网下载/同步突然被限。
    pub enabled: bool,
    pub global_qps: u32,
    pub per_ip_qps: u32,
    pub per_ip_conn: u32,
    pub per_url_qps: u32,
    /// 超限后的处置动作
    pub action: RateLimitAction,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            global_qps: 2_000,
            per_ip_qps: 100,
            per_ip_conn: 64,
            per_url_qps: 200,
            action: RateLimitAction::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    /// 直接返回 429
    #[default]
    Block,
    /// 先过人机验证，通过后放行
    Challenge,
    /// 只记录事件，不拦截
    Log,
}

/// 人机验证（JS 工作量证明）参数。
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChallengeConfig {
    pub enabled: bool,
    /// 前导零的十六进制位数。每加 1 计算量约翻 16 倍，家用默认 4（平均 6.5 万次哈希）。
    pub difficulty: u8,
    /// 通过验证后的免打扰时长
    pub ttl: Duration,
    /// 是否对中风险（30–59 分）启用滑块轨迹验证。
    /// 本期只预留令牌字段，页面尚未渲染滑块。
    pub slider: bool,
    /// IP 风险分达到该值即升级人机验证
    pub risk_challenge_threshold: u32,
    /// IP 风险分达到该值直接拦截
    pub risk_block_threshold: u32,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            difficulty: 4,
            ttl: Duration::from_secs(1_800),
            slider: false,
            risk_challenge_threshold: 30,
            risk_block_threshold: 60,
        }
    }
}

// ============================================================
// 日志
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub retention_days: u32,
    pub body_capture: BodyCapture,
    pub redact: RedactConfig,
    /// 日志根目录。按类型分成 access / upstream / security / error 四个子目录。
    /// 设为空字符串则只输出到控制台。
    pub dir: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            retention_days: 30,
            body_capture: BodyCapture::OnBlock,
            redact: RedactConfig::default(),
            dir: "./data/logs".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyCapture {
    Never,
    #[default]
    OnBlock,
    Always,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactConfig {
    pub headers: Vec<String>,
    pub params: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "x-api-key".to_string(),
            ],
            params: vec![
                "password".to_string(),
                "token".to_string(),
                "id_card".to_string(),
            ],
        }
    }
}

// ============================================================
// 应用
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub domains: Domains,
    /// 对外监听端口。空表示接受任意端口（沿用全局监听）。
    ///
    /// 参考雷池：一个应用可以只监听 80、或 80+443、或自定义端口。
    /// 这样同一台机器上不同应用能绑不同端口，不必都挤在 80/443。
    #[serde(default)]
    pub listen_ports: Vec<u16>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub tls: TlsModeConfig,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub lb: LbConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub headers: HeadersConfig,
    #[serde(default)]
    pub websocket: bool,
    /// 临时应用到期时间（Unix 秒）
    pub expires_at: Option<i64>,
    /// 备注，显示在应用列表与详情页
    #[serde(default)]
    pub description: String,
    /// 分组名，仅用于控制台归类
    #[serde(default)]
    pub group: String,
    /// 接入方式：反向代理 / 静态文件 / 重定向
    #[serde(default)]
    pub access_mode: AccessMode,
    /// `access_mode = static` 时生效
    #[serde(default)]
    pub static_site: StaticSiteConfig,
    /// `access_mode = redirect` 时生效
    #[serde(default)]
    pub redirect: RedirectConfig,
    /// 应用级快捷防护开关（对应列表页的防护按钮）
    #[serde(default)]
    pub features: AppFeatures,
    /// 网页防篡改：按基线校验静态文件是否被修改
    #[serde(default)]
    pub tamper: TamperConfig,
}

/// 网页防篡改配置。
///
/// 通过「基线指纹」判断文件是否被改动：建立基线时记录每个文件的大小与 SHA-256，
/// 之后静态文件请求会先比对指纹，命中变更按 [`TamperAction`] 处置。
/// `paths` 为空时默认监控 `static_site.root`。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TamperConfig {
    pub enabled: bool,
    /// 需要监控的目录，相对路径按 `static_site.root` 解析，也支持绝对路径
    pub paths: Vec<String>,
    pub action: TamperAction,
}

impl Default for TamperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: Vec::new(),
            action: TamperAction::Block,
        }
    }
}

/// 篡改命中后的处置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TamperAction {
    /// 拒绝访问被修改的文件，并记录事件
    #[default]
    Block,
    /// 正常返回文件，只记录事件
    Log,
}

/// 应用级快捷开关。
///
/// `attack` / `cc` 直接参与请求策略解析；`bot` 与 `auth` 先保留字段，
/// 便于后续接入 BOT 识别与身份认证，不影响现有配置兼容。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppFeatures {
    #[serde(default = "default_true")]
    pub attack: bool,
    #[serde(default = "default_true")]
    pub cc: bool,
    #[serde(default)]
    pub bot: bool,
    #[serde(default)]
    pub auth: bool,
}

impl Default for AppFeatures {
    fn default() -> Self {
        Self {
            attack: true,
            cc: true,
            bot: false,
            auth: false,
        }
    }
}

/// 应用的接入方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// 反向代理到上游（默认）
    #[default]
    Proxy,
    /// 直接由 WAF 提供本地静态文件
    Static,
    /// 固定重定向到另一个地址
    Redirect,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticSiteConfig {
    /// 站点根目录，必须存在且可读
    pub root: String,
    /// 目录请求与找不到文件时使用的首页
    pub index: String,
    /// 单页应用：非静态资源路径回退到 index
    pub spa_fallback: bool,
}

impl Default for StaticSiteConfig {
    fn default() -> Self {
        Self {
            root: String::new(),
            index: "index.html".to_string(),
            spa_fallback: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedirectConfig {
    /// 目标地址，支持 `{path}` / `{query}` 占位符
    pub target: String,
    /// 301 / 302 / 307 / 308
    pub status: u16,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            status: 302,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Domains {
    pub primary: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub addr: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub scheme: Scheme,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default)]
    pub backup: bool,
    #[serde(default = "default_max_conns")]
    pub max_conns: u32,
    #[serde(default)]
    pub tls: Option<UpstreamTlsConfig>,
}

fn default_weight() -> u16 {
    1
}

fn default_max_conns() -> u32 {
    128
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[default]
    Http,
    Https,
    Grpc,
    Ws,
    Wss,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamTlsConfig {
    pub verify: bool,
    pub sni: Option<String>,
    pub ca_file: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            sni: None,
            ca_file: None,
            client_cert: None,
            client_key: None,
        }
    }
}

/// 解析后的上游目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
}

impl Upstream {
    /// 解析 `addr` 字段，支持四种写法：
    ///
    /// ```text
    /// 192.168.1.5            → http://192.168.1.5:80
    /// 192.168.1.5:8080       → http://192.168.1.5:8080
    /// https://nas.lan        → https://nas.lan:443
    /// https://nas.lan:8443   → https://nas.lan:8443
    /// [::1]:8080             → http://[::1]:8080
    /// ```
    ///
    /// 优先级：`addr` 里写的 > 独立字段 `scheme`/`port` > 协议默认端口。
    /// 这样用户既可以只填一个 URL，也可以拆开写。
    pub fn target(&self) -> Result<UpstreamTarget, String> {
        let raw = self.addr.trim();
        if raw.is_empty() {
            return Err("上游地址不能为空".into());
        }

        // 1. 拆出 scheme
        let (scheme, authority) = if let Some((s, rest)) = raw.split_once("://") {
            let scheme = match s.to_ascii_lowercase().as_str() {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                "grpc" | "grpcs" => Scheme::Grpc,
                "ws" => Scheme::Ws,
                "wss" => Scheme::Wss,
                other => return Err(format!("不支持的协议 `{other}`（http/https/grpc/ws/wss）")),
            };
            (Some(scheme), rest.trim_end_matches('/'))
        } else {
            (None, raw)
        };

        // 2. 拆出 host 与端口。IPv6 用方括号包裹，避免和端口分隔符混淆
        let (host, inline_port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err(format!("上游地址 `{raw}` 缺少主机名"));
        }

        // 3. 决定最终协议与端口
        let final_scheme = scheme.unwrap_or(self.scheme);
        let port = inline_port
            .or(self.port)
            .unwrap_or_else(|| default_port(final_scheme));

        Ok(UpstreamTarget {
            host,
            port,
            scheme: final_scheme,
        })
    }
}

/// 拆分 `host:port` 或 `[v6]:port`。
fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    // IPv6：[::1]:8080 或 [::1]
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("IPv6 地址 `{authority}` 缺少 `]`"))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => {
                Some(p.parse().map_err(|_| format!("端口 `{p}` 不是合法数字"))?)
            }
            Some(_) => return Err("`:` 后面缺少端口号".into()),
            None => None,
        };
        return Ok((host, port));
    }

    // 普通 host:port —— 只在最后一段是纯数字时才当端口
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            let port = p.parse().map_err(|_| format!("端口 `{p}` 超出范围"))?;
            Ok((h.to_string(), Some(port)))
        }
        // 冒号后面不是数字，说明是裸 IPv6（如 `::1`），整串当 host
        _ => Ok((authority.to_string(), None)),
    }
}

fn default_port(scheme: Scheme) -> u16 {
    match scheme {
        Scheme::Https | Scheme::Wss => 443,
        _ => 80,
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsModeConfig {
    pub mode: TlsMode,
    pub cert_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Auto,
    Manual,
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub path: String,
    #[serde(default)]
    pub upstreams: Option<Vec<Upstream>>,
    #[serde(default)]
    pub rewrite: Option<Rewrite>,
    #[serde(default)]
    pub policy: Option<Policy>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub cache: Option<RouteCacheConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub mode: RewriteMode,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteMode {
    /// 去掉匹配到的路由前缀。`/a/b` 匹配 `/a` → `/b`
    StripPrefix,
    /// 在路径前加一段。`/b` → `/a/b`
    AddPrefix,
    /// 把匹配到的路由前缀**替换**成 `value`。`/a/b` 匹配 `/a`、value 为 `/c` → `/c/b`
    ///
    /// 这是最常用的模式：`/a` 转发到上游的 `/c`。
    Prefix,
    /// 正则替换
    Regex,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteCacheConfig {
    pub enabled: bool,
    pub ttl: Option<Duration>,
}

// ============================================================
// 策略（应用级 / 路由级覆盖）
// ============================================================

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub preset: Option<Preset>,
    pub protection: Option<ProtectionConfig>,
    pub observe_mode: Option<ObserveMode>,
    pub block_threshold: Option<u32>,
    pub fail_policy: Option<FailPolicy>,
    pub require_auth: Option<AuthMode>,
    pub allow_cidr: Option<Vec<IpNet>>,
    pub deny_cidr: Option<Vec<IpNet>>,
    pub max_body_size: Option<Size>,
    pub ratelimit: Option<RateLimitConfig>,
    pub require_challenge: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Basic,
    Form,
    Totp,
    Passkey,
    Oidc,
}

// ============================================================
// 转发参数
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LbConfig {
    pub algorithm: LbAlgorithm,
    pub sticky: bool,
}

impl Default for LbConfig {
    fn default() -> Self {
        Self {
            algorithm: LbAlgorithm::RoundRobin,
            sticky: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
    #[default]
    RoundRobin,
    Weighted,
    LeastConn,
    IpHash,
    ConsistentHash,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutsConfig {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
    pub request: Option<Duration>,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
            idle: Duration::from_secs(75),
            request: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheckConfig {
    pub active: Option<ActiveHealthCheck>,
    pub passive: Option<PassiveHealthCheck>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveHealthCheck {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_hc_interval")]
    pub interval: Duration,
    #[serde(default = "default_hc_timeout")]
    pub timeout: Duration,
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_hc_method")]
    pub method: String,
    #[serde(default = "default_hc_status")]
    pub expect_status: Vec<u16>,
    #[serde(default = "default_hc_healthy")]
    pub healthy_threshold: u32,
    #[serde(default = "default_hc_unhealthy")]
    pub unhealthy_threshold: u32,
}

fn default_hc_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_hc_timeout() -> Duration {
    Duration::from_secs(3)
}
fn default_hc_method() -> String {
    "GET".to_string()
}
fn default_hc_status() -> Vec<u16> {
    vec![200, 204]
}
fn default_hc_healthy() -> u32 {
    2
}
fn default_hc_unhealthy() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveHealthCheck {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_pc_fail")]
    pub fail_threshold: u32,
    #[serde(default = "default_pc_recover")]
    pub recover_threshold: u32,
    #[serde(default = "default_pc_window")]
    pub window: Duration,
}

impl Default for PassiveHealthCheck {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_threshold: default_pc_fail(),
            recover_threshold: default_pc_recover(),
            window: default_pc_window(),
        }
    }
}

fn default_pc_fail() -> u32 {
    5
}
fn default_pc_recover() -> u32 {
    2
}
fn default_pc_window() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetryConfig {
    pub enabled: bool,
    pub attempts: u32,
    pub on: Vec<RetryCondition>,
    pub methods: Vec<String>,
    pub backoff: Duration,
    pub budget: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            attempts: 2,
            on: vec![
                RetryCondition::ConnectError,
                RetryCondition::Status502,
                RetryCondition::Status503,
                RetryCondition::Status504,
            ],
            // 非幂等方法默认不重试
            methods: vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()],
            backoff: Duration::from_millis(100),
            budget: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryCondition {
    ConnectError,
    #[serde(rename = "502")]
    Status502,
    #[serde(rename = "503")]
    Status503,
    #[serde(rename = "504")]
    Status504,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeadersConfig {
    pub request: HeaderOps,
    pub response: HeaderOps,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderOps {
    pub set: BTreeMap<String, String>,
    pub add: BTreeMap<String, String>,
    pub remove: Vec<String>,
}
