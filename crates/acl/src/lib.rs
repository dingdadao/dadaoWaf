//! IP 访问控制。
//!
//! 匹配顺序（越具体越优先）：
//! 1. 应用专属白名单 → 2. 应用专属黑名单
//! 3. 全局白名单     → 4. 全局黑名单
//! 5. 内网网段策略   → 6. 正常流程
//!
//! 白名单永远优先于黑名单：用户显式加白某台机器，不应该被自动封禁推翻。

pub mod ban;
pub mod feed;
pub mod http;
pub mod prefix;

pub use ban::{BanOutcome, BanStatus, BanTable};
pub use feed::{apply_guards, parse as parse_feed, FeedError, GuardOutcome, ParsedFeed};
pub use http::{fetch as fetch_feed, FetchError};
pub use prefix::PrefixMap;

use std::collections::HashMap;
use std::net::IpAddr;

use homewaf_config::{AclConfig, PrivateNetworkAction};
use ipnet::IpNet;

/// 规则动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
}

/// 一条 ACL 规则。通常来自数据库，而不是配置文件。
#[derive(Debug, Clone)]
pub struct AclRule {
    /// 规则标识，写入日志便于追溯"是谁封的"
    pub id: String,
    pub cidr: IpNet,
    pub action: RuleAction,
    /// 生效应用；`None` 表示全局
    pub scope: Option<String>,
    /// 到期时间（Unix 秒）；`None` 表示永久
    pub expires_at: Option<i64>,
    pub note: Option<String>,
}

impl AclRule {
    pub fn allow(id: impl Into<String>, cidr: IpNet) -> Self {
        Self {
            id: id.into(),
            cidr,
            action: RuleAction::Allow,
            scope: None,
            expires_at: None,
            note: None,
        }
    }

    pub fn deny(id: impl Into<String>, cidr: IpNet) -> Self {
        Self {
            id: id.into(),
            cidr,
            action: RuleAction::Deny,
            scope: None,
            expires_at: None,
            note: None,
        }
    }

    pub fn with_scope(mut self, app: impl Into<String>) -> Self {
        self.scope = Some(app.into());
        self
    }

    pub fn with_expiry(mut self, ts: i64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|ts| ts <= now)
    }
}

/// 命中的规则引用（只保留日志需要的字段）。
#[derive(Debug, Clone)]
pub struct RuleRef {
    pub id: String,
    pub prefix_len: u8,
}

/// 判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 放行且跳过检测（白名单 / 内网放行）
    Allow(Reason),
    /// 拒绝
    Deny(Reason),
    /// 走正常检测流程
    Normal,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny(_))
    }
}

/// 判定原因，写入日志与事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// 手动白名单
    ManualAllow { rule: String },
    /// 手动黑名单
    ManualDeny { rule: String },
    /// 内网网段
    PrivateNetwork,
}

impl Reason {
    pub fn describe(&self) -> String {
        match self {
            Reason::ManualAllow { rule } => format!("白名单规则 {rule}"),
            Reason::ManualDeny { rule } => format!("黑名单规则 {rule}"),
            Reason::PrivateNetwork => "内网网段".to_string(),
        }
    }
}

/// 单个作用域的规则集合。
#[derive(Debug, Clone, Default)]
struct ScopeRules {
    allow: PrefixMap<RuleRef>,
    deny: PrefixMap<RuleRef>,
}

impl ScopeRules {
    fn insert(&mut self, rule: &AclRule) {
        let reference = RuleRef {
            id: rule.id.clone(),
            prefix_len: rule.cidr.prefix_len(),
        };
        match rule.action {
            RuleAction::Allow => {
                self.allow.insert(rule.cidr, reference);
            }
            RuleAction::Deny => {
                self.deny.insert(rule.cidr, reference);
            }
        }
    }

    /// 返回 Some 表示命中（白或黑），None 表示无规则。
    fn check(&self, ip: IpAddr) -> Option<Decision> {
        if let Some(r) = self.allow.lookup(ip) {
            return Some(Decision::Allow(Reason::ManualAllow { rule: r.id.clone() }));
        }
        if let Some(r) = self.deny.lookup(ip) {
            return Some(Decision::Deny(Reason::ManualDeny { rule: r.id.clone() }));
        }
        None
    }

    fn len(&self) -> usize {
        self.allow.len() + self.deny.len()
    }
}

/// IP 访问控制。
#[derive(Debug, Clone)]
pub struct Acl {
    global: ScopeRules,
    by_app: HashMap<String, ScopeRules>,
    private: Vec<IpNet>,
    private_action: PrivateNetworkAction,
    ipv6_prefix_match: u8,
}

impl Acl {
    /// 从配置构建（只含静态规则）。
    pub fn from_config(config: &AclConfig, now: i64) -> Self {
        let rules = rules_from_config(config);
        Self::build(config, &rules, now)
    }

    /// 用当前时间从配置构建。
    pub fn from_config_now(config: &AclConfig) -> Self {
        Self::from_config(config, now_unix())
    }

    /// 从配置与规则构建。`now` 用于过滤已过期规则。
    pub fn build(config: &AclConfig, rules: &[AclRule], now: i64) -> Self {
        let mut global = ScopeRules::default();
        let mut by_app: HashMap<String, ScopeRules> = HashMap::new();

        for rule in rules {
            if rule.is_expired(now) {
                continue;
            }
            match &rule.scope {
                None => global.insert(rule),
                Some(app) => by_app.entry(app.clone()).or_default().insert(rule),
            }
        }

        Self {
            global,
            by_app,
            private: config.private_network.cidrs.clone(),
            private_action: config.private_network.action,
            ipv6_prefix_match: config.ipv6_prefix_match,
        }
    }

    /// 判定某个 IP 在某个应用下的处置。
    pub fn check(&self, ip: IpAddr, app_id: Option<&str>) -> Decision {
        let ip = normalize(ip);

        // 应用专属规则优先（更具体）
        if let Some(app) = app_id {
            if let Some(rules) = self.by_app.get(app) {
                if let Some(d) = rules.check(ip) {
                    return d;
                }
            }
        }

        if let Some(d) = self.global.check(ip) {
            return d;
        }

        if self.is_private(ip) {
            return match self.private_action {
                PrivateNetworkAction::Allow => Decision::Allow(Reason::PrivateNetwork),
                PrivateNetworkAction::Deny => Decision::Deny(Reason::PrivateNetwork),
                PrivateNetworkAction::Normal => Decision::Normal,
            };
        }

        Decision::Normal
    }

    fn is_private(&self, ip: IpAddr) -> bool {
        self.private.iter().any(|net| net.contains(&ip))
    }

    /// 自动封禁时使用的键。
    ///
    /// IPv6 按 `ipv6_prefix_match`（默认 /64）聚合——隐私扩展会让同一台设备
    /// 不断更换后缀，按 /128 封禁等于没封。
    pub fn ban_key(&self, ip: IpAddr) -> IpAddr {
        match normalize(ip) {
            IpAddr::V6(v6) => {
                let len = self.ipv6_prefix_match.min(128);
                if len == 0 {
                    IpAddr::V6(v6)
                } else {
                    let raw = u128::from(v6);
                    let masked = raw & (!0u128 << (128 - len));
                    IpAddr::V6(masked.into())
                }
            }
            v4 => v4,
        }
    }

    /// 规则总数（含应用专属）。
    pub fn rule_count(&self) -> usize {
        self.global.len() + self.by_app.values().map(ScopeRules::len).sum::<usize>()
    }

    pub fn app_count(&self) -> usize {
        self.by_app.len()
    }
}

/// 把配置里的静态规则转成运行时规则。
pub fn rules_from_config(config: &AclConfig) -> Vec<AclRule> {
    config
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| AclRule {
            id: r.id.clone().unwrap_or_else(|| format!("static-{i}")),
            cidr: r.cidr,
            action: match r.action {
                homewaf_config::AclRuleAction::Allow => RuleAction::Allow,
                homewaf_config::AclRuleAction::Deny => RuleAction::Deny,
            },
            scope: r.scope.clone(),
            expires_at: r.expires_at,
            note: r.note.clone(),
        })
        .collect()
}

/// 订阅状态的读写接口。
///
/// 由调用方实现（proxy 用 SQLite），`acl` 本身不依赖存储层——
/// 保持它可以纯逻辑测试，不必拖着数据库。
pub trait FeedState {
    /// 上次成功导入的条目。没有记录时返回空，表示首次导入。
    fn previous(&self, group: &str) -> Vec<ipnet::IpNet>;
    /// 记录本次成功导入的条目。
    fn remember(&self, group: &str, entries: &[ipnet::IpNet]);
    /// 上次成功导入的时间（Unix 秒）。实现方不保存时间时返回 `None`，
    /// 表示每次重载都重新拉取。
    fn updated_at(&self, _group: &str) -> Option<i64> {
        None
    }
}

/// 不做状态保存的实现，用于纯内存模式。
pub struct NoFeedState;

impl FeedState for NoFeedState {
    fn previous(&self, _group: &str) -> Vec<ipnet::IpNet> {
        Vec::new()
    }
    fn remember(&self, _group: &str, _entries: &[ipnet::IpNet]) {}
}

/// 拉取并转换一个 IP 组订阅。
///
/// `previous` 是上次成功导入的条目，用于变更幅度校验。首次导入传空。
pub fn load_group(
    group: &homewaf_config::IpGroup,
    previous: &[ipnet::IpNet],
) -> Result<(Vec<AclRule>, Vec<ipnet::IpNet>), String> {
    let text = http::fetch(
        &group.source.url,
        group.source.timeout.0,
        group.guards.max_response_bytes.as_bytes() as usize,
        &group.source.headers,
    )
    .map_err(|e| format!("拉取失败：{e}"))?;

    let parsed = feed::parse(&text, group.source.format).map_err(|e| format!("解析失败：{e}"))?;

    let entries = match feed::apply_guards(parsed.entries, previous, &group.guards) {
        feed::GuardOutcome::Accepted(v) => v,
        feed::GuardOutcome::PartiallyAccepted { entries, dropped } => {
            tracing::warn!(group = %group.name, dropped, "部分条目前缀过短，已丢弃");
            entries
        }
        feed::GuardOutcome::Rejected(reason) => {
            return Err(format!("护栏拒绝：{reason}"));
        }
    };

    let rules = feed::rules_from_group(group, &entries);
    Ok((rules, entries))
}

/// 加载全部启用的订阅，返回规则与失败列表。
///
/// 单个订阅失败不影响其余订阅，也不会让调用方整体失败。
/// 成功导入的条目会写回 `state`，供下次变更幅度校验使用。
///
/// 两个避免拖慢重载的处理：
/// - 未到 `interval` 且已有上次结果时，直接用上次条目生成规则，不联网；
/// - 拉取失败且 `on_failure = keep-last` 时，沿用上次条目而不是丢掉整组。
pub fn load_enabled_groups(
    groups: &[homewaf_config::IpGroup],
    state: &dyn FeedState,
) -> (Vec<AclRule>, Vec<(String, String)>) {
    let mut rules = Vec::new();
    let mut failures = Vec::new();
    let now = now_unix();

    for group in groups.iter().filter(|g| g.enabled) {
        let previous = state.previous(&group.name);

        let due = match state.updated_at(&group.name) {
            Some(at) => now.saturating_sub(at) >= group.source.interval.as_secs() as i64,
            None => true,
        };
        if !due && !previous.is_empty() {
            rules.extend(feed::rules_from_group(group, &previous));
            continue;
        }

        match load_group(group, &previous) {
            Ok((r, entries)) => {
                tracing::info!(
                    group = %group.name,
                    rules = r.len(),
                    previous = previous.len(),
                    "订阅加载成功"
                );
                // 只有校验通过才写回，被拒绝的批次不能污染基线
                state.remember(&group.name, &entries);
                rules.extend(r);
            }
            Err(e) => {
                tracing::warn!(group = %group.name, error = %e, "订阅加载失败");
                failures.push((group.name.clone(), e));
                if group.on_failure == homewaf_config::OnFailure::KeepLast && !previous.is_empty() {
                    let r = feed::rules_from_group(group, &previous);
                    tracing::warn!(
                        group = %group.name,
                        rules = r.len(),
                        "沿用上次成功内容（keep-last）"
                    );
                    rules.extend(r);
                }
            }
        }
    }

    (rules, failures)
}

/// 把 IPv4-mapped IPv6 归一化为 IPv4。
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

/// 当前 Unix 秒。
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn config() -> AclConfig {
        AclConfig::default()
    }

    #[test]
    fn empty_acl_returns_normal() {
        let acl = Acl::build(&config(), &[], 0);
        assert_eq!(acl.check(ip("203.0.113.9"), None), Decision::Normal);
        assert_eq!(acl.rule_count(), 0);
    }

    #[test]
    fn manual_deny_blocks() {
        let rules = vec![AclRule::deny("ban-1", net("203.0.113.0/24"))];
        let acl = Acl::build(&config(), &rules, 0);
        let d = acl.check(ip("203.0.113.9"), None);
        assert!(d.is_denied());
        assert_eq!(
            d,
            Decision::Deny(Reason::ManualDeny {
                rule: "ban-1".to_string()
            })
        );
    }

    #[test]
    fn whitelist_beats_blacklist() {
        let rules = vec![
            AclRule::deny("ban-wide", net("203.0.113.0/24")),
            AclRule::allow("allow-host", net("203.0.113.9/32")),
        ];
        let acl = Acl::build(&config(), &rules, 0);
        // 同一 IP 同时在黑名单段和白名单精确条目中，白名单优先
        assert!(acl.check(ip("203.0.113.9"), None).is_allowed());
        assert!(acl.check(ip("203.0.113.10"), None).is_denied());
    }

    #[test]
    fn private_network_default_allow() {
        let acl = Acl::build(&config(), &[], 0);
        let d = acl.check(ip("192.168.1.50"), None);
        assert_eq!(d, Decision::Allow(Reason::PrivateNetwork));
    }

    #[test]
    fn private_network_can_be_normal() {
        let mut cfg = config();
        cfg.private_network.action = PrivateNetworkAction::Normal;
        let acl = Acl::build(&cfg, &[], 0);
        assert_eq!(acl.check(ip("192.168.1.50"), None), Decision::Normal);
    }

    #[test]
    fn manual_rule_beats_private_network() {
        let rules = vec![AclRule::deny("ban-internal", net("192.168.1.66/32"))];
        let acl = Acl::build(&config(), &rules, 0);
        // 内网默认放行，但显式黑名单优先
        assert!(acl.check(ip("192.168.1.66"), None).is_denied());
        assert!(acl.check(ip("192.168.1.67"), None).is_allowed());
    }

    #[test]
    fn app_scoped_rule_beats_global() {
        let rules = vec![
            AclRule::deny("global-deny", net("203.0.113.0/24")),
            AclRule::allow("app-allow", net("203.0.113.9/32")).with_scope("nas"),
        ];
        let acl = Acl::build(&config(), &rules, 0);

        // 在 nas 应用下：应用白名单优先
        assert!(acl.check(ip("203.0.113.9"), Some("nas")).is_allowed());
        // 其他应用：全局黑名单生效
        assert!(acl.check(ip("203.0.113.9"), Some("photos")).is_denied());
        // 不指定应用：只有全局规则
        assert!(acl.check(ip("203.0.113.9"), None).is_denied());
        assert_eq!(acl.app_count(), 1);
    }

    #[test]
    fn expired_rule_is_ignored() {
        let rules = vec![AclRule::deny("temp", net("203.0.113.9/32")).with_expiry(1_000)];
        // now 在到期时间之后
        let acl = Acl::build(&config(), &rules, 2_000);
        assert_eq!(acl.rule_count(), 0);
        assert_eq!(acl.check(ip("203.0.113.9"), None), Decision::Normal);

        // now 在到期之前仍然生效
        let acl2 = Acl::build(&config(), &rules, 500);
        assert!(acl2.check(ip("203.0.113.9"), None).is_denied());
    }

    #[test]
    fn ipv6_ban_key_aggregates_to_64() {
        let acl = Acl::build(&config(), &[], 0);
        let key = acl.ban_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        assert_eq!(key, ip("2001:db8:1:2::"));
    }

    #[test]
    fn ipv6_ban_key_respects_config() {
        let mut cfg = config();
        cfg.ipv6_prefix_match = 48;
        let acl = Acl::build(&cfg, &[], 0);
        let key = acl.ban_key(ip("2001:db8:1:2::1"));
        assert_eq!(key, ip("2001:db8:1::"));
    }

    #[test]
    fn ipv4_ban_key_unchanged() {
        let acl = Acl::build(&config(), &[], 0);
        assert_eq!(acl.ban_key(ip("203.0.113.9")), ip("203.0.113.9"));
    }

    #[test]
    fn ipv4_mapped_ipv6_normalized() {
        let rules = vec![AclRule::deny("ban", net("203.0.113.9/32"))];
        let acl = Acl::build(&config(), &rules, 0);
        // ::ffff:203.0.113.9 应被识别为 IPv4 并命中规则
        assert!(acl.check(ip("::ffff:203.0.113.9"), None).is_denied());
    }

    struct MemFeedState {
        entries: std::collections::HashMap<String, Vec<IpNet>>,
        at: std::collections::HashMap<String, i64>,
    }

    impl FeedState for MemFeedState {
        fn previous(&self, group: &str) -> Vec<IpNet> {
            self.entries.get(group).cloned().unwrap_or_default()
        }
        fn remember(&self, _group: &str, _entries: &[IpNet]) {}
        fn updated_at(&self, group: &str) -> Option<i64> {
            self.at.get(group).copied()
        }
    }

    fn feed_group(url: &str, action: homewaf_config::IpGroupAction) -> homewaf_config::IpGroup {
        use homewaf_config::*;
        IpGroup {
            name: "g".to_string(),
            enabled: true,
            source: IpGroupSource {
                url: url.to_string(),
                format: FeedFormat::Cidr,
                interval: Duration::from_secs(3600),
                timeout: Duration::from_secs(2),
                headers: Default::default(),
            },
            action,
            scope: Vec::new(),
            expires: Duration::from_secs(86_400),
            guards: IpGroupGuards::default(),
            on_failure: OnFailure::KeepLast,
        }
    }

    #[test]
    fn not_due_reuses_cached_entries_without_network() {
        let mut state = MemFeedState {
            entries: Default::default(),
            at: Default::default(),
        };
        state
            .entries
            .insert("g".to_string(), vec![net("1.2.3.0/24")]);
        state.at.insert("g".to_string(), now_unix());
        // 不可达地址：只要不联网就不会变慢
        let groups = vec![feed_group(
            "https://127.0.0.1:9/none",
            homewaf_config::IpGroupAction::Block,
        )];
        let started = std::time::Instant::now();
        let (rules, failures) = load_enabled_groups(&groups, &state);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(failures.is_empty());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cidr, net("1.2.3.0/24"));
        assert_eq!(rules[0].action, RuleAction::Deny);
    }

    #[test]
    fn keep_last_falls_back_when_fetch_fails() {
        let mut state = MemFeedState {
            entries: Default::default(),
            at: Default::default(),
        };
        state
            .entries
            .insert("g".to_string(), vec![net("4.5.6.0/24")]);
        // 记录很久以前，强制进入拉取分支；本机端口未监听会立刻失败
        state.at.insert("g".to_string(), 1);
        let groups = vec![feed_group(
            "http://127.0.0.1:1/none",
            homewaf_config::IpGroupAction::Allow,
        )];
        let (rules, failures) = load_enabled_groups(&groups, &state);
        assert_eq!(failures.len(), 1);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cidr, net("4.5.6.0/24"));
        assert_eq!(rules[0].action, RuleAction::Allow);
    }
}
