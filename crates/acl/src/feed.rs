//! IP 组订阅：拉取外部 IP 列表并做护栏校验。
//!
//! 订阅的风险不是"拉不到"，而是"拉到了投毒的内容"——一个被篡改的订阅源
//! 如果返回 `0.0.0.0/0`，就能一次性封掉整个互联网。所以护栏不是可选功能，
//! 是订阅能力的前置条件。
//!
//! 三层防护：
//! 1. 格式层：只接受合法 CIDR，非法行丢弃并计数
//! 2. 内容层：前缀不能短于阈值（防止 `0.0.0.0/0`）
//! 3. 变更层：与上次相比变动幅度超阈值则整批拒绝，保留旧数据

use std::collections::HashSet;
use std::net::IpAddr;

use homewaf_config::{FeedFormat, IpGroupGuards};
use ipnet::IpNet;

use crate::{AclRule, RuleAction};

/// 解析失败的原因。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    #[error("订阅内容为空")]
    Empty,
    #[error("JSON 解析失败：{0}")]
    Json(String),
    #[error("无法识别的订阅格式")]
    UnknownFormat,
}

/// 解析结果。`skipped` 记录被丢弃的行数，用于日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFeed {
    pub entries: Vec<IpNet>,
    pub skipped: usize,
}

/// 护栏判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// 全部通过
    Accepted(Vec<IpNet>),
    /// 部分条目因前缀过短被丢弃，其余可用
    PartiallyAccepted {
        entries: Vec<IpNet>,
        dropped: usize,
    },
    /// 整批拒绝，应保留上一次的数据
    Rejected(String),
}

impl GuardOutcome {
    pub fn entries(&self) -> Option<&[IpNet]> {
        match self {
            GuardOutcome::Accepted(v) => Some(v),
            GuardOutcome::PartiallyAccepted { entries, .. } => Some(entries),
            GuardOutcome::Rejected(_) => None,
        }
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, GuardOutcome::Rejected(_))
    }
}

/// 解析订阅内容。
pub fn parse(input: &str, format: FeedFormat) -> Result<ParsedFeed, FeedError> {
    if input.trim().is_empty() {
        return Err(FeedError::Empty);
    }

    match format {
        FeedFormat::Cidr => Ok(parse_lines(input)),
        FeedFormat::Text => Ok(parse_lines(input)),
        FeedFormat::Json => parse_json(input),
        FeedFormat::Auto => {
            let trimmed = input.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                parse_json(input).or_else(|_| Ok(parse_lines(input)))
            } else {
                Ok(parse_lines(input))
            }
        }
    }
}

/// 逐行解析，支持 `#` 注释、空行、行尾注释。
fn parse_lines(input: &str) -> ParsedFeed {
    let mut entries = Vec::new();
    let mut skipped = 0;

    for line in input.lines() {
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        match parse_entry(content) {
            Some(net) => entries.push(net),
            None => skipped += 1,
        }
    }

    ParsedFeed { entries, skipped }
}

/// 解析单条：CIDR 或裸 IP（裸 IP 补全为 /32 或 /128）。
fn parse_entry(s: &str) -> Option<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Some(net);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(IpNet::from(ip));
    }
    None
}

/// 解析 JSON。兼容三种常见结构：
/// - `["1.2.3.0/24", ...]`
/// - `{"ips": ["1.2.3.0/24"]}`
/// - `{"ip_groups": [{"ips": [...]}, ...]}`（雷池分享格式）
fn parse_json(input: &str) -> Result<ParsedFeed, FeedError> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| FeedError::Json(e.to_string()))?;

    let mut entries = Vec::new();
    let mut skipped = 0;
    collect_ips(&value, &mut entries, &mut skipped);

    if entries.is_empty() {
        return Err(FeedError::UnknownFormat);
    }
    Ok(ParsedFeed { entries, skipped })
}

fn collect_ips(value: &serde_json::Value, out: &mut Vec<IpNet>, skipped: &mut usize) {
    match value {
        serde_json::Value::String(s) => match parse_entry(s.trim()) {
            Some(net) => out.push(net),
            None => *skipped += 1,
        },
        serde_json::Value::Array(items) => {
            for item in items {
                collect_ips(item, out, skipped);
            }
        }
        serde_json::Value::Object(map) => {
            // 优先看常见键，找不到就递归所有值
            let mut found = false;
            for key in ["ips", "ip_list", "cidrs", "list", "ip_groups", "data"] {
                if let Some(v) = map.get(key) {
                    collect_ips(v, out, skipped);
                    found = true;
                }
            }
            if !found {
                for v in map.values() {
                    collect_ips(v, out, skipped);
                }
            }
        }
        _ => {}
    }
}

/// 应用护栏。
///
/// `previous` 是上次成功导入的列表。首次导入时传空切片，此时跳过变更幅度检查。
pub fn apply_guards(
    entries: Vec<IpNet>,
    previous: &[IpNet],
    guards: &IpGroupGuards,
) -> GuardOutcome {
    // 去重（排序后去重，保证结果稳定）
    let mut entries = entries;
    entries.sort();
    entries.dedup();

    // 剔除前缀过短的条目
    let before = entries.len();
    entries.retain(|net| match net {
        IpNet::V4(n) => n.prefix_len() >= guards.min_prefix_v4,
        IpNet::V6(n) => n.prefix_len() >= guards.min_prefix_v6,
    });
    let dropped = before - entries.len();

    if entries.is_empty() {
        return GuardOutcome::Rejected(format!(
            "过滤后无有效条目（{dropped} 条前缀过短被丢弃）"
        ));
    }

    if entries.len() > guards.max_entries {
        return GuardOutcome::Rejected(format!(
            "条目数 {} 超过上限 {}",
            entries.len(),
            guards.max_entries
        ));
    }

    // 变更幅度：首次导入（previous 为空）不检查
    if !previous.is_empty() {
        let prev: HashSet<&IpNet> = previous.iter().collect();
        let curr: HashSet<&IpNet> = entries.iter().collect();
        let added = curr.difference(&prev).count();
        let removed = prev.difference(&curr).count();
        let ratio = (added + removed) as f32 / prev.len() as f32;

        if ratio > guards.max_delta_ratio {
            return GuardOutcome::Rejected(format!(
                "变更幅度 {:.0}%（新增 {added}、删除 {removed}）超过阈值 {:.0}%",
                ratio * 100.0,
                guards.max_delta_ratio * 100.0
            ));
        }
    }

    if dropped > 0 {
        GuardOutcome::PartiallyAccepted { entries, dropped }
    } else {
        GuardOutcome::Accepted(entries)
    }
}

/// 把订阅条目转成 ACL 规则。
///
/// 动作映射：
/// - `block` → 拒绝
/// - `challenge` → 暂按拒绝处理（人机验证尚未实现，放行会失去防护）
/// - `log` → 不产生规则（只记录，不拦截）
///
/// 订阅的 `scope` 为空表示全局；否则每个应用各生成一份规则。
pub fn rules_from_group(
    group: &homewaf_config::IpGroup,
    entries: &[IpNet],
) -> Vec<AclRule> {
    use homewaf_config::IpGroupAction;

    let action = match group.action {
        IpGroupAction::Block | IpGroupAction::Challenge => RuleAction::Deny,
        IpGroupAction::Log => return Vec::new(),
    };

    let scopes: Vec<Option<String>> = if group.scope.is_empty() {
        vec![None]
    } else {
        group.scope.iter().map(|s| Some(s.clone())).collect()
    };

    let mut rules = Vec::with_capacity(entries.len() * scopes.len());
    for (idx, net) in entries.iter().enumerate() {
        for scope in &scopes {
            let suffix = scope.as_deref().unwrap_or("global");
            rules.push(AclRule {
                id: format!("feed:{}:{}:{suffix}", group.name, idx),
                cidr: *net,
                action,
                scope: scope.clone(),
                expires_at: None,
                note: Some(format!("订阅 {}", group.name)),
            });
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn guards() -> IpGroupGuards {
        IpGroupGuards::default()
    }

    // ============================================================
    // 解析
    // ============================================================

    #[test]
    fn parses_cidr_lines() {
        let input = "1.2.3.0/24\n10.0.0.0/8\n";
        let r = parse(input, FeedFormat::Cidr).unwrap();
        assert_eq!(r.entries, vec![net("1.2.3.0/24"), net("10.0.0.0/8")]);
        assert_eq!(r.skipped, 0);
    }

    #[test]
    fn parses_comments_and_blank_lines() {
        let input = "# 这是注释\n1.2.3.0/24\n\n10.0.0.1  # 行尾注释\n";
        let r = parse(input, FeedFormat::Cidr).unwrap();
        assert_eq!(r.entries.len(), 2);
    }

    #[test]
    fn bare_ip_gets_full_prefix() {
        let r = parse("1.2.3.4\n2001:db8::1\n", FeedFormat::Text).unwrap();
        assert_eq!(r.entries, vec![net("1.2.3.4/32"), net("2001:db8::1/128")]);
    }

    #[test]
    fn invalid_lines_counted_as_skipped() {
        let input = "1.2.3.0/24\nnot-an-ip\n300.1.1.1\n10.0.0.0/8\n";
        let r = parse(input, FeedFormat::Cidr).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.skipped, 2);
    }

    #[test]
    fn empty_input_rejected() {
        assert_eq!(parse("   \n\n", FeedFormat::Auto), Err(FeedError::Empty));
    }

    #[test]
    fn parses_json_array() {
        let input = r#"["1.2.3.0/24", "10.0.0.1"]"#;
        let r = parse(input, FeedFormat::Json).unwrap();
        assert_eq!(r.entries, vec![net("1.2.3.0/24"), net("10.0.0.1/32")]);
    }

    #[test]
    fn parses_json_with_ips_key() {
        let input = r#"{"ips": ["1.2.3.0/24"]}"#;
        let r = parse(input, FeedFormat::Json).unwrap();
        assert_eq!(r.entries, vec![net("1.2.3.0/24")]);
    }

    #[test]
    fn parses_chaitin_share_format() {
        // 雷池分享链接的结构
        let input = r#"{
            "ip_groups": [
                {"name": "g1", "ips": ["1.2.3.0/24", "4.5.6.7"]},
                {"name": "g2", "ips": ["10.0.0.0/8"]}
            ]
        }"#;
        let r = parse(input, FeedFormat::Json).unwrap();
        assert_eq!(r.entries.len(), 3);
    }

    #[test]
    fn json_without_ips_is_unknown_format() {
        let input = r#"{"foo": "bar"}"#;
        assert_eq!(
            parse(input, FeedFormat::Json),
            Err(FeedError::UnknownFormat)
        );
    }

    #[test]
    fn auto_detects_json() {
        let input = r#"["1.2.3.0/24"]"#;
        let r = parse(input, FeedFormat::Auto).unwrap();
        assert_eq!(r.entries, vec![net("1.2.3.0/24")]);
    }

    #[test]
    fn auto_falls_back_to_lines() {
        let input = "1.2.3.0/24\n10.0.0.0/8\n";
        let r = parse(input, FeedFormat::Auto).unwrap();
        assert_eq!(r.entries.len(), 2);
    }

    // ============================================================
    // 护栏
    // ============================================================

    #[test]
    fn guards_accept_normal_feed() {
        let entries = vec![net("1.2.3.0/24"), net("10.0.0.0/8")];
        let outcome = apply_guards(entries.clone(), &[], &guards());
        assert_eq!(outcome, GuardOutcome::Accepted(entries));
    }

    #[test]
    fn guards_dedup_entries() {
        let entries = vec![net("1.2.3.0/24"), net("1.2.3.0/24"), net("1.2.3.0/24")];
        let outcome = apply_guards(entries, &[], &guards());
        assert_eq!(outcome.entries().unwrap().len(), 1);
    }

    #[test]
    fn guards_reject_too_short_prefix() {
        // 0.0.0.0/0 必须被拦下——否则等于封掉整个互联网
        let entries = vec![net("0.0.0.0/0")];
        let outcome = apply_guards(entries, &[], &guards());
        assert!(outcome.is_rejected(), "实际: {outcome:?}");
    }

    #[test]
    fn guards_drop_short_prefix_but_keep_rest() {
        let entries = vec![net("1.0.0.0/4"), net("1.2.3.0/24")];
        let outcome = apply_guards(entries, &[], &guards());
        match outcome {
            GuardOutcome::PartiallyAccepted { entries, dropped } => {
                assert_eq!(dropped, 1);
                assert_eq!(entries, vec![net("1.2.3.0/24")]);
            }
            other => panic!("期望部分接受，实际: {other:?}"),
        }
    }

    #[test]
    fn guards_reject_when_all_prefixes_too_short() {
        let entries = vec![net("1.0.0.0/4"), net("2.0.0.0/3")];
        let outcome = apply_guards(entries, &[], &guards());
        assert!(outcome.is_rejected());
    }

    #[test]
    fn guards_reject_oversized_feed() {
        let mut g = guards();
        g.max_entries = 2;
        let entries = vec![
            net("1.2.3.0/24"),
            net("4.5.6.0/24"),
            net("7.8.9.0/24"),
        ];
        let outcome = apply_guards(entries, &[], &g);
        assert!(outcome.is_rejected());
        let msg = match outcome {
            GuardOutcome::Rejected(m) => m,
            _ => unreachable!(),
        };
        assert!(msg.contains("超过上限"), "信息应说明原因: {msg}");
    }

    #[test]
    fn guards_reject_large_delta() {
        let mut g = guards();
        g.max_delta_ratio = 0.5;

        // 上次 4 条，这次完全不同 4 条 → 变动 100%
        let previous = vec![
            net("1.1.1.0/24"),
            net("2.2.2.0/24"),
            net("3.3.3.0/24"),
            net("4.4.4.0/24"),
        ];
        let entries = vec![
            net("5.5.5.0/24"),
            net("6.6.6.0/24"),
            net("7.7.7.0/24"),
            net("8.8.8.0/24"),
        ];
        let outcome = apply_guards(entries, &previous, &g);
        assert!(outcome.is_rejected(), "实际: {outcome:?}");
    }

    #[test]
    fn guards_accept_small_delta() {
        let mut g = guards();
        g.max_delta_ratio = 0.5;

        let previous = vec![
            net("1.1.1.0/24"),
            net("2.2.2.0/24"),
            net("3.3.3.0/24"),
            net("4.4.4.0/24"),
        ];
        // 只替换 1 条 → 变动 25%
        let entries = vec![
            net("1.1.1.0/24"),
            net("2.2.2.0/24"),
            net("3.3.3.0/24"),
            net("9.9.9.0/24"),
        ];
        let outcome = apply_guards(entries.clone(), &previous, &g);
        assert_eq!(outcome, GuardOutcome::Accepted(entries));
    }

    #[test]
    fn first_import_skips_delta_check() {
        let mut g = guards();
        g.max_delta_ratio = 0.01; // 极严格
        let entries = vec![net("1.2.3.0/24"), net("4.5.6.0/24")];
        // previous 为空表示首次导入，不应因"变动 100%"被拒
        let outcome = apply_guards(entries.clone(), &[], &g);
        assert_eq!(outcome, GuardOutcome::Accepted(entries));
    }

    #[test]
    fn identical_feed_has_zero_delta() {
        let g = guards();
        let entries = vec![net("1.2.3.0/24"), net("4.5.6.0/24")];
        let outcome = apply_guards(entries.clone(), &entries, &g);
        assert_eq!(outcome, GuardOutcome::Accepted(entries));
    }

    #[test]
    fn ipv6_min_prefix_enforced() {
        let mut g = guards();
        g.min_prefix_v6 = 32;
        // /16 短于阈值，应被丢弃
        let entries = vec![net("2001:db8::/16"), net("2001:db8::/32")];
        let outcome = apply_guards(entries, &[], &g);
        match outcome {
            GuardOutcome::PartiallyAccepted { entries, dropped } => {
                assert_eq!(dropped, 1);
                assert_eq!(entries, vec![net("2001:db8::/32")]);
            }
            other => panic!("期望部分接受，实际: {other:?}"),
        }
    }

    // ============================================================
    // 订阅 → ACL 规则
    // ============================================================

    fn group(name: &str, action: homewaf_config::IpGroupAction, scope: &[&str]) -> homewaf_config::IpGroup {
        use homewaf_config::*;
        IpGroup {
            name: name.to_string(),
            enabled: true,
            source: IpGroupSource {
                url: "https://example.com/list".to_string(),
                format: FeedFormat::Auto,
                interval: Duration::from_secs(3600),
                timeout: Duration::from_secs(15),
                headers: Default::default(),
            },
            action,
            scope: scope.iter().map(|s| s.to_string()).collect(),
            expires: Duration::from_secs(86_400),
            guards: IpGroupGuards::default(),
            on_failure: OnFailure::KeepLast,
        }
    }

    #[test]
    fn group_without_scope_creates_global_rules() {
        use homewaf_config::IpGroupAction;
        let g = group("test", IpGroupAction::Block, &[]);
        let rules = rules_from_group(&g, &[net("1.2.3.0/24"), net("4.5.6.0/24")]);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.scope.is_none()));
        assert!(rules.iter().all(|r| r.action == RuleAction::Deny));
    }

    #[test]
    fn group_with_scope_creates_rule_per_app() {
        use homewaf_config::IpGroupAction;
        let g = group("test", IpGroupAction::Block, &["nas", "photos"]);
        let rules = rules_from_group(&g, &[net("1.2.3.0/24")]);
        // 1 条目 × 2 应用
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].scope.as_deref(), Some("nas"));
        assert_eq!(rules[1].scope.as_deref(), Some("photos"));
    }

    #[test]
    fn log_action_produces_no_rules() {
        use homewaf_config::IpGroupAction;
        let g = group("test", IpGroupAction::Log, &[]);
        let rules = rules_from_group(&g, &[net("1.2.3.0/24")]);
        assert!(rules.is_empty(), "log 动作不应产生拦截规则");
    }

    #[test]
    fn challenge_downgrades_to_deny() {
        use homewaf_config::IpGroupAction;
        // 人机验证未实现，challenge 暂按拒绝处理
        let g = group("test", IpGroupAction::Challenge, &[]);
        let rules = rules_from_group(&g, &[net("1.2.3.0/24")]);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, RuleAction::Deny);
    }

    #[test]
    fn rule_ids_are_unique() {
        use homewaf_config::IpGroupAction;
        let g = group("test", IpGroupAction::Block, &["a", "b"]);
        let rules = rules_from_group(&g, &[net("1.2.3.0/24"), net("4.5.6.0/24")]);
        let ids: HashSet<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), rules.len(), "规则 id 必须唯一");
    }
}
