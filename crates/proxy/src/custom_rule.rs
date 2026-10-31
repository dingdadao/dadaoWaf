//! 自定义规则求值（访问控制 / 黑白名单）。
//!
//! 规则格式兼容雷池（长亭）：`pattern` 外层是 OR、内层是 AND。
//! 动作沿用雷池的数字编码并做扩展：
//!
//! | action | 含义 | 命中后的处置 |
//! |---|---|---|
//! | 0 | 放行 | 跳过检测与自动封禁，直接转发 |
//! | 1 | 拦截 | 返回 403，记事件 |
//! | 2 | 人机验证 | 走挑战页，通过后放行 |
//! | 3 | 仅记录 | 记事件，继续正常流程 |
//!
//! 优先级：放行 > 拦截/验证 > 仅记录。放行最高是刻意的——用户显式加白
//! 一台机器，不应该被同一条链路上的拦截规则推翻。

use std::collections::HashMap;
use std::net::IpAddr;

use homewaf_config::{CustomRule, MatchMode, RuleActionKind, RuleCondition};
use ipnet::IpNet;
use regex::Regex;

/// 求值所需的请求信息。
pub struct RuleRequest<'a> {
    pub app: &'a str,
    pub host: &'a str,
    pub ip: Option<IpAddr>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub method: &'a str,
    pub user_agent: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub cookie: Option<&'a str>,
    pub headers: &'a http::HeaderMap,
    /// 该连接的 JA4 TLS 指纹。只有 HTTPS 终结连接才有值
    pub ja4: Option<&'a str>,
    /// IP 组快照：组名 → 条目。由订阅加载后注入，用于 `ip_group` 条件。
    pub ip_groups: &'a HashMap<String, Vec<IpNet>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomDecision {
    /// 白名单命中，规则名
    Allow(String),
    /// 黑名单命中，规则名
    Deny(String),
    /// 需要人机验证，规则名
    Challenge(String),
    /// 只记录，规则名
    Log(String),
}

impl CustomDecision {
    pub fn rule(&self) -> &str {
        match self {
            CustomDecision::Allow(n)
            | CustomDecision::Deny(n)
            | CustomDecision::Challenge(n)
            | CustomDecision::Log(n) => n,
        }
    }

    pub fn action_str(&self) -> &'static str {
        match self {
            CustomDecision::Allow(_) => "allow",
            CustomDecision::Deny(_) => "block",
            CustomDecision::Challenge(_) => "challenge",
            CustomDecision::Log(_) => "log",
        }
    }
}

/// 按顺序求值。
///
/// 先扫一遍放行规则（命中即返回），再取第一条命中的拦截/验证规则，
/// 最后才考虑"仅记录"。这样即使用户把记录规则排在前面，也不会削弱拦截。
pub fn evaluate(rules: &[CustomRule], req: &RuleRequest<'_>, now: i64) -> Option<CustomDecision> {
    let mut blocking: Option<(String, RuleActionKind)> = None;
    let mut log: Option<String> = None;

    for rule in rules {
        if !rule.is_effective() || rule.is_expired(now) || !rule.applies_to(req.app) {
            continue;
        }
        if !rule_matches(rule, req) {
            continue;
        }
        let kind = rule.action_kind();
        match kind {
            RuleActionKind::Allow => return Some(CustomDecision::Allow(rule_label(rule))),
            RuleActionKind::Deny | RuleActionKind::Challenge if blocking.is_none() => {
                blocking = Some((rule_label(rule), kind));
            }
            RuleActionKind::Log if log.is_none() => log = Some(rule_label(rule)),
            _ => {}
        }
    }

    if let Some((name, kind)) = blocking {
        return Some(match kind {
            RuleActionKind::Challenge => CustomDecision::Challenge(name),
            _ => CustomDecision::Deny(name),
        });
    }
    log.map(CustomDecision::Log)
}

fn rule_label(rule: &CustomRule) -> String {
    if rule.name.trim().is_empty() {
        rule.id.clone()
    } else {
        rule.name.clone()
    }
}

fn rule_matches(rule: &CustomRule, req: &RuleRequest<'_>) -> bool {
    // 组内始终是 AND；组间由「匹配方式」决定
    let groups: Vec<&Vec<RuleCondition>> = rule.pattern.iter().filter(|g| !g.is_empty()).collect();
    if groups.is_empty() {
        return false;
    }
    let group_ok = |g: &Vec<RuleCondition>| g.iter().all(|c| condition_matches(c, req));

    match rule.match_mode {
        MatchMode::Any => groups.iter().any(|g| group_ok(g)),
        MatchMode::All => groups.iter().all(|g| group_ok(g)),
    }
}

fn condition_matches(cond: &RuleCondition, req: &RuleRequest<'_>) -> bool {
    let key = cond.k.trim().to_ascii_lowercase();

    // IP 组是集合成员判断，不能走字符串比较
    if key == "ip_group" {
        let Some(ip) = req.ip else {
            return false;
        };
        let hit = cond.v.iter().any(|name| {
            req.ip_groups
                .get(name.trim())
                .is_some_and(|nets| nets.iter().any(|net| net.contains(&ip)))
        });
        return match cond.op.trim().to_ascii_lowercase().as_str() {
            "ne" | "not" | "not_eq" => !hit,
            _ => hit,
        };
    }

    let Some(actual) = actual_value(cond, req) else {
        return false;
    };
    if cond.v.is_empty() {
        return false;
    }

    let op = cond.op.trim().to_ascii_lowercase();
    match op.as_str() {
        "eq" | "equal" | "is" | "in" => cond.v.iter().any(|v| compare(cond, &actual, v)),
        "ne" | "not_eq" | "not" => cond.v.iter().all(|v| !compare(cond, &actual, v)),
        "contain" | "contains" | "like" => cond.v.iter().any(|v| actual.contains(v.as_str())),
        "not_contain" | "not_contains" | "not_like" => {
            cond.v.iter().all(|v| !actual.contains(v.as_str()))
        }
        "prefix" | "start_with" | "starts_with" => {
            cond.v.iter().any(|v| actual.starts_with(v.as_str()))
        }
        "suffix" | "end_with" | "ends_with" => cond.v.iter().any(|v| actual.ends_with(v.as_str())),
        "regex" | "match" | "re" => cond.v.iter().any(|v| {
            Regex::new(v)
                .map(|re| re.is_match(&actual))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

/// `src_ip` 支持 CIDR；其余字段按字符串比较。
fn compare(cond: &RuleCondition, actual: &str, expected: &str) -> bool {
    if is_ip_key(&cond.k) {
        if let (Ok(ip), Ok(net)) = (actual.parse::<IpAddr>(), expected.parse::<IpNet>()) {
            return net.contains(&ip);
        }
    }
    actual.eq_ignore_ascii_case(expected)
}

fn is_ip_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "src_ip" | "ip" | "client_ip" | "source_ip"
    )
}

fn actual_value(cond: &RuleCondition, req: &RuleRequest<'_>) -> Option<String> {
    match cond.k.trim().to_ascii_lowercase().as_str() {
        "src_ip" | "ip" | "client_ip" | "source_ip" => req.ip.map(|ip| ip.to_string()),
        // 雷池里的 website 是站点名；这里同时接受应用 ID 与 Host
        "website" | "app" | "site" => Some(req.app.to_string()),
        "host" | "domain" => Some(req.host.to_string()),
        "path" | "uri" => Some(req.path.to_string()),
        "url" => Some(match req.query {
            Some(q) if !q.is_empty() => format!("{}?{}", req.path, q),
            _ => req.path.to_string(),
        }),
        "query" | "args" | "query_string" => req.query.map(|q| q.to_string()),
        "method" => Some(req.method.to_string()),
        "user_agent" | "ua" => req.user_agent.map(|v| v.to_string()),
        "content_type" => req.content_type.map(|v| v.to_string()),
        "cookie" => req.cookie.map(|v| v.to_string()),
        "ja4" | "tls_fingerprint" => req.ja4.map(|v| v.to_string()),
        "header" | "headers" => {
            let name = cond.sub_k.as_deref()?;
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        }
        other if other.starts_with("header:") => {
            let name = &other["header:".len()..];
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn req<'a>(
        headers: &'a http::HeaderMap,
        groups: &'a HashMap<String, Vec<IpNet>>,
    ) -> RuleRequest<'a> {
        RuleRequest {
            app: "blog",
            host: "nas.test",
            ip: Some("10.0.0.5".parse().unwrap()),
            path: "/admin/login",
            query: Some("x=1"),
            method: "GET",
            user_agent: Some("curl/8"),
            content_type: None,
            cookie: None,
            headers,
            ja4: None,
            ip_groups: groups,
        }
    }

    fn rule(action: u8, pattern: Vec<Vec<RuleCondition>>) -> CustomRule {
        CustomRule {
            id: "r1".into(),
            name: "测试规则".into(),
            enabled: true,
            action,
            match_mode: MatchMode::Any,
            seq: 0,
            created_at: None,
            scope: Vec::new(),
            expires_at: None,
            pattern,
        }
    }

    fn cond(k: &str, op: &str, v: &[&str]) -> RuleCondition {
        RuleCondition {
            k: k.into(),
            op: op.into(),
            v: v.iter().map(|s| s.to_string()).collect(),
            sub_k: None,
        }
    }

    #[test]
    fn and_or_semantics() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![rule(
            1,
            vec![
                vec![cond("path", "contain", &["/admin"])],
                vec![cond("method", "eq", &["POST"])],
            ],
        )];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Deny(_))
        ));

        let rules = vec![rule(
            1,
            vec![vec![
                cond("path", "contain", &["/admin"]),
                cond("method", "eq", &["POST"]),
            ]],
        )];
        assert!(evaluate(&rules, &r, NOW).is_none());
    }

    #[test]
    fn whitelist_wins() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![
            rule(1, vec![vec![cond("path", "contain", &["/admin"])]]),
            rule(0, vec![vec![cond("src_ip", "eq", &["10.0.0.0/24"])]]),
        ];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Allow(_))
        ));
    }

    #[test]
    fn challenge_action_is_reported_as_challenge() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![rule(2, vec![vec![cond("path", "prefix", &["/admin"])]])];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Challenge(_))
        ));
    }

    #[test]
    fn log_action_does_not_block() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![rule(3, vec![vec![cond("path", "prefix", &["/admin"])]])];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Log(_))
        ));
    }

    #[test]
    fn deny_beats_log_regardless_of_order() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![
            rule(3, vec![vec![cond("path", "prefix", &["/admin"])]]),
            rule(1, vec![vec![cond("path", "prefix", &["/admin"])]]),
        ];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Deny(_))
        ));
    }

    #[test]
    fn ip_group_condition_matches_membership() {
        let headers = http::HeaderMap::new();
        let mut groups = HashMap::new();
        groups.insert(
            "bad".to_string(),
            vec!["10.0.0.0/24".parse::<IpNet>().unwrap()],
        );
        let r = req(&headers, &groups);
        let rules = vec![rule(1, vec![vec![cond("ip_group", "in", &["bad"])]])];
        assert!(matches!(
            evaluate(&rules, &r, NOW),
            Some(CustomDecision::Deny(_))
        ));

        // 不存在的组名不匹配，也不能误伤
        let rules = vec![rule(1, vec![vec![cond("ip_group", "in", &["nope"])]])];
        assert!(evaluate(&rules, &r, NOW).is_none());
    }

    #[test]
    fn scope_limits_rule_to_app() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let mut scoped = rule(1, vec![vec![cond("path", "prefix", &["/admin"])]]);
        scoped.scope = vec!["nas".to_string()];
        assert!(evaluate(&[scoped.clone()], &r, NOW).is_none());

        scoped.scope = vec!["blog".to_string()];
        assert!(evaluate(&[scoped], &r, NOW).is_some());
    }

    #[test]
    fn expired_and_disabled_rules_ignored() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);

        let mut expired = rule(1, vec![vec![cond("path", "prefix", &["/admin"])]]);
        expired.expires_at = Some(NOW - 1);
        assert!(evaluate(&[expired], &r, NOW).is_none());

        let mut disabled = rule(1, vec![vec![cond("path", "prefix", &["/admin"])]]);
        disabled.enabled = false;
        assert!(evaluate(&[disabled], &r, NOW).is_none());
    }

    #[test]
    fn match_mode_all_requires_every_group() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups); // GET /admin/login
        let mut rule = rule(
            1,
            vec![
                vec![cond("path", "prefix", &["/admin"])],
                vec![cond("method", "eq", &["POST"])],
            ],
        );
        rule.match_mode = MatchMode::All;
        // 只有路径命中，方法不匹配 → 全部模式不成立
        assert!(evaluate(&[rule.clone()], &r, NOW).is_none());

        rule.match_mode = MatchMode::Any;
        assert!(evaluate(&[rule], &r, NOW).is_some());
    }

    #[test]
    fn higher_seq_wins_between_conflicting_rules() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let mut deny = rule(1, vec![vec![cond("path", "prefix", &["/admin"])]]);
        deny.seq = 1;
        let mut allow = rule(0, vec![vec![cond("path", "prefix", &["/admin"])]]);
        allow.seq = 2;
        allow.id = "r2".into();
        // 放行优先是硬规则，与序号无关
        assert!(matches!(
            evaluate(&[deny, allow], &r, NOW),
            Some(CustomDecision::Allow(_))
        ));
    }

    #[test]
    fn header_condition_uses_sub_key() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-debug", http::HeaderValue::from_static("1"));
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let mut c = cond("header", "eq", &["1"]);
        c.sub_k = Some("x-debug".into());
        assert!(evaluate(&[rule(1, vec![vec![c]])], &r, NOW).is_some());
    }

    #[test]
    fn ja4_condition_matches_only_when_present() {
        let headers = http::HeaderMap::new();
        let groups = HashMap::new();
        let r = req(&headers, &groups);
        let rules = vec![rule(1, vec![vec![cond("ja4", "prefix", &["t13d1516h2"])]])];
        // 明文 HTTP 连接没有指纹，规则不命中，不能误伤
        assert!(evaluate(&rules, &r, NOW).is_none());

        let with_ja4 = RuleRequest {
            ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6"),
            ..req(&headers, &groups)
        };
        assert!(matches!(
            evaluate(&rules, &with_ja4, NOW),
            Some(CustomDecision::Deny(_))
        ));
    }
}
