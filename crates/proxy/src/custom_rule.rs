//! 自定义规则求值。
//!
//! 兼容雷池（长亭）的规则格式：`pattern` 外层是 OR、内层是 AND，
//! `action` 为 0 时是白名单（命中后放行并跳过检测），为 1 时是黑名单（直接拦截）。
//! 白名单优先于黑名单，与雷池保持一致。

use std::net::IpAddr;

use homewaf_config::{CustomRule, RuleCondition};
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomDecision {
    /// 白名单命中，规则名
    Allow(String),
    /// 黑名单命中，规则名
    Deny(String),
}

/// 按顺序求值。白名单只要命中一条就放行；否则返回第一条命中的黑名单。
pub fn evaluate(rules: &[CustomRule], req: &RuleRequest<'_>) -> Option<CustomDecision> {
    let mut deny: Option<String> = None;
    for rule in rules.iter().filter(|r| r.enabled && !r.pattern.is_empty()) {
        if !rule_matches(rule, req) {
            continue;
        }
        if rule.is_whitelist() {
            return Some(CustomDecision::Allow(rule_label(rule)));
        }
        if deny.is_none() {
            deny = Some(rule_label(rule));
        }
    }
    deny.map(CustomDecision::Deny)
}

fn rule_label(rule: &CustomRule) -> String {
    if rule.name.trim().is_empty() {
        rule.id.clone()
    } else {
        rule.name.clone()
    }
}

fn rule_matches(rule: &CustomRule, req: &RuleRequest<'_>) -> bool {
    // 外层 OR：任意一组全部满足即可
    rule.pattern
        .iter()
        .any(|group| !group.is_empty() && group.iter().all(|c| condition_matches(c, req)))
}

fn condition_matches(cond: &RuleCondition, req: &RuleRequest<'_>) -> bool {
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

    fn req<'a>(headers: &'a http::HeaderMap) -> RuleRequest<'a> {
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
        }
    }

    fn rule(action: u8, pattern: Vec<Vec<RuleCondition>>) -> CustomRule {
        CustomRule {
            id: "r1".into(),
            name: "测试规则".into(),
            enabled: true,
            action,
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
        let r = req(&headers);
        let rules = vec![rule(
            1,
            vec![
                vec![cond("path", "contain", &["/admin"])],
                vec![cond("method", "eq", &["POST"])],
            ],
        )];
        assert!(matches!(
            evaluate(&rules, &r),
            Some(CustomDecision::Deny(_))
        ));

        let rules = vec![rule(
            1,
            vec![vec![
                cond("path", "contain", &["/admin"]),
                cond("method", "eq", &["POST"]),
            ]],
        )];
        assert!(evaluate(&rules, &r).is_none());
    }

    #[test]
    fn whitelist_wins() {
        let headers = http::HeaderMap::new();
        let r = req(&headers);
        let rules = vec![
            rule(1, vec![vec![cond("path", "contain", &["/admin"])]]),
            rule(0, vec![vec![cond("src_ip", "eq", &["10.0.0.0/24"])]]),
        ];
        assert!(matches!(
            evaluate(&rules, &r),
            Some(CustomDecision::Allow(_))
        ));
    }
}
