//! 域名匹配：把请求的 Host 映射到应用。
//!
//! 优先级：精确（含别名）> 通配 > 正则 > 未匹配。
//! 通配符 `*.home.lan` 只匹配一级子域，不匹配多级。

use std::collections::HashMap;

use homewaf_config::Application;
use regex::Regex;

use crate::BuildError;

/// 域名匹配器。构建后只读，可安全共享。
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    /// 精确域名（含别名）→ 应用索引
    exact: HashMap<String, usize>,
    /// 通配后缀（不含 `*.`）→ 应用索引，按后缀长度降序
    wildcard: Vec<(String, usize)>,
    /// 正则域名 → 应用索引，按配置顺序
    regex: Vec<(Regex, usize)>,
}

impl DomainMatcher {
    /// 从应用列表构建。
    ///
    /// `allow_regex` 为 false 时，遇到 `~` 开头的域名会报错（正则默认关闭）。
    pub fn build(apps: &[Application], allow_regex: bool) -> Result<Self, BuildError> {
        let mut exact = HashMap::new();
        let mut wildcard = Vec::new();
        let mut regex = Vec::new();

        for (index, app) in apps.iter().enumerate() {
            if !app.enabled {
                continue;
            }
            for domain in std::iter::once(&app.domains.primary).chain(app.domains.aliases.iter()) {
                let normalized =
                    normalize_host(domain).ok_or_else(|| BuildError::InvalidDomain {
                        app: app.id.clone(),
                        domain: domain.clone(),
                        reason: "不是合法的域名".to_string(),
                    })?;

                if let Some(suffix) = normalized.strip_prefix("*.") {
                    wildcard.push((suffix.to_string(), index));
                } else if let Some(pattern) = normalized.strip_prefix('~') {
                    if !allow_regex {
                        return Err(BuildError::RegexNotAllowed {
                            app: app.id.clone(),
                            pattern: pattern.to_string(),
                        });
                    }
                    let re = Regex::new(pattern).map_err(|source| BuildError::InvalidRegex {
                        app: app.id.clone(),
                        pattern: pattern.to_string(),
                        source,
                    })?;
                    regex.push((re, index));
                } else {
                    // 同一域名重复声明时保留先出现的（校验层已报错，这里只做防御）
                    exact.entry(normalized).or_insert(index);
                }
            }
        }

        // 后缀越长越具体，优先匹配；同长度时保持配置顺序
        wildcard.sort_by_key(|(suffix, index)| (std::cmp::Reverse(suffix.len()), *index));

        Ok(Self {
            exact,
            wildcard,
            regex,
        })
    }

    /// 查找 Host 对应的应用索引。
    pub fn lookup(&self, host: &str) -> Option<usize> {
        let host = normalize_host(host)?;

        if let Some(&index) = self.exact.get(&host) {
            return Some(index);
        }
        for (suffix, index) in &self.wildcard {
            if wildcard_match(suffix, &host) {
                return Some(*index);
            }
        }
        for (re, index) in &self.regex {
            if re.is_match(&host) {
                return Some(*index);
            }
        }
        None
    }

    /// 已注册的精确域名数量（含别名）。
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// 已注册的通配域名数量。
    pub fn wildcard_count(&self) -> usize {
        self.wildcard.len()
    }

    /// 已注册的正则域名数量。
    pub fn regex_count(&self) -> usize {
        self.regex.len()
    }
}

/// 规范化 Host：去空白、去端口、转小写、去末尾点。
///
/// 非法输入返回 `None`（含 `/`、空白、控制字符、裸 IPv6）。
pub fn normalize_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host = strip_port(trimmed)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // Host 里不允许出现路径分隔符、空白、控制字符
    if host
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c.is_control())
    {
        return None;
    }
    // 通配符与正则前缀在这里保留，由调用方判断
    Some(host)
}

/// 去掉端口。
///
/// - `a.com:8080` → `a.com`
/// - `[::1]:443` → `::1`
/// - `[::1]` → `::1`
/// - 裸 IPv6（`::1`）视为非法 Host（RFC 9110 要求带方括号）
fn strip_port(s: &str) -> Option<&str> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        if host.is_empty() {
            return None;
        }
        return Some(host);
    }
    if s.matches(':').count() > 1 {
        // 裸 IPv6，非法
        return None;
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            if host.is_empty() {
                None
            } else {
                Some(host)
            }
        }
        Some(_) => Some(s),
        None => Some(s),
    }
}

/// 通配匹配：`suffix` 不含 `*.`，要求 host 恰好比 suffix 多一级。
fn wildcard_match(suffix: &str, host: &str) -> bool {
    let Some(prefix) = host.strip_suffix(suffix) else {
        return false;
    };
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{Application, Domains, LbConfig, Policy, Scheme, TlsModeConfig, Upstream};

    fn app(id: &str, primary: &str, aliases: &[&str]) -> Application {
        Application {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            domains: Domains {
                primary: primary.to_string(),
                aliases: aliases.iter().map(|s| s.to_string()).collect(),
            },
            listen_ports: Vec::new(),
            upstreams: vec![Upstream {
                addr: "192.168.1.5".to_string(),
                port: Some(8080),
                scheme: Scheme::Http,
                weight: 1,
                backup: false,
                max_conns: 128,
                tls: None,
            }],
            routes: vec![],
            tls: TlsModeConfig::default(),
            policy: Policy::default(),
            lb: LbConfig::default(),
            timeouts: Default::default(),
            health_check: Default::default(),
            retry: Default::default(),
            headers: Default::default(),
            websocket: false,
            expires_at: None,
            description: String::new(),
            group: String::new(),
            access_mode: Default::default(),
            static_site: Default::default(),
            redirect: Default::default(),
            features: Default::default(),
            tamper: Default::default(),
        }
    }

    #[test]
    fn exact_match() {
        let m = DomainMatcher::build(&[app("a", "a.home.lan", &[])], false).unwrap();
        assert_eq!(m.lookup("a.home.lan"), Some(0));
        assert_eq!(m.lookup("b.home.lan"), None);
    }

    #[test]
    fn alias_matches() {
        let m = DomainMatcher::build(&[app("a", "a.home.lan", &["b.home.lan"])], false).unwrap();
        assert_eq!(m.lookup("a.home.lan"), Some(0));
        assert_eq!(m.lookup("b.home.lan"), Some(0));
    }

    #[test]
    fn host_normalization() {
        let m = DomainMatcher::build(&[app("a", "a.home.lan", &[])], false).unwrap();
        assert_eq!(m.lookup("A.HOME.LAN"), Some(0), "应大小写不敏感");
        assert_eq!(m.lookup("a.home.lan."), Some(0), "应忽略末尾点");
        assert_eq!(m.lookup("a.home.lan:8443"), Some(0), "应忽略端口");
        assert_eq!(m.lookup("  a.home.lan  "), Some(0), "应忽略空白");
    }

    #[test]
    fn wildcard_matches_one_level_only() {
        let m = DomainMatcher::build(&[app("a", "*.home.lan", &[])], false).unwrap();
        assert_eq!(m.lookup("x.home.lan"), Some(0));
        assert_eq!(m.lookup("x.y.home.lan"), None, "不应匹配多级");
        assert_eq!(m.lookup("home.lan"), None, "不应匹配裸域名");
    }

    #[test]
    fn exact_beats_wildcard() {
        let m = DomainMatcher::build(
            &[
                app("wild", "*.home.lan", &[]),
                app("exact", "nas.home.lan", &[]),
            ],
            false,
        )
        .unwrap();
        assert_eq!(m.lookup("nas.home.lan"), Some(1));
        assert_eq!(m.lookup("other.home.lan"), Some(0));
    }

    #[test]
    fn longer_wildcard_suffix_wins() {
        let m = DomainMatcher::build(
            &[
                app("wide", "*.home.lan", &[]),
                app("narrow", "*.a.home.lan", &[]),
            ],
            false,
        )
        .unwrap();
        // 两级子域：只有 narrow 的 suffix 能对上
        assert_eq!(m.lookup("x.a.home.lan"), Some(1));
        // 一级子域：只有 wide 能对上
        assert_eq!(m.lookup("y.home.lan"), Some(0));
        // 两级但不含 a：两个都不匹配（通配只匹配一级）
        assert_eq!(m.lookup("x.b.home.lan"), None);
    }

    #[test]
    fn disabled_app_is_skipped() {
        let mut a = app("a", "a.home.lan", &[]);
        a.enabled = false;
        let m = DomainMatcher::build(&[a], false).unwrap();
        assert_eq!(m.lookup("a.home.lan"), None);
    }

    #[test]
    fn regex_requires_opt_in() {
        let apps = [app("a", "~^api\\d+\\.home\\.lan$", &[])];
        assert!(DomainMatcher::build(&apps, false).is_err());

        let m = DomainMatcher::build(&apps, true).unwrap();
        assert_eq!(m.lookup("api1.home.lan"), Some(0));
        assert_eq!(m.lookup("apiX.home.lan"), None);
    }

    #[test]
    fn invalid_hosts_rejected() {
        assert!(normalize_host("").is_none());
        assert!(normalize_host("a b.com").is_none());
        assert!(normalize_host("a/b.com").is_none());
        assert!(normalize_host("::1").is_none(), "裸 IPv6 应被拒绝");
        assert_eq!(normalize_host("[::1]:443").as_deref(), Some("::1"));
    }

    #[test]
    fn ipv6_host_matches() {
        let m = DomainMatcher::build(&[app("a", "nas.home.lan", &[])], false).unwrap();
        // IPv6 字面量不是注册的域名，应不匹配
        assert_eq!(m.lookup("[::1]:443"), None);
    }
}
