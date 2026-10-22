//! 路径匹配与规范化。
//!
//! 匹配类型与优先级对齐 Nginx：`=` > `^~` > `~` > 最长前缀 > `/`。
//!
//! **规范化是安全关键**：检测与转发必须使用同一份规范化结果，
//! 否则会出现"检测看到 A、后端收到 B"的绕过。

use std::collections::HashMap;

use homewaf_config::Route;
use regex::Regex;

use crate::BuildError;

/// 命中的匹配类型，用于日志与调试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// `= /path`
    Exact,
    /// `^~ /path`，命中后不再试正则
    PrefixNoRegex,
    /// `~ pattern`
    Regex,
    /// 普通前缀
    Prefix,
    /// 兜底 `/`
    Default,
}

/// 路径匹配器。
#[derive(Debug, Clone)]
pub struct PathMatcher {
    exact: HashMap<String, usize>,
    no_regex_prefix: Vec<(String, usize)>,
    regex: Vec<(Regex, usize)>,
    prefix: Vec<(String, usize)>,
    default_index: Option<usize>,
}

impl PathMatcher {
    /// 从路由列表构建。`allow_regex` 为 false 时遇到 `~` 路由会报错。
    pub fn build(routes: &[Route], allow_regex: bool) -> Result<Self, BuildError> {
        let mut exact = HashMap::new();
        let mut no_regex_prefix = Vec::new();
        let mut regex = Vec::new();
        let mut prefix = Vec::new();
        let mut default_index = None;

        for (index, route) in routes.iter().enumerate() {
            let pattern = route.path.trim();
            if pattern.is_empty() {
                return Err(BuildError::InvalidPath {
                    path: pattern.to_string(),
                    reason: "路由路径不能为空".to_string(),
                });
            }

            if let Some(rest) = pattern.strip_prefix('=') {
                exact.insert(normalize_path(rest.trim()), index);
            } else if let Some(rest) = pattern.strip_prefix("^~") {
                no_regex_prefix.push((normalize_path(rest.trim()), index));
            } else if let Some(rest) = pattern.strip_prefix("~*") {
                if !allow_regex {
                    return Err(BuildError::RegexNotAllowed {
                        app: String::new(),
                        pattern: rest.trim().to_string(),
                    });
                }
                let re = Regex::new(&format!("(?i){}", rest.trim())).map_err(|source| {
                    BuildError::InvalidRegex {
                        app: String::new(),
                        pattern: rest.trim().to_string(),
                        source,
                    }
                })?;
                regex.push((re, index));
            } else if let Some(rest) = pattern.strip_prefix('~') {
                if !allow_regex {
                    return Err(BuildError::RegexNotAllowed {
                        app: String::new(),
                        pattern: rest.trim().to_string(),
                    });
                }
                let re = Regex::new(rest.trim()).map_err(|source| BuildError::InvalidRegex {
                    app: String::new(),
                    pattern: rest.trim().to_string(),
                    source,
                })?;
                regex.push((re, index));
            } else {
                let normalized = normalize_path(pattern);
                if normalized == "/" {
                    default_index = Some(index);
                }
                prefix.push((normalized, index));
            }
        }

        // 前缀越长越具体，优先匹配
        no_regex_prefix.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        prefix.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));

        Ok(Self {
            exact,
            no_regex_prefix,
            regex,
            prefix,
            default_index,
        })
    }

    /// 查找路径命中的路由索引。
    ///
    /// 传入的路径必须已经过 [`normalize_path`]。若传入原始路径，
    /// 含 `..` 或重复斜杠的请求可能匹配不到预期路由。
    pub fn lookup(&self, normalized_path: &str) -> Option<(usize, MatchKind)> {
        if let Some(&index) = self.exact.get(normalized_path) {
            return Some((index, MatchKind::Exact));
        }

        // 找最长前缀（`^~` 与普通前缀一起比较）
        let mut best: Option<(&str, usize, MatchKind)> = None;
        for (p, i) in &self.no_regex_prefix {
            if normalized_path.starts_with(p.as_str())
                && best.is_none_or(|(bp, _, _)| p.len() > bp.len())
            {
                best = Some((p, *i, MatchKind::PrefixNoRegex));
            }
        }
        for (p, i) in &self.prefix {
            if normalized_path.starts_with(p.as_str())
                && best.is_none_or(|(bp, _, _)| p.len() > bp.len())
            {
                best = Some((p, *i, MatchKind::Prefix));
            }
        }

        // 最长前缀若是 `^~`，直接返回，不再试正则
        if let Some((_, index, MatchKind::PrefixNoRegex)) = best {
            return Some((index, MatchKind::PrefixNoRegex));
        }

        for (re, index) in &self.regex {
            if re.is_match(normalized_path) {
                return Some((*index, MatchKind::Regex));
            }
        }

        if let Some((_, index, kind)) = best {
            return Some((index, kind));
        }

        self.default_index.map(|i| (i, MatchKind::Default))
    }

    /// 是否有兜底路由 `/`。
    pub fn has_default(&self) -> bool {
        self.default_index.is_some()
    }
}

/// 路径规范化。
///
/// 步骤固定，顺序不可变：
/// 1. 截掉 `?query` 与 `#fragment`
/// 2. 百分号解码（单层，非法序列保留原样）
/// 3. 按 `/` 分段，去掉每段 `;` 之后的内容
/// 4. 处理 `.` 与 `..`（`..` 在栈空时忽略，不能跳出根）
/// 5. 重新拼接，保留尾斜杠
pub fn normalize_path(raw: &str) -> String {
    let path_part = raw.split(['?', '#']).next().unwrap_or("");

    let decoded = percent_decode(path_part);
    let trailing_slash = decoded.len() > 1 && decoded.ends_with('/');

    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        let segment = segment.split(';').next().unwrap_or("");
        match segment {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    let mut out = String::with_capacity(decoded.len().max(1));
    out.push('/');
    out.push_str(&segments.join("/"));
    if trailing_slash && !out.ends_with('/') {
        out.push('/');
    }
    out
}

/// 百分号解码。非法序列（如 `%zz`、结尾单个 `%`）原样保留。
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::Route;

    fn route(path: &str) -> Route {
        Route {
            path: path.to_string(),
            upstreams: None,
            rewrite: None,
            policy: None,
            allow_methods: None,
            cache: None,
        }
    }

    // ============================================================
    // 规范化
    // ============================================================

    #[test]
    fn normalize_basic() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/api"), "/api");
        assert_eq!(normalize_path("/api/v1"), "/api/v1");
    }

    #[test]
    fn normalize_collapses_duplicate_slashes() {
        assert_eq!(normalize_path("//api//v1"), "/api/v1");
        assert_eq!(normalize_path("/a///b"), "/a/b");
    }

    #[test]
    fn normalize_resolves_dot_segments() {
        assert_eq!(normalize_path("/a/../b"), "/b");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn normalize_cannot_escape_root() {
        assert_eq!(normalize_path("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_path("/.."), "/");
        assert_eq!(normalize_path("/a/../../../b"), "/b");
    }

    #[test]
    fn normalize_decodes_percent() {
        assert_eq!(normalize_path("/%61pi"), "/api");
        assert_eq!(normalize_path("/%2e%2e/admin"), "/admin");
        assert_eq!(normalize_path("/a%2fb"), "/a/b");
    }

    #[test]
    fn normalize_keeps_invalid_percent() {
        assert_eq!(normalize_path("/100%"), "/100%");
        assert_eq!(normalize_path("/a%zzb"), "/a%zzb");
    }

    #[test]
    fn normalize_strips_path_params() {
        assert_eq!(normalize_path("/a;jsessionid=xyz"), "/a");
        assert_eq!(normalize_path("/a;x/b;y"), "/a/b");
    }

    #[test]
    fn normalize_strips_query_and_fragment() {
        assert_eq!(normalize_path("/api?x=1"), "/api");
        assert_eq!(normalize_path("/api#top"), "/api");
    }

    #[test]
    fn normalize_keeps_trailing_slash() {
        assert_eq!(normalize_path("/api/"), "/api/");
        assert_eq!(normalize_path("/api"), "/api");
        assert_ne!(normalize_path("/api/"), normalize_path("/api"));
    }

    #[test]
    fn normalize_empty_becomes_root() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("?x=1"), "/");
    }

    #[test]
    fn normalize_is_idempotent() {
        // 规范化结果再规范化必须不变，否则"检测用的路径"和"转发用的路径"会分叉
        for raw in [
            "/",
            "/api",
            "//a//b",
            "/a/../b",
            "/a/",
            "/%2e%2e/x",
            "/a;b=1/c",
            "/a/./b/../c/",
            "/%61pi/%2e%2e/admin",
        ] {
            let once = normalize_path(raw);
            let twice = normalize_path(&once);
            assert_eq!(once, twice, "规范化不幂等: {raw} → {once} → {twice}");
        }
    }

    #[test]
    fn normalize_never_produces_empty() {
        for raw in ["", "?", "#", "///", "/..", "/../..", ";x"] {
            let out = normalize_path(raw);
            assert!(out.starts_with('/'), "{raw} → {out} 应以 / 开头");
            assert!(!out.is_empty());
        }
    }

    // ============================================================
    // 匹配
    // ============================================================

    #[test]
    fn exact_match_wins() {
        let m = PathMatcher::build(&[route("/api"), route("= /api")], false).unwrap();
        assert_eq!(m.lookup("/api"), Some((1, MatchKind::Exact)));
        assert_eq!(m.lookup("/api/v1"), Some((0, MatchKind::Prefix)));
    }

    #[test]
    fn no_regex_prefix_beats_regex() {
        let m = PathMatcher::build(&[route("~ \\.php$"), route("^~ /static")], true).unwrap();
        assert_eq!(
            m.lookup("/static/a.php"),
            Some((1, MatchKind::PrefixNoRegex))
        );
    }

    #[test]
    fn regex_checked_in_order() {
        let m = PathMatcher::build(&[route("~ ^/a"), route("~ ^/ab")], true).unwrap();
        // 第一个正则命中即返回，即使第二个更长
        assert_eq!(m.lookup("/abc"), Some((0, MatchKind::Regex)));
    }

    #[test]
    fn regex_falls_back_to_prefix() {
        let m = PathMatcher::build(&[route("/api"), route("~ \\.php$")], true).unwrap();
        assert_eq!(m.lookup("/api/x"), Some((0, MatchKind::Prefix)));
    }

    #[test]
    fn longest_prefix_wins() {
        let m = PathMatcher::build(&[route("/"), route("/api"), route("/api/v1")], false).unwrap();
        assert_eq!(m.lookup("/api/v1/users"), Some((2, MatchKind::Prefix)));
        assert_eq!(m.lookup("/api/v2"), Some((1, MatchKind::Prefix)));
        assert_eq!(m.lookup("/other"), Some((0, MatchKind::Prefix)));
    }

    #[test]
    fn default_route_used_when_nothing_matches() {
        let m = PathMatcher::build(&[route("/"), route("/api")], false).unwrap();
        assert_eq!(m.lookup("/unknown"), Some((0, MatchKind::Prefix)));
        assert!(m.has_default());
    }

    #[test]
    fn no_default_returns_none() {
        let m = PathMatcher::build(&[route("/api")], false).unwrap();
        assert_eq!(m.lookup("/unknown"), None);
        assert!(!m.has_default());
    }

    #[test]
    fn regex_disabled_by_default() {
        let err = PathMatcher::build(&[route("~ \\.php$")], false).unwrap_err();
        assert!(matches!(err, BuildError::RegexNotAllowed { .. }));
    }

    #[test]
    fn case_insensitive_regex() {
        let m = PathMatcher::build(&[route("~* \\.php$")], true).unwrap();
        assert_eq!(m.lookup("/a.PHP"), Some((0, MatchKind::Regex)));
    }

    #[test]
    fn routes_are_normalized_at_build_time() {
        let m = PathMatcher::build(&[route("/api/")], false).unwrap();
        assert_eq!(m.lookup("/api/"), Some((0, MatchKind::Prefix)));
    }

    #[test]
    fn bypass_attempt_normalized_before_lookup() {
        let m = PathMatcher::build(&[route("^~ /admin")], false).unwrap();
        // 攻击者尝试用 .. 和重复斜杠绕过 /admin 的严格策略
        let raw = "//api/../admin";
        let normalized = normalize_path(raw);
        assert_eq!(normalized, "/admin");
        assert_eq!(m.lookup(&normalized), Some((0, MatchKind::PrefixNoRegex)));
    }
}
