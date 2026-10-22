//! 路径重写。
//!
//! 路由匹配到 `/a` 之后，后端可能期望收到 `/c`——这是反向代理的常规能力，
//! 但之前只有配置结构、没有实现。
//!
//! 四种模式：
//! - `strip_prefix`：去掉匹配到的路由前缀
//! - `add_prefix`：在最前面加一段
//! - `prefix`：**把匹配到的路由前缀替换成 value**（最常用）
//! - `regex`：正则替换

use homewaf_config::{Rewrite, RewriteMode};

/// 按重写规则改写路径。
///
/// `path` 是规范化后的请求路径，`route_path` 是命中的路由前缀（用于定位要替换的部分）。
pub fn apply(path: &str, route_path: &str, rewrite: &Rewrite) -> String {
    match rewrite.mode {
        RewriteMode::StripPrefix => {
            let rest = path.strip_prefix(route_path).unwrap_or(path);
            normalize(rest)
        }
        RewriteMode::AddPrefix => {
            if rewrite.value.is_empty() {
                return path.to_string();
            }
            let prefix = rewrite.value.trim_end_matches('/');
            format!("{prefix}{path}")
        }
        RewriteMode::Prefix => {
            // 路径不以路由前缀开头时原样返回。理论上不会发生（路由已匹配），
            // 但把整个路径丢掉比不改更糟。
            let Some(rest) = path.strip_prefix(route_path) else {
                return path.to_string();
            };
            let target = rewrite.value.trim_end_matches('/');

            if rest.is_empty() {
                return if target.is_empty() {
                    "/".to_string()
                } else {
                    target.to_string()
                };
            }

            let rest = if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            };
            format!("{target}{rest}")
        }
        RewriteMode::Regex => apply_regex(path, rewrite),
    }
}

/// 保证结果以 `/` 开头，空串变成 `/`。
fn normalize(s: &str) -> String {
    if s.is_empty() {
        "/".to_string()
    } else if s.starts_with('/') {
        s.to_string()
    } else {
        format!("/{s}")
    }
}

fn apply_regex(path: &str, rewrite: &Rewrite) -> String {
    let (Some(pattern), Some(replacement)) = (&rewrite.regex, &rewrite.replacement) else {
        return path.to_string();
    };
    // 正则编译失败时原样返回，不因为一条坏规则把请求搞挂
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace(path, replacement.as_str()).into_owned(),
        Err(e) => {
            tracing::warn!(pattern, error = %e, "重写正则非法，已跳过");
            path.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::RewriteMode;

    fn rw(mode: RewriteMode, value: &str) -> Rewrite {
        Rewrite {
            mode,
            value: value.to_string(),
            regex: None,
            replacement: None,
        }
    }

    #[test]
    fn prefix_replaces_route_prefix() {
        let r = rw(RewriteMode::Prefix, "/c");
        // 核心场景：/a 转发到上游的 /c
        assert_eq!(apply("/a/foo", "/a", &r), "/c/foo");
        assert_eq!(apply("/a", "/a", &r), "/c");
        assert_eq!(apply("/a/b/c", "/a", &r), "/c/b/c");
    }

    #[test]
    fn prefix_with_nested_route() {
        let r = rw(RewriteMode::Prefix, "/internal/v1");
        assert_eq!(apply("/api/users", "/api", &r), "/internal/v1/users");
    }

    #[test]
    fn prefix_to_root() {
        let r = rw(RewriteMode::Prefix, "/");
        assert_eq!(apply("/a/foo", "/a", &r), "/foo");
        assert_eq!(apply("/a", "/a", &r), "/");
    }

    #[test]
    fn strip_prefix_removes_it() {
        let r = rw(RewriteMode::StripPrefix, "");
        assert_eq!(apply("/a/foo", "/a", &r), "/foo");
        assert_eq!(apply("/a", "/a", &r), "/");
    }

    #[test]
    fn add_prefix_prepends() {
        let r = rw(RewriteMode::AddPrefix, "/c");
        assert_eq!(apply("/foo", "/", &r), "/c/foo");
        assert_eq!(apply("/", "/", &r), "/c/");
    }

    #[test]
    fn add_prefix_empty_is_noop() {
        let r = rw(RewriteMode::AddPrefix, "");
        assert_eq!(apply("/foo", "/", &r), "/foo");
    }

    #[test]
    fn regex_replace() {
        let mut r = rw(RewriteMode::Regex, "");
        r.regex = Some(r"^/a/(.*)$".to_string());
        r.replacement = Some("/c/$1".to_string());
        assert_eq!(apply("/a/foo", "/a", &r), "/c/foo");
    }

    #[test]
    fn invalid_regex_is_skipped() {
        let mut r = rw(RewriteMode::Regex, "");
        r.regex = Some("(unclosed".to_string());
        r.replacement = Some("x".to_string());
        // 坏正则不该 panic，也不该把路径搞丢
        assert_eq!(apply("/a/foo", "/a", &r), "/a/foo");
    }

    #[test]
    fn missing_regex_fields_is_noop() {
        let r = rw(RewriteMode::Regex, "");
        assert_eq!(apply("/a", "/a", &r), "/a");
    }

    #[test]
    fn result_always_starts_with_slash() {
        for (mode, value) in [
            (RewriteMode::Prefix, "/c"),
            (RewriteMode::StripPrefix, ""),
            (RewriteMode::AddPrefix, "/x"),
        ] {
            let r = rw(mode, value);
            for path in ["/a", "/a/b", "/"] {
                let out = apply(path, "/a", &r);
                assert!(
                    out.starts_with('/'),
                    "{mode:?} 对 {path} 产生了不以 / 开头的结果: {out}"
                );
            }
        }
    }

    #[test]
    fn path_not_matching_route_prefix_is_handled() {
        // 理论上不会发生（路由已经匹配过），但防御性处理：原样返回，不丢路径
        let r = rw(RewriteMode::Prefix, "/c");
        assert_eq!(apply("/other", "/a", &r), "/other");
    }
}
