//! 检测白名单（误报豁免）。
//!
//! 和 ACL 的「放行」不是一回事：
//! - ACL 放行 = 这个 IP 是好的，不做任何防护
//! - 检测白名单 = 这个路径/参数里的内容不该按攻击处理，但仍然走 ACL 和其他防护
//!
//! 典型场景：后台的文章编辑器提交 HTML 富文本，`<script>` 是正常内容不是 XSS。
//! 没有白名单，用户只有两个选择：关掉 XSS 检测，或者忍受误报。两个都很糟。

use std::collections::HashSet;

/// 一条白名单规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistRule {
    pub id: String,
    /// 生效应用；`None` 表示全部应用
    pub app: Option<String>,
    /// 路径前缀；`None` 表示不限制路径
    pub path: Option<String>,
    /// 只豁免这条检测规则；`None` 表示跳过全部检测
    pub rule_id: Option<String>,
    pub note: Option<String>,
}

impl WhitelistRule {
    /// 这条规则是否适用于该请求。
    pub fn matches(&self, app: &str, path: &str) -> bool {
        if let Some(a) = &self.app {
            if a != app {
                return false;
            }
        }
        if let Some(p) = &self.path {
            if !p.is_empty() && !path.starts_with(p.as_str()) {
                return false;
            }
        }
        true
    }
}

/// 命中白名单后的豁免结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exemption {
    /// 完全跳过检测
    pub skip_all: bool,
    /// 只豁免这些规则 id
    pub rules: HashSet<String>,
    /// 命中的白名单规则 id，用于日志
    pub matched: Vec<String>,
}

impl Exemption {
    pub fn is_empty(&self) -> bool {
        !self.skip_all && self.rules.is_empty()
    }

    /// 某条规则是否被豁免。
    pub fn exempts(&self, rule_id: &str) -> bool {
        self.skip_all || self.rules.contains(rule_id)
    }
}

/// 计算某个请求的豁免。
///
/// 多条规则会合并：一条说"跳过全部"，另一条说"只豁免 XSS"，
/// 结果就是跳过全部——更宽的豁免胜出，符合"白名单是显式信任"的直觉。
pub fn compute(rules: &[WhitelistRule], app: &str, path: &str) -> Exemption {
    let mut out = Exemption::default();

    for rule in rules {
        if !rule.matches(app, path) {
            continue;
        }
        out.matched.push(rule.id.clone());
        match &rule.rule_id {
            None => out.skip_all = true,
            Some(rid) => {
                out.rules.insert(rid.clone());
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        app: Option<&str>,
        path: Option<&str>,
        rule_id: Option<&str>,
    ) -> WhitelistRule {
        WhitelistRule {
            id: id.to_string(),
            app: app.map(|s| s.to_string()),
            path: path.map(|s| s.to_string()),
            rule_id: rule_id.map(|s| s.to_string()),
            note: None,
        }
    }

    #[test]
    fn no_rules_means_no_exemption() {
        let e = compute(&[], "nas", "/api");
        assert!(e.is_empty());
        assert!(!e.skip_all);
    }

    #[test]
    fn global_rule_matches_everything() {
        let rules = vec![rule("w1", None, None, None)];
        let e = compute(&rules, "nas", "/anything");
        assert!(e.skip_all);
        assert!(e.exempts("sqli-union-select"));
        assert_eq!(e.matched, vec!["w1"]);
    }

    #[test]
    fn app_scoped_rule() {
        let rules = vec![rule("w1", Some("blog"), None, None)];

        assert!(compute(&rules, "blog", "/").skip_all);
        assert!(compute(&rules, "nas", "/").is_empty(), "其他应用不受影响");
    }

    #[test]
    fn path_prefix_rule() {
        let rules = vec![rule("w1", None, Some("/admin/editor"), None)];

        assert!(compute(&rules, "nas", "/admin/editor/post").skip_all);
        assert!(compute(&rules, "nas", "/admin/editor").skip_all);
        assert!(
            compute(&rules, "nas", "/admin/other").is_empty(),
            "前缀之外不生效"
        );
        assert!(
            compute(&rules, "nas", "/public/admin/editor").is_empty(),
            "必须是前缀，不能是包含"
        );
    }

    #[test]
    fn app_and_path_combined() {
        let rules = vec![rule("w1", Some("blog"), Some("/editor"), None)];

        assert!(compute(&rules, "blog", "/editor/x").skip_all);
        assert!(compute(&rules, "nas", "/editor/x").is_empty());
        assert!(compute(&rules, "blog", "/other").is_empty());
    }

    #[test]
    fn rule_specific_exemption() {
        let rules = vec![rule("w1", None, Some("/editor"), Some("xss-script-tag"))];
        let e = compute(&rules, "nas", "/editor/post");

        assert!(!e.skip_all, "只豁免单条规则，不跳过全部");
        assert!(e.exempts("xss-script-tag"));
        assert!(!e.exempts("sqli-union-select"), "其他规则仍生效");
    }

    #[test]
    fn broader_exemption_wins() {
        // 一条豁免全部，一条只豁免 XSS → 结果是豁免全部
        let rules = vec![
            rule("w1", None, Some("/editor"), Some("xss-script-tag")),
            rule("w2", None, Some("/editor"), None),
        ];
        let e = compute(&rules, "nas", "/editor/x");
        assert!(e.skip_all);
        assert_eq!(e.matched.len(), 2);
    }

    #[test]
    fn multiple_rule_specific_exemptions_merge() {
        let rules = vec![
            rule("w1", None, None, Some("xss-script-tag")),
            rule("w2", None, None, Some("xss-javascript-uri")),
        ];
        let e = compute(&rules, "nas", "/");
        assert!(e.exempts("xss-script-tag"));
        assert!(e.exempts("xss-javascript-uri"));
        assert!(!e.exempts("sqli-union-select"));
    }

    #[test]
    fn empty_path_means_no_path_limit() {
        let rules = vec![rule("w1", None, Some(""), None)];
        assert!(compute(&rules, "nas", "/anything").skip_all);
    }

    #[test]
    fn matched_ids_recorded_for_logging() {
        let rules = vec![
            rule("a", None, Some("/x"), Some("r1")),
            rule("b", None, Some("/x/y"), None),
        ];
        let e = compute(&rules, "nas", "/x/y");
        assert_eq!(e.matched, vec!["a", "b"], "两条规则的路径前缀都匹配");
    }
}
