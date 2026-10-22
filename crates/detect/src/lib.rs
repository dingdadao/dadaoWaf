//! HomeWAF 检测引擎。
//!
//! 三层：
//! 1. [`normalize`]：把各种编码变形折叠成可比较的形式
//! 2. [`rule`]：规则模型与内置规则集
//! 3. [`matcher`]：关键词预过滤 + 正则精判
//!
//! 上层只需要构造 [`InspectionInput`] 并调用 [`Engine::inspect`]。

pub mod body;
pub mod matcher;
pub mod normalize;
pub mod rule;
pub mod whitelist;

pub use body::{should_inspect_content_type, BodyBuffer, DEFAULT_MAX_INSPECT_BYTES};
pub use matcher::Matcher;
pub use normalize::{normalize, Normalized, MAX_DECODE_ROUNDS};
pub use rule::{Action, Category, Rule, Severity, Target, BUILTIN_RULES};
pub use whitelist::{Exemption, WhitelistRule};

/// 待检测的请求内容。
#[derive(Debug, Default, Clone)]
pub struct InspectionInput {
    pub path: String,
    pub query: Option<String>,
    pub body: Option<String>,
    pub user_agent: Option<String>,
    pub cookie: Option<String>,
    /// 需要检测的请求头。调用方应预先过滤掉无意义的头（如 `host`）
    pub headers: Vec<(String, String)>,
}

/// 单条命中。
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub target: Target,
    pub action: Action,
    /// 归一化后的命中片段，截断后用于日志
    pub evidence: String,
}

/// 检测结论。
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub findings: Vec<Finding>,
    /// 所有命中的分数总和（含 Log 类）
    pub score: u32,
    /// 仅 `Block` 类规则的分数，用于自动封禁判定。
    ///
    /// 用这个而不是总分：扫描器 UA 这类只该记录的特征，
    /// 不该因为重复访问就把用户封掉。
    pub blocking_score: u32,
    /// 是否应拦截。观察模式下恒为 false
    pub blocked: bool,
    /// 是否处于观察模式
    pub observe: bool,
}

impl Verdict {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// 命中的规则 id 列表，便于日志与测试断言。
    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.findings.iter().map(|f| f.rule_id).collect()
    }
}

/// 检测引擎。
pub struct Engine {
    matcher: Matcher,
    observe_mode: bool,
    /// 可拦截的分数达到该值才拦
    block_threshold: u32,
}

impl Engine {
    /// `observe_mode` 为 true 时只记录不拦截，用于上线前评估误报。
    pub fn new(observe_mode: bool, block_threshold: u32) -> Self {
        Self {
            matcher: Matcher::new(BUILTIN_RULES),
            observe_mode,
            block_threshold,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.matcher.len()
    }

    pub fn is_observe_mode(&self) -> bool {
        self.observe_mode
    }

    /// 检测一个请求（不做白名单豁免）。
    pub fn inspect(&self, input: &InspectionInput) -> Verdict {
        self.inspect_with(input, &Exemption::default())
    }

    /// 检测一个请求，按白名单豁免部分或全部规则。
    pub fn inspect_with(&self, input: &InspectionInput, exemption: &Exemption) -> Verdict {
        // 完全豁免：直接返回干净结果，连归一化都省了
        if exemption.skip_all {
            return Verdict {
                observe: self.observe_mode,
                ..Default::default()
            };
        }

        let mut findings = Vec::new();

        let targets: [(Target, Option<&str>); 5] = [
            (Target::Path, Some(input.path.as_str())),
            (Target::Query, input.query.as_deref()),
            (Target::Body, input.body.as_deref()),
            (Target::UserAgent, input.user_agent.as_deref()),
            (Target::Cookie, input.cookie.as_deref()),
        ];

        for (target, value) in targets {
            let Some(value) = value else { continue };
            self.scan_target(value, target, exemption, &mut findings);
        }

        for (_, value) in &input.headers {
            self.scan_target(value, Target::Header, exemption, &mut findings);
        }

        let score: u32 = findings.iter().map(|f| f.severity.score()).sum();
        // 只有 Block 类规则参与拦截判定，Log 类（如扫描器 UA）只记分数
        let blocking_score: u32 = findings
            .iter()
            .filter(|f| f.action == Action::Block)
            .map(|f| f.severity.score())
            .sum();

        Verdict {
            blocked: !self.observe_mode && blocking_score >= self.block_threshold,
            observe: self.observe_mode,
            score,
            blocking_score,
            findings,
        }
    }

    fn scan_target(
        &self,
        value: &str,
        target: Target,
        exemption: &Exemption,
        out: &mut Vec<Finding>,
    ) {
        if value.is_empty() {
            return;
        }

        let normalized = normalize(value);
        if normalized.canonical.is_empty() {
            return;
        }

        for idx in self.matcher.scan(&normalized.canonical) {
            let Some(rule) = self.matcher.rule(idx) else {
                continue;
            };
            // 规则可能只针对特定目标，关键词命中不代表适用
            if !rule.targets.contains(&target) {
                continue;
            }
            // 白名单豁免了这条规则
            if exemption.exempts(rule.id) {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id,
                rule_name: rule.name,
                category: rule.category,
                severity: rule.severity,
                target,
                action: rule.action,
                evidence: truncate(&normalized.canonical, 120),
            });
        }
    }
}

/// 按字符截断，避免切坏多字节字符。
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(false, 50)
    }

    fn query(q: &str) -> InspectionInput {
        InspectionInput {
            path: "/".to_string(),
            query: Some(q.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn clean_request_passes() {
        let v = engine().inspect(&InspectionInput {
            path: "/api/users".to_string(),
            query: Some("page=1&size=20".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            ..Default::default()
        });
        assert!(v.is_clean());
        assert!(!v.blocked);
        assert_eq!(v.score, 0);
    }

    #[test]
    fn blocks_union_select() {
        let v = engine().inspect(&query("id=1 union select 1,2,3"));
        assert!(v.blocked);
        assert!(v.rule_ids().contains(&"sqli-union-select"));
    }

    #[test]
    fn blocks_encoded_bypass() {
        // 双重编码的 ' or 1=1
        let v = engine().inspect(&query("%2527%2520or%25201%253D1"));
        assert!(v.blocked, "编码绕过应被识别: {:?}", v.rule_ids());
    }

    #[test]
    fn blocks_fullwidth_bypass() {
        let v = engine().inspect(&query("１　ＵＮＩＯＮ　ＳＥＬＥＣＴ　１"));
        assert!(v.blocked, "全角绕过应被识别: {:?}", v.rule_ids());
    }

    #[test]
    fn blocks_comment_obfuscation() {
        let v = engine().inspect(&query("1 union/**/select 1"));
        assert!(v.blocked, "注释绕过应被识别: {:?}", v.rule_ids());
    }

    #[test]
    fn blocks_xss() {
        let v = engine().inspect(&query("q=<script>alert(1)</script>"));
        assert!(v.blocked);
        assert!(v.rule_ids().contains(&"xss-script-tag"));
    }

    #[test]
    fn blocks_path_traversal() {
        let v = engine().inspect(&InspectionInput {
            path: "/files/../../etc/passwd".to_string(),
            ..Default::default()
        });
        assert!(v.blocked);
        assert!(v.rule_ids().contains(&"traversal-dotdot"));
    }

    #[test]
    fn scanner_ua_scores_but_does_not_block() {
        let v = engine().inspect(&InspectionInput {
            path: "/".to_string(),
            user_agent: Some("sqlmap/1.7".to_string()),
            ..Default::default()
        });
        assert!(!v.is_clean(), "应记录命中");
        assert!(v.score > 0);
        assert!(!v.blocked, "扫描器 UA 规则是 Log 级，不应直接拦截");
    }

    #[test]
    fn observe_mode_never_blocks() {
        let engine = Engine::new(true, 50);
        let v = engine.inspect(&query("id=1 union select 1"));
        assert!(!v.is_clean(), "观察模式仍要记录");
        assert!(!v.blocked, "观察模式不能拦截");
        assert!(v.observe);
    }

    #[test]
    fn threshold_controls_blocking() {
        // 阈值高于 High(50) 时，单条 High 命中不拦
        let engine = Engine::new(false, 60);
        let v = engine.inspect(&query("id=1 union select 1"));
        assert!(!v.blocked, "分数未达阈值不应拦截");
        assert!(v.score >= 50);
    }

    #[test]
    fn header_injection_detected() {
        let v = engine().inspect(&InspectionInput {
            path: "/".to_string(),
            headers: vec![("x-forwarded-for".to_string(), "1 union select 1".to_string())],
            ..Default::default()
        });
        // 该规则目标不含 header，不应误判
        assert!(v.is_clean(), "规则不覆盖 header 时不该命中: {:?}", v.rule_ids());
    }

    #[test]
    fn evidence_is_truncated() {
        let long = format!("{} union select 1", "a".repeat(500));
        let v = engine().inspect(&query(&long));
        assert!(v.blocked);
        assert!(v.findings[0].evidence.chars().count() <= 121);
    }

    // ============================================================
    // 白名单豁免
    // ============================================================

    #[test]
    fn whitelist_skip_all_passes_everything() {
        let e = Exemption {
            skip_all: true,
            ..Default::default()
        };
        let v = engine().inspect_with(&query("id=1 union select 1"), &e);
        assert!(v.is_clean(), "完全豁免后不应有命中");
        assert!(!v.blocked);
    }

    #[test]
    fn whitelist_exempts_single_rule() {
        let mut e = Exemption::default();
        e.rules.insert("sqli-union-select".to_string());

        let v = engine().inspect_with(&query("id=1 union select 1"), &e);
        assert!(v.is_clean(), "该规则被豁免，实际: {:?}", v.rule_ids());
    }

    #[test]
    fn whitelist_does_not_exempt_other_rules() {
        let mut e = Exemption::default();
        e.rules.insert("xss-script-tag".to_string());

        let v = engine().inspect_with(&query("id=1 union select 1"), &e);
        assert!(v.blocked, "未豁免的规则应继续生效");
        assert!(v.rule_ids().contains(&"sqli-union-select"));
    }

    #[test]
    fn whitelist_still_records_other_findings() {
        // 豁免 XSS，但同一请求里的 SQL 注入仍应被记录
        let mut e = Exemption::default();
        e.rules.insert("xss-script-tag".to_string());

        let v = engine().inspect_with(&query("<script>alert(1)</script> union select 1"), &e);
        assert!(v.rule_ids().contains(&"sqli-union-select"));
        assert!(!v.rule_ids().contains(&"xss-script-tag"));
    }
}
