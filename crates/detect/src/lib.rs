//! HomeWAF 检测引擎。
//!
//! 三层：
//! 1. [`normalize`]：把各种编码变形折叠成可比较的形式
//! 2. [`rule`]：规则模型与内置规则集
//! 3. [`matcher`]：关键词预过滤 + 正则精判
//!
//! 上层只需要构造 [`InspectionInput`] 并调用 [`Engine::inspect`]。

pub mod body;
pub mod feed;
pub mod matcher;
pub mod normalize;
pub mod rule;
pub mod whitelist;

use std::sync::Arc;

pub use body::{should_inspect_content_type, BodyBuffer, DEFAULT_MAX_INSPECT_BYTES};
pub use matcher::{Matcher, MatcherError};
pub use normalize::{normalize, Normalized, MAX_DECODE_ROUNDS};
pub use rule::{Action, Category, Rule, RuleMeta, RuleSource, Severity, Target, BUILTIN_RULES};
pub use whitelist::{Exemption, WhitelistRule};

/// 单个攻击分类的处置模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryMode {
    /// 关闭该分类的检测
    Off,
    /// 照常检测并记录，但不计入拦截分
    Monitor,
    /// 检测并按阈值拦截
    Block,
}

/// 检测策略：分类开关 + 观察模式 + 阻断阈值。
///
/// 按应用/路由解析后传给引擎。正则只编译一次，所有策略共享同一个
/// [`Matcher`]，策略差异不产生额外内存与启动成本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPolicy {
    modes: [CategoryMode; Category::COUNT],
    pub observe: bool,
    pub block_threshold: u32,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self::all_block(50)
    }
}

impl ScanPolicy {
    pub fn all_block(block_threshold: u32) -> Self {
        Self {
            modes: [CategoryMode::Block; Category::COUNT],
            observe: false,
            block_threshold,
        }
    }

    pub fn set(&mut self, category: Category, mode: CategoryMode) {
        self.modes[category.index()] = mode;
    }

    pub fn mode(&self, category: Category) -> CategoryMode {
        self.modes[category.index()]
    }

    /// 全部关闭，用于应用级"不检测"的快速路径。
    pub fn all_off(&self) -> bool {
        self.modes.iter().all(|m| *m == CategoryMode::Off)
    }
}

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
    pub rule_id: String,
    pub rule_name: String,
    pub category: Category,
    pub severity: Severity,
    pub target: Target,
    /// 实际处置。影子期内的订阅规则固定为 [`Action::Log`]。
    pub action: Action,
    /// 命中即拦（用户手写的检测黑名单）
    pub immediate: bool,
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
    pub fn rule_ids(&self) -> Vec<&str> {
        self.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }
}

/// 检测引擎。
#[derive(Clone)]
pub struct Engine {
    /// 规则只编译一次，所有应用/路由共享
    matcher: Arc<Matcher>,
    observe_mode: bool,
    /// 可拦截的分数达到该值才拦
    block_threshold: u32,
}

impl Engine {
    /// `observe_mode` 为 true 时只记录不拦截，用于上线前评估误报。
    pub fn new(observe_mode: bool, block_threshold: u32) -> Self {
        Self {
            matcher: Arc::new(Matcher::new(BUILTIN_RULES)),
            observe_mode,
            block_threshold,
        }
    }

    /// 用共享的规则匹配器构建，多个引擎实例之间不重复编译正则。
    pub fn with_matcher(matcher: Arc<Matcher>, observe_mode: bool, block_threshold: u32) -> Self {
        Self {
            matcher,
            observe_mode,
            block_threshold,
        }
    }

    /// 内置规则 + 订阅规则。规则包非法时返回错误，调用方应保留旧状态。
    pub fn with_extra_rules(
        extra: Vec<RuleMeta>,
        observe_mode: bool,
        block_threshold: u32,
    ) -> Result<Self, MatcherError> {
        let matcher = Matcher::with_extra(extra)?;
        Ok(Self::with_matcher(
            Arc::new(matcher),
            observe_mode,
            block_threshold,
        ))
    }

    pub fn matcher(&self) -> Arc<Matcher> {
        Arc::clone(&self.matcher)
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
        let policy = ScanPolicy {
            observe: self.observe_mode,
            block_threshold: self.block_threshold,
            ..ScanPolicy::default()
        };
        self.inspect_with_policy(input, exemption, &policy)
    }

    /// 用指定策略检测。策略决定分类开关、观察模式与阈值。
    pub fn inspect_with_policy(
        &self,
        input: &InspectionInput,
        exemption: &Exemption,
        policy: &ScanPolicy,
    ) -> Verdict {
        // 完全豁免：直接返回干净结果，连归一化都省了
        if exemption.skip_all || policy.all_off() {
            return Verdict {
                observe: policy.observe,
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
            self.scan_target(value, target, exemption, policy, &mut findings);
        }

        for (_, value) in &input.headers {
            self.scan_target(value, Target::Header, exemption, policy, &mut findings);
        }

        let score: u32 = findings.iter().map(|f| f.severity.score()).sum();
        // 只有 Block 类规则、且分类未被降级为 Monitor/Off 时才参与拦截判定
        let blocking_score: u32 = findings
            .iter()
            .filter(|f| f.action == Action::Block)
            .filter(|f| policy.mode(f.category) == CategoryMode::Block)
            .map(|f| f.severity.score())
            .sum();

        // 用户手写的检测黑名单命中即拦，不等分数累积
        let immediate = findings
            .iter()
            .any(|f| f.immediate && policy.mode(f.category) == CategoryMode::Block);

        Verdict {
            blocked: !policy.observe && (immediate || blocking_score >= policy.block_threshold),
            observe: policy.observe,
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
        policy: &ScanPolicy,
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
            // 关闭的分类连记录都不需要
            if policy.mode(rule.category) == CategoryMode::Off {
                continue;
            }
            // 规则可能只针对特定目标，关键词命中不代表适用
            if !rule.targets.contains(&target) {
                continue;
            }
            // 白名单豁免了这条规则
            if exemption.exempts(&rule.id) {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                category: rule.category,
                severity: rule.severity,
                target,
                // 影子期规则只记录：降级成 Log 后自然不计入 blocking_score
                action: if rule.shadow {
                    Action::Log
                } else {
                    rule.action
                },
                immediate: rule.immediate && !rule.shadow,
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
            headers: vec![(
                "x-forwarded-for".to_string(),
                "1 union select 1".to_string(),
            )],
            ..Default::default()
        });
        // 该规则目标不含 header，不应误判
        assert!(
            v.is_clean(),
            "规则不覆盖 header 时不该命中: {:?}",
            v.rule_ids()
        );
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

    // ============================================================
    // 应用级策略
    // ============================================================

    #[test]
    fn category_off_skips_rule_entirely() {
        let mut policy = ScanPolicy::default();
        policy.set(Category::Sqli, CategoryMode::Off);

        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(v.is_clean(), "关闭分类后不应记录: {:?}", v.rule_ids());
        assert!(!v.blocked);
    }

    #[test]
    fn category_monitor_records_but_never_blocks() {
        let mut policy = ScanPolicy::default();
        policy.set(Category::Sqli, CategoryMode::Monitor);

        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(!v.is_clean(), "监控模式仍要记录");
        assert!(v.score > 0);
        assert_eq!(v.blocking_score, 0, "监控模式不计入拦截分");
        assert!(!v.blocked);
    }

    #[test]
    fn category_off_does_not_affect_other_categories() {
        let mut policy = ScanPolicy::default();
        policy.set(Category::Xss, CategoryMode::Off);

        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(v.blocked, "关闭 XSS 不应影响 SQL 注入检测");
    }

    #[test]
    fn policy_observe_mode_beats_engine_setting() {
        let policy = ScanPolicy {
            observe: true,
            ..Default::default()
        };

        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(!v.blocked);
        assert!(v.observe);
    }

    #[test]
    fn policy_threshold_controls_blocking() {
        let mut policy = ScanPolicy::all_block(200);
        policy.observe = false;

        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(!v.blocked, "阈值 200 时单条 High 不拦");
    }

    #[test]
    fn all_off_policy_short_circuits() {
        let mut policy = ScanPolicy::default();
        for c in Category::ALL {
            policy.set(c, CategoryMode::Off);
        }
        assert!(policy.all_off());
        let v = engine().inspect_with_policy(
            &query("id=1 union select 1"),
            &Exemption::default(),
            &policy,
        );
        assert!(v.is_clean());
    }

    // ============================================================
    // 订阅规则与影子期
    // ============================================================

    fn feed_rule(shadow: bool) -> RuleMeta {
        RuleMeta {
            id: "feed-shadow-test".to_string(),
            name: "订阅测试规则".to_string(),
            category: Category::Custom,
            severity: Severity::Critical,
            pattern: r"shadow-marker".to_string(),
            targets: vec![Target::Query],
            keywords: vec!["shadow-marker".to_string()],
            action: Action::Block,
            immediate: false,
            shadow,
            source: RuleSource::Feed("test".to_string()),
        }
    }

    #[test]
    fn immediate_rule_blocks_below_threshold() {
        // 用户手写的黑名单：medium(25) 也要立刻拦，不能等凑到阈值 50
        let mut rule = feed_rule(false);
        rule.severity = Severity::Medium;
        rule.immediate = true;
        rule.action = Action::Block;
        let engine = Engine::with_extra_rules(vec![rule], false, 50).unwrap();

        let verdict = engine.inspect(&InspectionInput {
            path: "/".to_string(),
            query: Some("x=shadow-marker".to_string()),
            body: None,
            user_agent: None,
            cookie: None,
            headers: Vec::new(),
        });
        assert!(verdict.score < 50, "分数应低于阈值");
        assert!(verdict.blocked, "命中即拦，不应受阈值限制");
    }

    #[test]
    fn non_immediate_rule_still_needs_threshold() {
        let mut rule = feed_rule(false);
        rule.severity = Severity::Medium;
        rule.immediate = false;
        let engine = Engine::with_extra_rules(vec![rule], false, 50).unwrap();

        let verdict = engine.inspect(&InspectionInput {
            path: "/".to_string(),
            query: Some("x=shadow-marker".to_string()),
            body: None,
            user_agent: None,
            cookie: None,
            headers: Vec::new(),
        });
        assert!(!verdict.blocked, "内置/订阅规则仍走阈值");
    }

    #[test]
    fn shadow_feed_rule_logs_but_never_blocks() {
        let engine = Engine::with_extra_rules(vec![feed_rule(true)], false, 50).unwrap();
        let v = engine.inspect(&query("shadow-marker"));

        assert!(!v.is_clean(), "影子期规则仍然要记录");
        assert_eq!(v.findings[0].action, Action::Log);
        assert_eq!(v.score, Severity::Critical.score());
        assert_eq!(v.blocking_score, 0, "影子期不计入拦截分");
        assert!(!v.blocked);
        assert!(v.rule_ids().contains(&"feed-shadow-test"));
    }

    #[test]
    fn active_feed_rule_blocks_by_default() {
        let engine = Engine::with_extra_rules(vec![feed_rule(false)], false, 50).unwrap();
        let v = engine.inspect(&query("shadow-marker"));
        assert!(v.blocked);
        assert_eq!(v.blocking_score, Severity::Critical.score());
        assert_eq!(v.findings[0].action, Action::Block);
    }
}
