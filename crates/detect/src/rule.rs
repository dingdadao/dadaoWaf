//! 规则模型与内置规则集。
//!
//! 内置规则追求"高命中、低误报"：宁可漏一些变种，也不要把正常请求拦下来。
//! 用户在家用场景被误拦一次，就会把整个 WAF 关掉。

use serde::{Deserialize, Serialize};

/// 检测目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Path,
    Query,
    Body,
    Header,
    Cookie,
    UserAgent,
}

impl Target {
    pub fn as_str(&self) -> &'static str {
        match self {
            Target::Path => "path",
            Target::Query => "query",
            Target::Body => "body",
            Target::Header => "header",
            Target::Cookie => "cookie",
            Target::UserAgent => "user_agent",
        }
    }

    /// 解析规则包里的目标名，同时接受 snake_case 与紧凑写法。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "path" | "url" => Some(Target::Path),
            "query" | "args" => Some(Target::Query),
            "body" => Some(Target::Body),
            "header" | "headers" => Some(Target::Header),
            "cookie" | "cookies" => Some(Target::Cookie),
            "user_agent" | "useragent" | "ua" => Some(Target::UserAgent),
            _ => None,
        }
    }
}

/// 攻击分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Sqli,
    Xss,
    CmdInjection,
    PathTraversal,
    /// 服务端请求伪造
    Ssrf,
    /// XML 外部实体注入
    Xxe,
    /// 服务端模板注入
    Ssti,
    /// NoSQL 注入
    Nosql,
    /// LDAP / XPath 注入
    LdapXpath,
    /// Webshell 特征
    Webshell,
    Scanner,
    /// 反序列化
    Deserialization,
    /// 响应拆分 / 头注入
    Crlf,
    /// 恶意文件上传
    FileUpload,
    /// 暴力破解
    Bruteforce,
    /// 敏感信息泄露
    SensitiveLeak,
    Custom,
}

impl Category {
    pub const COUNT: usize = 17;

    /// 固定的分类顺序，用于按索引存放策略。
    pub const ALL: [Category; Self::COUNT] = [
        Category::Sqli,
        Category::Xss,
        Category::CmdInjection,
        Category::PathTraversal,
        Category::Ssrf,
        Category::Xxe,
        Category::Ssti,
        Category::Nosql,
        Category::LdapXpath,
        Category::Webshell,
        Category::Scanner,
        Category::Deserialization,
        Category::Crlf,
        Category::FileUpload,
        Category::Bruteforce,
        Category::SensitiveLeak,
        Category::Custom,
    ];

    pub fn index(self) -> usize {
        match self {
            Category::Sqli => 0,
            Category::Xss => 1,
            Category::CmdInjection => 2,
            Category::PathTraversal => 3,
            Category::Ssrf => 4,
            Category::Xxe => 5,
            Category::Ssti => 6,
            Category::Nosql => 7,
            Category::LdapXpath => 8,
            Category::Webshell => 9,
            Category::Scanner => 10,
            Category::Deserialization => 11,
            Category::Crlf => 12,
            Category::FileUpload => 13,
            Category::Bruteforce => 14,
            Category::SensitiveLeak => 15,
            Category::Custom => 16,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Sqli => "sqli",
            Category::Xss => "xss",
            Category::CmdInjection => "cmdi",
            Category::PathTraversal => "traversal",
            Category::Ssrf => "ssrf",
            Category::Xxe => "xxe",
            Category::Ssti => "ssti",
            Category::Nosql => "nosql",
            Category::LdapXpath => "ldap",
            Category::Webshell => "webshell",
            Category::Scanner => "scanner",
            Category::Deserialization => "deserialization",
            Category::Crlf => "crlf",
            Category::FileUpload => "file_upload",
            Category::Bruteforce => "bruteforce",
            Category::SensitiveLeak => "sensitive_leak",
            Category::Custom => "custom",
        }
    }

    /// 解析规则包里的分类名。兼容 `as_str` 与 serde 的紧凑写法。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sqli" | "sql" => Some(Category::Sqli),
            "xss" => Some(Category::Xss),
            "cmdi" | "cmdinjection" | "cmd_injection" | "command_injection" => {
                Some(Category::CmdInjection)
            }
            "traversal" | "pathtraversal" | "path_traversal" => Some(Category::PathTraversal),
            "ssrf" => Some(Category::Ssrf),
            "xxe" => Some(Category::Xxe),
            "ssti" => Some(Category::Ssti),
            "nosql" => Some(Category::Nosql),
            "ldap" | "ldapxpath" | "ldap_xpath" => Some(Category::LdapXpath),
            "webshell" | "web_shell" => Some(Category::Webshell),
            "scanner" => Some(Category::Scanner),
            "deserialization" | "deserialize" => Some(Category::Deserialization),
            "crlf" => Some(Category::Crlf),
            "file_upload" | "fileupload" => Some(Category::FileUpload),
            "bruteforce" | "brute_force" => Some(Category::Bruteforce),
            "sensitive_leak" | "sensitiveleak" | "leak" => Some(Category::SensitiveLeak),
            "custom" => Some(Category::Custom),
            _ => None,
        }
    }
}

/// 严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// 命中该级别时累加的分数。
    pub fn score(&self) -> u32 {
        match self {
            Severity::Low => 10,
            Severity::Medium => 25,
            Severity::High => 50,
            Severity::Critical => 80,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// 处置动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// 拦截
    Block,
    /// 只记录
    Log,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Log => "log",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "block" | "deny" | "drop" => Some(Action::Block),
            "log" | "monitor" | "observe" => Some(Action::Log),
            _ => None,
        }
    }
}

/// 一条检测规则。
///
/// 这是内置规则的静态定义。运行时使用的规则统一转成 [`RuleMeta`]，
/// 因为订阅规则包是运行时加载的，不能再依赖 `'static` 生命周期。
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// 正则，作用于归一化后的文本
    pub pattern: &'static str,
    pub targets: &'static [Target],
    /// 预过滤关键词（小写）。命中任一才跑正则。
    pub keywords: &'static [&'static str],
    pub action: Action,
}

/// 规则来源，用于日志与控制台展示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    Builtin,
    /// 规则包订阅名称
    Feed(String),
}

impl RuleSource {
    pub fn as_str(&self) -> &str {
        match self {
            RuleSource::Builtin => "builtin",
            RuleSource::Feed(name) => name,
        }
    }

    pub fn is_builtin(&self) -> bool {
        matches!(self, RuleSource::Builtin)
    }
}

/// 运行时规则。内置规则与订阅规则共用同一套结构与匹配路径。
#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern: String,
    pub targets: Vec<Target>,
    pub keywords: Vec<String>,
    pub action: Action,
    /// 影子期内的规则只记录、不计入拦截分。
    pub shadow: bool,
    pub source: RuleSource,
}

impl From<&Rule> for RuleMeta {
    fn from(rule: &Rule) -> Self {
        Self {
            id: rule.id.to_string(),
            name: rule.name.to_string(),
            category: rule.category,
            severity: rule.severity,
            pattern: rule.pattern.to_string(),
            targets: rule.targets.to_vec(),
            keywords: rule.keywords.iter().map(|k| k.to_string()).collect(),
            action: rule.action,
            shadow: false,
            source: RuleSource::Builtin,
        }
    }
}

/// 内置规则集。
///
/// 正则都写成有界形式，避免 ReDoS：`[\s\S]{0,20}` 比 `.*` 安全得多。
pub const BUILTIN_RULES: &[Rule] = &[
    // ==================== SQL 注入 ====================
    Rule {
        id: "sqli-union-select",
        name: "SQL 联合查询注入",
        category: Category::Sqli,
        severity: Severity::High,
        pattern: r"\bunion\b[\s\S]{0,30}\bselect\b",
        targets: &[Target::Query, Target::Body, Target::Cookie],
        keywords: &["union"],
        action: Action::Block,
    },
    Rule {
        id: "sqli-boolean-tautology",
        name: "SQL 布尔恒真",
        category: Category::Sqli,
        severity: Severity::High,
        pattern: r"\b(or|and)\b\s+\d+\s*=\s*\d+",
        targets: &[Target::Query, Target::Body],
        keywords: &["or", "and"],
        action: Action::Block,
    },
    Rule {
        id: "sqli-time-based",
        name: "SQL 时间盲注",
        category: Category::Sqli,
        severity: Severity::Critical,
        pattern: r"\b(sleep|benchmark|pg_sleep)\s*\(",
        targets: &[Target::Query, Target::Body],
        keywords: &["sleep", "benchmark"],
        action: Action::Block,
    },
    Rule {
        id: "sqli-metadata",
        name: "SQL 元数据探测",
        category: Category::Sqli,
        severity: Severity::High,
        pattern: r"\b(information_schema|sysobjects|pg_catalog)\b",
        targets: &[Target::Query, Target::Body],
        keywords: &["information_schema", "sysobjects", "pg_catalog"],
        action: Action::Block,
    },
    Rule {
        id: "sqli-file-access",
        name: "SQL 文件读写",
        category: Category::Sqli,
        severity: Severity::Critical,
        pattern: r"\b(load_file|into\s+outfile|into\s+dumpfile)\b",
        targets: &[Target::Query, Target::Body],
        keywords: &["load_file", "outfile", "dumpfile"],
        action: Action::Block,
    },
    Rule {
        id: "sqli-comment-terminator",
        name: "SQL 注释截断",
        category: Category::Sqli,
        severity: Severity::Medium,
        pattern: r"['\x22]\s*(--|#)",
        targets: &[Target::Query, Target::Body],
        keywords: &["--", "#"],
        action: Action::Block,
    },

    // ==================== XSS ====================
    Rule {
        id: "xss-script-tag",
        name: "XSS script 标签",
        category: Category::Xss,
        severity: Severity::High,
        pattern: r"<script",
        targets: &[Target::Query, Target::Body],
        keywords: &["<script"],
        action: Action::Block,
    },
    Rule {
        id: "xss-javascript-uri",
        name: "XSS javascript 伪协议",
        category: Category::Xss,
        severity: Severity::High,
        pattern: r"javascript\s*:",
        targets: &[Target::Query, Target::Body],
        keywords: &["javascript"],
        action: Action::Block,
    },
    Rule {
        id: "xss-event-handler",
        name: "XSS 事件处理器",
        category: Category::Xss,
        severity: Severity::High,
        pattern: r"\bon(error|load|click|mouseover|focus|submit)\s*=",
        targets: &[Target::Query, Target::Body],
        keywords: &["onerror", "onload", "onclick", "onmouseover"],
        action: Action::Block,
    },
    Rule {
        id: "xss-dangerous-tag",
        name: "XSS 危险标签",
        category: Category::Xss,
        severity: Severity::Medium,
        pattern: r"<(iframe|object|embed|svg)\b",
        targets: &[Target::Query, Target::Body],
        keywords: &["<iframe", "<object", "<embed", "<svg"],
        action: Action::Block,
    },

    // ==================== 命令注入 ====================
    Rule {
        id: "cmdi-shell-separator",
        name: "命令注入分隔符",
        category: Category::CmdInjection,
        severity: Severity::Critical,
        pattern: r"[;|&`]\s*(cat|ls|id|whoami|nc|wget|curl|bash|sh|python)\b",
        targets: &[Target::Query, Target::Body],
        keywords: &[";", "|", "&", "`"],
        action: Action::Block,
    },
    Rule {
        id: "cmdi-subshell",
        name: "命令替换",
        category: Category::CmdInjection,
        severity: Severity::Critical,
        pattern: r"\$\([^)]{1,100}\)",
        targets: &[Target::Query, Target::Body],
        keywords: &["$("],
        action: Action::Block,
    },

    // ==================== 路径穿越 ====================
    Rule {
        id: "traversal-dotdot",
        name: "路径穿越",
        category: Category::PathTraversal,
        severity: Severity::High,
        pattern: r"\.\.[/\\]",
        targets: &[Target::Path, Target::Query, Target::Body],
        keywords: &[".."],
        action: Action::Block,
    },
    Rule {
        id: "traversal-sensitive-file",
        name: "敏感文件读取",
        category: Category::PathTraversal,
        severity: Severity::Critical,
        pattern: r"(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|\.\./\.\./)",
        targets: &[Target::Path, Target::Query],
        keywords: &["passwd", "shadow", "win.ini", "boot.ini"],
        action: Action::Block,
    },

    // ==================== SSRF ====================
    Rule {
        id: "ssrf-cloud-metadata",
        name: "SSRF 云元数据",
        category: Category::Ssrf,
        severity: Severity::Critical,
        pattern: r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
        targets: &[Target::Query, Target::Body, Target::Path],
        keywords: &["169.254.169.254", "metadata.google", "100.100.100.200"],
        action: Action::Block,
    },
    Rule {
        id: "ssrf-loopback",
        name: "SSRF 回环地址",
        category: Category::Ssrf,
        severity: Severity::High,
        pattern: r"(://|^|[/=])(127\.0\.0\.1|localhost|0\.0\.0\.0)([:/]|$)",
        targets: &[Target::Query, Target::Body],
        keywords: &["127.0.0.1", "localhost", "0.0.0.0"],
        action: Action::Block,
    },
    Rule {
        id: "ssrf-private-network",
        name: "SSRF 内网地址",
        category: Category::Ssrf,
        severity: Severity::High,
        pattern: r"(:|//|=)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
        targets: &[Target::Query, Target::Body],
        keywords: &["10.", "192.168.", "172."],
        action: Action::Block,
    },
    Rule {
        id: "ssrf-file-scheme",
        name: "SSRF file 协议",
        category: Category::Ssrf,
        severity: Severity::Critical,
        pattern: r"file://",
        targets: &[Target::Query, Target::Body],
        keywords: &["file://"],
        action: Action::Block,
    },
    Rule {
        id: "ssrf-dangerous-scheme",
        name: "SSRF 危险协议",
        category: Category::Ssrf,
        severity: Severity::High,
        pattern: r"(gopher|dict|ldap|tftp)://",
        targets: &[Target::Query, Target::Body],
        keywords: &["gopher://", "dict://", "ldap://", "tftp://"],
        action: Action::Block,
    },
    Rule {
        id: "ssrf-internal-host",
        name: "SSRF 内网主机名",
        category: Category::Ssrf,
        severity: Severity::Medium,
        pattern: r"\.(internal|local)([:/]|$)",
        targets: &[Target::Query, Target::Body],
        keywords: &[".internal", ".local"],
        action: Action::Block,
    },

    // ==================== XXE ====================
    Rule {
        id: "xxe-doctype-system",
        name: "XXE DOCTYPE 外部实体",
        category: Category::Xxe,
        severity: Severity::Critical,
        pattern: r"<!doctype[^>]{0,200}system",
        targets: &[Target::Body, Target::Query],
        keywords: &["<!doctype"],
        action: Action::Block,
    },
    Rule {
        id: "xxe-entity-decl",
        name: "XXE 实体声明",
        category: Category::Xxe,
        severity: Severity::High,
        pattern: r"<!entity",
        targets: &[Target::Body, Target::Query],
        keywords: &["<!entity"],
        action: Action::Block,
    },
    Rule {
        id: "xxe-file-read",
        name: "XXE 本地文件读取",
        category: Category::Xxe,
        severity: Severity::Critical,
        pattern: r#"SYSTEM\s+["']file://"#,
        targets: &[Target::Body, Target::Query],
        keywords: &["file://"],
        action: Action::Block,
    },
    Rule {
        id: "xxe-php-filter",
        name: "XXE php://filter 包装器",
        category: Category::Xxe,
        severity: Severity::Critical,
        pattern: r"php://(filter|input|stdin)",
        targets: &[Target::Body, Target::Query, Target::Path],
        keywords: &["php://"],
        action: Action::Block,
    },

    // ==================== Webshell ====================
    Rule {
        id: "webshell-eval-superglobal",
        name: "Webshell 执行用户输入",
        category: Category::Webshell,
        severity: Severity::Critical,
        pattern: r"(eval|assert|system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(post|get|request|cookie|server)",
        targets: &[Target::Body, Target::Query],
        keywords: &["eval(", "assert(", "system(", "exec(", "shell_exec("],
        action: Action::Block,
    },
    Rule {
        id: "webshell-obfuscation",
        name: "Webshell 混淆解码",
        category: Category::Webshell,
        severity: Severity::High,
        pattern: r"(base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(",
        targets: &[Target::Body, Target::Query],
        keywords: &["base64_decode", "str_rot13", "gzinflate"],
        action: Action::Block,
    },
    Rule {
        id: "webshell-preg-e",
        name: "Webshell preg_replace /e 执行",
        category: Category::Webshell,
        severity: Severity::Critical,
        pattern: r"preg_replace\s*\([^)]{0,80}/[a-z]*e[a-z]*['\x22]",
        targets: &[Target::Body, Target::Query],
        keywords: &["preg_replace"],
        action: Action::Block,
    },
    Rule {
        id: "webshell-upload-filename",
        name: "Webshell 上传文件名",
        category: Category::Webshell,
        severity: Severity::High,
        pattern: r"\.(php[0-9]?|phtml|jspx?|asp[x]?|cgi|pl)(\?|$|[\x22'])",
        targets: &[Target::Path, Target::Body],
        keywords: &[".php", ".phtml", ".jsp", ".asp", ".cgi"],
        action: Action::Log,
    },

    // ==================== SSTI ====================
    Rule {
        id: "ssti-python-dunder",
        name: "SSTI Python 魔术方法",
        category: Category::Ssti,
        severity: Severity::Critical,
        pattern: r"\{\{[^}]{0,80}(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__)",
        targets: &[Target::Query, Target::Body],
        keywords: &["__class__", "__mro__", "__subclasses__", "__globals__", "__import__"],
        action: Action::Block,
    },
    Rule {
        id: "ssti-java-runtime",
        name: "SSTI Java 类加载",
        category: Category::Ssti,
        severity: Severity::Critical,
        pattern: r"(\$\{|<%|#\{)[^}%>]{0,80}(runtime|processbuilder|getruntime|class\.forname)",
        targets: &[Target::Query, Target::Body],
        keywords: &["runtime", "processbuilder", "class.forname"],
        action: Action::Block,
    },
    Rule {
        id: "ssti-freemarker-exec",
        name: "SSTI 模板执行函数",
        category: Category::Ssti,
        severity: Severity::High,
        pattern: r"\$\{[^}]{0,80}(exec|eval|new\s+\w+)\s*\(",
        targets: &[Target::Query, Target::Body],
        keywords: &["${"],
        action: Action::Block,
    },

    // ==================== NoSQL 注入 ====================
    Rule {
        id: "nosql-where",
        name: "NoSQL $where 执行",
        category: Category::Nosql,
        severity: Severity::Critical,
        pattern: r#"\$where\b"#,
        targets: &[Target::Query, Target::Body],
        keywords: &["$where"],
        action: Action::Block,
    },
    Rule {
        id: "nosql-operator-injection",
        name: "NoSQL 操作符注入",
        category: Category::Nosql,
        severity: Severity::High,
        pattern: r#"["']?\$(ne|gt|gte|lt|lte|regex|exists|in|nin|or|and|not|nor)["']?\s*:"#,
        targets: &[Target::Query, Target::Body],
        keywords: &["$ne", "$gt", "$regex", "$exists", "$nin"],
        action: Action::Block,
    },
    Rule {
        id: "nosql-function",
        name: "NoSQL 服务端函数",
        category: Category::Nosql,
        severity: Severity::Critical,
        pattern: r"\$(function|accumulator)\b",
        targets: &[Target::Query, Target::Body],
        keywords: &["$function", "$accumulator"],
        action: Action::Block,
    },

    // ==================== LDAP / XPath ====================
    Rule {
        id: "ldap-injection",
        name: "LDAP 注入",
        category: Category::LdapXpath,
        severity: Severity::High,
        pattern: r"\)\s*\(\s*\|?\s*\(",
        targets: &[Target::Query, Target::Body],
        keywords: &[")("],
        action: Action::Block,
    },
    Rule {
        id: "ldap-wildcard-injection",
        name: "LDAP 通配符注入",
        category: Category::LdapXpath,
        severity: Severity::Medium,
        pattern: r"\*\)\s*\(\s*\w+\s*=",
        targets: &[Target::Query, Target::Body],
        keywords: &["*)("],
        action: Action::Block,
    },
    Rule {
        id: "xpath-injection",
        name: "XPath 注入",
        category: Category::LdapXpath,
        severity: Severity::High,
        pattern: r"\]\s*\|{1,2}\s*/{1,2}\*",
        targets: &[Target::Query, Target::Body],
        keywords: &["]|//"],
        action: Action::Block,
    },

    // ==================== 文件包含 ====================
    Rule {
        id: "lfi-stream-wrapper",
        name: "文件包含流包装器",
        category: Category::PathTraversal,
        severity: Severity::Critical,
        pattern: r"(data|zip|phar|expect|compress\.zlib)://",
        targets: &[Target::Query, Target::Body, Target::Path],
        keywords: &["data://", "zip://", "phar://", "expect://"],
        action: Action::Block,
    },
    Rule {
        id: "lfi-sensitive-path",
        name: "文件包含敏感路径",
        category: Category::PathTraversal,
        severity: Severity::Critical,
        pattern: r"\.\.[/\\].{0,40}(etc/passwd|etc/shadow|proc/self|windows/win\.ini)",
        targets: &[Target::Query, Target::Body, Target::Path],
        keywords: &["etc/passwd", "proc/self", "win.ini"],
        action: Action::Block,
    },

    // ==================== 反序列化 ====================
    Rule {
        id: "deser-php-object",
        name: "PHP 对象反序列化",
        category: Category::Deserialization,
        severity: Severity::High,
        pattern: r#"o:\d{1,3}:"[a-z\\_]{1,80}":\d{1,3}:\{"#,
        targets: &[Target::Query, Target::Body],
        keywords: &["O:"],
        action: Action::Block,
    },

    // ==================== 扫描器 ====================
    Rule {
        id: "scanner-user-agent",
        name: "扫描器特征 UA",
        category: Category::Scanner,
        severity: Severity::Medium,
        pattern: r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster)",
        targets: &[Target::UserAgent],
        keywords: &["sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus"],
        action: Action::Log,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = BUILTIN_RULES.iter().map(|r| r.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "规则 id 必须唯一");
    }

    #[test]
    fn all_patterns_compile() {
        for rule in BUILTIN_RULES {
            assert!(
                regex::Regex::new(rule.pattern).is_ok(),
                "规则 {} 的正则非法: {}",
                rule.id,
                rule.pattern
            );
        }
    }

    #[test]
    fn severity_scores_are_ordered() {
        assert!(Severity::Low.score() < Severity::Medium.score());
        assert!(Severity::Medium.score() < Severity::High.score());
        assert!(Severity::High.score() < Severity::Critical.score());
    }

    #[test]
    fn every_rule_has_targets_and_keywords() {
        for rule in BUILTIN_RULES {
            assert!(!rule.targets.is_empty(), "规则 {} 缺少检测目标", rule.id);
            assert!(!rule.keywords.is_empty(), "规则 {} 缺少预过滤关键词", rule.id);
        }
    }
}
