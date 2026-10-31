//! UA 启发式 BOT 评分。
//!
//! 只依据 User-Agent 做低成本判断，不引入指纹库、JA4 或机器学习。
//! 评分范围 0–100，按分档处置：
//! - 0 分：视为正常请求，不做任何处置
//! - 低于挑战阈值：只记录（识别到可疑特征，但不影响请求）
//! - 达到挑战阈值：人机验证（客户端无法执行 JS 时按拦截处理）
//! - 达到拦截阈值：直接拦截
//!
//! 已知搜索引擎爬虫单独放行：它们的 UA 同样带 `bot` / `spider` 字样，
//! 不先排除会被通用规则误伤。

/// 升级人机验证的分值。
pub const CHALLENGE_THRESHOLD: u32 = 40;
/// 直接拦截的分值。
pub const BLOCK_THRESHOLD: u32 = 70;

/// 一次 UA 评分的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BotAssessment {
    pub score: u32,
    /// 命中的特征名，写入事件与日志
    pub signals: Vec<&'static str>,
}

impl BotAssessment {
    pub fn is_clean(&self) -> bool {
        self.score == 0
    }

    /// 按分值给出处置；正常请求返回 `None`。
    pub fn action(&self) -> Option<BotAction> {
        if self.score >= BLOCK_THRESHOLD {
            Some(BotAction::Block)
        } else if self.score >= CHALLENGE_THRESHOLD {
            Some(BotAction::Challenge)
        } else if self.score > 0 {
            Some(BotAction::Log)
        } else {
            None
        }
    }

    /// 逗号分隔的特征名。
    pub fn signal_names(&self) -> String {
        self.signals.join(",")
    }

    /// 追加特征分值；同名特征只计一次，总分封顶 100。
    fn add(&mut self, signal: &'static str, score: u32) {
        if self.signals.contains(&signal) {
            return;
        }
        self.signals.push(signal);
        self.score = self.score.saturating_add(score).min(100);
    }
}

/// BOT 处置档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotAction {
    /// 只记录事件
    Log,
    /// 人机验证
    Challenge,
    /// 直接拦截
    Block,
}

/// 已知搜索引擎爬虫。命中即放行，不参与后续评分。
const SEARCH_ENGINES: &[&str] = &[
    "googlebot",
    "bingbot",
    "baiduspider",
    "slurp",
    "yandexbot",
    "duckduckbot",
    "applebot",
    "sogou web spider",
    "360spider",
    "bytespider",
    "petalbot",
];

/// 扫描器 / 漏洞利用工具的 UA 特征。
const SCANNERS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nuclei",
    "nmap",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "wpscan",
    "acunetix",
    "nessus",
    "openvas",
    "whatweb",
    "wapiti",
    "hydra",
    "fuzz",
];

/// 无头浏览器特征。
const HEADLESS: &[&str] = &[
    "headlesschrome",
    "headless",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "webdriver",
];

/// 常见脚本 / HTTP 客户端。很多是正常 API 调用，只记录不拦截。
const AUTOMATION_CLIENTS: &[&str] = &[
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "go-http-client",
    "java/",
    "okhttp",
    "libwww-perl",
    "axios/",
    "node-fetch",
    "undici",
    "reqwest",
    "scrapy",
    "ruby",
    "php/",
];

/// UA 中的通用爬虫关键字。
const GENERIC_BOT: &[&str] = &["bot", "spider", "crawler", "slurp"];

/// UA 长度上限，超过视为异常。
const MAX_UA_LEN: usize = 1_024;

/// 对 User-Agent 做启发式评分。
pub fn assess(ua: &str) -> BotAssessment {
    let mut out = BotAssessment::default();

    if ua.is_empty() {
        out.add("empty_ua", 25);
        return out;
    }

    if ua.len() > MAX_UA_LEN {
        out.add("ua_too_long", 20);
    }
    if ua.bytes().any(|b| b < 0x20 || b == 0x7f) {
        out.add("ua_control_chars", 40);
    }

    let lower = ua.to_ascii_lowercase();

    if SEARCH_ENGINES.iter().any(|m| lower.contains(m)) {
        return out;
    }

    if SCANNERS.iter().any(|m| lower.contains(m)) {
        out.add("scanner_ua", 80);
    }
    if HEADLESS.iter().any(|m| lower.contains(m)) {
        out.add("headless_ua", 55);
    }
    if AUTOMATION_CLIENTS.iter().any(|m| lower.contains(m)) {
        out.add("automation_ua", 35);
    }
    if GENERIC_BOT.iter().any(|m| lower.contains(m)) {
        out.add("generic_bot", 50);
    }

    if inconsistent(&lower) {
        out.add("ua_inconsistent", 40);
    }

    out
}

/// UA 内部自相矛盾：声明的浏览器/平台组合不可能同时出现。
fn inconsistent(lower: &str) -> bool {
    let has = |m: &str| lower.contains(m);

    // 浏览器 UA 必然以 Mozilla/5.0 开头；缺了它基本是伪造的。
    let claims_browser = ["chrome/", "firefox/", "safari/", "edg/", "opr/"]
        .iter()
        .any(|m| has(m));
    if claims_browser && !has("mozilla/") {
        return true;
    }

    // 同时声明两个互斥的内核。
    if has("chrome/") && has("firefox/") {
        return true;
    }

    // 移动端机型与桌面系统混在一起。
    let mobile = has("iphone") || has("ipad");
    if mobile && (has("windows") || has("android")) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    #[test]
    fn normal_browser_is_clean() {
        assert!(assess(CHROME).is_clean());
        assert_eq!(assess(CHROME).action(), None);
    }

    #[test]
    fn search_engine_crawler_is_clean() {
        let bot =
            assess("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert!(bot.is_clean(), "搜索引擎爬虫不应被误伤");
    }

    #[test]
    fn empty_ua_only_logs() {
        let bot = assess("");
        assert_eq!(bot.score, 25);
        assert_eq!(bot.action(), Some(BotAction::Log));
    }

    #[test]
    fn curl_only_logs() {
        let bot = assess("curl/8.0.1");
        assert_eq!(bot.signals, vec!["automation_ua"]);
        assert_eq!(bot.action(), Some(BotAction::Log));
    }

    #[test]
    fn headless_browser_requires_challenge() {
        let bot = assess(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
             (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
        );
        assert_eq!(bot.action(), Some(BotAction::Challenge));
    }

    #[test]
    fn scanner_is_blocked() {
        let bot = assess("sqlmap/1.7.2#stable (https://sqlmap.org)");
        assert_eq!(bot.signals, vec!["scanner_ua"]);
        assert_eq!(bot.action(), Some(BotAction::Block));
    }

    #[test]
    fn generic_crawler_requires_challenge() {
        let bot = assess("MyBot/1.0 (+http://example.com/bot)");
        assert!(bot.signals.contains(&"generic_bot"));
        assert_eq!(bot.action(), Some(BotAction::Challenge));
    }

    #[test]
    fn forged_safari_without_mozilla_is_inconsistent() {
        let bot = assess("Safari/605.1.15");
        assert!(bot.signals.contains(&"ua_inconsistent"));
        assert_eq!(bot.action(), Some(BotAction::Challenge));
    }

    #[test]
    fn combined_signals_cap_at_100_and_block() {
        let bot = assess("HeadlessChrome/120.0 sqlmap/1.7");
        assert_eq!(bot.score, 100);
        assert_eq!(bot.action(), Some(BotAction::Block));
    }

    #[test]
    fn duplicate_signals_count_once() {
        let bot = assess("headless headlesschrome webdriver");
        assert_eq!(bot.signals, vec!["headless_ua"]);
        assert_eq!(bot.score, 55);
    }
}
