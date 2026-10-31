//! 风险标签与 IP 风险累积。
//!
//! 检测规则回答“这个请求像不像攻击”，风险标签回答“这个客户端可不可信”。
//! 两者分开算分：
//! - 规则分进入 [`homewaf_detect::Verdict`]，按拦截阈值决定是否 403；
//! - 风险分进入 [`RiskTable`]，决定“要不要升级人机验证”，
//!   只有 hard 标签才允许直接联动自动封禁。
//!
//! hard 标签是“服务端能证伪”的事实：指纹与信号不符、自报自动化、
//! 同一指纹跨多个 IP。软标签只是倾向性判断，单靠它封人会误伤共享出口。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;

use homewaf_config::ChallengeConfig;

/// 风险分窗口：与自动封禁保持一致，避免两套时间尺度互相打架。
pub const WINDOW_SECS: u64 = 600;
/// 同一指纹在窗口内出现多少个不同 IP 才判定为复用。
const REPLAY_IP_THRESHOLD: usize = 3;

/// 一个风险标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTag {
    /// 客户端自报 `navigator.webdriver` 或 CDP 注入物
    AutomationReported,
    /// 客户端指纹与服务端按信号重算的结果不一致
    FingerprintForged,
    /// 挑战回调缺少信号或指纹
    FingerprintMissing,
    /// 同一指纹短时间内出现在多个 IP
    FingerprintReplay,
    /// UA 带无头浏览器特征
    HeadlessUa,
    /// UA 与 UA-CH / Accept-Language 矛盾
    UaChMismatch,
    /// 单次挑战失败
    ChallengeFailed,
    /// CC 限流触发
    CcBurst,
    /// 滑块轨迹校验失败（本期只定义，不产生）
    SliderFailed,
}

impl RiskTag {
    /// 该标签的分值。
    pub fn weight(self) -> u32 {
        match self {
            Self::AutomationReported => 100,
            Self::FingerprintForged => 100,
            Self::FingerprintMissing => 60,
            Self::FingerprintReplay => 50,
            Self::HeadlessUa => 30,
            Self::UaChMismatch => 20,
            Self::ChallengeFailed => 15,
            Self::CcBurst => 10,
            Self::SliderFailed => 25,
        }
    }

    /// 是否属于“服务端可证伪”的硬标签。硬标签可直接联动封禁。
    pub fn hard(self) -> bool {
        matches!(
            self,
            Self::AutomationReported
                | Self::FingerprintForged
                | Self::FingerprintMissing
                | Self::FingerprintReplay
        )
    }

    /// 写进事件与日志的稳定名称。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AutomationReported => "automation_reported",
            Self::FingerprintForged => "fingerprint_forged",
            Self::FingerprintMissing => "fingerprint_missing",
            Self::FingerprintReplay => "fingerprint_replay",
            Self::HeadlessUa => "headless_ua",
            Self::UaChMismatch => "ua_ch_mismatch",
            Self::ChallengeFailed => "challenge_failed",
            Self::CcBurst => "cc_burst",
            Self::SliderFailed => "slider_failed",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "automation_reported" => Self::AutomationReported,
            "fingerprint_forged" => Self::FingerprintForged,
            "fingerprint_missing" => Self::FingerprintMissing,
            "fingerprint_replay" => Self::FingerprintReplay,
            "headless_ua" => Self::HeadlessUa,
            "ua_ch_mismatch" => Self::UaChMismatch,
            "challenge_failed" => Self::ChallengeFailed,
            "cc_burst" => Self::CcBurst,
            "slider_failed" => Self::SliderFailed,
            _ => return None,
        })
    }
}

/// 一次风险评估的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RiskAssessment {
    pub tags: Vec<RiskTag>,
    pub score: u32,
    pub hard: bool,
}

impl RiskAssessment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_tags(tags: impl IntoIterator<Item = RiskTag>) -> Self {
        let mut out = Self::new();
        for tag in tags {
            out.add(tag);
        }
        out
    }

    /// 追加标签：重复标签不重复计分，避免同一事实被放大。
    pub fn add(&mut self, tag: RiskTag) {
        if self.tags.contains(&tag) {
            return;
        }
        self.tags.push(tag);
        self.score = self.score.saturating_add(tag.weight());
        self.hard |= tag.hard();
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// 事件表 `rules` / `risk_tags` 列用的逗号分隔串。
    pub fn tag_names(&self) -> String {
        self.tags
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// 处置等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Normal,
    Challenge,
    Block,
}

/// 检测规则命中应当折算成多少风险分。
///
/// 取**总命中分**而不是 `blocking_score`：封禁分是 1:1 累积、50 分就封，
/// 拦截类规则的升级路径本来就很短；真正的缺口是 `Log` 类规则——
/// 它们 `blocking_score` 恒为 0、永远进不了封禁通道，反复触发也毫无后果。
/// 折算进风险表后，这类“可疑但不够格封”的信号才会升级成人机验证
/// （浏览器挑战页 / 非浏览器客户端按 `risk_api_ban_threshold` 封）。
///
/// 折算按 1/5 并封顶 20：高危（50）一次 10 分、严重（80）一次 16 分，
/// 单次命中不会把风险直接拉满，要重复触发才升级；
/// 多规则叠加的单次命中（如 210 分）也只算 20，避免一发入魂。
pub fn detect_weight(score: u32) -> u32 {
    (score / 5).min(20)
}

/// IP 维度的风险累计表。
///
/// 只存内存：风险分是行为信号，重启后重新观察即可；真正需要跨重启的
/// 封禁记录由 `BanTable` 落库，两者职责不重叠。
#[derive(Debug, Default)]
pub struct RiskTable {
    scores: Mutex<HashMap<IpAddr, (u32, u64)>>,
    /// 指纹 → (出现过的 IP, 最近时间)
    replay: Mutex<HashMap<String, (HashSet<IpAddr>, u64)>>,
}

impl RiskTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 用当前时间累加风险分，返回累计值。
    pub fn add(&self, ip: IpAddr, score: u32) -> u32 {
        self.add_at(ip, score, homewaf_acl::now_unix().max(0) as u64)
    }

    /// 累加点数（可注入时间，便于测试）。
    pub fn add_at(&self, ip: IpAddr, score: u32, now: u64) -> u32 {
        if score == 0 {
            return self.score_at(ip, now);
        }
        let mut map = self.scores.lock().expect("风险表锁不应中毒");
        let entry = map.entry(ip).or_insert((0, now));
        if now.saturating_sub(entry.1) > WINDOW_SECS {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(score);
        entry.1 = now;
        entry.0
    }

    /// 当前窗口内的风险分；过期的条目返回 0。
    pub fn score(&self, ip: IpAddr) -> u32 {
        self.score_at(ip, homewaf_acl::now_unix().max(0) as u64)
    }

    pub fn score_at(&self, ip: IpAddr, now: u64) -> u32 {
        let map = self.scores.lock().expect("风险表锁不应中毒");
        match map.get(&ip) {
            Some((score, ts)) if now.saturating_sub(*ts) <= WINDOW_SECS => *score,
            _ => 0,
        }
    }

    /// 按配置阈值给出处置等级。
    pub fn level(&self, ip: IpAddr) -> RiskLevel {
        self.level_at(
            ip,
            &ChallengeConfig::default(),
            homewaf_acl::now_unix().max(0) as u64,
        )
    }

    pub fn level_at(&self, ip: IpAddr, cfg: &ChallengeConfig, now: u64) -> RiskLevel {
        let (challenge, block) = thresholds(cfg);
        let score = self.score_at(ip, now);
        if score >= block {
            RiskLevel::Block
        } else if score >= challenge {
            RiskLevel::Challenge
        } else {
            RiskLevel::Normal
        }
    }

    /// 记录一次指纹出现。窗口内同一指纹出现在 >=3 个 IP 时返回 true。
    pub fn bump_replay(&self, fp: &str, ip: IpAddr, now: u64) -> bool {
        if fp.is_empty() {
            return false;
        }
        let mut map = self.replay.lock().expect("指纹复用表锁不应中毒");
        if map.len() > 8_192 {
            map.retain(|_, (_, ts)| now.saturating_sub(*ts) <= WINDOW_SECS);
        }
        let entry = map
            .entry(fp.to_string())
            .or_insert_with(|| (HashSet::new(), now));
        if now.saturating_sub(entry.1) > WINDOW_SECS {
            entry.0.clear();
        }
        entry.0.insert(ip);
        entry.1 = now;
        entry.0.len() >= REPLAY_IP_THRESHOLD
    }

    /// 清空某个 IP 的累计分（验证通过后调用，避免正常用户被历史分数拖累）。
    pub fn clear(&self, ip: IpAddr) {
        let mut map = self.scores.lock().expect("风险表锁不应中毒");
        map.remove(&ip);
    }
}

/// 阈值归一化：保证 block 严格大于 challenge，避免配置写反时永远只挑战不拦截。
fn thresholds(cfg: &ChallengeConfig) -> (u32, u32) {
    let challenge = cfg.risk_challenge_threshold.max(1);
    let block = cfg.risk_block_threshold.max(challenge.saturating_add(1));
    (challenge, block)
}

/// UA 里的无头浏览器特征。只做低成本判断，宁漏不误伤。
const HEADLESS_MARKERS: &[&str] = &[
    "headlesschrome",
    "phantomjs",
    "slimerjs",
    "puppeteer",
    "playwright",
    "selenium",
    "webdriver",
];

/// 从 UA 提取软标签。
pub fn assess_user_agent(ua: &str) -> RiskAssessment {
    let lower = ua.to_ascii_lowercase();
    let mut out = RiskAssessment::new();
    if HEADLESS_MARKERS.iter().any(|m| lower.contains(m)) {
        out.add(RiskTag::HeadlessUa);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg() -> ChallengeConfig {
        ChallengeConfig {
            difficulty: 4,
            ttl: homewaf_config::Duration::from_secs(1800),
            slider: false,
            risk_challenge_threshold: 30,
            risk_block_threshold: 60,
            risk_api_ban_threshold: 50,
        }
    }

    #[test]
    fn weights_and_hard_flags() {
        assert_eq!(RiskTag::FingerprintForged.weight(), 100);
        assert!(RiskTag::FingerprintForged.hard());
        assert!(!RiskTag::CcBurst.hard());
        assert_eq!(RiskTag::ChallengeFailed.weight(), 15);
    }

    #[test]
    fn assessment_dedupes_tags() {
        let a = RiskAssessment::from_tags([
            RiskTag::ChallengeFailed,
            RiskTag::ChallengeFailed,
            RiskTag::CcBurst,
        ]);
        assert_eq!(a.tags.len(), 2);
        assert_eq!(a.score, 25);
        assert!(!a.hard);
    }

    #[test]
    fn window_decays_after_600s() {
        let table = RiskTable::new();
        let addr = ip("203.0.113.9");
        table.add_at(addr, 40, 1_000);
        assert_eq!(table.score_at(addr, 1_100), 40);
        // 超过窗口再累加：旧分清零，只保留本次
        assert_eq!(table.add_at(addr, 20, 1_601), 20);
    }

    #[test]
    fn level_boundaries() {
        let table = RiskTable::new();
        let addr = ip("203.0.113.10");
        let cfg = cfg();
        table.add_at(addr, 29, 100);
        assert_eq!(table.level_at(addr, &cfg, 100), RiskLevel::Normal);
        table.add_at(addr, 1, 100);
        assert_eq!(table.level_at(addr, &cfg, 100), RiskLevel::Challenge);
        table.add_at(addr, 30, 100);
        assert_eq!(table.level_at(addr, &cfg, 100), RiskLevel::Block);
    }

    #[test]
    fn block_threshold_never_below_challenge() {
        let table = RiskTable::new();
        let addr = ip("203.0.113.11");
        let mut cfg = cfg();
        cfg.risk_challenge_threshold = 80;
        cfg.risk_block_threshold = 10;
        table.add_at(addr, 80, 100);
        // block 被抬到 81，80 分只能触发挑战
        assert_eq!(table.level_at(addr, &cfg, 100), RiskLevel::Challenge);
    }

    #[test]
    fn replay_detected_on_third_ip() {
        let table = RiskTable::new();
        assert!(!table.bump_replay("abcdef0123456789", ip("203.0.113.1"), 100));
        assert!(!table.bump_replay("abcdef0123456789", ip("203.0.113.2"), 100));
        assert!(table.bump_replay("abcdef0123456789", ip("203.0.113.3"), 100));
        // 换一个指纹不触发
        assert!(!table.bump_replay("ffffffffffffffff", ip("203.0.113.4"), 100));
    }

    #[test]
    fn clear_resets_ip() {
        let table = RiskTable::new();
        let addr = ip("203.0.113.12");
        table.add_at(addr, 50, 100);
        table.clear(addr);
        assert_eq!(table.score_at(addr, 100), 0);
    }

    #[test]
    fn headless_ua_detected() {
        assert_eq!(
            assess_user_agent("Mozilla/5.0 HeadlessChrome/120").score,
            30
        );
        assert!(assess_user_agent("Mozilla/5.0 (Macintosh) Chrome/120").is_empty());
    }

    #[test]
    fn detect_weight_scales_with_severity() {
        // 0 分不产生风险（未命中或纯白名单放行）
        assert_eq!(detect_weight(0), 0);
        // medium(25) → 5，high(50) → 10，critical(80) → 16
        assert_eq!(detect_weight(25), 5);
        assert_eq!(detect_weight(50), 10);
        assert_eq!(detect_weight(80), 16);
        // 多规则叠加封顶 20，单发不会直接把风险打满
        assert_eq!(detect_weight(210), 20);
        assert_eq!(detect_weight(10_000), 20);
    }

    #[test]
    fn detect_hits_escalate_to_challenge() {
        let table = RiskTable::new();
        let addr = ip("203.0.113.20");
        let cfg = cfg(); // challenge 30 / block 60
                         // 高危规则命中 2 次 = 20 分，还不够
        table.add_at(addr, detect_weight(50), 100);
        table.add_at(addr, detect_weight(50), 110);
        assert_eq!(table.level_at(addr, &cfg, 110), RiskLevel::Normal);
        // 第 3 次累计 30 分 → 升级人机验证
        table.add_at(addr, detect_weight(50), 120);
        assert_eq!(table.level_at(addr, &cfg, 120), RiskLevel::Challenge);
        // 再 3 次累计 60 分 → 封禁等级
        for t in [130, 140, 150] {
            table.add_at(addr, detect_weight(50), t);
        }
        assert_eq!(table.level_at(addr, &cfg, 150), RiskLevel::Block);
    }
}
