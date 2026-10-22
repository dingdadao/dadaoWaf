//! 自动封禁。
//!
//! 检测命中累加分数，超过阈值就封禁来源 IP，封禁时长随重犯次数递增。
//!
//! 三个设计要点：
//! - **分数会衰减**：窗口内没再得分就清零，避免"一个月前踩过两次线"被永久盯上
//! - **封禁时长递增但有上限**：重犯加重，但封顶在配置的最后一项
//! - **IPv6 按前缀聚合**：隐私扩展会让同一设备不断换后缀，按 /128 封等于没封

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use homewaf_config::AutoBanConfig;

/// 分数衰减窗口：超过这个时间没再得分，累计分数清零。
const SCORE_WINDOW_SECS: u64 = 600;

/// 封禁过期后保留记录的时长，用于重犯时递增时长。
const RETENTION_SECS: u64 = 7 * 86_400;

/// 封禁状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanStatus {
    /// 剩余秒数
    pub remaining_secs: u64,
    /// 第几次被封
    pub offenses: u32,
}

/// 一次得分的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanOutcome {
    /// 本次是否触发了封禁
    pub banned: bool,
    /// 封禁截止时间（Unix 秒）
    pub until: u64,
    /// 本次封禁时长（秒），未封禁时为 0
    pub duration_secs: u64,
    /// 累计分数（封禁后清零）
    pub score: u32,
    /// 第几次被封
    pub offenses: u32,
}

#[derive(Debug, Default)]
struct Entry {
    score: u32,
    last_score_at: u64,
    until: u64,
    offenses: u32,
    /// 手动封禁：即使自动封禁关闭也必须生效
    manual: bool,
}

/// 可热更新的封禁参数。
///
/// 与条目分开存：改配置不应该清空已有的封禁记录，
/// 否则用户调一下阈值就把所有攻击者放了出来。
#[derive(Debug, Clone)]
struct Settings {
    enabled: bool,
    trigger_score: u32,
    /// 各档封禁时长（秒）
    durations: Vec<u64>,
    ipv6_prefix: u8,
}

impl Settings {
    fn from_config(config: &AutoBanConfig, ipv6_prefix: u8) -> Self {
        let mut durations: Vec<u64> = config.durations.iter().map(|d| d.0.as_secs()).collect();
        if durations.is_empty() {
            durations.push(300);
        }
        Self {
            enabled: config.enabled,
            trigger_score: config.trigger_score.max(1),
            durations,
            ipv6_prefix,
        }
    }
}

/// 自动封禁表。
pub struct BanTable {
    inner: RwLock<HashMap<IpAddr, Entry>>,
    settings: RwLock<Settings>,
}

impl BanTable {
    pub fn new(config: &AutoBanConfig, ipv6_prefix: u8) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            settings: RwLock::new(Settings::from_config(config, ipv6_prefix)),
        }
    }

    /// 热重载时更新参数，保留已有封禁记录。
    pub fn update_settings(&self, config: &AutoBanConfig, ipv6_prefix: u8) {
        if let Ok(mut s) = self.settings.write() {
            *s = Settings::from_config(config, ipv6_prefix);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.read().map(|s| s.enabled).unwrap_or(false)
    }

    fn settings_snapshot(&self) -> Option<Settings> {
        self.settings.read().ok().map(|s| s.clone())
    }

    /// 查询某 IP 是否处于封禁中。
    pub fn check(&self, ip: IpAddr, now: u64) -> Option<BanStatus> {
        let settings = self.settings_snapshot()?;
        let key = ban_key(ip, settings.ipv6_prefix);
        let map = self.inner.read().ok()?;
        let entry = map.get(&key)?;

        // 手动封禁不受 auto_ban.enabled 影响，否则关掉自动封禁时手动操作会失效
        if !settings.enabled && !entry.manual {
            return None;
        }

        if entry.until > now {
            Some(BanStatus {
                remaining_secs: entry.until - now,
                offenses: entry.offenses,
            })
        } else {
            None
        }
    }

    /// 记录一次检测得分。返回 `Some` 表示本次触发了封禁。
    ///
    /// 即使未触发封禁也会返回 `None`，分数已在内部累加。
    pub fn record(&self, ip: IpAddr, score: u32, now: u64) -> Option<BanOutcome> {
        let settings = self.settings_snapshot()?;
        if !settings.enabled || score == 0 {
            return None;
        }

        let key = ban_key(ip, settings.ipv6_prefix);
        let mut map = self.inner.write().ok()?;
        let entry = map.entry(key).or_default();

        // 分数衰减：窗口内没再得分，重新计
        if now.saturating_sub(entry.last_score_at) > SCORE_WINDOW_SECS {
            entry.score = 0;
        }
        entry.last_score_at = now;
        entry.score = entry.score.saturating_add(score);

        if entry.score < settings.trigger_score {
            return None;
        }

        // 触发封禁
        entry.offenses = entry.offenses.saturating_add(1);
        let duration = duration_for(&settings.durations, entry.offenses);
        entry.until = now.saturating_add(duration);
        entry.score = 0;

        Some(BanOutcome {
            banned: true,
            until: entry.until,
            duration_secs: duration,
            score: settings.trigger_score,
            offenses: entry.offenses,
        })
    }

    /// 从持久化恢复一条封禁。
    ///
    /// 启动时调用。只恢复尚未过期的记录，过期的直接丢弃。
    pub fn restore(&self, ip: IpAddr, until: u64, offenses: u32, now: u64) {
        if until <= now {
            return;
        }
        let Some(settings) = self.settings_snapshot() else {
            return;
        };
        let key = ban_key(ip, settings.ipv6_prefix);
        if let Ok(mut map) = self.inner.write() {
            let entry = map.entry(key).or_default();
            entry.until = until;
            entry.offenses = offenses;
        }
    }

    /// 手动封禁。不受自动封禁开关影响，重犯时长由调用方决定。
    pub fn manual_ban(&self, ip: IpAddr, until: u64, offenses: u32, now: u64) {
        if until <= now {
            return;
        }
        let Some(settings) = self.settings_snapshot() else {
            return;
        };
        let key = ban_key(ip, settings.ipv6_prefix);
        if let Ok(mut map) = self.inner.write() {
            let entry = map.entry(key).or_default();
            entry.until = until;
            entry.offenses = offenses;
            entry.manual = true;
        }
    }

    /// 手动解封。返回是否确实解除了一个封禁。
    pub fn unban(&self, ip: IpAddr) -> bool {
        let Some(settings) = self.settings_snapshot() else {
            return false;
        };
        let key = ban_key(ip, settings.ipv6_prefix);
        match self.inner.write() {
            Ok(mut map) => match map.get_mut(&key) {
                Some(entry) => {
                    let was_banned = entry.until > 0;
                    entry.until = 0;
                    was_banned
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// 清理长期无活动的记录，避免内存无限增长。
    ///
    /// 只删除"封禁已过期且分数已衰减"的条目；封禁中的条目必须保留。
    pub fn cleanup(&self, now: u64) -> usize {
        let Ok(mut map) = self.inner.write() else {
            return 0;
        };
        let before = map.len();
        map.retain(|_, e| {
            let ban_expired = e.until == 0 || e.until.saturating_add(RETENTION_SECS) < now;
            let score_stale = now.saturating_sub(e.last_score_at) > RETENTION_SECS;
            !(ban_expired && score_stale)
        });
        before - map.len()
    }

    /// 当前封禁中的 IP 数量。
    pub fn active_count(&self, now: u64) -> usize {
        match self.inner.read() {
            Ok(map) => map.values().filter(|e| e.until > now).count(),
            Err(_) => 0,
        }
    }

    /// 当前累计分数的 IP 数量（含未封禁的）。
    pub fn tracked_count(&self) -> usize {
        self.inner.read().map(|m| m.len()).unwrap_or(0)
    }
}

/// 按重犯次数选择封禁时长。超出列表长度时取最后一项。
fn duration_for(durations: &[u64], offenses: u32) -> u64 {
    if durations.is_empty() {
        return 300;
    }
    let idx = (offenses.saturating_sub(1) as usize).min(durations.len() - 1);
    durations[idx]
}

/// 把 IP 归一化为封禁键。IPv6 按配置前缀聚合。
fn ban_key(ip: IpAddr, ipv6_prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let len = ipv6_prefix.min(128);
            if len == 0 {
                return IpAddr::V6(v6);
            }
            let raw = u128::from(v6);
            let masked = raw & (!0u128 << (128 - len));
            IpAddr::V6(masked.into())
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::Duration as CfgDuration;

    fn config() -> AutoBanConfig {
        AutoBanConfig {
            enabled: true,
            trigger_score: 50,
            durations: vec![
                CfgDuration::from_secs(300),
                CfgDuration::from_secs(1_800),
                CfgDuration::from_secs(7_200),
            ],
        }
    }

    fn table() -> BanTable {
        BanTable::new(&config(), 64)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn below_threshold_does_not_ban() {
        let t = table();
        assert!(t.record(ip("203.0.113.9"), 25, NOW).is_none());
        assert!(t.check(ip("203.0.113.9"), NOW).is_none());
        assert_eq!(t.tracked_count(), 1);
    }

    #[test]
    fn reaching_threshold_bans() {
        let t = table();
        assert!(t.record(ip("203.0.113.9"), 25, NOW).is_none());
        let out = t.record(ip("203.0.113.9"), 25, NOW).expect("应触发封禁");

        assert!(out.banned);
        assert_eq!(out.duration_secs, 300, "首次封禁应为第一档时长");
        assert_eq!(out.offenses, 1);

        let status = t.check(ip("203.0.113.9"), NOW).unwrap();
        assert_eq!(status.remaining_secs, 300);
    }

    #[test]
    fn single_critical_hit_bans_immediately() {
        let t = table();
        // Critical 一条就是 80 分，超过阈值 50
        let out = t.record(ip("203.0.113.9"), 80, NOW).expect("单次高分应直接封禁");
        assert!(out.banned);
    }

    #[test]
    fn repeated_offense_escalates_duration() {
        let t = table();
        let addr = ip("203.0.113.9");

        let first = t.record(addr, 50, NOW).unwrap();
        assert_eq!(first.duration_secs, 300);

        // 解封后再犯
        t.unban(addr);
        let second = t.record(addr, 50, NOW + 400).unwrap();
        assert_eq!(second.offenses, 2);
        assert_eq!(second.duration_secs, 1_800);
    }

    #[test]
    fn duration_caps_at_last_entry() {
        let t = table();
        let addr = ip("203.0.113.9");

        for i in 0..10 {
            let out = t.record(addr, 50, NOW + i * 1000).unwrap();
            if i >= 2 {
                assert_eq!(out.duration_secs, 7_200, "超出列表应取最后一档");
            }
        }
    }

    #[test]
    fn ban_expires() {
        let t = table();
        let addr = ip("203.0.113.9");
        t.record(addr, 50, NOW).unwrap();

        assert!(t.check(addr, NOW + 299).is_some());
        assert!(t.check(addr, NOW + 301).is_none(), "过期后应解封");
    }

    #[test]
    fn score_decays_after_window() {
        let t = table();
        let addr = ip("203.0.113.9");

        t.record(addr, 25, NOW);
        // 超过窗口再得分，前面的分数应清零
        let out = t.record(addr, 25, NOW + SCORE_WINDOW_SECS + 1);
        assert!(out.is_none(), "分数应已衰减，25 分不足以封禁");
    }

    #[test]
    fn score_accumulates_within_window() {
        let t = table();
        let addr = ip("203.0.113.9");

        t.record(addr, 25, NOW);
        // 窗口内累加
        let out = t.record(addr, 25, NOW + 60);
        assert!(out.is_some(), "窗口内累计应触发封禁");
    }

    #[test]
    fn ipv6_aggregates_to_prefix() {
        let t = table();
        // 同一个 /64 下的两个不同地址
        let a = ip("2001:db8:1:2::1");
        let b = ip("2001:db8:1:2:ffff::9");

        t.record(a, 50, NOW).unwrap();
        assert!(
            t.check(b, NOW).is_some(),
            "同一 /64 内的其他地址也应被封"
        );

        // 不同 /64 不受影响
        let c = ip("2001:db8:1:3::1");
        assert!(t.check(c, NOW).is_none());
    }

    #[test]
    fn manual_unban_works() {
        let t = table();
        let addr = ip("203.0.113.9");
        t.record(addr, 50, NOW).unwrap();
        assert!(t.check(addr, NOW).is_some());

        assert!(t.unban(addr));
        assert!(t.check(addr, NOW).is_none());
        assert!(!t.unban(addr), "重复解封应返回 false");
    }

    #[test]
    fn disabled_table_never_bans() {
        let mut cfg = config();
        cfg.enabled = false;
        let t = BanTable::new(&cfg, 64);

        assert!(t.record(ip("203.0.113.9"), 100, NOW).is_none());
        assert!(t.check(ip("203.0.113.9"), NOW).is_none());
    }

    #[test]
    fn settings_update_keeps_existing_bans() {
        // 热重载只更新参数，不能把已有封禁清掉
        let t = table();
        let addr = ip("203.0.113.9");
        t.record(addr, 50, NOW).unwrap();
        assert!(t.check(addr, NOW).is_some());

        let mut new_cfg = config();
        new_cfg.trigger_score = 100;
        t.update_settings(&new_cfg, 64);

        assert!(
            t.check(addr, NOW).is_some(),
            "改配置不应解除已有封禁"
        );
    }

    #[test]
    fn settings_update_takes_effect() {
        let t = table();
        let addr = ip("203.0.113.9");

        // 把阈值调高后，50 分不再触发
        let mut new_cfg = config();
        new_cfg.trigger_score = 100;
        t.update_settings(&new_cfg, 64);

        assert!(t.record(addr, 50, NOW).is_none());
        assert!(t.record(addr, 60, NOW).is_some());
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let t = table();
        t.record(ip("203.0.113.9"), 25, NOW);
        assert_eq!(t.tracked_count(), 1);

        // 很久以后清理
        let removed = t.cleanup(NOW + RETENTION_SECS + 10);
        assert_eq!(removed, 1);
        assert_eq!(t.tracked_count(), 0);
    }

    #[test]
    fn cleanup_keeps_active_bans() {
        let t = table();
        let addr = ip("203.0.113.9");
        t.record(addr, 50, NOW).unwrap();

        // 封禁 300 秒，在封禁期内清理不应删除
        let removed = t.cleanup(NOW + 100);
        assert_eq!(removed, 0);
        assert!(t.check(addr, NOW + 100).is_some());
    }

    #[test]
    fn active_count_only_counts_banned() {
        let t = table();
        t.record(ip("203.0.113.1"), 50, NOW).unwrap();
        t.record(ip("203.0.113.2"), 10, NOW); // 未达阈值

        assert_eq!(t.active_count(NOW), 1);
        assert_eq!(t.tracked_count(), 2);
    }

    #[test]
    fn zero_score_is_ignored() {
        let t = table();
        assert!(t.record(ip("203.0.113.9"), 0, NOW).is_none());
        assert_eq!(t.tracked_count(), 0);
    }
}
