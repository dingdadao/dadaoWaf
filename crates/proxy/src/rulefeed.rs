//! 规则包订阅运行时。
//!
//! 处理链路：拉取 → 拆签名 → 验签 → 解析校验 → 版本/通道约束 →
//! 写入缓存 → 合并进检测引擎。任何一步失败都不能让服务失去现有防护：
//! 默认回滚到上一次验签通过的缓存。
//!
//! 影子期：新载荷第一次出现时，其规则在 `shadow_period` 内只记录不拦截。
//! 同样的载荷重复拉取不会重置影子期，否则检查间隔会让规则永远处于影子期。

use std::collections::HashSet;

use homewaf_config::{FeedChannel, RuleFeed};
use homewaf_detect::{feed, RuleMeta, BUILTIN_RULES};
use homewaf_store::{RuleFeedPackageRow, Store};

/// 数据库中保存订阅配置的设置键。
pub const RULE_FEEDS_SETTING: &str = "rule_feeds";

/// 规则包缓存。没有数据库时使用 [`NoRuleFeedCache`]，退化为每次重新拉取。
pub trait RuleFeedCache {
    fn load(&self, feed: &str) -> Option<RuleFeedPackageRow>;
    fn save(&self, pkg: &RuleFeedPackageRow);
}

/// 纯内存模式：无缓存，重启或失败时只能依赖远端。
pub struct NoRuleFeedCache;

impl RuleFeedCache for NoRuleFeedCache {
    fn load(&self, _feed: &str) -> Option<RuleFeedPackageRow> {
        None
    }

    fn save(&self, _pkg: &RuleFeedPackageRow) {}
}

/// SQLite 缓存实现。
pub struct StoreRuleFeedCache<'a> {
    store: &'a Store,
}

impl<'a> StoreRuleFeedCache<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }
}

impl RuleFeedCache for StoreRuleFeedCache<'_> {
    fn load(&self, feed: &str) -> Option<RuleFeedPackageRow> {
        match self.store.load_rule_feed_package(feed) {
            Ok(pkg) => pkg,
            Err(e) => {
                tracing::warn!(error = %e, feed, "读取规则包缓存失败，按无缓存处理");
                None
            }
        }
    }

    fn save(&self, pkg: &RuleFeedPackageRow) {
        if let Err(e) = self.store.save_rule_feed_package(pkg) {
            tracing::warn!(error = %e, feed = %pkg.feed, "保存规则包缓存失败");
        }
    }
}

/// 拉取接口。生产环境走 HTTPS，测试里可以注入固定内容。
pub trait RuleFeedFetcher {
    fn fetch(&self, feed: &RuleFeed) -> Result<String, String>;
}

pub struct HttpRuleFeedFetcher;

impl RuleFeedFetcher for HttpRuleFeedFetcher {
    fn fetch(&self, feed: &RuleFeed) -> Result<String, String> {
        homewaf_acl::fetch_feed(
            &feed.url,
            feed.timeout.0,
            feed.max_size.as_bytes() as usize,
            &feed.headers,
        )
        .map_err(|e| format!("拉取失败：{e}"))
    }
}

/// 单个订阅的加载状态，直接暴露给控制台。
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleFeedStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub auto_update: bool,
    pub channel: String,
    pub version: Option<String>,
    pub rule_count: usize,
    pub shadow_until: Option<i64>,
    /// `remote` / `cache` / `none` / `disabled`
    pub source: String,
    pub signature_ok: bool,
    pub fetched_at: Option<i64>,
    pub next_check_at: Option<i64>,
    pub error: Option<String>,
}

/// 加载结果。
pub struct RuleFeedLoad {
    pub rules: Vec<RuleMeta>,
    pub statuses: Vec<RuleFeedStatus>,
}

/// 加载全部订阅。
///
/// `force` 为 true 时忽略检查间隔与更新窗口（手动刷新、文件模式热重载）。
pub fn load_rule_feeds(
    feeds: &[RuleFeed],
    cache: &dyn RuleFeedCache,
    fetcher: &dyn RuleFeedFetcher,
    force: bool,
    now: i64,
) -> RuleFeedLoad {
    let mut rules = Vec::new();
    let mut statuses = Vec::new();
    let mut used_ids: HashSet<String> =
        BUILTIN_RULES.iter().map(|r| r.id.to_string()).collect();

    for feed in feeds {
        let cached = cache.load(&feed.name);
        let channel = channel_str(feed.channel);

        if !feed.enabled {
            statuses.push(RuleFeedStatus {
                name: feed.name.clone(),
                url: feed.url.clone(),
                enabled: false,
                auto_update: feed.auto_update,
                channel,
                version: cached.as_ref().and_then(|c| c.version.clone()),
                rule_count: cached.as_ref().map(|c| c.rule_count).unwrap_or(0),
                shadow_until: None,
                source: "disabled".to_string(),
                signature_ok: cached.as_ref().map(|c| c.signature_ok).unwrap_or(false),
                fetched_at: cached.as_ref().map(|c| c.fetched_at),
                next_check_at: None,
                error: None,
            });
            continue;
        }

        let next_check_at = cached.as_ref().map(|c| {
            c.fetched_at
                .saturating_add(feed.check_interval.as_secs() as i64)
        });
        let due = force
            || cached.is_none()
            || (feed.auto_update
                && next_check_at.map(|t| now >= t).unwrap_or(true)
                && within_update_window(now, feed.update_window.as_deref()));

        let mut error: Option<String> = None;
        let mut fetched: Option<FetchedPackage> = None;

        if due {
            match fetch_package(feed, fetcher) {
                Ok(pkg) => match check_release(feed, &pkg.parsed) {
                    Ok(()) => fetched = Some(pkg),
                    Err(e) => error = Some(e),
                },
                Err(e) => error = Some(e),
            }
        }

        let (active, source) = if let Some(pkg) = fetched {
            let shadow_until = if feed.shadow_period.map(|d| d.as_secs() > 0).unwrap_or(false) {
                match &cached {
                    // 同一份载荷重复拉取：保留原影子期，避免永远处于影子期
                    Some(old) if old.payload == pkg.payload => old.shadow_until,
                    _ => now.saturating_add(feed.shadow_period.unwrap().as_secs() as i64),
                }
            } else {
                0
            };

            let row = RuleFeedPackageRow {
                feed: feed.name.clone(),
                payload: pkg.payload,
                version: pkg.parsed.version.clone(),
                fetched_at: now,
                shadow_until,
                signature_ok: pkg.signature_ok,
                rule_count: pkg.parsed.rules.len(),
            };
            cache.save(&row);
            (Some((pkg.parsed.rules, row)), "remote")
        } else if error.is_none() {
            // 未到期：直接使用缓存
            match cached.as_ref().map(|c| parse_cached(feed, c)) {
                Some(Ok((rules, pkg))) => (Some((rules, pkg)), "cache"),
                Some(Err(e)) => {
                    error = Some(e);
                    (None, "none")
                }
                None => (None, "none"),
            }
        } else if feed.rollback_on_error {
            match cached.as_ref().map(|c| parse_cached(feed, c)) {
                Some(Ok((rules, pkg))) => {
                    error = Some(format!(
                        "{}；已回退到上次成功版本",
                        error.unwrap_or_default()
                    ));
                    (Some((rules, pkg)), "cache")
                }
                Some(Err(e)) => {
                    error = Some(format!(
                        "{}；缓存也无法使用：{e}",
                        error.unwrap_or_default()
                    ));
                    (None, "none")
                }
                None => (None, "none"),
            }
        } else {
            (None, "none")
        };

        let (mut feed_rules, pkg) = match active {
            Some((mut rules, pkg)) => {
                let shadow = pkg.shadow_until > now;
                for rule in &mut rules {
                    rule.shadow = shadow;
                }
                (rules, Some(pkg))
            }
            None => (Vec::new(), None),
        };

        // 跨订阅去重：整包接受或整包拒绝，避免只加载半个规则包
        let mut collision = None;
        for rule in &feed_rules {
            if used_ids.contains(&rule.id) {
                collision = Some(rule.id.clone());
                break;
            }
        }
        if let Some(id) = collision {
            error = Some(format!("规则 id `{id}` 与已启用的规则冲突，整包已跳过"));
            feed_rules.clear();
        } else {
            used_ids.extend(feed_rules.iter().map(|r| r.id.clone()));
        }

        if let Some(pkg) = &pkg {
            statuses.push(RuleFeedStatus {
                name: feed.name.clone(),
                url: feed.url.clone(),
                enabled: true,
                auto_update: feed.auto_update,
                channel,
                version: pkg.version.clone(),
                rule_count: feed_rules.len(),
                shadow_until: (pkg.shadow_until > now).then_some(pkg.shadow_until),
                source: source.to_string(),
                signature_ok: pkg.signature_ok,
                fetched_at: Some(pkg.fetched_at),
                next_check_at: Some(
                    pkg.fetched_at
                        .saturating_add(feed.check_interval.as_secs() as i64),
                ),
                error,
            });
        } else {
            statuses.push(RuleFeedStatus {
                name: feed.name.clone(),
                url: feed.url.clone(),
                enabled: true,
                auto_update: feed.auto_update,
                channel,
                version: cached.as_ref().and_then(|c| c.version.clone()),
                rule_count: 0,
                shadow_until: None,
                source: "none".to_string(),
                signature_ok: cached.as_ref().map(|c| c.signature_ok).unwrap_or(false),
                fetched_at: cached.as_ref().map(|c| c.fetched_at),
                next_check_at: Some(
                    cached
                        .as_ref()
                        .map(|c| c.fetched_at)
                        .unwrap_or(now)
                        .saturating_add(feed.check_interval.as_secs() as i64),
                ),
                error,
            });
        }

        rules.extend(feed_rules);
    }

    RuleFeedLoad { rules, statuses }
}

/// 是否有启用的订阅到了检查时间。调度器用它避免无意义的重载。
pub fn rule_feeds_due(feeds: &[RuleFeed], cache: &dyn RuleFeedCache, now: i64) -> bool {
    feeds.iter().filter(|f| f.enabled && f.auto_update).any(|f| {
        let Some(cached) = cache.load(&f.name) else {
            return true;
        };
        let next = cached
            .fetched_at
            .saturating_add(f.check_interval.as_secs() as i64);
        now >= next && within_update_window(now, f.update_window.as_deref())
    })
}

/// 从数据库读取订阅配置。
pub fn load_rule_feed_configs(store: &Store) -> Result<Vec<RuleFeed>, String> {
    store
        .get_setting::<Vec<RuleFeed>>(RULE_FEEDS_SETTING)
        .map_err(|e| format!("读取规则订阅配置失败：{e}"))
        .map(|v| v.unwrap_or_default())
}

struct FetchedPackage {
    parsed: feed::ParsedRuleFeed,
    payload: String,
    signature_ok: bool,
}

fn fetch_package(
    feed: &RuleFeed,
    fetcher: &dyn RuleFeedFetcher,
) -> Result<FetchedPackage, String> {
    let raw = fetcher.fetch(feed)?;
    let (signature, payload) = feed::split_signature(&raw).map_err(|e| e.to_string())?;

    let signature_ok = match (&signature, &feed.public_key) {
        (Some(sig), Some(key)) => {
            feed::verify_signature(key, payload.as_bytes(), sig).map_err(|e| e.to_string())?;
            true
        }
        (Some(_), None) if feed.require_signature => {
            return Err("订阅要求验签，但未配置公钥".to_string())
        }
        (None, _) if feed.require_signature => {
            return Err(feed::RuleFeedError::MissingSignature.to_string())
        }
        // 有签名但没配公钥：签名无法验证，按未签名处理
        _ => false,
    };

    let parsed = feed::parse_rules(payload, &feed.name).map_err(|e| e.to_string())?;
    Ok(FetchedPackage {
        parsed,
        payload: payload.to_string(),
        signature_ok,
    })
}

fn parse_cached(
    feed: &RuleFeed,
    pkg: &RuleFeedPackageRow,
) -> Result<(Vec<RuleMeta>, RuleFeedPackageRow), String> {
    let parsed = feed::parse_rules(&pkg.payload, &feed.name).map_err(|e| e.to_string())?;
    Ok((parsed.rules, pkg.clone()))
}

fn check_release(feed: &RuleFeed, parsed: &feed::ParsedRuleFeed) -> Result<(), String> {
    if feed.channel == FeedChannel::Pinned {
        if parsed.version.as_deref() != feed.pinned_version.as_deref() {
            return Err(format!(
                "版本不匹配：订阅固定为 `{}`，远端为 `{}`",
                feed.pinned_version.as_deref().unwrap_or(""),
                parsed.version.as_deref().unwrap_or("未声明")
            ));
        }
        return Ok(());
    }

    match parsed.channel.as_deref() {
        Some("stable") => Ok(()),
        Some("beta") if feed.channel == FeedChannel::Beta => Ok(()),
        Some("beta") => Err("远端是 beta 通道，稳定通道订阅不会自动升级".to_string()),
        Some(other) if !other.is_empty() => {
            Err(format!("远端声明了未知通道 `{other}`"))
        }
        _ => Ok(()),
    }
}

/// 更新窗口按 UTC 计算。支持跨午夜，如 `23:00-01:00`。
pub fn within_update_window(now: i64, window: Option<&str>) -> bool {
    let Some(window) = window else {
        return true;
    };
    let Some((start, end)) = window.split_once('-') else {
        return true;
    };
    let (Some((sh, sm)), Some((eh, em))) = (parse_hhmm(start), parse_hhmm(end)) else {
        return true;
    };

    let minute = (now.rem_euclid(86_400) / 60) as u32;
    let start = sh * 60 + sm;
    let end = eh * 60 + em;
    if start == end {
        true
    } else if start < end {
        minute >= start && minute < end
    } else {
        minute >= start || minute < end
    }
}

fn parse_hhmm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    (h < 24 && m < 60).then_some((h, m))
}

fn channel_str(channel: FeedChannel) -> String {
    match channel {
        FeedChannel::Stable => "stable",
        FeedChannel::Beta => "beta",
        FeedChannel::Pinned => "pinned",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::units::{Duration, Size};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const NOW: i64 = 1_700_000_000;

    fn feed(name: &str) -> RuleFeed {
        RuleFeed {
            name: name.to_string(),
            url: format!("https://example.com/{name}.hwrule"),
            enabled: true,
            channel: FeedChannel::Stable,
            auto_update: true,
            check_interval: Duration::from_secs(3_600),
            update_window: None,
            timeout: Duration::from_secs(20),
            max_size: Size::from_bytes(4 * 1024 * 1024),
            headers: BTreeMap::new(),
            require_signature: true,
            public_key: None,
            shadow_period: None,
            rollback_on_error: true,
            pinned_version: None,
        }
    }

    fn doc(version: &str, rule_id: &str) -> String {
        format!(
            r#"{{
                "format": "homewaf-rules",
                "version": "{version}",
                "rules": [{{
                    "id": "{rule_id}",
                    "name": "测试规则",
                    "category": "custom",
                    "severity": "high",
                    "pattern": "marker-{rule_id}",
                    "targets": ["query"],
                    "keywords": ["marker-"]
                }}]
            }}"#
        )
    }

    struct Fetcher {
        body: Mutex<Result<String, String>>,
        calls: Mutex<usize>,
    }

    impl Fetcher {
        fn ok(body: String) -> Self {
            Self {
                body: Mutex::new(Ok(body)),
                calls: Mutex::new(0),
            }
        }

        fn fail(msg: &str) -> Self {
            Self {
                body: Mutex::new(Err(msg.to_string())),
                calls: Mutex::new(0),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl RuleFeedFetcher for Fetcher {
        fn fetch(&self, _feed: &RuleFeed) -> Result<String, String> {
            *self.calls.lock().unwrap() += 1;
            self.body.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct MemCache {
        pkg: Mutex<Option<RuleFeedPackageRow>>,
    }

    impl RuleFeedCache for MemCache {
        fn load(&self, _feed: &str) -> Option<RuleFeedPackageRow> {
            self.pkg.lock().unwrap().clone()
        }

        fn save(&self, pkg: &RuleFeedPackageRow) {
            *self.pkg.lock().unwrap() = Some(pkg.clone());
        }
    }

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn signed(key: &Ed25519KeyPair, payload: &str) -> String {
        let sig = key.sign(payload.as_bytes());
        format!(
            "{} ed25519:{}\n{}",
            feed::SIGNATURE_PREFIX,
            feed::encode_base64(sig.as_ref()),
            payload
        )
    }

    fn public_key(key: &Ed25519KeyPair) -> String {
        format!("ed25519:{}", feed::encode_base64(key.public_key().as_ref()))
    }

    fn signed_feed(name: &str, version: &str, rule_id: &str) -> (RuleFeed, String, Ed25519KeyPair) {
        let key = keypair();
        let mut f = feed(name);
        f.public_key = Some(public_key(&key));
        let body = signed(&key, &doc(version, rule_id));
        (f, body, key)
    }

    #[test]
    fn loads_signed_feed_and_caches_it() {
        let (f, body, _) = signed_feed("official", "1.0", "rule-a");
        let cache = MemCache::default();
        let fetcher = Fetcher::ok(body);

        let loaded = load_rule_feeds(&[f], &cache, &fetcher, true, NOW);
        assert_eq!(fetcher.calls(), 1);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].id, "rule-a");
        assert!(!loaded.rules[0].shadow);
        let status = &loaded.statuses[0];
        assert_eq!(status.source, "remote");
        assert!(status.signature_ok);
        assert_eq!(status.version.as_deref(), Some("1.0"));
        assert!(status.error.is_none());

        let cached = cache.pkg.lock().unwrap().clone().unwrap();
        assert_eq!(cached.rule_count, 1);
        assert!(cached.signature_ok);
    }

    #[test]
    fn unsigned_feed_rejected_when_signature_required() {
        let mut f = feed("official");
        f.public_key = Some("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        let cache = MemCache::default();
        let fetcher = Fetcher::ok(doc("1.0", "rule-a"));

        let loaded = load_rule_feeds(&[f], &cache, &fetcher, true, NOW);
        assert!(loaded.rules.is_empty());
        assert_eq!(loaded.statuses[0].source, "none");
        assert!(loaded
            .statuses[0]
            .error
            .as_deref()
            .unwrap()
            .contains("缺少签名"));
    }

    #[test]
    fn bad_signature_rejected() {
        let (f, body, _) = signed_feed("official", "1.0", "rule-a");
        let tampered = body.replace("marker-rule-a", "marker-rule-b");
        let cache = MemCache::default();
        let fetcher = Fetcher::ok(tampered);

        let loaded = load_rule_feeds(&[f], &cache, &fetcher, true, NOW);
        assert!(loaded.rules.is_empty());
        assert!(loaded.statuses[0]
            .error
            .as_deref()
            .unwrap()
            .contains("签名校验失败"));
    }

    #[test]
    fn fetch_failure_rolls_back_to_cache() {
        let (f, body, _) = signed_feed("official", "1.0", "rule-a");
        let cache = MemCache::default();
        load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);

        let loaded = load_rule_feeds(&[f], &cache, &Fetcher::fail("timeout"), true, NOW + 60);
        assert_eq!(loaded.rules.len(), 1, "应回退到缓存规则");
        assert_eq!(loaded.statuses[0].source, "cache");
        assert!(loaded.statuses[0]
            .error
            .as_deref()
            .unwrap()
            .contains("timeout"));
    }

    #[test]
    fn rollback_disabled_drops_rules_on_failure() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        let cache = MemCache::default();
        load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);

        f.rollback_on_error = false;
        let loaded = load_rule_feeds(&[f], &cache, &Fetcher::fail("timeout"), true, NOW + 60);
        assert!(loaded.rules.is_empty());
        assert_eq!(loaded.statuses[0].source, "none");
    }

    #[test]
    fn check_interval_skips_fetch() {
        let (f, body, _) = signed_feed("official", "1.0", "rule-a");
        let cache = MemCache::default();
        load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);

        let fetcher = Fetcher::fail("should not be called");
        let loaded = load_rule_feeds(&[f], &cache, &fetcher, false, NOW + 60);
        assert_eq!(fetcher.calls(), 0);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.statuses[0].source, "cache");
    }

    #[test]
    fn update_window_blocks_refresh() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        // 2023-11-14 22:13:20 UTC
        f.update_window = Some("03:00-05:00".to_string());
        let cache = MemCache::default();
        load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);

        let fetcher = Fetcher::fail("should not be called");
        let loaded = load_rule_feeds(&[f], &cache, &fetcher, false, NOW + 86_400);
        assert_eq!(fetcher.calls(), 0, "窗口外不应拉取");
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn shadow_period_marks_rules_log_only() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        f.shadow_period = Some(Duration::from_secs(3_600));
        let cache = MemCache::default();
        let loaded = load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);
        assert!(loaded.rules[0].shadow, "新规则应处于影子期");
        assert_eq!(loaded.statuses[0].shadow_until, Some(NOW + 3_600));

        let loaded = load_rule_feeds(&[f.clone()], &cache, &Fetcher::fail("x"), false, NOW + 60);
        assert!(loaded.rules[0].shadow, "缓存版本仍在影子期");

        // 同一份载荷重复拉取不能重置影子期
        let (mut f2, body2, _) = signed_feed("official", "1.0", "rule-a");
        f2.shadow_period = Some(Duration::from_secs(3_600));
        let loaded = load_rule_feeds(&[f2], &cache, &Fetcher::ok(body2), true, NOW + 120);
        assert_eq!(loaded.statuses[0].shadow_until, Some(NOW + 3_600));
    }

    #[test]
    fn changed_payload_starts_new_shadow_period() {
        let (mut f, body, key) = signed_feed("official", "1.0", "rule-a");
        f.shadow_period = Some(Duration::from_secs(3_600));
        let cache = MemCache::default();
        load_rule_feeds(std::slice::from_ref(&f), &cache, &Fetcher::ok(body), true, NOW);

        let new_body = signed(&key, &doc("1.1", "rule-a"));
        let loaded = load_rule_feeds(&[f], &cache, &Fetcher::ok(new_body), true, NOW + 600);
        assert_eq!(loaded.statuses[0].shadow_until, Some(NOW + 600 + 3_600));
        assert_eq!(loaded.statuses[0].version.as_deref(), Some("1.1"));
    }

    #[test]
    fn pinned_version_mismatch_is_rejected() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        f.channel = FeedChannel::Pinned;
        f.pinned_version = Some("9.9".to_string());
        let cache = MemCache::default();
        let loaded = load_rule_feeds(&[f], &cache, &Fetcher::ok(body), true, NOW);
        assert!(loaded.rules.is_empty());
        assert!(loaded.statuses[0]
            .error
            .as_deref()
            .unwrap()
            .contains("版本不匹配"));
    }

    #[test]
    fn pinned_version_match_is_accepted() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        f.channel = FeedChannel::Pinned;
        f.pinned_version = Some("1.0".to_string());
        let loaded = load_rule_feeds(
            &[f],
            &MemCache::default(),
            &Fetcher::ok(body),
            true,
            NOW,
        );
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn stable_feed_rejects_beta_document() {
        let (f, _, key) = signed_feed("official", "1.0", "rule-a");
        let beta_doc = doc("1.0", "rule-a")
            .replace(r#""version": "1.0","#, r#""version": "1.0", "channel": "beta","#);
        let body = signed(&key, &beta_doc);
        let loaded = load_rule_feeds(
            &[f],
            &MemCache::default(),
            &Fetcher::ok(body),
            true,
            NOW,
        );
        assert!(loaded.rules.is_empty());
        assert!(loaded.statuses[0]
            .error
            .as_deref()
            .unwrap()
            .contains("beta"));
    }

    #[test]
    fn duplicate_ids_across_feeds_skip_later_feed() {
        let (f1, body1, _) = signed_feed("one", "1.0", "same-rule");
        let (f2, body2, _) = signed_feed("two", "1.0", "same-rule");
        struct MapFetcher {
            one: String,
            two: String,
        }
        impl RuleFeedFetcher for MapFetcher {
            fn fetch(&self, feed: &RuleFeed) -> Result<String, String> {
                Ok(if feed.name == "one" {
                    self.one.clone()
                } else {
                    self.two.clone()
                })
            }
        }
        let loaded = load_rule_feeds(
            &[f1, f2],
            &MemCache::default(),
            &MapFetcher {
                one: body1,
                two: body2,
            },
            true,
            NOW,
        );
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.statuses[0].rule_count, 1);
        assert_eq!(loaded.statuses[1].rule_count, 0);
        assert!(loaded.statuses[1]
            .error
            .as_deref()
            .unwrap()
            .contains("冲突"));
    }

    #[test]
    fn disabled_feed_contributes_no_rules() {
        let (mut f, body, _) = signed_feed("official", "1.0", "rule-a");
        f.enabled = false;
        let fetcher = Fetcher::ok(body);
        let loaded = load_rule_feeds(&[f], &MemCache::default(), &fetcher, true, NOW);
        assert!(loaded.rules.is_empty());
        assert_eq!(loaded.statuses[0].source, "disabled");
        assert_eq!(fetcher.calls(), 0);
    }

    #[test]
    fn update_window_handles_wraparound() {
        // UTC 23:30
        let ts = 23 * 3_600 + 30 * 60;
        assert!(within_update_window(ts, Some("23:00-01:00")));
        // UTC 00:30 仍在窗口内
        assert!(within_update_window(30 * 60, Some("23:00-01:00")));
        // UTC 12:00 不在窗口内
        assert!(!within_update_window(12 * 3_600, Some("23:00-01:00")));
        assert!(within_update_window(12 * 3_600, None));
        assert!(within_update_window(12 * 3_600, Some("bad")));
    }
}
