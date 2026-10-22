//! CC 防护：滑动窗口 QPS 限制与并发连接计数。
//!
//! 三层限流共用一套近似滑动窗口：
//! - 全局 QPS
//! - 单 IP QPS
//! - 单 URL QPS（应用 + 路径，不含查询串）
//!
//! 用「当前窗口计数 + 上一窗口计数 × 剩余权重」估算，误差在 1 秒窗口内可控，
//! 比固定窗口少了临界突刺（59 秒 + 60 秒各打满会放过两倍流量）。
//!
//! 所有计数都带过期清理：单机长期运行时，攻击者换 IP 就能把 HashMap 撑爆。

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// 分片数。单 IP 限流在 2 万 RPS 下也不该被一把大锁卡住。
const SHARDS: usize = 16;
const WINDOW_MS: u64 = 1_000;
/// 每个分片的条目上限。超过后先做一次过期清理，仍然超就拒绝新键，
/// 宁可漏限一个新 IP，也不让内存无限增长。
const MAX_ENTRIES_PER_SHARD: usize = 4_096;
/// 每处理这么多次请求做一次全量清理。
const SWEEP_EVERY: u64 = 4_096;

/// 命中的限流层级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Global,
    Ip,
    Url,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Ip => "ip",
            Scope::Url => "url",
        }
    }
}

/// 一次限流命中。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitHit {
    pub scope: Scope,
    /// 配置的阈值
    pub limit: u32,
    /// 当前窗口估算值
    pub observed: u32,
}

/// 一次请求要检查的阈值。`0` 表示该层不限制。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitParams {
    pub global_qps: u32,
    pub per_ip_qps: u32,
    pub per_url_qps: u32,
}

impl LimitParams {
    pub fn is_limited(&self) -> bool {
        self.global_qps > 0 || self.per_ip_qps > 0 || self.per_url_qps > 0
    }
}

/// 一个滑动窗口。
#[derive(Debug, Clone, Copy)]
struct Window {
    start_ms: u64,
    current: u32,
    previous: u32,
}

impl Window {
    fn new(now_ms: u64) -> Self {
        Self {
            start_ms: now_ms,
            current: 0,
            previous: 0,
        }
    }

    /// 推进窗口并返回当前估算计数（不增加本次请求）。
    fn estimate(&mut self, now_ms: u64) -> u32 {
        let elapsed = now_ms.saturating_sub(self.start_ms);
        if elapsed >= 2 * WINDOW_MS {
            self.start_ms = now_ms;
            self.current = 0;
            self.previous = 0;
        } else if elapsed >= WINDOW_MS {
            // 最多跨一个窗口：把当前窗口降级为上一窗口
            self.start_ms += WINDOW_MS;
            self.previous = self.current;
            self.current = 0;
        }

        let elapsed = now_ms.saturating_sub(self.start_ms).min(WINDOW_MS);
        let remaining = WINDOW_MS - elapsed;
        // previous 的权重从 1.0 线性衰减到 0
        let weighted_previous = (self.previous as u64 * remaining) / WINDOW_MS;
        self.current.saturating_add(weighted_previous as u32)
    }

    fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.start_ms) >= 2 * WINDOW_MS
    }
}

/// 分片哈希表。键必须是可哈希的拥有型数据。
struct Sharded<K> {
    shards: Vec<Mutex<HashMap<K, Window>>>,
}

impl<K: Eq + Hash + Clone> Sharded<K> {
    fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// 估算 + 计数。返回 `Some(observed)` 表示超限。
    fn hit(&self, key: &K, limit: u32, now_ms: u64) -> Option<u32> {
        if limit == 0 {
            return None;
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % SHARDS;

        let mut map = self.shards[idx]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if map.len() >= MAX_ENTRIES_PER_SHARD {
            map.retain(|_, w| !w.is_stale(now_ms));
            // 清理完仍然满，说明短时间内键太多。拒绝新键的计数，
            // 已经存在的键继续正常限流。
            if map.len() >= MAX_ENTRIES_PER_SHARD && !map.contains_key(key) {
                return None;
            }
        }

        let window = map
            .entry(key.clone())
            .or_insert_with(|| Window::new(now_ms));
        let observed = window.estimate(now_ms);
        if observed >= limit {
            // 被拒绝的请求不计数：否则一次突刺会让用户在整个窗口内持续被拒。
            return Some(observed);
        }
        window.current = window.current.saturating_add(1);
        None
    }

    fn sweep(&self, now_ms: u64) {
        for shard in &self.shards {
            let mut map = shard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.retain(|_, w| !w.is_stale(now_ms));
        }
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum()
    }
}

/// 并发连接计数。
///
/// 和 QPS 分开：QPS 高不代表同时占用很多连接，长连接（WebSocket、大文件下载）
/// 才是需要单独限制的对象。
pub struct ConnTable {
    shards: Vec<Mutex<HashMap<IpAddr, u32>>>,
}

impl ConnTable {
    fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn shard(&self, ip: &IpAddr) -> &Mutex<HashMap<IpAddr, u32>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % SHARDS]
    }

    /// 尝试占用一个连接槽位。`limit == 0` 表示不限。
    fn try_acquire(self: &Arc<Self>, ip: IpAddr, limit: u32) -> Option<ConnGuard> {
        if limit == 0 {
            return Some(ConnGuard {
                table: self.clone(),
                ip,
                tracked: false,
            });
        }

        {
            let mut map = self
                .shard(&ip)
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = map.entry(ip).or_insert(0);
            if *count >= limit {
                return None;
            }
            *count += 1;
        }

        Some(ConnGuard {
            table: self.clone(),
            ip,
            tracked: true,
        })
    }

    /// 当前某 IP 的并发数。
    pub fn count(&self, ip: IpAddr) -> u32 {
        self.shard(&ip)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }

    pub fn tracked_ips(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum()
    }

    fn release(&self, ip: IpAddr) {
        let mut map = self
            .shard(&ip)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&ip);
            }
        }
    }
}

/// 连接槽位。请求结束（含被拦截）时由 `Drop` 释放，
/// 不需要在每个提前返回的分支手动减一。
pub struct ConnGuard {
    table: Arc<ConnTable>,
    ip: IpAddr,
    tracked: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self.tracked {
            self.table.release(self.ip);
        }
    }
}

/// CC 防护运行时。
pub struct RateLimiter {
    start: Instant,
    seq: AtomicU64,
    global: Mutex<Window>,
    ips: Sharded<IpAddr>,
    urls: Sharded<String>,
    conns: Arc<ConnTable>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            seq: AtomicU64::new(0),
            global: Mutex::new(Window::new(0)),
            ips: Sharded::new(),
            urls: Sharded::new(),
            conns: Arc::new(ConnTable::new()),
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// 检查三层限流。返回 `None` 表示放行。
    ///
    /// `url_key` 由调用方拼接（建议 `应用ID + 路径`），不含查询串，
    /// 否则 `?t=随机数` 会让每个请求都成为独立键。
    pub fn check(
        &self,
        ip: Option<IpAddr>,
        url_key: Option<&str>,
        params: LimitParams,
    ) -> Option<LimitHit> {
        let now = self.now_ms();
        self.check_at(now, ip, url_key, params)
    }

    fn check_at(
        &self,
        now_ms: u64,
        ip: Option<IpAddr>,
        url_key: Option<&str>,
        params: LimitParams,
    ) -> Option<LimitHit> {
        if !params.is_limited() {
            return None;
        }

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if seq % SWEEP_EVERY == 0 && seq > 0 {
            self.sweep_at(now_ms);
        }

        if params.global_qps > 0 {
            let mut window = self
                .global
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let observed = window.estimate(now_ms);
            if observed >= params.global_qps {
                return Some(LimitHit {
                    scope: Scope::Global,
                    limit: params.global_qps,
                    observed,
                });
            }
            window.current = window.current.saturating_add(1);
        }

        if let Some(ip) = ip {
            if let Some(observed) = self.ips.hit(&ip, params.per_ip_qps, now_ms) {
                return Some(LimitHit {
                    scope: Scope::Ip,
                    limit: params.per_ip_qps,
                    observed,
                });
            }
        }

        if let Some(key) = url_key {
            if let Some(observed) = self.urls.hit(&key.to_string(), params.per_url_qps, now_ms) {
                return Some(LimitHit {
                    scope: Scope::Url,
                    limit: params.per_url_qps,
                    observed,
                });
            }
        }

        None
    }

    /// 尝试占用一个并发连接槽位。
    pub fn try_acquire_conn(self: &Arc<Self>, ip: IpAddr, limit: u32) -> Option<ConnGuard> {
        self.conns.try_acquire(ip, limit)
    }

    pub fn conn_count(&self, ip: IpAddr) -> u32 {
        self.conns.count(ip)
    }

    pub fn connection_table(&self) -> &Arc<ConnTable> {
        &self.conns
    }

    /// 清理所有过期窗口。由请求计数触发，也可由后台线程调用。
    pub fn sweep(&self) {
        self.sweep_at(self.now_ms());
    }

    fn sweep_at(&self, now_ms: u64) {
        {
            let mut global = self
                .global
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if global.is_stale(now_ms) {
                *global = Window::new(now_ms);
            }
        }
        self.ips.sweep(now_ms);
        self.urls.sweep(now_ms);
    }

    /// 当前跟踪的键数量，用于测试与运行状态展示。
    pub fn tracked_keys(&self) -> (usize, usize) {
        (self.ips.len(), self.urls.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn params(global: u32, per_ip: u32, per_url: u32) -> LimitParams {
        LimitParams {
            global_qps: global,
            per_ip_qps: per_ip,
            per_url_qps: per_url,
        }
    }

    #[test]
    fn zero_limits_mean_unlimited() {
        let rl = RateLimiter::new();
        for _ in 0..10_000 {
            assert!(rl
                .check_at(0, Some(ip("1.2.3.4")), Some("/a"), params(0, 0, 0))
                .is_none());
        }
    }

    #[test]
    fn ip_limit_enforced() {
        let rl = RateLimiter::new();
        let p = params(0, 2, 0);
        assert!(rl.check_at(0, Some(ip("1.2.3.4")), Some("/a"), p).is_none());
        assert!(rl
            .check_at(10, Some(ip("1.2.3.4")), Some("/a"), p)
            .is_none());
        let hit = rl
            .check_at(20, Some(ip("1.2.3.4")), Some("/a"), p)
            .expect("第三次应超限");
        assert_eq!(hit.scope, Scope::Ip);
        assert_eq!(hit.limit, 2);
    }

    #[test]
    fn different_ips_are_independent() {
        let rl = RateLimiter::new();
        let p = params(0, 1, 0);
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_none());
        assert!(rl.check_at(0, Some(ip("2.2.2.2")), Some("/a"), p).is_none());
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_some());
    }

    #[test]
    fn different_urls_are_independent() {
        let rl = RateLimiter::new();
        let p = params(0, 0, 1);
        assert!(rl
            .check_at(0, Some(ip("1.1.1.1")), Some("app/a"), p)
            .is_none());
        assert!(rl
            .check_at(0, Some(ip("1.1.1.1")), Some("app/b"), p)
            .is_none());
        assert!(rl
            .check_at(0, Some(ip("1.1.1.1")), Some("app/a"), p)
            .is_some());
    }

    #[test]
    fn global_limit_enforced() {
        let rl = RateLimiter::new();
        let p = params(2, 100, 100);
        assert!(rl
            .check_at(0, Some(ip("1.1.1.1")), Some("app/a"), p)
            .is_none());
        assert!(rl
            .check_at(0, Some(ip("2.2.2.2")), Some("app/b"), p)
            .is_none());
        let hit = rl
            .check_at(0, Some(ip("3.3.3.3")), Some("app/c"), p)
            .expect("应触发全局限流");
        assert_eq!(hit.scope, Scope::Global);
    }

    #[test]
    fn window_recovers_after_one_second() {
        let rl = RateLimiter::new();
        let p = params(0, 2, 0);
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_none());
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_none());
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_some());

        // 1.5 秒：上一窗口权重减半，估算为 1，允许一条
        assert!(rl
            .check_at(1_500, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_none());
        // 2 秒：1.5 秒那条还在上一窗口里，只能再放一条
        assert!(rl
            .check_at(2_000, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_none());
        assert!(rl
            .check_at(2_000, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_some());
        // 3.1 秒：窗口彻底清空，重新允许两条
        assert!(rl
            .check_at(3_100, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_none());
        assert!(rl
            .check_at(3_100, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_none());
        assert!(rl
            .check_at(3_100, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_some());
    }

    #[test]
    fn rejected_requests_do_not_extend_block() {
        let rl = RateLimiter::new();
        let p = params(0, 1, 0);
        assert!(rl.check_at(0, Some(ip("1.1.1.1")), Some("/a"), p).is_none());
        for _ in 0..100 {
            assert!(rl
                .check_at(100, Some(ip("1.1.1.1")), Some("/a"), p)
                .is_some());
        }
        // 拒绝不计数，窗口滑过后应恢复
        assert!(rl
            .check_at(1_500, Some(ip("1.1.1.1")), Some("/a"), p)
            .is_none());
    }

    #[test]
    fn sweep_drops_stale_entries() {
        let rl = RateLimiter::new();
        let p = params(0, 10, 10);
        for i in 0..100u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            rl.check_at(0, Some(addr), Some(&format!("app/{i}")), p);
        }
        let (ips, urls) = rl.tracked_keys();
        assert_eq!((ips, urls), (100, 100));
        rl.sweep_at(5_000);
        assert_eq!(rl.tracked_keys(), (0, 0));
    }

    #[test]
    fn missing_ip_or_url_skips_that_layer() {
        let rl = RateLimiter::new();
        let p = params(0, 1, 1);
        assert!(rl.check_at(0, None, None, p).is_none());
        assert!(
            rl.check_at(0, None, None, p).is_none(),
            "没有 IP/URL 时不应限流"
        );
    }

    // ============================================================
    // 并发连接
    // ============================================================

    #[test]
    fn conn_limit_enforced_and_released() {
        let rl = Arc::new(RateLimiter::new());
        let addr = ip("1.1.1.1");

        let g1 = rl.try_acquire_conn(addr, 2).expect("第一个连接应通过");
        let _g2 = rl.try_acquire_conn(addr, 2).expect("第二个连接应通过");
        assert_eq!(rl.conn_count(addr), 2);
        assert!(rl.try_acquire_conn(addr, 2).is_none(), "第三个应被拒绝");

        drop(g1);
        assert_eq!(rl.conn_count(addr), 1);
        let _g3 = rl.try_acquire_conn(addr, 2).expect("释放后应能再次占用");
    }

    #[test]
    fn conn_limit_zero_is_unlimited() {
        let rl = Arc::new(RateLimiter::new());
        let addr = ip("1.1.1.1");
        let mut guards = Vec::new();
        for _ in 0..100 {
            guards.push(rl.try_acquire_conn(addr, 0).expect("不限时应通过"));
        }
        assert_eq!(rl.conn_count(addr), 0, "不限额时不记账");
    }

    #[test]
    fn conn_counts_are_per_ip() {
        let rl = Arc::new(RateLimiter::new());
        let _a = rl.try_acquire_conn(ip("1.1.1.1"), 1).unwrap();
        let _b = rl.try_acquire_conn(ip("2.2.2.2"), 1).unwrap();
        assert_eq!(rl.connection_table().tracked_ips(), 2);
    }

    #[test]
    fn conn_guard_release_is_idempotent_under_many_drops() {
        let rl = Arc::new(RateLimiter::new());
        let addr = ip("1.1.1.1");
        for _ in 0..100 {
            let g = rl.try_acquire_conn(addr, 10).unwrap();
            drop(g);
        }
        assert_eq!(rl.conn_count(addr), 0);
        assert_eq!(rl.connection_table().tracked_ips(), 0, "归零后应删除条目");
    }
}
