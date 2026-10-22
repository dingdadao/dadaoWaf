//! 上游选择与被动健康检查。
//!
//! 之前只用第一个上游，配了多个也不生效——这是静默的功能失效，比没有功能更糟。
//!
//! 设计取舍：
//! - **被动健康检查优先**：不主动探测，靠真实请求的失败累积判断。家用场景上游少、
//!   流量低，主动探测的心跳包反而增加负担。
//! - **半开恢复**：标记 down 后不永久剔除，超过 `window` 后放行一次试探，
//!   成功则恢复。否则上游修好了也永远回不来。
//! - **备份上游最后用**：只有主池全不可用才启用，避免主备混用导致流量倾斜。

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use homewaf_config::{Application, LbAlgorithm, PassiveHealthCheck, Route, Upstream};

const HEALTHY: u8 = 0;
const DOWN: u8 = 1;

/// 一次选择的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// 上游地址 `host:port`
    pub addr: String,
    /// 是否 TLS 回源
    pub tls: bool,
    /// TLS 回源的 SNI（IP 上游直接用 IP 字符串）
    pub sni: String,
    /// TLS 回源是否校验证书
    pub verify: bool,
    /// 在池内的下标，用于回写健康状态
    pub slot: usize,
    /// 是否来自备份池
    pub backup: bool,
}

/// 单个上游的运行时状态。
#[derive(Debug)]
struct Slot {
    addr: String,
    tls: bool,
    /// TLS 回源的 SNI（IP 上游直接用 IP 字符串，否则握手会失败）
    sni: String,
    /// TLS 回源是否校验证书
    verify: bool,
    weight: u32,
    backup: bool,
    state: AtomicU8,
    failures: AtomicU32,
    successes: AtomicU32,
    /// 正在处理的请求数（least_conn 用）
    active: AtomicUsize,
    /// 标记 down 的时间（Unix 毫秒），用于半开恢复
    down_since_ms: AtomicU64,
    /// 连续主动探测成功次数
    active_ok: AtomicU32,
    /// 连续主动探测失败次数
    active_fail: AtomicU32,
}

impl Slot {
    fn new(u: &Upstream) -> Option<Self> {
        // 用 target() 统一解析：addr 里可能写的是完整 URL
        let target = match u.target() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(addr = %u.addr, error = %e, "上游地址非法，已跳过");
                return None;
            }
        };

        let tls = matches!(
            target.scheme,
            homewaf_config::Scheme::Https | homewaf_config::Scheme::Wss
        );
        // SNI 不能留空：rustls 解析空域名会直接握手失败；IP 上游用 IP 作 ServerName
        let sni = u
            .tls
            .as_ref()
            .and_then(|t| t.sni.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| target.host.clone());
        // 未显式配置时沿用默认（校验），内网自签上游需要显式关闭
        let verify = u.tls.as_ref().map(|t| t.verify).unwrap_or(true);

        Some(Self {
            addr: format!("{}:{}", target.host, target.port),
            tls,
            sni: if tls { sni } else { String::new() },
            verify,
            weight: u.weight.max(1) as u32,
            backup: u.backup,
            state: AtomicU8::new(HEALTHY),
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            active: AtomicUsize::new(0),
            down_since_ms: AtomicU64::new(0),
            active_ok: AtomicU32::new(0),
            active_fail: AtomicU32::new(0),
        })
    }

    /// 当前是否可选。
    ///
    /// down 状态超过 `window` 后返回 true（半开），允许试探一次。
    fn is_available(&self, now_ms: u64, hc: &PassiveHealthCheck) -> bool {
        if self.state.load(Ordering::Relaxed) == HEALTHY {
            return true;
        }
        let window = hc.window.0.as_millis() as u64;
        let since = self.down_since_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(since) >= window
    }

    fn mark_failure(&self, now_ms: u64, hc: &PassiveHealthCheck) {
        self.successes.store(0, Ordering::Relaxed);
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= hc.fail_threshold {
            self.state.store(DOWN, Ordering::Relaxed);
            self.down_since_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    fn mark_success(&self, hc: &PassiveHealthCheck) {
        self.failures.store(0, Ordering::Relaxed);
        if self.state.load(Ordering::Relaxed) == DOWN {
            let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
            if successes >= hc.recover_threshold {
                self.state.store(HEALTHY, Ordering::Relaxed);
                self.successes.store(0, Ordering::Relaxed);
            }
        }
    }

    fn is_down(&self) -> bool {
        self.state.load(Ordering::Relaxed) == DOWN
    }
}

/// 一组上游（应用默认或某条路由专属）。
#[derive(Debug)]
struct UpstreamSet {
    slots: Vec<Slot>,
    /// 加权轮询序列：按权重重复下标
    order: Vec<usize>,
    /// 轮询游标
    cursor: AtomicU64,
    algorithm: LbAlgorithm,
}

impl UpstreamSet {
    fn new(upstreams: &[Upstream], algorithm: LbAlgorithm) -> Self {
        let slots: Vec<Slot> = upstreams.iter().filter_map(Slot::new).collect();

        // 权重展开。单个权重上限 100，避免畸形配置把序列撑爆
        let mut order = Vec::new();
        for (idx, slot) in slots.iter().enumerate() {
            if slot.backup {
                continue;
            }
            let repeat = slot.weight.min(100) as usize;
            for _ in 0..repeat {
                order.push(idx);
            }
        }
        // 全备份的池：备份也进入轮询序列，否则永远选不到
        if order.is_empty() {
            for idx in 0..slots.len() {
                order.push(idx);
            }
        }

        Self {
            slots,
            order,
            cursor: AtomicU64::new(0),
            algorithm,
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// 在候选集中按算法挑一个。
    fn pick(&self, candidates: &[usize], client_ip: IpAddr) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(candidates[0]);
        }

        match self.algorithm {
            LbAlgorithm::LeastConn => candidates.iter().copied().min_by_key(|&idx| {
                // 按权重归一化：连接数 / 权重，权重高的容忍更多连接
                let active = self.slots[idx].active.load(Ordering::Relaxed) as u64;
                let weight = self.slots[idx].weight.max(1) as u64;
                active * 1000 / weight
            }),
            LbAlgorithm::IpHash | LbAlgorithm::ConsistentHash => {
                let hash = hash_ip(client_ip);
                Some(candidates[(hash % candidates.len() as u64) as usize])
            }
            // RoundRobin / Weighted：都走加权序列，权重全 1 时等价于轮询
            LbAlgorithm::RoundRobin | LbAlgorithm::Weighted => {
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize;
                let len = self.order.len();
                for offset in 0..len {
                    let idx = self.order[(start + offset) % len];
                    if candidates.contains(&idx) {
                        return Some(idx);
                    }
                }
                candidates.first().copied()
            }
        }
    }

    fn select(&self, client_ip: IpAddr, now_ms: u64, hc: &PassiveHealthCheck) -> Option<Selection> {
        self.select_avoiding(client_ip, now_ms, hc, &[])
    }

    /// 与 [`select`] 相同，但跳过 `avoid` 里的槽位。
    fn select_avoiding(
        &self,
        client_ip: IpAddr,
        now_ms: u64,
        hc: &PassiveHealthCheck,
        avoid: &[usize],
    ) -> Option<Selection> {
        let available: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_available(now_ms, hc))
            .filter(|(i, _)| !avoid.contains(i))
            .map(|(i, _)| i)
            .collect();

        if available.is_empty() {
            return None;
        }

        // 优先主池，主池全不可用才用备份
        let primary: Vec<usize> = available
            .iter()
            .copied()
            .filter(|&i| !self.slots[i].backup)
            .collect();
        let pool = if primary.is_empty() {
            &available
        } else {
            &primary
        };

        let idx = self.pick(pool, client_ip)?;
        let slot = &self.slots[idx];
        Some(Selection {
            addr: slot.addr.clone(),
            tls: slot.tls,
            sni: slot.sni.clone(),
            verify: slot.verify,
            slot: idx,
            backup: slot.backup,
        })
    }
}

/// 整个代理的上游池，按应用与路由组织。
#[derive(Debug)]
pub struct UpstreamPool {
    apps: Vec<AppPool>,
}

#[derive(Debug)]
struct AppPool {
    default: UpstreamSet,
    /// 与路由下标对齐；`None` 表示该路由用默认上游
    routes: Vec<Option<UpstreamSet>>,
    /// 被动健康检查参数
    health: PassiveHealthCheck,
    /// 主动健康检查参数
    active: Option<homewaf_config::ActiveHealthCheck>,
}

impl UpstreamPool {
    /// 从配置构建。
    pub fn build(apps: &[Application]) -> Self {
        let apps = apps
            .iter()
            .map(|app| {
                let health = app.health_check.passive.clone().unwrap_or_default();
                let default = UpstreamSet::new(&app.upstreams, app.lb.algorithm);
                let routes = app
                    .routes
                    .iter()
                    .map(|r: &Route| {
                        r.upstreams
                            .as_ref()
                            .map(|ups| UpstreamSet::new(ups, app.lb.algorithm))
                    })
                    .collect();
                AppPool {
                    default,
                    routes,
                    health,
                    active: app.health_check.active.clone(),
                }
            })
            .collect();
        Self { apps }
    }

    /// 选一个上游。
    pub fn select(
        &self,
        app_index: usize,
        route_index: Option<usize>,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<Selection> {
        let app = self.apps.get(app_index)?;

        // 路由专属上游优先，没配或为空则回退应用默认
        let set = route_index
            .and_then(|i| app.routes.get(i))
            .and_then(|o| o.as_ref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&app.default);

        set.select(client_ip, now_ms, &app.health)
    }

    /// 选一个上游，并跳过本次请求已经试过的上游。
    ///
    /// 重试时用：坏上游 + 好上游的场景下，第一次尝试的槽位即使还没被
    /// 被动健康检查标记为 down，也不应该再选中一次。
    pub fn select_retry(
        &self,
        app_index: usize,
        route_index: Option<usize>,
        client_ip: IpAddr,
        now_ms: u64,
        tried: &[usize],
    ) -> Option<Selection> {
        let app = self.apps.get(app_index)?;
        let set = route_index
            .and_then(|i| app.routes.get(i))
            .and_then(|o| o.as_ref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&app.default);

        // 先排除已试过的；都试过了再退回普通选择，至少再试一次
        set.select_avoiding(client_ip, now_ms, &app.health, tried)
            .or_else(|| set.select(client_ip, now_ms, &app.health))
    }

    /// 标记某次请求失败（连接失败或 5xx）。
    pub fn mark_failure(
        &self,
        app_index: usize,
        route_index: Option<usize>,
        slot: usize,
        now_ms: u64,
    ) {
        if let Some(s) = self.set_of(app_index, route_index) {
            if let Some(sl) = s.slots.get(slot) {
                sl.mark_failure(now_ms, &self.apps[app_index].health);
            }
        }
    }

    /// 标记某次请求成功。
    pub fn mark_success(&self, app_index: usize, route_index: Option<usize>, slot: usize) {
        if let Some(s) = self.set_of(app_index, route_index) {
            if let Some(sl) = s.slots.get(slot) {
                sl.mark_success(&self.apps[app_index].health);
            }
        }
    }

    /// 请求开始：增加活跃连接数。
    pub fn acquire(&self, app_index: usize, route_index: Option<usize>, slot: usize) {
        if let Some(s) = self.set_of(app_index, route_index) {
            if let Some(sl) = s.slots.get(slot) {
                sl.active.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 请求结束：减少活跃连接数。
    pub fn release(&self, app_index: usize, route_index: Option<usize>, slot: usize) {
        if let Some(s) = self.set_of(app_index, route_index) {
            if let Some(sl) = s.slots.get(slot) {
                // 用 CAS 做 saturating 减法：不用 fetch_update（1.82 可用但已弃用），
                // 也不用 try_update（需要 1.95，超出 MSRV）
                let mut current = sl.active.load(Ordering::Relaxed);
                while current > 0 {
                    match sl.active.compare_exchange_weak(
                        current,
                        current - 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => current = actual,
                    }
                }
            }
        }
    }

    fn set_of(&self, app_index: usize, route_index: Option<usize>) -> Option<&UpstreamSet> {
        let app = self.apps.get(app_index)?;
        let set = route_index
            .and_then(|i| app.routes.get(i))
            .and_then(|o| o.as_ref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&app.default);
        Some(set)
    }

    /// 上游总数（用于启动日志）。
    pub fn total_upstreams(&self) -> usize {
        self.apps
            .iter()
            .map(|a| {
                a.default.slots.len()
                    + a.routes
                        .iter()
                        .flatten()
                        .map(|s| s.slots.len())
                        .sum::<usize>()
            })
            .sum()
    }

    /// 某应用当前不可用的上游数（供健康状态展示）。
    pub fn down_count(&self, app_index: usize) -> usize {
        self.apps
            .get(app_index)
            .map(|a| a.default.slots.iter().filter(|s| s.is_down()).count())
            .unwrap_or(0)
    }

    /// 收集需要主动探测的上游。
    pub fn probe_targets(&self) -> Vec<ProbeTarget> {
        let mut out = Vec::new();
        for (app_index, app) in self.apps.iter().enumerate() {
            let Some(hc) = &app.active else { continue };
            if !hc.enabled {
                continue;
            }
            for (slot, s) in app.default.slots.iter().enumerate() {
                out.push(ProbeTarget {
                    app_index,
                    slot,
                    addr: s.addr.clone(),
                    tls: s.tls,
                    verify: s.verify,
                    path: hc.path.clone(),
                    timeout_ms: hc.timeout.0.as_millis() as u64,
                    expect_status: hc.expect_status.clone(),
                });
            }
        }
        out
    }

    /// 写回主动探测结果。
    ///
    /// 与被动检查共用同一个 `state`：主动探测说健康就恢复，说不健康就下线。
    /// 两者都只是"证据"，最终状态取最近一次结论。
    pub fn set_active_health(&self, app_index: usize, slot: usize, healthy: bool) {
        let Some(app) = self.apps.get(app_index) else {
            return;
        };
        let Some(s) = app.default.slots.get(slot) else {
            return;
        };
        // 连续阈值：单次探测抖动（例如负载下的 3s 超时）不应该直接摘除应用
        let (ok_need, fail_need) = match &app.active {
            Some(hc) => (hc.healthy_threshold.max(1), hc.unhealthy_threshold.max(1)),
            None => (1, 1),
        };

        if healthy {
            s.active_fail.store(0, Ordering::Relaxed);
            let ok = s.active_ok.fetch_add(1, Ordering::Relaxed) + 1;
            if ok >= ok_need {
                s.state.store(HEALTHY, Ordering::Relaxed);
                s.failures.store(0, Ordering::Relaxed);
                s.active_ok.store(0, Ordering::Relaxed);
            }
        } else {
            s.active_ok.store(0, Ordering::Relaxed);
            let fail = s.active_fail.fetch_add(1, Ordering::Relaxed) + 1;
            if fail >= fail_need {
                s.state.store(DOWN, Ordering::Relaxed);
                s.down_since_ms.store(now_ms(), Ordering::Relaxed);
            }
        }
    }

    /// 探测间隔：取所有启用主动检查的应用里最小的那个。
    pub fn probe_interval(&self) -> Option<std::time::Duration> {
        self.apps
            .iter()
            .filter_map(|a| a.active.as_ref())
            .filter(|hc| hc.enabled)
            .map(|hc| hc.interval.0)
            .min()
    }

    /// 所有上游的当前健康快照，供控制台展示。
    pub fn health_snapshot(&self) -> Vec<(String, bool)> {
        self.apps
            .iter()
            .flat_map(|a| {
                a.default
                    .slots
                    .iter()
                    .map(|s| (s.addr.clone(), !s.is_down()))
            })
            .collect()
    }

    /// 单个应用的默认上游健康状态，供应用详情页展示。
    pub fn health_for_app(&self, app_index: usize) -> Vec<(String, bool)> {
        self.apps
            .get(app_index)
            .map(|a| {
                a.default
                    .slots
                    .iter()
                    .map(|s| (s.addr.clone(), !s.is_down()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// 一个待探测的上游。
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub app_index: usize,
    pub slot: usize,
    pub addr: String,
    pub tls: bool,
    /// TLS 探测是否校验证书（自签上游必须关闭，否则永远判为不健康）
    pub verify: bool,
    pub path: String,
    pub timeout_ms: u64,
    pub expect_status: Vec<u16>,
}

/// 探测单个上游。返回是否健康。
pub fn probe(t: &ProbeTarget) -> bool {
    let scheme = if t.tls { "https" } else { "http" };
    let path = if t.path.starts_with('/') {
        t.path.clone()
    } else if t.path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", t.path)
    };
    let url = format!("{scheme}://{}{path}", t.addr);

    let builder = ureq::Agent::config_builder().timeout_global(Some(
        std::time::Duration::from_millis(t.timeout_ms.max(100)),
    ));
    let builder = if t.tls && !t.verify {
        builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        )
    } else {
        builder
    };
    let agent: ureq::Agent = builder.build().into();

    match agent.get(&url).call() {
        Ok(resp) => healthy_status(resp.status().as_u16(), &t.expect_status),
        // ureq 把 4xx/5xx 当成 Err(StatusCode)，不能一律判成不可达——
        // 上游返回 404 说明它活着，只是没有这个路径。
        Err(ureq::Error::StatusCode(code)) => healthy_status(code, &t.expect_status),
        Err(_) => false,
    }
}

/// 探测拿到状态码后是否算健康。
///
/// `expect_status` 为空表示"任意非 5xx 都算可达"；配置了列表就严格比对。
fn healthy_status(code: u16, expect: &[u16]) -> bool {
    if expect.is_empty() {
        code < 500
    } else {
        expect.contains(&code)
    }
}

/// 当前 Unix 毫秒。
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// FNV-1a 哈希，用于 IP 哈希。分布够用且不引入依赖。
fn hash_ip(ip: IpAddr) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let bytes: Vec<u8> = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    for b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{Application, Domains, LbAlgorithm, Scheme, TlsModeConfig, Upstream};

    fn upstream(addr: &str, port: u16) -> Upstream {
        Upstream {
            addr: addr.to_string(),
            port: Some(port),
            scheme: Scheme::Http,
            weight: 1,
            backup: false,
            max_conns: 128,
            tls: None,
        }
    }

    fn upstream_with_tls(addr: &str, port: u16, verify: bool) -> Upstream {
        let mut u = upstream(addr, port);
        u.tls = Some(homewaf_config::UpstreamTlsConfig {
            verify,
            ..Default::default()
        });
        u
    }

    #[test]
    fn https_upstream_gets_sni_and_verify_flag() {
        // IP 上游：SNI 用 IP 字符串，否则 rustls 解析空域名会握手失败
        let ip = Slot::new(&upstream_with_tls("https://10.0.0.14:9443", 9443, false)).unwrap();
        assert!(ip.tls);
        assert_eq!(ip.sni, "10.0.0.14");
        assert!(!ip.verify);

        // 域名上游：默认用主机名做 SNI，并保持证书校验
        let host = Slot::new(&upstream_with_tls("https://nas.home.lan", 443, true)).unwrap();
        assert_eq!(host.sni, "nas.home.lan");
        assert!(host.verify);

        // 明文上游不带 SNI
        let plain = Slot::new(&upstream("http://10.0.0.4:5666", 5666)).unwrap();
        assert!(!plain.tls);
        assert!(plain.sni.is_empty());
    }

    fn app_with(upstreams: Vec<Upstream>, algorithm: LbAlgorithm) -> Application {
        Application {
            id: "a".to_string(),
            name: "a".to_string(),
            enabled: true,
            domains: Domains {
                primary: "a.home.lan".to_string(),
                aliases: vec![],
            },
            listen_ports: Vec::new(),
            upstreams,
            routes: vec![],
            tls: TlsModeConfig::default(),
            policy: Default::default(),
            lb: homewaf_config::LbConfig {
                algorithm,
                sticky: false,
            },
            timeouts: Default::default(),
            health_check: Default::default(),
            retry: Default::default(),
            headers: Default::default(),
            websocket: false,
            expires_at: None,
            description: String::new(),
            group: String::new(),
            access_mode: Default::default(),
            static_site: Default::default(),
            redirect: Default::default(),
            features: Default::default(),
            tamper: Default::default(),
        }
    }

    fn ip() -> IpAddr {
        "203.0.113.9".parse().unwrap()
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn round_robin_cycles_through_all() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::RoundRobin,
        )]);

        let mut seen = Vec::new();
        for _ in 0..4 {
            let s = pool.select(0, None, ip(), NOW).unwrap();
            seen.push(s.addr);
        }
        assert_eq!(
            seen,
            vec!["10.0.0.1:80", "10.0.0.2:80", "10.0.0.1:80", "10.0.0.2:80"]
        );
    }

    #[test]
    fn weighted_respects_weights() {
        let mut a = upstream("10.0.0.1", 80);
        a.weight = 3;
        let mut b = upstream("10.0.0.2", 80);
        b.weight = 1;

        let pool = UpstreamPool::build(&[app_with(vec![a, b], LbAlgorithm::Weighted)]);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..8 {
            let s = pool.select(0, None, ip(), NOW).unwrap();
            *counts.entry(s.addr).or_insert(0) += 1;
        }
        // 权重 3:1，8 次请求应约 6:2
        assert_eq!(counts.get("10.0.0.1:80"), Some(&6));
        assert_eq!(counts.get("10.0.0.2:80"), Some(&2));
    }

    #[test]
    fn least_conn_prefers_idle() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::LeastConn,
        )]);

        // 给第一个压 5 个活跃请求
        for _ in 0..5 {
            pool.acquire(0, None, 0);
        }
        let s = pool.select(0, None, ip(), NOW).unwrap();
        assert_eq!(s.addr, "10.0.0.2:80");
    }

    #[test]
    fn ip_hash_is_sticky() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::IpHash,
        )]);

        let first = pool.select(0, None, ip(), NOW).unwrap();
        for _ in 0..10 {
            let again = pool.select(0, None, ip(), NOW).unwrap();
            assert_eq!(again.addr, first.addr, "同一 IP 应固定命中同一上游");
        }
    }

    #[test]
    fn failure_marks_down_after_threshold() {
        let mut a = upstream("10.0.0.1", 80);
        a.weight = 1;
        let app = app_with(vec![a, upstream("10.0.0.2", 80)], LbAlgorithm::RoundRobin);
        let hc = app.health_check.passive.clone().unwrap_or_default();
        let threshold = hc.fail_threshold;

        let pool = UpstreamPool::build(&[app]);
        for _ in 0..threshold {
            pool.mark_failure(0, None, 0, NOW);
        }

        // 第一个已 down，之后只应选到第二个
        for _ in 0..5 {
            let s = pool.select(0, None, ip(), NOW).unwrap();
            assert_eq!(s.addr, "10.0.0.2:80");
        }
        assert_eq!(pool.down_count(0), 1);
    }

    #[test]
    fn all_down_returns_none() {
        let app = app_with(vec![upstream("10.0.0.1", 80)], LbAlgorithm::RoundRobin);
        let hc = app.health_check.passive.clone().unwrap_or_default();
        let pool = UpstreamPool::build(&[app]);

        for _ in 0..hc.fail_threshold {
            pool.mark_failure(0, None, 0, NOW);
        }
        assert!(pool.select(0, None, ip(), NOW).is_none());
    }

    #[test]
    fn recovers_after_window() {
        let app = app_with(vec![upstream("10.0.0.1", 80)], LbAlgorithm::RoundRobin);
        let hc = app.health_check.passive.clone().unwrap_or_default();
        let window_ms = hc.window.0.as_millis() as u64;
        let pool = UpstreamPool::build(&[app]);

        for _ in 0..hc.fail_threshold {
            pool.mark_failure(0, None, 0, NOW);
        }
        assert!(pool.select(0, None, ip(), NOW).is_none());

        // 超过 window 后允许半开试探
        let later = NOW + window_ms + 1;
        assert!(pool.select(0, None, ip(), later).is_some());
    }

    #[test]
    fn success_restores_health() {
        let app = app_with(vec![upstream("10.0.0.1", 80)], LbAlgorithm::RoundRobin);
        let hc = app.health_check.passive.clone().unwrap_or_default();
        let window_ms = hc.window.0.as_millis() as u64;
        let pool = UpstreamPool::build(&[app]);

        for _ in 0..hc.fail_threshold {
            pool.mark_failure(0, None, 0, NOW);
        }

        // 半开试探成功若干次后恢复
        let later = NOW + window_ms + 1;
        for _ in 0..hc.recover_threshold {
            pool.mark_success(0, None, 0);
        }
        assert_eq!(pool.down_count(0), 0);
        assert!(pool.select(0, None, ip(), later).is_some());
    }

    #[test]
    fn backup_used_only_when_primary_down() {
        let mut backup = upstream("10.0.0.9", 80);
        backup.backup = true;

        let app = app_with(
            vec![upstream("10.0.0.1", 80), backup],
            LbAlgorithm::RoundRobin,
        );
        let hc = app.health_check.passive.clone().unwrap_or_default();
        let pool = UpstreamPool::build(&[app]);

        // 主上游健康时不应选备份
        for _ in 0..4 {
            let s = pool.select(0, None, ip(), NOW).unwrap();
            assert!(!s.backup, "主上游可用时不该用备份");
        }

        // 主上游全挂后启用备份
        for _ in 0..hc.fail_threshold {
            pool.mark_failure(0, None, 0, NOW);
        }
        let s = pool.select(0, None, ip(), NOW).unwrap();
        assert!(s.backup, "主池全挂应回落到备份");
        assert_eq!(s.addr, "10.0.0.9:80");
    }

    #[test]
    fn route_upstreams_override_default() {
        let mut app = app_with(vec![upstream("10.0.0.1", 80)], LbAlgorithm::RoundRobin);
        app.routes = vec![Route {
            path: "/other".to_string(),
            upstreams: Some(vec![upstream("10.0.0.2", 80)]),
            rewrite: None,
            policy: None,
            allow_methods: None,
            cache: None,
        }];

        let pool = UpstreamPool::build(&[app]);
        assert_eq!(pool.select(0, None, ip(), NOW).unwrap().addr, "10.0.0.1:80");
        assert_eq!(
            pool.select(0, Some(0), ip(), NOW).unwrap().addr,
            "10.0.0.2:80"
        );
    }

    #[test]
    fn active_count_never_underflows() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80)],
            LbAlgorithm::LeastConn,
        )]);
        // 没 acquire 就 release，不应 panic 或回绕
        pool.release(0, None, 0);
        pool.release(0, None, 0);
        pool.acquire(0, None, 0);
        assert!(pool.select(0, None, ip(), NOW).is_some());
    }

    // ============================================================
    // 主动健康检查
    // ============================================================

    #[test]
    fn active_probe_marks_down() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80)],
            LbAlgorithm::RoundRobin,
        )]);

        assert_eq!(pool.down_count(0), 0);
        pool.set_active_health(0, 0, false);
        assert_eq!(pool.down_count(0), 1, "探测失败应标记不健康");
        assert!(
            pool.select(0, None, ip(), now_ms()).is_none(),
            "唯一上游不健康时应选不到"
        );
    }

    #[test]
    fn active_probe_recovers() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80)],
            LbAlgorithm::RoundRobin,
        )]);

        pool.set_active_health(0, 0, false);
        assert!(pool.select(0, None, ip(), now_ms()).is_none());

        pool.set_active_health(0, 0, true);
        assert_eq!(pool.down_count(0), 0, "探测成功应恢复");
        assert!(pool.select(0, None, ip(), now_ms()).is_some());
    }

    #[test]
    fn active_probe_picks_healthy_one() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::RoundRobin,
        )]);

        pool.set_active_health(0, 0, false);
        // 只剩第二个健康，无论轮询游标在哪都该选到它
        for _ in 0..5 {
            let s = pool.select(0, None, ip(), now_ms()).unwrap();
            assert_eq!(s.addr, "10.0.0.2:80");
        }
    }

    #[test]
    fn health_snapshot_reports_all() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::RoundRobin,
        )]);

        pool.set_active_health(0, 1, false);
        let snap = pool.health_snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(a, ok)| a == "10.0.0.1:80" && *ok));
        assert!(snap.iter().any(|(a, ok)| a == "10.0.0.2:80" && !*ok));
    }

    #[test]
    fn probe_targets_only_for_enabled_apps() {
        // 没配 active 的应用不产生探测目标
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80)],
            LbAlgorithm::RoundRobin,
        )]);
        assert!(pool.probe_targets().is_empty());
    }

    #[test]
    fn upstream_url_forms_are_parsed() {
        // addr 支持完整 URL，端口与协议从 URL 推导
        let mut a = upstream("http://10.0.0.1", 0);
        a.port = None;
        let b = Upstream {
            addr: "https://nas.lan".to_string(),
            port: None,
            ..upstream("x", 1)
        };
        let pool = UpstreamPool::build(&[app_with(vec![a, b], LbAlgorithm::RoundRobin)]);
        let snap = pool.health_snapshot();
        assert!(
            snap.iter().any(|(addr, _)| addr == "10.0.0.1:80"),
            "实际: {snap:?}"
        );
        assert!(
            snap.iter().any(|(addr, _)| addr == "nas.lan:443"),
            "https 默认 443，实际: {snap:?}"
        );
    }

    #[test]
    fn probe_status_semantics() {
        // 空列表 = 任意非 5xx 都算可达（雷池同步来的上游常只有 404 首页）
        assert!(healthy_status(404, &[]));
        assert!(healthy_status(200, &[]));
        assert!(!healthy_status(500, &[]));
        // 显式配置了列表就严格比对
        assert!(healthy_status(404, &[404]));
        assert!(!healthy_status(200, &[404]));
    }

    #[test]
    fn active_probe_honors_thresholds() {
        let mut app = app_with(vec![upstream("10.0.0.1", 80)], LbAlgorithm::RoundRobin);
        app.health_check.active = Some(homewaf_config::ActiveHealthCheck {
            enabled: true,
            interval: homewaf_config::Duration::from_secs(5),
            timeout: homewaf_config::Duration::from_secs(3),
            path: "/".to_string(),
            method: "GET".to_string(),
            expect_status: Vec::new(),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        });
        let pool = UpstreamPool::build(&[app]);

        // 连续两次失败还不够下线
        pool.set_active_health(0, 0, false);
        pool.set_active_health(0, 0, false);
        assert_eq!(pool.down_count(0), 0, "未达 unhealthy_threshold 不该下线");
        pool.set_active_health(0, 0, false);
        assert_eq!(pool.down_count(0), 1, "达到阈值应下线");

        // 恢复同样要连续两次成功
        pool.set_active_health(0, 0, true);
        assert_eq!(pool.down_count(0), 1, "未达 healthy_threshold 不该恢复");
        pool.set_active_health(0, 0, true);
        assert_eq!(pool.down_count(0), 0, "达到阈值应恢复");
    }

    #[test]
    fn retry_selection_skips_tried_slot() {
        let pool = UpstreamPool::build(&[app_with(
            vec![upstream("10.0.0.1", 80), upstream("10.0.0.2", 80)],
            LbAlgorithm::RoundRobin,
        )]);
        let first = pool.select(0, None, ip(), NOW).unwrap();
        let second = pool
            .select_retry(0, None, ip(), NOW, &[first.slot])
            .unwrap();
        assert_ne!(first.addr, second.addr, "重试应换一个上游");
    }
}
