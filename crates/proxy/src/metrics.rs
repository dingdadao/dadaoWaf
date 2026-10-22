//! 流量指标聚合。
//!
//! 以分钟桶保存最近 24 小时的访问数据。指标只保留聚合结果，不保留请求样本：
//! 首页、大屏和报表需要的是“多少、谁、从哪来”，不是逐条重放。
//!
//! 这里刻意做成同步锁 + 纯内存聚合。家用场景流量有限，一次记录只做几次
//! 哈希与自增；真正昂贵的 GeoIP 查询、排序和序列化放在控制台侧按需完成。

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use serde::Serialize;

/// 指标保留时长：24 小时。
pub const RETENTION_MINUTES: i64 = 24 * 60;
/// 单个排行在每个分钟桶里最多保留的条目数。超过后新值不再进入排行，
/// 避免扫描器用随机路径把内存打爆。
const TOP_CAP: usize = 64;
/// 实时 OPS 窗口（秒）。
const OPS_WINDOW: i64 = 60;

pub const OS_LABELS: [&str; 7] = ["Windows", "macOS", "iOS", "Android", "Linux", "Bot", "未知"];
pub const BROWSER_LABELS: [&str; 10] = [
    "Chrome",
    "Safari",
    "Edge",
    "Firefox",
    "curl",
    "Go-http-client",
    "Python",
    "Bot",
    "其他",
    "未知",
];

const OS_WINDOWS: usize = 0;
const OS_MAC: usize = 1;
const OS_IOS: usize = 2;
const OS_ANDROID: usize = 3;
const OS_LINUX: usize = 4;
const OS_BOT: usize = 5;
const OS_UNKNOWN: usize = 6;

const BR_CHROME: usize = 0;
const BR_SAFARI: usize = 1;
const BR_EDGE: usize = 2;
const BR_FIREFOX: usize = 3;
const BR_CURL: usize = 4;
const BR_GO: usize = 5;
const BR_PYTHON: usize = 6;
const BR_BOT: usize = 7;
const BR_OTHER: usize = 8;
const BR_UNKNOWN: usize = 9;

/// 一次请求的指标样本。字段都是借用，记录时立即聚合，不延长生命周期。
pub struct TrafficSample<'a> {
    pub ts: i64,
    pub app: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub status: u16,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
    pub blocked: bool,
}

/// 指标存储。由代理写入，控制台读取。
#[derive(Default)]
pub struct TrafficMetrics {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    buckets: VecDeque<Bucket>,
    seconds: VecDeque<SecCount>,
}

struct SecCount {
    sec: i64,
    requests: u32,
    blocked: u32,
}

struct Bucket {
    minute: i64,
    apps: HashMap<String, AppBucket>,
}

#[derive(Default)]
struct AppBucket {
    requests: u64,
    pv: u64,
    blocked: u64,
    statuses: HashMap<u16, u32>,
    /// IP → 请求数。既用于独立 IP，也用于控制台侧做 GeoIP 聚合。
    ips: HashMap<u128, u32>,
    /// (IP, UA) 哈希，用于独立访客。
    visitors: HashSet<u64>,
    blocked_ips: HashSet<u128>,
    os: [u32; OS_LABELS.len()],
    browsers: [u32; BROWSER_LABELS.len()],
    hosts: HashMap<String, u32>,
    paths: HashMap<String, u32>,
    referer_hosts: HashMap<String, u32>,
    referer_urls: HashMap<String, u32>,
}

impl AppBucket {
    fn record(&mut self, sample: &TrafficSample<'_>, ip_hash: Option<u128>, visitor: Option<u64>) {
        self.requests += 1;
        if is_page_view(sample) {
            self.pv += 1;
        }
        if sample.blocked {
            self.blocked += 1;
            if let Some(ip) = ip_hash {
                self.blocked_ips.insert(ip);
            }
        }

        if sample.status > 0 {
            *self.statuses.entry(sample.status).or_insert(0) += 1;
        }
        if let Some(ip) = ip_hash {
            *self.ips.entry(ip).or_insert(0) += 1;
        }
        if let Some(v) = visitor {
            self.visitors.insert(v);
        }

        let (os, browser) = classify(sample.user_agent);
        self.os[os] += 1;
        self.browsers[browser] += 1;

        bump(&mut self.hosts, sample.host);
        bump(&mut self.paths, sample.path);
        if let Some(referer) = sample.referer {
            if let Some((host, url)) = split_referer(referer) {
                bump(&mut self.referer_hosts, host);
                bump(&mut self.referer_urls, url);
            }
        }
    }
}

impl TrafficMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次请求。错误或未匹配应用的请求也会记录，只是 `app` 为空。
    pub fn record(&self, sample: TrafficSample<'_>) {
        let ip_hash = sample.ip.map(ip_key);
        let visitor = sample.ip.map(|ip| visitor_key(ip, sample.user_agent));

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let minute = sample.ts - sample.ts.rem_euclid(60);
        inner.prune(minute);

        if inner.buckets.back().map(|b| b.minute) != Some(minute) {
            inner.buckets.push_back(Bucket {
                minute,
                apps: HashMap::new(),
            });
        }
        let bucket = inner.buckets.back_mut().expect("刚插入的分钟桶");
        bucket
            .apps
            .entry(sample.app.to_string())
            .or_default()
            .record(&sample, ip_hash, visitor);

        let sec = sample.ts - sample.ts.rem_euclid(1);
        match inner.seconds.back_mut() {
            Some(s) if s.sec == sec => {
                s.requests += 1;
                if sample.blocked {
                    s.blocked += 1;
                }
            }
            _ => {
                inner.seconds.push_back(SecCount {
                    sec,
                    requests: 1,
                    blocked: sample.blocked as u32,
                });
                let cutoff = sample.ts - OPS_WINDOW;
                while inner.seconds.front().map(|s| s.sec).unwrap_or(i64::MAX) < cutoff {
                    inner.seconds.pop_front();
                }
            }
        }
    }

    /// 聚合一个时间范围的仪表盘数据。
    pub fn dashboard(&self, range_secs: i64, app: Option<&str>, now: i64) -> DashboardData {
        let range_secs = range_secs.clamp(60, RETENTION_MINUTES * 60);
        let now_minute = now - now.rem_euclid(60);
        let start = now_minute - (range_secs / 60).max(1) * 60 + 60;

        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut agg = Agg::default();
        let group = if range_secs <= 3_600 {
            60
        } else if range_secs <= 6 * 3_600 {
            120
        } else {
            300
        };

        let mut points: HashMap<i64, (u64, u64)> = HashMap::new();
        for bucket in inner.buckets.iter().filter(|b| b.minute >= start) {
            if let Some(id) = app {
                if let Some(b) = bucket.apps.get(id) {
                    agg.add(b);
                    let slot = bucket.minute - bucket.minute.rem_euclid(group);
                    let p = points.entry(slot).or_default();
                    p.0 += b.requests;
                    p.1 += b.blocked;
                }
            } else {
                let mut total = 0;
                let mut blocked = 0;
                for b in bucket.apps.values() {
                    agg.add(b);
                    total += b.requests;
                    blocked += b.blocked;
                }
                let slot = bucket.minute - bucket.minute.rem_euclid(group);
                let p = points.entry(slot).or_default();
                p.0 += total;
                p.1 += blocked;
            }
        }

        let mut series: Vec<Point> = points
            .into_iter()
            .map(|(ts, (requests, blocked))| Point {
                ts,
                requests,
                blocked,
            })
            .collect();
        series.sort_by_key(|p| p.ts);

        let mut ops = Vec::with_capacity(OPS_WINDOW as usize);
        for i in (0..OPS_WINDOW).rev() {
            let sec = now - i;
            let n = inner
                .seconds
                .iter()
                .rev()
                .find(|s| s.sec == sec)
                .map(|s| s.requests)
                .unwrap_or(0);
            ops.push(n);
        }

        let mut data = agg.finish();
        data.series = series;
        data.ops = ops;
        data.range_secs = range_secs;
        data
    }

    /// 已完成分钟桶的快照，供持久化线程使用。
    pub fn completed_buckets(&self, after_minute: i64, before_minute: i64) -> Vec<BucketSnapshot> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner
            .buckets
            .iter()
            .filter(|b| b.minute > after_minute && b.minute < before_minute)
            .flat_map(|b| {
                b.apps
                    .iter()
                    .filter(|(_, v)| v.requests > 0)
                    .map(move |(app, v)| BucketSnapshot {
                        minute: b.minute,
                        app: app.clone(),
                        requests: v.requests,
                        pv: v.pv,
                        blocked: v.blocked,
                        status_4xx: v
                            .statuses
                            .iter()
                            .filter(|(s, _)| (400..500).contains(*s))
                            .map(|(_, n)| *n as u64)
                            .sum(),
                        status_5xx: v
                            .statuses
                            .iter()
                            .filter(|(s, _)| (500..600).contains(*s))
                            .map(|(_, n)| *n as u64)
                            .sum(),
                        unique_ips: v.ips.len() as u64,
                        unique_visitors: v.visitors.len() as u64,
                        ips: v.ips.keys().copied().collect(),
                        visitors: v.visitors.iter().copied().collect(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

impl Inner {
    fn prune(&mut self, current_minute: i64) {
        let cutoff = current_minute - (RETENTION_MINUTES - 1) * 60;
        while self.buckets.front().map(|b| b.minute).unwrap_or(i64::MAX) < cutoff {
            self.buckets.pop_front();
        }
    }
}

#[derive(Default)]
struct Agg {
    requests: u64,
    pv: u64,
    blocked: u64,
    statuses: HashMap<u16, u32>,
    ips: HashMap<u128, u32>,
    visitors: HashSet<u64>,
    blocked_ips: HashSet<u128>,
    os: [u32; OS_LABELS.len()],
    browsers: [u32; BROWSER_LABELS.len()],
    hosts: HashMap<String, u32>,
    paths: HashMap<String, u32>,
    referer_hosts: HashMap<String, u32>,
    referer_urls: HashMap<String, u32>,
}

impl Agg {
    fn add(&mut self, b: &AppBucket) {
        self.requests += b.requests;
        self.pv += b.pv;
        self.blocked += b.blocked;
        for (s, n) in &b.statuses {
            *self.statuses.entry(*s).or_insert(0) += n;
        }
        for (ip, n) in &b.ips {
            *self.ips.entry(*ip).or_insert(0) += n;
        }
        self.visitors.extend(b.visitors.iter().copied());
        self.blocked_ips.extend(b.blocked_ips.iter().copied());
        for (i, n) in b.os.iter().enumerate() {
            self.os[i] += n;
        }
        for (i, n) in b.browsers.iter().enumerate() {
            self.browsers[i] += n;
        }
        merge_top(&mut self.hosts, &b.hosts);
        merge_top(&mut self.paths, &b.paths);
        merge_top(&mut self.referer_hosts, &b.referer_hosts);
        merge_top(&mut self.referer_urls, &b.referer_urls);
    }

    fn finish(self) -> DashboardData {
        let mut ips: Vec<(IpAddr, u32)> = self
            .ips
            .into_iter()
            .filter_map(|(k, n)| decode_ip(k).map(|ip| (ip, n)))
            .collect();
        let unique_ips = ips.len() as u64;
        ips.sort_by_key(|a| std::cmp::Reverse(a.1));
        ips.truncate(5_000);

        DashboardData {
            requests: self.requests,
            pv: self.pv,
            uv: self.visitors.len() as u64,
            unique_ips,
            blocked: self.blocked,
            attack_ips: self.blocked_ips.len() as u64,
            statuses: counts(
                self.statuses
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v as u64)),
            ),
            os: labeled_counts(&OS_LABELS, &self.os),
            browsers: labeled_counts(&BROWSER_LABELS, &self.browsers),
            hosts: counts(self.hosts.into_iter().map(|(k, v)| (k, v as u64))),
            paths: counts(self.paths.into_iter().map(|(k, v)| (k, v as u64))),
            referer_hosts: counts(self.referer_hosts.into_iter().map(|(k, v)| (k, v as u64))),
            referer_urls: counts(self.referer_urls.into_iter().map(|(k, v)| (k, v as u64))),
            series: Vec::new(),
            ops: Vec::new(),
            range_secs: 0,
            ips,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Count {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Point {
    pub ts: i64,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DashboardData {
    pub requests: u64,
    pub pv: u64,
    pub uv: u64,
    pub unique_ips: u64,
    pub blocked: u64,
    pub attack_ips: u64,
    pub statuses: Vec<Count>,
    pub os: Vec<Count>,
    pub browsers: Vec<Count>,
    pub hosts: Vec<Count>,
    pub paths: Vec<Count>,
    pub referer_hosts: Vec<Count>,
    pub referer_urls: Vec<Count>,
    pub series: Vec<Point>,
    pub ops: Vec<u32>,
    pub range_secs: i64,
    /// 原始 IP 列表只给 GeoIP 聚合使用，不下发到前端
    #[serde(skip)]
    pub ips: Vec<(IpAddr, u32)>,
}

#[derive(Debug, Clone)]
pub struct BucketSnapshot {
    pub minute: i64,
    pub app: String,
    pub requests: u64,
    pub pv: u64,
    pub blocked: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub unique_ips: u64,
    pub unique_visitors: u64,
    pub ips: Vec<u128>,
    pub visitors: Vec<u64>,
}

fn counts(it: impl Iterator<Item = (String, u64)>) -> Vec<Count> {
    let mut v: Vec<Count> = it
        .filter(|(name, count)| !name.is_empty() && *count > 0)
        .map(|(name, count)| Count { name, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(10);
    v
}

fn labeled_counts(labels: &[&str], counts: &[u32]) -> Vec<Count> {
    let mut v: Vec<Count> = labels
        .iter()
        .zip(counts)
        .filter(|(_, n)| **n > 0)
        .map(|(name, n)| Count {
            name: name.to_string(),
            count: *n as u64,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v
}

fn bump(map: &mut HashMap<String, u32>, key: &str) {
    if key.is_empty() {
        return;
    }
    if let Some(n) = map.get_mut(key) {
        *n += 1;
        return;
    }
    if map.len() < TOP_CAP {
        map.insert(key.to_string(), 1);
    }
}

fn merge_top(dst: &mut HashMap<String, u32>, src: &HashMap<String, u32>) {
    for (k, n) in src {
        if let Some(v) = dst.get_mut(k) {
            *v += n;
            continue;
        }
        if dst.len() < TOP_CAP {
            dst.insert(k.clone(), *n);
        }
    }
}

fn ip_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn decode_ip(key: u128) -> Option<IpAddr> {
    if key <= u32::MAX as u128 {
        Some(IpAddr::V4(std::net::Ipv4Addr::from(key as u32)))
    } else {
        Some(IpAddr::V6(std::net::Ipv6Addr::from(key)))
    }
}

fn visitor_key(ip: IpAddr, ua: Option<&str>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut push = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match ip {
        IpAddr::V4(v4) => push(&v4.octets()),
        IpAddr::V6(v6) => push(&v6.octets()),
    }
    push(ua.unwrap_or("").as_bytes());
    h
}

fn split_referer(referer: &str) -> Option<(&str, &str)> {
    let rest = referer
        .strip_prefix("https://")
        .or_else(|| referer.strip_prefix("http://"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    // 去掉 query，避免把 token 等敏感参数写进排行
    let path = path.split(['?', '#']).next().unwrap_or(path);
    Some((host, path))
}

fn is_page_view(sample: &TrafficSample<'_>) -> bool {
    if !matches!(sample.method, "GET" | "HEAD") {
        return false;
    }
    let static_ext = [
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".otf", ".map", ".avif", ".mp4", ".webm",
    ];
    let path = sample.path.to_ascii_lowercase();
    !static_ext.iter().any(|ext| path.ends_with(ext))
}

fn classify(ua: Option<&str>) -> (usize, usize) {
    let Some(ua) = ua.filter(|s| !s.is_empty()) else {
        return (OS_UNKNOWN, BR_UNKNOWN);
    };
    let u = ua.to_ascii_lowercase();

    let os = if u.contains("windows") {
        OS_WINDOWS
    } else if u.contains("android") {
        OS_ANDROID
    } else if u.contains("iphone") || u.contains("ipad") || u.contains("ipod") {
        OS_IOS
    } else if u.contains("mac os") || u.contains("macintosh") {
        OS_MAC
    } else if u.contains("linux") {
        OS_LINUX
    } else if looks_like_bot(&u) {
        OS_BOT
    } else {
        OS_UNKNOWN
    };

    let browser = if u.contains("edg/") || u.contains("edgios/") {
        BR_EDGE
    } else if u.contains("chrome/") || u.contains("crios/") {
        BR_CHROME
    } else if u.contains("firefox/") || u.contains("fxios/") {
        BR_FIREFOX
    } else if u.contains("safari/") {
        BR_SAFARI
    } else if u.starts_with("curl/") {
        BR_CURL
    } else if u.contains("go-http-client") {
        BR_GO
    } else if u.contains("python-requests") || u.starts_with("python/") {
        BR_PYTHON
    } else if looks_like_bot(&u) {
        BR_BOT
    } else {
        BR_OTHER
    };

    (os, browser)
}

fn looks_like_bot(ua: &str) -> bool {
    [
        "bot", "spider", "crawler", "slurp", "scanner", "nmap", "masscan", "zgrab", "nuclei",
        "sqlmap", "nikto",
    ]
    .iter()
    .any(|k| ua.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NOW: i64 = 1_700_000_000;

    fn sample<'a>(ts: i64, ip: &'a str, path: &'a str, blocked: bool) -> TrafficSample<'a> {
        TrafficSample {
            ts,
            app: "nas",
            host: "nas.home.lan",
            path,
            method: "GET",
            status: if blocked { 403 } else { 200 },
            ip: Some(IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap())),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36"),
            referer: Some("https://www.baidu.com/s?wd=nas"),
            blocked,
        }
    }

    #[test]
    fn aggregates_basic_counts() {
        let m = TrafficMetrics::new();
        m.record(sample(NOW, "1.1.1.1", "/index", false));
        m.record(sample(NOW + 10, "1.1.1.1", "/index", false));
        m.record(sample(NOW + 20, "2.2.2.2", "/admin", true));
        m.record(sample(NOW + 30, "2.2.2.2", "/style.css", false));

        let d = m.dashboard(3_600, Some("nas"), NOW + 60);
        assert_eq!(d.requests, 4);
        assert_eq!(d.pv, 3, "静态资源不计 PV");
        assert_eq!(d.uv, 2);
        assert_eq!(d.unique_ips, 2);
        assert_eq!(d.blocked, 1);
        assert_eq!(d.attack_ips, 1);
        assert_eq!(d.hosts[0].name, "nas.home.lan");
        assert_eq!(d.paths[0].name, "/index");
        assert_eq!(d.referer_hosts[0].name, "www.baidu.com");
        assert_eq!(d.os[0].name, "Windows");
        assert_eq!(d.browsers[0].name, "Chrome");
        assert_eq!(
            d.statuses.iter().find(|c| c.name == "403").unwrap().count,
            1
        );
    }

    #[test]
    fn filters_by_app() {
        let m = TrafficMetrics::new();
        m.record(sample(NOW, "1.1.1.1", "/index", false));
        m.record(TrafficSample {
            app: "blog",
            ..sample(NOW + 1, "2.2.2.2", "/post", false)
        });

        assert_eq!(m.dashboard(3_600, Some("nas"), NOW).requests, 1);
        assert_eq!(m.dashboard(3_600, Some("blog"), NOW).requests, 1);
        assert_eq!(m.dashboard(3_600, None, NOW).requests, 2);
    }

    #[test]
    fn range_excludes_old_buckets() {
        let m = TrafficMetrics::new();
        m.record(sample(NOW - 3_600, "1.1.1.1", "/old", false));
        m.record(sample(NOW, "1.1.1.1", "/new", false));

        let d = m.dashboard(60, None, NOW);
        assert_eq!(d.requests, 1);
        assert_eq!(d.paths[0].name, "/new");
    }

    #[test]
    fn ops_window_counts_last_seconds() {
        let m = TrafficMetrics::new();
        m.record(sample(NOW, "1.1.1.1", "/a", false));
        m.record(sample(NOW, "1.1.1.1", "/b", false));
        m.record(sample(NOW - 10, "1.1.1.1", "/c", false));

        let d = m.dashboard(3_600, None, NOW);
        assert_eq!(*d.ops.last().unwrap(), 2);
        assert_eq!(d.ops[d.ops.len() - 11], 1);
    }

    #[test]
    fn ua_classification() {
        assert_eq!(classify(None), (OS_UNKNOWN, BR_UNKNOWN));
        assert_eq!(classify(Some("curl/8.0")), (OS_UNKNOWN, BR_CURL));
        assert_eq!(
            classify(Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15"
            )),
            (OS_MAC, BR_SAFARI)
        );
        assert_eq!(
            classify(Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) EdgiOS/120.0"
            )),
            (OS_IOS, BR_EDGE)
        );
        assert_eq!(
            classify(Some("Mozilla/5.0 (compatible; Googlebot/2.1)")),
            (OS_BOT, BR_BOT)
        );
    }

    #[test]
    fn referer_query_is_stripped() {
        assert_eq!(
            split_referer("https://example.com/a/b?token=secret"),
            Some(("example.com", "/a/b"))
        );
        assert_eq!(split_referer("not a url"), None);
    }

    #[test]
    fn completed_buckets_have_aggregates() {
        let m = TrafficMetrics::new();
        m.record(sample(NOW, "1.1.1.1", "/a", false));
        m.record(sample(NOW, "2.2.2.2", "/b", true));

        let buckets = m.completed_buckets(NOW - 120, NOW + 120);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].requests, 2);
        assert_eq!(buckets[0].blocked, 1);
        assert_eq!(buckets[0].unique_ips, 2);
        assert_eq!(buckets[0].ips.len(), 2);
    }
}
