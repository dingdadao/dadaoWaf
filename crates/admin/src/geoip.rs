//! GeoIP 归属地查询。
//!
//! 代理热路径不查库：请求只记录 IP，控制台生成统计快照时再批量解析
//! 国家 / 省份 / 城市 / 经纬度。这样 mmdb 读取、字符串分配和缓存都留在
//! 管理面，不影响转发延迟。
//!
//! 数据来源是 MaxMind GeoLite2-City.mmdb（GeoIP2-City 同样可用），路径由
//! 设置项 [`GEOIP_SETTING`] 指定。路径为空表示未启用，地图区域降级为
//! “未启用地理位置”，不影响其它功能。

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use maxminddb::Reader;
use serde::Serialize;

/// 设置项键名：mmdb 文件路径。
pub const GEOIP_SETTING: &str = "geoip_db";

/// 默认下载源：jsDelivr 上的 GeoLite2-City 压缩包。
pub const DEFAULT_DOWNLOAD_URL: &str =
    "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz";

/// 下载后保存的文件名。
pub const DEFAULT_DB_FILE: &str = "GeoLite2-City.mmdb";

/// 压缩包大小上限，防止异常响应打爆内存。
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// 解压后的大小上限。
const MAX_DB_BYTES: u64 = 1024 * 1024 * 1024;

/// 缓存 IP 数量上限。超过后整体清空，按需重新查询。
const CACHE_CAP: usize = 8192;
/// 排行榜最多保留的条目数。
const TOP_CAP: usize = 20;
/// 地图打点最多保留的坐标数。
const POINT_CAP: usize = 2000;
/// 单次快照最多解析的 IP 数（指标层已经截断到 5000，这里再兜一层）。
const MAX_IPS: usize = 5000;

/// 单个 IP 的地理信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub province: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// 名称 + 计数。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoCount {
    pub name: String,
    pub count: u64,
}

/// 地图打点：坐标 + 该坐标上的请求数。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
    pub count: u64,
}

/// 一次统计快照的地理聚合结果。
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoStats {
    /// 是否加载了可用的 mmdb
    pub available: bool,
    /// 当前数据库路径
    pub path: String,
    /// 加载或查询错误（仅在可用时可能为查询错误）
    pub error: Option<String>,
    /// 实际解析成功的 IP 数
    pub resolved_ips: usize,
    /// 本次快照的来源 IP 总数（含无法解析的内网 / 保留地址）
    pub total_ips: usize,
    pub countries: Vec<GeoCount>,
    pub provinces: Vec<GeoCount>,
    pub cities: Vec<GeoCount>,
    pub points: Vec<GeoPoint>,
}

/// GeoIP 运行状态。
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoStatus {
    pub enabled: bool,
    pub path: String,
    pub error: Option<String>,
    pub cached_ips: usize,
}

/// GeoIP 查询器。由控制台持有，代理不感知。
pub struct GeoIp {
    inner: RwLock<Inner>,
}

struct Inner {
    path: String,
    reader: Option<Reader<Vec<u8>>>,
    error: Option<String>,
    /// IP → 归属地。未命中也缓存 `None`，避免反复查同一个内网 / 未知 IP。
    cache: HashMap<IpAddr, Option<GeoInfo>>,
}

impl Default for GeoIp {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIp {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                path: String::new(),
                reader: None,
                error: None,
                cache: HashMap::new(),
            }),
        }
    }

    /// 从数据库设置项 `geoip_db` 重新加载。空路径表示禁用。
    pub fn reload_from_store(&self, store: &homewaf_store::Store) {
        let path = store
            .get_setting::<serde_json::Value>(GEOIP_SETTING)
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        self.load(&path);
    }

    /// 加载指定路径的 mmdb。失败时保留错误信息，查询返回 `None`。
    pub fn load(&self, path: &str) {
        let path = path.trim().to_string();
        let (reader, error) = if path.is_empty() {
            (None, None)
        } else {
            match Reader::open_readfile(&path) {
                Ok(reader) => (Some(reader), None),
                Err(e) => (None, Some(format!("无法加载 {path}：{e}"))),
            }
        };

        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.path = path;
        inner.reader = reader;
        inner.error = error;
        // 换库后旧结果不再可信
        inner.cache.clear();
    }

    pub fn status(&self) -> GeoStatus {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        GeoStatus {
            enabled: inner.reader.is_some(),
            path: inner.path.clone(),
            error: inner.error.clone(),
            cached_ips: inner.cache.len(),
        }
    }

    /// 查询单个 IP。内网 / 保留地址直接返回 `None`，不进入 mmdb。
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        if !is_public(ip) {
            return None;
        }

        {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some(hit) = inner.cache.get(&ip) {
                return hit.clone();
            }
            inner.reader.as_ref()?;
        }

        let info = {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            let reader = inner.reader.as_ref()?;
            match reader.lookup(ip) {
                Ok(result) => match result.decode::<maxminddb::geoip2::City>() {
                    Ok(Some(city)) => Some(from_city(&city)),
                    Ok(None) => None,
                    Err(e) => {
                        // 单条损坏不应拖垮整个查询，记录下来继续
                        tracing::debug!(%ip, error = %e, "GeoIP 记录解析失败");
                        None
                    }
                },
                Err(e) => {
                    tracing::debug!(%ip, error = %e, "GeoIP 查询失败");
                    None
                }
            }
        };

        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if inner.cache.len() >= CACHE_CAP {
            inner.cache.clear();
        }
        inner.cache.insert(ip, info.clone());
        info
    }

    /// 在统计快照上批量解析 IP 归属地。
    pub fn resolve(&self, ips: &[(IpAddr, u32)]) -> GeoStats {
        let status = self.status();
        let mut stats = GeoStats {
            available: status.enabled,
            path: status.path,
            error: status.error,
            total_ips: ips.len(),
            ..Default::default()
        };
        if !stats.available {
            return stats;
        }

        let mut countries: HashMap<String, u64> = HashMap::new();
        let mut provinces: HashMap<String, u64> = HashMap::new();
        let mut cities: HashMap<String, u64> = HashMap::new();
        let mut points: HashMap<(i64, i64), u64> = HashMap::new();

        for (ip, count) in ips.iter().take(MAX_IPS) {
            let Some(info) = self.lookup(*ip) else {
                continue;
            };
            let count = u64::from(*count);
            stats.resolved_ips += 1;

            let country = if info.country.is_empty() {
                info.country_code.clone()
            } else {
                info.country.clone()
            };
            bump(&mut countries, &country, count);
            bump(&mut provinces, &info.province, count);

            let city = match (country.as_str(), info.city.as_str()) {
                ("", "") => String::new(),
                ("", city) => city.to_string(),
                (country, "") => country.to_string(),
                (country, city) => format!("{country} · {city}"),
            };
            bump(&mut cities, &city, count);

            if info.latitude != 0.0 || info.longitude != 0.0 {
                // 落到 0.01° 网格再聚合，避免同一城市出现成千上万个点
                let key = (
                    (info.latitude * 100.0).round() as i64,
                    (info.longitude * 100.0).round() as i64,
                );
                *points.entry(key).or_insert(0) += count;
            }
        }

        stats.countries = top(countries);
        stats.provinces = top(provinces);
        stats.cities = top(cities);

        let mut points: Vec<GeoPoint> = points
            .into_iter()
            .map(|((lat, lon), count)| GeoPoint {
                latitude: lat as f64 / 100.0,
                longitude: lon as f64 / 100.0,
                count,
            })
            .collect();
        points.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.latitude.total_cmp(&b.latitude))
                .then_with(|| a.longitude.total_cmp(&b.longitude))
        });
        points.truncate(POINT_CAP);
        stats.points = points;

        stats
    }
}

/// 校验 mmdb 路径是否可加载，供设置项写库前使用。
pub fn validate_db(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Ok(());
    }
    Reader::open_readfile(path.trim())
        .map(|_| ())
        .map_err(|e| format!("GeoIP 数据库无法加载：{e}"))
}

/// 从默认下载源拉取 GeoLite2-City，解压后保存到 `dir`，返回文件路径。
///
/// 阻塞调用，控制台需要在 `spawn_blocking` 里执行。先写临时文件再 rename，
/// 避免下载中断留下半截 mmdb；写盘后用 [`validate_db`] 做一次可加载校验。
pub fn download_default(dir: &Path) -> Result<PathBuf, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .build()
        .into();

    let response = agent
        .get(DEFAULT_DOWNLOAD_URL)
        .call()
        .map_err(|e| format!("下载 {DEFAULT_DOWNLOAD_URL} 失败：{e}"))?;

    let mut gz = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut gz)
        .map_err(|e| format!("读取下载内容失败：{e}"))?;
    if gz.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(format!("下载内容超过上限 {MAX_DOWNLOAD_BYTES} 字节"));
    }
    if gz.is_empty() {
        return Err("下载内容为空".to_string());
    }

    let mut db = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .take(MAX_DB_BYTES + 1)
        .read_to_end(&mut db)
        .map_err(|e| format!("解压 GeoIP 数据库失败：{e}"))?;
    if db.len() as u64 > MAX_DB_BYTES {
        return Err(format!("解压后数据库超过上限 {MAX_DB_BYTES} 字节"));
    }

    std::fs::create_dir_all(dir).map_err(|e| format!("创建目录 {} 失败：{e}", dir.display()))?;
    let target = dir.join(DEFAULT_DB_FILE);
    let tmp = dir.join(format!(".{DEFAULT_DB_FILE}.tmp"));
    if let Err(e) = std::fs::write(&tmp, &db) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("写入 {} 失败：{e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("保存 {} 失败：{e}", target.display()));
    }

    validate_db(&target.display().to_string())?;
    Ok(target)
}

fn from_city(city: &maxminddb::geoip2::City<'_>) -> GeoInfo {
    GeoInfo {
        country: name(&city.country.names),
        country_code: city.country.iso_code.unwrap_or("").to_string(),
        province: city
            .subdivisions
            .last()
            .map(|s| name(&s.names))
            .unwrap_or_default(),
        city: name(&city.city.names),
        latitude: city.location.latitude.unwrap_or(0.0),
        longitude: city.location.longitude.unwrap_or(0.0),
    }
}

/// 优先简体中文，其次英文。
fn name(names: &maxminddb::geoip2::Names<'_>) -> String {
    names
        .simplified_chinese
        .or(names.english)
        .unwrap_or("")
        .to_string()
}

fn bump(map: &mut HashMap<String, u64>, key: &str, count: u64) {
    if key.is_empty() {
        return;
    }
    *map.entry(key.to_string()).or_insert(0) += count;
}

fn top(map: HashMap<String, u64>) -> Vec<GeoCount> {
    let mut v: Vec<GeoCount> = map
        .into_iter()
        .map(|(name, count)| GeoCount { name, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(TOP_CAP);
    v
}

/// 是否是公网地址。内网、回环、链路本地与文档网段查库没有意义。
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 唯一本地地址
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 链路本地
                || (seg[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = "8.8.8.8";

    #[test]
    fn disabled_by_default() {
        let g = GeoIp::new();
        let s = g.status();
        assert!(!s.enabled);
        assert!(s.path.is_empty());
        assert_eq!(s.cached_ips, 0);
        assert_eq!(g.lookup(PUBLIC.parse().unwrap()), None);

        let stats = g.resolve(&[(PUBLIC.parse().unwrap(), 3)]);
        assert!(!stats.available, "未配置数据库时地图不可用");
        assert!(stats.points.is_empty());
        assert_eq!(stats.resolved_ips, 0);
    }

    #[test]
    fn missing_database_reports_error() {
        let g = GeoIp::new();
        g.load("/nonexistent/GeoLite2-City.mmdb");
        let s = g.status();
        assert!(!s.enabled);
        assert!(s.error.as_deref().unwrap_or("").contains("无法加载"));
        assert!(validate_db("/nonexistent/GeoLite2-City.mmdb").is_err());
    }

    #[test]
    fn empty_path_disables_cleanly() {
        let g = GeoIp::new();
        g.load("/nonexistent/GeoLite2-City.mmdb");
        g.load("   ");
        let s = g.status();
        assert!(!s.enabled);
        assert!(s.error.is_none(), "空路径是正常禁用，不是错误");
    }

    #[test]
    fn private_and_reserved_ips_are_skipped() {
        assert!(is_public(PUBLIC.parse().unwrap()));
        assert!(!is_public("127.0.0.1".parse().unwrap()));
        assert!(!is_public("10.0.0.1".parse().unwrap()));
        assert!(!is_public("192.168.1.5".parse().unwrap()));
        assert!(!is_public("172.16.0.1".parse().unwrap()));
        assert!(!is_public("169.254.1.1".parse().unwrap()));
        assert!(!is_public("203.0.113.9".parse().unwrap()), "文档网段不查库");
        assert!(!is_public("::1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(!is_public("fe80::1".parse().unwrap()));
        assert!(is_public("2400:3200::1".parse().unwrap()));
    }

    #[test]
    fn validate_empty_path_is_ok() {
        assert!(validate_db("").is_ok());
        assert!(validate_db("   ").is_ok());
    }

    #[test]
    fn resolve_without_database_is_safe() {
        let g = GeoIp::new();
        let ips = vec![
            (PUBLIC.parse().unwrap(), 10),
            ("192.168.1.5".parse().unwrap(), 100),
        ];
        let stats = g.resolve(&ips);
        assert!(!stats.available);
        assert_eq!(stats.resolved_ips, 0);
        assert!(stats.countries.is_empty());
    }
}
