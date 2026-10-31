//! GeoIP 归属地查询。
//!
//! 代理热路径不查库：请求只记录 IP，控制台生成统计快照时再批量解析
//! 国家 / 省份 / 城市 / 经纬度。这样 mmdb 读取、字符串分配和缓存都留在
//! 管理面，不影响转发延迟。
//!
//! 数据来源是 MaxMind GeoLite2-City.mmdb（GeoIP2-City 同样可用），路径由
//! 设置项 [`GEOIP_SETTING`] 指定。路径为空表示未启用，地图区域降级为
//! “未启用地理位置”，不影响其它功能。
//!
//! mmdb 只有国家 / 省 / 城市，没有运营商 / ASN，且国内 IPv6 经常缺城市。
//! 事件与来源 IP 排行这类“单个 IP 详情”场景走 [`GeoIp::lookup_detailed_batch`]，
//! 会用 ip-api.com 批量接口把运营商 / ASN（机房）和缺失的城市补上。
//! 在线结果持久化缓存 + 失败熔断，限流（45 次/分）下也只在冷启动产生少量请求。

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use maxminddb::Reader;
use serde::{Deserialize, Serialize};

/// 设置项键名：mmdb 文件路径。
pub const GEOIP_SETTING: &str = "geoip_db";

/// 设置项键名：连线目的地坐标（`纬度,经度`），科技连线地图的汇聚点。
/// 空值表示用 [`DEFAULT_DEST`]。
pub const MAP_DEST_SETTING: &str = "map_dest";

/// 默认连线目的地：北京。控制台部署在家庭网络时，访问汇聚点就是本机出口城市。
pub const DEFAULT_DEST: (f64, f64) = (39.9042, 116.4074);

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

/// 在线补充查询接口：ip-api.com 批量（免费档 45 次/分，仅 HTTP）。
const ONLINE_BATCH_URL: &str = "http://ip-api.com/batch";
/// 只取需要的字段，缩小响应体。
const ONLINE_FIELDS: &str =
    "status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query";
/// 在线查询超时。控制台同步路径等它，不能太久。
const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);
/// 在线查询失败后的熔断时长，期间只用本地结果降级展示。
const ONLINE_COOLDOWN: Duration = Duration::from_secs(300);
/// 在线缓存 IP 数量上限。超过后整体清空，按需重新查询。
const ONLINE_CACHE_CAP: usize = 8192;
/// 批量接口单次最多查询的 IP 数。
const ONLINE_BATCH_CAP: usize = 100;
/// 在线缓存响应体大小上限，防止异常响应打爆内存。
const ONLINE_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// 在线缓存文件名（放在数据目录，重启不丢）。
const ONLINE_CACHE_FILE: &str = "geoip_online.json";

/// 单个 IP 的地理信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub province: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    /// 运营商 / 机房名称（在线 API 补充，mmdb 没有这个字段）
    pub isp: String,
    /// ASN 与骨干网描述，如 `AS4837 CHINA UNICOM China169 Backbone`
    pub asn: String,
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
    /// 城市标签（如 `湖南 · 长沙`），供连线图 tooltip 展示
    #[serde(default)]
    pub name: String,
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
    /// 连线目的地（本节点）坐标，科技连线地图的汇聚点
    pub dest_lat: f64,
    pub dest_lon: f64,
}

/// GeoIP 运行状态。
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoStatus {
    pub enabled: bool,
    pub path: String,
    pub error: Option<String>,
    pub cached_ips: usize,
    /// 在线补充查询（运营商 / ASN / 城市补全）已缓存的 IP 数
    pub online_cached: usize,
}

/// 在线 API 返回的归属地补充信息，也是持久化缓存的条目。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct OnlineEntry {
    #[serde(default)]
    country: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    province: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    latitude: f64,
    #[serde(default)]
    longitude: f64,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    asn: String,
}

/// ip-api.com 批量接口的单条响应。
#[derive(Debug, Deserialize)]
struct IpApiItem {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "countryCode")]
    country_code: String,
    #[serde(default, rename = "regionName")]
    region_name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    org: String,
    #[serde(default, rename = "as")]
    asn: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default)]
    query: String,
}

/// 在线补充查询的缓存与熔断状态。
///
/// 与 mmdb 缓存分开加锁：网络请求期间两边互不阻塞。
#[derive(Default)]
struct OnlineState {
    /// IP → 在线补充信息。查过但没查到的也存空条目，避免反复重查
    map: HashMap<IpAddr, OnlineEntry>,
    /// 熔断截止时刻（单调时钟）。失败后一段时间内不再发在线请求
    cooldown_until: Option<std::time::Instant>,
    /// 持久化缓存文件路径。`None` 表示只存内存
    path: Option<PathBuf>,
    /// 关闭在线请求（测试 / 离线环境）。缓存仍可读
    disabled: bool,
}

/// GeoIP 查询器。由控制台持有，代理不感知。
pub struct GeoIp {
    inner: RwLock<Inner>,
    /// 在线补充查询（运营商 / ASN / 城市补全）的缓存与熔断状态
    online: Mutex<OnlineState>,
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
            online: Mutex::new(OnlineState::default()),
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
        let online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        GeoStatus {
            enabled: inner.reader.is_some(),
            path: inner.path.clone(),
            error: inner.error.clone(),
            cached_ips: inner.cache.len(),
            online_cached: online.map.len(),
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

    /// 设置在线补充查询的持久化缓存文件（放在数据目录），启动时调用一次。
    ///
    /// 已有缓存直接加载，重启后不重复请求在线 API。
    pub fn set_online_cache(&self, dir: &Path) {
        let path = dir.join(ONLINE_CACHE_FILE);
        let loaded = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<HashMap<IpAddr, OnlineEntry>>(&b).ok());
        let mut online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(map) = loaded {
            online.map = map;
        }
        online.path = Some(path);
    }

    /// 开关在线补充查询。关闭后只用本地结果（测试 / 离线环境用），缓存仍可读。
    pub fn set_online_enabled(&self, enabled: bool) {
        let mut online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        online.disabled = !enabled;
    }

    /// 批量查询详细归属地：mmdb 基础信息 + 在线补充运营商 / ASN（机房）与缺失的城市。
    ///
    /// 返回数组与 `ips` 一一对应。内网 / 保留地址返回 `None`。
    /// 在线查询失败时静默降级为 mmdb 结果（或 `None`），不影响页面加载。
    pub fn lookup_detailed_batch(&self, ips: &[IpAddr]) -> Vec<Option<GeoInfo>> {
        // mmdb 快路径：纯本地，结果缓存在 inner.cache
        let bases: Vec<Option<GeoInfo>> = ips.iter().map(|ip| self.lookup(*ip)).collect();

        // 收集缺少在线补充的公网 IP（去重），一次性批量查询
        let mut need: Vec<IpAddr> = Vec::new();
        let (cooled, disabled) = {
            let online = self.online.lock().unwrap_or_else(|e| e.into_inner());
            for ip in ips {
                if is_public(*ip) && !online.map.contains_key(ip) && !need.contains(ip) {
                    need.push(*ip);
                }
            }
            (
                online
                    .cooldown_until
                    .is_some_and(|t| std::time::Instant::now() < t),
                online.disabled,
            )
        };
        if !need.is_empty() && !cooled && !disabled {
            self.fetch_and_cache(&need);
        }

        let online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        ips.iter()
            .zip(bases)
            .map(|(ip, base)| merged(base, online.map.get(ip)))
            .collect()
    }

    /// 批量拉取在线归属地并写入缓存。失败进入熔断，只影响在线补充字段。
    fn fetch_and_cache(&self, ips: &[IpAddr]) {
        let mut fetched: Vec<(IpAddr, OnlineEntry)> = Vec::new();
        let mut ok = true;
        for chunk in ips.chunks(ONLINE_BATCH_CAP) {
            match fetch_online(chunk) {
                Ok(mut entries) => fetched.append(&mut entries),
                Err(e) => {
                    ok = false;
                    tracing::warn!(error = %e, "IP 归属地在线查询失败，进入冷却降级");
                    break;
                }
            }
        }

        let mut online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        online.cooldown_until = if ok {
            None
        } else {
            Some(std::time::Instant::now() + ONLINE_COOLDOWN)
        };
        if !ok && fetched.is_empty() {
            return;
        }
        if online.map.len() + fetched.len() >= ONLINE_CACHE_CAP {
            online.map.clear();
        }
        // 请求过但没返回的 IP 记空条目，避免每次翻页都重查
        for ip in ips {
            online.map.entry(*ip).or_default();
        }
        for (ip, entry) in fetched {
            online.map.insert(ip, entry);
        }
        save_online_cache(&online);
    }

    /// 在统计快照上批量解析 IP 归属地。
    pub fn resolve(&self, ips: &[(IpAddr, u32)]) -> GeoStats {
        let status = self.status();
        let mut stats = GeoStats {
            available: status.enabled,
            path: status.path,
            error: status.error,
            total_ips: ips.len(),
            dest_lat: DEFAULT_DEST.0,
            dest_lon: DEFAULT_DEST.1,
            ..Default::default()
        };
        if !stats.available {
            return stats;
        }

        let mut countries: HashMap<String, u64> = HashMap::new();
        let mut provinces: HashMap<String, u64> = HashMap::new();
        let mut cities: HashMap<String, u64> = HashMap::new();
        // 网格 → (请求数, 城市标签)。ips 按次数降序进入，首个非空标签就是该网格的代表城市
        let mut points: HashMap<(i64, i64), (u64, String)> = HashMap::new();

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
                let slot = points.entry(key).or_default();
                slot.0 += count;
                if slot.1.is_empty() {
                    slot.1 = point_label(&info);
                }
            }
        }

        stats.countries = top(countries);
        stats.provinces = top(provinces);
        stats.cities = top(cities);

        let mut points: Vec<GeoPoint> = points
            .into_iter()
            .map(|((lat, lon), (count, name))| GeoPoint {
                latitude: lat as f64 / 100.0,
                longitude: lon as f64 / 100.0,
                count,
                name,
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
        ..Default::default()
    }
}

/// 在线条目转基础地理信息。
fn from_online(e: &OnlineEntry) -> GeoInfo {
    GeoInfo {
        country: e.country.clone(),
        country_code: e.country_code.clone(),
        province: e.province.clone(),
        city: e.city.clone(),
        latitude: e.latitude,
        longitude: e.longitude,
        isp: e.isp.clone(),
        asn: e.asn.clone(),
    }
}

/// 合并 mmdb 结果与在线补充：mmdb 非空字段优先，在线补空缺；
/// 运营商 / ASN 只有在线接口有，始终取在线值。
fn merged(base: Option<GeoInfo>, online: Option<&OnlineEntry>) -> Option<GeoInfo> {
    match (base, online) {
        (None, None) => None,
        (Some(base), None) => Some(base),
        (None, Some(o)) => Some(from_online(o)),
        (Some(mut base), Some(o)) => {
            if base.country.is_empty() {
                base.country = o.country.clone();
            }
            if base.country_code.is_empty() {
                base.country_code = o.country_code.clone();
            }
            if base.province.is_empty() {
                base.province = o.province.clone();
            }
            if base.city.is_empty() {
                base.city = o.city.clone();
            }
            if base.latitude == 0.0 && base.longitude == 0.0 {
                base.latitude = o.latitude;
                base.longitude = o.longitude;
            }
            base.isp = o.isp.clone();
            base.asn = o.asn.clone();
            Some(base)
        }
    }
}

/// 上游 CDN（阿里云 ESA「托管转换」）注入的访问者位置头：`ali-ip-country`
/// （ISO 3166-1 Alpha-2，如 `CN`）与 `ali-ip-city`（城市名，如 `Changsha`），
/// `ali-ip-province` 可由自定义规则补充。
///
/// 这些头由边缘节点按真实客户端 IP 查库后注入，经 CDN 时会覆盖客户端伪造的
/// 同名头，比 mmdb / 在线 API 更准——国内 IPv6 的 mmdb 城市经常错或缺。
///
/// `headers` 是事件落库的扁平快照（`name: value` 逐行）；`secret_header` 是
/// 「真实 IP」设置里的回源密钥头名（可为空）。采信前提是请求确实过了可信链路：
/// 密钥头在场（头名即秘密，外人不知道头名），或 `cdn-loop` 带 `esa`
/// （能证明过了 ESA 边缘）。两者都没有则不采信，防直连伪造归属地。
///
/// 返回的 [`GeoInfo`] 只带码 / 省 / 市，展示名由 [`overlay_upstream`] 负责补。
pub fn upstream_geo(headers: &str, secret_header: &str) -> Option<GeoInfo> {
    let secret = secret_header.trim();
    let mut trusted = false;
    let mut country_code = String::new();
    let mut province = String::new();
    let mut city = String::new();

    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if !secret.is_empty() && name.eq_ignore_ascii_case(secret) {
            trusted = true;
            continue;
        }
        match name.to_ascii_lowercase().as_str() {
            "cdn-loop" => {
                if value
                    .split(';')
                    .any(|t| t.trim().eq_ignore_ascii_case("esa"))
                {
                    trusted = true;
                }
            }
            "ali-ip-country" => country_code = value.to_ascii_uppercase(),
            "ali-ip-province" => province = value.to_string(),
            "ali-ip-city" => city = value.to_string(),
            _ => {}
        }
    }

    if !trusted || (country_code.is_empty() && city.is_empty()) {
        return None;
    }
    Some(GeoInfo {
        country_code,
        province,
        city,
        ..Default::default()
    })
}

/// 上游归属地头覆盖到 mmdb / 在线结果之上：国家码 / 省 / 市以上游为准；
/// 运营商 / ASN / 坐标上游没有，保留原值。国家名在国家码一致时沿用已有
/// 中文名（mmdb / 在线查出来的），否则按 [`country_display_name`] 码表补。
///
/// 城市被上游纠正时，旧省份多半也跟着错（mmdb 的国内 IPv6 整条都偏），
/// 除非上游另给了省份，否则一并清掉，宁缺毋错。
pub fn overlay_upstream(base: Option<GeoInfo>, upstream: Option<GeoInfo>) -> Option<GeoInfo> {
    let Some(u) = upstream else {
        return base;
    };
    let mut g = base.unwrap_or_default();
    if !u.country_code.is_empty() {
        let same = g.country_code.eq_ignore_ascii_case(&u.country_code);
        g.country_code = u.country_code;
        if !(same && !g.country.is_empty()) {
            g.country = country_display_name(&g.country_code);
        }
    }
    if !u.city.is_empty() {
        if !g.city.is_empty() && !g.city.eq_ignore_ascii_case(&u.city) && u.province.is_empty() {
            g.province.clear();
        }
        g.city = u.city;
    }
    if !u.province.is_empty() {
        g.province = u.province;
    }
    if g.country.is_empty()
        && g.country_code.is_empty()
        && g.province.is_empty()
        && g.city.is_empty()
    {
        return None;
    }
    Some(g)
}

/// 国家 / 地区码 → 展示名。只覆盖常见码，未知码原样展示。
fn country_display_name(code: &str) -> String {
    match code.to_ascii_uppercase().as_str() {
        "CN" => "中国",
        "HK" => "中国香港",
        "MO" => "中国澳门",
        "TW" => "中国台湾",
        "US" => "美国",
        "JP" => "日本",
        "KR" => "韩国",
        "SG" => "新加坡",
        "MY" => "马来西亚",
        "TH" => "泰国",
        "VN" => "越南",
        "ID" => "印尼",
        "IN" => "印度",
        "RU" => "俄罗斯",
        "DE" => "德国",
        "FR" => "法国",
        "GB" => "英国",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        "NL" => "荷兰",
        "BR" => "巴西",
        _ => code,
    }
    .to_string()
}

/// 调 ip-api.com 批量接口查一批 IP，返回成功条目。
fn fetch_online(ips: &[IpAddr]) -> Result<Vec<(IpAddr, OnlineEntry)>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(ONLINE_TIMEOUT))
        .build()
        .into();
    let body = serde_json::to_string(&ips.iter().map(|i| i.to_string()).collect::<Vec<_>>())
        .map_err(|e| format!("序列化查询参数失败：{e}"))?;
    let response = agent
        .post(ONLINE_BATCH_URL)
        .query("lang", "zh-CN")
        .query("fields", ONLINE_FIELDS)
        .header("content-type", "application/json")
        .send(body)
        .map_err(|e| format!("请求 {ONLINE_BATCH_URL} 失败：{e}"))?;
    let mut text = String::new();
    response
        .into_body()
        .into_reader()
        .take(ONLINE_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("读取响应失败：{e}"))?;
    if text.len() as u64 > ONLINE_MAX_BYTES {
        return Err("响应体超过上限".to_string());
    }
    let items: Vec<IpApiItem> =
        serde_json::from_str(&text).map_err(|e| format!("解析响应失败：{e}"))?;
    Ok(parse_online_items(items))
}

/// 把 ip-api.com 的响应映射成缓存条目。`status != success` 的条目跳过。
fn parse_online_items(items: Vec<IpApiItem>) -> Vec<(IpAddr, OnlineEntry)> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.status != "success" {
            tracing::debug!(ip = %item.query, message = %item.message, "在线归属地查询失败条目");
            continue;
        }
        let Ok(ip) = item.query.parse::<IpAddr>() else {
            continue;
        };
        let isp = if item.isp.is_empty() {
            item.org.clone()
        } else {
            item.isp.clone()
        };
        out.push((
            ip,
            OnlineEntry {
                country: item.country,
                country_code: item.country_code,
                province: item.region_name,
                city: item.city,
                latitude: item.lat,
                longitude: item.lon,
                isp,
                asn: item.asn,
            },
        ));
    }
    out
}

/// 把在线缓存写回磁盘（临时文件 + rename，避免半截文件）。
fn save_online_cache(state: &OnlineState) {
    let Some(path) = &state.path else {
        return;
    };
    let Ok(json) = serde_json::to_string(&state.map) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
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

/// 网格点的城市标签：`省 · 市`，退化到省 / 国家。
fn point_label(info: &GeoInfo) -> String {
    match (info.province.as_str(), info.city.as_str()) {
        ("", "") => info.country.clone(),
        (p, "") => p.to_string(),
        ("", c) => c.to_string(),
        (p, c) if p == c => p.to_string(),
        (p, c) => format!("{p} · {c}"),
    }
}

/// 解析 `纬度,经度`。空串 / 非法返回 [`DEFAULT_DEST`]。
pub fn parse_dest(raw: &str) -> (f64, f64) {
    let mut it = raw.trim().split(',').map(str::trim);
    let (Some(lat), Some(lon)) = (it.next(), it.next()) else {
        return DEFAULT_DEST;
    };
    match (lat.parse::<f64>(), lon.parse::<f64>()) {
        (Ok(lat), Ok(lon)) if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) => {
            (lat, lon)
        }
        _ => DEFAULT_DEST,
    }
}

/// 校验 `map_dest` 设置值。空串合法（用默认值），否则必须是合法的 `纬度,经度`。
pub fn validate_dest(raw: &str) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    let mut it = raw.trim().split(',').map(str::trim);
    let (Some(lat), Some(lon)) = (it.next(), it.next()) else {
        return Err("坐标格式应为「纬度,经度」，如 39.9042,116.4074".to_string());
    };
    match (lat.parse::<f64>(), lon.parse::<f64>()) {
        (Ok(lat), Ok(lon)) if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) => {
            Ok(())
        }
        _ => Err("坐标必须是合法的「纬度,经度」（纬度 ±90、经度 ±180）".to_string()),
    }
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

    // ---------- 在线补充（运营商 / ASN / 城市补全） ----------

    fn online_entry() -> OnlineEntry {
        OnlineEntry {
            country: "中国".to_string(),
            country_code: "CN".to_string(),
            province: "北京市".to_string(),
            city: "西城区".to_string(),
            latitude: 39.9,
            longitude: 116.33,
            isp: "China Unicom Network".to_string(),
            asn: "AS4837 CHINA UNICOM China169 Backbone".to_string(),
        }
    }

    #[test]
    fn merge_fills_missing_city_and_isp_from_online() {
        // 国内 IPv6 典型情况：mmdb 有国家/省但缺城市，运营商/ASN 只有在线接口有
        let base = GeoInfo {
            country: "中国".to_string(),
            country_code: "CN".to_string(),
            province: "北京市".to_string(),
            ..Default::default()
        };
        let got = merged(Some(base), Some(&online_entry())).unwrap();
        assert_eq!(got.city, "西城区");
        assert_eq!(got.province, "北京市");
        assert_eq!(got.isp, "China Unicom Network");
        assert_eq!(got.asn, "AS4837 CHINA UNICOM China169 Backbone");
        assert_eq!(got.latitude, 39.9);
    }

    #[test]
    fn merge_prefers_mmdb_fields_over_online() {
        let base = GeoInfo {
            country: "中国".to_string(),
            province: "上海市".to_string(),
            city: "浦东新区".to_string(),
            latitude: 31.2,
            longitude: 121.6,
            ..Default::default()
        };
        let got = merged(Some(base), Some(&online_entry())).unwrap();
        assert_eq!(got.province, "上海市");
        assert_eq!(got.city, "浦东新区");
        assert_eq!(got.latitude, 31.2);
        // 运营商/ASN 仍然取在线值
        assert_eq!(got.isp, "China Unicom Network");
    }

    #[test]
    fn merge_online_only_when_mmdb_misses() {
        let got = merged(None, Some(&online_entry())).unwrap();
        assert_eq!(got.city, "西城区");
        assert_eq!(got.isp, "China Unicom Network");
        assert_eq!(merged(None, None), None);
    }

    #[test]
    fn parse_online_items_maps_fields_and_skips_failures() {
        let items: Vec<IpApiItem> = serde_json::from_str(
            r#"[{"status":"success","country":"中国","countryCode":"CN","regionName":"北京市","city":"西城区","isp":"China Unicom Network","org":"","as":"AS4837 CHINA UNICOM China169 Backbone","lat":39.9,"lon":116.33,"query":"2408:8352:e40:4faa:a113:a416:63e6:73b7"},{"status":"fail","message":"private range","query":"10.0.0.1"},{"status":"success","country":"美国","countryCode":"US","regionName":"","city":"","isp":"","org":"Amazon.com","as":"AS16509 AMAZON-02","lat":0.0,"lon":0.0,"query":"8.8.8.8"}]"#,
        )
        .expect("样本响应可解析");
        let out = parse_online_items(items);
        assert_eq!(out.len(), 2, "fail 条目被跳过");

        let (ip, e) = &out[0];
        assert_eq!(ip.to_string(), "2408:8352:e40:4faa:a113:a416:63e6:73b7");
        assert_eq!(e.province, "北京市");
        assert_eq!(e.city, "西城区");
        assert_eq!(e.isp, "China Unicom Network");
        assert_eq!(e.asn, "AS4837 CHINA UNICOM China169 Backbone");

        // isp 为空时回退 org
        let (_, e2) = &out[1];
        assert_eq!(e2.isp, "Amazon.com");
        assert_eq!(e2.asn, "AS16509 AMAZON-02");
    }

    #[test]
    fn detailed_batch_reads_cache_without_network() {
        let dir = std::env::temp_dir().join(format!("homewaf-geoip-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ip: IpAddr = "2408:8352:e40:4faa:a113:a416:63e6:73b7".parse().unwrap();
        let mut map = HashMap::new();
        map.insert(ip, online_entry());
        std::fs::write(
            dir.join(ONLINE_CACHE_FILE),
            serde_json::to_string(&map).unwrap(),
        )
        .unwrap();

        let g = GeoIp::new();
        g.set_online_cache(&dir);
        // 显式关闭在线请求：命中缓存仍可用，miss 不发网络
        g.set_online_enabled(false);
        assert_eq!(g.status().online_cached, 1);

        // 命中缓存 → 不发在线请求；mmdb 未启用 → 全部字段来自在线条目
        let got = g.lookup_detailed_batch(&[ip, "192.168.1.5".parse().unwrap()]);
        assert_eq!(got.len(), 2);
        let info = got[0].clone().expect("缓存命中应返回归属地");
        assert_eq!(info.city, "西城区");
        assert_eq!(info.isp, "China Unicom Network");
        assert_eq!(info.asn, "AS4837 CHINA UNICOM China169 Backbone");
        assert!(got[1].is_none(), "内网地址不查询");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geo_status_reports_online_cache() {
        let g = GeoIp::new();
        assert_eq!(g.status().online_cached, 0);
    }

    // ---------- 连线目的地 ----------

    #[test]
    fn parse_dest_handles_valid_and_invalid() {
        assert_eq!(parse_dest("39.9042,116.4074"), (39.9042, 116.4074));
        assert_eq!(parse_dest(" 31.23 , 121.47 "), (31.23, 121.47));
        // 空 / 非法都回落默认（北京），不让地图画到几内亚湾
        assert_eq!(parse_dest(""), DEFAULT_DEST);
        assert_eq!(parse_dest("abc,def"), DEFAULT_DEST);
        assert_eq!(parse_dest("91,116"), DEFAULT_DEST);
        assert_eq!(parse_dest("39.9"), DEFAULT_DEST);
    }

    #[test]
    fn validate_dest_accepts_empty_and_real_coords() {
        assert!(validate_dest("").is_ok());
        assert!(validate_dest("  ").is_ok());
        assert!(validate_dest("39.9042,116.4074").is_ok());
        assert!(validate_dest("-33.86,151.20").is_ok());
        assert!(validate_dest("abc").is_err());
        assert!(validate_dest("91,116").is_err());
        assert!(validate_dest("39,200").is_err());
    }

    #[test]
    fn point_label_falls_back_to_province_or_country() {
        let mk = |province: &str, city: &str, country: &str| GeoInfo {
            province: province.to_string(),
            city: city.to_string(),
            country: country.to_string(),
            ..Default::default()
        };
        assert_eq!(point_label(&mk("湖南", "长沙", "中国")), "湖南 · 长沙");
        assert_eq!(point_label(&mk("湖南", "湖南", "中国")), "湖南");
        assert_eq!(point_label(&mk("湖南", "", "中国")), "湖南");
        assert_eq!(point_label(&mk("", "西城区", "中国")), "西城区");
        assert_eq!(point_label(&mk("", "", "中国")), "中国");
    }

    // ---------- 上游 CDN 归属地头（ali-ip-*） ----------

    #[test]
    fn upstream_geo_parses_country_and_city() {
        let headers = "accept: application/dns-message\n\
            cdn-loop: esa;loop=1\n\
            ali-ip-country: CN\n\
            ali-ip-city: Changsha\n\
            xxxxxxx-real-forwarded-for: 2408:8352:e40:4faa::1\n";
        let g = upstream_geo(headers, "xxxxxxx-Real-Forwarded-For").expect("应解析出上游归属地");
        assert_eq!(g.country_code, "CN");
        assert_eq!(g.city, "Changsha");
        assert_eq!(g.province, "");
        assert_eq!(g.country, "", "展示名由 overlay_upstream 决定");
    }

    #[test]
    fn upstream_geo_requires_trust_evidence() {
        let forged = "ali-ip-country: CN\nali-ip-city: Changsha\n";
        assert_eq!(
            upstream_geo(forged, ""),
            None,
            "没有 cdn-loop / 密钥头，直连伪造不采信"
        );
        assert_eq!(
            upstream_geo(forged, "xxxxxxx-Real-Forwarded-For"),
            None,
            "配了密钥头但请求没带，不采信"
        );
        // cdn-loop 带 esa 即可信（请求确实过了 ESA 边缘）
        let via_esa = "cdn-loop: esa;loop=1\nali-ip-country: CN\nali-ip-city: Changsha\n";
        assert!(upstream_geo(via_esa, "").is_some());
        assert!(upstream_geo(via_esa, "X-Key").is_some());
        // 密钥头在场也可信（头名即秘密）
        let via_secret =
            "xxxxxxx-real-forwarded-for: 1.2.3.4\nali-ip-country: CN\nali-ip-city: Changsha\n";
        assert!(upstream_geo(via_secret, "xxxxxxx-Real-Forwarded-For").is_some());
        // 可信但没有归属地头 → None
        assert_eq!(upstream_geo("cdn-loop: esa;loop=1\n", ""), None);
    }

    #[test]
    fn overlay_upstream_corrects_city_and_keeps_isp() {
        // mmdb 把国内 IPv6 错解成北京，上游头给出真实城市
        let base = GeoInfo {
            country: "中国".to_string(),
            country_code: "CN".to_string(),
            province: "北京".to_string(),
            city: "北京".to_string(),
            isp: "中国联通".to_string(),
            asn: "AS4837 CHINA UNICOM".to_string(),
            ..Default::default()
        };
        let upstream = GeoInfo {
            country_code: "CN".to_string(),
            city: "Changsha".to_string(),
            ..Default::default()
        };
        let g = overlay_upstream(Some(base), Some(upstream)).unwrap();
        assert_eq!(g.country, "中国", "国家码一致时沿用中文名");
        assert_eq!(g.city, "Changsha");
        assert_eq!(g.province, "", "城市被纠正时旧省份一并清掉");
        assert_eq!(g.isp, "中国联通", "运营商 / ASN 上游没有，保留");
    }

    #[test]
    fn overlay_upstream_keeps_province_when_city_was_missing() {
        // mmdb 只有省没市：省份大概率对，只补城市，不动省份
        let base = GeoInfo {
            country: "中国".to_string(),
            country_code: "CN".to_string(),
            province: "湖南".to_string(),
            ..Default::default()
        };
        let upstream = GeoInfo {
            country_code: "CN".to_string(),
            city: "Changsha".to_string(),
            ..Default::default()
        };
        let g = overlay_upstream(Some(base), Some(upstream)).unwrap();
        assert_eq!(g.province, "湖南");
        assert_eq!(g.city, "Changsha");
    }

    #[test]
    fn overlay_upstream_handles_missing_sides() {
        let upstream = GeoInfo {
            country_code: "CN".to_string(),
            city: "Changsha".to_string(),
            ..Default::default()
        };
        // 没有基线（mmdb / 在线都没查到）也能靠上游头出归属地
        let g = overlay_upstream(None, Some(upstream.clone())).unwrap();
        assert_eq!(g.country, "中国");
        assert_eq!(g.country_code, "CN");
        assert_eq!(g.city, "Changsha");
        // 没有上游头则维持原结果
        let base = GeoInfo {
            city: "北京".to_string(),
            ..Default::default()
        };
        assert_eq!(overlay_upstream(Some(base.clone()), None), Some(base));
        assert_eq!(overlay_upstream(None, None), None);
    }

    /// 真实网络集成测试（默认忽略）：`cargo test -p homewaf-admin -- --ignored` 手动跑。
    /// 验证 ip-api.com 批量接口连通、响应解析与 IPv6 城市 / 运营商补全。
    #[test]
    #[ignore = "需要外网，手动运行"]
    fn online_lookup_real_network() {
        let g = GeoIp::new();
        let ip: IpAddr = "2408:8352:e40:4faa:a113:a416:63e6:73b7".parse().unwrap();
        let got = g.lookup_detailed_batch(&[ip, "42.48.101.219".parse().unwrap()]);
        let info = got[0].clone().expect("IPv6 在线查询应返回归属地");
        assert!(
            info.country.contains("中国") || info.country_code == "CN",
            "国家字段：{info:?}"
        );
        assert!(!info.city.is_empty(), "IPv6 应能定位到城市：{info:?}");
        assert!(
            !info.isp.is_empty() || !info.asn.is_empty(),
            "应有运营商 / ASN：{info:?}"
        );
        let v4 = got[1].clone().expect("IPv4 在线查询应返回归属地");
        assert!(
            !v4.asn.is_empty() || !v4.isp.is_empty(),
            "IPv4 应有机房信息：{v4:?}"
        );
    }
}
