//! HomeWAF 管理 API 与 Web 控制台。
//!
//! 设计取舍：
//! - **API 与前端同一个 crate**，前端是嵌入二进制的静态文件，没有构建步骤
//! - **认证用 Bearer token**，未配置 token 时只允许回环访问（家用默认安全）
//! - **写操作后显式触发重载**，这是 DB 模式补回热重载的唯一途径

pub mod geoip;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use homewaf_acl::BanTable;
use homewaf_config::Application;
use homewaf_proxy::{RuntimeState, SharedState, TrafficMetrics};
use homewaf_store::{AclRuleRow, Store};
use serde::{Deserialize, Serialize};

/// 管理服务的共享状态。
pub struct AdminState {
    pub store: Arc<Store>,
    pub shared: SharedState,
    pub bans: Arc<BanTable>,
    pub metrics: Arc<TrafficMetrics>,
    /// GeoIP 查询器。只在控制台聚合快照时使用，代理热路径不查库
    pub geoip: Arc<geoip::GeoIp>,
    pub allow_regex: bool,
    /// 认证 token。`None` 时只允许回环访问
    pub token: Option<String>,
    /// 日志根目录，用于控制台的日志查看
    pub log_dir: std::path::PathBuf,
    /// 进程启动时间（Unix 秒），用于系统页展示运行时长
    pub started_at: i64,
}

type Ctx = Arc<AdminState>;

/// 统一错误类型。
type ApiError = (StatusCode, String);

fn internal(e: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "需要认证").into_response()
}

/// 校验请求是否被允许。
///
/// 配了 token 就比对 token；没配 token 时只信任回环地址——
/// 家用场景下管理面本来就不该暴露到局域网。
fn authorized(state: &AdminState, headers: &HeaderMap) -> bool {
    match &state.token {
        Some(expected) => headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == expected)
            .unwrap_or(false),
        // 无 token：依赖监听地址是回环（启动时已校验），这里放行
        None => true,
    }
}

/// 构造路由。
pub fn router(state: Ctx) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/stats", get(stats))
        .route("/api/stats/geo", get(geo_stats))
        .route("/api/security", get(security))
        .route("/api/reports", get(list_reports))
        .route("/api/reports/{day}", get(report_detail))
        .route("/api/reports/{day}/csv", get(report_csv))
        .route("/api/screen", get(screen))
        .route("/api/attack/overview", get(attack_overview))
        .route("/api/geoip", get(geoip_status))
        .route("/api/apps", get(list_apps).post(upsert_app))
        .route("/api/apps/{id}", get(get_app).delete(delete_app))
        .route("/api/apps/{id}/enabled", post(set_app_enabled))
        .route("/api/apps/{id}/features", post(set_app_features))
        .route("/api/apps/{id}/tamper", get(get_app_tamper))
        .route("/api/apps/{id}/tamper/baseline", post(build_app_tamper_baseline))
        .route("/api/apps/{id}/tamper/scan", post(scan_app_tamper))
        .route("/api/rules", get(list_rules).post(upsert_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/bans", get(list_bans).post(create_ban))
        .route("/api/bans/{ip}", delete(unban))
        .route("/api/events", get(list_events))
        .route("/api/events/export", get(export_events))
        .route("/api/logs", get(list_logs))
        .route("/api/feeds", get(list_feeds).post(upsert_feed))
        .route("/api/feeds/{name}", delete(delete_feed))
        .route("/api/feeds/{name}/refresh", post(refresh_feed))
        .route(
            "/api/rule-feeds",
            get(list_rule_feeds).post(upsert_rule_feed),
        )
        .route("/api/rule-feeds/{name}", delete(delete_rule_feed))
        .route(
            "/api/rule-feeds/{name}/refresh",
            post(refresh_rule_feed),
        )
        .route("/api/whitelist", get(list_whitelist).post(upsert_whitelist))
        .route("/api/whitelist/{id}", delete(delete_whitelist))
        .route("/api/settings", get(get_all_settings))
        .route("/api/settings/{key}", get(get_setting).put(put_setting))
        .route("/api/system/info", get(system_info))
        .route("/api/system/backup", get(system_backup))
        .route("/api/system/prune", post(system_prune))
        .route(
            "/api/custom-rules",
            get(list_custom_rules).post(import_custom_rules),
        )
        .route("/api/custom-rules/export", get(export_custom_rules))
        .route("/api/reload", post(reload))
        .with_state(state)
}

/// 启动管理服务（独立线程 + 独立 tokio runtime）。
pub fn spawn(state: AdminState, listen: String) -> anyhow::Result<()> {
    // 没配 token 时强制只监听回环，避免管理面裸奔在局域网
    if state.token.is_none() {
        let addr: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("管理面监听地址非法：{listen}（{e}）"))?;
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "管理面监听 {listen} 不是回环地址，但未配置 admin token。\
                 请设置 token 或改为 127.0.0.1"
            );
        }
    }

    // 启动前加载 GeoIP。失败只告警，不影响控制台其它功能
    state.geoip.reload_from_store(&state.store);
    let geo = state.geoip.status();
    match (&geo.error, geo.enabled) {
        (Some(err), _) => tracing::warn!(path = %geo.path, error = %err, "GeoIP 数据库加载失败"),
        (None, true) => tracing::info!(path = %geo.path, "GeoIP 数据库已加载"),
        (None, false) => {}
    }

    let ctx = Arc::new(state);
    std::thread::Builder::new()
        .name("homewaf-admin".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "创建管理面 runtime 失败");
                    return;
                }
            };

            rt.block_on(async move {
                spawn_rule_feed_scheduler(ctx.clone());

                let listener = match tokio::net::TcpListener::bind(&listen).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(listen, error = %e, "管理面绑定失败");
                        return;
                    }
                };
                tracing::info!(listen, "控制台已启动");
                if let Err(e) = axum::serve(listener, router(ctx)).await {
                    tracing::error!(error = %e, "管理面退出");
                }
            });
        })?;

    Ok(())
}

// ============================================================
// 页面
// ============================================================

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

// ============================================================
// 概览
// ============================================================

#[derive(Serialize)]
struct Stats {
    apps: usize,
    upstreams: usize,
    acl_rules: usize,
    active_bans: usize,
    events_total: usize,
    events_blocked: usize,
    detect_rules: usize,
    observe_mode: bool,
    /// 最近 24 小时按小时聚合：时间戳、总数、拦截数
    hourly: Vec<HourBucket>,
    /// 最近 24 小时的攻击类型分布
    categories: Vec<CategoryCount>,
    /// 本次查询的时间范围（秒）
    range: i64,
    /// 本次查询的应用过滤
    app: Option<String>,
    /// 流量看板完整数据，供统计报表「流量分析」页签使用
    traffic: homewaf_proxy::TrafficDashboard,
}

#[derive(Serialize)]
struct HourBucket {
    ts: i64,
    total: usize,
    blocked: usize,
}

#[derive(Serialize)]
struct CategoryCount {
    name: String,
    count: usize,
}

async fn stats(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let state = ctx.shared.load_full();
    let now = homewaf_acl::now_unix();
    let range = q.range.unwrap_or(86_400).clamp(60, 86_400);
    let app = norm_app(&q.app);

    let events_blocked = ctx
        .store
        .query_events(&homewaf_store::EventFilter {
            limit: 0,
            action: Some("block".to_string()),
            ..Default::default()
        })
        .map(|(_, total)| total)
        .unwrap_or(0);

    let now_hour = now - now.rem_euclid(3_600);
    let start = now_hour - 23 * 3_600;
    let mut hourly: Vec<HourBucket> = (0..24)
        .map(|i| HourBucket {
            ts: start + i * 3_600,
            total: 0,
            blocked: 0,
        })
        .collect();

    // 分桶统计交给 SQLite，避免每 5 秒轮询都把上万条事件搬进内存。
    for (ts, total, blocked) in ctx.store.hourly_event_counts(start).unwrap_or_default() {
        let idx = ((ts - start) / 3_600).clamp(0, 23) as usize;
        hourly[idx].total += total;
        hourly[idx].blocked += blocked;
    }

    let categories = attack_categories(&state, &ctx.store, start, now + 1);
    let traffic = ctx.metrics.dashboard(range, app, now);

    Json(Stats {
        apps: state.router.len(),
        upstreams: state.upstream_count(),
        acl_rules: state.rule_count(),
        active_bans: ctx.bans.active_count(now.max(0) as u64),
        events_total: ctx.store.event_count().unwrap_or(0),
        events_blocked,
        detect_rules: state.detection_rule_count(),
        observe_mode: state.engine.is_observe_mode(),
        hourly,
        categories,
        range,
        app: app.map(str::to_string),
        traffic,
    })
    .into_response()
}

// ============================================================
// GeoIP / 地理分布
// ============================================================

#[derive(Deserialize)]
struct RangeQuery {
    /// 时间范围（秒），默认 24 小时
    #[serde(default)]
    range: Option<i64>,
    #[serde(default)]
    app: Option<String>,
    /// 地理聚合口径：`blocked` 只看被拦截的来源，其它值按全部请求
    #[serde(default)]
    mode: Option<String>,
}

/// 统一去掉空白的应用过滤，`""` 视为不过滤。
fn norm_app(app: &Option<String>) -> Option<&str> {
    app.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Serialize)]
struct NameCount {
    name: String,
    count: usize,
}

#[derive(Serialize)]
struct IpRow {
    ip: String,
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    geo: Option<geoip::GeoInfo>,
}

/// 安全态势趋势点：按事件类型分列。
#[derive(Default, Serialize)]
struct KindPoint {
    ts: i64,
    detect: usize,
    ban: usize,
    acl: usize,
    ratelimit: usize,
    challenge: usize,
}

/// 把事件命中的规则 id 映射成攻击类型分布。
///
/// 映射表取自当前生效的检测规则集，订阅规则也能正确归类。
fn attack_categories(
    state: &homewaf_proxy::RuntimeState,
    store: &Store,
    since: i64,
    until: i64,
) -> Vec<CategoryCount> {
    let matcher = state.engine.matcher();
    let rule_categories: std::collections::HashMap<&str, &str> = matcher
        .metas()
        .map(|r| (r.id.as_str(), r.category.as_str()))
        .collect();

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for rules in store
        .event_rule_strings_between(since, until, 50_000)
        .unwrap_or_default()
    {
        for rule in rules.split(',').filter(|s| !s.is_empty()) {
            let category = rule_categories
                .get(rule)
                .copied()
                .unwrap_or_else(|| if rule.starts_with("cc-") { "cc" } else { "other" });
            *counts.entry(category).or_insert(0) += 1;
        }
    }

    let mut out: Vec<CategoryCount> = counts
        .into_iter()
        .map(|(name, count)| CategoryCount {
            name: name.to_string(),
            count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    out.truncate(8);
    out
}

/// 规则命中排行。一个事件可能同时命中多条规则，逐条计数。
fn rule_hits(store: &Store, since: i64, until: i64, limit: usize) -> Vec<NameCount> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for rules in store
        .event_rule_strings_between(since, until, 50_000)
        .unwrap_or_default()
    {
        for rule in rules.split(',').filter(|s| !s.is_empty()) {
            *counts.entry(rule.to_string()).or_insert(0) += 1;
        }
    }
    let mut out: Vec<NameCount> = counts
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    out.truncate(limit);
    out
}

/// 给来源 IP 排行补上归属地。查库发生在控制台请求路径，不在代理热路径。
fn ip_rows(geoip: &geoip::GeoIp, pairs: &[(String, usize)]) -> Vec<IpRow> {
    pairs
        .iter()
        .map(|(ip, count)| IpRow {
            ip: ip.clone(),
            count: *count,
            geo: ip.parse::<IpAddr>().ok().and_then(|ip| geoip.lookup(ip)),
        })
        .collect()
}

/// 把 `(ip, 次数)` 转成地图聚合结果。
fn geo_stats_from(geoip: &geoip::GeoIp, pairs: &[(String, usize)]) -> geoip::GeoStats {
    let parsed: Vec<(IpAddr, u32)> = pairs
        .iter()
        .filter_map(|(ip, n)| ip.parse::<IpAddr>().ok().map(|ip| (ip, *n as u32)))
        .collect();
    geoip.resolve(&parsed)
}

/// 百分比，保留两位小数；分母为 0 时返回 0。
fn rate(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    ((part as f64) * 10_000.0 / (total as f64)).round() / 100.0
}

fn date_of(ts: i64) -> String {
    format_utc(ts).chars().take(10).collect()
}

async fn geoip_status(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    Json(ctx.geoip.status()).into_response()
}

/// 把指标快照里的 IP 批量解析成国家/城市/经纬度。
///
/// 查询发生在控制台请求路径上，不在代理热路径；结果只保留聚合值。
async fn geo_stats(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let range = q.range.unwrap_or(86_400).clamp(60, 86_400);
    let app = norm_app(&q.app);
    let now = homewaf_acl::now_unix();
    // 「仅拦截」口径取事件表里的攻击来源；与内存快照不同，它天然带着处置结果，
    // 也不受应用过滤影响（事件归属应用，但地图只看来源地区）。
    let stats = if q.mode.as_deref() == Some("blocked") {
        let pairs = ctx
            .store
            .top_event_ips(now - range + 1, now + 1, Some("block"), 500)
            .unwrap_or_default();
        geo_stats_from(&ctx.geoip, &pairs)
    } else {
        ctx.geoip.resolve(&ctx.metrics.dashboard(range, app, now).ips)
    };
    Json(stats).into_response()
}

// ============================================================
// 安全态势
// ============================================================

/// 安全态势最多回看 30 天，避免一张页面把整库扫一遍。
const SECURITY_MAX_RANGE: i64 = 30 * 86_400;

#[derive(Serialize)]
struct SecurityTotals {
    events: usize,
    blocked: usize,
    attack_ips: usize,
}

#[derive(Serialize)]
struct SecurityStats {
    generated_at: i64,
    range: i64,
    totals: SecurityTotals,
    /// 事件类型分布：detect / ban / acl / ratelimit / challenge
    kinds: Vec<NameCount>,
    /// 按类型拆分的趋势，供多线折线图
    series: Vec<KindPoint>,
    /// 按攻击类型（规则分类）分布
    categories: Vec<CategoryCount>,
    /// ACL 命中原因：黑名单、CIDR、方法限制等
    acl_reasons: Vec<NameCount>,
    /// 规则命中排行
    rules: Vec<NameCount>,
    /// 攻击来源排行（带归属地）
    top_ips: Vec<IpRow>,
    /// 实时事件流
    recent: Vec<homewaf_store::Event>,
}

async fn security(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let now = homewaf_acl::now_unix();
    let range = q.range.unwrap_or(86_400).clamp(60, SECURITY_MAX_RANGE);
    let since = now - range + 1;
    let until = now + 1;

    let kinds: Vec<NameCount> = ctx
        .store
        .event_kind_counts(since, until, None)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let blocked: usize = ctx
        .store
        .event_kind_counts(since, until, Some("block"))
        .unwrap_or_default()
        .iter()
        .map(|(_, n)| n)
        .sum();
    let events: usize = kinds.iter().map(|k| k.count).sum();
    let attack_ips = ctx
        .store
        .event_ip_count(since, until, Some("block"))
        .unwrap_or(0);

    let group = if range <= 3_600 {
        60
    } else if range <= 21_600 {
        300
    } else {
        3_600
    };
    let mut points: std::collections::BTreeMap<i64, KindPoint> = std::collections::BTreeMap::new();
    for (ts, kind, n) in ctx
        .store
        .event_series_by_kind(since, until, group)
        .unwrap_or_default()
    {
        let p = points.entry(ts).or_insert_with(|| KindPoint {
            ts,
            ..Default::default()
        });
        match kind.as_str() {
            "detect" => p.detect += n,
            "ban" => p.ban += n,
            "acl" => p.acl += n,
            "ratelimit" => p.ratelimit += n,
            "challenge" => p.challenge += n,
            _ => {}
        }
    }

    let state = ctx.shared.load_full();
    let categories = attack_categories(&state, &ctx.store, since, until);
    let acl_reasons = ctx
        .store
        .acl_reason_counts(since, until, 10)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let rules = rule_hits(&ctx.store, since, until, 10);
    let top = ctx
        .store
        .top_event_ips(since, until, None, 10)
        .unwrap_or_default();
    let top_ips = ip_rows(&ctx.geoip, &top);
    let recent = ctx
        .store
        .query_events(&homewaf_store::EventFilter {
            limit: 20,
            since: Some(since),
            ..Default::default()
        })
        .map(|(events, _)| events)
        .unwrap_or_default();

    Json(SecurityStats {
        generated_at: now,
        range,
        totals: SecurityTotals {
            events,
            blocked,
            attack_ips,
        },
        kinds,
        series: points.into_values().collect(),
        categories,
        acl_reasons,
        rules,
        top_ips,
        recent,
    })
    .into_response()
}

// ============================================================
// 攻击防护
// ============================================================

#[derive(Serialize)]
struct AttackTotals {
    events: usize,
    blocked: usize,
    attack_ips: usize,
    apps: usize,
    banned: usize,
}

#[derive(Serialize)]
struct AttackPoint {
    ts: i64,
    total: usize,
    blocked: usize,
}

#[derive(Serialize)]
struct AttackOverview {
    generated_at: i64,
    range: i64,
    totals: AttackTotals,
    series: Vec<AttackPoint>,
    /// 事件类型分布
    kinds: Vec<NameCount>,
    /// 处置动作分布
    actions: Vec<NameCount>,
    /// 攻击来源排行
    top_ips: Vec<IpRow>,
    /// 被攻击应用排行
    top_apps: Vec<NameCount>,
    /// 命中规则排行
    rules: Vec<NameCount>,
}

async fn attack_overview(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let now = homewaf_acl::now_unix();
    let range = q.range.unwrap_or(86_400).clamp(60, SECURITY_MAX_RANGE);
    let since = now - range + 1;
    let until = now + 1;

    let kinds: Vec<NameCount> = ctx
        .store
        .event_kind_counts(since, until, None)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let events: usize = kinds.iter().map(|k| k.count).sum();
    let blocked = ctx
        .store
        .event_kind_counts(since, until, Some("block"))
        .unwrap_or_default()
        .iter()
        .map(|(_, n)| *n)
        .sum();
    let attack_ips = ctx
        .store
        .event_ip_count(since, until, Some("block"))
        .unwrap_or(0);

    let group = if range <= 3_600 {
        60
    } else if range <= 21_600 {
        300
    } else {
        3_600
    };
    let series = ctx
        .store
        .event_series_counts(since, until, group)
        .unwrap_or_default()
        .into_iter()
        .map(|(ts, total, blocked)| AttackPoint {
            ts,
            total,
            blocked,
        })
        .collect::<Vec<_>>();
    let actions = ctx
        .store
        .event_action_counts(since, until)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let top = ctx
        .store
        .top_event_ips(since, until, None, 10)
        .unwrap_or_default();
    let top_ips = ip_rows(&ctx.geoip, &top);
    let app_counts = ctx
        .store
        .event_app_counts(since, until, None, 10)
        .unwrap_or_default();
    let apps = app_counts.len();
    let top_apps = app_counts
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let rules = rule_hits(&ctx.store, since, until, 10);
    let banned = ctx
        .store
        .load_active_bans(now)
        .map(|b| b.len())
        .unwrap_or(0);

    Json(AttackOverview {
        generated_at: now,
        range,
        totals: AttackTotals {
            events,
            blocked,
            attack_ips,
            apps,
            banned,
        },
        series,
        kinds,
        actions,
        top_ips,
        top_apps,
        rules,
    })
    .into_response()
}

// ============================================================
// 防护报告
// ============================================================

#[derive(Deserialize)]
struct ReportsQuery {
    /// 回看天数，默认 30
    #[serde(default)]
    days: Option<i64>,
}

#[derive(Deserialize)]
struct ReportQuery {
    #[serde(default)]
    app: Option<String>,
}

#[derive(Serialize)]
struct ReportSummary {
    /// 报告 id 就是当天 00:00 的 Unix 时间戳
    id: i64,
    date: String,
    requests: u64,
    blocked: u64,
    events: usize,
    block_rate: f64,
}

#[derive(Serialize)]
struct ReportDetail {
    id: i64,
    date: String,
    app: Option<String>,
    generated_at: i64,
    totals: homewaf_store::TrafficTotals,
    block_rate: f64,
    four_xx_rate: f64,
    five_xx_rate: f64,
    /// 按小时拆分的请求 / 拦截趋势
    series: Vec<homewaf_store::TrafficPoint>,
    kinds: Vec<NameCount>,
    categories: Vec<CategoryCount>,
    acl_reasons: Vec<NameCount>,
    rules: Vec<NameCount>,
    top_ips: Vec<IpRow>,
    geo: geoip::GeoStats,
}

async fn list_reports(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<ReportsQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let days = q.days.unwrap_or(30).clamp(1, 365);
    let now = homewaf_acl::now_unix();
    let since = now - days * 86_400;

    let mut by_day: std::collections::BTreeMap<i64, ReportSummary> =
        std::collections::BTreeMap::new();
    for d in ctx.store.traffic_days(since, 400).unwrap_or_default() {
        let entry = by_day.entry(d.day).or_insert(ReportSummary {
            id: d.day,
            date: date_of(d.day),
            requests: 0,
            blocked: 0,
            events: 0,
            block_rate: 0.0,
        });
        entry.requests = d.requests;
        entry.blocked = d.blocked;
    }
    for (day, _kind, n) in ctx.store.daily_event_counts(since).unwrap_or_default() {
        let entry = by_day.entry(day).or_insert(ReportSummary {
            id: day,
            date: date_of(day),
            requests: 0,
            blocked: 0,
            events: 0,
            block_rate: 0.0,
        });
        entry.events += n;
    }

    let mut reports: Vec<ReportSummary> = by_day.into_values().collect();
    for r in &mut reports {
        r.block_rate = rate(r.blocked, r.requests);
    }
    reports.sort_by_key(|a| std::cmp::Reverse(a.id));

    Json(serde_json::json!({"reports": reports})).into_response()
}

/// 汇总某一天的报告数据。`day` 会向下对齐到自然日。
fn build_report(
    ctx: &AdminState,
    day: i64,
    app: Option<&str>,
) -> Result<ReportDetail, homewaf_store::StoreError> {
    let day = day - day.rem_euclid(86_400);
    let until = day + 86_400;
    let totals = ctx.store.traffic_totals(day, until, app)?;
    let series = ctx.store.traffic_series(day, until, app, 3_600)?;
    let kinds: Vec<NameCount> = ctx
        .store
        .event_kind_counts(day, until, None)?
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let state = ctx.shared.load_full();
    let categories = attack_categories(&state, &ctx.store, day, until);
    let acl_reasons = ctx
        .store
        .acl_reason_counts(day, until, 10)?
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let rules = rule_hits(&ctx.store, day, until, 10);
    let top = ctx.store.top_event_ips(day, until, None, 50)?;
    let top_ips = ip_rows(&ctx.geoip, &top);
    let geo = geo_stats_from(&ctx.geoip, &ctx.store.top_event_ips(day, until, None, 200)?);

    Ok(ReportDetail {
        id: day,
        date: date_of(day),
        app: app.map(str::to_string),
        generated_at: homewaf_acl::now_unix(),
        block_rate: rate(totals.blocked, totals.requests),
        four_xx_rate: rate(totals.status_4xx, totals.requests),
        five_xx_rate: rate(totals.status_5xx, totals.requests),
        totals,
        series,
        kinds,
        categories,
        acl_reasons,
        rules,
        top_ips,
        geo,
    })
}

async fn report_detail(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(day): Path<i64>,
    Query(q): Query<ReportQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let app = norm_app(&q.app);
    match build_report(&ctx, day, app) {
        Ok(report) => Json(report).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// 报告导出为 CSV，包含汇总、趋势、攻击类型、来源、规则与名单命中。
async fn report_csv(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(day): Path<i64>,
    Query(q): Query<ReportQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let app = norm_app(&q.app);
    let Ok(r) = build_report(&ctx, day, app) else {
        return internal("生成报告失败").into_response();
    };

    let mut out = String::with_capacity(4_096);
    out.push('\u{feff}');
    out.push_str(&format!("防护报告,{},{}\r\n\r\n", r.date, r.app.as_deref().unwrap_or("全部应用")));
    out.push_str("指标,值\r\n");
    out.push_str(&format!("请求数,{}\r\n", r.totals.requests));
    out.push_str(&format!("页面浏览量,{}\r\n", r.totals.pv));
    out.push_str(&format!("独立 IP,{}\r\n", r.totals.unique_ips));
    out.push_str(&format!("独立访客,{}\r\n", r.totals.unique_visitors));
    out.push_str(&format!("拦截数,{}\r\n", r.totals.blocked));
    out.push_str(&format!("拦截率,{:.2}%\r\n", r.block_rate));
    out.push_str(&format!("4xx 数,{}\r\n", r.totals.status_4xx));
    out.push_str(&format!("4xx 率,{:.2}%\r\n", r.four_xx_rate));
    out.push_str(&format!("5xx 数,{}\r\n", r.totals.status_5xx));
    out.push_str(&format!("5xx 率,{:.2}%\r\n\r\n", r.five_xx_rate));

    out.push_str("小时,请求数,拦截数\r\n");
    for p in &r.series {
        out.push_str(&format!(
            "{},{},{}\r\n",
            format_utc(p.ts),
            p.requests,
            p.blocked
        ));
    }
    out.push_str("\r\n");

    out.push_str("事件类型,数量\r\n");
    for k in &r.kinds {
        out.push_str(&format!("{},{}\r\n", csv_field(&k.name), k.count));
    }
    out.push_str("\r\n攻击类型,数量\r\n");
    for c in &r.categories {
        out.push_str(&format!("{},{}\r\n", csv_field(&c.name), c.count));
    }
    out.push_str("\r\n命中规则,数量\r\n");
    for x in &r.rules {
        out.push_str(&format!("{},{}\r\n", csv_field(&x.name), x.count));
    }
    out.push_str("\r\n名单/策略命中,数量\r\n");
    for x in &r.acl_reasons {
        out.push_str(&format!("{},{}\r\n", csv_field(&x.name), x.count));
    }
    out.push_str("\r\n来源 IP,事件数,国家,省市,城市\r\n");
    for row in &r.top_ips {
        let (country, region, city) = match &row.geo {
            Some(g) => (
                g.country.as_str(),
                format!("{} {}", g.province, g.city),
                g.city.as_str(),
            ),
            None => ("", String::new(), ""),
        };
        out.push_str(&format!(
            "{},{},{},{},{}\r\n",
            csv_field(&row.ip),
            row.count,
            csv_field(country),
            csv_field(region.trim()),
            csv_field(city),
        ));
    }

    let filename = format!("homewaf-report-{}.csv", r.date);
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (
                axum::http::header::CACHE_CONTROL,
                "no-store".to_string(),
            ),
        ],
        out,
    )
        .into_response()
}

// ============================================================
// 防护大屏
// ============================================================

#[derive(Serialize)]
struct ScreenKpi {
    requests: u64,
    pv: u64,
    blocked: u64,
    unique_ips: u64,
    unique_visitors: u64,
    attack_ips: usize,
    block_rate: f64,
    /// 最近 60 秒平均每秒请求数
    qps: f64,
    /// 最近 60 秒峰值
    peak_qps: u32,
}

#[derive(Serialize)]
struct ScreenData {
    generated_at: i64,
    today: i64,
    kpi: ScreenKpi,
    /// 最近 60 秒每秒请求数
    ops: Vec<u32>,
    /// 最近 30 天请求 / 拦截趋势
    trend: Vec<homewaf_store::TrafficPoint>,
    /// 最近 30 天事件量趋势
    attack_trend: Vec<NameCount>,
    kinds: Vec<NameCount>,
    categories: Vec<CategoryCount>,
    blocked_rules: Vec<NameCount>,
    top_ips: Vec<IpRow>,
    /// 最近 24 小时访问来源地图
    geo: geoip::GeoStats,
    /// 最近 30 天攻击来源地图
    attack_geo: geoip::GeoStats,
    recent: Vec<homewaf_store::Event>,
}

async fn screen(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let now = homewaf_acl::now_unix();
    let today = now - now.rem_euclid(86_400);
    let totals = ctx
        .store
        .traffic_totals(today, today + 86_400, None)
        .unwrap_or_default();

    // 实时 QPS 用最近 60 秒桶计算，不用瞬时单秒值，避免动画抖动
    let realtime = ctx.metrics.dashboard(60, None, now);
    let qps = if realtime.ops.is_empty() {
        0.0
    } else {
        realtime.ops.iter().map(|v| *v as f64).sum::<f64>() / realtime.ops.len() as f64
    };
    let peak_qps = realtime.ops.iter().copied().max().unwrap_or(0);

    let kinds: Vec<NameCount> = ctx
        .store
        .event_kind_counts(today, now + 1, None)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    let attack_ips = ctx
        .store
        .event_ip_count(today, now + 1, Some("block"))
        .unwrap_or(0);

    let state = ctx.shared.load_full();
    let categories = attack_categories(&state, &ctx.store, today, now + 1);
    let blocked_rules = rule_hits(&ctx.store, today, now + 1, 10);
    let top = ctx
        .store
        .top_event_ips(today, now + 1, None, 10)
        .unwrap_or_default();
    let top_ips = ip_rows(&ctx.geoip, &top);

    let since_30d = now - 30 * 86_400;
    let trend = ctx
        .store
        .traffic_series(since_30d, now + 86_400, None, 86_400)
        .unwrap_or_default();
    let mut daily: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
    for (day, _kind, n) in ctx
        .store
        .daily_event_counts(since_30d)
        .unwrap_or_default()
    {
        *daily.entry(day).or_insert(0) += n;
    }
    let attack_trend: Vec<NameCount> = daily
        .into_iter()
        .map(|(day, count)| NameCount {
            name: date_of(day),
            count,
        })
        .collect();

    // 访问来源取内存快照（24 小时），攻击来源取事件表（30 天）
    let geo = ctx
        .geoip
        .resolve(&ctx.metrics.dashboard(86_400, None, now).ips);
    let attack_pairs = ctx
        .store
        .top_event_ips(since_30d, now + 1, Some("block"), 500)
        .unwrap_or_default();
    let attack_geo = geo_stats_from(&ctx.geoip, &attack_pairs);

    let recent = ctx
        .store
        .query_events(&homewaf_store::EventFilter {
            limit: 20,
            ..Default::default()
        })
        .map(|(events, _)| events)
        .unwrap_or_default();

    Json(ScreenData {
        generated_at: now,
        today,
        kpi: ScreenKpi {
            requests: totals.requests,
            pv: totals.pv,
            blocked: totals.blocked,
            unique_ips: totals.unique_ips,
            unique_visitors: totals.unique_visitors,
            attack_ips,
            block_rate: rate(totals.blocked, totals.requests),
            qps: (qps * 10.0).round() / 10.0,
            peak_qps,
        },
        ops: realtime.ops,
        trend,
        attack_trend,
        kinds,
        categories,
        blocked_rules,
        top_ips,
        geo,
        attack_geo,
        recent,
    })
    .into_response()
}

// ============================================================
// 应用
// ============================================================

async fn list_apps(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.list_applications::<Application>() {
        Ok(apps) => Json(apps).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// 单个应用详情：完整配置 + 上游健康状态 + 最近 24 小时概况。
async fn get_app(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let apps: Vec<Application> = match ctx.store.list_applications() {
        Ok(apps) => apps,
        Err(e) => return internal(e).into_response(),
    };
    let Some((index, app)) = apps
        .iter()
        .enumerate()
        .find(|(_, a)| a.id == id)
        .map(|(i, a)| (i, a.clone()))
    else {
        return (StatusCode::NOT_FOUND, "应用不存在").into_response();
    };

    let runtime = ctx.shared.load_full();
    let health = runtime.pool.health_for_app(index);
    let health: Vec<_> = app
        .upstreams
        .iter()
        .enumerate()
        .map(|(i, u)| {
            serde_json::json!({
                "addr": u.addr,
                "healthy": health.get(i).map(|h| h.1).unwrap_or(true),
            })
        })
        .collect();

    let now = homewaf_acl::now_unix();
    let dashboard = ctx.metrics.dashboard(86_400, Some(&app.id), now);
    let stats = serde_json::json!({
        "requests": dashboard.requests,
        "blocked": dashboard.blocked,
        "attack_ips": dashboard.attack_ips,
        "unique_ips": dashboard.unique_ips,
    });

    Json(serde_json::json!({
        "app": app,
        "health": health,
        "stats": stats,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct EnabledInput {
    enabled: bool,
}

/// 启停应用。列表里的开关直接调这个接口，不必整份配置回传。
async fn set_app_enabled(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<EnabledInput>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let mut app: Application = match ctx
        .store
        .list_applications::<Application>()
        .map(|apps| apps.into_iter().find(|a| a.id == id))
    {
        Ok(Some(app)) => app,
        Ok(None) => return (StatusCode::NOT_FOUND, "应用不存在").into_response(),
        Err(e) => return internal(e).into_response(),
    };
    app.enabled = input.enabled;

    let now = homewaf_acl::now_unix();
    if let Err(e) =
        ctx.store
            .upsert_application(&app.id, &app.domains.primary, app.enabled, &app, now)
    {
        return internal(e).into_response();
    }
    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true, "enabled": app.enabled})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已写入数据库，但重载失败：{e}"),
        )
            .into_response(),
    }
}

/// 应用级快捷开关（攻击防护 / CC 防护）。列表卡片直接调这个接口切换，
/// 不必整份应用配置回传。
async fn set_app_features(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(features): Json<homewaf_config::AppFeatures>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let mut app: Application = match ctx
        .store
        .list_applications::<Application>()
        .map(|apps| apps.into_iter().find(|a| a.id == id))
    {
        Ok(Some(app)) => app,
        Ok(None) => return (StatusCode::NOT_FOUND, "应用不存在").into_response(),
        Err(e) => return internal(e).into_response(),
    };
    app.features = features;

    let now = homewaf_acl::now_unix();
    if let Err(e) =
        ctx.store
            .upsert_application(&app.id, &app.domains.primary, app.enabled, &app, now)
    {
        return internal(e).into_response();
    }
    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true, "features": app.features})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已写入数据库，但重载失败：{e}"),
        )
            .into_response(),
    }
}

fn find_app(ctx: &AdminState, id: &str) -> Result<Application, ApiError> {
    match ctx.store.list_applications::<Application>() {
        Ok(apps) => apps
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "应用不存在".to_string())),
        Err(e) => Err(internal(e)),
    }
}

/// 应用防篡改状态：配置、基线文件数与实际保护目录。
async fn get_app_tamper(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let app = match find_app(&ctx, &id) {
        Ok(app) => app,
        Err(e) => return e.into_response(),
    };
    let baseline = match ctx.store.tamper_baseline_count(&id) {
        Ok(n) => n,
        Err(e) => return internal(e).into_response(),
    };
    let roots: Vec<String> = homewaf_proxy::tamper::protected_roots(&app)
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    Json(serde_json::json!({
        "app": id,
        "enabled": app.tamper.enabled,
        "paths": app.tamper.paths,
        "action": app.tamper.action,
        "baseline": baseline,
        "roots": roots,
        "live_check": matches!(app.access_mode, homewaf_config::AccessMode::Static),
    }))
    .into_response()
}

/// 扫描受保护目录并重建基线。
async fn build_app_tamper_baseline(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let app = match find_app(&ctx, &id) {
        Ok(app) => app,
        Err(e) => return e.into_response(),
    };
    let (entries, scan) = match homewaf_proxy::tamper::build_baseline(&app) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    if let Err(e) = ctx.store.replace_tamper_baseline(
        &id,
        &entries,
        homewaf_acl::now_unix(),
    ) {
        return internal(e).into_response();
    }
    if let Err(e) = reload_state(&ctx) {
        return (
            StatusCode::BAD_REQUEST,
            format!("基线已保存，但热重载失败：{e}"),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "baseline": entries.len(),
        "files": scan.files,
        "skipped": scan.skipped,
    }))
    .into_response()
}

/// 与基线对比，返回被修改 / 新增 / 删除的文件，并记录事件。
async fn scan_app_tamper(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let app = match find_app(&ctx, &id) {
        Ok(app) => app,
        Err(e) => return e.into_response(),
    };
    let rows = match ctx.store.tamper_baseline(&id) {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, "尚未建立基线，请先建立基线").into_response();
        }
        Err(e) => return internal(e).into_response(),
    };
    let baseline = homewaf_proxy::tamper::TamperBaseline::from_rows(&rows);
    let scan = match homewaf_proxy::tamper::scan_changes(&app, &baseline) {
        Ok(scan) => scan,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let action = match app.tamper.action {
        homewaf_config::TamperAction::Block => "block",
        homewaf_config::TamperAction::Log => "log",
    };
    for change in &scan.changes {
        if !homewaf_proxy::tamper::should_record(&id, &change.path) {
            continue;
        }
        let event = homewaf_store::Event::new(homewaf_acl::now_unix(), homewaf_store::EventKind::Detect, "")
            .with_app(id.clone())
            .with_path(change.path.clone())
            .with_rules(format!("tamper-{}", change.kind))
            .with_score(100)
            .with_action(action.to_string());
        if let Err(e) = ctx.store.insert_event(&event) {
            tracing::warn!(error = %e, "写入防篡改扫描事件失败");
        }
    }

    Json(scan).into_response()
}

async fn upsert_app(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(app): Json<Application>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    // 先做完整校验再落库。写进去再校验的话，坏数据会留在库里，
    // 下次启动直接起不来。
    if let Err(e) = validate_app(&ctx, &app) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let now = homewaf_acl::now_unix();
    if let Err(e) =
        ctx.store
            .upsert_application(&app.id, &app.domains.primary, app.enabled, &app, now)
    {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已写入数据库，但重载失败：{e}"),
        )
            .into_response(),
    }
}

/// 校验一个待写入的应用。
fn validate_app(ctx: &AdminState, app: &Application) -> Result<(), String> {
    let id = app.id.trim();
    if id.is_empty() {
        return Err("ID 不能为空".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("ID 只能包含小写字母、数字和横线".into());
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err("ID 不能以横线开头或结尾".into());
    }

    homewaf_config::validate_domain(&app.domains.primary)
        .map_err(|e| format!("主域名非法：{e}"))?;

    if app.domains.aliases.len() > 10 {
        return Err("别名域名最多 10 个".into());
    }
    for (i, alias) in app.domains.aliases.iter().enumerate() {
        homewaf_config::validate_domain(alias)
            .map_err(|e| format!("别名 {} 非法：{e}", i + 1))?;
    }

    if app.listen_ports.contains(&0) {
        return Err("监听端口不能为 0".into());
    }

    match app.access_mode {
        homewaf_config::AccessMode::Proxy => {
            if app.upstreams.is_empty() {
                return Err("反向代理应用至少需要一个上游".into());
            }
            for (i, u) in app.upstreams.iter().enumerate() {
                if u.addr.trim().is_empty() {
                    return Err(format!("上游 {} 的地址不能为空", i + 1));
                }
                if u.port == Some(0) {
                    return Err(format!("上游 {} 的端口不能为 0", i + 1));
                }
            }
        }
        homewaf_config::AccessMode::Static => {
            if app.static_site.root.trim().is_empty() {
                return Err("静态站点必须填写根目录".into());
            }
            let root = std::path::Path::new(app.static_site.root.trim());
            if !root.is_dir() {
                return Err(format!("静态站点根目录不存在或不是目录：{}", root.display()));
            }
        }
        homewaf_config::AccessMode::Redirect => {
            let target = app.redirect.target.trim();
            if target.is_empty() {
                return Err("重定向必须填写目标地址".into());
            }
            if !(target.starts_with("http://") || target.starts_with("https://")) {
                return Err("重定向目标必须以 http:// 或 https:// 开头".into());
            }
            if ![301, 302, 303, 307, 308].contains(&app.redirect.status) {
                return Err("重定向状态码只能是 301 / 302 / 303 / 307 / 308".into());
            }
        }
    }

    // 域名冲突：主域名与别名都不能和其他应用重复。
    // 不检查的话，DB 的唯一索引会抛一个用户看不懂的 SQL 错误。
    let existing: Vec<Application> = ctx.store.list_applications().unwrap_or_default();
    let mine = |a: &Application| a.id == app.id;

    for other in existing.iter().filter(|a| !mine(a)) {
        let mut theirs = vec![other.domains.primary.as_str()];
        theirs.extend(other.domains.aliases.iter().map(|s| s.as_str()));

        let mut ours = vec![app.domains.primary.as_str()];
        ours.extend(app.domains.aliases.iter().map(|s| s.as_str()));

        for o in &ours {
            if theirs.iter().any(|t| t.eq_ignore_ascii_case(o)) {
                return Err(format!("域名 `{o}` 已被应用 `{}` 使用", other.id));
            }
        }
    }

    Ok(())
}

async fn delete_app(State(ctx): State<Ctx>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.delete_application(&id) {
        Ok(true) => match reload_state(&ctx) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                format!("已删除，但重载失败：{e}"),
            )
                .into_response(),
        },
        Ok(false) => (StatusCode::NOT_FOUND, "应用不存在").into_response(),
        Err(e) => internal(e).into_response(),
    }
}

// ============================================================
// ACL 规则
// ============================================================

async fn list_rules(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.list_acl_rules() {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

#[derive(Deserialize)]
struct RuleInput {
    id: Option<String>,
    cidr: String,
    action: String,
    scope: Option<String>,
    expires_at: Option<i64>,
    note: Option<String>,
}

async fn upsert_rule(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(input): Json<RuleInput>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    // 先验证网段合法，避免把坏数据写进库
    if input.cidr.parse::<ipnet::IpNet>().is_err() {
        return (StatusCode::BAD_REQUEST, "网段格式非法").into_response();
    }
    if !matches!(input.action.as_str(), "allow" | "deny") {
        return (StatusCode::BAD_REQUEST, "action 只能是 allow 或 deny").into_response();
    }

    // 防重复：同网段 + 同动作 + 同作用域视为同一条规则。
    // 不检查的话，用户连点两次就会得到两条一模一样的规则。
    if let Ok(existing) = ctx.store.list_acl_rules() {
        if let Some(dup) = existing.iter().find(|r| {
            r.cidr == input.cidr
                && r.action == input.action
                && r.scope.as_deref() == input.scope.as_deref()
        }) {
            return (
                StatusCode::CONFLICT,
                format!(
                    "相同规则已存在（{}）：{} → {}",
                    dup.id,
                    dup.cidr,
                    if dup.action == "allow" { "放行" } else { "拒绝" }
                ),
            )
                .into_response();
        }
    }

    let id = input
        .id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("ui-{}", homewaf_acl::now_unix()));

    let row = AclRuleRow {
        id,
        cidr: input.cidr,
        action: input.action,
        scope: input.scope,
        expires_at: input.expires_at,
        note: input.note,
    };

    let now = homewaf_acl::now_unix();
    if let Err(e) = ctx.store.upsert_acl_rule(&row, now) {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": row.id})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已写入，但重载失败：{e}"),
        )
            .into_response(),
    }
}

async fn delete_rule(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.delete_acl_rule(&id) {
        Ok(true) => match reload_state(&ctx) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                format!("已删除，但重载失败：{e}"),
            )
                .into_response(),
        },
        Ok(false) => (StatusCode::NOT_FOUND, "规则不存在").into_response(),
        Err(e) => internal(e).into_response(),
    }
}

// ============================================================
// 封禁
// ============================================================

#[derive(Serialize)]
struct BanView {
    ip: String,
    until: i64,
    remaining_secs: u64,
    offenses: u32,
    reason: String,
}

async fn list_bans(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let now = homewaf_acl::now_unix();
    match ctx.store.load_active_bans(now) {
        Ok(bans) => {
            let view: Vec<BanView> = bans
                .into_iter()
                .map(|b| BanView {
                    remaining_secs: (b.until - now).max(0) as u64,
                    ip: b.ip,
                    until: b.until,
                    offenses: b.offenses,
                    reason: b.reason,
                })
                .collect();
            Json(view).into_response()
        }
        Err(e) => internal(e).into_response(),
    }
}

async fn unban(State(ctx): State<Ctx>, headers: HeaderMap, Path(ip): Path<String>) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return (StatusCode::BAD_REQUEST, "IP 格式非法").into_response();
    };

    ctx.bans.unban(addr);
    match ctx.store.delete_ban(&ip) {
        Ok(_) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

#[derive(Deserialize)]
struct BanCreate {
    ip: String,
    /// 封禁时长（秒），默认 1 小时
    #[serde(default)]
    duration_secs: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

/// 手动封禁。写入运行时封禁表与数据库，重启后可恢复。
async fn create_ban(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(body): Json<BanCreate>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let Ok(addr) = body.ip.trim().parse::<std::net::IpAddr>() else {
        return (StatusCode::BAD_REQUEST, "IP 格式非法").into_response();
    };
    let now = homewaf_acl::now_unix().max(0) as u64;
    let duration = body.duration_secs.unwrap_or(3_600).clamp(60, 30 * 86_400);
    let until = now + duration;
    let reason = body
        .reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "manual".to_string());

    ctx.bans.manual_ban(addr, until, 1, now);
    let record = homewaf_store::BanRecord {
        ip: addr.to_string(),
        until: until as i64,
        offenses: 1,
        score: 0,
        reason: reason.clone(),
        created_at: now as i64,
    };
    if let Err(e) = ctx.store.upsert_ban(&record, now as i64) {
        return internal(e).into_response();
    }

    Json(serde_json::json!({
        "ok": true,
        "ip": record.ip,
        "until": until,
        "duration_secs": duration,
        "reason": reason,
    }))
    .into_response()
}

// ============================================================
// 事件
// ============================================================

#[derive(Deserialize)]
struct EventQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    since: Option<i64>,
    #[serde(default)]
    until: Option<i64>,
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

fn default_limit() -> usize {
    50
}

async fn list_events(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<EventQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let filter = homewaf_store::EventFilter {
        limit: q.limit.min(200),
        offset: q.offset,
        kind: q.kind,
        ip: q.ip,
        action: q.action,
        since: q.since,
        until: q.until,
        app: q.app,
        path: q.path,
        q: q.q,
    };

    match ctx.store.query_events(&filter) {
        Ok((events, total)) => Json(serde_json::json!({
            "events": events,
            "total": total,
            "limit": filter.limit,
            "offset": filter.offset,
        }))
        .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// 事件导出为 CSV。带 UTF-8 BOM，Excel 直接打开不乱码。
async fn export_events(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<EventQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let filter = homewaf_store::EventFilter {
        limit: if q.limit == default_limit() {
            50_000
        } else {
            q.limit.min(50_000)
        },
        offset: q.offset,
        kind: q.kind,
        ip: q.ip,
        action: q.action,
        since: q.since,
        until: q.until,
        app: q.app,
        path: q.path,
        q: q.q,
    };

    let Ok((events, _)) = ctx.store.query_events(&filter) else {
        return internal("查询事件失败").into_response();
    };

    let mut out = String::with_capacity(64 + events.len() * 120);
    out.push('\u{feff}');
    out.push_str("id,时间,类型,来源 IP,应用,路径,命中规则,评分,动作\r\n");
    for e in &events {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\r\n",
            e.id,
            csv_field(&format_utc(e.ts)),
            e.kind.as_str(),
            csv_field(&e.client_ip),
            csv_field(&e.app),
            csv_field(&e.path),
            csv_field(&e.rules),
            e.score,
            csv_field(&e.action),
        ));
    }

    let filename = format!("homewaf-events-{}.csv", homewaf_acl::now_unix());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (
                axum::http::header::CACHE_CONTROL,
                "no-store".to_string(),
            ),
        ],
        out,
    )
        .into_response()
}

fn csv_field(s: &str) -> String {
    // 防 CSV 公式注入：以这些字符开头的单元格会被 Excel 当公式执行
    let guarded = matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'));
    let mut out = if guarded {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if out.contains([',', '"', '\n', '\r']) {
        out = format!("\"{}\"", out.replace('"', "\"\""));
    }
    out
}

/// Unix 秒转 UTC `YYYY-MM-DD HH:MM:SS`。
fn format_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Howard Hinnant 的 civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

// ============================================================
// 日志查看
// ============================================================

#[derive(Deserialize)]
struct LogQuery {
    /// access / upstream / security / error
    #[serde(default = "default_log_type")]
    kind: String,
    #[serde(default = "default_log_limit")]
    limit: usize,
    /// 关键字过滤（匹配整行）
    #[serde(default)]
    q: Option<String>,
    /// 按请求 ID 精确过滤——把三个文件的同一条请求串起来
    #[serde(default)]
    req: Option<String>,
}

fn default_log_type() -> String {
    "access".to_string()
}

fn default_log_limit() -> usize {
    200
}

async fn list_logs(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<LogQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let kind = match q.kind.as_str() {
        "access" | "upstream" | "security" | "error" => q.kind.as_str(),
        other => return (StatusCode::BAD_REQUEST, format!("未知日志类型 `{other}`")).into_response(),
    };

    // 找该类型下最新的日志文件（按文件名倒序，文件名带日期）
    let dir = ctx.log_dir.join(kind);
    let Some(file) = latest_log_file(&dir) else {
        return Json(serde_json::json!({
            "lines": [],
            "file": null,
            "total": 0,
        }))
        .into_response();
    };

    let content = match std::fs::read_to_string(&file) {
        Ok(c) => c,
        Err(e) => return internal(format!("读取日志失败：{e}")).into_response(),
    };

    let needle = q
        .req
        .as_deref()
        .map(|r| r.to_string())
        .or_else(|| q.q.clone())
        .filter(|s| !s.trim().is_empty());

    let mut lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| match &needle {
            Some(n) => l.contains(n.as_str()),
            None => true,
        })
        .collect();

    let total = lines.len();
    // 最新的在最后，倒序取 limit 条
    let take = q.limit.clamp(1, 2000);
    if lines.len() > take {
        lines = lines.split_off(lines.len() - take);
    }
    lines.reverse();

    Json(serde_json::json!({
        "lines": lines,
        "file": file.file_name().and_then(|s| s.to_str()).unwrap_or(""),
        "total": total,
    }))
    .into_response()
}

/// 目录里文件名最大的那个（文件名前缀带日期，字符串序即时间序）。
fn latest_log_file(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    files.pop()
}

// ============================================================
// 设置
// ============================================================

/// 返回所有设置项的**有效值**：库里有就用库里的，没有就用默认值。
///
/// 前端必须拿到完整结构才能渲染表单——空库时不该让界面显示空白。
async fn get_all_settings(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let defaults = homewaf_config::Config::default();
    let load = |key: &str, default: serde_json::Value| -> serde_json::Value {
        ctx.store
            .get_setting::<serde_json::Value>(key)
            .ok()
            .flatten()
            .unwrap_or(default)
    };

    let mut out = serde_json::Map::new();
    for (key, value) in [
        (
            "protection",
            serde_json::to_value(&defaults.protection).unwrap_or_default(),
        ),
        (
            "acl",
            serde_json::to_value(&defaults.acl).unwrap_or_default(),
        ),
        (
            "real_ip",
            serde_json::to_value(&defaults.real_ip).unwrap_or_default(),
        ),
        (
            "ratelimit",
            serde_json::to_value(defaults.ratelimit).unwrap_or_default(),
        ),
        (
            "challenge",
            serde_json::to_value(defaults.challenge).unwrap_or_default(),
        ),
        (
            "logging",
            serde_json::to_value(&defaults.logging).unwrap_or_default(),
        ),
        (
            "rule_feeds",
            serde_json::to_value(&defaults.rule_feeds).unwrap_or_default(),
        ),
        // GeoIP 数据库路径，空表示未启用
        ("geoip_db", serde_json::Value::String(String::new())),
        ("custom_rules", serde_json::Value::Array(Vec::new())),
    ] {
        out.insert(key.to_string(), load(key, value));
    }

    Json(serde_json::Value::Object(out)).into_response()
}

async fn get_setting(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.get_setting::<serde_json::Value>(&key) {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "设置项不存在").into_response(),
        Err(e) => internal(e).into_response(),
    }
}

async fn put_setting(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(value): Json<serde_json::Value>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    // 类型校验：按 key 反序列化成对应结构，失败直接拒绝。
    // 不做这一步的话，一个字段写错就会让服务下次启动失败。
    if let Err(e) = check_setting_type(&key, &value) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let now = homewaf_acl::now_unix();
    let old = ctx
        .store
        .get_setting::<serde_json::Value>(&key)
        .ok()
        .flatten();

    if let Err(e) = ctx.store.set_setting(&key, &value, now) {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => {
            // GeoIP 路径不属于运行时状态，单独换库
            if key == geoip::GEOIP_SETTING {
                ctx.geoip.reload_from_store(&ctx.store);
                if let Some(err) = ctx.geoip.status().error {
                    return (StatusCode::BAD_REQUEST, err).into_response();
                }
            }
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => {
            // 重载失败说明业务校验没过（比如阈值非法）。回滚，别把库留在坏状态
            let rolled_back = match &old {
                Some(v) => ctx.store.set_setting(&key, v, now).is_ok(),
                None => ctx.store.delete_setting(&key).is_ok(),
            };
            let hint = if rolled_back {
                "已回滚到修改前"
            } else {
                "回滚失败，请手动检查数据库"
            };
            (
                StatusCode::BAD_REQUEST,
                format!("配置不合法，{hint}：{e}"),
            )
                .into_response()
        }
    }
}

/// 按 key 校验设置项能否反序列化成对应类型。
fn check_setting_type(key: &str, value: &serde_json::Value) -> Result<(), String> {
    use homewaf_config::*;
    match key {
        "protection" => serde_json::from_value::<ProtectionConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("protection 结构不合法：{e}")),
        "acl" => serde_json::from_value::<AclConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("acl 结构不合法：{e}")),
        "real_ip" => serde_json::from_value::<RealIpConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("real_ip 结构不合法：{e}")),
        "ratelimit" => serde_json::from_value::<RateLimitConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("ratelimit 结构不合法：{e}")),
        "challenge" => serde_json::from_value::<ChallengeConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("challenge 结构不合法：{e}")),
        "logging" => serde_json::from_value::<LoggingConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("logging 结构不合法：{e}")),
        "tls" => serde_json::from_value::<TlsConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("tls 结构不合法：{e}")),
        "limits" => serde_json::from_value::<LimitsConfig>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("limits 结构不合法：{e}")),
        "rule_feeds" => serde_json::from_value::<Vec<RuleFeed>>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("rule_feeds 结构不合法：{e}")),
        // 兼容雷池（长亭）导出的自定义规则数组
        "custom_rules" => serde_json::from_value::<Vec<CustomRule>>(value.clone())
            .map(|_| ())
            .map_err(|e| format!("custom_rules 结构不合法：{e}")),
        "geoip_db" => {
            let path = value
                .as_str()
                .ok_or_else(|| "geoip_db 必须是字符串路径".to_string())?;
            geoip::validate_db(path)
        }
        // 未知 key 直接拒绝，避免往库里塞垃圾
        other => Err(format!("未知的设置项 `{other}`")),
    }
}

// ============================================================
// 系统设置 / 自定义规则
// ============================================================

const CUSTOM_RULES_KEY: &str = "custom_rules";

fn load_custom_rules(
    store: &Store,
) -> Result<Vec<homewaf_config::CustomRule>, homewaf_store::StoreError> {
    Ok(store
        .get_setting::<Vec<homewaf_config::CustomRule>>(CUSTOM_RULES_KEY)?
        .unwrap_or_default())
}

async fn system_info(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let now = homewaf_acl::now_unix();
    let state = ctx.shared.load_full();
    let apps = ctx
        .store
        .list_applications::<homewaf_config::Application>()
        .map(|v| v.len())
        .unwrap_or(0);
    let acl_rules = ctx.store.list_acl_rules().map(|v| v.len()).unwrap_or(0);
    let custom_rules = load_custom_rules(&ctx.store).map(|v| v.len()).unwrap_or(0);
    let events = ctx.store.event_count().unwrap_or(0);
    let active_bans = ctx
        .store
        .load_active_bans(now)
        .map(|v| v.len())
        .unwrap_or(0);

    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "started_at": ctx.started_at,
        "now": now,
        "uptime_secs": (now - ctx.started_at).max(0),
        "listen": state.server.listen,
        "tls_listen": state.server.tls_listen,
        "admin_listen": state.server.admin.listen,
        "workers": state.server.workers,
        "apps": apps,
        "acl_rules": acl_rules,
        "custom_rules": custom_rules,
        "detection_rules": state.detection_rule_count(),
        "upstreams": state.upstream_count(),
        "events": events,
        "active_bans": active_bans,
    }))
    .into_response()
}

/// 导出可迁移的配置快照（不含事件与日志）。
async fn system_backup(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let mut settings = serde_json::Map::new();
    for key in [
        "server",
        "tls",
        "protection",
        "real_ip",
        "acl",
        "limits",
        "ratelimit",
        "challenge",
        "logging",
        "storage",
        "rule_feeds",
        CUSTOM_RULES_KEY,
        "geoip_db",
    ] {
        if let Ok(Some(v)) = ctx.store.get_setting::<serde_json::Value>(key) {
            settings.insert(key.to_string(), v);
        }
    }

    let applications: Vec<homewaf_config::Application> =
        ctx.store.list_applications().unwrap_or_default();
    let acl_rules = ctx.store.list_acl_rules().unwrap_or_default();
    let custom_rules = load_custom_rules(&ctx.store).unwrap_or_default();

    let body = serde_json::json!({
        "product": "homewaf",
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": homewaf_acl::now_unix(),
        "applications": applications,
        "settings": settings,
        "acl_rules": acl_rules,
        "custom_rules": custom_rules,
    });

    let filename = format!("homewaf-backup-{}.json", homewaf_acl::now_unix());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        serde_json::to_string_pretty(&body).unwrap_or_default(),
    )
        .into_response()
}

#[derive(Deserialize)]
struct PruneInput {
    /// 保留天数
    days: u32,
}

/// 清理过期事件。只删事件，不动配置与封禁记录。
async fn system_prune(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(input): Json<PruneInput>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let days = input.days.clamp(1, 3_650) as i64;
    let before = homewaf_acl::now_unix() - days * 86_400;
    match ctx.store.prune_events(before) {
        Ok(removed) => Json(serde_json::json!({
            "ok": true,
            "removed": removed,
            "before": before,
        }))
        .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

async fn list_custom_rules(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match load_custom_rules(&ctx.store) {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

async fn export_custom_rules(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let rules = match load_custom_rules(&ctx.store) {
        Ok(rules) => rules,
        Err(e) => return internal(e).into_response(),
    };
    let filename = format!("homewaf-custom-rules-{}.json", homewaf_acl::now_unix());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        serde_json::to_string_pretty(&rules).unwrap_or_default(),
    )
        .into_response()
}

/// 兼容雷池导出的三种形态：裸数组、`{"rules": [...]}`、`{"data": [...]}`。
#[derive(Deserialize)]
#[serde(untagged)]
enum RulesPayload {
    List(Vec<homewaf_config::CustomRule>),
    Wrapper {
        #[serde(default)]
        rules: Vec<homewaf_config::CustomRule>,
        #[serde(default)]
        data: Vec<homewaf_config::CustomRule>,
    },
}

#[derive(Deserialize)]
struct ImportQuery {
    /// append 追加（按 id 去重），默认整体替换
    #[serde(default)]
    mode: Option<String>,
}

async fn import_custom_rules(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<ImportQuery>,
    Json(payload): Json<RulesPayload>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let incoming = match payload {
        RulesPayload::List(v) => v,
        RulesPayload::Wrapper { rules, data } => {
            if !rules.is_empty() {
                rules
            } else {
                data
            }
        }
    };

    let now = homewaf_acl::now_unix();
    let mut rules: Vec<homewaf_config::CustomRule> = Vec::with_capacity(incoming.len());
    for (i, mut rule) in incoming.into_iter().enumerate() {
        if rule.action > 1 {
            return (
                StatusCode::BAD_REQUEST,
                format!("第 {} 条规则的 action 只能是 0（白名单）或 1（黑名单）", i + 1),
            )
                .into_response();
        }
        rule.pattern.retain(|group| !group.is_empty());
        if rule.pattern.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                format!("第 {} 条规则的 pattern 不能为空", i + 1),
            )
                .into_response();
        }
        if rule.id.trim().is_empty() {
            rule.id = format!("lei-{now}-{i}");
        }
        if rule.name.trim().is_empty() {
            rule.name = rule.id.clone();
        }
        rules.push(rule);
    }

    let merged = if q.mode.as_deref() == Some("append") {
        let mut existing = load_custom_rules(&ctx.store).unwrap_or_default();
        for rule in rules {
            match existing.iter_mut().find(|r| r.id == rule.id) {
                Some(old) => *old = rule,
                None => existing.push(rule),
            }
        }
        existing
    } else {
        rules
    };

    let value = match serde_json::to_value(&merged) {
        Ok(v) => v,
        Err(e) => return internal(e).into_response(),
    };
    if let Err(e) = ctx.store.set_setting(CUSTOM_RULES_KEY, &value, now) {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true, "count": merged.len()})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已写入数据库，但重载失败：{e}"),
        )
            .into_response(),
    }
}

// ============================================================
// IP 组订阅
// ============================================================

#[derive(Deserialize)]
struct FeedInput {
    name: String,
    url: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    scope: Option<Vec<String>>,
}

/// 把简化输入构造成完整的订阅配置。未提供的字段用默认值。
fn build_group(input: &FeedInput) -> Result<homewaf_config::IpGroup, String> {
    use homewaf_config::*;

    let name = input.name.trim();
    if name.is_empty() {
        return Err("名称不能为空".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("名称只能包含字母、数字、横线和下划线".into());
    }

    let url = input.url.trim();
    if !url.starts_with("https://") {
        return Err("订阅地址必须是 HTTPS（明文 HTTP 可能被中间人投毒）".into());
    }

    let action = match input.action.as_deref().unwrap_or("block") {
        "block" => IpGroupAction::Block,
        "challenge" => IpGroupAction::Challenge,
        "log" => IpGroupAction::Log,
        other => return Err(format!("动作 `{other}` 非法（block / challenge / log）")),
    };

    Ok(IpGroup {
        name: name.to_string(),
        enabled: input.enabled.unwrap_or(true),
        source: IpGroupSource {
            url: url.to_string(),
            format: FeedFormat::Auto,
            interval: Duration::from_secs(3600),
            timeout: Duration::from_secs(15),
            headers: std::collections::BTreeMap::new(),
        },
        action,
        scope: input.scope.clone().unwrap_or_default(),
        expires: Duration::from_secs(86_400),
        guards: IpGroupGuards::default(),
        on_failure: OnFailure::KeepLast,
    })
}

async fn list_feeds(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.list_ip_groups() {
        Ok(groups) => {
            let mut out = Vec::new();
            for g in groups {
                match serde_json::from_str::<homewaf_config::IpGroup>(&g.body) {
                    Ok(mut group) => {
                        group.enabled = g.enabled;
                        out.push(group);
                    }
                    Err(e) => {
                        tracing::warn!(name = %g.name, error = %e, "订阅数据损坏，已跳过");
                    }
                }
            }
            Json(out).into_response()
        }
        Err(e) => internal(e).into_response(),
    }
}

async fn upsert_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(input): Json<FeedInput>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let group = match build_group(&input) {
        Ok(g) => g,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let now = homewaf_acl::now_unix();
    if let Err(e) = ctx
        .store
        .upsert_ip_group(&group.name, group.enabled, &group, now)
    {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => {
            // 订阅保存成功不代表拉取成功。拉取失败只记在 feed_failures 里，
            // 不告诉用户的话，他会以为防护已经生效了。
            let snapshot = ctx.shared.load_full();
            if let Some((_, err)) = snapshot
                .feed_failures
                .iter()
                .find(|(n, _)| n == &group.name)
            {
                return Json(serde_json::json!({
                    "ok": true,
                    "name": group.name,
                    "warning": format!("订阅已保存，但首次拉取失败：{err}"),
                }))
                .into_response();
            }
            Json(serde_json::json!({"ok": true, "name": group.name})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已保存，但加载订阅失败：{e}"),
        )
            .into_response(),
    }
}

async fn delete_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.delete_ip_group(&name) {
        Ok(true) => match reload_state(&ctx) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                format!("已删除，但重载失败：{e}"),
            )
                .into_response(),
        },
        Ok(false) => (StatusCode::NOT_FOUND, "订阅不存在").into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// 立即重新拉取。本质就是触发一次重载——`load_state_from_db` 会重新加载所有启用的订阅。
async fn refresh_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match reload_state(&ctx) {
        Ok(()) => {
            let snapshot = ctx.shared.load_full();
            if let Some((_, err)) = snapshot.feed_failures.iter().find(|(n, _)| n == &name) {
                return Json(serde_json::json!({
                    "ok": true,
                    "warning": format!("刷新失败：{err}"),
                }))
                .into_response();
            }
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// ============================================================
// 规则包订阅
// ============================================================

#[derive(Serialize)]
struct RuleFeedsView {
    feeds: Vec<homewaf_config::RuleFeed>,
    statuses: Vec<homewaf_proxy::RuleFeedStatus>,
}

async fn list_rule_feeds(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let feeds = match homewaf_proxy::load_rule_feed_configs(&ctx.store) {
        Ok(f) => f,
        Err(e) => return internal(e).into_response(),
    };
    let statuses = ctx.shared.load_full().rule_feeds.clone();
    Json(RuleFeedsView { feeds, statuses }).into_response()
}

/// 复用完整配置校验：规则包订阅的约束和 YAML 模式完全一致。
fn validate_rule_feed(feed: &homewaf_config::RuleFeed) -> Result<(), String> {
    let probe = homewaf_config::Config {
        rule_feeds: vec![feed.clone()],
        ..Default::default()
    };
    let report = probe.validate();
    if report.has_errors() {
        return Err(report
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.message))
            .collect::<Vec<_>>()
            .join("；"));
    }
    Ok(())
}

/// 把订阅配置写回设置项，返回修改前的值供回滚。
fn save_rule_feed_configs(
    ctx: &AdminState,
    feeds: &[homewaf_config::RuleFeed],
) -> Result<Vec<homewaf_config::RuleFeed>, String> {
    let old = homewaf_proxy::load_rule_feed_configs(&ctx.store)?;
    let value = serde_json::to_value(feeds).map_err(|e| format!("序列化订阅配置失败：{e}"))?;
    let now = homewaf_acl::now_unix();
    ctx.store
        .set_setting(homewaf_proxy::RULE_FEEDS_SETTING, &value, now)
        .map_err(|e| format!("写入订阅配置失败：{e}"))?;
    Ok(old)
}

async fn upsert_rule_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(feed): Json<homewaf_config::RuleFeed>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    if let Err(e) = validate_rule_feed(&feed) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let mut feeds = match homewaf_proxy::load_rule_feed_configs(&ctx.store) {
        Ok(f) => f,
        Err(e) => return internal(e).into_response(),
    };
    match feeds.iter_mut().find(|f| f.name == feed.name) {
        Some(existing) => *existing = feed.clone(),
        None => feeds.push(feed.clone()),
    }

    let old = match save_rule_feed_configs(&ctx, &feeds) {
        Ok(old) => old,
        Err(e) => return internal(e).into_response(),
    };

    // 保存后强制拉取一次，让用户立刻看到版本与验签结果
    match reload_state_with(&ctx, true) {
        Ok(()) => {
            let snapshot = ctx.shared.load_full();
            if let Some(status) = snapshot.rule_feeds.iter().find(|s| s.name == feed.name) {
                if let Some(err) = &status.error {
                    return Json(serde_json::json!({
                        "ok": true,
                        "warning": format!("订阅已保存，但首次拉取失败：{err}"),
                    }))
                    .into_response();
                }
            }
            Json(serde_json::json!({"ok": true, "name": feed.name})).into_response()
        }
        Err(e) => {
            // 重载失败（比如规则与内置规则冲突）时回滚，避免留下一个起不来的配置
            let _ = save_rule_feed_configs(&ctx, &old);
            (StatusCode::BAD_REQUEST, format!("已保存，但加载失败：{e}")).into_response()
        }
    }
}

async fn delete_rule_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let mut feeds = match homewaf_proxy::load_rule_feed_configs(&ctx.store) {
        Ok(f) => f,
        Err(e) => return internal(e).into_response(),
    };
    let before = feeds.len();
    feeds.retain(|f| f.name != name);
    if feeds.len() == before {
        return (StatusCode::NOT_FOUND, "规则包订阅不存在").into_response();
    }

    let old = match save_rule_feed_configs(&ctx, &feeds) {
        Ok(old) => old,
        Err(e) => return internal(e).into_response(),
    };
    // 缓存也要清掉，否则重新添加同名订阅时会先载入旧规则
    let _ = ctx.store.delete_rule_feed_package(&name);

    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => {
            let _ = save_rule_feed_configs(&ctx, &old);
            (
                StatusCode::BAD_REQUEST,
                format!("已删除，但重载失败：{e}"),
            )
                .into_response()
        }
    }
}

async fn refresh_rule_feed(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let feeds = match homewaf_proxy::load_rule_feed_configs(&ctx.store) {
        Ok(f) => f,
        Err(e) => return internal(e).into_response(),
    };
    if !feeds.iter().any(|f| f.name == name) {
        return (StatusCode::NOT_FOUND, "规则包订阅不存在").into_response();
    }

    match reload_state_with(&ctx, true) {
        Ok(()) => {
            let snapshot = ctx.shared.load_full();
            match snapshot.rule_feeds.iter().find(|s| s.name == name) {
                Some(status) if !status.enabled => {
                    Json(serde_json::json!({"ok": true, "warning": "订阅已停用，未拉取"}))
                        .into_response()
                }
                Some(status) if status.error.is_some() => Json(serde_json::json!({
                    "ok": true,
                    "warning": format!("刷新失败：{}", status.error.as_deref().unwrap_or("")),
                }))
                .into_response(),
                Some(_) => Json(serde_json::json!({"ok": true})).into_response(),
                None => (StatusCode::NOT_FOUND, "订阅未生效").into_response(),
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// 定期检查订阅是否需要更新。到点后重建运行时状态，`load_rule_feeds`
/// 会按各自的检查间隔只拉取到期的那几个。
fn spawn_rule_feed_scheduler(ctx: Ctx) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;

            let store = ctx.store.clone();
            let due = tokio::task::spawn_blocking(move || {
                let feeds = homewaf_proxy::load_rule_feed_configs(&store)?;
                let cache = homewaf_proxy::StoreRuleFeedCache::new(&store);
                Ok::<bool, String>(homewaf_proxy::rule_feeds_due(
                    &feeds,
                    &cache,
                    homewaf_acl::now_unix(),
                ))
            })
            .await;

            match due {
                Ok(Ok(true)) => {
                    let reload_ctx = ctx.clone();
                    let result =
                        tokio::task::spawn_blocking(move || reload_state(&reload_ctx)).await;
                    match result {
                        Ok(Ok(())) => tracing::info!("规则包订阅检查完成"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "规则包自动更新失败"),
                        Err(e) => tracing::warn!(error = %e, "规则包更新任务异常退出"),
                    }
                }
                Ok(Ok(false)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "读取规则包订阅配置失败"),
                Err(e) => tracing::warn!(error = %e, "规则包检查任务异常退出"),
            }
        }
    });
}

// ============================================================
// 检测白名单
// ============================================================

#[derive(Deserialize)]
struct WhitelistInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// 把空字符串当成"不限制"。
fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn build_whitelist(input: &WhitelistInput) -> Result<homewaf_store::WhitelistRow, String> {
    let app = non_empty(input.app.clone());
    let path = non_empty(input.path.clone());
    let rule_id = non_empty(input.rule_id.clone());

    // 三道限制全空等于"对所有请求关闭全部检测"，这是灾难性的配置
    if app.is_none() && path.is_none() && rule_id.is_none() {
        return Err(
            "白名单至少要指定应用、路径或规则之一。三个都空等于对所有请求关闭检测".to_string(),
        );
    }

    // 路径必须以 / 开头，否则前缀匹配会得到意外结果
    if let Some(p) = &path {
        if !p.starts_with('/') {
            return Err("路径必须以 / 开头".to_string());
        }
    }

    Ok(homewaf_store::WhitelistRow {
        id: non_empty(input.id.clone())
            .unwrap_or_else(|| format!("wl-{}", homewaf_acl::now_unix())),
        app,
        path,
        rule_id,
        note: non_empty(input.note.clone()),
    })
}

async fn list_whitelist(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.list_whitelist() {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

async fn upsert_whitelist(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(input): Json<WhitelistInput>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let row = match build_whitelist(&input) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let now = homewaf_acl::now_unix();
    if let Err(e) = ctx.store.upsert_whitelist(&row, now) {
        return internal(e).into_response();
    }

    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": row.id})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("已保存，但重载失败：{e}"),
        )
            .into_response(),
    }
}

async fn delete_whitelist(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match ctx.store.delete_whitelist(&id) {
        Ok(true) => match reload_state(&ctx) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                format!("已删除，但重载失败：{e}"),
            )
                .into_response(),
        },
        Ok(false) => (StatusCode::NOT_FOUND, "白名单不存在").into_response(),
        Err(e) => internal(e).into_response(),
    }
}

// ============================================================
// 重载
// ============================================================

async fn reload(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    match reload_state(&ctx) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// 从数据库重建运行时状态并原子替换。
///
/// 这是 DB 模式下的"热重载"：没有文件可监视，只能由写操作显式触发。
fn reload_state(ctx: &AdminState) -> Result<(), String> {
    reload_state_with(ctx, false)
}

/// `force` 为 true 时忽略检查间隔与更新窗口，立即拉取全部规则包。
fn reload_state_with(ctx: &AdminState, force_rule_feeds: bool) -> Result<(), String> {
    let mut new_state: RuntimeState =
        homewaf_proxy::load_state_from_db_with(&ctx.store, ctx.allow_regex, force_rule_feeds)?;

    // CC 计数属于运行时状态，不能因为改了一条 ACL 就被清零
    new_state.limiter = ctx.shared.load().limiter.clone();

    // 封禁参数同步，但保留已有封禁记录
    ctx.bans
        .update_settings(&new_state.auto_ban, new_state.ipv6_prefix);

    tracing::info!(
        apps = new_state.router.len(),
        rules = new_state.rule_count(),
        "配置已重载"
    );

    ctx.shared.store(Arc::new(new_state));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{
        AclConfig, AutoBanConfig, Application, Domains, Duration, FeedChannel, RealIpConfig,
        RuleFeed, Scheme, Size, TlsModeConfig, Upstream,
    };

    fn empty_runtime() -> RuntimeState {
        RuntimeState {
            router: homewaf_router::Router::build(vec![], false).unwrap(),
            acl: homewaf_acl::Acl::build(&AclConfig::default(), &[], 0),
            pool: homewaf_proxy::UpstreamPool::build(&[]),
            real_ip: RealIpConfig::default(),
            engine: homewaf_detect::Engine::new(true, 50),
            policies: homewaf_proxy::PolicySet::build(
                &[],
                &Default::default(),
                Default::default(),
                &Default::default(),
            ),
            limiter: Arc::new(homewaf_limit::RateLimiter::new()),
            challenge: Default::default(),
            whitelist: Vec::new(),
            auto_ban: AutoBanConfig::default(),
            ipv6_prefix: 64,
            server: Default::default(),
            tls: Default::default(),
            feed_failures: Vec::new(),
            rule_feeds: Vec::new(),
            custom_rules: Vec::new(),
            tamper: Vec::new(),
        }
    }

    fn state() -> AdminState {
        AdminState {
            store: Arc::new(Store::open_memory().unwrap()),
            shared: homewaf_proxy::shared(empty_runtime()),
            bans: Arc::new(BanTable::new(&AutoBanConfig::default(), 64)),
            metrics: Arc::new(TrafficMetrics::new()),
            geoip: Arc::new(geoip::GeoIp::new()),
            allow_regex: false,
            token: None,
            log_dir: std::env::temp_dir(),
            started_at: 0,
        }
    }

    fn app(id: &str, domain: &str) -> Application {
        Application {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            domains: Domains {
                primary: domain.to_string(),
                aliases: vec![],
            },
            listen_ports: Vec::new(),
            upstreams: vec![Upstream {
                addr: "192.168.1.5".to_string(),
                port: Some(8080),
                scheme: Scheme::Http,
                weight: 1,
                backup: false,
                max_conns: 128,
                tls: None,
            }],
            routes: vec![],
            tls: TlsModeConfig::default(),
            policy: Default::default(),
            lb: Default::default(),
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

    // ============================================================
    // 认证
    // ============================================================

    #[test]
    fn auth_without_token_allows() {
        assert!(authorized(&state(), &HeaderMap::new()));
    }

    #[test]
    fn auth_with_token_requires_match() {
        let mut st = state();
        st.token = Some("secret".to_string());

        assert!(!authorized(&st, &HeaderMap::new()), "无头应拒绝");

        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(!authorized(&st, &h), "错 token 应拒绝");

        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        assert!(authorized(&st, &h));
    }

    // ============================================================
    // 应用校验
    // ============================================================

    #[test]
    fn valid_app_passes() {
        let st = state();
        assert!(validate_app(&st, &app("nas", "nas.home.lan")).is_ok());
    }

    #[test]
    fn empty_id_rejected() {
        let st = state();
        let err = validate_app(&st, &app("", "a.lan")).unwrap_err();
        assert!(err.contains("ID"), "{err}");
    }

    #[test]
    fn uppercase_id_rejected() {
        let st = state();
        let err = validate_app(&st, &app("Nas", "a.lan")).unwrap_err();
        assert!(err.contains("小写"), "{err}");
    }

    #[test]
    fn id_with_trailing_dash_rejected() {
        let st = state();
        assert!(validate_app(&st, &app("nas-", "a.lan")).is_err());
        assert!(validate_app(&st, &app("-nas", "a.lan")).is_err());
    }

    #[test]
    fn invalid_domain_rejected() {
        let st = state();
        let err = validate_app(&st, &app("nas", "bad domain")).unwrap_err();
        assert!(err.contains("域名"), "{err}");
    }

    #[test]
    fn empty_upstreams_rejected() {
        let st = state();
        let mut a = app("nas", "a.lan");
        a.upstreams.clear();
        assert!(validate_app(&st, &a).unwrap_err().contains("上游"));
    }

    #[test]
    fn zero_port_rejected() {
        let st = state();
        let mut a = app("nas", "a.lan");
        a.upstreams[0].port = Some(0);
        assert!(validate_app(&st, &a).unwrap_err().contains("端口"));
    }

    #[test]
    fn duplicate_domain_rejected() {
        let st = state();
        st.store
            .upsert_application("other", "nas.home.lan", true, &app("other", "nas.home.lan"), 0)
            .unwrap();

        let err = validate_app(&st, &app("nas", "nas.home.lan")).unwrap_err();
        assert!(err.contains("已被应用"), "{err}");
    }

    #[test]
    fn duplicate_alias_rejected() {
        let st = state();
        let mut other = app("other", "other.lan");
        other.domains.aliases = vec!["shared.lan".to_string()];
        st.store.upsert_application("other", "other.lan", true, &other, 0).unwrap();

        let mut mine = app("nas", "nas.lan");
        mine.domains.aliases = vec!["shared.lan".to_string()];
        let err = validate_app(&st, &mine).unwrap_err();
        assert!(err.contains("shared.lan"), "{err}");
    }

    #[test]
    fn self_update_does_not_conflict() {
        let st = state();
        let a = app("nas", "nas.home.lan");
        st.store.upsert_application("nas", "nas.home.lan", true, &a, 0).unwrap();
        // 更新自己时不应报域名冲突
        assert!(validate_app(&st, &a).is_ok());
    }

    // ============================================================
    // 设置类型校验
    // ============================================================

    #[test]
    fn setting_type_accepts_valid() {
        assert!(check_setting_type("protection", &serde_json::json!({})).is_ok());
        assert!(check_setting_type("acl", &serde_json::json!({})).is_ok());
        assert!(check_setting_type("real_ip", &serde_json::json!({})).is_ok());
        assert!(check_setting_type("ratelimit", &serde_json::json!({})).is_ok());
    }

    #[test]
    fn setting_type_rejects_unknown_key() {
        let err = check_setting_type("nonsense", &serde_json::json!({})).unwrap_err();
        assert!(err.contains("未知"), "{err}");
    }

    #[test]
    fn setting_type_rejects_wrong_shape() {
        // protection 期望对象，给个字符串应失败
        assert!(check_setting_type("protection", &serde_json::json!("oops")).is_err());
    }

    #[test]
    fn setting_type_accepts_rule_feeds() {
        assert!(check_setting_type("rule_feeds", &serde_json::json!([])).is_ok());
        assert!(check_setting_type("rule_feeds", &serde_json::json!({})).is_err());
    }

    #[test]
    fn setting_type_accepts_empty_geoip_path() {
        // 留空是合法配置，表示不启用地图
        assert!(check_setting_type("geoip_db", &serde_json::json!("")).is_ok());
        assert!(check_setting_type("geoip_db", &serde_json::json!("  ")).is_ok());
    }

    #[test]
    fn setting_type_rejects_bad_geoip() {
        assert!(check_setting_type("geoip_db", &serde_json::json!(123)).is_err());
        assert!(check_setting_type("geoip_db", &serde_json::json!("/no/such.mmdb")).is_err());
    }

    // ============================================================
    // 规则包订阅
    // ============================================================

    fn rule_feed(name: &str) -> RuleFeed {
        RuleFeed {
            name: name.to_string(),
            url: "https://rules.example.com/core.hwrule".to_string(),
            enabled: true,
            channel: FeedChannel::Stable,
            auto_update: true,
            check_interval: Duration::from_secs(3_600),
            update_window: None,
            timeout: Duration::from_secs(20),
            max_size: Size::from_bytes(4 * 1024 * 1024),
            headers: std::collections::BTreeMap::new(),
            require_signature: true,
            public_key: Some(
                "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ),
            shadow_period: None,
            rollback_on_error: true,
            pinned_version: None,
        }
    }

    #[test]
    fn valid_rule_feed_passes_admin_validation() {
        assert!(validate_rule_feed(&rule_feed("official")).is_ok());
    }

    #[test]
    fn rule_feed_with_bad_name_rejected_by_admin() {
        assert!(validate_rule_feed(&rule_feed("a b")).is_err());
    }

    #[test]
    fn rule_feed_with_http_url_rejected_by_admin() {
        let mut f = rule_feed("official");
        f.url = "http://rules.example.com/core.hwrule".to_string();
        assert!(validate_rule_feed(&f).unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn rule_feed_without_key_rejected_by_admin() {
        let mut f = rule_feed("official");
        f.public_key = None;
        assert!(validate_rule_feed(&f).unwrap_err().contains("公钥"));
    }

    // ============================================================
    // IP 组订阅构造
    // ============================================================

    fn feed(name: &str, url: &str) -> FeedInput {
        FeedInput {
            name: name.to_string(),
            url: url.to_string(),
            enabled: None,
            action: None,
            scope: None,
        }
    }

    #[test]
    fn feed_defaults_are_sane() {
        let g = build_group(&feed("chaitin", "https://example.com/list")).unwrap();
        assert_eq!(g.name, "chaitin");
        assert!(g.enabled, "默认启用");
        assert_eq!(g.action, homewaf_config::IpGroupAction::Block, "默认拦截");
        assert!(g.scope.is_empty(), "默认全局");
        assert_eq!(g.on_failure, homewaf_config::OnFailure::KeepLast);
    }

    #[test]
    fn feed_requires_https() {
        let err = build_group(&feed("x", "http://example.com/list")).unwrap_err();
        assert!(err.contains("HTTPS"), "{err}");
    }

    #[test]
    fn feed_rejects_empty_name() {
        assert!(build_group(&feed("", "https://a.com/l")).is_err());
    }

    #[test]
    fn feed_rejects_bad_name_chars() {
        assert!(build_group(&feed("a b", "https://a.com/l")).is_err());
        assert!(build_group(&feed("a/b", "https://a.com/l")).is_err());
        assert!(build_group(&feed("a-b_c", "https://a.com/l")).is_ok());
    }

    #[test]
    fn feed_action_parsed() {
        let mut f = feed("x", "https://a.com/l");
        f.action = Some("log".to_string());
        assert_eq!(build_group(&f).unwrap().action, homewaf_config::IpGroupAction::Log);

        f.action = Some("challenge".to_string());
        assert_eq!(
            build_group(&f).unwrap().action,
            homewaf_config::IpGroupAction::Challenge
        );

        f.action = Some("bogus".to_string());
        assert!(build_group(&f).is_err());
    }

    #[test]
    fn feed_scope_preserved() {
        let mut f = feed("x", "https://a.com/l");
        f.scope = Some(vec!["nas".to_string()]);
        assert_eq!(build_group(&f).unwrap().scope, vec!["nas"]);
    }

    // ============================================================
    // 白名单构造
    // ============================================================

    fn wl(app: Option<&str>, path: Option<&str>, rule: Option<&str>) -> WhitelistInput {
        WhitelistInput {
            id: None,
            app: app.map(|s| s.to_string()),
            path: path.map(|s| s.to_string()),
            rule_id: rule.map(|s| s.to_string()),
            note: None,
        }
    }

    #[test]
    fn whitelist_with_path_is_valid() {
        let row = build_whitelist(&wl(None, Some("/admin/editor"), None)).unwrap();
        assert_eq!(row.path.as_deref(), Some("/admin/editor"));
        assert!(row.rule_id.is_none(), "未指定规则表示跳过全部检测");
        assert!(row.id.starts_with("wl-"));
    }

    #[test]
    fn whitelist_with_only_rule_is_valid() {
        let row = build_whitelist(&wl(None, None, Some("xss-script-tag"))).unwrap();
        assert_eq!(row.rule_id.as_deref(), Some("xss-script-tag"));
    }

    #[test]
    fn whitelist_with_only_app_is_valid() {
        assert!(build_whitelist(&wl(Some("nas"), None, None)).is_ok());
    }

    #[test]
    fn whitelist_all_empty_is_rejected() {
        // 三个都不填等于关闭全部检测，必须拦住
        let err = build_whitelist(&wl(None, None, None)).unwrap_err();
        assert!(err.contains("至少"), "{err}");
    }

    #[test]
    fn whitelist_path_must_start_with_slash() {
        let err = build_whitelist(&wl(None, Some("admin"), None)).unwrap_err();
        assert!(err.contains("/"), "{err}");
    }

    #[test]
    fn whitelist_blank_strings_treated_as_none() {
        let input = WhitelistInput {
            id: Some("  ".to_string()),
            app: Some("  ".to_string()),
            path: Some("/x".to_string()),
            rule_id: Some("".to_string()),
            note: Some("  ".to_string()),
        };
        let row = build_whitelist(&input).unwrap();
        assert!(row.app.is_none(), "空白字符串应视为不限制");
        assert!(row.rule_id.is_none());
        assert!(row.note.is_none());
        assert!(row.id.starts_with("wl-"), "空白 id 应自动生成");
    }

    #[test]
    fn whitelist_explicit_id_kept() {
        let mut input = wl(None, Some("/x"), None);
        input.id = Some("custom-id".to_string());
        assert_eq!(build_whitelist(&input).unwrap().id, "custom-id");
    }

    #[test]
    fn csv_fields_are_quoted_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn csv_formula_injection_is_neutralized() {
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("+cmd"), "'+cmd");
        assert_eq!(csv_field("-2+3"), "'-2+3");
    }

    #[test]
    fn utc_format_matches_known_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00");
    }

    // ============================================================
    // 统计报表聚合
    // ============================================================

    #[test]
    fn rate_handles_zero_and_rounding() {
        assert_eq!(rate(0, 0), 0.0);
        assert_eq!(rate(1, 3), 33.33);
        assert_eq!(rate(2, 2), 100.0);
    }

    #[test]
    fn date_of_takes_calendar_day() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn norm_app_trims_and_drops_empty() {
        assert_eq!(norm_app(&None), None);
        assert_eq!(norm_app(&Some("   ".to_string())), None);
        assert_eq!(norm_app(&Some(" nas ".to_string())), Some("nas"));
    }

    #[test]
    fn report_summarizes_day() {
        let st = state();
        let day = 1_700_006_400;
        st.store
            .save_traffic(&[homewaf_store::TrafficBucketRow {
                minute: day + 60,
                app: "nas".to_string(),
                requests: 10,
                pv: 8,
                blocked: 2,
                status_4xx: 3,
                status_5xx: 1,
                unique_ips: 2,
                unique_visitors: 2,
                ips: vec![1, 2],
                visitors: vec![10, 20],
            }])
            .unwrap();
        st.store
            .insert_event(
                &homewaf_store::Event::new(day + 30, homewaf_store::EventKind::Detect, "1.1.1.1")
                    .with_rules("sqli-union")
                    .with_action("block"),
            )
            .unwrap();

        // 传入一天中间的任意时刻，也会对齐到当天
        let r = build_report(&st, day + 100, None).unwrap();
        assert_eq!(r.id, day);
        assert_eq!(r.date, date_of(day));
        assert_eq!(r.totals.requests, 10);
        assert_eq!(r.totals.blocked, 2);
        assert_eq!(r.block_rate, 20.0);
        assert_eq!(r.four_xx_rate, 30.0);
        assert_eq!(r.kinds.len(), 1);
        assert_eq!(r.top_ips[0].ip, "1.1.1.1");
        assert!(r.top_ips[0].geo.is_none(), "未配置 mmdb 时不做归属地");
    }

    #[test]
    fn report_filters_by_app() {
        let st = state();
        let day = 1_700_006_400;
        st.store
            .save_traffic(&[
                homewaf_store::TrafficBucketRow {
                    minute: day + 60,
                    app: "nas".to_string(),
                    requests: 5,
                    ..Default::default()
                },
                homewaf_store::TrafficBucketRow {
                    minute: day + 60,
                    app: "blog".to_string(),
                    requests: 7,
                    ..Default::default()
                },
            ])
            .unwrap();

        assert_eq!(build_report(&st, day, Some("nas")).unwrap().totals.requests, 5);
        assert_eq!(build_report(&st, day, None).unwrap().totals.requests, 12);
    }
}
