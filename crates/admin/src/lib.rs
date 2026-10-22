//! HomeWAF 管理 API 与 Web 控制台。
//!
//! 设计取舍：
//! - **API 与前端同一个 crate**，前端是嵌入二进制的静态文件，没有构建步骤
//! - **认证用 Bearer token**，未配置 token 时只允许回环访问（家用默认安全）
//! - **写操作后显式触发重载**，这是 DB 模式补回热重载的唯一途径

pub mod geoip;

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
        .route("/api/geoip", get(geoip_status))
        .route("/api/apps", get(list_apps).post(upsert_app))
        .route("/api/apps/{id}", delete(delete_app))
        .route("/api/rules", get(list_rules).post(upsert_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/bans", get(list_bans))
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

async fn stats(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }

    let state = ctx.shared.load_full();
    let now = homewaf_acl::now_unix();

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

    // 分类映射必须读取当前生效规则集，否则订阅规则会全部落进 other
    let matcher = state.engine.matcher();
    let mut category_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let rule_categories: std::collections::HashMap<&str, &str> = matcher
        .metas()
        .map(|r| (r.id.as_str(), r.category.as_str()))
        .collect();

    for rules in ctx
        .store
        .event_rule_strings(start, 50_000)
        .unwrap_or_default()
    {
        for rule in rules.split(',').filter(|s| !s.is_empty()) {
            let category = rule_categories
                .get(rule)
                .copied()
                .unwrap_or_else(|| if rule.starts_with("cc-") { "cc" } else { "other" });
            *category_counts.entry(category).or_insert(0) += 1;
        }
    }

    let mut categories: Vec<CategoryCount> = category_counts
        .into_iter()
        .map(|(name, count)| CategoryCount {
            name: name.to_string(),
            count,
        })
        .collect();
    categories.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    categories.truncate(8);

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
    })
    .into_response()
}

// ============================================================
// GeoIP / 地理分布
// ============================================================

#[derive(Deserialize)]
struct GeoQuery {
    /// 时间范围（秒），默认 24 小时
    #[serde(default)]
    range: Option<i64>,
    #[serde(default)]
    app: Option<String>,
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
    Query(q): Query<GeoQuery>,
) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let range = q.range.unwrap_or(86_400).clamp(60, 86_400);
    let app = q
        .app
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let now = homewaf_acl::now_unix();
    let data = ctx.metrics.dashboard(range, app, now);
    Json(ctx.geoip.resolve(&data.ips)).into_response()
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

    if app.upstreams.is_empty() {
        return Err("至少需要一个上游".into());
    }
    for (i, u) in app.upstreams.iter().enumerate() {
        if u.addr.trim().is_empty() {
            return Err(format!("上游 {} 的地址不能为空", i + 1));
        }
        if u.port == Some(0) {
            return Err(format!("上游 {} 的端口不能为 0", i + 1));
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
}
