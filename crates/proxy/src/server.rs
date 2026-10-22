//! Pingora 集成。

use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::Session;

use homewaf_acl::{BanTable, Decision as AclDecision};
use homewaf_config::RateLimitAction;
use homewaf_limit::{ConnGuard, LimitParams};
use homewaf_store::{BanRecord, Event, EventKind, Store};

use crate::challenge::{self, ChallengeService, CHALLENGE_PATH, COOKIE_NAME};
use crate::headers::{self, ForwardedCtx};
use crate::metrics::{TrafficMetrics, TrafficSample};
use crate::realip;
use crate::reload::{RuntimeState, SharedState};
use crate::upstream;

/// 请求 ID 计数器。
static REQ_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 生成一个短请求 ID。
///
/// 8 位十六进制，够短能人眼扫，也够唯一（同一天内不会重复）。
/// 这是把 access / upstream / security 三个日志文件串起来的唯一线索——
/// 没有它，一个请求的完整链路只能靠时间戳猜。
fn next_request_id() -> String {
    use std::sync::atomic::Ordering;
    let n = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // 固定 8 位十六进制：取纳秒的低 24 位 + 计数器的低 8 位。
    // 不取整 40 位是因为 `{:08x}` 只是"至少 8 位"，超了会变成 9-10 位，扫起来不整齐。
    format!("{:08x}", ((nanos & 0x00FF_FFFF) << 8) | (n & 0xFF))
}

/// 每个请求的上下文，在 `request_filter` 与 `upstream_peer` 之间传递决策结果。
#[derive(Default)]
pub struct RequestCtx {
    /// 请求 ID，贯穿所有日志
    pub request_id: String,
    /// 命中的应用索引
    pub app_index: Option<usize>,
    /// 命中的路由索引
    pub route_index: Option<usize>,
    /// 选中的上游下标（用于回写健康状态）
    pub upstream_slot: Option<usize>,
    /// 是否选中的是备份上游
    pub upstream_backup: bool,
    /// 已解析的上游地址 `host:port`
    pub upstream: Option<String>,
    /// 是否走 TLS 回源
    pub upstream_tls: bool,
    /// TLS 回源的 SNI
    pub upstream_sni: String,
    /// TLS 回源是否校验证书
    pub upstream_verify: bool,
    /// 规范化后的路径（转发时必须用它）
    pub normalized_path: String,
    /// 原始查询串，转发时拼回
    pub query: Option<String>,
    /// 还原后的真实客户端 IP
    pub client_ip: Option<IpAddr>,
    /// TCP 直连 IP
    pub direct_ip: Option<IpAddr>,
    /// IP 来源（直连或某个转发头）
    pub ip_source: Option<crate::realip::IpSource>,
    /// 直连来源是否属于可信代理
    pub trusted_proxy: bool,
    /// 命中的应用 ID（未匹配路由时为空）
    pub app_id: String,
    /// 本请求是否被 WAF 主动拦截，供流量统计区分“上游 4xx”和“WAF 拦截”
    pub blocked: bool,
    /// 原始 Host（不含端口）
    pub original_host: String,
    /// `http` 或 `https`
    pub scheme: &'static str,
    /// 原始端口
    pub port: u16,
    /// ACL 判定结果（写入日志）
    pub acl_reason: Option<String>,
    /// 被 ACL 明确放行（后续可跳过检测）
    pub acl_allowed: bool,
    /// 本请求使用的运行时状态快照。
    ///
    /// 热重载会替换全局状态，但进行中的请求必须继续用同一份快照，
    /// 否则会出现"路由用新配置、上游用旧池"的错配。
    pub state: Option<Arc<RuntimeState>>,
    /// 请求体累积器。`Some` 表示这个请求需要做 body 检测
    pub body_buffer: Option<homewaf_detect::BodyBuffer>,
    /// body 检测是否已判定拦截
    pub body_blocked: bool,
    /// 本请求生效的检测策略（body 阶段继续使用）
    pub scan_policy: homewaf_detect::ScanPolicy,
    /// 本请求的白名单豁免（body 阶段继续使用）
    pub exemption: Option<homewaf_detect::Exemption>,
    /// 并发连接槽位，请求结束自动释放
    pub conn_guard: Option<ConnGuard>,
    /// 本请求是否已通过人机验证
    pub challenge_passed: bool,
    /// 请求开始时间，用于统计
    pub start: Option<Instant>,
}

/// 代理主体。
pub struct WafProxy {
    state: SharedState,
    bans: Arc<BanTable>,
    /// 持久化层。`None` 表示纯内存运行
    store: Option<Arc<Store>>,
    /// 流量指标。与控制台共享同一个实例
    metrics: Arc<TrafficMetrics>,
    /// 人机验证签名服务（密钥进程内唯一，重启后旧凭据失效）
    challenges: Arc<ChallengeService>,
}

impl WafProxy {
    pub fn new(
        state: SharedState,
        bans: Arc<BanTable>,
        store: Option<Arc<Store>>,
        metrics: Arc<TrafficMetrics>,
    ) -> Self {
        Self {
            state,
            bans,
            store,
            metrics,
            challenges: Arc::new(ChallengeService::new()),
        }
    }

    /// 当前状态快照（供测试与调试）。
    pub fn snapshot(&self) -> Arc<RuntimeState> {
        self.state.load_full()
    }

    /// 校验挑战回调，成功后下发 Cookie 并跳回原地址。
    #[allow(clippy::too_many_arguments)]
    async fn handle_challenge_callback(
        &self,
        session: &mut Session,
        state: &RuntimeState,
        app: &str,
        ip: Option<IpAddr>,
        query: Option<&str>,
        secure: bool,
        request_id: &str,
    ) -> Result<bool> {
        let token = query.and_then(|q| query_param(q, "token"));
        let nonce = query.and_then(|q| query_param(q, "nonce"));
        let (Some(token), Some(nonce)) = (token, nonce) else {
            return write_text(session, 400, "验证参数缺失").await;
        };

        let now = homewaf_acl::now_unix().max(0) as u64;
        match self.challenges.verify(&token, &nonce, app, ip, now) {
            Ok(payload) => {
                let cookie = self.challenges.issue_cookie(&state.challenge, app, ip, now);
                let ttl = state.challenge.ttl.as_secs();
                let next = safe_next(payload.next());

                let mut resp = ResponseHeader::build(303, None)?;
                resp.insert_header("location", next)?;
                resp.insert_header(
                    "set-cookie",
                    self.challenges.cookie_header(&cookie, ttl, secure),
                )?;
                resp.insert_header("content-length", "0")?;
                resp.insert_header("cache-control", "no-store")?;
                session.write_response_header(Box::new(resp), true).await?;

                tracing::info!(
                    target: "homewaf.security",

                    req = %request_id,
                    app,
                    client_ip = ?ip,
                    next,
                    "人机验证通过"
                );
                Ok(true)
            }
            Err(e) => {
                tracing::debug!(
                    target: "homewaf.security",

                    req = %request_id,
                    app,
                    client_ip = ?ip,
                    error = %e,
                    "人机验证失败"
                );
                write_text(session, 400, "验证失败，请刷新重试").await
            }
        }
    }

    /// 下发挑战页。状态码区分"普通要求验证"（403）与"CC 限流"（429）。
    #[allow(clippy::too_many_arguments)]
    async fn issue_challenge(
        &self,
        session: &mut Session,
        state: &RuntimeState,
        app: &str,
        ip: Option<IpAddr>,
        next: &str,
        status: u16,
    ) -> Result<bool> {
        let now = homewaf_acl::now_unix().max(0) as u64;
        let issued = self.challenges.issue(&state.challenge, app, ip, next, now);

        tracing::info!(
            target: "homewaf.security",

            app,
            client_ip = ?ip,
            difficulty = issued.difficulty,
            status,
            "下发人机验证"
        );

        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header("content-type", "text/html; charset=utf-8")?;
        resp.insert_header("content-length", issued.page.len().to_string())?;
        resp.insert_header("cache-control", "no-store")?;
        resp.insert_header("x-homewaf-challenge", issued.difficulty.to_string())?;

        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(issued.page)), true)
            .await?;
        Ok(true)
    }

    /// 记录 CC 事件。`scope` 只用于把三层限流区分开。
    #[allow(clippy::too_many_arguments)]
    fn record_security_event(
        &self,
        ctx: &RequestCtx,
        kind: EventKind,
        app: &str,
        path: &str,
        rules: &str,
        score: u32,
        action: &str,
    ) {
        let Some(store) = &self.store else {
            return;
        };
        let event = Event::new(
            homewaf_acl::now_unix(),
            kind,
            ctx.client_ip.map(|i| i.to_string()).unwrap_or_default(),
        )
        .with_app(app.to_string())
        .with_path(path.to_string())
        .with_rules(rules.to_string())
        .with_score(score)
        .with_action(action.to_string());
        if let Err(e) = store.insert_event(&event) {
            tracing::warn!(error = %e, "写入安全事件失败");
        }
    }

    fn record_rate_event(
        &self,
        ctx: &RequestCtx,
        app: &str,
        path: &str,
        scope: homewaf_limit::Scope,
        action: &str,
        observed: u32,
    ) {
        let Some(store) = &self.store else {
            return;
        };
        let now = homewaf_acl::now_unix();
        let event = Event::new(
            now,
            EventKind::RateLimit,
            ctx.client_ip.map(|i| i.to_string()).unwrap_or_default(),
        )
        .with_app(app.to_string())
        .with_path(path.to_string())
        .with_rules(format!("cc-{}", scope.as_str()))
        .with_score(observed)
        .with_action(action.to_string());
        if let Err(e) = store.insert_event(&event) {
            tracing::warn!(error = %e, "写入 CC 事件失败");
        }
    }
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            request_id: next_request_id(),
            start: Some(Instant::now()),
            scheme: "http",
            ..Default::default()
        }
    }

    /// 请求头阶段：还原客户端 IP、决定路由，未匹配则直接拒绝。
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 取一份状态快照，整个请求生命周期都用它
        let state = self.state.load_full();
        ctx.state = Some(state.clone());

        // 先取连接信息（Copy 与 bool），避免后续借用冲突
        // Pingora 的 SocketAddr 是 Inet/Unix 枚举，取 Inet 分支
        let direct: Option<SocketAddr> = session
            .downstream_session
            .client_addr()
            .and_then(|addr| addr.as_inet().copied());
        let is_tls = session
            .downstream_session
            .digest()
            .map(|d| d.ssl_digest.is_some())
            .unwrap_or(false);

        // 一次性把请求信息取成拥有型数据，后面要跨 await 使用
        let (
            raw_host,
            method,
            path,
            uri_path,
            query,
            user_agent,
            cookie_header,
            content_type,
            content_length,
        ) = {
            let req = session.req_header();
            (
                extract_host(req),
                req.method.as_str().to_string(),
                req.uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string()),
                req.uri.path().to_string(),
                req.uri.query().map(|q| q.to_string()),
                req.headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                req.headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                req.headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                req.headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok()),
            )
        };

        // 真实 IP 还原
        let client = realip::resolve(
            direct.as_ref(),
            &session.req_header().headers,
            &state.real_ip,
        );
        if let Some(c) = client {
            ctx.client_ip = Some(c.real);
            ctx.direct_ip = Some(c.direct);
            ctx.trusted_proxy = c.trusted_proxy;
            ctx.ip_source = Some(c.source);
        }

        let host = strip_port(&raw_host);
        let port = extract_port(&raw_host).unwrap_or(if is_tls { 443 } else { 80 });
        let scheme: &'static str = if is_tls { "https" } else { "http" };

        ctx.original_host = host.clone();
        ctx.port = port;
        ctx.scheme = scheme;

        let Some(hit) = state.router.resolve(&host, port, &path) else {
            // 未配置的域名：返回 404，不泄露任何后端指纹
            return write_empty(session, 404).await;
        };

        let app = state
            .router
            .app(hit.app_index)
            .expect("路由返回的应用索引必然有效");
        let Some(policy) = state.policies.resolve(hit.app_index, hit.route_index) else {
            tracing::error!(app = %app.id, "应用策略缺失，拒绝请求");
            return write_empty(session, 500).await;
        };
        ctx.app_id = app.id.clone();

        // ACL：用还原后的真实 IP 判定，而不是直连 IP
        if let Some(ip) = ctx.client_ip {
            match state.acl.check(ip, Some(&app.id)) {
                AclDecision::Deny(reason) => {
                    let desc = reason.describe();
                    tracing::info!(
                        target: "homewaf.security",

                        req = %ctx.request_id,
                        client_ip = %ip,
                        app = %app.id,
                        reason = %desc,
                        "拒绝"
                    );
                    self.record_security_event(
                        ctx,
                        EventKind::Acl,
                        &app.id,
                        &hit.normalized_path,
                        &desc,
                        0,
                        "block",
                    );
                    ctx.acl_reason = Some(desc);
                    ctx.blocked = true;
                    return write_empty(session, 403).await;
                }
                AclDecision::Allow(reason) => {
                    ctx.acl_reason = Some(reason.describe());
                    ctx.acl_allowed = true;
                }
                AclDecision::Normal => {}
            }
        }

        // 自定义规则（兼容雷池格式）：白名单优先放行，黑名单直接拦截。
        // 放在 ACL 之后、自动封禁之前——白名单命中时连封禁都可以绕过。
        let mut custom_whitelisted = false;
        let custom = {
            let headers = &session.req_header().headers;
            let creq = crate::custom_rule::RuleRequest {
                app: &app.id,
                host: &host,
                ip: ctx.client_ip,
                path: &hit.normalized_path,
                query: query.as_deref(),
                method: &method,
                user_agent: user_agent.as_deref(),
                content_type: content_type.as_deref(),
                cookie: cookie_header.as_deref(),
                headers,
            };
            crate::custom_rule::evaluate(&state.custom_rules, &creq)
        };
        match custom {
            Some(crate::custom_rule::CustomDecision::Allow(name)) => {
                tracing::debug!(req = %ctx.request_id, rule = %name, "自定义白名单命中");
                ctx.acl_allowed = true;
                custom_whitelisted = true;
            }
            Some(crate::custom_rule::CustomDecision::Deny(name)) => {
                let reason = format!("自定义黑名单：{name}");
                tracing::info!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    client_ip = ?ctx.client_ip,
                    app = %app.id,
                    rule = %name,
                    "自定义规则拦截"
                );
                self.record_security_event(
                    ctx,
                    EventKind::Acl,
                    &app.id,
                    &hit.normalized_path,
                    &reason,
                    0,
                    "block",
                );
                ctx.acl_reason = Some(reason);
                ctx.blocked = true;
                return write_empty(session, 403).await;
            }
            None => {}
        }

        // 自动封禁检查：命中直接拒绝，连检测都不必做。
        // 这是 WAF 的核心价值回路——被封的 IP 不再消耗检测资源。
        if let Some(ip) = ctx.client_ip {
            let now_secs = homewaf_acl::now_unix().max(0) as u64;
            if !custom_whitelisted {
                if let Some(status) = self.bans.check(ip, now_secs) {
                    tracing::info!(
                        target: "homewaf.security",

                        req = %ctx.request_id,
                        client_ip = %ip,
                        remaining_secs = status.remaining_secs,
                        offenses = status.offenses,
                        "处于自动封禁中，拒绝"
                    );
                    self.record_security_event(
                        ctx,
                        EventKind::Ban,
                        &app.id,
                        &hit.normalized_path,
                        "自动封禁",
                        status.offenses,
                        "block",
                    );
                    ctx.acl_reason = Some("自动封禁".to_string());
                    ctx.blocked = true;
                    return write_empty(session, 403).await;
                }
            }
        }

        // CIDR 策略：deny 优先，allow 非空时只允许列表内地址
        if let Some(ip) = ctx.client_ip {
            let denied = policy.deny_cidr.iter().any(|net| net.contains(&ip));
            let outside_allow = !policy.allow_cidr.is_empty()
                && !policy.allow_cidr.iter().any(|net| net.contains(&ip));
            if denied || outside_allow {
                tracing::info!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    client_ip = %ip,
                    app = %app.id,
                    denied,
                    outside_allow,
                    "被应用 CIDR 策略拒绝"
                );
                let reason = if denied {
                    "命中 deny_cidr"
                } else {
                    "不在 allow_cidr 内"
                };
                self.record_security_event(
                    ctx,
                    EventKind::Acl,
                    &app.id,
                    &hit.normalized_path,
                    reason,
                    0,
                    "block",
                );
                ctx.acl_reason = Some(reason.to_string());
                ctx.blocked = true;
                return write_empty(session, 403).await;
            }
        }

        // 人机验证回调：校验令牌 + 工作量证明，通过后下发 Cookie 并跳回原地址
        if uri_path == CHALLENGE_PATH {
            return self
                .handle_challenge_callback(
                    session,
                    &state,
                    &app.id,
                    ctx.client_ip,
                    query.as_deref(),
                    scheme == "https",
                    &ctx.request_id,
                )
                .await;
        }

        // 路由级方法限制
        if let Some(methods) = &policy.allow_methods {
            let method_allowed = methods.iter().any(|m| m == &method)
                || (method == "HEAD" && methods.iter().any(|m| m == "GET"));
            if !method_allowed {
                tracing::info!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    method = %method,
                    allowed = ?methods,
                    app = %app.id,
                    "方法不被允许"
                );
                self.record_security_event(
                    ctx,
                    EventKind::Acl,
                    &app.id,
                    &hit.normalized_path,
                    "method-not-allowed",
                    0,
                    "block",
                );
                ctx.blocked = true;
                let mut resp = ResponseHeader::build(405, None)?;
                resp.insert_header("allow", methods.join(", "))?;
                resp.insert_header("content-length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        // 请求体上限（明确的策略声明，超过直接 413）
        if let Some(len) = content_length {
            if len > policy.max_body_size {
                tracing::info!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    content_length = len,
                    max_body_size = policy.max_body_size,
                    app = %app.id,
                    "请求体超过应用策略上限"
                );
                self.record_security_event(
                    ctx,
                    EventKind::Acl,
                    &app.id,
                    &hit.normalized_path,
                    "body-too-large",
                    0,
                    "block",
                );
                ctx.blocked = true;
                return write_text(session, 413, "请求体过大").await;
            }
        }

        // 已通过的人机验证凭据
        let now_secs = homewaf_acl::now_unix().max(0) as u64;
        let challenge_passed = cookie_header
            .as_deref()
            .and_then(|h| challenge::cookie_value(Some(h), COOKIE_NAME))
            .map(|v| {
                self.challenges
                    .verify_cookie(v, &app.id, ctx.client_ip, now_secs)
            })
            .unwrap_or(false);
        ctx.challenge_passed = challenge_passed;

        // 应用/路由要求人机验证
        if policy.require_challenge && !challenge_passed && !ctx.acl_allowed {
            self.record_security_event(
                ctx,
                EventKind::Challenge,
                &app.id,
                &hit.normalized_path,
                "challenge",
                0,
                "block",
            );
            ctx.blocked = true;
            if state.challenge.enabled {
                return self
                    .issue_challenge(session, &state, &app.id, ctx.client_ip, &path, 403)
                    .await;
            }
            // 要求挑战但挑战功能被关闭：保守拦截，而不是静默放行
            tracing::warn!(
                target: "homewaf.security",

                req = %ctx.request_id,
                app = %app.id,
                "require_challenge 已开启但 challenge.enabled=false，按拦截处理"
            );
            return write_text(session, 403, "人机验证未启用").await;
        }

        // CC 防护：ACL 明确放行的地址不参与限流
        if !ctx.acl_allowed {
            if let Some(action) = policy.limit_action() {
                let params = LimitParams {
                    global_qps: policy.ratelimit.global_qps,
                    per_ip_qps: policy.ratelimit.per_ip_qps,
                    per_url_qps: policy.ratelimit.per_url_qps,
                };

                // 只有开了单 URL 限流才拼 key，避免每个请求都分配字符串
                let url_key = (params.per_url_qps > 0)
                    .then(|| format!("{}\0{}", app.id, hit.normalized_path));
                let qps_hit = state
                    .limiter
                    .check(ctx.client_ip, url_key.as_deref(), params);

                if let Some(hit_limit) = qps_hit {
                    let blocked = match action {
                        RateLimitAction::Log => false,
                        RateLimitAction::Block => true,
                        RateLimitAction::Challenge => {
                            if !state.challenge.enabled || challenge_passed {
                                true
                            } else {
                                ctx.conn_guard.take();
                                self.record_rate_event(
                                    ctx,
                                    &app.id,
                                    &hit.normalized_path,
                                    hit_limit.scope,
                                    "block",
                                    hit_limit.observed,
                                );
                                self.record_security_event(
                                    ctx,
                                    EventKind::Challenge,
                                    &app.id,
                                    &hit.normalized_path,
                                    "cc-challenge",
                                    hit_limit.observed,
                                    "block",
                                );
                                ctx.blocked = true;
                                return self
                                    .issue_challenge(
                                        session,
                                        &state,
                                        &app.id,
                                        ctx.client_ip,
                                        &path,
                                        429,
                                    )
                                    .await;
                            }
                        }
                    };

                    tracing::warn!(
                        target: "homewaf.security",

                        req = %ctx.request_id,
                        client_ip = ?ctx.client_ip,
                        app = %app.id,
                        scope = hit_limit.scope.as_str(),
                        limit = hit_limit.limit,
                        observed = hit_limit.observed,
                        action = ?action,
                        blocked,
                        "CC 防护触发"
                    );
                    self.record_rate_event(
                        ctx,
                        &app.id,
                        &hit.normalized_path,
                        hit_limit.scope,
                        if blocked { "block" } else { "log" },
                        hit_limit.observed,
                    );

                    if blocked {
                        ctx.blocked = true;
                        let body = "请求过于频繁，请稍后再试";
                        let mut resp = ResponseHeader::build(429, None)?;
                        resp.insert_header("content-type", "text/plain; charset=utf-8")?;
                        resp.insert_header("content-length", body.len().to_string())?;
                        resp.insert_header("retry-after", "1")?;
                        resp.insert_header("cache-control", "no-store")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session
                            .write_response_body(Some(Bytes::from_static(body.as_bytes())), true)
                            .await?;
                        return Ok(true);
                    }
                }

                // 并发连接数单独限制；Log 模式不拒绝连接
                if action != RateLimitAction::Log {
                    if let Some(ip) = ctx.client_ip {
                        match state
                            .limiter
                            .try_acquire_conn(ip, policy.ratelimit.per_ip_conn)
                        {
                            Some(guard) => ctx.conn_guard = Some(guard),
                            None => {
                                tracing::warn!(
                                    target: "homewaf.security",

                                    req = %ctx.request_id,
                                    client_ip = %ip,
                                    app = %app.id,
                                    limit = policy.ratelimit.per_ip_conn,
                                    "并发连接数超限"
                                );
                                self.record_rate_event(
                                    ctx,
                                    &app.id,
                                    &hit.normalized_path,
                                    homewaf_limit::Scope::Ip,
                                    "block",
                                    policy.ratelimit.per_ip_conn,
                                );
                                ctx.blocked = true;
                                return write_text(session, 429, "并发连接数过多").await;
                            }
                        }
                    }
                }
            }
        }

        // 自定义白名单命中：按雷池语义直接放行，跳过应用层检测（含 body 检测）。
        if custom_whitelisted {
            tracing::debug!(
                req = %ctx.request_id,
                app = %app.id,
                "自定义白名单命中，跳过检测"
            );
        } else {
            // 应用层攻击检测。
            // 用规范化后的路径——检测与转发必须看到同一个路径，否则又是一条绕过。
            let method_is_bodyless = method == "GET" || method == "HEAD";
            if !method_is_bodyless
                && homewaf_detect::should_inspect_content_type(content_type.as_deref())
            {
                let cap = policy
                    .max_body_size
                    .min(homewaf_detect::DEFAULT_MAX_INSPECT_BYTES as u64)
                    .max(1) as usize;
                ctx.body_buffer = Some(homewaf_detect::BodyBuffer::new(cap));
            }

            // 先算白名单豁免：命中的路径/规则不再检测
            let exemption =
                homewaf_detect::whitelist::compute(&state.whitelist, &app.id, &hit.normalized_path);

            let verdict = state.engine.inspect_with_policy(
                &homewaf_detect::InspectionInput {
                    path: hit.normalized_path.clone(),
                    query: query.clone(),
                    user_agent,
                    cookie: cookie_header,
                    ..Default::default()
                },
                &exemption,
                &policy.scan,
            );

            // body 阶段继续使用同一份策略与豁免
            ctx.scan_policy = policy.scan;
            ctx.exemption = Some(exemption.clone());

            if !verdict.is_clean() {
                tracing::warn!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    rules = ?verdict.rule_ids(),
                    score = verdict.score,
                    blocking_score = verdict.blocking_score,
                    blocked = verdict.blocked,
                    observe = verdict.observe,
                    whitelist = ?exemption.matched,
                    app = %app.id,
                    path = %hit.normalized_path,
                    "检测命中"
                );

                // 记录事件（控制台与事后溯源的数据来源）
                if let Some(store) = &self.store {
                    let action = if verdict.observe {
                        "observe"
                    } else if verdict.blocked {
                        "block"
                    } else {
                        "log"
                    };
                    let event = Event::new(
                        now_secs as i64,
                        EventKind::Detect,
                        ctx.client_ip.map(|i| i.to_string()).unwrap_or_default(),
                    )
                    .with_app(app.id.clone())
                    .with_path(hit.normalized_path.clone())
                    .with_rules(verdict.rule_ids().join(","))
                    .with_score(verdict.score)
                    .with_action(action);
                    if let Err(e) = store.insert_event(&event) {
                        tracing::warn!(error = %e, "写入检测事件失败");
                    }
                }

                // 累计分数并可能触发封禁。
                // 观察模式下不封禁——观察的全部意义就是"先看误报再决定"。
                if !verdict.observe {
                    if let Some(ip) = ctx.client_ip {
                        if let Some(outcome) =
                            self.bans.record(ip, verdict.blocking_score, now_secs)
                        {
                            self.record_security_event(
                                ctx,
                                EventKind::Ban,
                                &app.id,
                                &hit.normalized_path,
                                &verdict.rule_ids().join(","),
                                verdict.score,
                                "ban",
                            );
                            tracing::warn!(
                                target: "homewaf.security",

                                req = %ctx.request_id,
                                client_ip = %ip,
                                duration_secs = outcome.duration_secs,
                                offenses = outcome.offenses,
                                rules = ?verdict.rule_ids(),
                                "检测触发自动封禁"
                            );

                            // 封禁落库，重启后仍在
                            if let Some(store) = &self.store {
                                let record = BanRecord {
                                    ip: ip.to_string(),
                                    until: outcome.until as i64,
                                    offenses: outcome.offenses,
                                    score: outcome.score,
                                    reason: verdict.rule_ids().join(","),
                                    created_at: now_secs as i64,
                                };
                                if let Err(e) = store.upsert_ban(&record, now_secs as i64) {
                                    tracing::warn!(error = %e, "写入封禁记录失败");
                                }
                            }
                        }
                    }
                }
            }

            if verdict.blocked {
                ctx.blocked = true;
                return write_empty(session, 403).await;
            }
        }

        // 本地接入方式：静态文件 / 重定向不经过上游，但仍走完上面的 ACL 与检测。
        match app.access_mode {
            homewaf_config::AccessMode::Static => {
                return serve_static(
                    session,
                    app,
                    &hit.normalized_path,
                    method.as_str(),
                    state.tamper.get(hit.app_index),
                    self.store.as_deref(),
                    ctx.client_ip,
                )
                .await;
            }
            homewaf_config::AccessMode::Redirect => {
                return serve_redirect(session, app, &hit.normalized_path, query.as_deref()).await;
            }
            homewaf_config::AccessMode::Proxy => {}
        }

        let upstreams = state
            .router
            .route_of(&hit)
            .and_then(|r| r.upstreams.as_deref())
            .unwrap_or(&app.upstreams);

        if upstreams.is_empty() {
            return write_empty(session, 502).await;
        }

        // 从上游池里按负载均衡算法选一个
        let client_ip = ctx
            .client_ip
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let Some(sel) = state.pool.select(
            hit.app_index,
            hit.route_index,
            client_ip,
            upstream::now_ms(),
        ) else {
            // 所有上游都不健康：返回固定错误页，不暴露后端细节
            tracing::warn!(app = %app.id, "无可用上游，返回固定错误页");
            return service_unavailable(session).await;
        };

        state.pool.acquire(hit.app_index, hit.route_index, sel.slot);

        ctx.app_index = Some(hit.app_index);
        ctx.route_index = hit.route_index;
        ctx.upstream_slot = Some(sel.slot);
        ctx.upstream_backup = sel.backup;
        ctx.upstream = Some(sel.addr);
        ctx.upstream_tls = sel.tls;
        ctx.upstream_sni = sel.sni;
        ctx.upstream_verify = sel.verify;

        // 转发路径：命中路由配了 rewrite 就改写，否则用规范化后的原路径。
        // 注意检测用的是 `hit.normalized_path`（原始请求），不是改写后的——
        // 攻击者发什么就检测什么，不能因为内部改写绕过规则。
        let forward_path = match state
            .router
            .route_of(&hit)
            .and_then(|r| r.rewrite.as_ref().map(|rw| (r.path.as_str(), rw)))
        {
            Some((route_path, rw)) => {
                homewaf_router::rewrite::apply(&hit.normalized_path, route_path, rw)
            }
            None => hit.normalized_path.clone(),
        };

        ctx.normalized_path = forward_path;
        ctx.query = query;

        Ok(false)
    }

    /// 转发前：替换为规范化路径，并注入转发头。
    ///
    /// 路径替换不能省：路由决策用的是规范化路径，若转发仍用原始路径，
    /// `//x/../other` 会出现"路由到 A、后端收到 B"的绕过。
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 1. 路径规范化
        if !ctx.normalized_path.is_empty() {
            match build_upstream_target(&ctx.normalized_path, ctx.query.as_deref()) {
                Ok(uri) => upstream_request.set_uri(uri),
                Err(e) => {
                    tracing::warn!(
                        path = %ctx.normalized_path,
                        query = ?ctx.query,
                        error = %e,
                        "无法构造上游 URI，拒绝转发"
                    );
                    return Err(pingora::Error::new_str("invalid normalized uri"));
                }
            }
        }

        // 2. 转发头
        if let Some(client_ip) = ctx.client_ip {
            let fwd = ForwardedCtx {
                client_ip,
                scheme: ctx.scheme,
                host: ctx.original_host.clone(),
                port: ctx.port,
                trusted_proxy: ctx.trusted_proxy,
            };
            headers::apply(upstream_request, &fwd);
        }

        Ok(())
    }

    /// 请求体检测。
    ///
    /// 这个钩子在每个 chunk **转发前**调用，所以在这里返回错误时当前 chunk
    /// 还没发给上游。但之前的 chunk 已经发出去了——流式模型下无法做到
    /// "完整缓冲后统一检测"，这是有意的取舍：拦得住大部分攻击，
    /// 代价是命中时上游可能收到不完整的请求（通常会自行报错）。
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let policy = ctx.scan_policy;
        let (Some(buffer), Some(state)) = (ctx.body_buffer.as_mut(), ctx.state.as_ref()) else {
            return Ok(());
        };
        let Some(chunk) = body.as_ref() else {
            return Ok(());
        };

        buffer.push(chunk);

        // 非 UTF-8 的 body 不做内容检测（可能是编码过的二进制）
        let Some(text) = buffer.as_str() else {
            return Ok(());
        };
        if text.is_empty() {
            return Ok(());
        }

        let empty = homewaf_detect::Exemption::default();
        let exemption = ctx.exemption.as_ref().unwrap_or(&empty);
        let verdict = state.engine.inspect_with_policy(
            &homewaf_detect::InspectionInput {
                body: Some(text.to_string()),
                ..Default::default()
            },
            exemption,
            &policy,
        );

        if verdict.is_clean() {
            return Ok(());
        }

        tracing::warn!(
            target: "homewaf.security",

            req = %ctx.request_id,
            rules = ?verdict.rule_ids(),
            score = verdict.score,
            blocked = verdict.blocked,
            observe = verdict.observe,
            body_len = buffer.len(),
            truncated = buffer.is_truncated(),
            end_of_stream,
            "请求体检测命中"
        );

        if verdict.blocked {
            ctx.body_blocked = true;
            ctx.blocked = true;
            let mut resp = ResponseHeader::build(403, None)?;
            resp.insert_header("content-length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Err(pingora::Error::new_str("request body blocked by WAF"));
        }

        Ok(())
    }

    /// 选择上游。
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let addr = ctx
            .upstream
            .clone()
            .unwrap_or_else(|| "127.0.0.1:1".to_string());

        let mut peer = HttpPeer::new(addr.as_str(), ctx.upstream_tls, ctx.upstream_sni.clone());
        if ctx.upstream_tls {
            // 内网自签上游：SNI 仍然发送，但跳过证书与主机名校验
            peer.options.verify_cert = ctx.upstream_verify;
            peer.options.verify_hostname = ctx.upstream_verify;
        }

        Ok(Box::new(peer))
    }

    /// 上游连接失败：只记日志，失败计数统一在 `logging` 里做。
    ///
    /// 两个钩子都会在连接失败时触发，若各记一次会让 `fail_threshold` 实际减半。
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        tracing::warn!(
            upstream = ctx.upstream.as_deref().unwrap_or("-"),
            error = %e,
            "上游连接失败"
        );
        e
    }

    /// 请求日志。
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let elapsed_us = ctx
            .start
            .map(|s| s.elapsed().as_micros())
            .unwrap_or_default();
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);
        let method = &session.req_header().method;
        let path = session.req_header().uri.path();

        // 回写上游健康状态与活跃连接数。
        // 用本请求的快照，而不是 self.state——热重载后新池的计数与旧池无关。
        if let (Some(state), Some(app), Some(slot)) =
            (ctx.state.as_ref(), ctx.app_index, ctx.upstream_slot)
        {
            state.pool.release(app, ctx.route_index, slot);
            let failed = e.is_some() || status >= 500;
            if failed {
                state
                    .pool
                    .mark_failure(app, ctx.route_index, slot, upstream::now_ms());
            } else {
                state.pool.mark_success(app, ctx.route_index, slot);
            }
        }

        // 反代日志：只记真正走了上游的请求，含耗时与失败原因。
        // 排查"为什么慢/为什么 502"看这个文件，不用在 access 里翻。
        if let Some(upstream) = &ctx.upstream {
            tracing::info!(
                target: "homewaf.upstream",

                req = %ctx.request_id,
                app = ctx.app_index.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()),
                upstream = %upstream,
                backup = ctx.upstream_backup,
                status = status,
                latency_us = elapsed_us,
                error = e.map(|err| err.to_string()).unwrap_or_default(),
                "upstream request"
            );
        }

        // 流量指标：记录在日志之前，避免日志 IO 抖动影响统计归属。
        {
            let req = session.req_header();
            let ua = req.headers.get("user-agent").and_then(|v| v.to_str().ok());
            let referer = req.headers.get("referer").and_then(|v| v.to_str().ok());
            let host = if ctx.original_host.is_empty() {
                strip_port(&extract_host(req))
            } else {
                ctx.original_host.clone()
            };
            let path = if ctx.normalized_path.is_empty() {
                req.uri.path()
            } else {
                ctx.normalized_path.as_str()
            };
            self.metrics.record(TrafficSample {
                ts: homewaf_acl::now_unix(),
                app: &ctx.app_id,
                host: &host,
                path,
                method: method.as_str(),
                status,
                ip: ctx.client_ip,
                user_agent: ua,
                referer,
                blocked: ctx.blocked,
            });
        }

        tracing::info!(
            target: "homewaf.access",

            req = %ctx.request_id,
            method = %method,
            path = %path,
            status = status,
            upstream = ctx.upstream.as_deref().unwrap_or("-"),
            backup = ctx.upstream_backup,
            app = ctx.app_index.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()),
            client_ip = ctx.client_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()),
            direct_ip = ctx.direct_ip.map(|i| i.to_string()).unwrap_or_else(|| "-".to_string()),
            ip_source = ctx.ip_source.as_ref().map(|s| s.as_str()).unwrap_or("-"),
            acl = ctx.acl_reason.as_deref().unwrap_or("-"),
            latency_us = elapsed_us,
            "request"
        );
    }
}

/// 拼接转发给上游的 URI：规范化路径 + 原始 query。
///
/// 单独抽出来是为了可单测——这段逻辑决定后端收到什么路径，
/// 一旦出错就是"检测看到 A、后端收到 B"的绕过。
fn build_upstream_target(path: &str, query: Option<&str>) -> Result<http::Uri, String> {
    let mut target = String::with_capacity(path.len() + query.map_or(0, |q| q.len() + 1));
    target.push_str(path);
    if let Some(q) = query {
        if !q.is_empty() {
            target.push('?');
            target.push_str(q);
        }
    }
    target
        .parse()
        .map_err(|e| format!("`{target}` 不是合法的请求目标: {e}"))
}

/// 上游全部不可用时返回的固定页面。
///
/// 内容固定、不含任何后端信息（不泄露服务名、内部地址、错误栈），
/// 用户看到的是一个干净的「服务暂不可用」，而不是浏览器的默认错误页。
const SERVICE_UNAVAILABLE_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>503 服务暂不可用</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#f7f7f5; color:#2c2c2a;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }
  .box { text-align:center; padding:40px 24px; }
  h1 { font-size:64px; margin:0; color:#b4b2a9; font-weight:600; letter-spacing:-2px; }
  p  { font-size:15px; margin:16px 0 0; color:#5f5e5a; }
  .hint { font-size:13px; color:#888780; margin-top:8px; }
</style>
</head>
<body>
  <div class="box">
    <h1>503</h1>
    <p>服务暂不可用</p>
    <p class="hint">后端服务暂时无法访问，请稍后重试</p>
  </div>
</body>
</html>"#;

/// 写一个固定的 503 页面。
async fn service_unavailable(session: &mut Session) -> Result<bool> {
    let mut resp = ResponseHeader::build(503, None)?;
    resp.insert_header("content-type", "text/html; charset=utf-8")?;
    resp.insert_header("content-length", SERVICE_UNAVAILABLE_HTML.len().to_string())?;
    resp.insert_header("retry-after", "5")?;
    // 这个响应是 WAF 自己产生的，不该被缓存
    resp.insert_header("cache-control", "no-store")?;

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(
            Some(Bytes::from_static(SERVICE_UNAVAILABLE_HTML.as_bytes())),
            true,
        )
        .await?;
    Ok(true)
}

/// 写一个空响应体的状态码。
async fn write_empty(session: &mut Session, status: u16) -> Result<bool> {
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-length", "0")?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(true)
}

/// 写一个纯文本响应。内容固定，不回显任何用户输入。
async fn write_text(session: &mut Session, status: u16, body: &str) -> Result<bool> {
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "text/plain; charset=utf-8")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("cache-control", "no-store")?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
        .await?;
    Ok(true)
}

/// 本地静态文件响应。
///
/// 只允许 GET / HEAD；路径逐段检查，拒绝 `..` 与绝对路径段，
/// 再用 canonicalize 兜一层，确保最终文件始终位于站点根目录内。
async fn serve_static(
    session: &mut Session,
    app: &homewaf_config::Application,
    path: &str,
    method: &str,
    baseline: Option<&crate::tamper::TamperBaseline>,
    store: Option<&Store>,
    client_ip: Option<std::net::IpAddr>,
) -> Result<bool> {
    if !matches!(method, "GET" | "HEAD") {
        let mut resp = ResponseHeader::build(405, None)?;
        resp.insert_header("allow", "GET, HEAD")?;
        resp.insert_header("content-length", "0")?;
        session.write_response_header(Box::new(resp), true).await?;
        return Ok(true);
    }

    let root_cfg = app.static_site.root.trim();
    let Ok(root) = std::fs::canonicalize(root_cfg) else {
        tracing::warn!(app = %app.id, root = %root_cfg, "静态站点根目录不可用");
        return service_unavailable(session).await;
    };

    let rel = path.trim_start_matches('/');
    let mut candidate = root.join(rel);
    if candidate.is_dir() || path.ends_with('/') {
        candidate.push(&app.static_site.index);
    }

    let mut data = std::fs::read(&candidate).ok();
    if data.is_none() && app.static_site.spa_fallback {
        candidate = root.join(&app.static_site.index);
        data = std::fs::read(&candidate).ok();
    }
    let Some(data) = data else {
        return write_text(session, 404, "Not Found").await;
    };

    // 防止软链接把文件指到站点根目录之外
    let Ok(real) = std::fs::canonicalize(&candidate) else {
        return write_text(session, 404, "Not Found").await;
    };
    if !real.starts_with(&root) || !is_safe_relative(rel) {
        return write_text(session, 404, "Not Found").await;
    }

    // 网页防篡改：基线比对。只在受保护目录内生效。
    match crate::tamper::check_file(app, baseline, &real, &data) {
        crate::tamper::FileState::Modified | crate::tamper::FileState::Added => {
            let block = app.tamper.action == homewaf_config::TamperAction::Block;
            let act = if block { "block" } else { "log" };
            let file_path = real.display().to_string();
            if crate::tamper::should_record(&app.id, &file_path) {
                tracing::warn!(
                    target: "homewaf.security",
                    app = %app.id,
                    path = %file_path,
                    action = act,
                    "网页文件与基线不一致"
                );
                if let Some(store) = store {
                    let event = Event::new(
                        homewaf_acl::now_unix(),
                        EventKind::Detect,
                        client_ip.map(|i| i.to_string()).unwrap_or_default(),
                    )
                    .with_app(app.id.clone())
                    .with_path(file_path.clone())
                    .with_rules("tamper".to_string())
                    .with_score(100)
                    .with_action(act.to_string());
                    if let Err(e) = store.insert_event(&event) {
                        tracing::warn!(error = %e, "写入防篡改事件失败");
                    }
                }
            }
            if block {
                return write_text(session, 403, "文件已被篡改，访问被拒绝").await;
            }
        }
        _ => {}
    }

    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("content-type", mime_of(&real))?;
    resp.insert_header("content-length", data.len().to_string())?;
    resp.insert_header("cache-control", "public, max-age=0, must-revalidate")?;
    resp.insert_header("x-content-type-options", "nosniff")?;

    if method == "HEAD" {
        session.write_response_header(Box::new(resp), true).await?;
    } else {
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(data)), true)
            .await?;
    }
    Ok(true)
}

/// 重定向响应。目标地址支持 `{path}` 与 `{query}` 占位符。
async fn serve_redirect(
    session: &mut Session,
    app: &homewaf_config::Application,
    path: &str,
    query: Option<&str>,
) -> Result<bool> {
    let target = app.redirect.target.trim();
    if target.is_empty() {
        return service_unavailable(session).await;
    }
    let location = target
        .replace("{path}", path)
        .replace("{query}", query.unwrap_or(""));
    let status = if [301, 302, 303, 307, 308].contains(&app.redirect.status) {
        app.redirect.status
    } else {
        302
    };

    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("location", location.as_str())?;
    resp.insert_header("content-length", "0")?;
    resp.insert_header("cache-control", "no-store")?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(true)
}

/// 只允许普通路径段，阻断 `..`、`.` 和绝对路径。
fn is_safe_relative(rel: &str) -> bool {
    Path::new(rel)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
}

fn mime_of(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

/// 只接受站内绝对路径，防止验证后被重定向到外部站点。
fn safe_next(next: &str) -> &str {
    if next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\r')
        && !next.contains('\n')
    {
        next
    } else {
        "/"
    }
}

/// 取查询参数并做百分号解码。
fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi * 16 + lo);
                    i += 3;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 从请求中提取 Host：优先 URI authority（HTTP/2 的 `:authority`），其次 `Host` 头。
fn extract_host(req: &pingora::http::RequestHeader) -> String {
    if let Some(authority) = req.uri.authority() {
        return authority.as_str().to_string();
    }
    req.headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// 去掉 `host:port` 中的端口，处理 IPv6 方括号。
fn strip_port(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
        return host.to_string();
    }
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            h.to_string()
        }
        _ => host.to_string(),
    }
}

/// 从 `host:port` 中提取端口。
fn extract_port(host: &str) -> Option<u16> {
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let after = &rest[end + 1..];
        return after.strip_prefix(':')?.parse().ok();
    }
    let (h, port) = host.rsplit_once(':')?;
    if h.is_empty() {
        return None;
    }
    port.parse().ok()
}

/// 代理启动参数。
///
/// 路由、ACL、上游池都在 [`RuntimeState`] 里，热重载时整体替换；
/// 这里的监听地址与 TLS 配置在启动时绑定，变更需要重启。
pub struct ProxySettings {
    /// 明文 HTTP 监听地址
    pub listen: Vec<String>,
    /// HTTPS 监听地址
    pub tls_listen: Vec<String>,
    pub tls: homewaf_config::TlsConfig,
    /// 持久化层。`None` 表示纯内存运行
    pub store: Option<Arc<Store>>,
    /// 封禁表。由调用方创建，因为控制台也要读写它
    pub bans: Arc<BanTable>,
    /// 流量指标。由调用方创建，因为控制台要读同一份数据
    pub metrics: Arc<TrafficMetrics>,
    /// 配置文件路径。`Some` 时启用热重载
    pub watch_path: Option<std::path::PathBuf>,
    /// 热重载是否允许正则路由
    pub allow_regex: bool,
    /// 热重载轮询间隔
    pub watch_interval: std::time::Duration,
    /// 事件保留天数，超期自动清理
    pub events_retention_days: u32,
}

/// 主动健康检查：后台线程定时探测所有启用的上游。
///
/// 每次探测都重新取状态快照，这样热重载后会自动探测新配置里的上游。
fn spawn_health_checker(state: SharedState, interval: std::time::Duration) {
    std::thread::Builder::new()
        .name("homewaf-health-checker".to_string())
        .spawn(move || loop {
            let snapshot = state.load_full();
            let targets = snapshot.pool.probe_targets();

            for t in &targets {
                let healthy = upstream::probe(t);
                snapshot
                    .pool
                    .set_active_health(t.app_index, t.slot, healthy);
                if !healthy {
                    tracing::debug!(addr = %t.addr, "主动探测失败，标记为不健康");
                }
            }

            drop(snapshot);
            std::thread::sleep(interval);
        })
        .expect("启动健康检查线程失败");
}

/// 空 TLS 回调。rustls 后端不需要 openssl 式的 certificate_callback，
/// 证书由 [`crate::tls::SniResolver`] 在 `ClientHello` 阶段选择。
struct NoTlsCallbacks;

#[async_trait]
impl pingora::listeners::TlsAccept for NoTlsCallbacks {}

/// 启动代理服务。
pub fn run(state: SharedState, settings: ProxySettings) -> anyhow::Result<()> {
    if settings.listen.is_empty() && settings.tls_listen.is_empty() {
        anyhow::bail!("没有配置监听地址");
    }

    let mut server = Server::new(None)?;
    server.bootstrap();

    // 封禁表由调用方创建并传入（控制台也要用同一个实例）
    let bans = settings.bans.clone();

    // 打开持久化层（由调用方传入，因为构建 RuntimeState 时就需要它读订阅状态）
    let store = settings.store.clone();

    // 恢复未过期的封禁，否则重启就等于给攻击者解封
    if let Some(store) = &store {
        let now = homewaf_acl::now_unix().max(0) as u64;
        match store.load_active_bans(now as i64) {
            Ok(records) => {
                let count = records.len();
                for r in &records {
                    if let Ok(ip) = r.ip.parse() {
                        if r.reason == "manual" {
                            bans.manual_ban(ip, r.until as u64, r.offenses, now);
                        } else {
                            bans.restore(ip, r.until as u64, r.offenses, now);
                        }
                    }
                }
                if count > 0 {
                    tracing::info!(count, "已从数据库恢复封禁记录");
                }
            }
            Err(e) => tracing::warn!(error = %e, "加载封禁记录失败"),
        }
    }

    // 定期清理：过期事件与过期封禁。
    // 不清理的话长期运行数据库会无限增长。
    if let Some(store) = store.clone() {
        let retention_days = settings.events_retention_days.max(1) as i64;
        std::thread::Builder::new()
            .name("homewaf-store-janitor".to_string())
            .spawn(move || loop {
                let now = homewaf_acl::now_unix();
                let cutoff = now - retention_days * 86_400;

                match store.prune_events(cutoff) {
                    Ok(n) if n > 0 => tracing::info!(removed = n, "清理过期事件"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "清理事件失败"),
                }
                match store.cleanup_bans(now) {
                    Ok(n) if n > 0 => tracing::info!(removed = n, "清理过期封禁"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "清理封禁失败"),
                }
                let traffic_cutoff = now - retention_days.max(30) * 86_400;
                match store.prune_traffic(traffic_cutoff) {
                    Ok(n) if n > 0 => tracing::info!(removed = n, "清理过期流量聚合"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "清理流量聚合失败"),
                }

                std::thread::sleep(std::time::Duration::from_secs(3_600));
            })
            .expect("启动清理线程失败");
    }

    // 流量聚合落库：每分钟重写最近 5 分钟，既幂等又能补上晚到的日志。
    if let Some(store) = store.clone() {
        let metrics = settings.metrics.clone();
        std::thread::Builder::new()
            .name("homewaf-traffic-flusher".to_string())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let now = homewaf_acl::now_unix();
                let minute = now - now.rem_euclid(60);
                let buckets = metrics.completed_buckets(minute - 300, minute);
                if buckets.is_empty() {
                    continue;
                }
                let rows: Vec<homewaf_store::TrafficBucketRow> = buckets
                    .into_iter()
                    .map(|b| homewaf_store::TrafficBucketRow {
                        minute: b.minute,
                        app: b.app,
                        requests: b.requests,
                        pv: b.pv,
                        blocked: b.blocked,
                        status_4xx: b.status_4xx,
                        status_5xx: b.status_5xx,
                        unique_ips: b.unique_ips,
                        unique_visitors: b.unique_visitors,
                        ips: b.ips,
                        visitors: b.visitors,
                    })
                    .collect();
                if let Err(e) = store.save_traffic(&rows) {
                    tracing::warn!(error = %e, "写入流量聚合失败");
                }
            })
            .expect("启动流量持久化线程失败");
    }

    if let Some(path) = settings.watch_path.clone() {
        crate::reload::spawn_watcher(
            state.clone(),
            bans.clone(),
            store.clone(),
            path,
            settings.allow_regex,
            settings.watch_interval,
        );
        tracing::info!(
            interval_secs = settings.watch_interval.as_secs(),
            "配置热重载已启用"
        );
    }

    let proxy = WafProxy::new(state.clone(), bans, store, settings.metrics.clone());

    // 有应用启用主动健康检查时才起线程
    let hc_interval = state.load_full().pool.probe_interval();
    if let Some(interval) = hc_interval {
        spawn_health_checker(state.clone(), interval);
        tracing::info!(interval_secs = interval.as_secs(), "主动健康检查已启用");
    }
    let mut service = pingora::proxy::http_proxy_service(&server.configuration, proxy);

    for addr in &settings.listen {
        tracing::info!(listen = %addr, mode = "http", "开始监听");
        service.add_tcp(addr);
    }

    if !settings.tls_listen.is_empty() {
        // 证书来自证书库（或全局 tls.cert/tls.key 兜底）。空证书库也允许启动：
        // 监听器先起来，用户在控制台上传证书后由解析器热生效，无需重启。
        if state.load().tls_certs.is_empty() {
            tracing::warn!(
                "配置了 tls_listen 但当前没有证书，握手会失败；请在控制台「证书管理」上传"
            );
        }

        // 证书解析器每次握手都读当前状态，因此证书更新是热生效的
        let resolver = Arc::new(crate::tls::SniResolver::new(state.clone()));
        let want_h2 = settings.tls.alpn.iter().any(|p| p == "h2");

        for addr in &settings.tls_listen {
            let mut tls_settings = TlsSettings::with_callbacks(Box::new(NoTlsCallbacks))
                .map_err(|e| anyhow::anyhow!("初始化 TLS 失败：{e}"))?;
            tls_settings.set_cert_resolver(resolver.clone());
            if want_h2 {
                tls_settings.enable_h2();
            }
            tracing::info!(listen = %addr, mode = "https", "开始监听");
            service.add_tls_with_settings(addr, None, tls_settings);
        }
    }

    server.add_service(service);
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_variants() {
        assert_eq!(strip_port("nas.home.lan:8443"), "nas.home.lan");
        assert_eq!(strip_port("nas.home.lan"), "nas.home.lan");
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
    }

    #[test]
    fn extract_port_variants() {
        assert_eq!(extract_port("[::1]:443"), Some(443));
        assert_eq!(extract_port("[::1]"), None);
        assert_eq!(extract_port("nas.home.lan"), None);
    }

    // ============================================================
    // 上游 URI 构造（安全关键：决定后端收到什么路径）
    // ============================================================

    fn target(path: &str, query: Option<&str>) -> String {
        build_upstream_target(path, query)
            .expect("应能构造合法 URI")
            .to_string()
    }

    #[test]
    fn builds_path_without_query() {
        assert_eq!(target("/api", None), "/api");
        assert_eq!(target("/", None), "/");
        assert_eq!(target("/a/b/c", None), "/a/b/c");
    }

    #[test]
    fn builds_path_with_query() {
        assert_eq!(target("/api", Some("x=1")), "/api?x=1");
        assert_eq!(target("/", Some("a=1&b=2")), "/?a=1&b=2");
    }

    #[test]
    fn empty_query_is_dropped() {
        // 不能产生 "/api?" 这种带空查询的怪路径
        assert_eq!(target("/api", Some("")), "/api");
    }

    #[test]
    fn query_with_special_chars_preserved() {
        assert_eq!(
            target("/search", Some("q=a%20b&lang=zh")),
            "/search?q=a%20b&lang=zh"
        );
    }

    #[test]
    fn trailing_slash_preserved() {
        assert_eq!(target("/api/", None), "/api/");
        assert_eq!(target("/api/", Some("x=1")), "/api/?x=1");
    }

    #[test]
    fn invalid_path_is_rejected() {
        // 空格等非法字符不能静默放过
        assert!(build_upstream_target("/a b", None).is_err());
        assert!(build_upstream_target("/a\r\nX-Injected: 1", None).is_err());
    }

    #[test]
    fn normalized_path_used_not_raw() {
        // 模拟真实流程：原始路径先规范化，再构造上游目标
        let raw = "//x/../admin/y";
        let normalized = homewaf_router::normalize_path(raw);
        assert_eq!(target(&normalized, None), "/admin/y");
    }
}
