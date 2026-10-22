//! Pingora 集成。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::Session;

use homewaf_acl::{BanTable, Decision as AclDecision};
use homewaf_store::{BanRecord, Event, EventKind, Store};

use crate::headers::{self, ForwardedCtx};
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
    /// 请求开始时间，用于统计
    pub start: Option<Instant>,
}

/// 代理主体。
pub struct WafProxy {
    state: SharedState,
    bans: Arc<BanTable>,
    /// 持久化层。`None` 表示纯内存运行
    store: Option<Arc<Store>>,
}

impl WafProxy {
    pub fn new(state: SharedState, bans: Arc<BanTable>, store: Option<Arc<Store>>) -> Self {
        Self { state, bans, store }
    }

    /// 当前状态快照（供测试与调试）。
    pub fn snapshot(&self) -> Arc<RuntimeState> {
        self.state.load_full()
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

        let req = session.req_header();
        let raw_host = extract_host(req);

        // 真实 IP 还原
        let client = realip::resolve(direct.as_ref(), &req.headers, &state.real_ip);
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

        let path = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let Some(hit) = state.router.resolve(&host, port, path) else {
            // 未配置的域名：返回 404，不泄露任何后端指纹
            let mut resp = ResponseHeader::build(404, None)?;
            resp.insert_header("content-length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        };

        let app = state
            .router
            .app(hit.app_index)
            .expect("路由返回的应用索引必然有效");

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
                    ctx.acl_reason = Some(desc);
                    let mut resp = ResponseHeader::build(403, None)?;
                    resp.insert_header("content-length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
                AclDecision::Allow(reason) => {
                    ctx.acl_reason = Some(reason.describe());
                    ctx.acl_allowed = true;
                }
                AclDecision::Normal => {}
            }
        }

        // 自动封禁检查：命中直接拒绝，连检测都不必做。
        // 这是 WAF 的核心价值回路——被封的 IP 不再消耗检测资源。
        if let Some(ip) = ctx.client_ip {
            let now_secs = homewaf_acl::now_unix().max(0) as u64;
            if let Some(status) = self.bans.check(ip, now_secs) {
                tracing::info!(
                    target: "homewaf.security",

                    req = %ctx.request_id,
                    client_ip = %ip,
                    remaining_secs = status.remaining_secs,
                    offenses = status.offenses,
                    "处于自动封禁中，拒绝"
                );
                ctx.acl_reason = Some("自动封禁".to_string());
                let mut resp = ResponseHeader::build(403, None)?;
                resp.insert_header("content-length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        // 应用层攻击检测。
        // 用规范化后的路径——检测与转发必须看到同一个路径，否则又是一条绕过。
        let query = req.uri.query().map(|q| q.to_string());
        let user_agent = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let cookie = req
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // 决定是否需要检测请求体。二进制与上传类跳过，避免误报与无谓开销
        let method = req.method.as_str();
        let content_type = req
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok());
        if method != "GET"
            && method != "HEAD"
            && homewaf_detect::should_inspect_content_type(content_type)
        {
            ctx.body_buffer =
                Some(homewaf_detect::BodyBuffer::new(homewaf_detect::DEFAULT_MAX_INSPECT_BYTES));
        }

        // 先算白名单豁免：命中的路径/规则不再检测
        let exemption = homewaf_detect::whitelist::compute(
            &state.whitelist,
            &app.id,
            &hit.normalized_path,
        );

        let verdict = state.engine.inspect_with(
            &homewaf_detect::InspectionInput {
                path: hit.normalized_path.clone(),
                query: query.clone(),
                user_agent,
                cookie,
                ..Default::default()
            },
            &exemption,
        );

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

            let now_secs = homewaf_acl::now_unix().max(0) as u64;

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
                    if let Some(outcome) = self.bans.record(ip, verdict.blocking_score, now_secs) {
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
            let mut resp = ResponseHeader::build(403, None)?;
            resp.insert_header("content-length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        let upstreams = state
            .router
            .route_of(&hit)
            .and_then(|r| r.upstreams.as_deref())
            .unwrap_or(&app.upstreams);

        if upstreams.is_empty() {
            let mut resp = ResponseHeader::build(502, None)?;
            resp.insert_header("content-length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // 从上游池里按负载均衡算法选一个
        let client_ip = ctx.client_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
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

        let verdict = state.engine.inspect(&homewaf_detect::InspectionInput {
            body: Some(text.to_string()),
            ..Default::default()
        });

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

        let peer = if ctx.upstream_tls {
            HttpPeer::new(addr.as_str(), true, String::new())
        } else {
            HttpPeer::new(addr.as_str(), false, String::new())
        };

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

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from_static(SERVICE_UNAVAILABLE_HTML.as_bytes())), true)
        .await?;
    Ok(true)
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
                        bans.restore(ip, r.until as u64, r.offenses, now);
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

                std::thread::sleep(std::time::Duration::from_secs(3_600));
            })
            .expect("启动清理线程失败");
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

    let proxy = WafProxy::new(state.clone(), bans, store);

    // 有应用启用主动健康检查时才起线程
    let hc_interval = state.load_full().pool.probe_interval();
    if let Some(interval) = hc_interval {
        spawn_health_checker(state.clone(), interval);
        tracing::info!(
            interval_secs = interval.as_secs(),
            "主动健康检查已启用"
        );
    }
    let mut service = pingora::proxy::http_proxy_service(&server.configuration, proxy);

    for addr in &settings.listen {
        tracing::info!(listen = %addr, mode = "http", "开始监听");
        service.add_tcp(addr);
    }

    if !settings.tls_listen.is_empty() {
        let cert = settings
            .tls
            .cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置了 tls_listen 但缺少 tls.cert"))?;
        let key = settings
            .tls
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置了 tls_listen 但缺少 tls.key"))?;

        // TlsSettings 不实现 Clone，每个监听地址各自构造一次（证书通常只读 1-2 次）
        let want_h2 = settings.tls.alpn.iter().any(|p| p == "h2");

        for addr in &settings.tls_listen {
            let mut tls_settings = TlsSettings::intermediate(cert, key)
                .map_err(|e| anyhow::anyhow!("加载 TLS 证书失败（{cert} / {key}）: {e}"))?;
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
