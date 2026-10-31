//! 配置语义校验。
//!
//! 校验分两级：`error` 阻止启动，`warning` 仅提示。
//! 所有问题都带字段路径，便于定位（如 `applications[0].upstreams[1].port`）。

use std::collections::{HashMap, HashSet};

use crate::error::ValidationError;
use crate::model::*;

/// 校验结果。
#[derive(Debug, Default)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn is_clean(&self) -> bool {
        self.errors.is_empty() && self.warnings.is_empty()
    }

    pub fn all(&self) -> Vec<&ValidationError> {
        self.errors.iter().chain(self.warnings.iter()).collect()
    }
}

struct Ctx {
    errors: Vec<ValidationError>,
    warnings: Vec<ValidationError>,
}

impl Ctx {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn error(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.errors.push(ValidationError::error(path, msg));
    }

    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.warnings.push(ValidationError::warning(path, msg));
    }

    fn finish(self) -> ValidationReport {
        ValidationReport {
            errors: self.errors,
            warnings: self.warnings,
        }
    }
}

/// 校验整份配置。
pub fn validate(config: &Config) -> ValidationReport {
    let mut ctx = Ctx::new();

    validate_server(&config.server, &mut ctx);
    validate_tls(&config.tls, &config.server.tls_listen, &mut ctx);
    validate_acme(&config.acme, &mut ctx);
    validate_real_ip(&config.real_ip, &mut ctx);
    validate_limits(&config.limits, &mut ctx);
    validate_protection(&config.protection, "protection", &mut ctx);
    validate_ratelimit(&config.ratelimit, "ratelimit", &mut ctx);
    validate_challenge(&config.challenge, &mut ctx);
    validate_acl(&config.acl, &config.applications, &mut ctx);
    validate_ip_groups(&config.ip_groups, &config.applications, &mut ctx);
    validate_rule_feeds(&config.rule_feeds, &mut ctx);
    validate_custom_rules(
        &config.custom_rules,
        &config.applications,
        &config.ip_groups,
        &mut ctx,
    );
    validate_detect_rules(&config.custom_detect_rules, &mut ctx);
    validate_applications(&config.applications, &mut ctx);

    ctx.finish()
}

// ============================================================
// 服务器
// ============================================================

fn validate_server(server: &ServerConfig, ctx: &mut Ctx) {
    if server.listen.is_empty() && server.tls_listen.is_empty() {
        ctx.error(
            "server.listen",
            "至少需要一个监听地址（listen 或 tls_listen）",
        );
    }
    for (i, addr) in server.listen.iter().enumerate() {
        if let Err(e) = validate_listen_addr(addr) {
            ctx.error(format!("server.listen[{i}]"), e);
        }
    }
    for (i, addr) in server.tls_listen.iter().enumerate() {
        if let Err(e) = validate_listen_addr(addr) {
            ctx.error(format!("server.tls_listen[{i}]"), e);
        }
    }
    if !server.admin.listen.is_empty() && !is_loopback_listen(&server.admin.listen) {
        ctx.warn(
            "server.admin.listen",
            "管理面监听在非回环地址，建议只监听 127.0.0.1 或使用 Unix Socket",
        );
    }
    if server.workers > 64 {
        ctx.warn("server.workers", "worker 数超过 64，家用设备通常不需要");
    }
}

fn validate_listen_addr(addr: &str) -> Result<(), String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err("监听地址不能为空".into());
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("监听地址 `{addr}` 缺少端口（格式 host:port）"))?;
    if port.parse::<u16>().is_err() {
        return Err(format!("监听地址 `{addr}` 的端口非法"));
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("监听地址 `{addr}` 缺少主机部分"));
    }
    if host != "0.0.0.0" && host != "::" && host.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("监听地址 `{addr}` 的主机必须是 IP（不支持域名）"));
    }
    Ok(())
}

fn is_loopback_listen(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("[::1]") || addr.starts_with("localhost")
}

// ============================================================
// TLS / ACME
// ============================================================

fn validate_tls(tls: &TlsConfig, tls_listen: &[String], ctx: &mut Ctx) {
    if tls.alpn.is_empty() {
        ctx.warn("tls.alpn", "ALPN 列表为空，HTTP/2 将不可用");
    }
    for (i, proto) in tls.alpn.iter().enumerate() {
        if !matches!(proto.as_str(), "h2" | "http/1.1" | "h3") {
            ctx.error(
                format!("tls.alpn[{i}]"),
                format!("不支持的 ALPN 协议 `{proto}`（支持 h2 / http/1.1 / h3）"),
            );
        }
    }
    if tls.hsts.enabled && tls.hsts.max_age < 86_400 {
        ctx.warn(
            "tls.hsts.max_age",
            "HSTS max-age 小于 1 天，实际防护效果有限",
        );
    }

    // 证书一致性：cert 与 key 必须成对，tls_listen 非空时必须有证书
    match (&tls.cert, &tls.key) {
        (Some(cert), Some(key)) => {
            if cert.trim().is_empty() {
                ctx.error("tls.cert", "证书路径不能为空");
            }
            if key.trim().is_empty() {
                ctx.error("tls.key", "私钥路径不能为空");
            }
            // 只做提示：配置可能在另一台机器上校验，文件不一定存在
            if !cert.trim().is_empty() && !std::path::Path::new(cert).exists() {
                ctx.warn("tls.cert", format!("证书文件 `{cert}` 当前不存在"));
            }
            if !key.trim().is_empty() && !std::path::Path::new(key).exists() {
                ctx.warn("tls.key", format!("私钥文件 `{key}` 当前不存在"));
            }
        }
        (None, None) => {
            if !tls_listen.is_empty() {
                ctx.error(
                    "tls.cert",
                    "配置了 server.tls_listen 但未指定 tls.cert / tls.key，HTTPS 无法启动",
                );
            }
        }
        _ => {
            ctx.error(
                "tls.key",
                "tls.cert 与 tls.key 必须同时配置（只配一个无法启动 TLS）",
            );
        }
    }
}

fn validate_acme(acme: &AcmeConfig, ctx: &mut Ctx) {
    if !acme.enabled {
        return;
    }
    if acme.email.is_empty() {
        ctx.error("acme.email", "启用 ACME 时必须填写邮箱");
    } else if !acme.email.contains('@') {
        ctx.error("acme.email", "邮箱格式不正确");
    }
    if acme.challenge == AcmeChallenge::Dns01 && acme.provider.is_none() {
        ctx.error(
            "acme.provider",
            "DNS-01 挑战必须指定 DNS 提供商（如 cloudflare）",
        );
    }
    if acme.renew_before_days == 0 || acme.renew_before_days > 89 {
        ctx.error("acme.renew_before_days", "续期提前天数需在 1-89 之间");
    }
}

// ============================================================
// 真实 IP
// ============================================================

fn validate_real_ip(real_ip: &RealIpConfig, ctx: &mut Ctx) {
    if !real_ip.enabled {
        return;
    }
    if real_ip.trusted_proxies.is_empty()
        && real_ip.trusted_proxy_groups.is_empty()
        && real_ip.preset.is_none()
    {
        ctx.warn(
            "real_ip.trusted_proxies",
            "已启用真实 IP 还原但未配置可信网段，所有转发头都会被忽略",
        );
    }
    if real_ip.trusted_proxies.len() > 512 {
        ctx.warn(
            "real_ip.trusted_proxies",
            "可信网段超过 512 条，匹配性能可能下降",
        );
    }
    for (i, cidr) in real_ip.trusted_proxies.iter().enumerate() {
        if cidr.prefix_len() == 0 {
            ctx.error(
                format!("real_ip.trusted_proxies[{i}]"),
                "可信网段不能是全网段（/0），这会让任何来源的转发头都被信任",
            );
        }
    }
    if real_ip.header_priority.is_empty() {
        ctx.error("real_ip.header_priority", "头部优先级列表不能为空");
    }
    for (i, name) in real_ip.header_priority.iter().enumerate() {
        if !is_valid_header_name(name) {
            ctx.error(
                format!("real_ip.header_priority[{i}]"),
                format!("`{name}` 不是合法的 HTTP 头名（只能含字母、数字与 !#$%&'*+-.^_`|~）"),
            );
        }
    }
    if real_ip.max_chain_depth == 0 {
        ctx.error("real_ip.max_chain_depth", "回溯深度至少为 1");
    }
}

// ============================================================
// 限制
// ============================================================

fn validate_limits(limits: &LimitsConfig, ctx: &mut Ctx) {
    if limits.max_header_size.as_bytes() < 1024 {
        ctx.error("limits.max_header_size", "头部大小上限不能小于 1KB");
    }
    if limits.max_header_count == 0 {
        ctx.error("limits.max_header_count", "头部数量上限至少为 1");
    }
    if limits.max_body_size.as_bytes() == 0 {
        ctx.error("limits.max_body_size", "请求体大小上限不能为 0");
    }
    if limits.queue_capacity == 0 {
        ctx.error("limits.queue_capacity", "等待池容量至少为 1");
    }
    if limits.queue_timeout.is_zero() {
        ctx.warn(
            "limits.queue_timeout",
            "排队超时为 0，等于禁用等待池（饱和时直接拒绝）",
        );
    }
    if limits.detect_budget.is_zero() {
        ctx.warn("limits.detect_budget", "检测预算为 0，将跳过所有深度检测");
    }
    if limits.request_timeout.as_secs() < 1 {
        ctx.error("limits.request_timeout", "请求总超时至少 1 秒");
    }
    if limits.request_timeout <= limits.queue_timeout {
        ctx.warn(
            "limits.request_timeout",
            "请求总超时不大于排队超时，排队后可能没有时间完成转发",
        );
    }
}

// ============================================================
// 防护开关
// ============================================================

fn validate_protection(p: &ProtectionConfig, base: &str, ctx: &mut Ctx) {
    if p.semantic.min_confidence < 0.0 || p.semantic.min_confidence > 1.0 {
        ctx.error(
            format!("{base}.semantic.min_confidence"),
            "置信度门槛必须在 0.0-1.0 之间",
        );
    }
    if let Some(threshold) = p.block_threshold {
        if threshold == 0 || threshold > 100 {
            ctx.error(format!("{base}.block_threshold"), "阻断阈值需在 1-100 之间");
        }
    }
    // preset 作为基线，显式指定的单项覆盖它。两者可以共存：
    //   preset: balanced
    //   file_upload: monitor   # 只覆盖这一项
    // 只有 UI 交互时（用户点单项开关）才自动切 custom，那是为了避免
    // "改了又被档位覆盖回去"的困惑；配置文件里显式字段的优先级是明确的。
    if p.observe_mode.enabled && p.observe_mode.scope.is_empty() {
        ctx.warn(
            format!("{base}.observe_mode.scope"),
            "观察范围为空，观察模式不会生效",
        );
    }
    if let Some(d) = p.observe_mode.auto_disable_after {
        if d.as_secs() == 0 {
            ctx.error(
                format!("{base}.observe_mode.auto_disable_after"),
                "自动关闭时间不能为 0",
            );
        }
    }
}

fn validate_ratelimit(r: &RateLimitConfig, base: &str, ctx: &mut Ctx) {
    if r.enabled
        && r.global_qps == 0
        && r.per_ip_qps == 0
        && r.per_ip_conn == 0
        && r.per_url_qps == 0
    {
        ctx.warn(base, "CC 防护已启用但四层阈值全为 0，等于不限制");
    }
}

fn validate_challenge(c: &ChallengeConfig, ctx: &mut Ctx) {
    if c.difficulty == 0 || c.difficulty > 8 {
        ctx.error(
            "challenge.difficulty",
            "难度需在 1-8 之间（前导零的十六进制位数）",
        );
    }
    if c.ttl.as_secs() == 0 {
        ctx.error("challenge.ttl", "挑战有效期不能为 0");
    }
    if c.difficulty > 5 {
        ctx.warn(
            "challenge.difficulty",
            "难度超过 5 会让性能较弱的手机/平板验证耗时超过数秒",
        );
    }
}

// ============================================================
// ACL
// ============================================================

fn validate_acl(acl: &AclConfig, apps: &[Application], ctx: &mut Ctx) {
    if acl.ipv6_prefix_match > 128 {
        ctx.error("acl.ipv6_prefix_match", "IPv6 前缀长度不能超过 128");
    } else if acl.ipv6_prefix_match < 48 {
        ctx.warn(
            "acl.ipv6_prefix_match",
            "IPv6 前缀短于 /48，可能误封整个运营商段",
        );
    }
    for (i, cidr) in acl.private_network.cidrs.iter().enumerate() {
        if cidr.prefix_len() == 0 {
            ctx.error(
                format!("acl.private_network.cidrs[{i}]"),
                "内网网段不能是全网段（/0）",
            );
        }
    }
    if acl.auto_ban.enabled && acl.auto_ban.durations.is_empty() {
        ctx.error(
            "acl.auto_ban.durations",
            "启用自动封禁时必须提供至少一个封禁时长",
        );
    }
    for (i, d) in acl.auto_ban.durations.iter().enumerate() {
        if d.as_secs() == 0 {
            ctx.error(format!("acl.auto_ban.durations[{i}]"), "封禁时长不能为 0");
        }
    }

    // 静态规则
    let app_ids: HashSet<&str> = apps.iter().map(|a| a.id.as_str()).collect();
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for (i, rule) in acl.rules.iter().enumerate() {
        let base = format!("acl.rules[{i}]");

        if rule.cidr.prefix_len() == 0 && rule.action == AclRuleAction::Allow {
            ctx.error(
                format!("{base}.cidr"),
                "白名单规则不能是全网段（/0），等于关闭所有防护",
            );
        }

        if let Some(scope) = &rule.scope {
            if !app_ids.contains(scope.as_str()) {
                ctx.error(
                    format!("{base}.scope"),
                    format!("引用了不存在的应用 `{scope}`"),
                );
            }
        }

        if let Some(id) = &rule.id {
            if id.trim().is_empty() {
                ctx.error(format!("{base}.id"), "规则 id 不能为空");
            } else if !seen_ids.insert(id.as_str()) {
                ctx.error(format!("{base}.id"), format!("规则 id `{id}` 重复"));
            }
        }

        if let Some(ts) = rule.expires_at {
            if ts <= 0 {
                ctx.error(
                    format!("{base}.expires_at"),
                    "到期时间必须为正数（Unix 秒）",
                );
            }
        }
    }
}

// ============================================================
// IP 组订阅
// ============================================================

fn validate_ip_groups(groups: &[IpGroup], apps: &[Application], ctx: &mut Ctx) {
    let app_ids: HashSet<&str> = apps.iter().map(|a| a.id.as_str()).collect();
    let mut seen = HashSet::new();

    for (i, g) in groups.iter().enumerate() {
        let base = format!("ip_groups[{i}]");

        if g.name.is_empty() {
            ctx.error(format!("{base}.name"), "订阅名称不能为空");
        } else if !seen.insert(g.name.as_str()) {
            ctx.error(
                format!("{base}.name"),
                format!("订阅名称 `{}` 重复", g.name),
            );
        }
        validate_label(&g.label, &base, ctx);

        match g.source.kind {
            crate::IpGroupSourceKind::Http => {
                if !g.source.url.starts_with("https://") {
                    ctx.error(format!("{base}.source.url"), "订阅地址必须使用 HTTPS");
                }
            }
            crate::IpGroupSourceKind::AliyunEsa => {
                let a = &g.source.aliyun;
                if a.access_key_id.trim().is_empty() {
                    ctx.error(
                        format!("{base}.source.aliyun.access_key_id"),
                        "缺少 AccessKey ID",
                    );
                }
                if a.access_key_secret.trim().is_empty() {
                    ctx.error(
                        format!("{base}.source.aliyun.access_key_secret"),
                        "缺少 AccessKey Secret",
                    );
                }
                if a.site_id.trim().is_empty() {
                    ctx.error(
                        format!("{base}.source.aliyun.site_id"),
                        "缺少站点 ID（SiteId）",
                    );
                }
                if a.region.trim().is_empty() {
                    ctx.error(format!("{base}.source.aliyun.region"), "缺少地域");
                }
            }
        }
        if g.source.interval.as_secs() < 60 {
            ctx.error(format!("{base}.source.interval"), "拉取周期不能短于 60 秒");
        }
        if g.source.timeout.as_secs() == 0 {
            ctx.error(format!("{base}.source.timeout"), "拉取超时不能为 0");
        }

        let guards = &g.guards;
        if guards.max_entries == 0 {
            ctx.error(format!("{base}.guards.max_entries"), "条目上限不能为 0");
        }
        if guards.min_prefix_v4 > 32 {
            ctx.error(
                format!("{base}.guards.min_prefix_v4"),
                "IPv4 最小前缀长度不能超过 32",
            );
        }
        if guards.min_prefix_v6 > 128 {
            ctx.error(
                format!("{base}.guards.min_prefix_v6"),
                "IPv6 最小前缀长度不能超过 128",
            );
        }
        if !(0.0..=1.0).contains(&guards.max_delta_ratio) {
            ctx.error(
                format!("{base}.guards.max_delta_ratio"),
                "变更幅度阈值必须在 0.0-1.0 之间",
            );
        }
        if guards.max_response_bytes.as_bytes() == 0 {
            ctx.error(
                format!("{base}.guards.max_response_bytes"),
                "响应体上限不能为 0",
            );
        }

        for (j, scope) in g.scope.iter().enumerate() {
            if !app_ids.contains(scope.as_str()) {
                ctx.error(
                    format!("{base}.scope[{j}]"),
                    format!("引用了不存在的应用 `{scope}`"),
                );
            }
        }
    }
}

// ============================================================
// 规则包订阅
// ============================================================

fn validate_rule_feeds(feeds: &[RuleFeed], ctx: &mut Ctx) {
    let mut seen = HashSet::new();
    for (i, f) in feeds.iter().enumerate() {
        let base = format!("rule_feeds[{i}]");
        if f.name.is_empty() {
            ctx.error(format!("{base}.name"), "订阅名称不能为空");
        } else if !seen.insert(f.name.as_str()) {
            ctx.error(
                format!("{base}.name"),
                format!("订阅名称 `{}` 重复", f.name),
            );
        }
        validate_label(&f.label, &base, ctx);
        if !f.url.starts_with("https://") {
            ctx.error(format!("{base}.url"), "规则包地址必须使用 HTTPS");
        }
        if f.name.chars().count() > 64 {
            ctx.error(format!("{base}.name"), "订阅名称不能超过 64 个字符");
        }
        if !f
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            ctx.error(
                format!("{base}.name"),
                "订阅名称只能包含字母、数字、横线和下划线",
            );
        }
        if f.require_signature && f.public_key.is_none() {
            ctx.error(format!("{base}.public_key"), "要求验签时必须提供公钥");
        }
        if let Some(key) = &f.public_key {
            if !is_valid_ed25519_key(key) {
                ctx.error(
                    format!("{base}.public_key"),
                    "公钥格式应为 `ed25519:<base64>`（32 字节）",
                );
            }
        }
        if f.channel == FeedChannel::Pinned && f.pinned_version.as_deref().unwrap_or("").is_empty()
        {
            ctx.error(
                format!("{base}.pinned_version"),
                "channel 为 pinned 时必须指定版本号",
            );
        }
        if f.check_interval.as_secs() < 60 {
            ctx.error(
                format!("{base}.check_interval"),
                "检查间隔不能小于 60s，避免频繁拉取",
            );
        }
        if f.timeout.as_secs() == 0 || f.timeout.as_secs() > 300 {
            ctx.error(format!("{base}.timeout"), "拉取超时应在 1s-300s 之间");
        }
        let max_size = f.max_size.as_bytes();
        if !(1024..=64 * 1024 * 1024).contains(&max_size) {
            ctx.error(
                format!("{base}.max_size"),
                "规则包大小上限应在 1KB-64MB 之间",
            );
        }
        if let Some(shadow) = f.shadow_period {
            if shadow.as_secs() > 30 * 86_400 {
                ctx.warn(
                    format!("{base}.shadow_period"),
                    "影子期超过 30 天，新规则将长期只记录不拦截",
                );
            }
        }
        for (name, value) in &f.headers {
            if !is_valid_header_name(name) {
                ctx.error(
                    format!("{base}.headers"),
                    format!("请求头名称 `{name}` 非法"),
                );
            }
            if value.contains(['\r', '\n']) || value.len() > 1024 {
                ctx.error(
                    format!("{base}.headers"),
                    format!("请求头 `{name}` 的值含换行或超过 1024 字节"),
                );
            }
        }
        if let Some(w) = &f.update_window {
            if !is_valid_window(w) {
                ctx.error(
                    format!("{base}.update_window"),
                    "时间窗格式应为 `HH:MM-HH:MM`，如 `03:00-05:00`",
                );
            }
        }
    }
}

/// 中文名称只做长度与可打印性校验——它不参与任何匹配逻辑，
/// 因此不该像 `name` 那样限制字符集，否则「长亭恶意 IP 库」这种名字就存不进去。
fn validate_label(label: &str, base: &str, ctx: &mut Ctx) {
    if label.chars().count() > 64 {
        ctx.error(format!("{base}.label"), "中文名称不能超过 64 个字符");
    }
    if label.chars().any(|c| c.is_control()) {
        ctx.error(format!("{base}.label"), "中文名称不能包含控制字符");
    }
}

// ============================================================
// 自定义规则（访问控制 / 黑白名单）
// ============================================================

/// 条件字段白名单。写错字段名不会报错、只会永远不匹配，
/// 所以这里必须显式拦住——否则用户会以为规则"没生效"。
const KNOWN_CONDITION_KEYS: &[&str] = &[
    "src_ip",
    "ip",
    "client_ip",
    "source_ip",
    "ip_group",
    "website",
    "app",
    "site",
    "host",
    "domain",
    "path",
    "uri",
    "url",
    "query",
    "args",
    "query_string",
    "method",
    "user_agent",
    "ua",
    "content_type",
    "cookie",
    "header",
    "headers",
];

const KNOWN_OPERATORS: &[&str] = &[
    "eq",
    "equal",
    "is",
    "in",
    "ne",
    "not_eq",
    "not",
    "contain",
    "contains",
    "like",
    "not_contain",
    "not_contains",
    "not_like",
    "prefix",
    "start_with",
    "starts_with",
    "suffix",
    "end_with",
    "ends_with",
    "regex",
    "match",
    "re",
];

/// 用与运行时一致的引擎试跑一条正则。
///
/// 控制台的「测试」按钮走这里，而不是浏览器自带的 RegExp：
/// JS 不认 `(?i)`、`\p{Han}` 这些 Rust 支持的语法，会把合法规则误判成非法。
pub fn regex_test(pattern: &str, sample: &str) -> Result<bool, String> {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(sample))
        .map_err(|e| e.to_string())
}

// ============================================================
// 自定义检测规则（检测黑名单）
// ============================================================

const DETECT_TARGETS: &[&str] = &["path", "query", "body", "header", "cookie", "user_agent"];
const DETECT_SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
const DETECT_ACTIONS: &[&str] = &["block", "log"];
const DETECT_CATEGORIES: &[&str] = &[
    "sqli",
    "xss",
    "cmdi",
    "traversal",
    "ssrf",
    "xxe",
    "ssti",
    "nosql",
    "ldap",
    "webshell",
    "scanner",
    "deserialization",
    "crlf",
    "upload",
    "bruteforce",
    "leak",
    "custom",
];

fn validate_detect_rules(rules: &[DetectRule], ctx: &mut Ctx) {
    let mut seen = HashSet::new();

    for (i, rule) in rules.iter().enumerate() {
        let base = format!("custom_detect_rules[{i}]");

        if rule.id.trim().is_empty() {
            ctx.error(format!("{base}.id"), "规则 id 不能为空");
        } else if rule.id.chars().count() > 64 {
            ctx.error(format!("{base}.id"), "规则 id 不能超过 64 个字符");
        } else if !rule
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            ctx.error(
                format!("{base}.id"),
                "规则 id 只能包含字母、数字、横线、下划线和点",
            );
        } else if !seen.insert(rule.id.as_str()) {
            ctx.error(format!("{base}.id"), format!("规则 id `{}` 重复", rule.id));
        }

        if rule.name.chars().count() > 64 {
            ctx.error(format!("{base}.name"), "规则名称不能超过 64 个字符");
        }

        if rule.pattern.trim().is_empty() {
            ctx.error(format!("{base}.pattern"), "正则不能为空");
        } else if let Err(e) = regex::Regex::new(&rule.pattern) {
            // 写错的正则运行时只会静默不匹配，必须在保存前拦住
            ctx.error(format!("{base}.pattern"), format!("正则非法：{e}"));
        }

        if rule.targets.is_empty() {
            ctx.error(format!("{base}.targets"), "至少要选一个作用对象");
        }
        for (j, t) in rule.targets.iter().enumerate() {
            if !DETECT_TARGETS.contains(&t.trim().to_ascii_lowercase().as_str()) {
                ctx.error(
                    format!("{base}.targets[{j}]"),
                    format!("未知作用对象 `{t}`（支持 path/query/body/header/cookie/user_agent）"),
                );
            }
        }

        let severity = rule.severity.trim().to_ascii_lowercase();
        if !DETECT_SEVERITIES.contains(&severity.as_str()) {
            ctx.error(
                format!("{base}.severity"),
                format!(
                    "未知分值档位 `{}`（支持 low/medium/high/critical）",
                    rule.severity
                ),
            );
        }

        let action = rule.action.trim().to_ascii_lowercase();
        if !DETECT_ACTIONS.contains(&action.as_str()) {
            ctx.error(
                format!("{base}.action"),
                format!("未知动作 `{}`（支持 block/log）", rule.action),
            );
        }

        let category = rule.category.trim().to_ascii_lowercase();
        if !DETECT_CATEGORIES.contains(&category.as_str()) {
            ctx.error(
                format!("{base}.category"),
                format!("未知分类 `{}`", rule.category),
            );
        }

        for (j, kw) in rule.keywords.iter().enumerate() {
            if kw.trim().is_empty() {
                ctx.error(format!("{base}.keywords[{j}]"), "关键词不能为空");
            }
        }
    }
}

fn validate_custom_rules(
    rules: &[CustomRule],
    apps: &[Application],
    ip_groups: &[IpGroup],
    ctx: &mut Ctx,
) {
    let app_ids: HashSet<&str> = apps.iter().map(|a| a.id.as_str()).collect();
    let group_names: HashSet<&str> = ip_groups.iter().map(|g| g.name.as_str()).collect();
    let mut seen = HashSet::new();

    for (i, rule) in rules.iter().enumerate() {
        let base = format!("custom_rules[{i}]");

        if rule.id.trim().is_empty() {
            ctx.error(format!("{base}.id"), "规则 id 不能为空");
        } else if rule.id.chars().count() > 64 {
            ctx.error(format!("{base}.id"), "规则 id 不能超过 64 个字符");
        } else if !seen.insert(rule.id.as_str()) {
            ctx.error(format!("{base}.id"), format!("规则 id `{}` 重复", rule.id));
        }

        if rule.name.chars().count() > 64 {
            ctx.error(format!("{base}.name"), "规则名称不能超过 64 个字符");
        }
        if rule.action > 3 {
            ctx.error(
                format!("{base}.action"),
                "动作只能是 0（放行）/ 1（拦截）/ 2（人机验证）/ 3（仅记录）",
            );
        }
        if rule.pattern.is_empty() || rule.pattern.iter().all(|g| g.is_empty()) {
            ctx.error(format!("{base}.pattern"), "规则至少要有一个条件");
        }
        for (j, scope) in rule.scope.iter().enumerate() {
            if !app_ids.contains(scope.as_str()) {
                ctx.error(
                    format!("{base}.scope[{j}]"),
                    format!("引用了不存在的应用 `{scope}`"),
                );
            }
        }

        for (j, group) in rule.pattern.iter().enumerate() {
            if group.is_empty() {
                ctx.error(
                    format!("{base}.pattern[{j}]"),
                    "条件组不能为空（空组会被忽略，容易让规则永远不生效）",
                );
                continue;
            }
            for (k, cond) in group.iter().enumerate() {
                validate_condition(
                    cond,
                    &format!("{base}.pattern[{j}][{k}]"),
                    &group_names,
                    ctx,
                );
            }
        }
    }
}

fn validate_condition(
    cond: &RuleCondition,
    base: &str,
    group_names: &HashSet<&str>,
    ctx: &mut Ctx,
) {
    let key = cond.k.trim().to_ascii_lowercase();
    let is_header = key == "header"
        || key == "headers"
        || key
            .strip_prefix("header:")
            .is_some_and(|rest| !rest.trim().is_empty());

    if key.is_empty() {
        ctx.error(format!("{base}.k"), "条件字段不能为空");
        return;
    }
    if !KNOWN_CONDITION_KEYS.contains(&key.as_str()) && !is_header {
        ctx.error(
            format!("{base}.k"),
            format!(
                "未知条件字段 `{}`（支持 IP / IP 组 / 路径 / 方法 / UA / 请求头 等）",
                cond.k
            ),
        );
    }

    let op = cond.op.trim().to_ascii_lowercase();
    if !KNOWN_OPERATORS.contains(&op.as_str()) {
        ctx.error(
            format!("{base}.op"),
            format!(
                "未知匹配方式 `{}`（支持 eq / contain / prefix / suffix / regex / ne 等）",
                cond.op
            ),
        );
    }

    if cond.v.is_empty() || cond.v.iter().all(|v| v.trim().is_empty()) {
        ctx.error(format!("{base}.v"), "匹配值不能为空");
        return;
    }

    // src_ip 的值必须是 CIDR：写成裸 IP 或写错格式时，运行期会静默不匹配
    if matches!(key.as_str(), "src_ip" | "ip" | "client_ip" | "source_ip") {
        for (n, v) in cond.v.iter().enumerate() {
            if v.parse::<ipnet::IpNet>().is_err() {
                ctx.error(
                    format!("{base}.v[{n}]"),
                    format!("`{v}` 不是合法的网段，请写成 1.2.3.4/32 或 1.2.3.0/24"),
                );
            }
        }
    }

    if key == "ip_group" {
        for (n, v) in cond.v.iter().enumerate() {
            if !group_names.contains(v.trim()) {
                ctx.error(
                    format!("{base}.v[{n}]"),
                    format!("引用了不存在的 IP 组 `{v}`"),
                );
            }
        }
    }

    if is_header && key != "header:" && cond.sub_k.as_deref().unwrap_or("").trim().is_empty() {
        ctx.error(format!("{base}.sub_k"), "请求头条件必须指定头名（sub_k）");
    }

    if matches!(op.as_str(), "regex" | "match" | "re") {
        for (n, v) in cond.v.iter().enumerate() {
            if regex::Regex::new(v).is_err() {
                ctx.error(format!("{base}.v[{n}]"), format!("正则表达式非法：{v}"));
            }
        }
    }
}

fn is_valid_ed25519_key(key: &str) -> bool {
    let Some(encoded) = key.strip_prefix("ed25519:") else {
        return false;
    };
    let encoded = encoded.trim();
    // 32 字节 base64 为 44 字符（含一个 `=`）；宽松接受无填充的 43 字符
    (40..=64).contains(&encoded.len())
        && encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

fn is_valid_window(w: &str) -> bool {
    let Some((start, end)) = w.split_once('-') else {
        return false;
    };
    parse_hhmm(start).is_some() && parse_hhmm(end).is_some()
}

fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u8 = h.parse().ok()?;
    let m: u8 = m.parse().ok()?;
    if h < 24 && m < 60 {
        Some((h, m))
    } else {
        None
    }
}

// ============================================================
// 应用
// ============================================================

fn validate_applications(apps: &[Application], ctx: &mut Ctx) {
    if apps.is_empty() {
        ctx.warn("applications", "未配置任何应用，WAF 不会转发任何流量");
        return;
    }

    let mut ids: HashMap<&str, usize> = HashMap::new();
    // 域名 → (应用索引, 字段路径)
    let mut domains: HashMap<String, (usize, String)> = HashMap::new();

    for (i, app) in apps.iter().enumerate() {
        let base = format!("applications[{i}]");

        // id
        if let Err(e) = validate_id(&app.id) {
            ctx.error(format!("{base}.id"), e);
        } else if let Some(prev) = ids.insert(app.id.as_str(), i) {
            ctx.error(
                format!("{base}.id"),
                format!("id `{}` 与 applications[{prev}] 重复", app.id),
            );
        }

        if app.name.trim().is_empty() {
            ctx.error(format!("{base}.name"), "应用名称不能为空");
        }

        // 主域名
        if let Err(e) = validate_domain(&app.domains.primary) {
            ctx.error(format!("{base}.domains.primary"), e);
        } else {
            register_domain(
                &mut domains,
                &app.domains.primary,
                i,
                format!("{base}.domains.primary"),
                ctx,
            );
        }

        // 别名
        if app.domains.aliases.len() > 10 {
            ctx.error(format!("{base}.domains.aliases"), "别名域名最多 10 个");
        }
        for (j, alias) in app.domains.aliases.iter().enumerate() {
            if let Err(e) = validate_domain(alias) {
                ctx.error(format!("{base}.domains.aliases[{j}]"), e);
            } else {
                register_domain(
                    &mut domains,
                    alias,
                    i,
                    format!("{base}.domains.aliases[{j}]"),
                    ctx,
                );
            }
        }

        // 上游：只有反向代理应用需要
        match app.access_mode {
            AccessMode::Proxy => {
                if app.upstreams.is_empty() {
                    ctx.error(format!("{base}.upstreams"), "应用至少需要一个上游");
                } else {
                    validate_upstreams(&app.upstreams, &format!("{base}.upstreams"), ctx);
                }
            }
            AccessMode::Static => {
                if app.static_site.root.trim().is_empty() {
                    ctx.error(format!("{base}.static_site.root"), "静态站点必须填写根目录");
                }
            }
            AccessMode::Redirect => {
                let target = app.redirect.target.trim();
                if target.is_empty() {
                    ctx.error(format!("{base}.redirect.target"), "重定向必须填写目标地址");
                } else if !(target.starts_with("http://") || target.starts_with("https://")) {
                    ctx.error(
                        format!("{base}.redirect.target"),
                        "重定向目标必须以 http:// 或 https:// 开头",
                    );
                }
                if ![301, 302, 303, 307, 308].contains(&app.redirect.status) {
                    ctx.error(format!("{base}.redirect.status"), "重定向状态码非法");
                }
            }
        }

        // 路由
        for (j, route) in app.routes.iter().enumerate() {
            validate_route(route, &format!("{base}.routes[{j}]"), ctx);
        }

        // 路由路径重复
        let mut paths = HashSet::new();
        for (j, route) in app.routes.iter().enumerate() {
            if !paths.insert(route.path.as_str()) {
                ctx.error(
                    format!("{base}.routes[{j}].path"),
                    format!("路由路径 `{}` 重复", route.path),
                );
            }
        }

        // 策略
        if let Some(p) = &app.policy.protection {
            validate_protection(p, &format!("{base}.policy.protection"), ctx);
        }
        if let Some(r) = app.policy.ratelimit {
            validate_ratelimit(&r, &format!("{base}.policy.ratelimit"), ctx);
        }
        validate_policy_cidrs(&app.policy, &format!("{base}.policy"), ctx);

        // 健康检查
        if let Some(active) = &app.health_check.active {
            if active.enabled && active.interval.as_secs() == 0 {
                ctx.error(
                    format!("{base}.health_check.active.interval"),
                    "健康检查间隔不能为 0",
                );
            }
        }

        // 临时应用到期时间
        if let Some(ts) = app.expires_at {
            if ts <= 0 {
                ctx.error(
                    format!("{base}.expires_at"),
                    "到期时间必须为正数（Unix 秒）",
                );
            }
        }
    }
}

fn register_domain(
    map: &mut HashMap<String, (usize, String)>,
    domain: &str,
    app_index: usize,
    path: String,
    ctx: &mut Ctx,
) {
    let key = normalize_domain(domain);
    if let Some((prev, _)) = map.get(&key) {
        ctx.error(
            path,
            format!("域名 `{domain}` 已被 applications[{prev}] 声明"),
        );
    } else {
        map.insert(key, (app_index, path));
    }
}

fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn validate_upstreams(upstreams: &[Upstream], base: &str, ctx: &mut Ctx) {
    if upstreams.len() > 16 {
        ctx.error(base, "单个应用的上游最多 16 个");
    }
    let mut non_backup = 0;
    for (i, u) in upstreams.iter().enumerate() {
        let p = format!("{base}[{i}]");

        // 统一用 target() 解析：addr 里可能写的是完整 URL
        match u.target() {
            Ok(t) => {
                if t.port == 0 {
                    ctx.error(format!("{p}.addr"), "端口不能为 0");
                }
            }
            Err(e) => ctx.error(format!("{p}.addr"), e),
        }

        if u.weight == 0 || u.weight > 100 {
            ctx.error(format!("{p}.weight"), "权重需在 1-100 之间");
        }
        if !u.backup {
            non_backup += 1;
        }
    }
    if non_backup == 0 {
        ctx.error(base, "至少需要一个非 backup 的上游");
    }
}

fn validate_route(route: &Route, base: &str, ctx: &mut Ctx) {
    // 路径支持普通前缀，以及 nginx 风格的 `= /x`、`^~ /x`、`~ re`、`~* re`
    let trimmed = route.path.trim_start();
    let has_operator = ["= ", "^~ ", "~* ", "~ "]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix));
    if !route.path.starts_with('/') && !has_operator {
        ctx.error(
            format!("{base}.path"),
            format!(
                "路由路径必须以 `/` 开头，或使用 `= /`、`^~ /`、`~ `、`~* ` 运算符，实际为 `{}`",
                route.path
            ),
        );
    }
    if route.path.len() > 2048 {
        ctx.error(format!("{base}.path"), "路由路径过长");
    }
    if let Some(ups) = &route.upstreams {
        if ups.is_empty() {
            ctx.error(format!("{base}.upstreams"), "指定了上游列表但不能为空");
        } else {
            validate_upstreams(ups, &format!("{base}.upstreams"), ctx);
        }
    }
    if let Some(rw) = &route.rewrite {
        match rw.mode {
            RewriteMode::StripPrefix => {}
            RewriteMode::AddPrefix | RewriteMode::Prefix => {
                if rw.value.trim().is_empty() {
                    ctx.error(
                        format!("{base}.rewrite.value"),
                        format!("{:?} 模式必须指定 value", rw.mode),
                    );
                } else if !rw.value.starts_with('/') {
                    ctx.error(format!("{base}.rewrite.value"), "重写目标必须以 `/` 开头");
                }
            }
            RewriteMode::Regex => {
                if rw.regex.as_deref().unwrap_or("").is_empty() {
                    ctx.error(format!("{base}.rewrite.regex"), "regex 模式必须指定 regex");
                }
                if rw.replacement.is_none() {
                    ctx.error(
                        format!("{base}.rewrite.replacement"),
                        "regex 模式必须指定 replacement",
                    );
                }
            }
        }
    }
    if let Some(methods) = &route.allow_methods {
        if methods.is_empty() {
            ctx.error(format!("{base}.allow_methods"), "方法列表不能为空");
        }
        for (i, m) in methods.iter().enumerate() {
            if !is_valid_method(m) {
                ctx.error(
                    format!("{base}.allow_methods[{i}]"),
                    format!("非法 HTTP 方法 `{m}`"),
                );
            }
        }
    }
    if let Some(p) = &route.policy {
        if let Some(prot) = &p.protection {
            validate_protection(prot, &format!("{base}.policy.protection"), ctx);
        }
        if let Some(r) = p.ratelimit {
            validate_ratelimit(&r, &format!("{base}.policy.ratelimit"), ctx);
        }
        validate_policy_cidrs(p, &format!("{base}.policy"), ctx);
    }
}

fn validate_policy_cidrs(policy: &Policy, base: &str, ctx: &mut Ctx) {
    // 分别检查 allow 与 deny：不能只在两者同时存在时才检查
    if let Some(allow) = &policy.allow_cidr {
        for (i, a) in allow.iter().enumerate() {
            if a.prefix_len() == 0 {
                ctx.error(
                    format!("{base}.allow_cidr[{i}]"),
                    "白名单不能是全网段（/0）",
                );
            }
        }
    }
    if let Some(deny) = &policy.deny_cidr {
        for (j, d) in deny.iter().enumerate() {
            if d.prefix_len() == 0 {
                ctx.error(format!("{base}.deny_cidr[{j}]"), "黑名单不能是全网段（/0）");
            }
        }
    }
    // 重叠检查需要两者都存在
    if let (Some(allow), Some(deny)) = (&policy.allow_cidr, &policy.deny_cidr) {
        for (i, a) in allow.iter().enumerate() {
            for d in deny.iter() {
                if a.contains(&d.network()) || d.contains(&a.network()) {
                    ctx.warn(
                        format!("{base}.allow_cidr[{i}]"),
                        format!("白名单 `{a}` 与黑名单 `{d}` 存在重叠，白名单优先"),
                    );
                }
            }
        }
    }
}

// ============================================================
// 基础校验工具
// ============================================================

fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("id 不能为空".into());
    }
    if id.len() > 32 {
        return Err("id 长度不能超过 32".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("id 只能包含小写字母、数字与连字符".into());
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err("id 不能以连字符开头或结尾".into());
    }
    Ok(())
}

/// 域名校验。允许通配符，但只允许最左侧一层。
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let d = domain.trim();
    if d.is_empty() {
        return Err("域名不能为空".into());
    }
    if d.len() > 253 {
        return Err("域名长度超过 253 字符".into());
    }

    let rest = d.strip_prefix("*.").unwrap_or(d);
    if rest.contains('*') {
        return Err("通配符只能出现在最左侧且只允许一层（如 *.home.lan）".into());
    }
    if rest.is_empty() {
        return Err("通配符后缺少域名".into());
    }

    for label in rest.split('.') {
        if label.is_empty() {
            return Err("域名包含空标签（连续的点或首尾点）".into());
        }
        if label.len() > 63 {
            return Err(format!("标签 `{label}` 超过 63 字符"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("标签 `{label}` 不能以连字符开头或结尾"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "标签 `{label}` 含非法字符（仅允许字母、数字、- 与 _）"
            ));
        }
    }
    Ok(())
}

/// 上游地址校验：IP / 域名 / unix socket。
pub fn validate_upstream_addr(addr: &str) -> Result<(), String> {
    let a = addr.trim();
    if a.is_empty() {
        return Err("上游地址不能为空".into());
    }
    if let Some(path) = a.strip_prefix("unix:") {
        if path.is_empty() {
            return Err("Unix Socket 路径不能为空".into());
        }
        if !path.starts_with('/') {
            return Err("Unix Socket 路径必须是绝对路径".into());
        }
        return Ok(());
    }
    if a.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    validate_domain(a).map_err(|e| format!("既不是合法 IP 也不是合法域名：{e}"))
}

fn is_valid_method(m: &str) -> bool {
    matches!(
        m.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
    )
}

/// HTTP 头名（RFC 9110 token）。允许自定义头名，但必须是合法 token。
fn is_valid_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::{Duration, Size};

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
            policy: Policy::default(),
            lb: LbConfig::default(),
            timeouts: TimeoutsConfig::default(),
            health_check: HealthCheckConfig::default(),
            retry: RetryConfig::default(),
            headers: HeadersConfig::default(),
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

    #[test]
    fn valid_domains_pass() {
        for d in [
            "nas.home.lan",
            "*.home.lan",
            "a-b.example.com",
            "xn--fiq228c.lan",
        ] {
            assert!(validate_domain(d).is_ok(), "{d} 应该合法");
        }
    }

    #[test]
    fn invalid_domains_rejected() {
        for d in ["", "a..b", "-bad.com", "bad-.com", "a.*.com", "a b.com"] {
            assert!(validate_domain(d).is_err(), "{d} 应该被拒绝");
        }
    }

    #[test]
    fn upstream_addr_forms() {
        assert!(validate_upstream_addr("192.168.1.5").is_ok());
        assert!(validate_upstream_addr("fd00::5").is_ok());
        assert!(validate_upstream_addr("nas.local").is_ok());
        assert!(validate_upstream_addr("unix:/run/app.sock").is_ok());
        assert!(validate_upstream_addr("").is_err());
        assert!(validate_upstream_addr("unix:relative.sock").is_err());
    }

    #[test]
    fn duplicate_domain_is_error() {
        let config = Config {
            applications: vec![app("a", "same.home.lan"), app("b", "same.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(report.has_errors());
        assert!(report
            .errors
            .iter()
            .any(|e| e.message.contains("已被 applications[0]")));
    }

    #[test]
    fn duplicate_id_is_error() {
        let config = Config {
            applications: vec![app("same", "a.home.lan"), app("same", "b.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(report.has_errors());
    }

    #[test]
    fn alias_conflicts_with_other_primary() {
        let mut a = app("a", "a.home.lan");
        a.domains.aliases = vec!["b.home.lan".to_string()];
        let config = Config {
            applications: vec![a, app("b", "b.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(report.has_errors());
    }

    #[test]
    fn preset_with_manual_toggle_is_allowed() {
        // preset 是基线，单项覆盖它。两者共存是正常用法，不应产生警告。
        let config = Config {
            protection: ProtectionConfig {
                preset: Some(Preset::Balanced),
                sqli: Some(Toggle::Block),
                file_upload: Some(Toggle::Monitor),
                ..Default::default()
            },
            applications: vec![app("a", "a.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(!report.has_errors());
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.path == "protection.preset"),
            "不应因 preset 与单项共存而警告"
        );
    }

    #[test]
    fn real_ip_without_trusted_proxies_warns() {
        let config = Config {
            real_ip: RealIpConfig {
                enabled: true,
                ..Default::default()
            },
            applications: vec![app("a", "a.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.path.contains("trusted_proxies")));
    }

    #[test]
    fn ip_group_requires_https() {
        let config = Config {
            ip_groups: vec![IpGroup {
                name: "bad".to_string(),
                label: "测试订阅".to_string(),
                enabled: true,
                source: IpGroupSource {
                    url: "http://example.com/list".to_string(),
                    kind: crate::IpGroupSourceKind::Http,
                    aliyun: Default::default(),
                    format: FeedFormat::Auto,
                    interval: crate::units::Duration::from_secs(3600),
                    timeout: crate::units::Duration::from_secs(15),
                    headers: Default::default(),
                },
                action: IpGroupAction::Block,
                scope: vec![],
                expires: crate::units::Duration::from_secs(86_400),
                guards: IpGroupGuards::default(),
                on_failure: OnFailure::KeepLast,
            }],
            applications: vec![app("a", "a.home.lan")],
            ..Default::default()
        };
        let report = validate(&config);
        assert!(report.errors.iter().any(|e| e.message.contains("HTTPS")));
    }

    #[test]
    fn empty_applications_warns() {
        let config = Config::default();
        let report = validate(&config);
        assert!(!report.has_errors());
        assert!(report.warnings.iter().any(|w| w.path == "applications"));
    }

    #[test]
    fn app_ratelimit_with_all_zero_thresholds_warns() {
        let mut a = app("a", "a.home.lan");
        a.policy.ratelimit = Some(RateLimitConfig {
            enabled: true,
            global_qps: 0,
            per_ip_qps: 0,
            per_ip_conn: 0,
            per_url_qps: 0,
            ..Default::default()
        });
        let report = validate(&Config {
            applications: vec![a],
            ..Default::default()
        });
        assert!(report
            .warnings
            .iter()
            .any(|w| w.path == "applications[0].policy.ratelimit"));
    }

    #[test]
    fn challenge_difficulty_out_of_range_is_error() {
        let report = validate(&Config {
            challenge: ChallengeConfig {
                difficulty: 9,
                ..Default::default()
            },
            ..Default::default()
        });
        assert!(report
            .errors
            .iter()
            .any(|e| e.path == "challenge.difficulty"));
    }

    // ============================================================
    // 规则包订阅
    // ============================================================

    // ============================================================
    // 自定义规则
    // ============================================================

    fn custom(id: &str, pattern: Vec<Vec<RuleCondition>>) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            name: "测试规则".to_string(),
            enabled: true,
            action: 1,
            match_mode: MatchMode::Any,
            seq: 0,
            created_at: None,
            scope: Vec::new(),
            expires_at: None,
            pattern,
        }
    }

    fn cond(k: &str, op: &str, v: &[&str]) -> RuleCondition {
        RuleCondition {
            k: k.to_string(),
            op: op.to_string(),
            v: v.iter().map(|s| s.to_string()).collect(),
            sub_k: None,
        }
    }

    // ============================================================
    // 自定义检测规则
    // ============================================================

    fn detect(id: &str, pattern: &str) -> DetectRule {
        DetectRule {
            id: id.to_string(),
            name: "测试规则".to_string(),
            pattern: pattern.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn valid_detect_rule_passes() {
        let report = validate(&Config {
            custom_detect_rules: vec![detect("local-1", r"(?i)evilscanner")],
            ..Default::default()
        });
        assert!(
            !report
                .errors
                .iter()
                .any(|e| e.path.starts_with("custom_detect_rules")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn detect_rule_rejects_bad_regex_and_target() {
        let mut rule = detect("local-1", "([a-z");
        rule.targets = vec!["bodyy".to_string()];
        let report = validate(&Config {
            custom_detect_rules: vec![rule],
            ..Default::default()
        });
        let msgs: Vec<&str> = report
            .errors
            .iter()
            .filter(|e| e.path.starts_with("custom_detect_rules"))
            .map(|e| e.message.as_str())
            .collect();
        assert!(msgs.iter().any(|m| m.contains("正则非法")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("未知作用对象")), "{msgs:?}");
    }

    #[test]
    fn detect_rule_rejects_duplicate_id() {
        let report = validate(&Config {
            custom_detect_rules: vec![detect("local-1", "a"), detect("local-1", "b")],
            ..Default::default()
        });
        assert!(report.errors.iter().any(|e| e.message.contains("重复")));
    }

    #[test]
    fn valid_custom_rule_passes() {
        let report = validate(&Config {
            custom_rules: vec![custom(
                "r1",
                vec![vec![cond("path", "prefix", &["/admin"])]],
            )],
            ..Default::default()
        });
        assert!(
            !report
                .errors
                .iter()
                .any(|e| e.path.starts_with("custom_rules")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn custom_rule_rejects_unknown_field_and_bad_cidr() {
        let report = validate(&Config {
            custom_rules: vec![custom(
                "r1",
                vec![vec![
                    cond("telepathy", "eq", &["x"]),
                    cond("src_ip", "eq", &["not-a-cidr"]),
                ]],
            )],
            ..Default::default()
        });
        let msgs: Vec<&str> = report
            .errors
            .iter()
            .filter(|e| e.path.starts_with("custom_rules"))
            .map(|e| e.message.as_str())
            .collect();
        assert!(msgs.iter().any(|m| m.contains("未知条件字段")), "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.contains("不是合法的网段")),
            "{msgs:?}"
        );
    }

    #[test]
    fn custom_rule_rejects_missing_ip_group() {
        let report = validate(&Config {
            custom_rules: vec![custom("r1", vec![vec![cond("ip_group", "in", &["nope"])]])],
            ..Default::default()
        });
        assert!(report
            .errors
            .iter()
            .any(|e| e.message.contains("不存在的 IP 组")));
    }

    #[test]
    fn custom_rule_rejects_empty_pattern_and_bad_action() {
        let mut rule = custom("r1", vec![vec![]]);
        rule.action = 9;
        let report = validate(&Config {
            custom_rules: vec![rule],
            ..Default::default()
        });
        assert!(report
            .errors
            .iter()
            .any(|e| e.message.contains("至少要有一个条件")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.message.contains("动作只能是")));
    }

    fn rule_feed() -> RuleFeed {
        RuleFeed {
            name: "official".to_string(),
            label: "官方规则包".to_string(),
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
            public_key: Some("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            shadow_period: None,
            rollback_on_error: true,
            pinned_version: None,
        }
    }

    fn validate_feed(f: RuleFeed) -> ValidationReport {
        validate(&Config {
            rule_feeds: vec![f],
            ..Default::default()
        })
    }

    #[test]
    fn valid_rule_feed_passes() {
        let report = validate_feed(rule_feed());
        assert!(!report.has_errors(), "{:?}", report.errors);
    }

    #[test]
    fn rule_feed_requires_https() {
        let mut f = rule_feed();
        f.url = "http://rules.example.com/core.hwrule".to_string();
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].url"));
    }

    #[test]
    fn rule_feed_signature_requires_key() {
        let mut f = rule_feed();
        f.public_key = None;
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].public_key"));
    }

    #[test]
    fn rule_feed_rejects_malformed_key() {
        for key in ["rsa:AAAA", "ed25519:short", "ed25519:!!!!"] {
            let mut f = rule_feed();
            f.public_key = Some(key.to_string());
            assert!(
                validate_feed(f)
                    .errors
                    .iter()
                    .any(|e| e.path == "rule_feeds[0].public_key"),
                "应拒绝 {key}"
            );
        }
    }

    #[test]
    fn rule_feed_rejects_bad_name() {
        let mut f = rule_feed();
        f.name = "a b".to_string();
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].name"));
    }

    #[test]
    fn rule_feed_rejects_too_frequent_check() {
        let mut f = rule_feed();
        f.check_interval = Duration::from_secs(5);
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].check_interval"));
    }

    #[test]
    fn rule_feed_rejects_header_injection() {
        let mut f = rule_feed();
        f.headers.insert(
            "authorization".to_string(),
            "token\r\nx-evil: 1".to_string(),
        );
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].headers"));
    }

    #[test]
    fn rule_feed_long_shadow_is_warning_only() {
        let mut f = rule_feed();
        f.shadow_period = Some(Duration::from_secs(31 * 86_400));
        let report = validate_feed(f);
        assert!(!report.has_errors());
        assert!(report
            .warnings
            .iter()
            .any(|w| w.path == "rule_feeds[0].shadow_period"));
    }

    #[test]
    fn pinned_rule_feed_requires_version() {
        let mut f = rule_feed();
        f.channel = FeedChannel::Pinned;
        assert!(validate_feed(f)
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].pinned_version"));
    }

    #[test]
    fn rule_feed_rejects_bad_limits() {
        let mut f = rule_feed();
        f.timeout = Duration::from_secs(0);
        f.max_size = Size::from_bytes(10);
        let report = validate_feed(f);
        assert!(report
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].timeout"));
        assert!(report
            .errors
            .iter()
            .any(|e| e.path == "rule_feeds[0].max_size"));
    }
}
