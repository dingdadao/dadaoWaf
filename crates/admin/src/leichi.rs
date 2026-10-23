//! 雷池（SafeLine）配置同步。
//!
//! 通过雷池开放接口 `/api/open/*` 拉取应用、自定义规则、IP 组与证书，
//! 转换成 HomeWAF 的模型写入数据库：
//! - 应用：`GET /api/open/site`，含监听端口、上游与负载均衡
//! - 访问控制：`GET /api/open/policy`，IP 条件展开成 CIDR 写入 ACL 规则，
//!   action 0 白名单 / 1 黑名单；条件不支持的策略跳过并写告警
//! - IP 组订阅：`GET /api/open/ipgroup`，带 `reference` 订阅地址的组原样建成
//!   IP 组订阅；无地址的内置情报组由雷池云端维护，跳过并告警
//! - 证书：`GET /api/open/cert`，证书链一律登记；无私钥（ACME 托管）的条目
//!   标记为不可用于 TLS
//!
//! 雷池 9443 默认使用自签证书，所以这里关闭了 TLS 校验——同步目标通常是内网。

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::time::{Duration as StdDuration, Instant};

use homewaf_config::{
    AccessMode, ActiveHealthCheck, Application, CustomRule, Domains, HealthCheckConfig,
    IpGroup, IpGroupAction, IpGroupSource, IpGroupGuards, LbAlgorithm, LbConfig, ObserveMode,
    OnFailure, Policy, Scheme, TlsMode, TlsModeConfig,
    Upstream, UpstreamTlsConfig,
};
use homewaf_store::{AclRuleRow, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 自定义规则在设置表里的键，管理端导入导出也用它。
pub const CUSTOM_RULES_KEY: &str = "custom_rules";
pub const LEICHI_URL_KEY: &str = "leichi_url";
pub const LEICHI_TOKEN_KEY: &str = "leichi_token";
pub const LEICHI_LAST_SYNC_KEY: &str = "leichi_last_sync";

#[derive(Debug, Clone, Deserialize)]
pub struct SyncRequest {
    /// 雷池地址，如 `https://10.0.0.14:9443`。留空则用已保存的地址
    #[serde(default)]
    pub url: String,
    /// `X-SLCE-API-Token` 对应的 token。留空则用已保存的 token
    #[serde(default)]
    pub token: String,
    /// 只拉取并生成报告，不写数据库
    #[serde(default)]
    pub preview: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncStat {
    pub total: usize,
    pub imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncReport {
    pub source: String,
    pub preview: bool,
    pub apps: SyncStat,
    pub rules: SyncStat,
    pub certs: SyncStat,
    pub ip_groups: SyncStat,
    pub warnings: Vec<String>,
    pub items: Vec<String>,
    pub duration_ms: u64,
}

struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl Client {
    fn new(url: &str, token: &str) -> Result<Self, String> {
        let base = url.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err("雷池地址必须以 http:// 或 https:// 开头".to_string());
        }
        if token.trim().is_empty() {
            return Err("缺少雷池 API Token".to_string());
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(StdDuration::from_secs(20)))
            // 内网雷池常用自签证书
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .disable_verification(true)
                    .build(),
            )
            .build()
            .into();
        Ok(Self {
            base,
            token: token.trim().to_string(),
            agent,
        })
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}/api{}", self.base, path);
        let resp = self
            .agent
            .get(&url)
            .header("X-SLCE-API-Token", &self.token)
            .call()
            .map_err(|e| format!("请求 {url} 失败：{e}"))?;
        let mut text = String::new();
        resp.into_body()
            .into_reader()
            .take(16 * 1024 * 1024)
            .read_to_string(&mut text)
            .map_err(|e| format!("读取 {url} 响应失败：{e}"))?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("解析 {url} 响应失败：{e}"))?;
        unwrap_envelope(value)
    }
}

/// 雷池响应是 `{"data": ..., "err": null, "msg": ""}`。
///
/// 不同接口的包裹层数不一致：列表接口是单层（`data.nodes` / `data.data`），
/// IP 组详情等又是多层（`data.data`）。这里统一剥到「不再是纯信封」为止。
fn unwrap_envelope(mut value: Value) -> Result<Value, String> {
    loop {
        if let Some(err) = value.get("err") {
            if !err.is_null() {
                return Err(format!("雷池返回错误：{err}"));
            }
        }
        let is_envelope = value
            .as_object()
            .map(|o| {
                o.contains_key("data")
                    && o.keys()
                        .all(|k| matches!(k.as_str(), "data" | "err" | "msg"))
            })
            .unwrap_or(false);
        if !is_envelope {
            return Ok(value);
        }
        value = value
            .get("data")
            .cloned()
            .ok_or_else(|| "雷池响应缺少 data 字段".to_string())?;
    }
}

/// 执行一次同步。`store` 在 `preview = false` 时会被写入。
pub fn sync(store: &Store, req: &SyncRequest) -> Result<SyncReport, String> {
    let started = Instant::now();
    let url = if req.url.trim().is_empty() {
        store
            .get_setting::<String>(LEICHI_URL_KEY)
            .map_err(|e| e.to_string())?
            .unwrap_or_default()
    } else {
        req.url.trim().to_string()
    };
    let token = if req.token.trim().is_empty() {
        store
            .get_setting::<String>(LEICHI_TOKEN_KEY)
            .map_err(|e| e.to_string())?
            .unwrap_or_default()
    } else {
        req.token.trim().to_string()
    };
    let client = Client::new(&url, &token)?;

    let mut report = SyncReport {
        source: client.base.clone(),
        preview: req.preview,
        ..Default::default()
    };
    let now = homewaf_acl::now_unix();

    // 1. IP 组：组 ID → IP 列表（供策略展开），同时挑出可订阅的组
    let ipg = fetch_ip_groups(&client, &mut report);
    let groups = ipg.ips;
    let mut ip_feeds = ipg.feeds;
    report.ip_groups = ipg.stat;

    // 2. 证书（只有手动上传的才带私钥）
    let mut new_certs: Vec<NewCert> = Vec::new();
    let certs = fetch_certs(
        &client,
        store,
        &mut report,
        req.preview,
        &mut new_certs,
        now,
    );

    // 3. 应用
    let sites = client.get("/open/site").and_then(|v| {
        v.get("data")
            .cloned()
            .ok_or_else(|| "应用列表缺少 data".to_string())
    })?;
    let sites = sites.as_array().cloned().unwrap_or_default();
    report.apps.total = sites.len();
    let mut apps: Vec<Application> = Vec::new();
    for site in &sites {
        match map_app(site) {
            Ok(app) => {
                report.items.push(format!(
                    "应用 {} → {}（{}，上游 {}）",
                    app.domains.primary,
                    app.id,
                    if app.enabled { "启用" } else { "停用" },
                    app.upstreams.len()
                ));
                report.apps.imported += 1;
                apps.push(app);
            }
            Err(reason) => {
                report.apps.skipped += 1;
                report.warnings.push(format!(
                    "跳过应用 {}：{reason}",
                    site.get("server_names")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                ));
            }
        }
    }

    // 4. 访问控制规则：雷池策略里的 IP 条件展开成 CIDR，写入 ACL 规则，
    //    不再塞进「自定义规则」——那个页面留给用户手写的规则。
    let policies = client.get("/open/policy").and_then(|v| {
        v.get("data")
            .cloned()
            .ok_or_else(|| "规则列表缺少 data".to_string())
    })?;
    let policies = policies.as_array().cloned().unwrap_or_default();
    report.rules.total = policies.len();
    let mut acl_rules: Vec<AclRuleRow> = Vec::new();
    for policy in &policies {
        match map_policy_acl(policy, &groups, &mut report) {
            Some(rows) => {
                let name = policy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未命名规则");
                let allow = policy_action(policy) == 0;
                report.items.push(format!(
                    "访问控制 {}（{}，{} 条网段）",
                    name,
                    if allow { "白名单" } else { "黑名单" },
                    rows.len()
                ));
                // 策略引用的 IP 组按策略动作决定订阅方向：白名单放行、黑名单拦截
                for feed in ip_feeds.iter_mut() {
                    if policy_references_group(policy, feed.id) {
                        feed.allow = allow;
                    }
                }
                report.rules.imported += 1;
                acl_rules.extend(rows);
            }
            None => report.rules.skipped += 1,
        }
    }

    // 启用中的策略引用了某组时，以策略动作决定订阅方向；都没有引用时
    // 保留按组名推断的结果（回源/CDN/白名单类放行，情报类拦截），并写明原因。
    for feed in &ip_feeds {
        let mut referenced = false;
        for policy in policies.iter().filter(|p| policy_enabled(p)) {
            if policy_references_group(policy, feed.id) {
                referenced = true;
            }
        }
        if !referenced {
            report.warnings.push(format!(
                "IP 组「{}」未被启用的策略引用，订阅动作按组名推断为{}，可在「IP 组订阅」页调整",
                feed.label,
                if feed.allow { "放行" } else { "拦截" }
            ));
        }
    }

    if !req.preview {
        // 证书
        for cert in new_certs.drain(..) {
            store
                .insert_certificate(
                    &cert.name,
                    &cert.cert_pem,
                    &cert.key_pem,
                    &cert.domains,
                    cert.not_before,
                    cert.not_after,
                    now,
                )
                .map_err(|e| format!("写入证书失败：{e}"))?;
        }

        // 应用
        for app in &apps {
            store
                .upsert_application(&app.id, &app.domains.primary, app.enabled, app, now)
                .map_err(|e| format!("写入应用 {} 失败：{e}", app.id))?;
        }

        // 访问控制：先清理上一轮同步、本轮已不存在的 lei-acl-* 规则，
        // 再写入本轮规则（稳定 id，重复同步不会产生重复条目）。
        let wanted: std::collections::HashSet<&str> =
            acl_rules.iter().map(|r| r.id.as_str()).collect();
        if let Ok(existing) = store.list_acl_rules() {
            for row in existing {
                if row.id.starts_with("lei-acl-") && !wanted.contains(row.id.as_str()) {
                    store.delete_acl_rule(&row.id).map_err(|e| e.to_string())?;
                }
            }
        }
        for rule in &acl_rules {
            store
                .upsert_acl_rule(rule, now)
                .map_err(|e| format!("写入访问控制规则 {} 失败：{e}", rule.id))?;
        }

        // IP 组订阅：雷池的 reference 地址原样建成订阅
        for feed in &ip_feeds {
            let group = IpGroup {
                name: feed.name.clone(),
                enabled: true,
                source: IpGroupSource {
                    url: feed.url.clone(),
                    format: homewaf_config::FeedFormat::Cidr,
                    interval: homewaf_config::Duration::from_secs(3600),
                    timeout: homewaf_config::Duration::from_secs(15),
                    headers: BTreeMap::new(),
                },
                action: if feed.allow {
                    IpGroupAction::Allow
                } else {
                    IpGroupAction::Block
                },
                scope: Vec::new(),
                expires: homewaf_config::Duration::from_secs(86_400),
                guards: IpGroupGuards::default(),
                on_failure: OnFailure::KeepLast,
            };
            store
                .upsert_ip_group(&group.name, group.enabled, &group, now)
                .map_err(|e| format!("写入 IP 组订阅 {} 失败：{e}", group.name))?;
            // 把雷池当前的快照写成本地基线：订阅源暂时不可达时也能按最近内容生效，
            // 同时也让本次同步后的重载无需联网。
            if let Some(ips) = groups.get(&feed.id) {
                let nets: Vec<String> = ips
                    .iter()
                    .filter_map(|s| s.parse::<ipnet::IpNet>().ok())
                    .map(|n| n.to_string())
                    .collect();
                if !nets.is_empty() {
                    store
                        .save_feed_state(&group.name, &nets.join("\n"), now)
                        .map_err(|e| format!("写入订阅快照 {} 失败：{e}", group.name))?;
                }
            }
        }

        // 自定义规则只保留用户手写规则：上一轮由雷池转换出来的 lei-* 条目清掉。
        let mut merged = store
            .get_setting::<Vec<CustomRule>>(CUSTOM_RULES_KEY)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let before = merged.len();
        merged.retain(|r| !r.id.starts_with("lei-"));
        if merged.len() != before {
            store
                .set_setting(CUSTOM_RULES_KEY, &merged, now)
                .map_err(|e| format!("清理雷池自定义规则失败：{e}"))?;
        }

        store
            .set_setting(LEICHI_URL_KEY, &client.base, now)
            .map_err(|e| e.to_string())?;
        store
            .set_setting(LEICHI_TOKEN_KEY, &client.token, now)
            .map_err(|e| e.to_string())?;
        report.certs = certs;
    } else {
        report.certs = certs;
    }

    report.duration_ms = started.elapsed().as_millis() as u64;

    if !req.preview {
        let value = serde_json::to_value(&report).unwrap_or(Value::Null);
        store
            .set_setting(LEICHI_LAST_SYNC_KEY, &value, now)
            .map_err(|e| e.to_string())?;
    }
    Ok(report)
}

/// 读取上次同步报告。
pub fn last_report(store: &Store) -> Result<Value, String> {
    Ok(store
        .get_setting::<Value>(LEICHI_LAST_SYNC_KEY)
        .map_err(|e| e.to_string())?
        .unwrap_or(Value::Null))
}

/// 读取已保存的连接配置。
pub fn saved_config(store: &Store) -> (String, String) {
    let url = store
        .get_setting::<String>(LEICHI_URL_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    let token = store
        .get_setting::<String>(LEICHI_TOKEN_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    (url, token)
}

/// 一次 IP 组拉取的结果：组 ID → IP 列表（供策略展开）、可订阅的组、统计。
struct IpGroupFetch {
    ips: HashMap<i64, Vec<String>>,
    feeds: Vec<IpGroupFeed>,
    stat: SyncStat,
}

/// 一条待写入的 IP 组订阅。
struct IpGroupFeed {
    id: i64,
    name: String,
    label: String,
    url: String,
    /// 该组是否被白名单策略引用：是则订阅命中后放行，否则拦截
    allow: bool,
}

const IP_GROUP_PREFIX: &str = "lei-ipgroup-";

fn fetch_ip_groups(client: &Client, report: &mut SyncReport) -> IpGroupFetch {
    let mut out = HashMap::new();
    let mut feeds = Vec::new();
    let mut stat = SyncStat::default();
    let list = match client.get("/open/ipgroup") {
        Ok(v) => v,
        Err(e) => {
            report.warnings.push(format!("读取 IP 组列表失败：{e}"));
            return IpGroupFetch {
                ips: out,
                feeds,
                stat,
            };
        }
    };
    let nodes = list
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    stat.total = nodes.len();
    for node in nodes {
        let Some(id) = node.get("id").and_then(|v| v.as_i64()) else {
            stat.skipped += 1;
            continue;
        };
        let label = group_label(&node);
        let detail = match client.get(&format!("/open/ipgroup/detail?id={id}")) {
            Ok(v) => v,
            Err(e) => {
                report
                    .warnings
                    .push(format!("读取 IP 组 {id} 详情失败：{e}"));
                stat.skipped += 1;
                continue;
            }
        };
        let ips: Vec<String> = detail
            .get("ips")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !ips.is_empty() {
            report
                .items
                .push(format!("IP 组 {}（{} 条）", label, ips.len()));
            out.insert(id, ips.clone());
        }

        // 有订阅地址的组直接建成 IP 组订阅，由本机定时拉取，不依赖雷池在线。
        let reference = node
            .get("reference")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if reference.starts_with("https://") {
            feeds.push(IpGroupFeed {
                id,
                name: format!("{IP_GROUP_PREFIX}{id}"),
                label: label.clone(),
                url: reference,
                // 先按组名推断，稍后用策略引用关系覆盖
                allow: infer_feed_allow(&label),
            });
            stat.imported += 1;
            report
                .items
                .push(format!("IP 组订阅 {label} → {IP_GROUP_PREFIX}{id}"));
        } else if reference.starts_with("http://") {
            stat.skipped += 1;
            report.warnings.push(format!(
                "IP 组「{label}」的订阅地址不是 HTTPS，已跳过（明文订阅可能被投毒）"
            ));
        } else if ips.is_empty() {
            stat.skipped += 1;
            report.warnings.push(format!(
                "IP 组「{label}」没有订阅地址，内容由雷池云端维护，无法迁移"
            ));
        } else {
            // 没有订阅地址但已有快照：内容已经展开成访问控制规则
            stat.imported += 1;
        }
    }
    IpGroupFetch {
        ips: out,
        feeds,
        stat,
    }
}

fn group_label(node: &Value) -> String {
    node.get("comment")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("#{}", node.get("id").and_then(|v| v.as_i64()).unwrap_or(0)))
}

struct NewCert {
    name: String,
    cert_pem: String,
    key_pem: String,
    domains: String,
    not_before: i64,
    not_after: i64,
}

fn fetch_certs(
    client: &Client,
    store: &Store,
    report: &mut SyncReport,
    preview: bool,
    new_certs: &mut Vec<NewCert>,
    _now: i64,
) -> SyncStat {
    let mut stat = SyncStat::default();
    let existing = store.list_certificates().unwrap_or_default();
    let list = match client.get("/open/cert") {
        Ok(v) => v,
        Err(e) => {
            report.warnings.push(format!("读取证书列表失败：{e}"));
            return stat;
        }
    };
    let nodes = list
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    stat.total = nodes.len();
    for node in nodes {
        let Some(id) = node.get("id").and_then(|v| v.as_i64()) else {
            stat.skipped += 1;
            continue;
        };
        let detail = match client.get(&format!("/open/cert/{id}")) {
            Ok(v) => v,
            Err(e) => {
                stat.skipped += 1;
                report.warnings.push(format!("读取证书 {id} 失败：{e}"));
                continue;
            }
        };
        let manual = detail.get("manual");
        let crt = manual
            .and_then(|m| m.get("crt"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let key = manual
            .and_then(|m| m.get("key"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if crt.is_empty() {
            stat.skipped += 1;
            report
                .warnings
                .push(format!("证书 #{id} 没有证书链内容，跳过"));
            continue;
        }
        // ACME / 托管证书在雷池侧不导出私钥：证书链照常登记（控制台可见），
        // 但没有私钥无法用于 TLS 握手，只能提示手动补齐。
        if key.is_empty() {
            report.warnings.push(format!(
                "证书 #{id} 为 ACME / 托管证书，雷池不提供私钥，已登记证书链但不会用于 TLS，需手动上传私钥"
            ));
        }
        if existing.iter().any(|row| row.cert_pem == crt) {
            stat.imported += 1;
            continue;
        }
        let info = match crate::certs::parse_cert(crt) {
            Ok(info) => info,
            Err(e) => {
                stat.skipped += 1;
                report.warnings.push(format!("证书 #{id} 解析失败：{e}"));
                continue;
            }
        };
        let first = info
            .domains
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !preview {
            new_certs.push(NewCert {
                name: if first.is_empty() {
                    format!("lei-cert-{id}")
                } else {
                    first.clone()
                },
                cert_pem: crt.to_string(),
                key_pem: key.to_string(),
                domains: info.domains.clone(),
                not_before: info.not_before,
                not_after: info.not_after,
            });
        }
        stat.imported += 1;
        report
            .items
            .push(format!("证书 {}（{}）", first, info.domains));
    }
    stat
}

fn map_app(site: &Value) -> Result<Application, String> {
    let names: Vec<String> = site
        .get("server_names")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let Some(primary) = names.first().cloned() else {
        return Err("没有域名".to_string());
    };
    if site.get("type").and_then(|v| v.as_i64()).unwrap_or(0) != 0
        || site
            .get("static")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        return Err("静态站点 / 重定向类型暂不支持自动同步".to_string());
    }

    let mut listen_ports: Vec<u16> = Vec::new();
    let mut has_ssl = false;
    if let Some(ports) = site.get("ports").and_then(|v| v.as_array()) {
        for p in ports.iter().filter_map(|v| v.as_str()) {
            has_ssl |= p.ends_with("_ssl");
            let num: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(port) = num.parse::<u16>() {
                if port != 0 && !listen_ports.contains(&port) {
                    listen_ports.push(port);
                }
            }
        }
    }
    if listen_ports.is_empty() {
        return Err("没有监听端口".to_string());
    }

    let weights: HashMap<String, (u16, bool)> = site
        .get("load_balance")
        .and_then(|v| v.get("upstreams"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|u| {
                    let addr = u.get("address")?.as_str()?.to_string();
                    let weight = u.get("weight").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
                    let backup = u
                        .get("role")
                        .and_then(|v| v.as_str())
                        .map(|r| r.eq_ignore_ascii_case("backup"))
                        .unwrap_or(false);
                    Some((addr, (weight.max(1), backup)))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut upstreams = Vec::new();
    if let Some(list) = site.get("upstreams").and_then(|v| v.as_array()) {
        for addr in list.iter().filter_map(|v| v.as_str()) {
            let addr = addr.trim();
            if addr.is_empty() {
                continue;
            }
            let (weight, backup) = weights.get(addr).copied().unwrap_or((1, false));
            let https = addr.to_ascii_lowercase().starts_with("https://");
            upstreams.push(Upstream {
                addr: addr.to_string(),
                port: None,
                scheme: if https { Scheme::Https } else { Scheme::Http },
                weight,
                backup,
                max_conns: 128,
                tls: if https {
                    // 内网上游常见自签证书，与雷池默认行为保持一致
                    Some(UpstreamTlsConfig {
                        verify: false,
                        ..Default::default()
                    })
                } else {
                    None
                },
            });
        }
    }
    if upstreams.is_empty() {
        return Err("没有上游".to_string());
    }

    let mode = site.get("mode").and_then(|v| v.as_i64()).unwrap_or(0);
    let enabled = site
        .get("is_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let observe = if mode == 2 {
        ObserveMode {
            enabled: true,
            ..Default::default()
        }
    } else {
        ObserveMode::default()
    };
    let interval = site
        .get("health_check_interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
        .max(5);
    let health = site
        .get("health_check")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let load_type = site
        .get("load_balance")
        .and_then(|v| v.get("balance_type"))
        .and_then(|v| v.as_i64())
        .unwrap_or(1);
    let algorithm = match load_type {
        2 => LbAlgorithm::IpHash,
        3 => LbAlgorithm::Weighted,
        4 => LbAlgorithm::LeastConn,
        _ => LbAlgorithm::RoundRobin,
    };

    Ok(Application {
        id: format!(
            "lei-{}",
            site.get("id").and_then(|v| v.as_i64()).unwrap_or(0)
        ),
        name: site
            .get("title")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&primary)
            .to_string(),
        // mode 1 = 离线（雷池术语），同步为停用
        enabled: enabled && mode != 1,
        domains: Domains {
            primary,
            aliases: names.iter().skip(1).take(10).cloned().collect(),
        },
        listen_ports,
        upstreams,
        routes: Vec::new(),
        tls: TlsModeConfig {
            mode: if has_ssl { TlsMode::Auto } else { TlsMode::Off },
            cert_id: None,
        },
        policy: Policy {
            observe_mode: Some(observe),
            ..Default::default()
        },
        lb: LbConfig {
            algorithm,
            sticky: false,
        },
        timeouts: Default::default(),
        health_check: if health {
            HealthCheckConfig {
                active: Some(ActiveHealthCheck {
                    enabled: true,
                    interval: homewaf_config::Duration::from_secs(interval),
                    timeout: homewaf_config::Duration::from_secs(3),
                    path: "/".to_string(),
                    method: "GET".to_string(),
                    // 雷池自身把"能建立连接并返回任意非 5xx"视为健康，
                    // 这里留空表示同样的语义；写死 200/204 会把只提供 404
                    // 首页的上游误判为不健康。
                    expect_status: Vec::new(),
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                }),
                passive: None,
            }
        } else {
            HealthCheckConfig::default()
        },
        retry: Default::default(),
        headers: Default::default(),
        websocket: false,
        expires_at: None,
        description: site
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        group: String::new(),
        access_mode: AccessMode::Proxy,
        static_site: Default::default(),
        redirect: Default::default(),
        features: Default::default(),
        tamper: Default::default(),
    })
}

/// 雷池策略动作：0 = 白名单，1 = 黑名单。
fn policy_action(policy: &Value) -> i64 {
    policy.get("action").and_then(|v| v.as_i64()).unwrap_or(1)
}

fn policy_enabled(policy: &Value) -> bool {
    policy
        .get("is_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// 没有被任何启用策略引用的情报组：按组名推断订阅方向。
/// 回源、CDN、白名单、爬虫类必须放行，否则会误伤正常流量；其余按威胁情报拦截。
fn infer_feed_allow(label: &str) -> bool {
    let l = label.to_lowercase();
    ["白名单", "局域网", "回源", "edgeone", "cdn", "爬虫", "crawler"]
        .iter()
        .any(|k| l.contains(k))
}

/// 策略是否引用了指定 IP 组（用于判定订阅组的处置方向）。
fn policy_references_group(policy: &Value, group_id: i64) -> bool {
    policy
        .get("pattern")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|branch| branch.as_array())
        .flatten()
        .filter(|cond| {
            is_ip_key(
                cond.get("k")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim(),
            )
        })
        .filter_map(|cond| cond.get("v").and_then(|v| v.as_array()))
        .flatten()
        .any(|v| {
            v.as_i64() == Some(group_id)
                || v.as_str().and_then(|s| s.trim().parse::<i64>().ok()) == Some(group_id)
        })
}

/// 把一条雷池策略转换成 ACL 规则。
///
/// 只处理「每个 OR 分支都恰好是一个 IP 条件」的策略：ACL 规则是单一 CIDR，
/// 无法表达 IP 与路径/Header 的与关系，这类策略保留在雷池侧并告警。
/// 数字形式的 IP 值表示 IP 组 ID，展开成具体网段后逐条落成规则。
fn map_policy_acl(
    policy: &Value,
    groups: &HashMap<i64, Vec<String>>,
    report: &mut SyncReport,
) -> Option<Vec<AclRuleRow>> {
    let name = policy
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("未命名规则")
        .to_string();
    let policy_id = policy.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if !policy
        .get("is_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        report.warnings.push(format!(
            "策略「{name}」在雷池中已停用，未迁移（ACL 规则没有停用状态）"
        ));
        return None;
    }

    let branches: Vec<&Vec<Value>> = policy
        .get("pattern")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|b| b.as_array()).collect())
        .unwrap_or_default();
    if branches.is_empty() {
        report
            .warnings
            .push(format!("策略「{name}」的 pattern 为空，跳过"));
        return None;
    }

    let mut cidrs: Vec<String> = Vec::new();
    for branch in branches {
        if branch.len() != 1 {
            report.warnings.push(format!(
                "策略「{name}」的分支有 {} 个条件（与关系），ACL 无法表达，跳过",
                branch.len()
            ));
            return None;
        }
        let cond = &branch[0];
        let key = cond.get("k").and_then(|v| v.as_str()).unwrap_or("").trim();
        let op = cond
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !is_ip_key(key) || !matches!(op.as_str(), "in" | "eq") {
            report.warnings.push(format!(
                "策略「{name}」含非 IP 条件 `{key}`，ACL 无法表达，跳过"
            ));
            return None;
        }
        let mut values: Vec<String> = cond
            .get("v")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .or_else(|| v.as_i64().map(|n| n.to_string()))
                    })
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if values.is_empty() {
            report
                .warnings
                .push(format!("策略「{name}」的 IP 条件没有可用值，跳过"));
            return None;
        }
        for value in values.drain(..) {
            match value.parse::<i64>() {
                Ok(group_id) => match groups.get(&group_id) {
                    Some(ips) => cidrs.extend(ips.iter().cloned()),
                    None => report.warnings.push(format!(
                        "策略「{name}」引用的 IP 组 {group_id} 没有数据，已忽略"
                    )),
                },
                Err(_) => cidrs.push(value),
            }
        }
    }

    let action = if policy_action(policy) == 0 {
        "allow"
    } else {
        "deny"
    };
    let mut rows = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for raw in cidrs {
        let Some(net) = normalize_cidr(&raw) else {
            report
                .warnings
                .push(format!("策略「{name}」的条目 `{raw}` 不是合法网段，已忽略"));
            continue;
        };
        if !seen.insert(net.clone()) {
            continue;
        }
        rows.push(AclRuleRow {
            id: format!("lei-acl-{policy_id}-{}", rows.len()),
            cidr: net,
            action: action.to_string(),
            scope: None,
            expires_at: None,
            note: Some(name.clone()),
        });
    }
    if rows.is_empty() {
        report
            .warnings
            .push(format!("策略「{name}」展开后没有可用网段，跳过"));
        return None;
    }
    Some(rows)
}

/// 单个 IP 补全成 /32（IPv6 为 /128）。
fn normalize_cidr(raw: &str) -> Option<String> {
    if let Ok(net) = raw.parse::<ipnet::IpNet>() {
        return Some(net.to_string());
    }
    let ip = raw.parse::<std::net::IpAddr>().ok()?;
    Some(match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}/32"),
        std::net::IpAddr::V6(v6) => format!("{v6}/128"),
    })
}

fn is_ip_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "src_ip" | "ip" | "client_ip" | "source_ip"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_whitelist_with_ip_group() {
        let mut groups = HashMap::new();
        groups.insert(10, vec!["10.0.0.0/24".to_string()]);
        let policy = json!({
            "id": 83,
            "name": "局域网",
            "action": 0,
            "is_enabled": true,
            "pattern": [[{"k": "src_ip", "op": "in", "v": ["10"], "sub_k": ""}]]
        });
        let mut report = SyncReport::default();
        let rows = map_policy_acl(&policy, &groups, &mut report).expect("应能转换");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "lei-acl-83-0");
        assert_eq!(rows[0].action, "allow");
        assert_eq!(rows[0].cidr, "10.0.0.0/24");
        // 白名单策略引用的 IP 组在订阅时应放行
        assert!(policy_references_group(&policy, 10));
    }

    #[test]
    fn skips_unsupported_condition() {
        let policy = json!({
            "id": 80,
            "name": "白名单",
            "action": 0,
            "is_enabled": true,
            "pattern": [[{"k": "ja4", "op": "eq", "v": ["t13d"]}]]
        });
        let mut report = SyncReport::default();
        assert!(map_policy_acl(&policy, &HashMap::new(), &mut report).is_none());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn skips_disabled_policy() {
        let policy = json!({
            "id": 2,
            "name": "旧规则",
            "action": 1,
            "is_enabled": false,
            "pattern": [[{"k": "src_ip", "op": "in", "v": ["1.2.3.4"]}]]
        });
        let mut report = SyncReport::default();
        assert!(map_policy_acl(&policy, &HashMap::new(), &mut report).is_none());
        assert!(report.warnings[0].contains("已停用"));
    }

    #[test]
    fn normalizes_single_ip_and_skips_bad_entry() {
        let mut groups = HashMap::new();
        groups.insert(3, vec!["1.2.3.4".to_string(), "not-a-cidr".to_string()]);
        let policy = json!({
            "id": 9,
            "name": "黑名单",
            "action": 1,
            "is_enabled": true,
            "pattern": [[{"k": "src_ip", "op": "in", "v": ["3"]}]]
        });
        let mut report = SyncReport::default();
        let rows = map_policy_acl(&policy, &groups, &mut report).expect("应能转换");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cidr, "1.2.3.4/32");
        assert_eq!(rows[0].action, "deny");
    }

    #[test]
    fn maps_site_ports_upstreams_and_mode() {
        let site = json!({
            "id": 14,
            "server_names": ["ddoh.niao.fun"],
            "ports": ["80", "443_ssl", "8443_ssl"],
            "upstreams": ["https://10.0.0.30:443"],
            "is_enabled": true,
            "mode": 0,
            "type": 0,
            "static": false,
            "title": "DNS 代理配置中心",
            "health_check": true,
            "health_check_interval": 60,
            "load_balance": {
                "balance_type": 1,
                "upstreams": [{"address": "https://10.0.0.30:443", "weight": 2, "role": "primary"}]
            }
        });
        let app = map_app(&site).expect("应能转换");
        assert_eq!(app.id, "lei-14");
        assert_eq!(app.name, "DNS 代理配置中心");
        assert_eq!(app.listen_ports, vec![80, 443, 8443]);
        assert_eq!(app.upstreams[0].weight, 2);
        assert_eq!(app.upstreams[0].tls.as_ref().map(|t| t.verify), Some(false));
        assert_eq!(app.tls.mode, TlsMode::Auto);
        assert!(app.enabled);
    }
}
