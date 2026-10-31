//! 配置热重载。
//!
//! 用**轮询 mtime** 而不是文件系统事件：编辑器保存普遍是"写临时文件 + rename"，
//! 事件方案会触发多次并需要 debounce；轮询天然去抖，且不依赖平台特性。
//!
//! 重载失败的处置原则：**保留旧配置，绝不让服务进入半坏状态**。
//! 一份写错配置不应该让正在运行的服务失去防护。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use homewaf_acl::{Acl, FeedState};
use homewaf_config::{Config, RealIpConfig, TlsConfig};
use homewaf_detect::Engine;
use homewaf_limit::RateLimiter;
use homewaf_router::Router;
use homewaf_store::Store;
use ipnet::IpNet;

use crate::policy::PolicySet;
use crate::upstream::UpstreamPool;

/// 基于 SQLite 的订阅状态存储。
///
/// 没有它，护栏的"变更幅度"检查每次都按首次导入处理，形同虚设——
/// 订阅源被投毒后一次性替换全部条目，也拦不住。
pub struct SqliteFeedState<'a> {
    store: &'a Store,
}

impl<'a> SqliteFeedState<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }
}

impl FeedState for SqliteFeedState<'_> {
    fn previous(&self, group: &str) -> Vec<IpNet> {
        match self.store.load_feed_state(group) {
            Ok(Some(text)) => text
                .lines()
                .filter_map(|l| l.trim().parse::<IpNet>().ok())
                .collect(),
            Ok(None) => Vec::new(),
            Err(e) => {
                tracing::warn!(error = %e, group, "读取订阅状态失败，按首次导入处理");
                Vec::new()
            }
        }
    }

    fn remember(&self, group: &str, entries: &[IpNet]) {
        let text: Vec<String> = entries.iter().map(|n| n.to_string()).collect();
        if let Err(e) = self
            .store
            .save_feed_state(group, &text.join("\n"), homewaf_acl::now_unix())
        {
            tracing::warn!(error = %e, group, "保存订阅状态失败");
        }
    }

    fn updated_at(&self, group: &str) -> Option<i64> {
        self.store.feed_state_updated_at(group).ok().flatten()
    }
}

/// 运行时可整体替换的状态。
///
/// 所有组件放在一个结构里一次性替换，避免出现"新路由配旧 ACL"的中间态。
pub struct RuntimeState {
    pub router: Router,
    pub acl: Acl,
    pub pool: UpstreamPool,
    pub real_ip: RealIpConfig,
    /// 检测引擎
    pub engine: Engine,
    /// 应用/路由级策略（检测开关、限流、CIDR、方法限制等）
    pub policies: PolicySet,
    /// CC 防护运行时。热重载会重建，窗口计数随之清零
    pub limiter: Arc<RateLimiter>,
    /// 人机验证参数
    pub challenge: homewaf_config::ChallengeConfig,
    /// 检测白名单（误报豁免）
    pub whitelist: Vec<homewaf_detect::WhitelistRule>,
    /// 自动封禁参数（热重载时同步给 BanTable）
    pub auto_ban: homewaf_config::AutoBanConfig,
    /// IPv6 封禁聚合前缀
    pub ipv6_prefix: u8,
    /// 服务器配置（监听地址等）。变更需要重启，不参与热重载
    pub server: homewaf_config::ServerConfig,
    /// 仅用于日志展示；TLS 监听器在启动时绑定，证书变更需要重启
    pub tls: TlsConfig,
    /// 多证书 SNI 索引。热重载时重建，握手阶段按 SNI 实时读取
    pub tls_certs: crate::tls::CertMap,
    /// 订阅加载失败的组，用于状态展示
    pub feed_failures: Vec<(String, String)>,
    /// 规则包订阅状态，用于控制台展示
    pub rule_feeds: Vec<crate::rulefeed::RuleFeedStatus>,
    /// 自定义规则（兼容雷池格式）
    pub custom_rules: Vec<homewaf_config::CustomRule>,
    /// IP 组快照：组名 → 条目。供自定义规则的 `ip_group` 条件使用
    pub ip_groups: std::collections::HashMap<String, Vec<ipnet::IpNet>>,
    /// 网页防篡改基线，索引与 Router 的应用顺序一致
    pub tamper: Vec<crate::tamper::TamperBaseline>,
}

impl RuntimeState {
    /// 从配置构建。
    pub fn build(
        config: Config,
        allow_regex: bool,
        feed_state: &dyn FeedState,
        rule_cache: &dyn crate::rulefeed::RuleFeedCache,
        force_rule_feeds: bool,
    ) -> Result<Self, String> {
        let (feed_rules, feed_failures) =
            homewaf_acl::load_enabled_groups(&config.ip_groups, feed_state);
        // 订阅条目同时留一份按组索引的快照，供自定义规则的 `ip_group` 条件使用。
        // 规则 id 形如 `feed:{组名}:{序号}:{作用域}`，这里从 id 反解组名。
        let ip_groups = group_snapshot(&feed_rules);

        // 可信代理网段 = 手工填写 + 订阅组条目。云回源 IP 会变，靠订阅自动跟上。
        let mut real_ip = config.real_ip;
        // 预设先展开，再并入订阅组：preset 可能补上回环地址与专有头序。
        real_ip.apply_preset();
        real_ip.expand_secret();
        merge_trusted_groups(&mut real_ip, &config.ip_groups, &ip_groups);

        let mut rules = homewaf_acl::rules_from_config(&config.acl);
        rules.extend(feed_rules);
        let acl = Acl::build(&config.acl, &rules, homewaf_acl::now_unix());

        // 规则包要先于 Router 加载：applications 会被移进 Router。
        let rule_feeds = crate::rulefeed::load_rule_feeds(
            &config.rule_feeds,
            rule_cache,
            &crate::rulefeed::HttpRuleFeedFetcher,
            force_rule_feeds,
            homewaf_acl::now_unix(),
        );

        // 上游池要在 applications 被移进 Router 之前构建
        let pool = UpstreamPool::build(&config.applications);
        let policies = PolicySet::build(
            &config.applications,
            &config.protection,
            config.ratelimit,
            &config.limits,
        );
        // 文件模式没有证书库，只可能有全局单证书
        let tls_certs = crate::tls::build_cert_map(&[], &config.applications, &config.tls)?;
        let router = Router::build(config.applications, allow_regex).map_err(|e| e.to_string())?;

        // 订阅规则包 + 控制台里手工加的本地检测规则，走同一条匹配路径
        let mut extra_rules = rule_feeds.rules;
        extra_rules.extend(local_detect_metas(&config.custom_detect_rules));
        let engine = Engine::with_extra_rules(
            extra_rules,
            config.protection.observe_mode.enabled,
            config.protection.block_threshold.unwrap_or(50),
        )
        .map_err(|e| format!("规则包加载失败：{e}"))?;

        Ok(Self {
            router,
            acl,
            pool,
            real_ip,
            engine,
            policies,
            limiter: Arc::new(RateLimiter::new()),
            challenge: config.challenge,
            whitelist: Vec::new(),
            auto_ban: config.acl.auto_ban.clone(),
            ipv6_prefix: config.acl.ipv6_prefix_match,
            server: config.server,
            tls: config.tls,
            tls_certs,
            feed_failures,
            rule_feeds: rule_feeds.statuses,
            // 序号大的先匹配：新建的规则排在最前，和列表顺序一致
            custom_rules: {
                let mut rules = config.custom_rules;
                rules.sort_by_key(|r| std::cmp::Reverse(r.seq));
                rules
            },
            ip_groups,
            tamper: Vec::new(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.acl.rule_count()
    }

    pub fn detection_rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    pub fn upstream_count(&self) -> usize {
        self.pool.total_upstreams()
    }
}

/// 把控制台里的本地检测规则转成运行时规则。
///
/// 与订阅规则包共用 `RuleMeta`，因此命中后一样计入分数、一样能触发自动封禁。
/// 只转换启用且有正则的规则：非法正则在校验阶段就该被拦住，
/// 这里再挡一次，避免一条坏规则让整次重载失败。
fn local_detect_metas(rules: &[homewaf_config::DetectRule]) -> Vec<homewaf_detect::RuleMeta> {
    use homewaf_detect::{Action, Category, RuleMeta, RuleSource, Severity, Target};

    let mut out = Vec::new();
    for rule in rules {
        if !rule.enabled || rule.pattern.trim().is_empty() {
            continue;
        }
        let category = match rule.category.trim().to_ascii_lowercase().as_str() {
            "sqli" => Category::Sqli,
            "xss" => Category::Xss,
            "cmdi" => Category::CmdInjection,
            "traversal" => Category::PathTraversal,
            "ssrf" => Category::Ssrf,
            "xxe" => Category::Xxe,
            "ssti" => Category::Ssti,
            "nosql" => Category::Nosql,
            "ldap" => Category::LdapXpath,
            "webshell" => Category::Webshell,
            "scanner" => Category::Scanner,
            "deserialization" => Category::Deserialization,
            "crlf" => Category::Crlf,
            "upload" => Category::FileUpload,
            "bruteforce" => Category::Bruteforce,
            "leak" => Category::SensitiveLeak,
            _ => Category::Custom,
        };
        let severity = match rule.severity.trim().to_ascii_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "critical" => Severity::Critical,
            _ => Severity::High,
        };
        let targets: Vec<Target> = rule
            .targets
            .iter()
            .filter_map(|t| Target::parse(t))
            .collect();
        if targets.is_empty() {
            continue;
        }
        out.push(RuleMeta {
            id: rule.id.clone(),
            name: if rule.name.trim().is_empty() {
                rule.id.clone()
            } else {
                rule.name.clone()
            },
            category,
            severity,
            pattern: rule.pattern.clone(),
            targets,
            keywords: rule.keywords.iter().map(|k| k.to_lowercase()).collect(),
            action: if rule.action.trim().eq_ignore_ascii_case("log") {
                Action::Log
            } else {
                Action::Block
            },
            // 用户手写的黑名单：命中即拦，不等分数累积
            immediate: !rule.action.trim().eq_ignore_ascii_case("log"),
            shadow: false,
            source: RuleSource::Local,
        });
    }
    out
}

/// 从订阅生成的 ACL 规则反解出「组名 → 条目」。
///
/// 规则 id 的格式由 `homewaf_acl::feed::rules_from_group` 决定，
/// 这里依赖它而不是再拉一遍订阅——避免重载时重复联网。
fn group_snapshot(
    rules: &[homewaf_acl::AclRule],
) -> std::collections::HashMap<String, Vec<ipnet::IpNet>> {
    let mut map: std::collections::HashMap<String, Vec<ipnet::IpNet>> =
        std::collections::HashMap::new();
    for rule in rules {
        let Some(rest) = rule.id.strip_prefix("feed:") else {
            continue;
        };
        let Some((group, _)) = rest.split_once(':') else {
            continue;
        };
        map.entry(group.to_string()).or_default().push(rule.cidr);
    }
    map
}

/// 把订阅 IP 组里的网段并入可信代理列表。
///
/// 与手工填写的 `trusted_proxies` 取并集：云厂商回源节点网段会变，
/// 订阅更新后自动生效，不用改设置。
///
/// **只接受「放行」动作的组**。可信代理意味着信任该来源的转发头，
/// 若拿黑名单组当可信代理，被拉黑的攻击者只要伪造 `X-Forwarded-For`
/// 就能把客户端 IP 换成放行网段，直接绕过 ACL。
fn merge_trusted_groups(
    real_ip: &mut RealIpConfig,
    groups: &[homewaf_config::IpGroup],
    snapshot: &std::collections::HashMap<String, Vec<IpNet>>,
) {
    if real_ip.trusted_proxy_groups.is_empty() {
        return;
    }

    let mut added = 0usize;
    for name in &real_ip.trusted_proxy_groups {
        let Some(group) = groups.iter().find(|g| &g.name == name) else {
            tracing::warn!(group = %name, "真实 IP 可信代理组不存在，已忽略");
            continue;
        };
        if group.action != homewaf_config::IpGroupAction::Allow {
            tracing::warn!(
                group = %name,
                "可信代理组必须是「放行」动作，已忽略（否则可伪造客户端 IP 绕过 ACL）"
            );
            continue;
        }
        match snapshot.get(name) {
            Some(entries) if !entries.is_empty() => {
                added += entries.len();
                real_ip.trusted_proxies.extend(entries.iter().copied());
            }
            _ => tracing::warn!(group = %name, "可信代理组还没有条目（未拉到或已停用），本次跳过"),
        }
    }

    if added == 0 {
        return;
    }
    real_ip.trusted_proxies.sort();
    real_ip.trusted_proxies.dedup();
    if real_ip.trusted_proxies.len() > 512 {
        tracing::warn!(
            count = real_ip.trusted_proxies.len(),
            "可信代理网段超过 512 条，逐请求匹配的开销会上升"
        );
    }
}

/// 共享的运行时状态句柄。
pub type SharedState = Arc<ArcSwap<RuntimeState>>;

/// 把状态包成可热替换的共享句柄。
pub fn shared(state: RuntimeState) -> SharedState {
    Arc::new(ArcSwap::from_pointee(state))
}

/// 从数据库构建运行时状态。
///
/// **这是唯一的配置来源**——进程启动后不再读任何配置文件。
/// 引导参数（DB 路径、监听地址）来自命令行，其余全部在库里。
pub fn load_state_from_db(store: &Store, allow_regex: bool) -> Result<RuntimeState, String> {
    load_state_from_db_with(store, allow_regex, false)
}

/// 同上，但可以强制重新拉取全部规则包（控制台手动刷新）。
pub fn load_state_from_db_with(
    store: &Store,
    allow_regex: bool,
    force_rule_feeds: bool,
) -> Result<RuntimeState, String> {
    // 应用
    let applications = store
        .list_applications::<homewaf_config::Application>()
        .map_err(|e| format!("读取应用失败：{e}"))?;
    let app_ids: Vec<String> = applications.iter().map(|a| a.id.clone()).collect();
    // 证书映射需要在 applications 移进 Router 之前拿到应用列表
    let tls_applications = applications.clone();

    let mut config = Config {
        applications,
        ..Config::default()
    };

    // 全局设置。缺失时用 Config::default() 的值，不报错——
    // 首次启动的库是空的，应该用默认策略跑起来。
    macro_rules! load_setting {
        ($key:literal, $field:expr) => {
            if let Some(v) = store
                .get_setting($key)
                .map_err(|e| format!("读取设置 {} 失败：{e}", $key))?
            {
                $field = v;
            }
        };
    }
    load_setting!("server", config.server);
    load_setting!("tls", config.tls);
    load_setting!("protection", config.protection);
    load_setting!("real_ip", config.real_ip);
    load_setting!("acl", config.acl);
    load_setting!("limits", config.limits);
    load_setting!("ratelimit", config.ratelimit);
    load_setting!("challenge", config.challenge);
    load_setting!("logging", config.logging);
    load_setting!("storage", config.storage);
    load_setting!("rule_feeds", config.rule_feeds);
    load_setting!("custom_rules", config.custom_rules);
    load_setting!("custom_detect_rules", config.custom_detect_rules);

    // ACL 静态规则
    let rows = store
        .list_acl_rules()
        .map_err(|e| format!("读取 ACL 规则失败：{e}"))?;
    let mut rules = Vec::with_capacity(rows.len());
    for r in rows {
        let cidr = r
            .cidr
            .parse()
            .map_err(|e| format!("规则 {} 的网段 `{}` 非法：{e}", r.id, r.cidr))?;
        let action = match r.action.as_str() {
            "allow" => homewaf_config::AclRuleAction::Allow,
            "deny" => homewaf_config::AclRuleAction::Deny,
            other => return Err(format!("规则 {} 的动作 `{other}` 非法", r.id)),
        };
        rules.push(homewaf_config::AclRuleConfig {
            id: Some(r.id),
            cidr,
            action,
            scope: r.scope,
            expires_at: r.expires_at,
            note: r.note,
        });
    }
    config.acl.rules = rules;

    // IP 组订阅
    let groups = store
        .list_ip_groups()
        .map_err(|e| format!("读取订阅失败：{e}"))?;
    let mut ip_groups = Vec::with_capacity(groups.len());
    for g in groups {
        let mut group: homewaf_config::IpGroup = serde_json::from_str(&g.body)
            .map_err(|e| format!("订阅 {} 的数据损坏：{e}", g.name))?;
        group.enabled = g.enabled;
        ip_groups.push(group);
    }
    config.ip_groups = ip_groups;

    // 校验：库里存了非法配置时宁可启动失败，也不要带着坏配置跑
    let report = config.validate();
    if report.has_errors() {
        let detail = report
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.message))
            .collect::<Vec<_>>()
            .join("；");
        return Err(format!("数据库中的配置不合法：{detail}"));
    }

    let feed_state = SqliteFeedState::new(store);
    let rule_cache = crate::rulefeed::StoreRuleFeedCache::new(store);
    let mut state = RuntimeState::build(
        config,
        allow_regex,
        &feed_state,
        &rule_cache,
        force_rule_feeds,
    )?;

    // 白名单不在 Config 里，直接从库里读
    state.whitelist = store
        .list_whitelist()
        .map_err(|e| format!("读取白名单失败：{e}"))?
        .into_iter()
        .map(|w| homewaf_detect::WhitelistRule {
            id: w.id,
            app: w.app,
            path: w.path,
            rule_id: w.rule_id,
            note: w.note,
        })
        .collect();

    // 证书库。证书解析失败要让重载失败，避免带着旧证书静默运行
    let cert_rows = store
        .list_certificates()
        .map_err(|e| format!("读取证书失败：{e}"))?;
    state.tls_certs = crate::tls::build_cert_map(&cert_rows, &tls_applications, &state.tls)?;

    // 网页防篡改基线。按应用 id 归组后，按 Router 顺序对齐成 Vec。
    let mut by_app: std::collections::HashMap<String, Vec<(String, u64, String)>> =
        std::collections::HashMap::new();
    for (app_id, path, size, digest) in store
        .all_tamper_baselines()
        .map_err(|e| format!("读取防篡改基线失败：{e}"))?
    {
        by_app.entry(app_id).or_default().push((path, size, digest));
    }
    state.tamper = app_ids
        .iter()
        .map(|id| {
            by_app
                .get(id)
                .map(|rows| crate::tamper::TamperBaseline::from_rows(rows))
                .unwrap_or_default()
        })
        .collect();

    Ok(state)
}

/// 从文件加载并构建新状态。校验有错误时返回 Err，调用方应保留旧状态。
pub fn load_state(
    path: &Path,
    allow_regex: bool,
    feed_state: &dyn FeedState,
) -> Result<RuntimeState, String> {
    let config = homewaf_config::load(path).map_err(|e| format!("读取配置失败：{e}"))?;

    let report = config.validate();
    if report.has_errors() {
        let detail = report
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.message))
            .collect::<Vec<_>>()
            .join("；");
        return Err(format!("配置校验失败：{detail}"));
    }

    // 文件模式没有缓存，每次重载都重新拉取；否则改配置后订阅规则不会更新
    RuntimeState::build(
        config,
        allow_regex,
        feed_state,
        &crate::rulefeed::NoRuleFeedCache,
        true,
    )
}

/// 打开持久化层。失败时降级为纯内存模式，**不阻塞启动**。
///
/// WAF 的首要职责是转发流量，不能因为磁盘满了就起不来。
pub fn open_store(config: &homewaf_config::StorageConfig) -> Option<Arc<Store>> {
    if config.path.trim().is_empty() {
        tracing::warn!("storage.path 为空，使用纯内存模式（重启后封禁与事件丢失）");
        return None;
    }

    let path = Path::new(&config.path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    match Store::open(path) {
        Ok(s) => {
            tracing::info!(path = %config.path, "数据库已打开");
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                path = %config.path,
                "打开数据库失败，降级为纯内存模式"
            );
            None
        }
    }
}

/// 启动后台监视线程。
///
/// 重载成功后会同步更新 `bans` 的参数，但**保留已有封禁记录**——
/// 改配置不应该把攻击者放出来。
pub fn spawn_watcher(
    state: SharedState,
    bans: Arc<homewaf_acl::BanTable>,
    store: Option<Arc<Store>>,
    path: PathBuf,
    allow_regex: bool,
    interval: Duration,
) {
    std::thread::Builder::new()
        .name("homewaf-config-watcher".to_string())
        .spawn(move || {
            let mut last = mtime(&path);
            loop {
                std::thread::sleep(interval);
                let current = mtime(&path);
                if current == last {
                    continue;
                }
                last = current;

                tracing::info!(path = %path.display(), "检测到配置变化，开始重载");

                let no_state = homewaf_acl::NoFeedState;
                let sqlite_state;
                let feed_state: &dyn FeedState = match store.as_deref() {
                    Some(s) => {
                        sqlite_state = SqliteFeedState::new(s);
                        &sqlite_state
                    }
                    None => &no_state,
                };

                match load_state(&path, allow_regex, feed_state) {
                    Ok(new_state) => {
                        let rules = new_state.rule_count();
                        let upstreams = new_state.upstream_count();
                        let apps = new_state.router.len();

                        // 先同步封禁参数，再替换状态
                        bans.update_settings(&new_state.auto_ban, new_state.ipv6_prefix);

                        state.store(Arc::new(new_state));
                        tracing::info!(apps, rules, upstreams, "配置重载成功，已生效");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "配置重载失败，继续使用旧配置"
                        );
                    }
                }
            }
        })
        .expect("启动配置监视线程失败");
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtime_missing_file_is_none() {
        assert!(mtime(Path::new("/nonexistent/homewaf-test.yaml")).is_none());
    }

    #[test]
    fn load_state_rejects_invalid_config() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("homewaf-reload-bad-{}.yaml", std::process::id()));
        std::fs::write(
            &path,
            r#"
applications:
  - id: BadId
    name: bad
    domains: { primary: "bad domain" }
    upstreams: [{ addr: 1.2.3.4, port: 80 }]
"#,
        )
        .unwrap();

        let result = load_state(&path, false, &homewaf_acl::NoFeedState);
        assert!(result.is_err(), "非法配置必须拒绝");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_state_accepts_valid_config() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("homewaf-reload-ok-{}.yaml", std::process::id()));
        std::fs::write(
            &path,
            r#"
applications:
  - id: ok
    name: ok
    domains: { primary: "ok.home.lan" }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#,
        )
        .unwrap();

        let state = load_state(&path, false, &homewaf_acl::NoFeedState).expect("合法配置应通过");
        assert_eq!(state.router.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn feed_state_roundtrip_through_sqlite() {
        // 验证"上次条目"能真正跨进程持久化——这是变更幅度护栏的前提
        let store = Store::open_memory().unwrap();
        let state = SqliteFeedState::new(&store);

        assert!(state.previous("g").is_empty(), "首次应为空");

        let entries: Vec<IpNet> =
            vec!["1.2.3.0/24".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        state.remember("g", &entries);

        let loaded = state.previous("g");
        assert_eq!(loaded, entries, "读回应与写入一致");
    }

    #[test]
    fn feed_state_isolated_between_groups() {
        let store = Store::open_memory().unwrap();
        let state = SqliteFeedState::new(&store);

        state.remember("a", &["1.1.1.0/24".parse().unwrap()]);
        state.remember("b", &["2.2.2.0/24".parse().unwrap()]);

        assert_eq!(state.previous("a").len(), 1);
        assert_eq!(
            state.previous("a")[0],
            "1.1.1.0/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            state.previous("b")[0],
            "2.2.2.0/24".parse::<IpNet>().unwrap()
        );
    }

    // ============================================================
    // 可信代理由订阅组补充
    // ============================================================

    fn real_ip_cfg(groups: &[&str], manual: &[&str]) -> RealIpConfig {
        RealIpConfig {
            enabled: true,
            trusted_proxies: manual.iter().map(|s| s.parse().unwrap()).collect(),
            trusted_proxy_groups: groups.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn ip_group(name: &str, action: homewaf_config::IpGroupAction) -> homewaf_config::IpGroup {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "source": { "url": "https://example.com/list" },
            "action": action,
        }))
        .unwrap()
    }

    fn snapshot(pairs: &[(&str, &[&str])]) -> std::collections::HashMap<String, Vec<IpNet>> {
        pairs
            .iter()
            .map(|(name, nets)| {
                (
                    name.to_string(),
                    nets.iter().map(|n| n.parse().unwrap()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn allow_group_merged_into_trusted_proxies() {
        let groups = vec![ip_group("esa", homewaf_config::IpGroupAction::Allow)];
        let snap = snapshot(&[("esa", &["2408:8752:0:5:2::/64", "42.48.120.0/24"])]);
        let mut cfg = real_ip_cfg(&["esa"], &["10.0.0.0/8"]);

        merge_trusted_groups(&mut cfg, &groups, &snap);

        assert_eq!(cfg.trusted_proxies.len(), 3, "手工 + 订阅取并集");
        assert!(cfg
            .trusted_proxies
            .contains(&"2408:8752:0:5:2::/64".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn block_group_is_never_trusted() {
        // 黑名单组当可信代理等于允许这些 IP 伪造 XFF 绕过 ACL
        let groups = vec![ip_group("bad", homewaf_config::IpGroupAction::Block)];
        let snap = snapshot(&[("bad", &["1.2.3.0/24"])]);
        let mut cfg = real_ip_cfg(&["bad"], &[]);

        merge_trusted_groups(&mut cfg, &groups, &snap);

        assert!(cfg.trusted_proxies.is_empty(), "黑名单组必须被忽略");
    }

    #[test]
    fn missing_or_empty_group_is_ignored() {
        let groups = vec![ip_group("esa", homewaf_config::IpGroupAction::Allow)];
        let mut cfg = real_ip_cfg(&["esa", "typo"], &[]);

        // esa 还没拉到条目；typo 根本不存在 —— 都不应 panic，也不应改动配置
        merge_trusted_groups(&mut cfg, &groups, &snapshot(&[]));

        assert!(cfg.trusted_proxies.is_empty());
    }

    #[test]
    fn duplicate_nets_are_deduped() {
        let groups = vec![ip_group("esa", homewaf_config::IpGroupAction::Allow)];
        let snap = snapshot(&[("esa", &["42.48.120.0/24", "42.48.120.0/24"])]);
        let mut cfg = real_ip_cfg(&["esa"], &["42.48.120.0/24"]);

        merge_trusted_groups(&mut cfg, &groups, &snap);

        assert_eq!(cfg.trusted_proxies.len(), 1);
    }
}
