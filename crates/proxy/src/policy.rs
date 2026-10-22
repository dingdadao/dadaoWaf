//! 三层策略解析：route > application > global。
//!
//! 只解析一次，随 [`RuntimeState`](crate::RuntimeState) 一起热替换。
//! 请求阶段拿到的是一份预计算结果，不做任何配置合并。
//!
//! 合并粒度是"逐字段"而不是整块替换：路由只想覆盖 `max_body_size` 时，
//! 不应该把应用的检测开关和限流阈值一起丢掉。

use homewaf_config::{
    Application, LimitsConfig, Policy, Preset, ProtectionConfig, RateLimitAction,
    RateLimitConfig, Toggle,
};
use homewaf_detect::{Category, CategoryMode, ScanPolicy};
use ipnet::IpNet;

/// 一次请求最终生效的策略。
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    pub scan: ScanPolicy,
    /// `protection.cc_attack` 解析出的 CC 档位
    pub cc_mode: CategoryMode,
    pub ratelimit: RateLimitConfig,
    /// 请求体检测上限（字节）
    pub max_body_size: u64,
    pub allow_cidr: Vec<IpNet>,
    pub deny_cidr: Vec<IpNet>,
    /// 路由级允许的方法；`None` 表示不限制
    pub allow_methods: Option<Vec<String>>,
    pub require_challenge: bool,
}

impl EffectivePolicy {
    /// CC 是否实际生效（总开关 + 分类开关）。
    pub fn cc_active(&self) -> bool {
        self.ratelimit.enabled && self.cc_mode != CategoryMode::Off
    }

    /// 超限后的处置。`None` 表示不限流。
    ///
    /// `protection.cc_attack: monitor` 可以单独把某个应用切成只记录，
    /// 不用改全局的限流动作。
    pub fn limit_action(&self) -> Option<RateLimitAction> {
        if !self.cc_active() {
            return None;
        }
        match self.cc_mode {
            CategoryMode::Off => None,
            CategoryMode::Monitor => Some(RateLimitAction::Log),
            CategoryMode::Block => Some(self.ratelimit.action),
        }
    }
}

/// 全部应用与路由的策略表，索引与 [`Router`](homewaf_router::Router) 对齐。
#[derive(Debug, Clone)]
pub struct PolicySet {
    global: EffectivePolicy,
    apps: Vec<EffectivePolicy>,
    routes: Vec<Vec<EffectivePolicy>>,
}

impl PolicySet {
    pub fn build(
        apps: &[Application],
        global_protection: &ProtectionConfig,
        global_ratelimit: RateLimitConfig,
        limits: &LimitsConfig,
    ) -> Self {
        let global = resolve(global_protection, limits, None, &[], global_ratelimit);

        let mut app_policies = Vec::with_capacity(apps.len());
        let mut route_policies = Vec::with_capacity(apps.len());

        for app in apps {
            let app_layer = [&app.policy];
            app_policies.push(apply_features(
                resolve(
                    global_protection,
                    limits,
                    None,
                    &app_layer,
                    global_ratelimit,
                ),
                &app.features,
            ));

            let mut routes = Vec::with_capacity(app.routes.len());
            for route in &app.routes {
                routes.push(apply_features(
                    resolve(
                        global_protection,
                        limits,
                        Some(route),
                        &app_layer,
                        global_ratelimit,
                    ),
                    &app.features,
                ));
            }
            route_policies.push(routes);
        }

        Self {
            global,
            apps: app_policies,
            routes: route_policies,
        }
    }

    pub fn global(&self) -> &EffectivePolicy {
        &self.global
    }

    pub fn app(&self, app_index: usize) -> Option<&EffectivePolicy> {
        self.apps.get(app_index)
    }

    /// 命中的路由策略；未命中路由时回退到应用默认策略。
    pub fn resolve(&self, app_index: usize, route_index: Option<usize>) -> Option<&EffectivePolicy> {
        let app = self.apps.get(app_index)?;
        match route_index {
            Some(i) => self
                .routes
                .get(app_index)
                .and_then(|routes| routes.get(i))
                .or(Some(app)),
            None => Some(app),
        }
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }
}

/// 应用级快捷开关：关闭攻击防护即关闭全部检测分类，
/// 关闭 CC 防护即忽略限流。只有显式关闭才生效。
fn apply_features(
    mut policy: EffectivePolicy,
    features: &homewaf_config::AppFeatures,
) -> EffectivePolicy {
    if !features.attack {
        for category in Category::ALL {
            policy.scan.set(category, CategoryMode::Off);
        }
    }
    if !features.cc {
        policy.cc_mode = CategoryMode::Off;
    }
    policy
}

fn resolve(
    global_protection: &ProtectionConfig,
    limits: &LimitsConfig,
    route: Option<&homewaf_config::Route>,
    app_layers: &[&Policy],
    global_ratelimit: RateLimitConfig,
) -> EffectivePolicy {
    let mut layers: Vec<&Policy> = app_layers.to_vec();
    if let Some(route) = route {
        if let Some(p) = &route.policy {
            layers.push(p);
        }
    }

    let (scan, cc_mode) = build_scan(global_protection, &layers);

    let mut ratelimit = global_ratelimit;
    let mut allow_cidr = Vec::new();
    let mut deny_cidr = Vec::new();
    let mut max_body_size = limits.max_body_size.as_bytes();
    let mut require_challenge = false;

    for p in &layers {
        if let Some(r) = p.ratelimit {
            ratelimit = r;
        }
        if let Some(v) = &p.allow_cidr {
            allow_cidr = v.clone();
        }
        if let Some(v) = &p.deny_cidr {
            deny_cidr = v.clone();
        }
        if let Some(s) = p.max_body_size {
            max_body_size = s.as_bytes();
        }
        if let Some(c) = p.require_challenge {
            require_challenge = c;
        }
    }

    let allow_methods = route
        .and_then(|r| r.allow_methods.as_ref())
        .map(|methods| methods.iter().map(|m| m.to_ascii_uppercase()).collect());

    EffectivePolicy {
        scan,
        cc_mode,
        ratelimit,
        max_body_size,
        allow_cidr,
        deny_cidr,
        allow_methods,
        require_challenge,
    }
}

fn build_scan(global: &ProtectionConfig, layers: &[&Policy]) -> (ScanPolicy, CategoryMode) {
    let mut prot = global.clone();
    let mut observe = global.observe_mode.enabled;

    for p in layers {
        if let Some(op) = &p.protection {
            overlay_protection(&mut prot, op);
        }
        if let Some(o) = &p.observe_mode {
            observe = o.enabled;
        }
        if let Some(preset) = p.preset {
            prot.preset = Some(preset);
        }
        if let Some(threshold) = p.block_threshold {
            prot.block_threshold = Some(threshold);
        }
    }

    let threshold = prot
        .block_threshold
        .or(prot.preset.map(Preset::block_threshold))
        .unwrap_or(50);

    let mut scan = ScanPolicy::all_block(threshold);
    scan.observe = observe;
    for category in Category::ALL {
        if let Some(toggle) = toggle_for(&prot, category) {
            scan.set(category, mode_of(toggle));
        }
    }

    let cc_mode = prot.cc_attack.map(mode_of).unwrap_or(CategoryMode::Block);
    (scan, cc_mode)
}

/// 只覆盖显式给出的字段。`observe_mode` 不在这里合并——
/// 应用/路由请使用 `Policy.observe_mode`，它的 `Option` 能区分"没写"和"关掉"。
fn overlay_protection(base: &mut ProtectionConfig, over: &ProtectionConfig) {
    if over.preset.is_some() {
        base.preset = over.preset;
    }
    if over.block_threshold.is_some() {
        base.block_threshold = over.block_threshold;
    }
    if over.fail_policy.is_some() {
        base.fail_policy = over.fail_policy;
    }

    macro_rules! overlay {
        ($($field:ident),* $(,)?) => {
            $(if over.$field.is_some() { base.$field = over.$field; })*
        };
    }
    overlay!(
        sqli,
        xss,
        cmdi,
        path_traversal,
        xxe,
        ssrf,
        ssti,
        ldap_xpath,
        nosql,
        crlf,
        deserialization,
        file_upload,
        webshell,
        scanner,
        bruteforce,
        cc_attack,
        sensitive_leak,
    );
}

fn mode_of(toggle: Toggle) -> CategoryMode {
    match toggle {
        Toggle::Off => CategoryMode::Off,
        Toggle::Monitor => CategoryMode::Monitor,
        Toggle::Block => CategoryMode::Block,
    }
}

fn toggle_for(p: &ProtectionConfig, category: Category) -> Option<Toggle> {
    match category {
        Category::Sqli => p.sqli,
        Category::Xss => p.xss,
        Category::CmdInjection => p.cmdi,
        Category::PathTraversal => p.path_traversal,
        Category::Ssrf => p.ssrf,
        Category::Xxe => p.xxe,
        Category::Ssti => p.ssti,
        Category::Nosql => p.nosql,
        Category::LdapXpath => p.ldap_xpath,
        Category::Webshell => p.webshell,
        Category::Scanner => p.scanner,
        Category::Deserialization => p.deserialization,
        Category::Crlf => p.crlf,
        Category::FileUpload => p.file_upload,
        Category::Bruteforce => p.bruteforce,
        Category::SensitiveLeak => p.sensitive_leak,
        Category::Custom => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{
        Domains, Policy, Route, Size, TlsModeConfig, Upstream,
    };

    fn upstream() -> Upstream {
        Upstream {
            addr: "192.168.1.5".to_string(),
            port: Some(8080),
            scheme: homewaf_config::Scheme::Http,
            weight: 1,
            backup: false,
            max_conns: 128,
            tls: None,
        }
    }

    fn route(path: &str, policy: Option<Policy>) -> Route {
        Route {
            path: path.to_string(),
            upstreams: None,
            rewrite: None,
            policy,
            allow_methods: None,
            cache: None,
        }
    }

    fn app(id: &str, policy: Policy, routes: Vec<Route>) -> Application {
        Application {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            domains: Domains {
                primary: format!("{id}.home.lan"),
                aliases: vec![],
            },
            listen_ports: Vec::new(),
            upstreams: vec![upstream()],
            routes,
            tls: TlsModeConfig::default(),
            policy,
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

    fn set() -> PolicySet {
        PolicySet::build(
            &[app("nas", Policy::default(), vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        )
    }

    #[test]
    fn default_allows_every_category() {
        let set = set();
        let p = set.app(0).unwrap();
        assert_eq!(p.scan.mode(Category::Sqli), CategoryMode::Block);
        assert_eq!(p.scan.block_threshold, 50);
        assert!(!p.scan.observe);
        assert!(!p.cc_active(), "CC 默认关闭");
    }

    #[test]
    fn app_toggle_off_disables_category() {
        let policy = Policy {
            protection: Some(ProtectionConfig {
                sqli: Some(Toggle::Off),
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", policy, vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        let p = set.app(0).unwrap();
        assert_eq!(p.scan.mode(Category::Sqli), CategoryMode::Off);
        assert_eq!(p.scan.mode(Category::Xss), CategoryMode::Block, "其他分类继承全局");
    }

    #[test]
    fn route_policy_overrides_app() {
        let app_policy = Policy {
            protection: Some(ProtectionConfig {
                sqli: Some(Toggle::Off),
                ..Default::default()
            }),
            ..Default::default()
        };
        let route_policy = Policy {
            protection: Some(ProtectionConfig {
                sqli: Some(Toggle::Block),
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app(
                "nas",
                app_policy,
                vec![route("/api", Some(route_policy))],
            )],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );

        assert_eq!(set.app(0).unwrap().scan.mode(Category::Sqli), CategoryMode::Off);
        assert_eq!(
            set.resolve(0, Some(0)).unwrap().scan.mode(Category::Sqli),
            CategoryMode::Block,
            "路由级应覆盖应用级"
        );
    }

    #[test]
    fn threshold_and_observe_resolution() {
        let app_policy = Policy {
            block_threshold: Some(90),
            observe_mode: Some(homewaf_config::ObserveMode {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", app_policy, vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        let p = set.app(0).unwrap();
        assert_eq!(p.scan.block_threshold, 90);
        assert!(p.scan.observe);
    }

    #[test]
    fn preset_sets_threshold_when_not_explicit() {
        let global = ProtectionConfig {
            preset: Some(Preset::Strict),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", Policy::default(), vec![])],
            &global,
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        assert_eq!(set.app(0).unwrap().scan.block_threshold, 10);
    }

    #[test]
    fn ratelimit_override_is_whole_config() {
        let route_policy = Policy {
            ratelimit: Some(RateLimitConfig {
                enabled: true,
                per_ip_qps: 5,
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app(
                "nas",
                Policy::default(),
                vec![route("/api", Some(route_policy))],
            )],
            &ProtectionConfig::default(),
            RateLimitConfig {
                enabled: false,
                ..Default::default()
            },
            &LimitsConfig::default(),
        );
        let p = set.resolve(0, Some(0)).unwrap();
        assert!(p.cc_active());
        assert_eq!(p.ratelimit.per_ip_qps, 5);

        let app_level = set.app(0).unwrap();
        assert!(!app_level.cc_active(), "应用级没有覆盖，沿用全局关闭");
    }

    #[test]
    fn cc_monitor_forces_log_action() {
        let policy = Policy {
            protection: Some(ProtectionConfig {
                cc_attack: Some(Toggle::Monitor),
                ..Default::default()
            }),
            ratelimit: Some(RateLimitConfig {
                enabled: true,
                action: RateLimitAction::Block,
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", policy, vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        let p = set.app(0).unwrap();
        assert_eq!(p.limit_action(), Some(RateLimitAction::Log));
    }

    #[test]
    fn cc_off_switch_disables_even_if_enabled() {
        let policy = Policy {
            protection: Some(ProtectionConfig {
                cc_attack: Some(Toggle::Off),
                ..Default::default()
            }),
            ratelimit: Some(RateLimitConfig {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", policy, vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        assert!(!set.app(0).unwrap().cc_active());
    }

    #[test]
    fn cidr_and_body_size_override() {
        let policy = Policy {
            max_body_size: Some(Size::from_bytes(1024)),
            deny_cidr: Some(vec!["10.0.0.0/8".parse().unwrap()]),
            ..Default::default()
        };
        let set = PolicySet::build(
            &[app("nas", policy, vec![])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        let p = set.app(0).unwrap();
        assert_eq!(p.max_body_size, 1024);
        assert_eq!(p.deny_cidr.len(), 1);
    }

    #[test]
    fn route_allow_methods_uppercased() {
        let mut r = route("/api", None);
        r.allow_methods = Some(vec!["get".to_string(), "Post".to_string()]);
        let set = PolicySet::build(
            &[app("nas", Policy::default(), vec![r])],
            &ProtectionConfig::default(),
            RateLimitConfig::default(),
            &LimitsConfig::default(),
        );
        assert_eq!(
            set.resolve(0, Some(0)).unwrap().allow_methods.as_deref(),
            Some(["GET".to_string(), "POST".to_string()].as_slice())
        );
        assert!(set.resolve(0, None).unwrap().allow_methods.is_none());
    }
}
