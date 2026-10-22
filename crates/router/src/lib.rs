//! HomeWAF 路由：把请求的 Host 与 Path 映射到应用与路由。
//!
//! ```no_run
//! use homewaf_router::Router;
//!
//! let config = homewaf_config::load("config.yaml").unwrap();
//! let router = Router::build(config.applications, false).unwrap();
//! if let Some(hit) = router.resolve("nas.home.lan", 443, "/jellyfin/web") {
//!     println!("应用索引 {} → 路由 {:?}", hit.app_index, hit.route_index);
//! }
//! ```

pub mod domain;
pub mod path;
pub mod rewrite;

pub use domain::{normalize_host, DomainMatcher};
pub use path::{normalize_path, MatchKind, PathMatcher};

use std::sync::Arc;

use homewaf_config::Application;

/// 构建路由表时的错误。
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("应用 `{app}` 的域名 `{domain}` 非法：{reason}")]
    InvalidDomain {
        app: String,
        domain: String,
        reason: String,
    },

    #[error("域名/路径正则 `{pattern}` 不是合法正则：{source}")]
    InvalidRegex {
        app: String,
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("未启用正则匹配，但使用了 `{pattern}`（应用 `{app}`）")]
    RegexNotAllowed { app: String, pattern: String },

    #[error("路由路径 `{path}` 非法：{reason}")]
    InvalidPath { path: String, reason: String },
}

/// 一次路由解析的结果。不持有引用，可安全跨 await 传递。
#[derive(Debug, Clone)]
pub struct Resolved {
    /// 应用在配置中的索引
    pub app_index: usize,
    /// 命中的路由索引；`None` 表示未匹配任何路由，应使用应用默认上游
    pub route_index: Option<usize>,
    pub match_kind: Option<MatchKind>,
    /// 规范化后的路径。**转发时必须使用它**，不能再用原始路径
    pub normalized_path: String,
}

/// 组合域名匹配与路径匹配。
///
/// 内部用 `Arc` 拥有应用列表，因此可以放进 `'static` 的代理对象里。
#[derive(Debug, Clone)]
pub struct Router {
    apps: Arc<Vec<Application>>,
    domains: DomainMatcher,
    /// 与应用索引对齐
    paths: Vec<PathMatcher>,
}

impl Router {
    /// 构建路由表。
    ///
    /// `allow_regex` 同时控制域名与路径的正则匹配（默认关闭）。
    pub fn build(apps: Vec<Application>, allow_regex: bool) -> Result<Self, BuildError> {
        let domains = DomainMatcher::build(&apps, allow_regex)?;

        let mut paths = Vec::with_capacity(apps.len());
        for app in &apps {
            paths.push(PathMatcher::build(&app.routes, allow_regex)?);
        }

        Ok(Self {
            apps: Arc::new(apps),
            domains,
            paths,
        })
    }

    /// 解析请求。
    ///
    /// `port` 是请求实际到达的端口，用于匹配应用声明的 `listen_ports`。
    /// 应用没声明端口时接受任意端口。
    pub fn resolve(&self, host: &str, port: u16, raw_path: &str) -> Option<Resolved> {
        self.resolve_normalized(host, port, normalize_path(raw_path))
    }

    /// 用已规范化的路径解析。
    pub fn resolve_normalized(
        &self,
        host: &str,
        port: u16,
        normalized_path: String,
    ) -> Option<Resolved> {
        let app_index = self.domains.lookup(host)?;

        // 应用声明了端口就必须匹配；没声明则接受任意端口
        let app = self.apps.get(app_index)?;
        if !app.listen_ports.is_empty() && !app.listen_ports.contains(&port) {
            return None;
        }

        let (route_index, match_kind) = match self.paths[app_index].lookup(&normalized_path) {
            Some((i, kind)) => (Some(i), Some(kind)),
            None => (None, None),
        };

        Some(Resolved {
            app_index,
            route_index,
            match_kind,
            normalized_path,
        })
    }

    /// 按索引取应用。
    pub fn app(&self, index: usize) -> Option<&Application> {
        self.apps.get(index)
    }

    /// 全部应用。
    pub fn apps(&self) -> &[Application] {
        &self.apps
    }

    /// 取某个解析结果对应的路由。
    pub fn route_of(&self, hit: &Resolved) -> Option<&homewaf_config::Route> {
        let app = self.apps.get(hit.app_index)?;
        hit.route_index.map(|i| &app.routes[i])
    }

    /// 域名匹配器（供调试与统计）。
    pub fn domains(&self) -> &DomainMatcher {
        &self.domains
    }

    /// 指定应用的路径匹配器。
    pub fn paths_of(&self, app_index: usize) -> Option<&PathMatcher> {
        self.paths.get(app_index)
    }

    /// 应用数量。
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{Domains, LbConfig, Policy, Route, Scheme, TlsModeConfig, Upstream};

    fn upstream() -> Upstream {
        Upstream {
            addr: "192.168.1.5".to_string(),
            port: Some(8080),
            scheme: Scheme::Http,
            weight: 1,
            backup: false,
            max_conns: 128,
            tls: None,
        }
    }

    fn app(id: &str, domain: &str, routes: Vec<Route>) -> Application {
        Application {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            domains: Domains {
                primary: domain.to_string(),
                aliases: vec![],
            },
            listen_ports: Vec::new(),
            upstreams: vec![upstream()],
            routes,
            tls: TlsModeConfig::default(),
            policy: Policy::default(),
            lb: LbConfig::default(),
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

    fn route(path: &str) -> Route {
        Route {
            path: path.to_string(),
            upstreams: None,
            rewrite: None,
            policy: None,
            allow_methods: None,
            cache: None,
        }
    }

    #[test]
    fn resolves_app_and_route() {
        let router = Router::build(
            vec![app(
                "nas",
                "nas.home.lan",
                vec![route("/"), route("/jellyfin")],
            )],
            false,
        )
        .unwrap();

        let hit = router.resolve("nas.home.lan", 443, "/jellyfin/web").unwrap();
        assert_eq!(hit.app_index, 0);
        assert_eq!(hit.route_index, Some(1));
        assert_eq!(hit.normalized_path, "/jellyfin/web");
        assert_eq!(router.route_of(&hit).unwrap().path, "/jellyfin");
    }

    #[test]
    fn unknown_host_returns_none() {
        let router =
            Router::build(vec![app("nas", "nas.home.lan", vec![route("/")])], false).unwrap();
        assert!(router.resolve("other.home.lan", 443, "/").is_none());
    }

    #[test]
    fn app_without_routes_uses_default_upstream() {
        let router = Router::build(vec![app("nas", "nas.home.lan", vec![])], false).unwrap();
        let hit = router.resolve("nas.home.lan", 443, "/anything").unwrap();
        assert_eq!(hit.route_index, None);
        assert!(router.route_of(&hit).is_none());
    }

    #[test]
    fn normalized_path_is_exposed_for_forwarding() {
        let router = Router::build(
            vec![app("nas", "nas.home.lan", vec![route("^~ /admin")])],
            false,
        )
        .unwrap();
        let hit = router.resolve("nas.home.lan", 443, "//api/../admin/x").unwrap();
        assert_eq!(hit.normalized_path, "/admin/x");
        assert_eq!(hit.match_kind, Some(MatchKind::PrefixNoRegex));
    }

    #[test]
    fn disabled_app_not_routable() {
        let mut a = app("nas", "nas.home.lan", vec![route("/")]);
        a.enabled = false;
        let router = Router::build(vec![a], false).unwrap();
        assert!(router.resolve("nas.home.lan", 443, "/").is_none());
    }

    #[test]
    fn router_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Router>();
    }
}
