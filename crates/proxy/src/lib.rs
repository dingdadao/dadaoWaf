//! HomeWAF 代理层。
//!
//! 基于 Pingora 的反向代理，负责：
//! - 监听与 TLS 终结（TLS 待接入）
//! - 用 [`homewaf_router::Router`] 决定上游
//! - 还原真实客户端 IP 并注入转发头
//! - 请求/响应生命周期钩子（后续接入检测引擎）

pub mod challenge;
pub mod custom_rule;
pub mod headers;
pub mod metrics;
pub mod policy;
pub mod realip;
pub mod reload;
pub mod rulefeed;
mod server;
pub mod tamper;
pub mod upstream;

pub use challenge::{ChallengeService, CHALLENGE_PATH, COOKIE_NAME};
pub use custom_rule::{evaluate as evaluate_custom_rules, CustomDecision, RuleRequest};
pub use headers::ForwardedCtx;
pub use metrics::{
    BucketSnapshot, Count as TrafficCount, DashboardData as TrafficDashboard, Point as TrafficPoint,
    TrafficMetrics, TrafficSample,
};
pub use policy::{EffectivePolicy, PolicySet};
pub use realip::{ClientIp, IpSource};
pub use reload::{
    load_state, load_state_from_db, load_state_from_db_with, open_store, shared, spawn_watcher,
    RuntimeState, SharedState, SqliteFeedState,
};
pub use rulefeed::{
    load_rule_feed_configs, rule_feeds_due, HttpRuleFeedFetcher, NoRuleFeedCache, RuleFeedCache,
    RuleFeedLoad, RuleFeedStatus, StoreRuleFeedCache, RULE_FEEDS_SETTING,
};
pub use server::{run, ProxySettings, WafProxy};
pub use upstream::{Selection, UpstreamPool};
