//! HomeWAF 代理层。
//!
//! 基于 Pingora 的反向代理，负责：
//! - 监听与 TLS 终结（TLS 待接入）
//! - 用 [`homewaf_router::Router`] 决定上游
//! - 还原真实客户端 IP 并注入转发头
//! - 请求/响应生命周期钩子（后续接入检测引擎）

pub mod headers;
pub mod realip;
pub mod reload;
mod server;
pub mod upstream;

pub use headers::ForwardedCtx;
pub use realip::{ClientIp, IpSource};
pub use reload::{
    load_state, load_state_from_db, open_store, shared, spawn_watcher, RuntimeState, SharedState,
    SqliteFeedState,
};
pub use server::{run, ProxySettings, WafProxy};
pub use upstream::{Selection, UpstreamPool};
