//! 日志初始化。
//!
//! 按类型分成四个目录，各写各的：
//!
//! ```text
//! data/logs/
//! ├── access/2026-10-22.log      每个请求一行（谁、访问什么、结果）
//! ├── upstream/2026-10-22.log    反代细节（上游、耗时、重试、失败原因）
//! ├── security/2026-10-22.log    安全事件（检测命中、封禁、ACL 拒绝）
//! └── error/2026-10-22.log       所有 WARN 及以上
//! ```
//!
//! **写入是异步的**：每条日志先丢进内存队列，由独立的后台线程批量落盘。
//! 请求线程不会因为磁盘 IO 被卡住——这一点很重要，日志不该成为代理的瓶颈。
//!
//! 代价是进程被强杀（kill -9）时队列里的日志可能丢。正常退出（SIGTERM）
//! 时 guard 会 flush，不丢。

use std::path::Path;

use homewaf_config::LoggingConfig;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{filter_fn, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// 日志队列的内存上限。超过后丢弃新日志（lossy），不阻塞请求。
const QUEUE_CAPACITY: usize = 64 * 1024;

/// 持有后台写线程的句柄。**必须活到进程结束**，drop 时会 flush 剩余日志。
///
/// 字段本身不会被读取——它的作用纯粹是「别被 drop」，所以标 allow(dead_code)。
pub struct LogGuards(#[allow(dead_code)] Vec<WorkerGuard>);

/// 初始化日志。
pub fn init(config: &LoggingConfig) -> Option<LogGuards> {
    let level = match config.level {
        homewaf_config::LogLevel::Trace => LevelFilter::TRACE,
        homewaf_config::LogLevel::Debug => LevelFilter::DEBUG,
        homewaf_config::LogLevel::Info => LevelFilter::INFO,
        homewaf_config::LogLevel::Warn => LevelFilter::WARN,
        homewaf_config::LogLevel::Error => LevelFilter::ERROR,
    };

    // 控制台始终输出，方便前台调试；环境变量可覆盖级别
    let console = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.to_string())),
        );

    let dir = config.dir.trim();
    if dir.is_empty() {
        tracing_subscriber::registry().with(console).init();
        return None;
    }

    let root = Path::new(dir);
    for sub in ["access", "upstream", "security", "error"] {
        if let Err(e) = std::fs::create_dir_all(root.join(sub)) {
            eprintln!("创建日志目录 {sub} 失败（{e}），仅输出到控制台");
            tracing_subscriber::registry().with(console).init();
            return None;
        }
    }

    let (access_w, g1) = non_blocking(root, "access");
    let (upstream_w, g2) = non_blocking(root, "upstream");
    let (security_w, g3) = non_blocking(root, "security");
    let (error_w, g4) = non_blocking(root, "error");

    tracing_subscriber::registry()
        .with(console)
        .with(target_layer(access_w, "homewaf.access"))
        .with(target_layer(upstream_w, "homewaf.upstream"))
        .with(target_layer(security_w, "homewaf.security"))
        // error 目录收所有 WARN 及以上，不看 target
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(error_w)
                .with_ansi(false)
                .json()
                .with_filter(LevelFilter::WARN),
        )
        .init();

    Some(LogGuards(vec![g1, g2, g3, g4]))
}

/// 建一个「按天滚动 + 异步写入」的 writer。
fn non_blocking(root: &Path, sub: &str) -> (NonBlocking, WorkerGuard) {
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(sub)
        .filename_suffix("log")
        .build(root.join(sub))
        .expect("日志文件初始化失败");

    // lossy：队列满了丢日志而不是阻塞请求线程
    tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(QUEUE_CAPACITY)
        .lossy(true)
        .finish(appender)
}

/// 按 target 过滤 + JSON 格式写入。
fn target_layer<S>(writer: NonBlocking, target: &'static str) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .json()
        .with_filter(filter_fn(move |meta| meta.target() == target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_blocking_creates_dir_and_guard() {
        let dir = std::env::temp_dir().join(format!("hw-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (writer, guard) = non_blocking(&dir, "access");
        drop(writer);
        drop(guard); // flush

        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
