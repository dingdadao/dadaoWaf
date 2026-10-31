//! 日志初始化。
//!
//! 按类型 + 应用两级分目录，各写各的：
//!
//! ```text
//! data/logs/
//! ├── access/{app}/2026-10-22.log       每个请求一行（谁、访问什么、结果）
//! ├── upstream/{app}/2026-10-22.log     反代细节（上游、耗时、重试、失败原因）
//! ├── security/{app}/2026-10-22.log     安全事件（检测命中、封禁、ACL 拒绝）
//! └── error/2026-10-22.log              所有 WARN 及以上，全局一份
//! ```
//!
//! 分应用是为了让控制台"进某个应用只看它自己的日志"时只读一个目录；
//! 全局视图由控制台按需 tail 合并几个小文件，不用每次扫一个越来越大的总文件。
//!
//! **写入是异步的**：每条日志先丢进内存队列，由独立的后台线程批量落盘。
//! 请求线程不会因为磁盘 IO 被卡住——这一点很重要，日志不该成为代理的瓶颈。
//!
//! 代价是进程被强杀（kill -9）时队列里的日志可能丢。正常退出（SIGTERM）
//! 时 guard 会 flush，不丢。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use homewaf_config::LoggingConfig;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{filter_fn, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// 日志队列的内存上限。超过后丢弃新日志（lossy），不阻塞请求。
const QUEUE_CAPACITY: usize = 64 * 1024;
/// 单个类型下最多缓存多少个应用 writer。应用数量在家庭场景很小，
/// 上限只是防止 app 字段异常时无限建文件。
const MAX_APP_WRITERS: usize = 128;
/// 没有 app 字段（或值为空/`-`）的日志落到这个目录，便于对照排查。
const FALLBACK_APP: &str = "_global";

/// 持有后台写线程的句柄。**必须活到进程结束**，drop 时会 flush 剩余日志。
///
/// 字段本身不会被读取——它的作用纯粹是「别被 drop」，所以标 allow(dead_code)。
pub struct LogGuards(#[allow(dead_code)] Vec<WorkerGuard>);

/// 按应用懒创建 writer。每个 (类型, 应用) 一条后台写线程。
struct AppWriters {
    root: PathBuf,
    kind: &'static str,
    writers: Mutex<HashMap<String, NonBlocking>>,
    /// guard 必须与 writer 一起活着，否则线程退出日志就丢了
    guards: Mutex<Vec<WorkerGuard>>,
    /// writer 数量触顶后只告警一次，避免每行刷屏
    warned: AtomicU64,
}

impl AppWriters {
    fn new(root: &Path, kind: &'static str) -> Self {
        Self {
            root: root.to_path_buf(),
            kind,
            writers: Mutex::new(HashMap::new()),
            guards: Mutex::new(Vec::new()),
            warned: AtomicU64::new(0),
        }
    }

    /// 取（必要时创建）某个应用的 writer。
    fn get(&self, app: &str) -> Option<NonBlocking> {
        let mut map = self.writers.lock().ok()?;
        if let Some(w) = map.get(app) {
            return Some(w.clone());
        }
        if map.len() >= MAX_APP_WRITERS {
            if self.warned.fetch_add(1, Ordering::Relaxed) == 0 {
                eprintln!(
                    "日志 writer 已达到上限 {MAX_APP_WRITERS}（{}），后续应用日志并入 {FALLBACK_APP}",
                    self.kind
                );
            }
            return None;
        }
        let (writer, guard) = non_blocking(&self.root, self.kind, app);
        if let Ok(mut guards) = self.guards.lock() {
            guards.push(guard);
        }
        map.insert(app.to_string(), writer.clone());
        Some(writer)
    }
}

/// 应用 ID 直接做目录名不安全（可能含 `/`、`..` 或空串），统一收敛成安全文件名。
fn sanitize_app(app: &str) -> String {
    let trimmed = app.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return FALLBACK_APP.to_string();
    }
    let cleaned: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // `..` / `.` 这类名字不能当目录
    if cleaned.chars().all(|c| c == '.') {
        FALLBACK_APP.to_string()
    } else {
        cleaned
    }
}

/// 从一行 JSON 日志里取出应用标识。
///
/// 访问日志同时有 `app`（策略索引）与 `app_id`（应用 ID），必须优先取后者；
/// 安全/上游日志只有 `app`，其值就是应用 ID。
fn app_of_line(line: &[u8]) -> Option<String> {
    let raw = find_json_string(line, b"\"app_id\":\"")
        .or_else(|| find_json_string(line, b"\"app\":\""))?;
    let cleaned = sanitize_app(std::str::from_utf8(raw).unwrap_or(""));
    Some(cleaned)
}

/// 在字节流里找 `key` 之后直到下一个未转义引号的内容。
fn find_json_string<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let start = find_subslice(line, key)? + key.len();
    let rest = &line[start..];
    let mut end = 0;
    while end < rest.len() {
        match rest[end] {
            b'"' => return Some(&rest[..end]),
            b'\\' => end += 1, // 跳过转义字符
            _ => {}
        }
        end += 1;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 按行内容把日志分发到「类型/应用」目录的 writer。
#[derive(Clone)]
struct SplitMakeWriter {
    writers: Arc<AppWriters>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SplitMakeWriter {
    type Writer = SplitWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SplitWriter {
            writers: self.writers.clone(),
            buf: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, _meta: &tracing::Metadata<'_>) -> Self::Writer {
        self.make_writer()
    }
}

struct SplitWriter {
    writers: Arc<AppWriters>,
    /// 一行可能分多次写入，攒到换行为止再分发。
    buf: Vec<u8>,
}

impl SplitWriter {
    fn dispatch(&mut self, mut line: &[u8]) {
        if line.ends_with(b"\n") {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            return;
        }
        let app = app_of_line(line).unwrap_or_else(|| FALLBACK_APP.to_string());
        let target = self
            .writers
            .get(&app)
            .or_else(|| self.writers.get(FALLBACK_APP));
        if let Some(mut w) = target {
            let _ = w.write_all(line);
            let _ = w.write_all(b"\n");
        }
    }
}

impl Write for SplitWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut rest = buf;
        while let Some(pos) = rest.iter().position(|b| *b == b'\n') {
            self.buf.extend_from_slice(&rest[..pos]);
            let mut line = std::mem::take(&mut self.buf);
            self.dispatch(&line);
            line.clear();
            self.buf = line;
            rest = &rest[pos + 1..];
        }
        self.buf.extend_from_slice(rest);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.dispatch(&line);
        }
        Ok(())
    }
}

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

    let (error_w, g4) = non_blocking(root, "error", "");

    tracing_subscriber::registry()
        .with(console)
        .with(split_layer(root, "access", "homewaf.access"))
        .with(split_layer(root, "upstream", "homewaf.upstream"))
        .with(split_layer(root, "security", "homewaf.security"))
        // error 目录收所有 WARN 及以上，不看 target
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(error_w)
                .with_ansi(false)
                .json()
                .with_filter(LevelFilter::WARN),
        )
        .init();

    Some(LogGuards(vec![g4]))
}

/// 按 target 过滤后写入「类型/应用」目录。
fn split_layer<S>(root: &Path, kind: &'static str, target: &'static str) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_writer(SplitMakeWriter {
            writers: Arc::new(AppWriters::new(root, kind)),
        })
        .with_ansi(false)
        .json()
        .with_filter(filter_fn(move |meta| meta.target() == target))
}

/// 建一个「按天滚动 + 异步写入」的 writer。`sub` 为应用子目录，空串表示直接用类型目录。
fn non_blocking(root: &Path, kind: &str, sub: &str) -> (NonBlocking, WorkerGuard) {
    let dir = if sub.is_empty() {
        root.join(kind)
    } else {
        root.join(kind).join(sub)
    };
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(kind)
        .filename_suffix("log")
        .build(&dir)
        .expect("日志文件初始化失败");

    // lossy：队列满了丢日志而不是阻塞请求线程
    tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(QUEUE_CAPACITY)
        .lossy(true)
        .finish(appender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_blocking_creates_dir_and_guard() {
        let dir = std::env::temp_dir().join(format!("hw-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (writer, guard) = non_blocking(&dir, "access", "nas");
        drop(writer);
        drop(guard); // flush

        assert!(dir.join("access").join("nas").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_name_is_sanitized() {
        assert_eq!(sanitize_app("nas"), "nas");
        assert_eq!(sanitize_app("my.app-1"), "my.app-1");
        assert_eq!(sanitize_app(""), FALLBACK_APP);
        assert_eq!(sanitize_app("   "), FALLBACK_APP);
        assert_eq!(sanitize_app("-"), FALLBACK_APP);
        assert_eq!(sanitize_app("../etc"), ".._etc");
        assert_eq!(sanitize_app("a/b"), "a_b");
        assert_eq!(sanitize_app(".."), FALLBACK_APP);
    }

    #[test]
    fn app_is_preferred_over_policy_index() {
        let line = br#"{"fields":{"app":3,"app_id":"nas"},"target":"homewaf.access"}"#;
        assert_eq!(app_of_line(line).as_deref(), Some("nas"));

        let security = br#"{"fields":{"app":"blog","client_ip":"1.2.3.4"}}"#;
        assert_eq!(app_of_line(security).as_deref(), Some("blog"));

        let none = br#"{"fields":{"path":"/"}}"#;
        assert_eq!(app_of_line(none), None);
    }
}
