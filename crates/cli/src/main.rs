//! HomeWAF 命令行入口。
//!
//! 当前阶段（M0 / T1.1-T1.2）只提供配置相关命令：
//! - `validate`：校验配置文件
//! - `dump`：输出解析后的规范化配置
//! - `default-config`：打印带注释的示例配置

use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use homewaf_config::{ConfigError, Severity};

mod logging;

#[derive(Parser)]
#[command(
    name = "homewaf",
    version,
    about = "HomeWAF — 家用 Web 应用防火墙",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 校验配置文件
    Validate {
        /// 配置文件路径
        path: String,
        /// 把 warning 也视为失败
        #[arg(long)]
        strict: bool,
    },
    /// 输出解析后的规范化配置（YAML）
    Dump {
        /// 配置文件路径
        path: String,
    },
    /// 打印带注释的示例配置
    DefaultConfig,
    /// 解析一个请求会命中哪个应用与路由（调试用）
    Route {
        /// 配置文件路径
        path: String,
        /// 请求的 Host，如 nas.home.lan
        host: String,
        /// 请求路径，如 /jellyfin/web
        #[arg(default_value = "/")]
        request_path: String,
        /// 请求到达的端口，用于匹配应用的监听端口
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// 启用正则匹配
        #[arg(long)]
        allow_regex: bool,
    },
    /// 启动代理服务。配置来自数据库，不再读配置文件
    Serve {
        /// 数据库路径
        #[arg(long, default_value = "./data/homewaf.db")]
        db: String,
        /// 监听地址，可重复。覆盖数据库中的设置
        #[arg(long)]
        listen: Vec<String>,
        /// TLS 监听地址，可重复。覆盖数据库中的设置
        #[arg(long)]
        tls_listen: Vec<String>,
        /// 管理面监听地址，如 `0.0.0.0:9443`。覆盖数据库中的设置
        #[arg(long)]
        admin_listen: Option<String>,
        /// 启用正则匹配
        #[arg(long)]
        allow_regex: bool,
        /// 关闭配置热重载（默认开启，轮询间隔 2 秒）
        #[arg(long)]
        no_watch: bool,
    },
    /// 把 YAML 配置一次性导入数据库（迁移用）
    Import {
        /// YAML 配置文件路径
        path: String,
        /// 目标数据库
        #[arg(long, default_value = "./data/homewaf.db")]
        db: String,
        /// 覆盖已存在的应用
        #[arg(long)]
        overwrite: bool,
    },
    /// 列出数据库中的应用
    AppList {
        /// 数据库路径
        #[arg(long, default_value = "./data/homewaf.db")]
        db: String,
    },
    /// 拉取并解析一个 IP 组订阅（dry-run，不写入任何状态）
    Feed {
        /// 订阅地址，必须是 HTTPS
        url: String,
        /// 内容格式：auto | cidr | json | text
        #[arg(long, default_value = "auto")]
        format: String,
        /// 响应体上限，如 10MB
        #[arg(long, default_value = "10MB")]
        max_bytes: String,
        /// 拉取超时，如 15s
        #[arg(long, default_value = "15s")]
        timeout: String,
        /// 只看前 N 条示例
        #[arg(long, default_value_t = 5)]
        sample: usize,
    },
    /// 规则包签名工具
    Rulepack {
        #[command(subcommand)]
        command: RulepackCommand,
    },
}

#[derive(Subcommand)]
enum RulepackCommand {
    /// 生成 Ed25519 签名密钥
    Keygen {
        /// 私钥输出路径（PKCS#8 DER，权限 0600）
        #[arg(long, default_value = "rulepack-signing.pkcs8")]
        out: String,
    },
    /// 给规则文档签名，生成可被订阅的 .hwrule 文件
    Sign {
        /// 私钥路径
        #[arg(long)]
        key: String,
        /// 规则文档（JSON 或 YAML）
        input: String,
        /// 输出路径；省略则写到标准输出
        #[arg(long, short)]
        out: Option<String>,
    },
    /// 校验签名并解析规则包（订阅端的完整检查）
    Verify {
        /// 公钥，格式 ed25519:<base64>
        #[arg(long)]
        key: String,
        /// 规则包路径
        path: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Validate { path, strict } => cmd_validate(&path, strict),
        Command::Dump { path } => cmd_dump(&path),
        Command::DefaultConfig => cmd_default_config(),
        Command::Route {
            path,
            host,
            request_path,
            port,
            allow_regex,
        } => cmd_route(&path, &host, &request_path, port, allow_regex),
        Command::Serve {
            db,
            listen,
            tls_listen,
            admin_listen,
            allow_regex,
            no_watch,
        } => cmd_serve(&db, listen, tls_listen, admin_listen, allow_regex, no_watch),
        Command::Import {
            path,
            db,
            overwrite,
        } => cmd_import(&path, &db, overwrite),
        Command::AppList { db } => cmd_app_list(&db),
        Command::Feed {
            url,
            format,
            max_bytes,
            timeout,
            sample,
        } => cmd_feed(&url, &format, &max_bytes, &timeout, sample),
        Command::Rulepack { command } => match command {
            RulepackCommand::Keygen { out } => cmd_rulepack_keygen(&out),
            RulepackCommand::Sign { key, input, out } => {
                cmd_rulepack_sign(&key, &input, out.as_deref())
            }
            RulepackCommand::Verify { key, path } => cmd_rulepack_verify(&key, &path),
        },
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_validate(path: &str, strict: bool) -> anyhow::Result<ExitCode> {
    match homewaf_config::load_with_warnings(path) {
        Ok((config, warnings)) => {
            println!("配置有效: {path}");
            println!(
                "  应用 {} 个 · 上游 {} 个 · IP 组订阅 {} 个 · 规则包订阅 {} 个",
                config.applications.len(),
                config
                    .applications
                    .iter()
                    .map(|a| a.upstreams.len())
                    .sum::<usize>(),
                config.ip_groups.len(),
                config.rule_feeds.len()
            );

            if warnings.is_empty() {
                println!("  无警告");
            } else {
                println!("\n警告 {} 条：", warnings.len());
                for w in &warnings {
                    println!("  warning {w}");
                }
            }

            if strict && !warnings.is_empty() {
                eprintln!("\n--strict 模式：存在警告，视为失败");
                return Ok(ExitCode::FAILURE);
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            report_error(&e);
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_dump(path: &str) -> anyhow::Result<ExitCode> {
    match homewaf_config::load_with_warnings(path) {
        Ok((config, warnings)) => {
            for w in &warnings {
                eprintln!("warning {w}");
            }
            let yaml = serde_yaml::to_string(&config)?;
            print!("{yaml}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            report_error(&e);
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_default_config() -> anyhow::Result<ExitCode> {
    print!("{}", include_str!("../../../configs/example.yaml"));
    Ok(ExitCode::SUCCESS)
}

fn cmd_route(
    path: &str,
    host: &str,
    request_path: &str,
    port: u16,
    allow_regex: bool,
) -> anyhow::Result<ExitCode> {
    let config = match homewaf_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            report_error(&e);
            return Ok(ExitCode::FAILURE);
        }
    };

    let router = match homewaf_router::Router::build(config.applications, allow_regex) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("构建路由表失败: {e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    println!("请求: {host}{request_path}");

    let Some(hit) = router.resolve(host, port, request_path) else {
        println!("  未匹配任何应用 → 返回 444（直接断开，不泄露指纹）");
        return Ok(ExitCode::SUCCESS);
    };

    let app = router.app(hit.app_index).expect("路由索引必然有效");
    println!("  应用: {} ({})", app.name, app.id);
    println!("  规范化路径: {}", hit.normalized_path);

    let kind = match hit.match_kind {
        Some(homewaf_router::MatchKind::Exact) => "精确",
        Some(homewaf_router::MatchKind::PrefixNoRegex) => "^~ 前缀",
        Some(homewaf_router::MatchKind::Regex) => "正则",
        Some(homewaf_router::MatchKind::Prefix) => "前缀",
        Some(homewaf_router::MatchKind::Default) => "默认",
        None => "无",
    };

    match router.route_of(&hit) {
        Some(route) => {
            println!("  路由: {} [{}]", route.path, kind);
            if let Some(rw) = &route.rewrite {
                println!("  重写: {:?} → {:?}", rw.mode, rw.value);
            }
            let upstreams = route.upstreams.as_deref().unwrap_or(&app.upstreams);
            print_upstreams(upstreams);
        }
        None => {
            println!("  路由: 未匹配（使用应用默认上游）");
            print_upstreams(&app.upstreams);
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn print_upstreams(upstreams: &[homewaf_config::Upstream]) {
    if upstreams.is_empty() {
        println!("  上游: 无（配置错误）");
        return;
    }
    for (i, u) in upstreams.iter().enumerate() {
        let port = u.port.map(|p| format!(":{p}")).unwrap_or_default();
        let backup = if u.backup { " [backup]" } else { "" };
        println!(
            "  上游{}: {}://{}{}{} weight={}",
            i + 1,
            scheme_str(u.scheme),
            u.addr,
            port,
            backup,
            u.weight
        );
    }
}

fn scheme_str(s: homewaf_config::Scheme) -> &'static str {
    match s {
        homewaf_config::Scheme::Http => "http",
        homewaf_config::Scheme::Https => "https",
        homewaf_config::Scheme::Grpc => "grpc",
        homewaf_config::Scheme::Ws => "ws",
        homewaf_config::Scheme::Wss => "wss",
    }
}

fn cmd_serve(
    db: &str,
    listen_override: Vec<String>,
    tls_override: Vec<String>,
    admin_override: Option<String>,
    allow_regex: bool,
    no_watch: bool,
) -> anyhow::Result<ExitCode> {
    // 日志初始化要在最前面：配置在数据库里，但数据库打不开时也要能记日志，
    // 所以日志配置走默认值 + 环境变量，不从数据库读。
    let mut logging_cfg = homewaf_config::LoggingConfig::default();
    if let Ok(dir) = std::env::var("HOMEWAF_LOG_DIR") {
        logging_cfg.dir = dir;
    }
    if let Ok(level) = std::env::var("HOMEWAF_LOG_LEVEL") {
        logging_cfg.level = match level.to_ascii_lowercase().as_str() {
            "trace" => homewaf_config::LogLevel::Trace,
            "debug" => homewaf_config::LogLevel::Debug,
            "warn" => homewaf_config::LogLevel::Warn,
            "error" => homewaf_config::LogLevel::Error,
            _ => homewaf_config::LogLevel::Info,
        };
    }
    // 必须 hold 住 guard：drop 会 flush 剩余日志，提前丢会丢数据
    let _log_guards = logging::init(&logging_cfg);

    // 数据库是唯一配置来源。引导参数只有 DB 路径与监听地址
    let storage = homewaf_config::StorageConfig {
        path: db.to_string(),
        ..Default::default()
    };

    let Some(store) = homewaf_proxy::open_store(&storage) else {
        eprintln!("无法打开数据库：{db}");
        return Ok(ExitCode::FAILURE);
    };

    // 启动即迁移历史 IP 规则：迁移只在管理端重载时跑的话，
    // 升级后不点任何页面就一直看不到旧规则，等于静默丢配置。
    if let Err(e) = homewaf_admin::migrate_legacy_acl(&store) {
        eprintln!("迁移历史 IP 规则失败（已跳过）：{e}");
    }
    if let Err(e) = homewaf_admin::normalize_rule_seq(&store) {
        eprintln!("补规则序号失败（已跳过）：{e}");
    }

    let mut state = match homewaf_proxy::load_state_from_db(&store, allow_regex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    // 管理面监听：命令行显式指定时覆盖，并回写到状态里，
    // 否则控制台「系统信息」显示的仍是数据库里的旧地址。
    if let Some(addr) = admin_override {
        state.server.admin.listen = addr;
    }

    // 监听地址优先级：命令行 > 数据库 > 默认
    let listen = if listen_override.is_empty() {
        state.server.listen.clone()
    } else {
        listen_override
    };
    let tls_listen = if tls_override.is_empty() {
        state.server.tls_listen.clone()
    } else {
        tls_override
    };
    let tls = state.tls.clone();

    tracing::info!(
        apps = state.router.len(),
        upstreams = state.upstream_count(),
        acl_rules = state.rule_count(),
        real_ip = state.real_ip.enabled,
        http = ?listen,
        https = ?tls_listen,
        "HomeWAF 启动（配置来自数据库 {db}）"
    );

    let shared = homewaf_proxy::shared(state);

    // 封禁表由 CLI 创建：控制台与代理必须共享同一个实例，
    // 否则控制台解封后代理那边还在封
    let bans = std::sync::Arc::new(homewaf_acl::BanTable::new(
        &shared.load_full().auto_ban,
        shared.load_full().ipv6_prefix,
    ));

    // 流量指标由代理写入、控制台读取，必须共享同一个实例
    let metrics = std::sync::Arc::new(homewaf_proxy::TrafficMetrics::new());

    // 启动控制台（独立线程，不阻塞代理）
    let admin_addr = shared.load_full().server.admin.listen.clone();
    if !admin_addr.is_empty() {
        let token = std::env::var("HOMEWAF_ADMIN_TOKEN").ok();
        let admin_state = homewaf_admin::AdminState {
            store: store.clone(),
            shared: shared.clone(),
            bans: bans.clone(),
            metrics: metrics.clone(),
            geoip: std::sync::Arc::new(homewaf_admin::geoip::GeoIp::new()),
            allow_regex,
            token,
            log_dir: std::path::PathBuf::from(&logging_cfg.dir),
            data_dir: std::path::Path::new(db)
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            started_at: homewaf_acl::now_unix(),
            listen: listen.clone(),
            tls_listen: tls_listen.clone(),
        };
        match homewaf_admin::spawn(admin_state, admin_addr.clone()) {
            Ok(()) => tracing::info!(listen = %admin_addr, "控制台启动中"),
            Err(e) => tracing::error!(error = %e, "控制台启动失败，代理继续运行"),
        }
    }

    let settings = homewaf_proxy::ProxySettings {
        listen,
        tls_listen,
        tls,
        store: Some(store),
        bans,
        metrics,
        // DB 模式下没有配置文件可监视。改配置后由控制台显式触发重载
        watch_path: None,
        allow_regex,
        watch_interval: std::time::Duration::from_secs(2),
        events_retention_days: 30,
    };
    let _ = no_watch;

    homewaf_proxy::run(shared, settings)?;
    Ok(ExitCode::SUCCESS)
}

/// 把 YAML 配置一次性导入数据库。迁移工具，运行时不再依赖 YAML。
fn cmd_import(path: &str, db: &str, overwrite: bool) -> anyhow::Result<ExitCode> {
    let config = match homewaf_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            report_error(&e);
            return Ok(ExitCode::FAILURE);
        }
    };

    let report = config.validate();
    if report.has_errors() {
        report_error(&ConfigError::Validation(report.errors.to_vec()));
        return Ok(ExitCode::FAILURE);
    }

    let storage = homewaf_config::StorageConfig {
        path: db.to_string(),
        ..Default::default()
    };
    let Some(store) = homewaf_proxy::open_store(&storage) else {
        eprintln!("无法打开数据库：{db}");
        return Ok(ExitCode::FAILURE);
    };

    let now = homewaf_acl::now_unix();

    // 应用
    let mut imported = 0;
    let mut skipped = 0;
    for app in &config.applications {
        let exists = store
            .list_applications::<homewaf_config::Application>()
            .map(|apps| apps.iter().any(|a| a.id == app.id))
            .unwrap_or(false);

        if exists && !overwrite {
            skipped += 1;
            continue;
        }

        if let Err(e) =
            store.upsert_application(&app.id, &app.domains.primary, app.enabled, app, now)
        {
            eprintln!("导入应用 {} 失败：{e}", app.id);
            return Ok(ExitCode::FAILURE);
        }
        imported += 1;
    }

    // 全局设置
    macro_rules! save_setting {
        ($key:literal, $value:expr) => {
            if let Err(e) = store.set_setting($key, &$value, now) {
                eprintln!("保存设置 {} 失败：{e}", $key);
                return Ok(ExitCode::FAILURE);
            }
        };
    }
    save_setting!("server", config.server);
    save_setting!("tls", config.tls);
    save_setting!("protection", config.protection);
    save_setting!("real_ip", config.real_ip);
    save_setting!("acl", config.acl);
    save_setting!("limits", config.limits);
    save_setting!("ratelimit", config.ratelimit);
    save_setting!("challenge", config.challenge);
    save_setting!("logging", config.logging);
    let rule_feed_count = config.rule_feeds.len();
    save_setting!("rule_feeds", config.rule_feeds);
    // 存实际 DB 路径，而不是 YAML 里写的（可能不一致）
    let mut storage_cfg = config.storage.clone();
    storage_cfg.path = db.to_string();
    save_setting!("storage", storage_cfg);

    // ACL 静态规则
    let mut rule_count = 0;
    for (i, r) in config.acl.rules.iter().enumerate() {
        let row = homewaf_store::AclRuleRow {
            id: r.id.clone().unwrap_or_else(|| format!("imported-{i}")),
            cidr: r.cidr.to_string(),
            action: match r.action {
                homewaf_config::AclRuleAction::Allow => "allow".to_string(),
                homewaf_config::AclRuleAction::Deny => "deny".to_string(),
            },
            scope: r.scope.clone(),
            expires_at: r.expires_at,
            note: r.note.clone(),
        };
        if let Err(e) = store.upsert_acl_rule(&row, now) {
            eprintln!("导入 ACL 规则 {} 失败：{e}", row.id);
            return Ok(ExitCode::FAILURE);
        }
        rule_count += 1;
    }

    // IP 组订阅
    let mut group_count = 0;
    for g in &config.ip_groups {
        if let Err(e) = store.upsert_ip_group(&g.name, g.enabled, g, now) {
            eprintln!("导入订阅 {} 失败：{e}", g.name);
            return Ok(ExitCode::FAILURE);
        }
        group_count += 1;
    }

    println!("导入完成 → {db}");
    println!("  应用 {imported} 个（跳过 {skipped} 个已存在）");
    println!("  ACL 规则 {rule_count} 条");
    println!("  IP 组订阅 {group_count} 个");
    println!("  规则包订阅 {rule_feed_count} 个");
    println!("  全局设置 10 项");

    Ok(ExitCode::SUCCESS)
}

fn cmd_app_list(db: &str) -> anyhow::Result<ExitCode> {
    let storage = homewaf_config::StorageConfig {
        path: db.to_string(),
        ..Default::default()
    };
    let Some(store) = homewaf_proxy::open_store(&storage) else {
        eprintln!("无法打开数据库：{db}");
        return Ok(ExitCode::FAILURE);
    };

    let apps: Vec<homewaf_config::Application> = match store.list_applications() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("读取应用失败：{e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    if apps.is_empty() {
        println!("数据库中没有应用。用 `homewaf import <yaml>` 导入，或等控制台接入。");
        return Ok(ExitCode::SUCCESS);
    }

    println!("{:<12} {:<24} {:<8} 上游", "ID", "主域名", "状态");
    for app in apps {
        println!(
            "{:<12} {:<24} {:<8} {}",
            app.id,
            app.domains.primary,
            if app.enabled { "启用" } else { "禁用" },
            app.upstreams.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_feed(
    url: &str,
    format: &str,
    max_bytes: &str,
    timeout: &str,
    sample: usize,
) -> anyhow::Result<ExitCode> {
    use homewaf_config::{FeedFormat, IpGroupGuards};

    let format = match format.to_ascii_lowercase().as_str() {
        "auto" => FeedFormat::Auto,
        "cidr" => FeedFormat::Cidr,
        "json" => FeedFormat::Json,
        "text" => FeedFormat::Text,
        other => {
            eprintln!("未知格式 `{other}`（支持 auto / cidr / json / text）");
            return Ok(ExitCode::FAILURE);
        }
    };

    let max_bytes = match homewaf_config::units::parse_size(max_bytes) {
        Ok(v) => v as usize,
        Err(e) => {
            eprintln!("--max-bytes 无效：{e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let timeout = match homewaf_config::units::parse_duration(timeout) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("--timeout 无效：{e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    println!("拉取 {url}");

    let text = match homewaf_acl::fetch_feed(url, timeout, max_bytes, &Default::default()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("拉取失败：{e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    println!("  收到 {} 字节", text.len());

    let parsed = match homewaf_acl::parse_feed(&text, format) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("解析失败：{e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    println!(
        "  解析 {} 条，跳过 {} 行",
        parsed.entries.len(),
        parsed.skipped
    );

    let guards = IpGroupGuards::default();
    let total_before = parsed.entries.len();
    let outcome = homewaf_acl::apply_guards(parsed.entries, &[], &guards);

    match &outcome {
        homewaf_acl::GuardOutcome::Accepted(v) => {
            println!("  护栏：通过（{} 条）", v.len());
        }
        homewaf_acl::GuardOutcome::PartiallyAccepted { entries, dropped } => {
            println!(
                "  护栏：部分接受（保留 {} 条，丢弃 {dropped} 条前缀过短的）",
                entries.len()
            );
        }
        homewaf_acl::GuardOutcome::Rejected(reason) => {
            eprintln!("  护栏：整批拒绝 —— {reason}");
            eprintln!("  （共解析 {total_before} 条，未写入任何状态）");
            return Ok(ExitCode::FAILURE);
        }
    }

    if let Some(entries) = outcome.entries() {
        if sample > 0 && !entries.is_empty() {
            println!("  示例：");
            for net in entries.iter().take(sample) {
                println!("    {net}");
            }
            if entries.len() > sample {
                println!("    ... 共 {} 条", entries.len());
            }
        }
    }

    println!("dry-run 完成，未修改任何状态");
    Ok(ExitCode::SUCCESS)
}

fn cmd_rulepack_keygen(out: &str) -> anyhow::Result<ExitCode> {
    let (key, public) =
        homewaf_detect::feed::generate_signing_key().map_err(|e| anyhow::anyhow!(e))?;

    if let Some(parent) = std::path::Path::new(out).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建目录 {} 失败", parent.display()))?;
        }
    }
    std::fs::write(out, &key).with_context(|| format!("写入私钥 {out} 失败"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("设置私钥权限失败：{out}"))?;
    }

    println!("私钥已写入 {out}（权限 0600，请离线保管）");
    println!("公钥（填到订阅的 public_key）：");
    println!("{public}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_rulepack_sign(key: &str, input: &str, out: Option<&str>) -> anyhow::Result<ExitCode> {
    let key_bytes = std::fs::read(key).with_context(|| format!("读取私钥 {key} 失败"))?;
    let payload =
        std::fs::read_to_string(input).with_context(|| format!("读取规则文档 {input} 失败"))?;

    // 先按订阅端的同一套规则校验，别签出一个自己都加载不了的文件
    homewaf_detect::feed::parse_rules(&payload, "local")
        .map_err(|e| anyhow::anyhow!("规则文档校验失败：{e}"))?;

    let signed =
        homewaf_detect::feed::sign_payload(&key_bytes, &payload).map_err(|e| anyhow::anyhow!(e))?;

    match out {
        Some(path) => {
            std::fs::write(path, signed).with_context(|| format!("写入 {path} 失败"))?;
            println!("已签名并写入 {path}");
        }
        None => print!("{signed}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_rulepack_verify(key: &str, path: &str) -> anyhow::Result<ExitCode> {
    let body = std::fs::read_to_string(path).with_context(|| format!("读取 {path} 失败"))?;
    let (signature, payload) = homewaf_detect::feed::split_signature(&body)
        .map_err(|e| anyhow::anyhow!("解析签名头失败：{e}"))?;
    let signature = signature.ok_or_else(|| anyhow::anyhow!("规则包没有签名"))?;

    homewaf_detect::feed::verify_signature(key, payload.as_bytes(), &signature)
        .map_err(|e| anyhow::anyhow!("验签失败：{e}"))?;

    let parsed = homewaf_detect::feed::parse_rules(payload, "verify")
        .map_err(|e| anyhow::anyhow!("规则包解析失败：{e}"))?;

    println!(
        "签名有效 · {} 条规则 · 版本 {} · 通道 {}",
        parsed.rules.len(),
        parsed.version.as_deref().unwrap_or("未声明"),
        parsed.channel.as_deref().unwrap_or("未声明"),
    );
    Ok(ExitCode::SUCCESS)
}

/// 拉取、解析并护栏校验一个 IP 组订阅，产出 ACL 规则。
fn report_error(err: &ConfigError) {
    match err {
        ConfigError::Validation(items) => {
            let errors: Vec<_> = items.iter().filter(|i| i.is_error()).collect();
            let warnings: Vec<_> = items
                .iter()
                .filter(|i| i.severity == Severity::Warning)
                .collect();

            if !errors.is_empty() {
                eprintln!("配置校验失败，{} 处错误：", errors.len());
                for e in errors {
                    eprintln!("  error   {e}");
                }
            }
            if !warnings.is_empty() {
                eprintln!("\n另有 {} 条警告：", warnings.len());
                for w in warnings {
                    eprintln!("  warning {w}");
                }
            }
        }
        other => eprintln!("{other}"),
    }
}
