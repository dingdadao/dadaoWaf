//! HomeWAF 持久化层（SQLite）。
//!
//! 一次解决三个问题：
//! 1. **封禁重启丢失**——内存态封禁在进程退出后清零，攻击者立刻回来
//! 2. **订阅变更幅度失效**——重启后没有"上次列表"可比，护栏形同虚设
//! 3. **事件无处存**——控制台需要历史数据
//!
//! 用 `bundled` 特性把 SQLite 源码编进去，不依赖系统库。

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

mod config_store;

pub use config_store::{AclRuleRow, CertificateRow, IpGroupRow, WhitelistRow};

/// 存储层错误。
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("数据库错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("数据库被其他线程占用")]
    Poisoned,
    #[error("数据解析失败：{0}")]
    Decode(String),
    #[error("数据序列化失败：{0}")]
    Encode(String),
}

/// 一条封禁记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    pub ip: String,
    /// 封禁截止时间（Unix 秒）
    pub until: i64,
    pub offenses: u32,
    pub score: u32,
    pub reason: String,
    pub created_at: i64,
}

/// 事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// 检测命中
    Detect,
    /// 自动封禁
    Ban,
    /// ACL 拒绝
    Acl,
    /// CC 防护（限流 / 并发超限）
    RateLimit,
    /// 人机验证
    Challenge,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Detect => "detect",
            EventKind::Ban => "ban",
            EventKind::Acl => "acl",
            EventKind::RateLimit => "ratelimit",
            EventKind::Challenge => "challenge",
        }
    }

    pub fn parse_kind(s: &str) -> Self {
        match s {
            "ban" => EventKind::Ban,
            "acl" => EventKind::Acl,
            "ratelimit" => EventKind::RateLimit,
            "challenge" => EventKind::Challenge,
            _ => EventKind::Detect,
        }
    }
}

/// 一条安全事件。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub kind: EventKind,
    pub client_ip: String,
    pub app: String,
    pub path: String,
    /// 命中的规则 id，逗号分隔
    pub rules: String,
    /// 命中的规则名称（人类可读），逗号分隔
    pub rule_names: String,
    pub score: u32,
    /// `block` / `log` / `observe` / `ban`
    pub action: String,
    /// 请求 ID，可与访问日志对照
    pub request_id: String,
    pub method: String,
    /// 查询串（不含 `?`）
    pub query: String,
    pub user_agent: String,
}

impl Event {
    /// 构造一条待写入的事件（`id` 由数据库分配）。其余字段用 builder 补齐。
    pub fn new(ts: i64, kind: EventKind, client_ip: impl Into<String>) -> Self {
        Self {
            id: 0,
            ts,
            kind,
            client_ip: client_ip.into(),
            app: String::new(),
            path: String::new(),
            rules: String::new(),
            rule_names: String::new(),
            score: 0,
            action: String::new(),
            request_id: String::new(),
            method: String::new(),
            query: String::new(),
            user_agent: String::new(),
        }
    }

    pub fn with_request(
        mut self,
        request_id: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        self.request_id = request_id.into();
        self.method = method.into();
        self
    }

    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    pub fn with_rule_names(mut self, names: impl Into<String>) -> Self {
        self.rule_names = names.into();
        self
    }

    pub fn with_app(mut self, app: impl Into<String>) -> Self {
        self.app = app.into();
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn with_rules(mut self, rules: impl Into<String>) -> Self {
        self.rules = rules.into();
        self
    }

    pub fn with_score(mut self, score: u32) -> Self {
        self.score = score;
        self
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }
}

/// 事件查询条件。`None` 表示不限制该维度。
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub limit: usize,
    pub offset: usize,
    /// detect / ban / acl / ratelimit / challenge
    pub kind: Option<String>,
    /// 精确匹配来源 IP
    pub ip: Option<String>,
    /// block / log / observe / ban
    pub action: Option<String>,
    /// 起始时间（Unix 秒，含）
    pub since: Option<i64>,
    /// 结束时间（Unix 秒，含）
    pub until: Option<i64>,
    /// 精确匹配应用名
    pub app: Option<String>,
    /// 路径包含匹配
    pub path: Option<String>,
    /// 关键字，模糊匹配路径 / 规则 / 来源 IP
    pub q: Option<String>,
}

/// 一条分钟级流量聚合。
#[derive(Debug, Clone, Default)]
pub struct TrafficBucketRow {
    pub minute: i64,
    pub app: String,
    pub requests: u64,
    pub pv: u64,
    pub blocked: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub unique_ips: u64,
    pub unique_visitors: u64,
    /// IP 的 u128 形式，用于日报按天去重。
    pub ips: Vec<u128>,
    /// (IP, UA) 哈希，用于日报独立访客。
    pub visitors: Vec<u64>,
    /// 明细快照 JSON（状态码分布、Top、来源 IP）。旧库行为空字符串。
    pub detail: String,
}

/// 一条分钟级聚合的明细行，供控制台把历史与当前进程内存合并。
#[derive(Debug, Clone, Default)]
pub struct TrafficDetailRow {
    pub minute: i64,
    pub app: String,
    pub requests: u64,
    pub pv: u64,
    pub blocked: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub unique_ips: u64,
    pub unique_visitors: u64,
    pub detail: String,
}

/// 一段时间的流量汇总。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TrafficTotals {
    pub requests: u64,
    pub pv: u64,
    pub blocked: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub unique_ips: u64,
    pub unique_visitors: u64,
}

/// 小时/天级趋势点。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficPoint {
    pub ts: i64,
    pub requests: u64,
    pub blocked: u64,
}

/// 报表列表中的一天。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficDay {
    pub day: i64,
    pub requests: u64,
    pub blocked: u64,
}

/// SQLite 存储。
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// 打开（或创建）数据库文件，并初始化表结构。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// 内存数据库，用于测试。
    pub fn open_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// 借出连接执行一段操作。给子模块用，避免把 `conn` 暴露成 pub。
    pub(crate) fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        f(&conn)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS bans (
                ip         TEXT PRIMARY KEY,
                until      INTEGER NOT NULL,
                offenses   INTEGER NOT NULL DEFAULT 1,
                score      INTEGER NOT NULL DEFAULT 0,
                reason     TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                app       TEXT NOT NULL DEFAULT '',
                path      TEXT NOT NULL DEFAULT '',
                rules     TEXT NOT NULL DEFAULT '',
                score     INTEGER NOT NULL DEFAULT 0,
                action    TEXT NOT NULL DEFAULT '',
                request_id TEXT NOT NULL DEFAULT '',
                method    TEXT NOT NULL DEFAULT '',
                query     TEXT NOT NULL DEFAULT '',
                ua        TEXT NOT NULL DEFAULT '',
                rule_names TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

            CREATE TABLE IF NOT EXISTS feed_state (
                name       TEXT PRIMARY KEY,
                entries    TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- 应用：一行一个应用，完整结构序列化成 JSON。
            -- 用 JSON 而不是拆列：应用数量在家庭场景 < 50，全量加载进内存即可，
            -- 拆列会让"加一个字段就要改表"变成常态。
            CREATE TABLE IF NOT EXISTS applications (
                id             TEXT PRIMARY KEY,
                primary_domain TEXT NOT NULL,
                enabled        INTEGER NOT NULL DEFAULT 1,
                body           TEXT NOT NULL,
                created_at     INTEGER NOT NULL,
                updated_at     INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_app_domain ON applications(primary_domain);

            -- 全局设置：一段 JSON 一个键，如 protection / real_ip / acl / tls
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- ACL 静态规则
            CREATE TABLE IF NOT EXISTS acl_rules (
                id         TEXT PRIMARY KEY,
                cidr       TEXT NOT NULL,
                action     TEXT NOT NULL,
                scope      TEXT,
                expires_at INTEGER,
                note       TEXT,
                created_at INTEGER NOT NULL
            );

            -- IP 组订阅
            CREATE TABLE IF NOT EXISTS ip_groups (
                name          TEXT PRIMARY KEY,
                enabled       INTEGER NOT NULL DEFAULT 1,
                body          TEXT NOT NULL,
                updated_at    INTEGER NOT NULL
            );

            -- 网页防篡改基线：一行一个受保护文件
            CREATE TABLE IF NOT EXISTS tamper_baselines (
                app_id     TEXT NOT NULL,
                path       TEXT NOT NULL,
                size       INTEGER NOT NULL,
                digest     TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (app_id, path)
            );

            -- TLS 证书：PEM 原文入库，由控制台与代理共享
            CREATE TABLE IF NOT EXISTS certificates (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                cert_pem   TEXT NOT NULL,
                key_pem    TEXT NOT NULL,
                domains    TEXT NOT NULL DEFAULT '',
                not_before INTEGER NOT NULL,
                not_after  INTEGER NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- 检测白名单（误报豁免）
            CREATE TABLE IF NOT EXISTS detect_whitelist (
                id         TEXT PRIMARY KEY,
                app        TEXT,
                path       TEXT,
                rule_id    TEXT,
                note       TEXT,
                created_at INTEGER NOT NULL
            );

            -- 规则包缓存：保存已验签的原始载荷。
            -- 拉取失败时回滚到这份数据，避免一次网络故障让防护退回内置规则。
            CREATE TABLE IF NOT EXISTS rule_feed_packages (
                feed         TEXT PRIMARY KEY,
                payload      TEXT NOT NULL,
                version      TEXT,
                fetched_at   INTEGER NOT NULL,
                shadow_until INTEGER NOT NULL DEFAULT 0,
                signature_ok INTEGER NOT NULL DEFAULT 0,
                rule_count   INTEGER NOT NULL DEFAULT 0
            );

            -- 流量分钟聚合。控制台的 24 小时视图读内存，历史报表读这里。
            CREATE TABLE IF NOT EXISTS traffic_minutes (
                minute          INTEGER NOT NULL,
                app             TEXT NOT NULL,
                requests        INTEGER NOT NULL,
                pv              INTEGER NOT NULL,
                blocked         INTEGER NOT NULL,
                status_4xx      INTEGER NOT NULL,
                status_5xx      INTEGER NOT NULL,
                unique_ips      INTEGER NOT NULL,
                unique_visitors INTEGER NOT NULL,
                -- 明细快照（状态码分布、Top、来源 IP），用于重启后补齐控制台 24 小时视图
                detail          TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (minute, app)
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_minute ON traffic_minutes(minute);

            -- 每天的去重集合。分钟独立 IP 相加会重复，日报/周报必须按天去重。
            CREATE TABLE IF NOT EXISTS traffic_unique (
                day   INTEGER NOT NULL,
                app   TEXT NOT NULL,
                kind  TEXT NOT NULL,
                hash  TEXT NOT NULL,
                PRIMARY KEY (day, app, kind, hash)
            ) WITHOUT ROWID;
            "#,
        )?;

        // 老库补列：SQLite 没有 `ADD COLUMN IF NOT EXISTS`，只能先查 table_info。
        // 事件表在 v0.2 之后新增了请求方法 / 查询串 / UA / 规则名，
        // 直接 ALTER 失败会让升级后整个服务起不来，所以必须容错。
        for (column, decl) in [
            ("request_id", "TEXT NOT NULL DEFAULT ''"),
            ("method", "TEXT NOT NULL DEFAULT ''"),
            ("query", "TEXT NOT NULL DEFAULT ''"),
            ("ua", "TEXT NOT NULL DEFAULT ''"),
            ("rule_names", "TEXT NOT NULL DEFAULT ''"),
        ] {
            ensure_column(&conn, "events", column, decl);
        }
        // 流量分钟表同理：detail 是后加的列，老库必须能平滑升级。
        ensure_column(&conn, "traffic_minutes", "detail", "TEXT NOT NULL DEFAULT ''");
        Ok(())
    }

    // ============================================================
    // 封禁
    // ============================================================

    /// 写入或更新一条封禁。
    pub fn upsert_ban(&self, record: &BanRecord, now: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            r#"
            INSERT INTO bans (ip, until, offenses, score, reason, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
            ON CONFLICT(ip) DO UPDATE SET
                until      = excluded.until,
                offenses   = excluded.offenses,
                score      = excluded.score,
                reason     = excluded.reason,
                updated_at = excluded.updated_at
            "#,
            params![
                record.ip,
                record.until,
                record.offenses,
                record.score,
                record.reason,
                now
            ],
        )?;
        Ok(())
    }

    /// 加载所有未过期的封禁。
    pub fn load_active_bans(&self, now: i64) -> Result<Vec<BanRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT ip, until, offenses, score, reason, created_at
             FROM bans WHERE until > ?1 ORDER BY until DESC",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            Ok(BanRecord {
                ip: row.get(0)?,
                until: row.get(1)?,
                offenses: row.get(2)?,
                score: row.get(3)?,
                reason: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 删除一条封禁（手动解封）。
    pub fn delete_ban(&self, ip: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute("DELETE FROM bans WHERE ip = ?1", params![ip])?;
        Ok(n > 0)
    }

    /// 清理已过期的封禁记录，返回删除条数。
    pub fn cleanup_bans(&self, now: i64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute("DELETE FROM bans WHERE until <= ?1", params![now])?;
        Ok(n)
    }

    /// 封禁总数（含已过期）。
    pub fn ban_count(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM bans", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    // ============================================================
    // 事件
    // ============================================================

    /// 写入一条事件。
    pub fn insert_event(&self, event: &Event) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            r#"
            INSERT INTO events (ts, kind, client_ip, app, path, rules, score, action,
                                request_id, method, query, ua, rule_names)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                event.ts,
                event.kind.as_str(),
                event.client_ip,
                event.app,
                event.path,
                event.rules,
                event.score,
                event.action,
                event.request_id,
                event.method,
                event.query,
                event.user_agent,
                event.rule_names
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// 最近的若干条事件（按时间倒序）。
    pub fn recent_events(&self, limit: usize) -> Result<Vec<Event>, StoreError> {
        let (events, _) = self.query_events(&EventFilter {
            limit,
            ..Default::default()
        })?;
        Ok(events)
    }

    /// 按条件查询事件，返回 (当前页, 总数)。
    ///
    /// 用 `(?1 IS NULL OR col = ?1)` 的模式做可选条件：参数个数固定，
    /// 不需要动态拼 SQL，也就不会有拼接注入的风险。
    pub fn query_events(&self, f: &EventFilter) -> Result<(Vec<Event>, usize), StoreError> {
        self.with_conn(|conn| {
            let total: i64 = conn.query_row(
                r#"
                SELECT COUNT(*) FROM events
                WHERE (?1 IS NULL OR kind = ?1)
                  AND (?2 IS NULL OR client_ip = ?2)
                  AND (?3 IS NULL OR action = ?3)
                  AND (?4 IS NULL OR ts >= ?4)
                  AND (?5 IS NULL OR app = ?5)
                  AND (?6 IS NULL OR ts <= ?6)
                  AND (?7 IS NULL OR path LIKE '%' || ?7 || '%')
                  AND (?8 IS NULL OR path LIKE '%' || ?8 || '%'
                       OR rules LIKE '%' || ?8 || '%'
                       OR rule_names LIKE '%' || ?8 || '%'
                       OR ua LIKE '%' || ?8 || '%'
                       OR request_id LIKE '%' || ?8 || '%'
                       OR client_ip LIKE '%' || ?8 || '%')
                "#,
                params![
                    f.kind.as_deref(),
                    f.ip.as_deref(),
                    f.action.as_deref(),
                    f.since,
                    f.app.as_deref(),
                    f.until,
                    f.path.as_deref(),
                    f.q.as_deref(),
                ],
                |r| r.get(0),
            )?;

            let mut stmt = conn.prepare(
                r#"
                SELECT id, ts, kind, client_ip, app, path, rules, score, action,
                       request_id, method, query, ua, rule_names
                FROM events
                WHERE (?1 IS NULL OR kind = ?1)
                  AND (?2 IS NULL OR client_ip = ?2)
                  AND (?3 IS NULL OR action = ?3)
                  AND (?4 IS NULL OR ts >= ?4)
                  AND (?5 IS NULL OR app = ?5)
                  AND (?6 IS NULL OR ts <= ?6)
                  AND (?7 IS NULL OR path LIKE '%' || ?7 || '%')
                  AND (?8 IS NULL OR path LIKE '%' || ?8 || '%'
                       OR rules LIKE '%' || ?8 || '%'
                       OR rule_names LIKE '%' || ?8 || '%'
                       OR ua LIKE '%' || ?8 || '%'
                       OR request_id LIKE '%' || ?8 || '%'
                       OR client_ip LIKE '%' || ?8 || '%')
                ORDER BY ts DESC, id DESC
                LIMIT ?9 OFFSET ?10
                "#,
            )?;
            let rows = stmt.query_map(
                params![
                    f.kind.as_deref(),
                    f.ip.as_deref(),
                    f.action.as_deref(),
                    f.since,
                    f.app.as_deref(),
                    f.until,
                    f.path.as_deref(),
                    f.q.as_deref(),
                    f.limit as i64,
                    f.offset as i64
                ],
                |row| {
                    Ok(Event {
                        id: row.get(0)?,
                        ts: row.get(1)?,
                        kind: EventKind::parse_kind(&row.get::<_, String>(2)?),
                        client_ip: row.get(3)?,
                        app: row.get(4)?,
                        path: row.get(5)?,
                        rules: row.get(6)?,
                        score: row.get(7)?,
                        action: row.get(8)?,
                        request_id: row.get(9)?,
                        method: row.get(10)?,
                        query: row.get(11)?,
                        user_agent: row.get(12)?,
                        rule_names: row.get(13)?,
                    })
                },
            )?;

            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok((out, total as usize))
        })
    }

    /// 按小时聚合事件量，返回 `(小时起点, 总数, 拦截数)`，只含 `since` 之后。
    pub fn hourly_event_counts(&self, since: i64) -> Result<Vec<(i64, usize, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (ts / 3600) * 3600 AS bucket,
                       COUNT(*),
                       SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END)
                FROM events
                WHERE ts >= ?1
                GROUP BY bucket
                ORDER BY bucket
                "#,
            )?;
            let rows = stmt.query_map(params![since], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? as usize,
                    r.get::<_, i64>(2)? as usize,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 取一段时间内（检测 + 限流）事件命中的规则串，用于分类统计。
    pub fn event_rule_strings(&self, since: i64, limit: usize) -> Result<Vec<String>, StoreError> {
        self.event_rule_strings_between(since, i64::MAX, limit)
    }

    /// 同上，但带右边界，供按天生成的报告使用。
    pub fn event_rule_strings_between(
        &self,
        since: i64,
        until: i64,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT rules FROM events
                WHERE ts >= ?1 AND ts < ?2 AND kind IN ('detect', 'ratelimit') AND rules <> ''
                ORDER BY ts DESC
                LIMIT ?3
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, limit as i64], |r| r.get(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 按事件类型统计，返回 `(类型, 条数)`，按条数倒序。
    ///
    /// `action` 传 `Some("block")` 时只统计被拦截的事件。
    pub fn event_kind_counts(
        &self,
        since: i64,
        until: i64,
        action: Option<&str>,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT kind, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR action = ?3)
                GROUP BY kind ORDER BY COUNT(*) DESC
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, action], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 事件趋势：按固定宽度与类型聚合，返回 `(桶起点, 类型, 条数)`。
    pub fn event_series_by_kind(
        &self,
        since: i64,
        until: i64,
        group_secs: i64,
    ) -> Result<Vec<(i64, String, usize)>, StoreError> {
        let group = group_secs.max(60);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (ts / ?3) * ?3 AS bucket, kind, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2
                GROUP BY bucket, kind ORDER BY bucket
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, group], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as usize,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 事件趋势总量：按固定宽度聚合为 `(桶起点, 总数, 拦截数)`。
    pub fn event_series_counts(
        &self,
        since: i64,
        until: i64,
        group_secs: i64,
    ) -> Result<Vec<(i64, usize, usize)>, StoreError> {
        let group = group_secs.max(60);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (ts / ?3) * ?3 AS bucket, COUNT(*),
                       SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END)
                FROM events
                WHERE ts >= ?1 AND ts < ?2
                GROUP BY bucket ORDER BY bucket
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, group], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? as usize,
                    r.get::<_, i64>(2)? as usize,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 时间范围内去重来源 IP 数。
    pub fn event_ip_count(
        &self,
        since: i64,
        until: i64,
        action: Option<&str>,
    ) -> Result<usize, StoreError> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                r#"
                SELECT COUNT(DISTINCT client_ip) FROM events
                WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR action = ?3)
                  AND client_ip <> ''
                "#,
                params![since, until, action],
                |r| r.get(0),
            )?;
            Ok(n as usize)
        })
    }

    /// 来源 IP 排行，`(ip, 事件数)`，按事件数倒序。
    pub fn top_event_ips(
        &self,
        since: i64,
        until: i64,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT client_ip, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR action = ?3)
                  AND client_ip <> ''
                GROUP BY client_ip ORDER BY COUNT(*) DESC, client_ip
                LIMIT ?4
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, action, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 应用维度的事件排行，`(应用, 事件数)`，按事件数倒序。
    pub fn event_app_counts(
        &self,
        since: i64,
        until: i64,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT app, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR action = ?3)
                  AND app <> ''
                GROUP BY app ORDER BY COUNT(*) DESC, app
                LIMIT ?4
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, action, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 处置动作分布，`(动作, 条数)`。
    pub fn event_action_counts(
        &self,
        since: i64,
        until: i64,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT action, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2
                GROUP BY action ORDER BY COUNT(*) DESC
                "#,
            )?;
            let rows = stmt.query_map(params![since, until], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// ACL 命中原因分布（黑名单、CIDR、方法限制等），返回 `(原因, 条数)`。
    pub fn acl_reason_counts(
        &self,
        since: i64,
        until: i64,
        limit: usize,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT rules, COUNT(*) FROM events
                WHERE ts >= ?1 AND ts < ?2 AND kind = 'acl' AND rules <> ''
                GROUP BY rules ORDER BY COUNT(*) DESC, rules
                LIMIT ?3
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 事件总数。
    pub fn event_count(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// 删除早于 `before` 的事件，返回删除条数。用于控制库体积。
    pub fn prune_events(&self, before: i64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute("DELETE FROM events WHERE ts < ?1", params![before])?;
        Ok(n)
    }

    // ============================================================
    // 流量统计
    // ============================================================

    /// 写入一批分钟聚合与去重集合。重复写入同一分钟会覆盖计数，
    /// 去重集合用 `INSERT OR IGNORE`，因此重放安全。
    pub fn save_traffic(&self, rows: &[TrafficBucketRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = conn.transaction()?;
        for row in rows {
            tx.execute(
                r#"
                INSERT INTO traffic_minutes
                    (minute, app, requests, pv, blocked, status_4xx, status_5xx,
                     unique_ips, unique_visitors, detail)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(minute, app) DO UPDATE SET
                    requests        = excluded.requests,
                    pv              = excluded.pv,
                    blocked         = excluded.blocked,
                    status_4xx      = excluded.status_4xx,
                    status_5xx      = excluded.status_5xx,
                    unique_ips      = excluded.unique_ips,
                    unique_visitors = excluded.unique_visitors,
                    detail          = excluded.detail
                "#,
                params![
                    row.minute,
                    row.app,
                    row.requests as i64,
                    row.pv as i64,
                    row.blocked as i64,
                    row.status_4xx as i64,
                    row.status_5xx as i64,
                    row.unique_ips as i64,
                    row.unique_visitors as i64,
                    row.detail,
                ],
            )?;

            let day = row.minute - row.minute.rem_euclid(86_400);
            for ip in &row.ips {
                tx.execute(
                    "INSERT OR IGNORE INTO traffic_unique (day, app, kind, hash)
                     VALUES (?1, ?2, 'ip', ?3)",
                    params![day, row.app, format!("{ip:032x}")],
                )?;
            }
            for v in &row.visitors {
                tx.execute(
                    "INSERT OR IGNORE INTO traffic_unique (day, app, kind, hash)
                     VALUES (?1, ?2, 'visitor', ?3)",
                    params![day, row.app, format!("{v:016x}")],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// 汇总一段时间。独立 IP / 访客按天去重，跨天范围也能得到正确值。
    pub fn traffic_totals(
        &self,
        since: i64,
        until: i64,
        app: Option<&str>,
    ) -> Result<TrafficTotals, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let (requests, pv, blocked, status_4xx, status_5xx): (i64, i64, i64, i64, i64) = conn
            .query_row(
                r#"
                SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(pv), 0),
                       COALESCE(SUM(blocked), 0), COALESCE(SUM(status_4xx), 0),
                       COALESCE(SUM(status_5xx), 0)
                FROM traffic_minutes
                WHERE minute >= ?1 AND minute < ?2 AND (?3 IS NULL OR app = ?3)
                "#,
                params![since, until, app],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;

        let day_start = since - since.rem_euclid(86_400);
        let distinct = |kind: &str| -> Result<u64, StoreError> {
            conn.query_row(
                r#"
                SELECT COUNT(DISTINCT hash) FROM traffic_unique
                WHERE day >= ?1 AND day <= ?2 AND kind = ?3
                  AND (?4 IS NULL OR app = ?4)
                "#,
                params![day_start, until, kind, app],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
            .map_err(StoreError::from)
        };

        Ok(TrafficTotals {
            requests: requests as u64,
            pv: pv as u64,
            blocked: blocked as u64,
            status_4xx: status_4xx as u64,
            status_5xx: status_5xx as u64,
            unique_ips: distinct("ip")?,
            unique_visitors: distinct("visitor")?,
        })
    }

    /// 读取分钟明细，用于控制台把「重启前已落库的分钟」与「当前进程内存」合并。
    ///
    /// 只返回聚合与明细 JSON，不返回 `traffic_unique` 的哈希集合——合并时
    /// 明细里已经带了来源 IP 与访客哈希。
    pub fn traffic_details(
        &self,
        since: i64,
        until: i64,
        app: Option<&str>,
    ) -> Result<Vec<TrafficDetailRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT minute, app, requests, pv, blocked,
                       status_4xx, status_5xx, unique_ips, unique_visitors, detail
                FROM traffic_minutes
                WHERE minute >= ?1 AND minute < ?2 AND (?3 IS NULL OR app = ?3)
                ORDER BY minute
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, app], |r| {
                Ok(TrafficDetailRow {
                    minute: r.get(0)?,
                    app: r.get(1)?,
                    requests: r.get::<_, i64>(2)? as u64,
                    pv: r.get::<_, i64>(3)? as u64,
                    blocked: r.get::<_, i64>(4)? as u64,
                    status_4xx: r.get::<_, i64>(5)? as u64,
                    status_5xx: r.get::<_, i64>(6)? as u64,
                    unique_ips: r.get::<_, i64>(7)? as u64,
                    unique_visitors: r.get::<_, i64>(8)? as u64,
                    detail: r.get(9)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 按固定宽度聚合趋势，供日报/大屏历史曲线使用。
    pub fn traffic_series(
        &self,
        since: i64,
        until: i64,
        app: Option<&str>,
        group_secs: i64,
    ) -> Result<Vec<TrafficPoint>, StoreError> {
        let group = group_secs.max(60);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (minute / ?4) * ?4 AS bucket,
                       COALESCE(SUM(requests), 0),
                       COALESCE(SUM(blocked), 0)
                FROM traffic_minutes
                WHERE minute >= ?1 AND minute < ?2 AND (?3 IS NULL OR app = ?3)
                GROUP BY bucket ORDER BY bucket
                "#,
            )?;
            let rows = stmt.query_map(params![since, until, app, group], |r| {
                Ok(TrafficPoint {
                    ts: r.get(0)?,
                    requests: r.get::<_, i64>(1)? as u64,
                    blocked: r.get::<_, i64>(2)? as u64,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 有流量数据的日期列表（按天聚合，倒序）。
    pub fn traffic_days(&self, since: i64, limit: usize) -> Result<Vec<TrafficDay>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (minute / 86400) * 86400 AS day,
                       COALESCE(SUM(requests), 0),
                       COALESCE(SUM(blocked), 0)
                FROM traffic_minutes
                WHERE minute >= ?1
                GROUP BY day ORDER BY day DESC LIMIT ?2
                "#,
            )?;
            let rows = stmt.query_map(params![since, limit as i64], |r| {
                Ok(TrafficDay {
                    day: r.get(0)?,
                    requests: r.get::<_, i64>(1)? as u64,
                    blocked: r.get::<_, i64>(2)? as u64,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 每天每类事件数，供报表列表与安全态势历史使用。
    pub fn daily_event_counts(&self, since: i64) -> Result<Vec<(i64, String, usize)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT (ts / 86400) * 86400 AS day, kind, COUNT(*)
                FROM events WHERE ts >= ?1
                GROUP BY day, kind ORDER BY day DESC
                "#,
            )?;
            let rows = stmt.query_map(params![since], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as usize,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 删除早于 `before` 的流量聚合与去重集合。
    pub fn prune_traffic(&self, before: i64) -> Result<usize, StoreError> {
        let day = before - before.rem_euclid(86_400);
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute(
            "DELETE FROM traffic_minutes WHERE minute < ?1",
            params![before],
        )?;
        conn.execute("DELETE FROM traffic_unique WHERE day < ?1", params![day])?;
        Ok(n)
    }

    // ============================================================
    // 订阅状态
    // ============================================================

    /// 保存订阅上次成功导入的条目（用于变更幅度校验）。
    pub fn save_feed_state(&self, name: &str, entries: &str, now: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            r#"
            INSERT INTO feed_state (name, entries, updated_at) VALUES (?1, ?2, ?3)
            ON CONFLICT(name) DO UPDATE SET
                entries = excluded.entries,
                updated_at = excluded.updated_at
            "#,
            params![name, entries, now],
        )?;
        Ok(())
    }

    /// 读取订阅上次的条目。
    pub fn load_feed_state(&self, name: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare("SELECT entries FROM feed_state WHERE name = ?1")?;
        let mut rows = stmt.query(params![name])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// 上次成功导入的时间。用于判断订阅是否到期，避免每次重载都联网拉取。
    pub fn feed_state_updated_at(&self, name: &str) -> Result<Option<i64>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare("SELECT updated_at FROM feed_state WHERE name = ?1")?;
        let mut rows = stmt.query(params![name])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    // ============================================================
    // 规则包缓存
    // ============================================================

    pub fn save_rule_feed_package(&self, pkg: &RuleFeedPackageRow) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            r#"
            INSERT INTO rule_feed_packages
                (feed, payload, version, fetched_at, shadow_until, signature_ok, rule_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(feed) DO UPDATE SET
                payload = excluded.payload,
                version = excluded.version,
                fetched_at = excluded.fetched_at,
                shadow_until = excluded.shadow_until,
                signature_ok = excluded.signature_ok,
                rule_count = excluded.rule_count
            "#,
            params![
                pkg.feed,
                pkg.payload,
                pkg.version,
                pkg.fetched_at,
                pkg.shadow_until,
                pkg.signature_ok as i64,
                pkg.rule_count as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_rule_feed_package(
        &self,
        feed: &str,
    ) -> Result<Option<RuleFeedPackageRow>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT feed, payload, version, fetched_at, shadow_until, signature_ok, rule_count \
             FROM rule_feed_packages WHERE feed = ?1",
        )?;
        let mut rows = stmt.query(params![feed])?;
        match rows.next()? {
            Some(row) => Ok(Some(RuleFeedPackageRow {
                feed: row.get(0)?,
                payload: row.get(1)?,
                version: row.get(2)?,
                fetched_at: row.get(3)?,
                shadow_until: row.get(4)?,
                signature_ok: row.get::<_, i64>(5)? != 0,
                rule_count: row.get::<_, i64>(6)? as usize,
            })),
            None => Ok(None),
        }
    }

    pub fn delete_rule_feed_package(&self, feed: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute(
            "DELETE FROM rule_feed_packages WHERE feed = ?1",
            params![feed],
        )?;
        Ok(n > 0)
    }
}

/// 缓存的规则包。`payload` 是验签通过的原始规则文档，不含签名头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFeedPackageRow {
    pub feed: String,
    pub payload: String,
    pub version: Option<String>,
    pub fetched_at: i64,
    pub shadow_until: i64,
    pub signature_ok: bool,
    pub rule_count: usize,
}

/// 确保表里有某一列；没有就补上。
///
/// 查不到表结构时按「已存在」处理：宁可少补一列，也不要因为 ALTER 报错让启动失败。
fn ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) {
    let sql = format!("PRAGMA table_info({table})");
    let exists = conn
        .prepare(&sql)
        .and_then(|mut stmt| {
            let names = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>();
            Ok(names.iter().any(|n| n == column))
        })
        .unwrap_or(true);
    if !exists {
        let _ = conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_memory().expect("内存库应可用")
    }

    const NOW: i64 = 1_700_000_000;

    fn ban(ip: &str, until: i64) -> BanRecord {
        BanRecord {
            ip: ip.to_string(),
            until,
            offenses: 1,
            score: 50,
            reason: "sqli".to_string(),
            created_at: NOW,
        }
    }

    #[test]
    fn schema_is_created() {
        let s = store();
        assert_eq!(s.ban_count().unwrap(), 0);
        assert_eq!(s.event_count().unwrap(), 0);
    }

    #[test]
    fn upsert_and_load_ban() {
        let s = store();
        s.upsert_ban(&ban("203.0.113.9", NOW + 300), NOW).unwrap();

        let bans = s.load_active_bans(NOW).unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "203.0.113.9");
        assert_eq!(bans[0].until, NOW + 300);
    }

    #[test]
    fn expired_ban_not_loaded() {
        let s = store();
        s.upsert_ban(&ban("203.0.113.9", NOW - 1), NOW).unwrap();
        assert!(s.load_active_bans(NOW).unwrap().is_empty());
        // 但仍存在库里，等待清理
        assert_eq!(s.ban_count().unwrap(), 1);
    }

    #[test]
    fn upsert_updates_existing() {
        let s = store();
        s.upsert_ban(&ban("203.0.113.9", NOW + 300), NOW).unwrap();

        let mut second = ban("203.0.113.9", NOW + 1800);
        second.offenses = 2;
        s.upsert_ban(&second, NOW + 10).unwrap();

        let bans = s.load_active_bans(NOW).unwrap();
        assert_eq!(bans.len(), 1, "同一 IP 不应产生两条记录");
        assert_eq!(bans[0].offenses, 2);
        assert_eq!(bans[0].until, NOW + 1800);
    }

    #[test]
    fn delete_ban_works() {
        let s = store();
        s.upsert_ban(&ban("203.0.113.9", NOW + 300), NOW).unwrap();
        assert!(s.delete_ban("203.0.113.9").unwrap());
        assert!(!s.delete_ban("203.0.113.9").unwrap(), "重复删除返回 false");
        assert_eq!(s.ban_count().unwrap(), 0);
    }

    #[test]
    fn cleanup_removes_expired() {
        let s = store();
        s.upsert_ban(&ban("203.0.113.1", NOW - 10), NOW).unwrap();
        s.upsert_ban(&ban("203.0.113.2", NOW + 300), NOW).unwrap();

        let removed = s.cleanup_bans(NOW).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(s.ban_count().unwrap(), 1);
    }

    #[test]
    fn insert_and_query_events() {
        let s = store();
        let e = Event::new(NOW, EventKind::Detect, "203.0.113.9")
            .with_app("nas")
            .with_path("/api")
            .with_rules("sqli-union-select")
            .with_score(50)
            .with_action("block");
        let id = s.insert_event(&e).unwrap();
        assert!(id > 0);

        let events = s.recent_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Detect);
        assert_eq!(events[0].client_ip, "203.0.113.9");
        assert_eq!(events[0].score, 50);
    }

    #[test]
    fn events_ordered_newest_first() {
        let s = store();
        for i in 0..3 {
            s.insert_event(&Event::new(NOW + i, EventKind::Detect, "1.2.3.4"))
                .unwrap();
        }
        let events = s.recent_events(10).unwrap();
        assert_eq!(events[0].ts, NOW + 2, "最新事件应排在最前");
    }

    #[test]
    fn recent_events_respects_limit() {
        let s = store();
        for _ in 0..5 {
            s.insert_event(&Event::new(NOW, EventKind::Ban, "1.2.3.4"))
                .unwrap();
        }
        assert_eq!(s.recent_events(2).unwrap().len(), 2);
    }

    #[test]
    fn prune_events_removes_old() {
        let s = store();
        s.insert_event(&Event::new(NOW - 100, EventKind::Detect, "1.1.1.1"))
            .unwrap();
        s.insert_event(&Event::new(NOW, EventKind::Detect, "2.2.2.2"))
            .unwrap();

        let removed = s.prune_events(NOW - 50).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(s.event_count().unwrap(), 1);
    }

    // ============================================================
    // 事件查询
    // ============================================================

    fn seed_events(s: &Store) {
        // 5 条：3 detect（2 block + 1 log）、2 ban
        for (i, (kind, ip, action)) in [
            (EventKind::Detect, "1.1.1.1", "block"),
            (EventKind::Detect, "1.1.1.1", "log"),
            (EventKind::Detect, "2.2.2.2", "block"),
            (EventKind::Ban, "1.1.1.1", "ban"),
            (EventKind::Ban, "3.3.3.3", "ban"),
        ]
        .iter()
        .enumerate()
        {
            s.insert_event(&Event::new(NOW + i as i64, *kind, *ip).with_action(*action))
                .unwrap();
        }
    }

    #[test]
    fn query_events_paginates() {
        let s = store();
        seed_events(&s);

        let (page1, total) = s
            .query_events(&EventFilter {
                limit: 2,
                offset: 0,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 5, "总数应是全部，不是当前页");
        assert_eq!(page1.len(), 2);
        // 最新的在前
        assert!(page1[0].ts > page1[1].ts);

        let (page3, _) = s
            .query_events(&EventFilter {
                limit: 2,
                offset: 4,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page3.len(), 1, "最后一页只剩 1 条");
    }

    #[test]
    fn query_events_filters_by_kind() {
        let s = store();
        seed_events(&s);

        let (detect, total) = s
            .query_events(&EventFilter {
                limit: 50,
                kind: Some("detect".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 3);
        assert!(detect.iter().all(|e| e.kind == EventKind::Detect));

        let (bans, total) = s
            .query_events(&EventFilter {
                limit: 50,
                kind: Some("ban".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 2);
        assert!(bans.iter().all(|e| e.kind == EventKind::Ban));
    }

    #[test]
    fn query_events_filters_by_ip() {
        let s = store();
        seed_events(&s);

        let (events, total) = s
            .query_events(&EventFilter {
                limit: 50,
                ip: Some("1.1.1.1".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 3);
        assert!(events.iter().all(|e| e.client_ip == "1.1.1.1"));
    }

    #[test]
    fn query_events_filters_by_action() {
        let s = store();
        seed_events(&s);

        let (_, total) = s
            .query_events(&EventFilter {
                limit: 50,
                action: Some("block".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 2);
    }

    #[test]
    fn query_events_combines_filters() {
        let s = store();
        seed_events(&s);

        let (events, total) = s
            .query_events(&EventFilter {
                limit: 50,
                kind: Some("detect".to_string()),
                ip: Some("1.1.1.1".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 2, "detect + 1.1.1.1 应命中 2 条");
        assert!(events
            .iter()
            .all(|e| e.kind == EventKind::Detect && e.client_ip == "1.1.1.1"));
    }

    #[test]
    fn query_events_since_filter() {
        let s = store();
        seed_events(&s);

        // 只要 NOW+3 之后的事件
        let (_, total) = s
            .query_events(&EventFilter {
                limit: 50,
                since: Some(NOW + 3),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 2);
    }

    #[test]
    fn query_events_empty_result() {
        let s = store();
        seed_events(&s);

        let (events, total) = s
            .query_events(&EventFilter {
                limit: 50,
                ip: Some("9.9.9.9".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn feed_state_roundtrip() {
        let s = store();
        assert!(s.load_feed_state("chaitin").unwrap().is_none());

        s.save_feed_state("chaitin", "1.2.3.0/24\n4.5.6.0/24", NOW)
            .unwrap();
        let loaded = s.load_feed_state("chaitin").unwrap().unwrap();
        assert!(loaded.contains("1.2.3.0/24"));
    }

    #[test]
    fn feed_state_overwrites() {
        let s = store();
        s.save_feed_state("g", "old", NOW).unwrap();
        s.save_feed_state("g", "new", NOW + 10).unwrap();
        assert_eq!(s.load_feed_state("g").unwrap().unwrap(), "new");
    }

    #[test]
    fn ban_survives_reopen() {
        // 用临时文件验证真正的持久化
        let dir = std::env::temp_dir();
        let path = dir.join(format!("homewaf-store-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let s = Store::open(&path).unwrap();
            s.upsert_ban(&ban("203.0.113.9", NOW + 300), NOW).unwrap();
        }
        {
            let s = Store::open(&path).unwrap();
            let bans = s.load_active_bans(NOW).unwrap();
            assert_eq!(bans.len(), 1, "重开后封禁应还在");
            assert_eq!(bans[0].ip, "203.0.113.9");
        }

        let _ = std::fs::remove_file(&path);
    }

    // ============================================================
    // 配置读写（DB 作为唯一配置源）
    // ============================================================

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct DemoApp {
        name: String,
        port: u16,
        tags: Vec<String>,
    }

    fn demo(name: &str, port: u16) -> DemoApp {
        DemoApp {
            name: name.to_string(),
            port,
            tags: vec!["a".into(), "b".into()],
        }
    }

    #[test]
    fn application_roundtrip() {
        let s = store();
        let app = demo("nas", 8080);
        s.upsert_application("nas", "nas.home.lan", true, &app, NOW)
            .unwrap();

        let apps: Vec<DemoApp> = s.list_applications().unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0], app);
        assert_eq!(s.app_count().unwrap(), 1);
    }

    #[test]
    fn application_upsert_updates() {
        let s = store();
        s.upsert_application("nas", "nas.home.lan", true, &demo("v1", 80), NOW)
            .unwrap();
        s.upsert_application("nas", "nas.home.lan", true, &demo("v2", 81), NOW + 10)
            .unwrap();

        let apps: Vec<DemoApp> = s.list_applications().unwrap();
        assert_eq!(apps.len(), 1, "同 id 不应产生两行");
        assert_eq!(apps[0].name, "v2");
    }

    #[test]
    fn certificate_crud_and_default() {
        let s = store();
        let a = s
            .insert_certificate("a", "CERT-A", "KEY-A", "a.test", 0, 100, NOW)
            .unwrap();
        let b = s
            .insert_certificate("b", "CERT-B", "KEY-B", "b.test", 0, 200, NOW)
            .unwrap();
        assert_eq!(s.list_certificates().unwrap().len(), 2);

        assert!(s
            .update_certificate(
                a,
                "a2",
                "CERT-A2",
                "KEY-A2",
                "a.test,www.a.test",
                0,
                300,
                NOW + 1
            )
            .unwrap());
        let got = s.get_certificate(a).unwrap().unwrap();
        assert_eq!(got.name, "a2");
        assert_eq!(got.domains, "a.test,www.a.test");
        assert_eq!(got.not_after, 300);

        assert!(s.set_default_certificate(b).unwrap());
        let certs = s.list_certificates().unwrap();
        assert!(certs.iter().find(|c| c.id == b).unwrap().is_default);
        assert!(!certs.iter().find(|c| c.id == a).unwrap().is_default);

        assert!(s.delete_certificate(b).unwrap());
        assert!(!s.delete_certificate(b).unwrap());
        assert_eq!(s.list_certificates().unwrap().len(), 1);
    }

    #[test]
    fn application_delete() {
        let s = store();
        s.upsert_application("a", "a.home.lan", true, &demo("a", 80), NOW)
            .unwrap();
        assert!(s.delete_application("a").unwrap());
        assert!(!s.delete_application("a").unwrap());
        assert_eq!(s.app_count().unwrap(), 0);
    }

    #[test]
    fn applications_ordered_by_id() {
        let s = store();
        for id in ["c", "a", "b"] {
            s.upsert_application(id, &format!("{id}.lan"), true, &demo(id, 80), NOW)
                .unwrap();
        }
        let ids: Vec<String> = s
            .list_applications::<DemoApp>()
            .unwrap()
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"], "顺序应稳定");
    }

    #[test]
    fn settings_roundtrip() {
        let s = store();
        assert!(s.get_setting::<DemoApp>("protection").unwrap().is_none());

        s.set_setting("protection", &demo("p", 1), NOW).unwrap();
        let got: DemoApp = s.get_setting("protection").unwrap().unwrap();
        assert_eq!(got, demo("p", 1));
        assert_eq!(s.list_setting_keys().unwrap(), vec!["protection"]);
    }

    #[test]
    fn settings_overwrite() {
        let s = store();
        s.set_setting("k", &demo("v1", 1), NOW).unwrap();
        s.set_setting("k", &demo("v2", 2), NOW + 5).unwrap();
        let got: DemoApp = s.get_setting("k").unwrap().unwrap();
        assert_eq!(got.name, "v2");
    }

    #[test]
    fn acl_rule_roundtrip() {
        let s = store();
        let rule = AclRuleRow {
            id: "block-x".to_string(),
            cidr: "203.0.113.0/24".to_string(),
            action: "deny".to_string(),
            scope: Some("nas".to_string()),
            expires_at: Some(NOW + 3600),
            note: Some("测试".to_string()),
        };
        s.upsert_acl_rule(&rule, NOW).unwrap();

        let rules = s.list_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], rule);
        assert_eq!(s.acl_rule_count().unwrap(), 1);
    }

    #[test]
    fn acl_rule_delete() {
        let s = store();
        let rule = AclRuleRow {
            id: "r".to_string(),
            cidr: "1.2.3.4/32".to_string(),
            action: "deny".to_string(),
            scope: None,
            expires_at: None,
            note: None,
        };
        s.upsert_acl_rule(&rule, NOW).unwrap();
        assert!(s.delete_acl_rule("r").unwrap());
        assert_eq!(s.acl_rule_count().unwrap(), 0);
    }

    #[test]
    fn ip_group_roundtrip() {
        let s = store();
        s.upsert_ip_group("chaitin", true, &demo("g", 1), NOW)
            .unwrap();

        let groups = s.list_ip_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "chaitin");
        assert!(groups[0].enabled);
        let body: DemoApp = serde_json::from_str(&groups[0].body).unwrap();
        assert_eq!(body.name, "g");
    }

    #[test]
    fn corrupted_json_returns_decode_error() {
        let s = store();
        // 直接塞坏数据
        s.with_conn(|conn| {
            conn.execute(
                "INSERT INTO applications (id, primary_domain, enabled, body, created_at, updated_at)
                 VALUES ('x', 'x.lan', 1, 'not-json', 0, 0)",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let result = s.list_applications::<DemoApp>();
        assert!(result.is_err(), "损坏数据应报错而不是 panic");
    }

    #[test]
    fn hourly_counts_group_by_bucket() {
        let s = store();
        let hour = 3_600;
        for (ts, action) in [(NOW, "block"), (NOW + 10, "log"), (NOW + hour, "block")] {
            s.insert_event(&Event::new(ts, EventKind::Detect, "1.1.1.1").with_action(action))
                .unwrap();
        }

        let buckets = s.hourly_event_counts(NOW).unwrap();
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].1, 2);
        assert_eq!(buckets[0].2, 1);
        assert_eq!(buckets[1].1, 1);
        assert_eq!(buckets[1].2, 1);
    }

    #[test]
    fn rule_strings_include_detect_and_ratelimit_only() {
        let s = store();
        s.insert_event(&Event::new(NOW, EventKind::Detect, "1.1.1.1").with_rules("xss-script-tag"))
            .unwrap();
        s.insert_event(&Event::new(NOW + 1, EventKind::RateLimit, "1.1.1.1").with_rules("cc-ip"))
            .unwrap();
        s.insert_event(&Event::new(NOW + 2, EventKind::Acl, "1.1.1.1").with_rules("deny"))
            .unwrap();

        let rules = s.event_rule_strings(NOW, 100).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r == "xss-script-tag"));
        assert!(rules.iter().any(|r| r == "cc-ip"));
    }

    #[test]
    fn security_aggregates_by_kind_and_ip() {
        let s = store();
        s.insert_event(&Event::new(NOW, EventKind::Detect, "1.1.1.1").with_action("block"))
            .unwrap();
        s.insert_event(&Event::new(NOW + 1, EventKind::Detect, "1.1.1.1").with_action("log"))
            .unwrap();
        s.insert_event(&Event::new(NOW + 2, EventKind::Challenge, "2.2.2.2").with_action("block"))
            .unwrap();
        s.insert_event(
            &Event::new(NOW + 3, EventKind::Acl, "2.2.2.2").with_rules("黑名单规则 ban-1"),
        )
        .unwrap();

        let kinds = s.event_kind_counts(NOW, NOW + 10, None).unwrap();
        assert_eq!(kinds.iter().find(|(k, _)| k == "detect").unwrap().1, 2);

        let blocked = s.event_kind_counts(NOW, NOW + 10, Some("block")).unwrap();
        assert_eq!(blocked.iter().map(|(_, n)| n).sum::<usize>(), 2);

        let ips = s.top_event_ips(NOW, NOW + 10, None, 10).unwrap();
        assert_eq!(ips[0], ("1.1.1.1".to_string(), 2));
        assert_eq!(s.event_ip_count(NOW, NOW + 10, None).unwrap(), 2);
        assert_eq!(s.event_ip_count(NOW, NOW + 10, Some("block")).unwrap(), 2);

        let series = s.event_series_by_kind(NOW, NOW + 10, 60).unwrap();
        assert!(series.iter().any(|(_, kind, _)| kind == "challenge"));

        let acl = s.acl_reason_counts(NOW, NOW + 10, 10).unwrap();
        assert_eq!(acl[0], ("黑名单规则 ban-1".to_string(), 1));

        assert!(s
            .event_rule_strings_between(NOW, NOW + 2, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rule_feed_package_roundtrip() {
        let s = store();
        assert!(s.load_rule_feed_package("official").unwrap().is_none());

        let pkg = RuleFeedPackageRow {
            feed: "official".to_string(),
            payload: r#"{"rules":[]}"#.to_string(),
            version: Some("2026.10.1".to_string()),
            fetched_at: NOW,
            shadow_until: NOW + 3_600,
            signature_ok: true,
            rule_count: 17,
        };
        s.save_rule_feed_package(&pkg).unwrap();

        let loaded = s.load_rule_feed_package("official").unwrap().unwrap();
        assert_eq!(loaded, pkg);
    }

    #[test]
    fn rule_feed_package_overwrite_and_delete() {
        let s = store();
        let mut pkg = RuleFeedPackageRow {
            feed: "feed".to_string(),
            payload: "old".to_string(),
            version: Some("1".to_string()),
            fetched_at: NOW,
            shadow_until: 0,
            signature_ok: false,
            rule_count: 1,
        };
        s.save_rule_feed_package(&pkg).unwrap();

        pkg.payload = "new".to_string();
        pkg.signature_ok = true;
        pkg.rule_count = 2;
        s.save_rule_feed_package(&pkg).unwrap();
        let loaded = s.load_rule_feed_package("feed").unwrap().unwrap();
        assert_eq!(loaded.payload, "new");
        assert!(loaded.signature_ok);
        assert_eq!(loaded.rule_count, 2);

        assert!(s.delete_rule_feed_package("feed").unwrap());
        assert!(s.load_rule_feed_package("feed").unwrap().is_none());
        assert!(!s.delete_rule_feed_package("feed").unwrap());
    }

    fn traffic_row(minute: i64, app: &str, requests: u64) -> TrafficBucketRow {
        TrafficBucketRow {
            minute,
            app: app.to_string(),
            requests,
            pv: requests.saturating_sub(1),
            blocked: 1,
            status_4xx: 2,
            status_5xx: 0,
            unique_ips: 2,
            unique_visitors: 2,
            ips: vec![1, 2],
            visitors: vec![11, 12],
            detail: String::new(),
        }
    }

    #[test]
    fn traffic_totals_and_filters() {
        let s = store();
        let minute = NOW - NOW.rem_euclid(60);
        s.save_traffic(&[
            traffic_row(minute, "nas", 10),
            traffic_row(minute, "blog", 5),
            traffic_row(minute + 60, "nas", 3),
        ])
        .unwrap();

        let all = s.traffic_totals(minute - 60, minute + 120, None).unwrap();
        assert_eq!(all.requests, 18);
        assert_eq!(all.blocked, 3);
        assert_eq!(all.status_4xx, 6);
        assert_eq!(all.unique_ips, 2, "同一 IP 跨分钟/应用按天去重");
        assert_eq!(all.unique_visitors, 2);

        let nas = s
            .traffic_totals(minute - 60, minute + 120, Some("nas"))
            .unwrap();
        assert_eq!(nas.requests, 13);
        assert_eq!(nas.unique_ips, 2);
    }

    #[test]
    fn traffic_series_groups_and_days() {
        let s = store();
        let minute = NOW - NOW.rem_euclid(60);
        s.save_traffic(&[
            traffic_row(minute, "nas", 4),
            traffic_row(minute + 60, "nas", 6),
            traffic_row(minute + 120, "blog", 8),
        ])
        .unwrap();

        let points = s.traffic_series(minute, minute + 180, None, 3_600).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ts, minute - minute.rem_euclid(3_600));
        assert_eq!(points[0].requests, 18);

        let days = s.traffic_days(minute - 86_400, 10).unwrap();
        assert_eq!(days.len(), 1);
        assert_eq!(days[0].requests, 18);
    }

    #[test]
    fn traffic_details_round_trip() {
        let s = store();
        let minute = NOW - NOW.rem_euclid(60);
        let mut row = traffic_row(minute, "nas", 10);
        row.detail = r#"{"statuses":{"200":9,"403":1}}"#.to_string();
        s.save_traffic(&[row]).unwrap();

        let rows = s.traffic_details(minute, minute + 60, Some("nas")).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 10);
        assert_eq!(rows[0].detail, r#"{"statuses":{"200":9,"403":1}}"#);

        // 重复写入同一分钟会覆盖明细，而不是累加
        let mut again = traffic_row(minute, "nas", 4);
        again.detail = r#"{"statuses":{"200":4}}"#.to_string();
        s.save_traffic(&[again]).unwrap();
        let rows = s.traffic_details(minute, minute + 60, None).unwrap();
        assert_eq!(rows[0].requests, 4);
        assert!(rows[0].detail.contains(r#""200":4"#));
    }

    #[test]
    fn traffic_replay_is_idempotent() {
        let s = store();
        let minute = NOW - NOW.rem_euclid(60);
        let row = traffic_row(minute, "nas", 10);
        s.save_traffic(std::slice::from_ref(&row)).unwrap();
        s.save_traffic(&[row]).unwrap();

        let totals = s.traffic_totals(minute, minute + 60, Some("nas")).unwrap();
        assert_eq!(totals.requests, 10);
        assert_eq!(totals.unique_ips, 2);
    }

    #[test]
    fn prune_traffic_removes_old_rows() {
        let s = store();
        let minute = NOW - NOW.rem_euclid(60);
        s.save_traffic(&[traffic_row(minute, "nas", 2)]).unwrap();
        assert_eq!(s.prune_traffic(minute + 60).unwrap(), 1);
        assert_eq!(
            s.traffic_totals(minute, minute + 60, None)
                .unwrap()
                .requests,
            0
        );
        // 去重集合按天保留，当天其余分钟的报表仍可正确去重
        assert_eq!(
            s.traffic_totals(minute, minute + 60, None)
                .unwrap()
                .unique_ips,
            2
        );
    }
}
