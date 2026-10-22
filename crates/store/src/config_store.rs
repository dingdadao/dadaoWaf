//! 配置读写：应用、全局设置、ACL 规则、IP 组订阅。
//!
//! **数据库是配置的唯一来源**。进程启动后不再读任何配置文件，
//! 引导参数（DB 路径、监听地址）来自命令行。
//!
//! 应用与订阅的完整结构序列化成 JSON 存一行：家庭场景应用数量 < 50，
//! 全量加载进内存即可，拆列会让"加一个字段就要改表"变成常态。

use rusqlite::params;
use serde::{de::DeserializeOwned, Serialize};

use crate::StoreError;

/// 一条 ACL 规则的原始行。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AclRuleRow {
    pub id: String,
    pub cidr: String,
    pub action: String,
    pub scope: Option<String>,
    pub expires_at: Option<i64>,
    pub note: Option<String>,
}

/// 一条 IP 组订阅的原始行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpGroupRow {
    pub name: String,
    pub enabled: bool,
    /// 订阅配置的 JSON
    pub body: String,
}

/// 一条检测白名单规则。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WhitelistRow {
    pub id: String,
    /// 生效应用；`None` 表示全部
    pub app: Option<String>,
    /// 路径前缀；`None` 表示不限
    pub path: Option<String>,
    /// 只豁免这条规则；`None` 表示跳过全部检测
    pub rule_id: Option<String>,
    pub note: Option<String>,
}

/// 一张 TLS 证书。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRow {
    pub id: i64,
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    /// 逗号分隔的域名（含 SAN 与 CN）
    pub domains: String,
    pub not_before: i64,
    pub not_after: i64,
    pub is_default: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl super::Store {
    // ============================================================
    // 应用
    // ============================================================

    /// 列出所有应用（按 id 排序保证顺序稳定）。
    pub fn list_applications<T: DeserializeOwned>(&self) -> Result<Vec<T>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT body FROM applications ORDER BY id")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                let text = r?;
                let parsed = serde_json::from_str(&text).map_err(|e| {
                    StoreError::Decode(format!("应用数据损坏：{e}"))
                })?;
                out.push(parsed);
            }
            Ok(out)
        })
    }

    /// 写入或更新一个应用。
    pub fn upsert_application<T: Serialize>(
        &self,
        id: &str,
        primary_domain: &str,
        enabled: bool,
        body: &T,
        now: i64,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(body)
            .map_err(|e| StoreError::Encode(format!("序列化应用失败：{e}")))?;
        self.with_conn(|conn| {
            conn.execute(
                r#"
                INSERT INTO applications (id, primary_domain, enabled, body, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                ON CONFLICT(id) DO UPDATE SET
                    primary_domain = excluded.primary_domain,
                    enabled        = excluded.enabled,
                    body           = excluded.body,
                    updated_at     = excluded.updated_at
                "#,
                params![id, primary_domain, enabled as i32, json, now],
            )?;
            Ok(())
        })
    }

    /// 删除一个应用。
    pub fn delete_application(&self, id: &str) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM applications WHERE id = ?1", params![id])?;
            Ok(n > 0)
        })
    }

    pub fn app_count(&self) -> Result<usize, StoreError> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM applications", [], |r| r.get(0))?;
            Ok(n as usize)
        })
    }

    // ============================================================
    // 全局设置
    // ============================================================

    /// 读一段设置。缺失或损坏时返回 `None`（用默认值继续）。
    pub fn get_setting<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
            let mut rows = stmt.query(params![key])?;
            match rows.next()? {
                Some(row) => {
                    let text: String = row.get(0)?;
                    match serde_json::from_str(&text) {
                        Ok(v) => Ok(Some(v)),
                        Err(e) => {
                            tracing::warn!(key, error = %e, "设置项解析失败，使用默认值");
                            Ok(None)
                        }
                    }
                }
                None => Ok(None),
            }
        })
    }

    /// 写一段设置。
    pub fn set_setting<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        now: i64,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(value)
            .map_err(|e| StoreError::Encode(format!("序列化设置失败：{e}")))?;
        self.with_conn(|conn| {
            conn.execute(
                r#"
                INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                "#,
                params![key, json, now],
            )?;
            Ok(())
        })
    }

    /// 列出所有设置键。
    pub fn list_setting_keys(&self) -> Result<Vec<String>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT key FROM settings ORDER BY key")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 删除一段设置。用于写入失败时回滚。
    pub fn delete_setting(&self, key: &str) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
            Ok(n > 0)
        })
    }

    // ============================================================
    // ACL 规则
    // ============================================================

    pub fn list_acl_rules(&self) -> Result<Vec<AclRuleRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, cidr, action, scope, expires_at, note
                 FROM acl_rules ORDER BY id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AclRuleRow {
                    id: row.get(0)?,
                    cidr: row.get(1)?,
                    action: row.get(2)?,
                    scope: row.get(3)?,
                    expires_at: row.get(4)?,
                    note: row.get(5)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn upsert_acl_rule(&self, rule: &AclRuleRow, now: i64) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            conn.execute(
                r#"
                INSERT INTO acl_rules (id, cidr, action, scope, expires_at, note, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(id) DO UPDATE SET
                    cidr = excluded.cidr,
                    action = excluded.action,
                    scope = excluded.scope,
                    expires_at = excluded.expires_at,
                    note = excluded.note
                "#,
                params![
                    rule.id,
                    rule.cidr,
                    rule.action,
                    rule.scope,
                    rule.expires_at,
                    rule.note,
                    now
                ],
            )?;
            Ok(())
        })
    }

    pub fn delete_acl_rule(&self, id: &str) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM acl_rules WHERE id = ?1", params![id])?;
            Ok(n > 0)
        })
    }

    pub fn acl_rule_count(&self) -> Result<usize, StoreError> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM acl_rules", [], |r| r.get(0))?;
            Ok(n as usize)
        })
    }

    // ============================================================
    // IP 组订阅
    // ============================================================

    pub fn list_ip_groups(&self) -> Result<Vec<IpGroupRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT name, enabled, body FROM ip_groups ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok(IpGroupRow {
                    name: row.get(0)?,
                    enabled: row.get::<_, i32>(1)? != 0,
                    body: row.get(2)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn upsert_ip_group<T: Serialize>(
        &self,
        name: &str,
        enabled: bool,
        body: &T,
        now: i64,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(body)
            .map_err(|e| StoreError::Encode(format!("序列化订阅失败：{e}")))?;
        self.with_conn(|conn| {
            conn.execute(
                r#"
                INSERT INTO ip_groups (name, enabled, body, updated_at) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(name) DO UPDATE SET
                    enabled = excluded.enabled,
                    body = excluded.body,
                    updated_at = excluded.updated_at
                "#,
                params![name, enabled as i32, json, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_ip_group(&self, name: &str) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM ip_groups WHERE name = ?1", params![name])?;
            Ok(n > 0)
        })
    }

    // ============================================================
    // 检测白名单
    // ============================================================

    pub fn list_whitelist(&self) -> Result<Vec<WhitelistRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, app, path, rule_id, note FROM detect_whitelist ORDER BY id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(WhitelistRow {
                    id: row.get(0)?,
                    app: row.get(1)?,
                    path: row.get(2)?,
                    rule_id: row.get(3)?,
                    note: row.get(4)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn upsert_whitelist(&self, row: &WhitelistRow, now: i64) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            conn.execute(
                r#"
                INSERT INTO detect_whitelist (id, app, path, rule_id, note, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(id) DO UPDATE SET
                    app     = excluded.app,
                    path    = excluded.path,
                    rule_id = excluded.rule_id,
                    note    = excluded.note
                "#,
                params![row.id, row.app, row.path, row.rule_id, row.note, now],
            )?;
            Ok(())
        })
    }

    pub fn delete_whitelist(&self, id: &str) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM detect_whitelist WHERE id = ?1", params![id])?;
            Ok(n > 0)
        })
    }

    pub fn whitelist_count(&self) -> Result<usize, StoreError> {
        self.with_conn(|conn| {
            let n: i64 =
                conn.query_row("SELECT COUNT(*) FROM detect_whitelist", [], |r| r.get(0))?;
            Ok(n as usize)
        })
    }

    // ============================================================
    // 网页防篡改基线
    // ============================================================

    /// 用新扫描结果整体替换某个应用的基线。
    pub fn replace_tamper_baseline(
        &self,
        app_id: &str,
        entries: &[(String, u64, String)],
        now: i64,
    ) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "DELETE FROM tamper_baselines WHERE app_id = ?1",
                params![app_id],
            )?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO tamper_baselines (app_id, path, size, digest, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for (path, size, digest) in entries {
                    stmt.execute(params![app_id, path, *size as i64, digest, now])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// 读取某个应用的基线：`(路径, 大小, SHA-256)`。
    pub fn tamper_baseline(&self, app_id: &str) -> Result<Vec<(String, u64, String)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, digest FROM tamper_baselines WHERE app_id = ?1 ORDER BY path",
            )?;
            let rows = stmt.query_map(params![app_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// 读取全部基线，用于启动时构建运行时索引：`(应用, 路径, 大小, SHA-256)`。
    pub fn all_tamper_baselines(&self) -> Result<Vec<(String, String, u64, String)>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT app_id, path, size, digest FROM tamper_baselines ORDER BY app_id, path")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn tamper_baseline_count(&self, app_id: &str) -> Result<usize, StoreError> {
        self.with_conn(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM tamper_baselines WHERE app_id = ?1",
                params![app_id],
                |r| r.get(0),
            )?;
            Ok(n as usize)
        })
    }

    // ============================================================
    // TLS 证书
    // ============================================================

    fn cert_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CertificateRow> {
        Ok(CertificateRow {
            id: row.get(0)?,
            name: row.get(1)?,
            cert_pem: row.get(2)?,
            key_pem: row.get(3)?,
            domains: row.get(4)?,
            not_before: row.get(5)?,
            not_after: row.get(6)?,
            is_default: row.get::<_, i64>(7)? != 0,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }

    const CERT_COLS: &str =
        "id, name, cert_pem, key_pem, domains, not_before, not_after, is_default, created_at, updated_at";

    pub fn list_certificates(&self) -> Result<Vec<CertificateRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {} FROM certificates ORDER BY id",
                Self::CERT_COLS
            ))?;
            let rows = stmt.query_map([], Self::cert_from_row)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    pub fn get_certificate(&self, id: i64) -> Result<Option<CertificateRow>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {} FROM certificates WHERE id = ?1",
                Self::CERT_COLS
            ))?;
            let mut rows = stmt.query_map(params![id], Self::cert_from_row)?;
            match rows.next() {
                Some(r) => Ok(Some(r?)),
                None => Ok(None),
            }
        })
    }

    /// 新增证书，返回自增 id。
    #[allow(clippy::too_many_arguments)]
    pub fn insert_certificate(
        &self,
        name: &str,
        cert_pem: &str,
        key_pem: &str,
        domains: &str,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<i64, StoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO certificates
                 (name, cert_pem, key_pem, domains, not_before, not_after, is_default, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7)",
                params![name, cert_pem, key_pem, domains, not_before, not_after, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// 覆盖已有证书。`id` 不存在时返回 `false`。
    #[allow(clippy::too_many_arguments)]
    pub fn update_certificate(
        &self,
        id: i64,
        name: &str,
        cert_pem: &str,
        key_pem: &str,
        domains: &str,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE certificates
                 SET name = ?2, cert_pem = ?3, key_pem = ?4, domains = ?5,
                     not_before = ?6, not_after = ?7, updated_at = ?8
                 WHERE id = ?1",
                params![id, name, cert_pem, key_pem, domains, not_before, not_after, now],
            )?;
            Ok(n > 0)
        })
    }

    pub fn delete_certificate(&self, id: i64) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let n = conn.execute("DELETE FROM certificates WHERE id = ?1", params![id])?;
            Ok(n > 0)
        })
    }

    /// 把指定证书设为默认证书（其它证书取消默认）。
    pub fn set_default_certificate(&self, id: i64) -> Result<bool, StoreError> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute("UPDATE certificates SET is_default = 0", [])?;
            let n = tx.execute(
                "UPDATE certificates SET is_default = 1 WHERE id = ?1",
                params![id],
            )?;
            tx.commit()?;
            Ok(n > 0)
        })
    }
}
