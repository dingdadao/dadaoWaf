//! 多证书 SNI 终结。
//!
//! 证书不再写死在配置文件里：库里每个应用可以绑定一张证书，
//! 未绑定的域名回落到「默认证书」。解析器持有 [`SharedState`]，
//! 因此控制台改完证书后热重载即可生效，不需要重启进程。

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use homewaf_config::{Application, TlsConfig, TlsMode};
use homewaf_store::CertificateRow;
use pingora::tls::sign::CertifiedKey;
use pingora::tls::{ClientHello, ResolvesServerCert};
use rustls::crypto::ring::default_provider;

use crate::reload::SharedState;

/// 按 SNI 索引的证书集合。
#[derive(Default)]
pub struct CertMap {
    /// 精确域名
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// 通配符域名（如 `*.example.com`）
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// 兜底证书：SNI 没命中时使用
    default: Option<Arc<CertifiedKey>>,
}

impl CertMap {
    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.exact.is_empty() && self.wildcard.is_empty()
    }

    /// 按 SNI 选择证书。`None`（客户端没发 SNI）也走默认证书。
    pub fn resolve(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = server_name.and_then(normalize_domain) else {
            return self.default.clone();
        };
        if let Some(key) = self.exact.get(&name) {
            return Some(key.clone());
        }
        // TLS 通配符只匹配一级：`*.example.com` 命中 `a.example.com`，
        // 不命中 `a.b.example.com`。取第一个点之后的部分拼成通配符。
        if let Some(pos) = name.find('.') {
            let wildcard = format!("*{}", &name[pos..]);
            if let Some(key) = self.wildcard.get(&wildcard) {
                return Some(key.clone());
            }
        }
        self.default.clone()
    }

    /// 合并进去重后的域名条目数，仅用于日志与状态展示。
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len() + usize::from(self.default.is_some())
    }

    fn insert(&mut self, domain: &str, key: Arc<CertifiedKey>) {
        let Some(d) = normalize_domain(domain) else {
            return;
        };
        if let Some(rest) = d.strip_prefix("*.") {
            self.wildcard
                .entry(format!("*.{rest}"))
                .or_insert(key.clone());
        } else {
            self.exact.entry(d).or_insert(key);
        }
    }
}

/// 从 PEM 文本加载证书与私钥，并校验两者匹配。
pub fn load_certified_key(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("解析证书 PEM 失败：{e}"))?;
    if certs.is_empty() {
        return Err("证书 PEM 中没有找到证书".to_string());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("解析私钥 PEM 失败：{e}"))?
        .ok_or_else(|| "私钥 PEM 中没有找到私钥".to_string())?;

    CertifiedKey::from_der(certs, key, &default_provider())
        .map(Arc::new)
        .map_err(|e| format!("证书与私钥不匹配或格式不受支持：{e}"))
}

/// 构建证书映射。
///
/// - 库里有证书：按证书声明的域名建索引，`is_default` 作为兜底。
/// - 应用显式绑定（`tls.mode = manual` 且 `cert_id` 命中）覆盖应用域名。
/// - 一张库证书都没有时，回退到全局 `tls.cert` / `tls.key` 文件证书。
pub fn build_cert_map(
    certs: &[CertificateRow],
    applications: &[Application],
    global: &TlsConfig,
) -> Result<CertMap, String> {
    let mut map = CertMap::default();
    let mut by_id: HashMap<i64, Arc<CertifiedKey>> = HashMap::new();

    for row in certs {
        let key = load_certified_key(&row.cert_pem, &row.key_pem)
            .map_err(|e| format!("证书「{}」加载失败：{e}", row.name))?;
        by_id.insert(row.id, key.clone());
        for domain in row.domains.split(',') {
            map.insert(domain, key.clone());
        }
        if row.is_default {
            map.default = Some(key);
        }
    }

    // 应用绑定：manual 模式且证书存在时，用该证书覆盖应用域名
    for app in applications {
        if app.tls.mode != TlsMode::Manual {
            continue;
        }
        let Some(id) = app
            .tls
            .cert_id
            .as_deref()
            .and_then(|s| s.trim().parse::<i64>().ok())
        else {
            continue;
        };
        let Some(key) = by_id.get(&id).cloned() else {
            continue;
        };
        map.insert(&app.domains.primary, key.clone());
        for alias in &app.domains.aliases {
            map.insert(alias, key.clone());
        }
    }

    if map.default.is_none() {
        // 没标默认证书：优先用全局文件证书，其次用第一张证书记录
        if let Some(key) = load_global_cert(global)? {
            map.default = Some(key);
        } else {
            map.default = certs
                .first()
                .and_then(|row| by_id.get(&row.id))
                .cloned();
        }
    }

    Ok(map)
}

fn load_global_cert(global: &TlsConfig) -> Result<Option<Arc<CertifiedKey>>, String> {
    let (Some(cert_path), Some(key_path)) = (global.cert.as_deref(), global.key.as_deref()) else {
        return Ok(None);
    };
    if cert_path.trim().is_empty() || key_path.trim().is_empty() {
        return Ok(None);
    }
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("读取证书文件 {cert_path} 失败：{e}"))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| format!("读取私钥文件 {key_path} 失败：{e}"))?;
    load_certified_key(&cert_pem, &key_pem)
        .map(Some)
        .map_err(|e| format!("全局证书 {cert_path} / {key_path} 加载失败：{e}"))
}

/// TLS 握手时按 SNI 选证书的解析器。
///
/// 每次握手都读一次当前状态：证书更新只需要替换 `SharedState`，
/// 正在等待的监听器立刻用新证书。
pub struct SniResolver {
    state: SharedState,
}

impl SniResolver {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniResolver")
            .field("certs", &self.state.load().tls_certs.len())
            .finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.state
            .load()
            .tls_certs
            .resolve(client_hello.server_name())
    }
}

/// 归一化域名：去空白、去末尾的点、转小写。空串或非法输入返回 `None`。
fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.contains('/') || d.contains(':') || d.contains(char::is_whitespace) {
        return None;
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_variants() {
        assert_eq!(normalize_domain(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("bad/domain"), None);
    }

    #[test]
    fn empty_map_resolves_nothing() {
        let map = CertMap::default();
        assert!(map.is_empty());
        assert!(map.resolve(Some("a.example.com")).is_none());
        assert!(map.resolve(None).is_none());
    }

    /// 用 openssl 生成自签证书，用于验证解析与 SNI 选择。
    fn test_cert() -> (String, String) {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!(
            "homewaf-tls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=test.local",
                "-addext", "subjectAltName=DNS:test.local,DNS:*.test.local",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {
                let c = std::fs::read_to_string(&cert).unwrap();
                let k = std::fs::read_to_string(&key).unwrap();
                let _ = std::fs::remove_dir_all(&dir);
                (c, k)
            }
            _ => panic!("需要 openssl 生成测试证书"),
        }
    }

    #[test]
    fn loads_cert_and_matches_sni() {
        let (cert, key) = test_cert();
        let row = CertificateRow {
            id: 1,
            name: "test".into(),
            cert_pem: cert,
            key_pem: key,
            domains: "test.local,*.test.local".into(),
            not_before: 0,
            not_after: 0,
            is_default: true,
            created_at: 0,
            updated_at: 0,
        };
        let map = build_cert_map(&[row], &[], &TlsConfig::default()).unwrap();
        assert!(!map.is_empty());
        assert!(map.resolve(Some("test.local")).is_some());
        assert!(map.resolve(Some("a.test.local")).is_some(), "通配符应命中一级子域");
        assert!(map.resolve(Some("a.b.test.local")).is_some(), "未命中时回落默认证书");
        assert!(map.resolve(None).is_some(), "无 SNI 时用默认证书");
    }

    #[test]
    fn rejects_mismatched_key() {
        let (cert, _) = test_cert();
        let (_, other_key) = test_cert();
        let err = load_certified_key(&cert, &other_key).unwrap_err();
        assert!(err.contains("不匹配"), "应识别出证书与私钥不匹配：{err}");
    }
}
