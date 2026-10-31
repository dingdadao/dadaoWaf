//! HomeWAF 配置模型与校验。
//!
//! ```no_run
//! use homewaf_config::load;
//!
//! let config = load("config.yaml").expect("配置无效");
//! println!("已加载 {} 个应用", config.applications.len());
//! ```
//!
//! 设计要点：
//! - 未知字段报错，不静默忽略（防止拼写错误导致配置失效）
//! - 所有字段有默认值
//! - 校验问题带字段路径，便于定位
//! - 三层覆盖：route > application > global

pub mod error;
pub mod model;
pub mod units;
pub mod validate;

use std::path::Path;

pub use error::{ConfigError, Severity, ValidationError};
pub use model::*;
pub use units::{Duration, Size};
pub use validate::{regex_test, validate, validate_domain, ValidationReport};

impl Config {
    /// 校验自身，返回报告（含 warning）。
    pub fn validate(&self) -> ValidationReport {
        validate(self)
    }
}

/// 仅解析，不做语义校验。
pub fn parse(input: &str) -> Result<Config, ConfigError> {
    let deserializer = serde_yaml::Deserializer::from_str(input);
    let config: Config = serde_path_to_error::deserialize(deserializer).map_err(|err| {
        let path = err.path().to_string();
        let inner = err.into_inner();
        let (line, column) = match inner.location() {
            Some(loc) => (Some(loc.line()), Some(loc.column())),
            None => (None, None),
        };
        // serde_yaml 的 message 末尾自带 " at line X column Y"，与结构化的位置重复，截掉。
        let mut message = inner.to_string();
        if let Some(idx) = message.find(" at line ") {
            message.truncate(idx);
        }
        ConfigError::Parse {
            path: if path.is_empty() { None } else { Some(path) },
            line,
            column,
            message,
        }
    })?;
    Ok(config)
}

/// 解析 + 校验。有 error 时返回 `ConfigError::Validation`。
pub fn from_str(input: &str) -> Result<Config, ConfigError> {
    let config = parse(input)?;
    let report = validate(&config);
    if report.has_errors() {
        let mut all = report.errors;
        all.extend(report.warnings);
        return Err(ConfigError::Validation(all));
    }
    Ok(config)
}

/// 解析 + 校验，同时把 warning 返回给调用方。
pub fn from_str_with_warnings(input: &str) -> Result<(Config, Vec<ValidationError>), ConfigError> {
    let config = parse(input)?;
    let report = validate(&config);
    if report.has_errors() {
        let mut all = report.errors;
        all.extend(report.warnings);
        return Err(ConfigError::Validation(all));
    }
    Ok((config, report.warnings))
}

/// 从文件加载。
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(ConfigError::Io)?;
    from_str(&content)
}

/// 从文件加载并返回 warning。
pub fn load_with_warnings(
    path: impl AsRef<Path>,
) -> Result<(Config, Vec<ValidationError>), ConfigError> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(ConfigError::Io)?;
    from_str_with_warnings(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
applications:
  - id: nas
    name: NAS
    domains:
      primary: nas.home.lan
    upstreams:
      - addr: 192.168.1.5
        port: 5000
"#;

    #[test]
    fn parses_minimal_config() {
        let config = from_str(MINIMAL).unwrap();
        assert_eq!(config.applications.len(), 1);
        assert_eq!(config.applications[0].id, "nas");
        // 默认值生效
        assert_eq!(config.limits.queue_capacity, 1024);
        assert_eq!(config.limits.max_body_size.as_bytes(), 10 * 1024 * 1024);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let bad = r#"
applications:
  - id: nas
    name: NAS
    domains:
      primary: nas.home.lan
    upstreams:
      - addr: 192.168.1.5
        port: 5000
    unknow_field: true
"#;
        let err = from_str(bad).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknow_field") || msg.contains("unknown"),
            "实际: {msg}"
        );
    }

    #[test]
    fn sites_alias_works() {
        let cfg = r#"
sites:
  - id: nas
    name: NAS
    domains:
      primary: nas.home.lan
    upstreams:
      - addr: 192.168.1.5
        port: 5000
"#;
        let config = from_str(cfg).unwrap();
        assert_eq!(config.applications.len(), 1);
    }

    #[test]
    fn duration_and_size_parse() {
        let cfg = format!(
            r#"
limits:
  queue_timeout: 200ms
  request_timeout: 30s
  max_body_size: 2GB
{MINIMAL}"#
        );
        let config = from_str(&cfg).unwrap();
        assert_eq!(config.limits.queue_timeout.as_millis(), 200);
        assert_eq!(config.limits.request_timeout.as_secs(), 30);
        assert_eq!(
            config.limits.max_body_size.as_bytes(),
            2u64 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn validation_error_is_reported() {
        let bad = r#"
applications:
  - id: nas
    name: NAS
    domains:
      primary: "bad domain"
    upstreams:
      - addr: 192.168.1.5
        port: 5000
"#;
        let err = from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(errors) => {
                assert!(!errors.is_empty());
                assert!(errors.iter().any(|e| e.path.contains("domains.primary")));
            }
            other => panic!("期望校验错误，实际: {other}"),
        }
    }

    #[test]
    fn warnings_are_returned_not_fatal() {
        // 关掉私有网段自动可信后，仍没有网段/订阅/密钥 → 应有「没有可信来源」警告
        let cfg = format!(
            r#"
real_ip:
  enabled: true
  trust_private_source: false
{MINIMAL}"#
        );
        let (_, warnings) = from_str_with_warnings(&cfg).unwrap();
        assert!(warnings.iter().any(|w| w.path.contains("trusted_proxies")));
    }
}
