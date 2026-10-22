//! 配置错误类型。

use std::fmt;

/// 配置加载或校验失败。
#[derive(Debug)]
pub enum ConfigError {
    /// 文件读取失败
    Io(std::io::Error),
    /// YAML 语法或字段类型错误
    Parse {
        path: Option<String>,
        line: Option<usize>,
        column: Option<usize>,
        message: String,
    },
    /// 语义校验失败（可能多条）
    Validation(Vec<ValidationError>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "读取配置文件失败: {e}"),
            ConfigError::Parse {
                path,
                line,
                column,
                message,
            } => {
                let loc = match (line, column) {
                    (Some(l), Some(c)) => format!("第 {l} 行第 {c} 列"),
                    (Some(l), None) => format!("第 {l} 行"),
                    _ => "未知位置".to_string(),
                };
                match path {
                    Some(p) if !p.is_empty() => write!(f, "{loc} [{p}] {message}"),
                    _ => write!(f, "{loc} {message}"),
                }
            }
            ConfigError::Validation(errors) => {
                writeln!(f, "配置校验失败，共 {} 处问题：", errors.len())?;
                for e in errors {
                    writeln!(f, "  {} {}", e.severity.marker(), e)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn marker(self) -> &'static str {
        match self {
            Severity::Error => "error  ",
            Severity::Warning => "warning",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => f.write_str("error"),
            Severity::Warning => f.write_str("warning"),
        }
    }
}

/// 单条校验问题，带字段路径便于定位。
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// 字段路径，如 `applications[0].upstreams[1].port`
    pub path: String,
    pub message: String,
    pub severity: Severity,
}

impl ValidationError {
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
            severity: Severity::Error,
        }
    }

    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
            severity: Severity::Warning,
        }
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}
