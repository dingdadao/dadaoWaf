//! 订阅源拉取。
//!
//! 只做"取回文本"这一件事，解析与护栏在 [`crate::feed`] 里。
//! 分开的原因：拉取需要网络，测试时想替换成固定内容，解析和护栏则应该能纯函数测试。

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

/// 拉取失败原因。
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("请求失败：{0}")]
    Request(String),
    #[error("响应体超过上限 {limit} 字节")]
    TooLarge { limit: usize },
    #[error("读取响应失败：{0}")]
    Io(String),
}

/// 拉取一个文本资源。
///
/// `max_bytes` 是硬上限：订阅源被投毒时可能返回超大响应体，先读满上限
/// 再判断，避免内存被打爆。
pub fn fetch(
    url: &str,
    timeout: Duration,
    max_bytes: usize,
    headers: &BTreeMap<String, String>,
) -> Result<String, FetchError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build();
    let agent: ureq::Agent = config.into();

    let mut request = agent.get(url);
    for (k, v) in headers {
        request = request.header(k.as_str(), v.as_str());
    }

    let response = request
        .call()
        .map_err(|e| FetchError::Request(e.to_string()))?;

    let mut reader = response.into_body().into_reader();
    let mut buf = Vec::new();
    // 多读 1 字节用于判断是否超限
    let read = reader
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Io(e.to_string()))?;

    if read > max_bytes {
        return Err(FetchError::TooLarge { limit: max_bytes });
    }

    String::from_utf8(buf).map_err(|e| FetchError::Io(format!("响应不是合法 UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_large_error_message_contains_limit() {
        let e = FetchError::TooLarge { limit: 1024 };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn request_error_is_displayable() {
        let e = FetchError::Request("connection refused".into());
        assert!(e.to_string().contains("connection refused"));
    }
}
