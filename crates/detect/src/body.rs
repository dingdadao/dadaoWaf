//! 请求体检测的辅助逻辑。
//!
//! Pingora 的 body 是流式的：`request_body_filter` 在每个 chunk **转发前**调用。
//! 这给了一个关键的窗口——在这个钩子里返回错误时，当前 chunk 还没发给上游。
//!
//! 但前面的 chunk 已经发出去了，所以"完整缓冲后再检测"在流式模型里做不到。
//! 策略是：
//! - 逐块累积，每次累积后对**整体**做检测
//! - 一旦命中就中断，此时最多泄露已经转发的部分
//! - 大多数 POST 攻击的 body 很小（一个 chunk 就完整），实际影响很小

/// 默认最多累积多少字节用于检测。超过后停止累积，避免内存被大 body 拖垮。
pub const DEFAULT_MAX_INSPECT_BYTES: usize = 64 * 1024;

/// 判断该 Content-Type 是否值得做内容检测。
///
/// 二进制类型（图片、视频、文件上传）跳过：它们不会承载 SQL 注入，
/// 强行解码既浪费 CPU 又会产生大量误报。
pub fn should_inspect_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        // 没有 Content-Type 时保守起见检测（可能是简单的 POST 表单）
        return true;
    };

    let ct = ct.trim().to_ascii_lowercase();

    // multipart/form-data 也做内容检测：头部字段名、文件名是纯文本，
    // PHP2Shell 等攻击的指纹（如 PHP_SESSION_UPLOAD_PROGRESS）就藏在字段名里。
    // 二进制文件内容由 BodyBuffer::as_str 的 UTF-8 校验兜底，非文本直接跳过。
    if ct.starts_with("application/octet-stream") {
        return false;
    }
    // 媒体与压缩包
    for prefix in [
        "image/",
        "video/",
        "audio/",
        "font/",
        "application/zip",
        "application/gzip",
        "application/pdf",
        "application/x-protobuf",
    ] {
        if ct.starts_with(prefix) {
            return false;
        }
    }

    true
}

/// 请求体累积器。
#[derive(Debug)]
pub struct BodyBuffer {
    buf: Vec<u8>,
    max: usize,
    /// 是否因为超限而丢弃了后续内容
    truncated: bool,
}

impl BodyBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
            truncated: false,
        }
    }

    /// 追加一块数据。返回 true 表示本次有新内容进入缓冲区。
    pub fn push(&mut self, chunk: &[u8]) -> bool {
        if self.truncated {
            return false;
        }

        let remaining = self.max.saturating_sub(self.buf.len());
        if remaining == 0 {
            self.truncated = true;
            return false;
        }

        if chunk.len() <= remaining {
            self.buf.extend_from_slice(chunk);
        } else {
            self.buf.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
        }
        true
    }

    /// 转成字符串。非 UTF-8 内容返回 None（不做检测）。
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.buf).ok()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl Default for BodyBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_INSPECT_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_text_content_types() {
        assert!(should_inspect_content_type(Some("application/json")));
        assert!(should_inspect_content_type(Some(
            "application/x-www-form-urlencoded"
        )));
        assert!(should_inspect_content_type(Some("text/plain")));
        assert!(should_inspect_content_type(Some("application/xml")));
        assert!(should_inspect_content_type(None));
    }

    #[test]
    fn skips_binary_content_types() {
        // multipart/form-data 也要检测：PHP2Shell 等攻击指纹就藏在字段名里
        assert!(should_inspect_content_type(Some(
            "multipart/form-data; boundary=x"
        )));
        assert!(!should_inspect_content_type(Some(
            "application/octet-stream"
        )));
        assert!(!should_inspect_content_type(Some("image/png")));
        assert!(!should_inspect_content_type(Some("video/mp4")));
        assert!(!should_inspect_content_type(Some("application/zip")));
    }

    #[test]
    fn content_type_is_case_insensitive() {
        assert!(!should_inspect_content_type(Some("IMAGE/PNG")));
        assert!(should_inspect_content_type(Some("APPLICATION/JSON")));
    }

    #[test]
    fn buffer_accumulates() {
        let mut b = BodyBuffer::new(1024);
        assert!(b.push(b"hello "));
        assert!(b.push(b"world"));
        assert_eq!(b.as_str(), Some("hello world"));
        assert!(!b.is_truncated());
    }

    #[test]
    fn buffer_truncates_at_max() {
        let mut b = BodyBuffer::new(10);
        assert!(b.push(b"0123456789abc"));
        assert_eq!(b.len(), 10);
        assert!(b.is_truncated());
        // 超限后不再接收
        assert!(!b.push(b"more"));
        assert_eq!(b.len(), 10);
    }

    #[test]
    fn buffer_rejects_non_utf8() {
        let mut b = BodyBuffer::new(64);
        b.push(&[0xff, 0xfe]);
        assert!(b.as_str().is_none(), "非 UTF-8 应返回 None 而不是 panic");
    }

    #[test]
    fn empty_buffer() {
        let b = BodyBuffer::new(64);
        assert!(b.is_empty());
        assert_eq!(b.as_str(), Some(""));
    }

    #[test]
    fn exact_fit_does_not_mark_truncated() {
        let mut b = BodyBuffer::new(5);
        b.push(b"12345");
        assert_eq!(b.len(), 5);
        assert!(!b.is_truncated(), "正好填满不算截断");
    }
}
