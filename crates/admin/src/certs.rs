//! 证书管理辅助：PEM 解析、极简 multipart 解析。
//!
//! 不引入 `multer`：离线构建环境里没有这个包，而证书上传只会出现
//! 两三个小字段，按 boundary 切分足够可靠。

use serde::Serialize;
use x509_parser::extensions::GeneralName;

/// 从证书里解析出来的展示/索引信息。
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    /// 逗号分隔的域名（SAN 优先，没有 SAN 时取 CN）
    pub domains: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: String,
    pub serial: String,
}

/// 解析 PEM 证书的域名与有效期。
pub fn parse_cert(cert_pem: &str) -> Result<CertInfo, String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| format!("证书 PEM 解析失败：{e}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| format!("X.509 解析失败：{e}"))?;

    let mut domains: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(d) = name {
                let d = d.trim();
                if !d.is_empty() && !domains.iter().any(|x| x == d) {
                    domains.push(d.to_string());
                }
            }
        }
    }
    if domains.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                let s = s.trim();
                if !s.is_empty() {
                    domains.push(s.to_string());
                }
            }
        }
    }

    Ok(CertInfo {
        domains: domains.join(","),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
    })
}

/// 一个 multipart 表单字段。
#[derive(Debug)]
pub struct FormPart {
    pub name: String,
    pub filename: Option<String>,
    pub data: Vec<u8>,
}

impl FormPart {
    pub fn text(&self) -> Result<String, String> {
        String::from_utf8(self.data.clone())
            .map(|s| s.trim().to_string())
            .map_err(|_| format!("字段 {} 不是合法文本", self.name))
    }
}

/// 从 `Content-Type: multipart/form-data; boundary=...` 里取出 boundary。
pub fn boundary_from_content_type(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    if !lower.starts_with("multipart/form-data") {
        return None;
    }
    let idx = lower.find("boundary=")?;
    let raw = content_type[idx + "boundary=".len()..].trim();
    let boundary = if let Some(rest) = raw.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        raw.split(';').next().unwrap_or("").trim()
    };
    if boundary.is_empty() {
        None
    } else {
        Some(boundary.to_string())
    }
}

/// 解析 multipart 请求体。
pub fn parse_multipart(body: &[u8], boundary: &str) -> Result<Vec<FormPart>, String> {
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    let mut parts = Vec::new();

    let mut pos = find(body, marker, 0).ok_or_else(|| "multipart 格式错误：缺少 boundary".to_string())?;
    pos += marker.len();

    while pos < body.len() {
        // 关闭标记 `--boundary--`
        if body[pos..].starts_with(b"--") {
            break;
        }
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        }
        let start = pos;
        let end = find(body, marker, start)
            .ok_or_else(|| "multipart 格式错误：缺少结束 boundary".to_string())?;
        let mut chunk = &body[start..end];
        // boundary 前的 CRLF 属于分隔符，不属于内容
        if chunk.ends_with(b"\r\n") {
            chunk = &chunk[..chunk.len() - 2];
        }
        if let Some(hdr_end) = find(chunk, b"\r\n\r\n", 0) {
            let headers = &chunk[..hdr_end];
            let data = chunk[hdr_end + 4..].to_vec();
            if let Some(part) = parse_part(headers, data) {
                parts.push(part);
            }
        }
        pos = end + marker.len();
    }

    Ok(parts)
}

fn parse_part(headers: &[u8], data: Vec<u8>) -> Option<FormPart> {
    let text = String::from_utf8_lossy(headers);
    let mut name = String::new();
    let mut filename = None;
    for line in text.lines() {
        let line = line.trim();
        if !line.to_ascii_lowercase().starts_with("content-disposition:") {
            continue;
        }
        for item in line.split(';') {
            let item = item.trim();
            if let Some(v) = item.strip_prefix("name=") {
                name = v.trim_matches('"').to_string();
            } else if let Some(v) = item.strip_prefix("filename=") {
                let v = v.trim_matches('"').to_string();
                if !v.is_empty() {
                    filename = Some(v);
                }
            }
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(FormPart {
        name,
        filename,
        data,
    })
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boundary_variants() {
        assert_eq!(
            boundary_from_content_type("multipart/form-data; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            boundary_from_content_type("multipart/form-data; boundary=\"a b\"").as_deref(),
            Some("a b")
        );
        assert!(boundary_from_content_type("application/json").is_none());
    }

    #[test]
    fn parses_multipart_fields() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nmycert\r\n\
--X\r\nContent-Disposition: form-data; name=\"crt_file\"; filename=\"a.pem\"\r\n\
Content-Type: application/octet-stream\r\n\r\nCERTDATA\r\n--X--\r\n";
        let parts = parse_multipart(body, "X").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "name");
        assert_eq!(parts[0].text().unwrap(), "mycert");
        assert_eq!(parts[1].name, "crt_file");
        assert_eq!(parts[1].filename.as_deref(), Some("a.pem"));
        assert_eq!(parts[1].data, b"CERTDATA");
    }

    #[test]
    fn parses_generated_certificate() {
        let dir = std::env::temp_dir().join(format!("homewaf-cert-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("c.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=home.local",
                "-addext", "subjectAltName=DNS:home.local,DNS:*.home.local",
                "-keyout",
            ])
            .arg(dir.join("k.pem"))
            .arg("-out")
            .arg(&cert_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            panic!("需要 openssl 生成测试证书");
        }
        let pem = std::fs::read_to_string(&cert_path).unwrap();
        let info = parse_cert(&pem).unwrap();
        assert!(info.domains.contains("home.local"));
        assert!(info.domains.contains("*.home.local"));
        assert!(info.not_after > info.not_before);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
