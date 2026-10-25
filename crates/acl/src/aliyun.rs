//! 阿里云 ESA「源站防护」回源网段订阅。
//!
//! ESA 的回源 IP 只在控制台页面提供（或走 OpenAPI），没有公开的订阅地址。
//! 这里直接调 `GetOriginProtection` 拿到 `LatestIPWhitelist`，拼成 CIDR 文本，
//! 交给 [`crate::feed`] 的解析与护栏管道——所以对上游来说是"自建订阅"。
//!
//! 签名用 ACS3-HMAC-SHA256（V3），见阿里云《V3版本请求体&签名机制》：
//! CanonicalRequest = METHOD \n URI \n Query \n CanonicalHeaders \n SignedHeaders \n
//! HashedRequestPayload；StringToSign = "ACS3-HMAC-SHA256" \n SHA256(CanonicalRequest)。

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use homewaf_config::AliyunEsaSource;
use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::SecureRandom;
use serde::Deserialize;

use crate::http::FetchError;

const ACTION: &str = "GetOriginProtection";
const API_VERSION: &str = "2024-09-10";
/// 空请求体的 SHA256，GET 请求固定用这个值。
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// 拉取 ESA 回源网段，返回一行一个 CIDR 的文本。
pub fn fetch_origin_ips(
    cfg: &AliyunEsaSource,
    timeout: Duration,
    max_bytes: usize,
) -> Result<String, FetchError> {
    let ak = cfg.access_key_id.trim();
    let sk = cfg.access_key_secret.trim();
    let site = cfg.site_id.trim();
    if ak.is_empty() || sk.is_empty() || site.is_empty() {
        return Err(FetchError::Request(
            "阿里云 ESA 订阅缺少 AccessKey 或 SiteId".into(),
        ));
    }

    let region = match cfg.region.trim() {
        "" => "cn-hangzhou",
        r => r,
    };
    let host = format!("esa.{region}.aliyuncs.com");
    let query = format!(
        "Action={ACTION}&SiteId={}&Version={API_VERSION}",
        encode(site)
    );
    let date = iso8601(now_secs());
    let nonce = random_nonce();
    let (headers, auth) = sign(&host, &query, ak, sk, &date, &nonce);

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        // 400 也要读到响应体：阿里云会在里面返回 InvalidAccessKeyId 之类的错误码
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = config.into();

    let mut request = agent.get(&format!("https://{host}/?{query}"));
    for (k, v) in &headers {
        // host 只参与签名：实际请求头由 HTTP 客户端按 URL 生成，重复设置会被拒绝
        if *k == "host" {
            continue;
        }
        request = request.header(*k, v.as_str());
    }
    request = request.header("authorization", auth.as_str());

    let response = request
        .call()
        .map_err(|e| FetchError::Request(e.to_string()))?;
    let status = response.status().as_u16();

    let mut reader = response.into_body().into_reader();
    let mut buf = Vec::new();
    let read = reader
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Io(e.to_string()))?;
    if read > max_bytes {
        return Err(FetchError::TooLarge { limit: max_bytes });
    }
    let body = String::from_utf8_lossy(&buf).to_string();

    if status != 200 {
        return Err(FetchError::Request(format!(
            "阿里云 API 返回 {status}：{}",
            truncate(&body, 300)
        )));
    }

    let resp: ApiResponse = serde_json::from_str(&body)
        .map_err(|e| FetchError::Request(format!("阿里云 API 响应解析失败：{e}")))?;
    let mut ips = resp.latest.ipv4;
    ips.extend(resp.latest.ipv6);
    if ips.is_empty() {
        return Err(FetchError::Request(format!(
            "站点没有回源 IP 列表（源站防护：{}）——请先在 ESA 控制台开启源站防护",
            if resp.origin_protection.is_empty() {
                "未知"
            } else {
                resp.origin_protection.as_str()
            }
        )));
    }
    Ok(ips.join("\n"))
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    #[serde(rename = "LatestIPWhitelist", default)]
    latest: Whitelist,
    #[serde(rename = "OriginProtection", default)]
    origin_protection: String,
}

#[derive(Debug, Default, Deserialize)]
struct Whitelist {
    #[serde(rename = "IPv4", default)]
    ipv4: Vec<String>,
    #[serde(rename = "IPv6", default)]
    ipv6: Vec<String>,
}

/// 构造签名头。`date`/`nonce` 由调用方传入，便于测试固定输入。
fn sign(
    host: &str,
    query: &str,
    ak: &str,
    sk: &str,
    date: &str,
    nonce: &str,
) -> (Vec<(&'static str, String)>, String) {
    let mut headers: Vec<(&'static str, String)> = vec![
        ("host", host.to_string()),
        ("x-acs-action", ACTION.to_string()),
        ("x-acs-content-sha256", EMPTY_SHA256.to_string()),
        ("x-acs-date", date.to_string()),
        ("x-acs-signature-nonce", nonce.to_string()),
        ("x-acs-version", API_VERSION.to_string()),
    ];
    headers.sort_by(|a, b| a.0.cmp(b.0));

    let canonical = canonical_request(&headers, query);
    let hashed = hex(digest(&SHA256, canonical.as_bytes()).as_ref());
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, sk.as_bytes());
    let signature = hex(hmac::sign(&key, string_to_sign.as_bytes()).as_ref());

    let signed_headers = headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join(";");
    let auth = format!(
        "ACS3-HMAC-SHA256 Credential={ak},SignedHeaders={signed_headers},Signature={signature}"
    );
    (headers, auth)
}

/// 规范化请求。头已按名称升序，值去首尾空格。
///
/// 注意 `canonical_headers` 后有两个换行：官方要求每个头都以 `\n` 结尾
/// （最后一行也算），再与 SignedHeaders 之间用 `\n` 分隔，所以会出现空行。
/// 少这一个换行阿里云会直接返回 SignatureDoesNotMatch。
fn canonical_request(headers: &[(&'static str, String)], query: &str) -> String {
    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}", v.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    let signed_headers = headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join(";");
    format!("GET\n/\n{query}\n{canonical_headers}\n\n{signed_headers}\n{EMPTY_SHA256}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix 秒 → `YYYY-MM-DDTHH:MM:SSZ`（UTC，x-acs-date 要求的格式）。
fn iso8601(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 的 days-from-civil 逆运算。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// RFC3986 编码，`~` 不编码（阿里云 V3 签名的特殊要求）。
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push_str("%20"),
            b'*' => out.push_str("%2A"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut buf).is_err() {
        // 取不到随机数时退化为时间戳，仍能生成合法请求（只是不可预测性差）
        let secs = now_secs();
        buf[..8].copy_from_slice(&secs.to_be_bytes());
    }
    hex(&buf)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let t: String = s.chars().take(max).collect();
    format!("{t}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc4231_case2() {
        // RFC 4231 Test Case 2
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        let tag = hmac::sign(&key, b"what do ya want for nothing?");
        assert_eq!(
            hex(tag.as_ref()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn iso8601_formats_utc() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        // 闰日
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn canonical_request_keeps_blank_line_before_signed_headers() {
        let cfg = AliyunEsaSource {
            access_key_id: "ak".into(),
            access_key_secret: "sk".into(),
            site_id: "12345".into(),
            region: "cn-hangzhou".into(),
        };
        let (headers, _) = sign(
            "esa.cn-hangzhou.aliyuncs.com",
            "Action=GetOriginProtection&SiteId=12345&Version=2024-09-10",
            &cfg.access_key_id,
            &cfg.access_key_secret,
            "2023-10-26T10:22:32Z",
            "3156853299f313e23d1673dc12e1703d",
        );
        let canonical = canonical_request(
            &headers,
            "Action=GetOriginProtection&SiteId=12345&Version=2024-09-10",
        );
        // 这是阿里云返回报错时给出的 server CanonicalRequest 形状：
        // 头块最后一行后面还有一个空行，再是 SignedHeaders。
        assert_eq!(
            canonical,
            "GET\n/\nAction=GetOriginProtection&SiteId=12345&Version=2024-09-10\n\
             host:esa.cn-hangzhou.aliyuncs.com\n\
             x-acs-action:GetOriginProtection\n\
             x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-acs-date:2023-10-26T10:22:32Z\n\
             x-acs-signature-nonce:3156853299f313e23d1673dc12e1703d\n\
             x-acs-version:2024-09-10\n\n\
             host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn encode_follows_rfc3986() {
        assert_eq!(encode("a b*c~d"), "a%20b%2Ac~d");
        assert_eq!(encode("2409:8c54::/64"), "2409%3A8c54%3A%3A%2F64");
    }

    #[test]
    fn parses_latest_whitelist() {
        let body = r#"{
            "RequestId": "x",
            "OriginProtection": "on",
            "LatestIPWhitelist": {
                "IPv4": ["101.66.250.0/25"],
                "IPv6": ["2409:8c54:1841:200a::/64"]
            }
        }"#;
        let resp: ApiResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.latest.ipv4, vec!["101.66.250.0/25"]);
        assert_eq!(resp.latest.ipv6, vec!["2409:8c54:1841:200a::/64"]);
        assert_eq!(resp.origin_protection, "on");
    }
}
