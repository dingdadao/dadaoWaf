//! 转发头注入。
//!
//! 让后端知道真实客户端 IP 与原始协议，同时**清理客户端伪造的头**。
//!
//! 关键安全约束：不可信来源的 `X-Forwarded-For` 必须**替换**而不是追加，
//! 否则客户端发一个 `XFF: 1.1.1.1` 就能让后端以为请求来自 1.1.1.1。

use std::net::IpAddr;

use pingora::http::RequestHeader;

/// 注入转发头所需的上下文。
pub struct ForwardedCtx {
    pub client_ip: IpAddr,
    /// `http` 或 `https`
    pub scheme: &'static str,
    /// 原始 Host（不含端口）
    pub host: String,
    /// 原始端口
    pub port: u16,
    /// 直连来源是否属于可信代理。决定 XFF 是追加还是替换。
    pub trusted_proxy: bool,
}

/// 把转发头写入上游请求。
pub fn apply(req: &mut RequestHeader, ctx: &ForwardedCtx) {
    let ip = ctx.client_ip.to_string();

    // X-Real-IP：始终覆盖为还原后的真实 IP
    let _ = req.insert_header("x-real-ip", ip.as_str());

    // X-Forwarded-For：
    //   可信来源 → 追加，保留上游代理链
    //   不可信来源 → 替换，丢弃客户端伪造的内容
    if ctx.trusted_proxy {
        let _ = req.append_header("x-forwarded-for", ip.as_str());
    } else {
        let _ = req.insert_header("x-forwarded-for", ip.as_str());
    }

    let _ = req.insert_header("x-forwarded-proto", ctx.scheme);

    if !ctx.host.is_empty() {
        let _ = req.insert_header("x-forwarded-host", ctx.host.as_str());
    }

    let port = ctx.port.to_string();
    let _ = req.insert_header("x-forwarded-port", port.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with_headers(pairs: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (k, v) in pairs {
            req.insert_header(k.to_string(), v.to_string()).unwrap();
        }
        req
    }

    fn ctx(trusted: bool) -> ForwardedCtx {
        ForwardedCtx {
            client_ip: "203.0.113.9".parse().unwrap(),
            scheme: "https",
            host: "nas.home.lan".to_string(),
            port: 443,
            trusted_proxy: trusted,
        }
    }

    fn get(req: &RequestHeader, name: &str) -> Option<String> {
        req.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// 取同名头的全部值（`append_header` 会产生多个）。
    fn get_all(req: &RequestHeader, name: &str) -> Vec<String> {
        req.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn sets_all_forwarded_headers() {
        let mut req = req_with_headers(&[]);
        apply(&mut req, &ctx(false));

        assert_eq!(get(&req, "x-real-ip").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&req, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&req, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(
            get(&req, "x-forwarded-host").as_deref(),
            Some("nas.home.lan")
        );
        assert_eq!(get(&req, "x-forwarded-port").as_deref(), Some("443"));
    }

    #[test]
    fn untrusted_source_replaces_forged_xff() {
        let mut req = req_with_headers(&[("x-forwarded-for", "1.1.1.1")]);
        apply(&mut req, &ctx(false));
        // 伪造的 1.1.1.1 必须消失
        assert_eq!(get(&req, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn trusted_source_appends_to_xff() {
        let mut req = req_with_headers(&[("x-forwarded-for", "198.51.100.1")]);
        apply(&mut req, &ctx(true));
        let values = get_all(&req, "x-forwarded-for");
        let joined = values.join(",");
        assert!(joined.contains("198.51.100.1"), "应保留已有链: {joined}");
        assert!(joined.contains("203.0.113.9"), "应追加真实 IP: {joined}");
        assert_eq!(values.len(), 2, "应该是两个独立的头值: {values:?}");
    }

    #[test]
    fn x_real_ip_is_always_overwritten() {
        let mut req = req_with_headers(&[("x-real-ip", "1.1.1.1")]);
        apply(&mut req, &ctx(false));
        assert_eq!(get(&req, "x-real-ip").as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn empty_host_not_injected() {
        let mut req = req_with_headers(&[]);
        let mut c = ctx(false);
        c.host = String::new();
        apply(&mut req, &c);
        assert!(get(&req, "x-forwarded-host").is_none());
    }

    #[test]
    fn ipv6_client_ip() {
        let mut req = req_with_headers(&[]);
        let mut c = ctx(false);
        c.client_ip = "2001:db8::1".parse().unwrap();
        apply(&mut req, &c);
        assert_eq!(get(&req, "x-real-ip").as_deref(), Some("2001:db8::1"));
        assert_eq!(get(&req, "x-forwarded-for").as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn ipv4_mapped_ipv6_written_as_is() {
        // realip 层已归一化，这里验证写出的格式不丢信息
        let mut req = req_with_headers(&[]);
        let mut c = ctx(false);
        c.client_ip = "::ffff:203.0.113.9".parse().unwrap();
        apply(&mut req, &c);
        assert_eq!(
            get(&req, "x-real-ip").as_deref(),
            Some("::ffff:203.0.113.9")
        );
    }
}
