//! 真实客户端 IP 还原。
//!
//! 当 HomeWAF 前面还有 CDN / Tunnel / frp 时，TCP 来源是中间节点。
//! 不还原会导致：封禁攻击者变成封禁整个 CDN 节点、所有用户共享限流配额、
//! GeoIP 全错、日志无法回答"谁在攻击我"。
//!
//! 安全前提：**只有来自 `trusted_proxies` 的请求才解析转发头**，
//! 否则客户端可以随意伪造 `X-Forwarded-For` 绕过 ACL。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use homewaf_config::RealIpConfig;
use http::HeaderMap;

/// IP 的来源，写入日志便于排查"为什么这个 IP 不对"。
///
/// 用 `Arc<str>` 而不是 `&'static str`，这样 `header_priority` 里配的
/// 自定义头名（如 `X-Company-Real-IP`）能原样出现在日志里。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSource {
    /// 直接使用 TCP 连接地址
    Direct,
    /// 来自某个转发头
    Header(Arc<str>),
}

impl IpSource {
    pub fn as_str(&self) -> &str {
        match self {
            IpSource::Direct => "direct",
            IpSource::Header(name) => name,
        }
    }
}

/// 解析结果。
#[derive(Debug, Clone)]
pub struct ClientIp {
    /// 还原后的真实客户端 IP（用于 ACL / 限流 / GeoIP / 日志）
    pub real: IpAddr,
    /// TCP 直连 IP
    pub direct: IpAddr,
    pub source: IpSource,
    /// 直连 IP 是否属于可信代理
    pub trusted_proxy: bool,
}

/// 解析真实客户端 IP。
pub fn resolve(
    direct: Option<&SocketAddr>,
    headers: &HeaderMap,
    config: &RealIpConfig,
) -> Option<ClientIp> {
    let direct = normalize_ip(direct?.ip());

    if !config.enabled {
        return Some(ClientIp {
            real: direct,
            direct,
            source: IpSource::Direct,
            trusted_proxy: false,
        });
    }

    let trusted = is_trusted(direct, config);
    if !trusted {
        // 不可信来源：整个头部都不可信，直接用直连 IP
        return Some(ClientIp {
            real: direct,
            direct,
            source: IpSource::Direct,
            trusted_proxy: false,
        });
    }

    for name in &config.header_priority {
        let Some(value) = headers.get(name.as_str()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };

        let candidate = if value.contains(',') {
            // 含逗号视为代理链（如 X-Forwarded-For），否则按单值处理。
            // 不依赖头名，自定义头（如 X-Company-Real-IP）也能正确解析。
            parse_xff_chain(value, config)
        } else {
            parse_single_ip(value)
        };

        if let Some(ip) = candidate {
            return Some(ClientIp {
                real: ip,
                direct,
                source: IpSource::Header(Arc::from(name.as_str())),
                trusted_proxy: true,
            });
        }
    }

    Some(ClientIp {
        real: direct,
        direct,
        source: IpSource::Direct,
        trusted_proxy: true,
    })
}

/// 解析 XFF 链：从右向左跳过可信段，取第一个不可信地址。
///
/// 从右往左是因为 XFF 是追加式头部，左侧可被客户端注入。
fn parse_xff_chain(value: &str, config: &RealIpConfig) -> Option<IpAddr> {
    let mut hops: Vec<IpAddr> = value.split(',').filter_map(parse_single_ip).collect();

    if hops.is_empty() {
        return None;
    }

    let depth = config.max_chain_depth as usize;
    let start = hops.len().saturating_sub(depth.max(1));
    hops.drain(..start);

    // 从右向左找第一个不可信地址
    for ip in hops.iter().rev() {
        if !is_trusted(*ip, config) {
            return Some(*ip);
        }
    }
    // 全是可信地址：取最左侧
    hops.first().copied()
}

/// 解析单个 IP，剥离端口，处理 IPv4-mapped IPv6。
fn parse_single_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // [2001:db8::1]:443 或 [2001:db8::1]
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse::<IpAddr>().ok().map(normalize_ip);
    }

    // 1.2.3.4:5678
    if let Some((host, port)) = s.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(normalize_ip(ip));
            }
        }
    }

    s.parse::<IpAddr>().ok().map(normalize_ip)
}

/// 把 IPv4-mapped IPv6（`::ffff:1.2.3.4`）归一化为 IPv4。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

fn is_trusted(ip: IpAddr, config: &RealIpConfig) -> bool {
    config.trusted_proxies.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{RealIpConfig, UntrustedHeaderAction};
    use http::{HeaderMap, HeaderValue};

    fn cfg(trusted: &[&str]) -> RealIpConfig {
        RealIpConfig {
            enabled: true,
            trusted_proxies: trusted.iter().map(|s| s.parse().unwrap()).collect(),
            header_priority: homewaf_config::default_real_ip_headers(),
            max_chain_depth: 3,
            on_untrusted_header: UntrustedHeaderAction::Ignore,
            log_both: true,
            ..Default::default()
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn direct(ip: &str) -> SocketAddr {
        format!("{ip}:12345").parse().unwrap()
    }

    #[test]
    fn disabled_returns_direct() {
        let mut config = cfg(&["10.0.0.0/8"]);
        config.enabled = false;
        let h = headers(&[("cf-connecting-ip", "203.0.113.9")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(r.source, IpSource::Direct);
    }

    #[test]
    fn untrusted_source_ignores_headers() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("cf-connecting-ip", "203.0.113.9")]);
        let r = resolve(Some(&direct("198.51.100.7")), &h, &config).unwrap();
        assert_eq!(r.real, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert!(!r.trusted_proxy);
    }

    #[test]
    fn trusted_source_uses_cf_header() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("cf-connecting-ip", "203.0.113.9")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(r.source, IpSource::Header("CF-Connecting-IP".into()));
        assert!(r.trusted_proxy);
    }

    #[test]
    fn custom_header_name_supported() {
        // 用户可以把 header_priority 换成自己的 CDN 头
        let mut config = cfg(&["10.0.0.0/8"]);
        config.header_priority = vec!["X-Company-Real-IP".to_string()];
        let h = headers(&[("x-company-real-ip", "203.0.113.77")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.77".parse::<IpAddr>().unwrap());
        assert_eq!(r.source.as_str(), "X-Company-Real-IP");
    }

    #[test]
    fn custom_header_with_chain_parsed() {
        // 自定义头里含逗号时按代理链解析，不依赖头名
        let mut config = cfg(&["10.0.0.0/8"]);
        config.header_priority = vec!["X-My-Chain".to_string()];
        let h = headers(&[("x-my-chain", "1.1.1.1, 2.2.2.2")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn xff_parsed_right_to_left() {
        let config = cfg(&["10.0.0.0/8"]);
        // 左侧 1.1.1.1 可能是客户端伪造，右侧才是最近一跳
        let h = headers(&[("x-forwarded-for", "1.1.1.1, 2.2.2.2, 10.0.0.5")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn xff_all_trusted_takes_leftmost() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("x-forwarded-for", "10.1.1.1, 10.2.2.2")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "10.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn private_ip_from_trusted_proxy_is_accepted() {
        // 内网代理链（如 Cloudflare Tunnel 后面的内网客户端）会传私有地址，
        // 来自可信代理时应当接受，否则真实 IP 会丢失。
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("x-real-ip", "192.168.1.50")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "192.168.1.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forged_xff_ignored_when_source_untrusted() {
        // 不可信来源连头部都不看，天然免疫伪造
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("x-real-ip", "192.168.1.50")]);
        let r = resolve(Some(&direct("198.51.100.7")), &h, &config).unwrap();
        assert_eq!(r.real, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn strips_port_from_header() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[("x-real-ip", "203.0.113.9:54321")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv4_mapped_ipv6_normalized() {
        assert_eq!(
            normalize_ip("::ffff:1.2.3.4".parse().unwrap()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn header_priority_order_respected() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[
            ("cf-connecting-ip", "203.0.113.1"),
            ("x-real-ip", "203.0.113.2"),
        ]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        // CF 头优先级更高
        assert_eq!(r.real, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_next_header_when_first_invalid() {
        let config = cfg(&["10.0.0.0/8"]);
        let h = headers(&[
            ("cf-connecting-ip", "not-an-ip"),
            ("x-real-ip", "203.0.113.2"),
        ]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.2".parse::<IpAddr>().unwrap());
    }
}
