//! 真实客户端 IP 还原。
//!
//! 当 HomeWAF 前面还有 CDN / Tunnel / frp 时，TCP 来源是中间节点。
//! 不还原会导致：封禁攻击者变成封禁整个 CDN 节点、所有用户共享限流配额、
//! GeoIP 全错、日志无法回答"谁在攻击我"。
//!
//! 安全前提：**只有来自可信来源的请求才解析转发头**，否则客户端可以随意伪造
//! `X-Forwarded-For` 绕过 ACL。可信来源有三种，取「或」：
//!
//! 1. 直连 IP 命中 `trusted_proxies`（含 `trusted_proxy_groups` 并入的网段）；
//! 2. `secret_header` 校验通过（CDN 回源标记头）；
//! 3. `trust_private_source` 开启且直连 IP 是私有地址（RFC1918 / ULA / 回环）。

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
    /// 直连 IP 是否属于可信代理（含密钥头命中的情况）
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

    let trusted = is_trusted(direct, config) || secret_matches(headers, config);
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
        if !is_trusted_hop(*ip, config) {
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
    // 显式选择「不判断来源」：任何请求的转发头都采信
    config.trust_any_source || is_trusted_hop(ip, config)
}

/// 单个地址是否属于「自己人」：可信网段或私有网段。
///
/// 与 `is_trusted` 的区别是**不看 `trust_any_source`**：XFF 链里「跳过可信
/// 代理」必须按真实网段判断，否则全信模式下每个 hop 都被当成代理跳过，
/// 最终取到最左侧那个客户端可任意伪造的地址。
fn is_trusted_hop(ip: IpAddr, config: &RealIpConfig) -> bool {
    config.trusted_proxies.iter().any(|net| net.contains(&ip))
        || (config.trust_private_source && is_private_source(ip))
}

/// 是否属于「不可能来自公网源站」的私有地址。
///
/// 覆盖 IPv4 的 RFC1918 / 回环 / 链路本地，IPv6 的 ULA（`fc00::/7`）、
/// 回环与链路本地。运营商不会把私有地址路由到公网，所以这条判定不能被
/// 公网攻击者利用——它只影响「同一内网内的客户端能不能伪造转发头」。
///
/// 用途：`trust_private_source` 开启时，内网设备直连 WAF 无需带任何头，
/// 也不必把会漂移的 IPv6 家居前缀手工写进 `trusted_proxies`。
pub fn is_private_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // 不用 `is_unique_local()` / `is_unicast_link_local()`：二者 1.84 才稳定，
            // 低于本仓库 MSRV，clippy 会直接报 incompatible_msrv
            let head = v6.segments()[0];
            v6.is_loopback() || head & 0xfe00 == 0xfc00 || head & 0xffc0 == 0xfe80
        }
    }
}

/// 回源密钥是否匹配。
///
/// 用于云 CDN 回源 IP 不可知/会漂移的场景（如阿里云 CDN）：只要请求带着
/// 「只有 CDN 会带」的头，就认为它经过了 CDN，可以信任转发头。
///
/// 两种模式：
/// - **严格**（填了 `secret`）：头值必须等于密钥。头名泄露也不致命。
/// - **头名即密钥**（只填 `secret_header`）：只要该头出现且值是合法 IP 就算通过。
///   适用于 CDN 把客户端 IP 写进自定义头的场景，代价是安全边界退化为
///   「头名不被猜到」——头名一旦泄露就等于向全网开放。
///
/// 两个细节：
/// - 严格模式用常量时间比较，避免按字节响应时间逐位爆破密钥；
/// - 用 `get_all` 任一值命中即算通过。CDN 的自定义回源头若是「追加」语义，
///   客户端能抢先塞一个假值，此时只看第一个值会被绕过。
fn secret_matches(headers: &HeaderMap, config: &RealIpConfig) -> bool {
    let Some(name) = config.secret_header.as_deref().filter(|n| !n.is_empty()) else {
        return false;
    };
    let expected = config.secret.as_deref().filter(|s| !s.is_empty());

    headers.get_all(name).iter().any(|value| {
        let Ok(raw) = value.to_str() else {
            return false;
        };
        match expected {
            Some(expected) => ct_eq(raw.as_bytes(), expected.as_bytes()),
            // 头名即密钥：值可以是单个 IP，也可以是逗号链，含合法 IP 即可
            None => raw.split(',').any(|part| parse_single_ip(part).is_some()),
        }
    })
}

/// 常量时间字节比较。长度不同直接返回 false（长度本身不算秘密）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 请求是否携带了任一被信任的转发头。
///
/// 用于 `on_untrusted_header: reject`：来源不可信却带了转发头，
/// 要么是客户端在伪造，要么是代理链没配对，都不该静默放过。
pub fn carries_forwarded_header(headers: &HeaderMap, config: &RealIpConfig) -> bool {
    config
        .header_priority
        .iter()
        .any(|name| headers.contains_key(name.as_str()))
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

    // ============================================================
    // 回源密钥信任（CDN 回源 IP 不公开时用）
    // ============================================================

    fn secret_cfg(secret: &str) -> RealIpConfig {
        let mut config = cfg(&[]);
        config.header_priority = vec!["Ali-Cdn-Real-Ip".to_string()];
        config.secret_header = Some("X-Origin-Verify".to_string());
        config.secret = Some(secret.to_string());
        config
    }

    #[test]
    fn secret_grants_trust_without_ip_whitelist() {
        // 直连是公网 CDN 回源节点，网段拿不到也无需知道：密钥对了就信
        let config = secret_cfg("s3cr3t-token-32-bytes-long");
        let h = headers(&[
            ("x-origin-verify", "s3cr3t-token-32-bytes-long"),
            ("ali-cdn-real-ip", "203.0.113.42"),
        ]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.42".parse::<IpAddr>().unwrap());
        assert!(r.trusted_proxy);
        assert_eq!(r.source.as_str(), "Ali-Cdn-Real-Ip");
    }

    #[test]
    fn wrong_secret_falls_back_to_direct() {
        let config = secret_cfg("expected-secret-value");
        let h = headers(&[
            ("x-origin-verify", "guessed"),
            ("ali-cdn-real-ip", "203.0.113.42"),
        ]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert_eq!(r.real, "47.100.1.1".parse::<IpAddr>().unwrap());
        assert!(!r.trusted_proxy);
        assert_eq!(r.source, IpSource::Direct);
    }

    #[test]
    fn missing_secret_header_falls_back_to_direct() {
        let config = secret_cfg("expected-secret-value");
        let h = headers(&[("ali-cdn-real-ip", "203.0.113.42")]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert_eq!(r.real, "47.100.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn repeated_secret_header_matches_any_value() {
        // CDN 的自定义回源头若是「追加」语义，客户端能抢先塞假值把真值挤到后面
        let config = secret_cfg("real-secret");
        let mut h = headers(&[("ali-cdn-real-ip", "203.0.113.42")]);
        h.append("x-origin-verify", HeaderValue::from_static("fake"));
        h.append("x-origin-verify", HeaderValue::from_static("real-secret"));

        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn header_name_only_mode_trusts_when_value_is_ip() {
        // 不填密钥值 = 头名即密钥：CDN 把客户端 IP 写进自定义头时用这种配法
        let mut config = cfg(&[]);
        config.secret_header = Some("X-8f3a2b-Real-Forwarded-For".to_string());
        let h = headers(&[
            ("x-8f3a2b-real-forwarded-for", "203.0.113.42"),
            ("x-forwarded-for", "203.0.113.42"),
        ]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert!(r.trusted_proxy);
        assert_eq!(r.real, "203.0.113.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn header_name_only_mode_chain_follows_xff_rule() {
        // 自定义头若是 CDN「覆盖写入」的单值，上面那条测试就是典型形态。
        // 若 CDN 是「追加」语义，链尾是 CDN 节点 IP，而回源 IP 又不在白名单里
        // 跳不过去 —— 所以这种模式只适合覆盖写入单个 IP 的头。
        let mut config = cfg(&[]);
        config.secret_header = Some("X-8f3a2b-Real-Forwarded-For".to_string());
        config.header_priority = vec!["X-8f3a2b-Real-Forwarded-For".to_string()];
        let h = headers(&[("x-8f3a2b-real-forwarded-for", "203.0.113.42, 47.100.1.1")]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert!(r.trusted_proxy);
        assert_eq!(r.real, "47.100.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn header_name_only_mode_rejects_non_ip_value() {
        let mut config = cfg(&[]);
        config.secret_header = Some("X-8f3a2b-Real-Forwarded-For".to_string());
        let h = headers(&[("x-8f3a2b-real-forwarded-for", "anything")]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert!(!r.trusted_proxy, "头在但值不是 IP，不能当作通过");
    }

    #[test]
    fn secret_value_without_header_never_trusts() {
        // 只配值不配头名：没有任何可信来源
        let mut config = cfg(&[]);
        config.secret = Some("0123456789abcdef".to_string());
        let h = headers(&[("ali-cdn-real-ip", "203.0.113.42")]);
        let r = resolve(Some(&direct("47.100.1.1")), &h, &config).unwrap();
        assert!(!r.trusted_proxy);
    }

    #[test]
    fn trusted_ip_still_works_when_secret_set() {
        // 密钥与 IP 白名单是「或」关系，内网直连不该因为配了密钥就失效
        let mut config = secret_cfg("whatever-secret");
        config.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let h = headers(&[("ali-cdn-real-ip", "203.0.113.9")]);
        let r = resolve(Some(&direct("10.0.0.5")), &h, &config).unwrap();
        assert_eq!(r.real, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert!(r.trusted_proxy);
    }

    // ============================================================
    // 私有网段来源自动可信（trust_private_source）
    // ============================================================

    #[test]
    fn private_direct_source_is_trusted_by_default() {
        // 内网设备直连 WAF 不带任何头，不该被迫把它抄进 trusted_proxies
        let config = cfg(&[]);
        let h = headers(&[("x-real-ip", "203.0.113.42")]);
        let r = resolve(Some(&direct("127.0.0.1")), &h, &config).unwrap();
        assert!(r.trusted_proxy);
        assert_eq!(r.real, "203.0.113.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn private_direct_source_ignored_when_auto_trust_disabled() {
        let mut config = cfg(&[]);
        config.trust_private_source = false;
        let h = headers(&[("x-real-ip", "203.0.113.42")]);
        let r = resolve(Some(&direct("127.0.0.1")), &h, &config).unwrap();
        assert!(!r.trusted_proxy);
        assert_eq!(r.real, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv6_ula_and_link_local_are_private_sources() {
        // 家宽 IPv6 前缀会变，靠 trusted_proxies 写死 /64 追不上；
        // ULA 与链路本地不会变，靠这条兜住
        assert!(is_private_source("fd12:3456::1".parse().unwrap()));
        assert!(is_private_source("fc00::1".parse().unwrap()));
        assert!(is_private_source("fe80::1".parse().unwrap()));
        assert!(is_private_source("::1".parse().unwrap()));
        // 公网 IPv6 不能算私有
        assert!(!is_private_source("2408:8752:0:5::1".parse().unwrap()));
        assert!(!is_private_source("240e:f7:c000:105::1".parse().unwrap()));
    }

    #[test]
    fn private_source_helper_covers_rfc1918() {
        for ip in [
            "10.1.2.3",
            "172.16.0.9",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
        ] {
            assert!(is_private_source(ip.parse().unwrap()), "{ip} 应算私有");
        }
        for ip in ["8.8.8.8", "203.0.113.7", "172.32.0.1", "47.100.1.1"] {
            assert!(!is_private_source(ip.parse().unwrap()), "{ip} 不该算私有");
        }
    }

    #[test]
    fn public_direct_still_untrusted_with_private_auto_trust() {
        // 关键安全性质：私有自动信任不能把公网来源也放进来
        let config = cfg(&[]);
        assert!(config.trust_private_source);
        let h = headers(&[("x-real-ip", "10.0.0.9")]);
        let r = resolve(Some(&direct("198.51.100.7")), &h, &config).unwrap();
        assert!(!r.trusted_proxy);
        assert_eq!(r.real, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ct_eq_is_exact() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn detects_forwarded_header_for_reject_mode() {
        let config = cfg(&[]);
        assert!(carries_forwarded_header(
            &headers(&[("x-forwarded-for", "1.2.3.4")]),
            &config
        ));
        assert!(carries_forwarded_header(
            &headers(&[("ali-cdn-real-ip", "1.2.3.4")]),
            &config
        ));
        assert!(!carries_forwarded_header(
            &headers(&[("user-agent", "curl")]),
            &config
        ));
    }
}
