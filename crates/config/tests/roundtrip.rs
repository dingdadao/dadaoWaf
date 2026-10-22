//! 集成测试：配置的序列化往返与默认值。
//!
//! 目标：确保「解析 → 序列化 → 再解析」稳定，且默认值不会在往返中漂移。
//! 这类测试能抓到 serde 属性写错（如 rename 不一致、skip_serializing 漏配）。

use homewaf_config::*;

fn example_yaml() -> &'static str {
    include_str!("../../../configs/example.yaml")
}

#[test]
fn example_config_loads() {
    let (config, warnings) = from_str_with_warnings(example_yaml()).expect("示例配置应能通过校验");
    assert!(warnings.is_empty(), "示例配置不应有警告: {warnings:?}");
    assert_eq!(config.applications.len(), 2);
    assert_eq!(config.applications[0].id, "nas");
    assert_eq!(config.applications[1].domains.aliases, vec!["photo.home.lan"]);
}

#[test]
fn full_config_roundtrip_is_stable() {
    let config = from_str(example_yaml()).expect("解析失败");
    let first = serde_yaml::to_string(&config).expect("序列化失败");
    let reparsed = from_str(&first).expect("往返后解析失败");
    let second = serde_yaml::to_string(&reparsed).expect("二次序列化失败");
    assert_eq!(first, second, "序列化往返不稳定，说明某个字段的 serde 属性有问题");
}

#[test]
fn duration_roundtrip_keeps_unit() {
    let yaml = r#"
limits:
  queue_timeout: 200ms
  request_timeout: 30s
  detect_budget: 50ms
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    let config = from_str(yaml).unwrap();
    let out = serde_yaml::to_string(&config).unwrap();
    assert!(out.contains("200ms"), "应保留毫秒单位: {out}");
    assert!(out.contains("30s"), "应保留秒单位: {out}");
}

#[test]
fn size_roundtrip_keeps_unit() {
    let yaml = r#"
limits:
  max_body_size: 2GB
  max_header_size: 32KB
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    let config = from_str(yaml).unwrap();
    let out = serde_yaml::to_string(&config).unwrap();
    assert!(out.contains("2GB"), "应保留 GB 单位: {out}");
    assert!(out.contains("32KB"), "应保留 KB 单位: {out}");
}

#[test]
fn defaults_are_applied() {
    let minimal = r#"
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    let config = from_str(minimal).unwrap();

    // 服务器
    assert_eq!(config.server.workers, 0);
    assert_eq!(config.server.listen.len(), 2);
    assert_eq!(config.server.admin.listen, "127.0.0.1:9443");

    // TLS
    assert_eq!(config.tls.min_version, TlsVersion::V1_2);
    assert_eq!(config.tls.alpn, vec!["h2", "http/1.1"]);
    assert!(!config.tls.hsts.enabled);

    // 真实 IP 默认关闭（未配可信网段时解析头部等于允许伪造）
    assert!(!config.real_ip.enabled);

    // 限制
    assert_eq!(config.limits.max_header_count, 100);
    assert_eq!(config.limits.max_body_size.as_bytes(), 10 * 1024 * 1024);
    assert_eq!(config.limits.queue_capacity, 1024);
    assert_eq!(config.limits.queue_timeout.as_millis(), 200);
    assert_eq!(config.limits.request_timeout.as_secs(), 30);

    // ACL：内网默认放行
    assert_eq!(
        config.acl.private_network.action,
        PrivateNetworkAction::Allow
    );
    assert_eq!(config.acl.ipv6_prefix_match, 64);
    assert_eq!(config.acl.auto_ban.durations.len(), 4);

    // 应用
    let app = &config.applications[0];
    assert!(app.enabled);
    assert_eq!(app.tls.mode, TlsMode::Auto);
    assert_eq!(app.lb.algorithm, LbAlgorithm::RoundRobin);
    assert_eq!(app.timeouts.connect.as_secs(), 5);
    assert_eq!(app.timeouts.read.as_secs(), 60);
    // 非幂等默认不重试
    assert_eq!(app.retry.methods, vec!["GET", "HEAD", "OPTIONS"]);
    assert_eq!(app.retry.attempts, 2);
}

#[test]
fn toggle_three_states_parse() {
    let yaml = r#"
protection:
  sqli: block
  xss: monitor
  cmdi: off
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    let config = from_str(yaml).unwrap();
    assert_eq!(config.protection.sqli, Some(Toggle::Block));
    assert_eq!(config.protection.xss, Some(Toggle::Monitor));
    assert_eq!(config.protection.cmdi, Some(Toggle::Off));
    assert_eq!(config.protection.xxe, None);
}

#[test]
fn all_enum_variants_parse_from_strings() {
    // 这些字符串是配置文件里实际会写的值，任何一个解析失败都意味着用户配置会报错
    let yaml = r#"
tls:
  min_version: "1.3"
acme:
  challenge: dns-01
protection:
  preset: strict
  fail_policy: open
real_ip:
  on_untrusted_header: reject
logging:
  body_capture: always
acl:
  private_network:
    action: normal
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    tls: { mode: off }
    lb: { algorithm: least_conn }
    upstreams:
      - addr: 192.168.1.5
        port: 80
        scheme: https
    routes:
      - path: /x
        rewrite: { mode: strip_prefix }
        allow_methods: [GET]
"#;
    let config = from_str(yaml).unwrap();
    assert_eq!(config.tls.min_version, TlsVersion::V1_3);
    assert_eq!(config.acme.challenge, AcmeChallenge::Dns01);
    assert_eq!(config.protection.preset, Some(Preset::Strict));
    assert_eq!(config.protection.fail_policy, Some(FailPolicy::Open));
    assert_eq!(
        config.real_ip.on_untrusted_header,
        UntrustedHeaderAction::Reject
    );
    assert_eq!(config.logging.body_capture, BodyCapture::Always);
    assert_eq!(
        config.acl.private_network.action,
        PrivateNetworkAction::Normal
    );
    assert_eq!(config.applications[0].tls.mode, TlsMode::Off);
    assert_eq!(config.applications[0].lb.algorithm, LbAlgorithm::LeastConn);
}

#[test]
fn preset_thresholds_are_ordered() {
    // 档位越严格，阈值越低
    assert!(Preset::Lenient.block_threshold() > Preset::Balanced.block_threshold());
    assert!(Preset::Balanced.block_threshold() > Preset::Strict.block_threshold());
    assert!(Preset::Lenient.min_confidence() > Preset::Strict.min_confidence());
}
