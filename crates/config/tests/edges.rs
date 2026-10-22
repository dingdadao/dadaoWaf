//! 集成测试：校验的边界条件。
//!
//! 每个用例对应 `docs/functional-spec.md` 里的一条约束。

use homewaf_config::*;

fn base_app(id: &str, domain: &str) -> String {
    format!(
        r#"
  - id: {id}
    name: {id}
    domains: {{ primary: "{domain}" }}
    upstreams: [{{ addr: 192.168.1.5, port: 80 }}]
"#
    )
}

fn with_apps(body: &str) -> String {
    format!("applications:\n{body}")
}

fn errors_of(yaml: &str) -> Vec<String> {
    match from_str(yaml) {
        Ok(_) => vec![],
        Err(ConfigError::Validation(items)) => items
            .into_iter()
            .filter(|i| i.is_error())
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect(),
        Err(other) => vec![format!("非校验错误: {other}")],
    }
}

fn warnings_of(yaml: &str) -> Vec<String> {
    match from_str_with_warnings(yaml) {
        Ok((_, ws)) => ws.iter().map(|w| format!("{}: {}", w.path, w.message)).collect(),
        Err(ConfigError::Validation(items)) => items
            .into_iter()
            .filter(|i| i.severity == Severity::Warning)
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect(),
        Err(_) => vec![],
    }
}

// ============================================================
// 端口与权重
// ============================================================

#[test]
fn port_upper_bound_accepted() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 65535 }]
"#,
    );
    assert!(errors_of(&yaml).is_empty());
}

#[test]
fn port_out_of_range_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 65536 }]
"#,
    );
    let errs = errors_of(&yaml);
    assert!(!errs.is_empty(), "端口 65536 应被拒绝");
}

#[test]
fn port_zero_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 0 }]
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("端口")));
}

#[test]
fn missing_port_defaults_to_80() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5 }]
"#,
    );
    // 行为变更：缺端口不再报错，自动按协议补 80
    assert!(
        errors_of(&yaml).is_empty(),
        "缺端口应自动补 80，实际错误: {:?}",
        errors_of(&yaml)
    );
}

#[test]
fn unix_socket_upstream_needs_no_port() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: "unix:/run/app.sock" }]
"#,
    );
    assert!(errors_of(&yaml).is_empty(), "{:?}", errors_of(&yaml));
}

#[test]
fn weight_bounds() {
    let ok = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80, weight: 100 }]
"#,
    );
    assert!(errors_of(&ok).is_empty());

    let bad = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80, weight: 101 }]
"#,
    );
    assert!(errors_of(&bad).iter().any(|e| e.contains("权重")));
}

#[test]
fn all_backup_upstreams_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams:
      - { addr: 192.168.1.5, port: 80, backup: true }
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("非 backup")));
}

// ============================================================
// 域名与 ID
// ============================================================

#[test]
fn long_domain_rejected() {
    let long_label = "a".repeat(64);
    let domain = format!("{long_label}.home.lan");
    let yaml = with_apps(&base_app("a", &domain));
    assert!(errors_of(&yaml).iter().any(|e| e.contains("63")));
}

#[test]
fn wildcard_multi_level_rejected() {
    // `*.a.home.lan` 是合法的（只匹配一级），多级通配才非法
    let ok = with_apps(&base_app("a", "*.a.home.lan"));
    assert!(errors_of(&ok).is_empty(), "{:?}", errors_of(&ok));

    let bad = with_apps(&base_app("a", "*.*.home.lan"));
    assert!(errors_of(&bad).iter().any(|e| e.contains("通配符")));

    let bad2 = with_apps(&base_app("a", "a.*.home.lan"));
    assert!(errors_of(&bad2).iter().any(|e| e.contains("通配符")));
}

#[test]
fn id_with_uppercase_rejected() {
    let yaml = with_apps(&base_app("MyApp", "a.home.lan"));
    assert!(errors_of(&yaml).iter().any(|e| e.contains("小写")));
}

#[test]
fn id_with_underscore_rejected() {
    let yaml = with_apps(&base_app("my_app", "a.home.lan"));
    assert!(errors_of(&yaml).iter().any(|e| e.contains("小写")));
}

#[test]
fn empty_name_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: "  "
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("名称不能为空")));
}

#[test]
fn too_many_aliases_rejected() {
    let aliases: Vec<String> = (0..11).map(|i| format!("\"a{i}.home.lan\"")).collect();
    let yaml = format!(
        r#"
applications:
  - id: a
    name: A
    domains:
      primary: main.home.lan
      aliases: [{}]
    upstreams: [{{ addr: 192.168.1.5, port: 80 }}]
"#,
        aliases.join(", ")
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("最多 10 个")));
}

// ============================================================
// 路由
// ============================================================

#[test]
fn route_path_must_start_with_slash() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: "api"
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("必须以 `/` 开头")));
}

#[test]
fn duplicate_route_path_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: /api
      - path: /api
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("重复")));
}

#[test]
fn regex_rewrite_requires_replacement() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: /x
        rewrite:
          mode: regex
          regex: "^/x/(.*)$"
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("replacement")));
}

#[test]
fn add_prefix_requires_value() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: /x
        rewrite:
          mode: add_prefix
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("value")));
}

#[test]
fn invalid_method_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: /x
        allow_methods: [GET, FOOBAR]
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("非法 HTTP 方法")));
}

#[test]
fn route_upstreams_cannot_be_empty_list() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    routes:
      - path: /x
        upstreams: []
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("不能为空")));
}

// ============================================================
// ACL 与策略
// ============================================================

#[test]
fn ipv6_prefix_too_short_warns() {
    let yaml = r#"
acl:
  ipv6_prefix_match: 32
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(warnings_of(yaml).iter().any(|w| w.contains("运营商段")));
}

#[test]
fn ipv6_prefix_over_128_rejected() {
    let yaml = r#"
acl:
  ipv6_prefix_match: 129
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("128")));
}

#[test]
fn allow_and_deny_overlap_warns() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    policy:
      allow_cidr: [192.168.1.0/24]
      deny_cidr: [192.168.1.128/25]
"#,
    );
    assert!(warnings_of(&yaml).iter().any(|w| w.contains("重叠")));
}

#[test]
fn allow_cidr_zero_rejected() {
    let yaml = with_apps(
        r#"
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
    policy:
      allow_cidr: [0.0.0.0/0]
"#,
    );
    assert!(errors_of(&yaml).iter().any(|e| e.contains("全网段")));
}

// ============================================================
// 订阅
// ============================================================

#[test]
fn ip_group_scope_must_reference_existing_app() {
    let yaml = r#"
ip_groups:
  - name: g
    source:
      url: "https://example.com/list"
    scope: [nonexistent]
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("不存在的应用")));
}

#[test]
fn ip_group_duplicate_name_rejected() {
    let yaml = r#"
ip_groups:
  - name: g
    source: { url: "https://example.com/a" }
  - name: g
    source: { url: "https://example.com/b" }
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("重复")));
}

#[test]
fn ip_group_guard_prefix_bounds() {
    let yaml = r#"
ip_groups:
  - name: g
    source: { url: "https://example.com/a" }
    guards:
      min_prefix_v6: 129
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("128")));
}

#[test]
fn rule_feed_window_format_validated() {
    let yaml = r#"
rule_feeds:
  - name: f
    url: "https://example.com/r.hwrule"
    update_window: "3am-5am"
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("HH:MM")));
}

#[test]
fn rule_feed_pinned_requires_version() {
    let yaml = r#"
rule_feeds:
  - name: f
    url: "https://example.com/r.hwrule"
    channel: pinned
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("pinned_version")));
}

// ============================================================
// 单位
// ============================================================

#[test]
fn zero_body_size_rejected() {
    let yaml = r#"
limits:
  max_body_size: 0
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).iter().any(|e| e.contains("不能为 0")));
}

#[test]
fn queue_timeout_longer_than_request_timeout_warns() {
    let yaml = r#"
limits:
  queue_timeout: 60s
  request_timeout: 30s
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(warnings_of(yaml).iter().any(|w| w.contains("没有时间完成转发")));
}

// ============================================================
// 真实 IP：自定义头名
// ============================================================

#[test]
fn custom_forwarded_header_name_allowed() {
    let yaml = r#"
real_ip:
  enabled: true
  trusted_proxies: [127.0.0.1/32]
  header_priority: ["X-Company-Real-IP", "X-Forwarded-For"]
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml).is_empty(), "{:?}", errors_of(yaml));
}

#[test]
fn invalid_forwarded_header_name_rejected() {
    let yaml = r#"
real_ip:
  enabled: true
  trusted_proxies: [127.0.0.1/32]
  header_priority: ["X Bad Header"]
applications:
  - id: a
    name: A
    domains: { primary: a.home.lan }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#;
    assert!(errors_of(yaml)
        .iter()
        .any(|e| e.contains("不是合法的 HTTP 头名")));
}
