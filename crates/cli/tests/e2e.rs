//! 端到端集成测试：真正启动 `homewaf serve` 子进程，用裸 TCP 发 HTTP 请求。
//!
//! 为什么需要这层测试：单元测试全绿但服务起不来，本项目已经发生过一次
//! （tokio 1.54 导致 Pingora 启动即 panic）。只有真的把进程跑起来才能拦住。
//!
//! 不引入 HTTP 客户端依赖：请求手写，响应手工解析，够用且零成本。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// 让操作系统分配一个空闲端口。
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定临时端口失败");
    listener.local_addr().unwrap().port()
}

/// 极简上游：收到请求就回固定响应体。
struct Upstream {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl Upstream {
    fn start(body: &'static str) -> Self {
        let port = free_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("上游绑定失败");
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread::spawn(move || {
                            let mut buf = [0u8; 4096];
                            // 读到请求头结束即可，测试用的都是 GET
                            if stream.read(&mut buf).is_ok() {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { port, stop }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 运行中的 homewaf 子进程，drop 时自动杀掉。
struct Proxy {
    child: Child,
    port: u16,
    db_path: std::path::PathBuf,
}

impl Proxy {
    fn start(config_path: &str) -> Self {
        let port = free_port();

        // 先把 YAML 导入临时数据库，再以数据库为唯一配置源启动
        let db_path = std::env::temp_dir().join(format!(
            "homewaf-e2e-{}-{}.db",
            std::process::id(),
            port
        ));
        let _ = std::fs::remove_file(&db_path);
        let db = db_path.to_string_lossy().into_owned();

        let import = Command::new(env!("CARGO_BIN_EXE_homewaf"))
            .args(["import", config_path, "--db", &db, "--overwrite"])
            .output()
            .expect("执行 import 失败");
        assert!(
            import.status.success(),
            "导入配置失败: {}",
            String::from_utf8_lossy(&import.stderr)
        );

        let child = Command::new(env!("CARGO_BIN_EXE_homewaf"))
            .args([
                "serve",
                "--db",
                &db,
                "--listen",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("启动 homewaf 失败");

        let proxy = Self {
            child,
            port,
            db_path,
        };
        proxy.wait_ready();
        proxy
    }

    /// 轮询等待端口可连接。超时说明服务起不来——这正是要测的问题。
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "homewaf 在 10 秒内未监听 127.0.0.1:{}，服务可能启动失败",
            self.port
        );
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db_path);
    }
}

/// 发一个 GET 请求，返回完整响应文本。
fn http_get(port: u16, host: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接代理失败");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("发送请求失败");

    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("读取响应失败");
    resp
}

fn status_of(resp: &str) -> u16 {
    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn body_of(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

/// 写一份临时配置，返回路径。
fn write_config(name: &str, content: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "homewaf-e2e-{}-{}.yaml",
        std::process::id(),
        name
    ));
    std::fs::write(&path, content).expect("写临时配置失败");
    path.to_string_lossy().into_owned()
}

fn config_for(upstream_port: u16) -> String {
    format!(
        r#"
server:
  listen: ["127.0.0.1:0"]
  admin:
    listen: "127.0.0.1:0"

limits:
  request_timeout: 10s

applications:
  - id: test
    name: "测试"
    domains:
      primary: "nas.home.lan"
      aliases: ["alias.home.lan"]
    upstreams:
      - addr: 127.0.0.1
        port: {upstream_port}
    routes:
      - path: /other
        upstreams:
          - addr: 127.0.0.1
            port: {upstream_port}
"#
    )
}

// ============================================================
// 测试用例
// ============================================================

#[test]
fn proxies_request_to_upstream() {
    let upstream = Upstream::start("hello-from-upstream");
    let cfg = write_config("basic", &config_for(upstream.port));
    let proxy = Proxy::start(&cfg);

    let resp = http_get(proxy.port, "nas.home.lan", "/anything");
    assert_eq!(status_of(&resp), 200, "响应: {resp}");
    assert_eq!(body_of(&resp), "hello-from-upstream");
}

#[test]
fn alias_domain_routes_to_same_upstream() {
    let upstream = Upstream::start("alias-ok");
    let cfg = write_config("alias", &config_for(upstream.port));
    let proxy = Proxy::start(&cfg);

    let resp = http_get(proxy.port, "alias.home.lan", "/x");
    assert_eq!(status_of(&resp), 200);
    assert_eq!(body_of(&resp), "alias-ok");
}

#[test]
fn unknown_host_returns_404_without_touching_upstream() {
    let upstream = Upstream::start("should-not-appear");
    let cfg = write_config("unknown", &config_for(upstream.port));
    let proxy = Proxy::start(&cfg);

    let resp = http_get(proxy.port, "evil.example.com", "/");
    assert_eq!(status_of(&resp), 404);
    assert!(
        !resp.contains("should-not-appear"),
        "未配置域名不能透传到后端: {resp}"
    );
}

#[test]
fn path_is_normalized_before_forwarding() {
    let upstream = Upstream::start("normalized");
    let cfg = write_config("normalize", &config_for(upstream.port));
    let proxy = Proxy::start(&cfg);

    // 关键安全用例：路由按 /other 匹配，后端必须收到规范化后的路径
    let resp = http_get(proxy.port, "nas.home.lan", "//x/../other/secret");
    assert_eq!(status_of(&resp), 200, "响应: {resp}");
    assert_eq!(body_of(&resp), "normalized");
}

#[test]
fn server_starts_and_accepts_connections() {
    // 这条测试看似平凡，但它拦的是"编译通过、启动即崩"的问题
    let upstream = Upstream::start("alive");
    let cfg = write_config("alive", &config_for(upstream.port));
    let proxy = Proxy::start(&cfg);

    let resp = http_get(proxy.port, "nas.home.lan", "/health");
    assert!(
        status_of(&resp) > 0,
        "服务未返回任何 HTTP 响应，可能启动后崩溃"
    );
}

#[test]
fn invalid_config_exits_nonzero() {
    let cfg = write_config(
        "invalid",
        r#"
applications:
  - id: BadId
    name: "坏配置"
    domains: { primary: "bad domain" }
    upstreams: [{ addr: 192.168.1.5, port: 80 }]
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_homewaf"))
        .args(["validate", &cfg])
        .output()
        .expect("执行 validate 失败");

    assert!(!output.status.success(), "非法配置应返回非零退出码");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error") || stderr.contains("失败"),
        "应输出错误信息: {stderr}"
    );
}
