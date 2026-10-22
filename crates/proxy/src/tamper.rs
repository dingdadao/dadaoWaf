//! 网页防篡改。
//!
//! 用「基线指纹」识别文件改动：建立基线时记录每个受保护文件的大小与 SHA-256，
//! 静态文件请求在返回前先比对指纹。命中变更按应用配置的
//! [`TamperAction`](homewaf_config::TamperAction) 拦截或只记录事件。
//!
//! 被保护目录由 `app.tamper.paths` 决定（相对 `static_site.root`，也支持绝对路径），
//! 为空时默认保护整个静态站点根目录。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use homewaf_config::Application;
use serde::Serialize;

/// 单次扫描的文件数上限，避免误把大目录（如整个家目录）纳入后拖垮进程。
const MAX_FILES: usize = 20_000;
/// 单个文件参与指纹计算的大小上限。
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// 同一个文件写入篡改事件的间隔（秒），防止刷日志。
const EVENT_INTERVAL_SECS: u64 = 60;

/// 数据库中的一条基线：`(路径, 大小, SHA-256 十六进制)`。
pub type BaselineEntry = (String, u64, String);

/// 一个文件的基线指纹。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub size: u64,
    pub digest: [u8; 32],
}

/// 某个应用的基线索引，按规范化绝对路径查找。
#[derive(Debug, Default, Clone)]
pub struct TamperBaseline {
    pub files: HashMap<PathBuf, Fingerprint>,
}

impl TamperBaseline {
    /// 从数据库行 `(路径, 大小, SHA-256 十六进制)` 构建。
    pub fn from_rows(rows: &[BaselineEntry]) -> Self {
        let mut files = HashMap::with_capacity(rows.len());
        for (path, size, hex) in rows {
            let Some(digest) = parse_hex(hex) else {
                continue;
            };
            files.insert(
                PathBuf::from(path),
                Fingerprint {
                    size: *size,
                    digest,
                },
            );
        }
        Self { files }
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// 单个文件相对基线的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// 与基线一致
    Clean,
    /// 内容被修改
    Modified,
    /// 基线中不存在的新文件
    Added,
    /// 不在受保护目录内
    NotCovered,
}

/// 文件相对基线的变化，用于控制台展示。
#[derive(Debug, Clone, Serialize)]
pub struct TamperChange {
    pub path: String,
    /// modified / added / deleted
    pub kind: String,
}

/// 一次扫描/建基线的结果。
#[derive(Debug, Clone, Default, Serialize)]
pub struct TamperScan {
    pub files: usize,
    pub changes: Vec<TamperChange>,
    /// 被跳过的路径（不存在、超限、符号链接等）
    pub skipped: Vec<String>,
}

/// 计算 SHA-256。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// 转为小写十六进制。
pub fn digest_hex(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn parse_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// 应用实际保护的根目录（已规范化）。相对路径按静态站点根目录解析。
pub fn protected_roots(app: &Application) -> Vec<PathBuf> {
    let base = app.static_site.root.trim();
    let mut roots = Vec::new();
    for p in &app.tamper.paths {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let raw = Path::new(p);
        let candidate = if raw.is_absolute() || base.is_empty() {
            raw.to_path_buf()
        } else {
            Path::new(base).join(raw)
        };
        if let Ok(real) = std::fs::canonicalize(&candidate) {
            if !roots.contains(&real) {
                roots.push(real);
            }
        }
    }
    if roots.is_empty() && !base.is_empty() {
        if let Ok(real) = std::fs::canonicalize(base) {
            roots.push(real);
        }
    }
    roots
}

fn under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

/// 校验一个静态文件是否被篡改。`data` 是即将返回的完整内容。
pub fn check_file(
    app: &Application,
    baseline: Option<&TamperBaseline>,
    real: &Path,
    data: &[u8],
) -> FileState {
    if !app.tamper.enabled {
        return FileState::NotCovered;
    }
    let Some(baseline) = baseline else {
        return FileState::NotCovered;
    };
    if baseline.is_empty() {
        // 还没建立基线时不拦截，控制台会提示先建基线
        return FileState::NotCovered;
    }
    let roots = protected_roots(app);
    if !under_roots(real, &roots) {
        return FileState::NotCovered;
    }
    let digest = sha256(data);
    match baseline.files.get(real) {
        Some(fp) if fp.size == data.len() as u64 && fp.digest == digest => FileState::Clean,
        Some(_) => FileState::Modified,
        None => FileState::Added,
    }
}

/// 遍历受保护目录并计算指纹。返回 `(路径, 大小, 十六进制摘要)`。
///
/// `error` 用于把「目录不存在」之类的硬错误带回控制台。
pub fn build_baseline(app: &Application) -> Result<(Vec<BaselineEntry>, TamperScan), String> {
    let roots = protected_roots(app);
    if roots.is_empty() {
        return Err("没有可保护的目录：请先填写静态站点根目录或监控目录".to_string());
    }
    let mut scan = TamperScan::default();
    let mut entries = Vec::new();
    let mut found = Vec::new();

    for root in &roots {
        if !root.exists() {
            scan.skipped.push(root.display().to_string());
            continue;
        }
        walk_files(root, &mut scan.skipped, &mut found);
        if found.len() >= MAX_FILES {
            scan.skipped
                .push(format!("文件数超过上限 {MAX_FILES}，已截断"));
            break;
        }
    }

    let mut seen = HashSet::new();
    for (path, size) in found {
        if !seen.insert(path.clone()) {
            continue;
        }
        match std::fs::read(&path) {
            Ok(data) => {
                entries.push((path.display().to_string(), size, digest_hex(&sha256(&data))))
            }
            Err(_) => scan.skipped.push(path.display().to_string()),
        }
    }
    scan.files = entries.len();

    if entries.is_empty() {
        return Err("受保护目录中没有可建立基线的文件".to_string());
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((entries, scan))
}

/// 与基线对比，找出被修改 / 新增 / 删除的文件。
pub fn scan_changes(app: &Application, baseline: &TamperBaseline) -> Result<TamperScan, String> {
    let roots = protected_roots(app);
    if roots.is_empty() {
        return Err("没有可检查的目录".to_string());
    }
    let mut scan = TamperScan::default();
    let mut found = Vec::new();

    for root in &roots {
        if !root.exists() {
            scan.skipped.push(root.display().to_string());
            continue;
        }
        walk_files(root, &mut scan.skipped, &mut found);
        if found.len() >= MAX_FILES {
            scan.skipped
                .push(format!("文件数超过上限 {MAX_FILES}，结果已截断"));
            break;
        }
    }

    let mut current = HashMap::new();
    for (path, size) in found {
        match std::fs::read(&path) {
            Ok(data) => {
                current.insert(path, (size, sha256(&data)));
            }
            Err(_) => scan.skipped.push(path.display().to_string()),
        }
    }
    scan.files = current.len();
    for (path, (size, digest)) in &current {
        match baseline.files.get(path) {
            None => scan.changes.push(TamperChange {
                path: path.display().to_string(),
                kind: "added".to_string(),
            }),
            Some(fp) if fp.size != *size || fp.digest != *digest => {
                scan.changes.push(TamperChange {
                    path: path.display().to_string(),
                    kind: "modified".to_string(),
                })
            }
            Some(_) => {}
        }
    }
    for path in baseline.files.keys() {
        if !current.contains_key(path) {
            scan.changes.push(TamperChange {
                path: path.display().to_string(),
                kind: "deleted".to_string(),
            });
        }
    }
    scan.changes.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(scan)
}

/// 递归遍历目录，收集普通文件的绝对路径与大小。
/// 跳过符号链接、超大文件和读不到的条目。
fn walk_files(dir: &Path, skipped: &mut Vec<String>, out: &mut Vec<(PathBuf, u64)>) {
    if out.len() >= MAX_FILES {
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        skipped.push(dir.display().to_string());
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            skipped.push(path.display().to_string());
            continue;
        }
        if ft.is_dir() {
            walk_files(&path, skipped, out);
            if out.len() >= MAX_FILES {
                return;
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            skipped.push(path.display().to_string());
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            skipped.push(format!("{}（超过大小上限）", path.display()));
            continue;
        }
        match std::fs::canonicalize(&path) {
            Ok(real) => out.push((real, meta.len())),
            Err(_) => skipped.push(path.display().to_string()),
        }
    }
}

/// 同一应用同一文件 60 秒内最多记录一次事件。
pub fn should_record(app: &str, path: &str) -> bool {
    static LAST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let map = LAST.get_or_init(|| Mutex::new(HashMap::new()));
    let key = format!("{app}\u{1}{path}");
    let Ok(mut map) = map.lock() else {
        return false;
    };
    let now = Instant::now();
    match map.get(&key) {
        Some(last) if now.duration_since(*last).as_secs() < EVENT_INTERVAL_SECS => false,
        _ => {
            map.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use homewaf_config::{AccessMode, Application, TamperConfig};

    fn app(root: &str) -> Application {
        Application {
            id: "static".into(),
            name: "static".into(),
            enabled: true,
            domains: homewaf_config::Domains {
                primary: "static.test".into(),
                aliases: vec![],
            },
            listen_ports: vec![],
            upstreams: vec![],
            routes: vec![],
            tls: Default::default(),
            policy: Default::default(),
            lb: Default::default(),
            timeouts: Default::default(),
            health_check: Default::default(),
            retry: Default::default(),
            headers: Default::default(),
            websocket: false,
            expires_at: None,
            description: String::new(),
            group: String::new(),
            access_mode: AccessMode::Static,
            static_site: homewaf_config::StaticSiteConfig {
                root: root.to_string(),
                index: "index.html".into(),
                spa_fallback: false,
            },
            redirect: Default::default(),
            features: Default::default(),
            tamper: TamperConfig {
                enabled: true,
                paths: vec![],
                action: Default::default(),
            },
        }
    }

    #[test]
    fn digest_is_stable() {
        let d = sha256(b"hello");
        assert_eq!(
            digest_hex(&d),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn detects_modify_and_add() {
        let dir = std::env::temp_dir().join(format!("hw-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, b"one").unwrap();

        let app = app(dir.to_str().unwrap());
        let (rows, scan) = build_baseline(&app).unwrap();
        assert_eq!(scan.files, 1);
        let baseline = TamperBaseline::from_rows(&rows);
        let real = std::fs::canonicalize(&a).unwrap();
        assert_eq!(
            check_file(&app, Some(&baseline), &real, b"one"),
            FileState::Clean
        );

        assert_eq!(
            check_file(&app, Some(&baseline), &real, b"two"),
            FileState::Modified
        );

        let b = dir.join("b.txt");
        std::fs::write(&b, b"new").unwrap();
        let real_b = std::fs::canonicalize(&b).unwrap();
        assert_eq!(
            check_file(&app, Some(&baseline), &real_b, b"new"),
            FileState::Added
        );

        let changes = scan_changes(&app, &baseline).unwrap();
        let kinds: Vec<_> = changes.changes.iter().map(|c| c.kind.as_str()).collect();
        assert!(kinds.contains(&"added"));

        // 真正改写磁盘上的文件后再扫描，应报告 modified
        std::fs::write(&a, b"two").unwrap();
        let changes = scan_changes(&app, &baseline).unwrap();
        let kinds: Vec<_> = changes.changes.iter().map(|c| c.kind.as_str()).collect();
        assert!(kinds.contains(&"modified"));

        std::fs::remove_file(&a).unwrap();
        let changes = scan_changes(&app, &baseline).unwrap();
        assert!(changes.changes.iter().any(|c| c.kind == "deleted"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_app_is_not_checked() {
        let mut a = app("/tmp");
        a.tamper.enabled = false;
        let baseline =
            TamperBaseline::from_rows(&[("/tmp/x".to_string(), 1, digest_hex(&sha256(b"x")))]);
        assert_eq!(
            check_file(&a, Some(&baseline), Path::new("/tmp/x"), b"y"),
            FileState::NotCovered
        );
    }
}
