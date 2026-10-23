//! 人机验证：JS 工作量证明 + 环境指纹 + HMAC 签名凭据。
//!
//! 为什么不直接上滑块/验证码：家用 WAF 没有外部服务依赖，也不该把
//! 用户数据送到第三方。工作量证明由浏览器本地计算，服务端只做一次
//! 哈希校验，零外部依赖。
//!
//! 三道防线（对标商用验证码里便宜且有效的部分，不做 JSVMP）：
//! - **成本墙**：PoW 由浏览器实算，批量通过要付真算力
//! - **环境指纹**：页内采集 canvas/WebGL/屏幕/时区等哈希，混入 PoW 输入，
//!   解题结果与运行环境绑定；webdriver/CDP 等自动化标记服务端直接拒收
//! - **签名绑定**：令牌 HMAC 签名绑定应用 + IP + 过期时间；解题单次使用，
//!   复制回调 URL 重放无效
//!
//! 注意：浏览器端不能用 `crypto.subtle`——家用 WAF 通常走 HTTP，
//! 而 Web Crypto 只在安全上下文（HTTPS / localhost）可用。所以页内
//! 自带一份纯 JS SHA-256。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use homewaf_config::ChallengeConfig;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// 挑战页与验证接口共用同一个路径。
pub const CHALLENGE_PATH: &str = "/.homewaf/challenge";
/// 验证通过后下发的 Cookie 名。
pub const COOKIE_NAME: &str = "homewaf_challenge";

const TOKEN_VERSION: u8 = 1;
const MAX_NEXT_LEN: usize = 1_024;
/// 环境指纹长度：sha256 前 16 个十六进制字符。
const FP_LEN: usize = 16;
/// 防重放表上限，超过即按过期时间清理。
const USED_CAP: usize = 8_192;

/// 挑战服务。持有 HMAC 密钥与已用解题记录，整个进程共享一个实例。
pub struct ChallengeService {
    key: hmac::Key,
    used: Mutex<HashMap<String, u64>>,
}

impl ChallengeService {
    pub fn new() -> Self {
        let mut raw = [0u8; 32];
        SystemRandom::new()
            .fill(&mut raw)
            .expect("系统随机数不可用，无法启动人机验证");
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &raw),
            used: Mutex::new(HashMap::new()),
        }
    }

    /// 生成一次挑战。
    pub fn issue(
        &self,
        cfg: &ChallengeConfig,
        app: &str,
        ip: Option<IpAddr>,
        next: &str,
        now: u64,
    ) -> Issued {
        let next = truncate(next, MAX_NEXT_LEN);
        let payload = TokenPayload {
            v: TOKEN_VERSION,
            e: now.saturating_add(cfg.ttl.as_secs()),
            a: app.to_string(),
            i: ip.map(|i| i.to_string()).unwrap_or_default(),
            n: next.to_string(),
            d: cfg.difficulty.clamp(1, 8),
        };
        let token = self.sign_json("token", &payload);
        let page = render_page(&token, payload.d);
        Issued {
            token,
            difficulty: payload.d,
            page,
        }
    }

    /// 校验挑战令牌、环境指纹与工作量证明。
    pub fn verify(
        &self,
        sol: &Solution,
        app: &str,
        ip: Option<IpAddr>,
        now: u64,
    ) -> Result<TokenPayload, ChallengeError> {
        let body = self.verify_signed("token", sol.token)?;
        let payload: TokenPayload =
            serde_json::from_slice(&body).map_err(|_| ChallengeError::Malformed)?;
        if payload.v != TOKEN_VERSION {
            return Err(ChallengeError::Malformed);
        }
        if payload.e <= now {
            return Err(ChallengeError::Expired);
        }
        if payload.a != app || payload.i != ip.map(|i| i.to_string()).unwrap_or_default() {
            return Err(ChallengeError::WrongClient);
        }
        if automated(sol.env) {
            return Err(ChallengeError::Automated);
        }
        if !fp_ok(sol.fp) {
            return Err(ChallengeError::BadFingerprint);
        }

        let difficulty = payload.d.clamp(1, 8);
        if !proof_ok(sol.token, sol.fp, sol.nonce, difficulty) {
            return Err(ChallengeError::BadProof);
        }

        // 单次使用：同一 (token, nonce, fp) 的解题只认一次，
        // 复制回调 URL 到别的会话/机器重放无效。
        let key = used_key(sol.token, sol.nonce, sol.fp);
        let mut used = self.used.lock().expect("防重放表锁不应中毒");
        if used.len() >= USED_CAP {
            used.retain(|_, exp| *exp > now);
        }
        if used.contains_key(&key) {
            return Err(ChallengeError::Replay);
        }
        used.insert(key, payload.e);
        Ok(payload)
    }

    /// 验证通过后下发 Cookie 值。
    pub fn issue_cookie(
        &self,
        cfg: &ChallengeConfig,
        app: &str,
        ip: Option<IpAddr>,
        now: u64,
    ) -> String {
        let payload = CookiePayload {
            v: TOKEN_VERSION,
            e: now.saturating_add(cfg.ttl.as_secs()),
            a: app.to_string(),
            i: ip.map(|i| i.to_string()).unwrap_or_default(),
        };
        self.sign_json("cookie", &payload)
    }

    /// 校验 Cookie。只需 HMAC + 过期时间，没有哈希计算。
    pub fn verify_cookie(&self, value: &str, app: &str, ip: Option<IpAddr>, now: u64) -> bool {
        let Ok(body) = self.verify_signed("cookie", value) else {
            return false;
        };
        let Ok(payload) = serde_json::from_slice::<CookiePayload>(&body) else {
            return false;
        };
        payload.v == TOKEN_VERSION
            && payload.e > now
            && payload.a == app
            && payload.i == ip.map(|i| i.to_string()).unwrap_or_default()
    }

    /// `Set-Cookie` 的完整值。HTTPS 下加 `Secure`。
    pub fn cookie_header(&self, value: &str, ttl_secs: u64, secure: bool) -> String {
        format!(
            "{COOKIE_NAME}={value}; Path=/; Max-Age={ttl_secs}; HttpOnly; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        )
    }

    fn sign_json<T: Serialize>(&self, kind: &str, payload: &T) -> String {
        let bytes = serde_json::to_vec(payload).expect("挑战载荷序列化不应失败");
        let body = b64url_encode(&bytes);
        let sig = hmac::sign(&self.key, signing_input(kind, &body).as_bytes());
        format!("{body}.{}", b64url_encode(sig.as_ref()))
    }

    fn verify_signed(&self, kind: &str, token: &str) -> Result<Vec<u8>, ChallengeError> {
        let (body, sig) = token.split_once('.').ok_or(ChallengeError::Malformed)?;
        let sig = b64url_decode(sig).ok_or(ChallengeError::Malformed)?;
        hmac::verify(&self.key, signing_input(kind, body).as_bytes(), &sig)
            .map_err(|_| ChallengeError::BadSignature)?;
        b64url_decode(body).ok_or(ChallengeError::Malformed)
    }
}

impl Default for ChallengeService {
    fn default() -> Self {
        Self::new()
    }
}

fn signing_input(kind: &str, body: &str) -> String {
    format!("homewaf-challenge-v1\0{kind}\0{body}")
}

/// 一次挑战的产物。
pub struct Issued {
    pub token: String,
    pub difficulty: u8,
    pub page: String,
}

/// 浏览器回传的一次解题：令牌、nonce、环境指纹与自动化标记。
pub struct Solution<'a> {
    pub token: &'a str,
    pub nonce: &'a str,
    pub fp: &'a str,
    pub env: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPayload {
    v: u8,
    e: u64,
    a: String,
    i: String,
    n: String,
    d: u8,
}

impl TokenPayload {
    /// 验证通过后应跳回的路径（含查询串）。
    pub fn next(&self) -> &str {
        &self.n
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CookiePayload {
    v: u8,
    e: u64,
    a: String,
    i: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    #[error("挑战令牌格式错误")]
    Malformed,
    #[error("挑战令牌签名无效")]
    BadSignature,
    #[error("挑战已过期")]
    Expired,
    #[error("挑战与当前应用或 IP 不匹配")]
    WrongClient,
    #[error("环境指纹缺失或异常")]
    BadFingerprint,
    #[error("检测到自动化浏览器")]
    Automated,
    #[error("解题结果已使用过")]
    Replay,
    #[error("工作量证明无效")]
    BadProof,
}

/// 服务端 PoW 校验：`sha256(token + "." + fp + "." + nonce)` 需有
/// `difficulty` 个前导零十六进制位。指纹混入输入，解题结果即绑定环境。
fn proof_ok(token: &str, fp: &str, nonce: &str, difficulty: u8) -> bool {
    if nonce.is_empty() || nonce.len() > 32 || !nonce.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut input = Vec::with_capacity(token.len() + fp.len() + nonce.len() + 2);
    input.extend_from_slice(token.as_bytes());
    input.push(b'.');
    input.extend_from_slice(fp.as_bytes());
    input.push(b'.');
    input.extend_from_slice(nonce.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);
    count_leading_zero_hex(digest.as_ref()) >= difficulty as usize
}

/// 环境指纹格式校验：16 位十六进制，且不能是全零退化值。
fn fp_ok(fp: &str) -> bool {
    fp.len() == FP_LEN
        && fp.bytes().all(|b| b.is_ascii_hexdigit())
        && !fp.bytes().all(|b| b == b'0')
}

/// 自动化标记串形如 `wd=0.cdp=0`；任一标记为 1 即判定自动化环境。
/// 标记由页内 JS 如实上报：webdriver 与 CDP 注入物是自动化浏览器的
/// 固有特征，正常浏览器恒为 0。两个标记必须齐全——缺字段视为
/// 客户端故意隐瞒，同样拒收。
fn automated(env: &str) -> bool {
    let mut wd = None;
    let mut cdp = None;
    for part in env.split('.') {
        let (key, val) = match part.split_once('=') {
            Some(kv) => kv,
            None => return true,
        };
        let flag = match val {
            "0" => false,
            "1" => true,
            _ => return true,
        };
        match key {
            "wd" => wd = Some(flag),
            "cdp" => cdp = Some(flag),
            _ => return true,
        }
    }
    match (wd, cdp) {
        (Some(a), Some(b)) => a || b,
        _ => true,
    }
}

fn used_key(token: &str, nonce: &str, fp: &str) -> String {
    let mut input = Vec::with_capacity(token.len() + nonce.len() + fp.len() + 2);
    input.extend_from_slice(token.as_bytes());
    input.push(b'.');
    input.extend_from_slice(nonce.as_bytes());
    input.push(b'.');
    input.extend_from_slice(fp.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);
    digest
        .as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn count_leading_zero_hex(bytes: &[u8]) -> usize {
    let mut count = 0;
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0x0f;
        if hi == 0 {
            count += 1;
        } else {
            return count;
        }
        if lo == 0 {
            count += 1;
        } else {
            return count;
        }
    }
    count
}

fn truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// URL 安全的 Base64，无填充。
fn b64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// 从 Cookie 头里取指定名字的值。
pub fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    let header = header?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
}

fn render_page(token: &str, difficulty: u8) -> String {
    // token 是 base64url，不含引号/尖括号，直接插入脚本安全
    format!(
        r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#f7f7f5; color:#2c2c2a;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }}
  .box {{ text-align:center; padding:40px 24px; max-width:420px; }}
  .ring {{ width:44px; height:44px; margin:0 auto 20px; border:3px solid #d9d7cf;
          border-top-color:#2c2c2a; border-radius:50%; animation:spin 1s linear infinite; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  h1 {{ font-size:18px; margin:0 0 10px; font-weight:600; }}
  p {{ font-size:14px; color:#5f5e5a; margin:6px 0; line-height:1.6; }}
  .hint {{ font-size:12px; color:#888780; }}
  .done {{ display:none; }}
</style>
</head>
<body>
  <div class="box">
    <div class="ring" id="ring"></div>
    <h1 id="title">正在验证您的浏览器</h1>
    <p id="msg">这一步用于确认访问来自真实浏览器，通常只需一两秒。</p>
    <p class="hint" id="hint"></p>
  </div>
<script>
(function () {{
  var token = "{token}";
  var difficulty = {difficulty};
  var nonce = 0;
  var started = Date.now();
  var title = document.getElementById("title");
  var msg = document.getElementById("msg");
  var hint = document.getElementById("hint");

  function sha256(ascii) {{
    function rr(v, a) {{ return (v >>> a) | (v << (32 - a)); }}
    var maxWord = Math.pow(2, 32), result = "", words = [], asciiBitLength = ascii.length * 8;
    var hash = sha256.h = sha256.h || [], k = sha256.k = sha256.k || [], primeCounter = k.length;
    var isComposite = {{}};
    for (var candidate = 2; primeCounter < 64; candidate++) {{
      if (!isComposite[candidate]) {{
        for (var i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (Math.pow(candidate, .5) * maxWord) | 0;
        k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
      }}
    }}
    ascii += "\x80";
    while (ascii.length % 64 - 56) ascii += "\x00";
    for (i = 0; i < ascii.length; i++) {{
      var j = ascii.charCodeAt(i);
      if (j >> 8) return "";
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }}
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;
    for (j = 0; j < words.length;) {{
      var w = words.slice(j, j += 16), oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {{
        var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
        var temp1 = hash[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) +
          ((e & hash[5]) ^ ((~e) & hash[6])) + k[i] +
          (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) +
            w[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0);
        var temp2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) +
          ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }}
      for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }}
    for (i = 0; i < 8; i++) {{
      for (j = 3; j + 1; j--) {{
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? "0" : "") + b.toString(16);
      }}
    }}
    return result;
  }}

  function ok(hex) {{
    for (var i = 0; i < difficulty; i++) if (hex.charAt(i) !== "0") return false;
    return true;
  }}

  // ---- 环境指纹：canvas / WebGL / 屏幕 / 时区等合成一个哈希 ----
  function canvasHash() {{
    try {{
      var c = document.createElement("canvas");
      c.width = 200; c.height = 40;
      var x = c.getContext("2d");
      x.textBaseline = "top"; x.font = "14px Arial"; x.fillStyle = "#f60";
      x.fillRect(0, 0, 100, 20);
      x.fillStyle = "#069"; x.fillText("homewaf", 2, 15);
      x.fillStyle = "rgba(102,204,0,0.7)"; x.fillText("fp", 60, 18);
      return sha256(c.toDataURL()).slice(0, 16);
    }} catch (e) {{ return "nocanvas"; }}
  }}
  function glHash() {{
    try {{
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      var r = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      return sha256(String(r)).slice(0, 8);
    }} catch (e) {{ return "nogl"; }}
  }}
  // 自动化标记：webdriver 与 CDP 注入物是自动化浏览器的固有特征
  var wd = (navigator.webdriver === true) ? 1 : 0;
  var cdp = (window.domAutomationController || document.$cdc_asdjflasutopfhvcZLmcfl_
             || window.cdc_adoQpoasnfa76pfcZLmcfl_Array) ? 1 : 0;
  var env = "wd=" + wd + ".cdp=" + cdp;
  var fp = sha256([wd, cdp, screen.width, screen.height, screen.colorDepth,
                   Intl.DateTimeFormat().resolvedOptions().timeZone,
                   navigator.language, navigator.hardwareConcurrency,
                   canvasHash(), glHash()].join("|")).slice(0, 16);

  if (wd === 1 || cdp === 1) {{
    title.textContent = "验证已停止";
    msg.textContent = "检测到自动化浏览器特征，本验证只面向真实用户浏览器。";
    document.getElementById("ring").className = "done";
    return;
  }}

  function tick() {{
    var end = Date.now() + 80;
    while (Date.now() < end) {{
      if (ok(sha256(token + "." + fp + "." + nonce))) {{
        title.textContent = "验证通过";
        msg.textContent = "正在进入，请稍候…";
        document.getElementById("ring").className = "done";
        location.replace("{path}?token=" + encodeURIComponent(token) + "&nonce=" + nonce
                         + "&fp=" + fp + "&env=" + env);
        return;
      }}
      nonce++;
    }}
    var secs = Math.round((Date.now() - started) / 1000);
    hint.textContent = "已计算 " + nonce.toLocaleString() + " 次 · " + secs + " 秒 · 指纹 " + fp;
    setTimeout(tick, 0);
  }}
  tick();
}})();
</script>
</body>
</html>"##,
        path = CHALLENGE_PATH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ChallengeConfig {
        ChallengeConfig {
            enabled: true,
            difficulty: 1,
            ttl: homewaf_config::Duration::from_secs(60),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn solve(token: &str, fp: &str, difficulty: u8) -> String {
        for nonce in 0u64..1_000_000 {
            let n = nonce.to_string();
            if proof_ok(token, fp, &n, difficulty) {
                return n;
            }
        }
        panic!("难度 {difficulty} 在 100 万次内无解");
    }

    const FP: &str = "0123456789abcdef";
    const ENV: &str = "wd=0.cdp=0";

    macro_rules! v {
        ($svc:expr, $token:expr, $nonce:expr, $fp:expr, $env:expr, $app:expr, $ip:expr, $now:expr) => {
            $svc.verify(
                &Solution {
                    token: $token,
                    nonce: $nonce,
                    fp: $fp,
                    env: $env,
                },
                $app,
                Some($ip),
                $now,
            )
        };
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/admin?x=1", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        let payload = v!(&svc, &issued.token, &nonce, FP, ENV, "nas", ip("192.168.1.9"), 1_001)
            .expect("应通过验证");
        assert_eq!(payload.next(), "/admin?x=1");
    }

    #[test]
    fn token_is_bound_to_ip() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        assert_eq!(
            v!(&svc, &issued.token, &nonce, FP, ENV, "nas", ip("192.168.1.10"), 1_001),
            Err(ChallengeError::WrongClient)
        );
    }

    #[test]
    fn token_is_bound_to_app() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        assert_eq!(
            v!(&svc, &issued.token, &nonce, FP, ENV, "blog", ip("192.168.1.9"), 1_001),
            Err(ChallengeError::WrongClient)
        );
    }

    #[test]
    fn token_expires() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        assert_eq!(
            v!(&svc, &issued.token, &nonce, FP, ENV, "nas", ip("192.168.1.9"), 1_060),
            Err(ChallengeError::Expired)
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let mut tampered = issued.token.clone();
        // 改 payload 中段而不是末位：base64url 末位含填充位，
        // 换一个末位字符可能解码出相同字节，签名仍然有效。
        let pos = tampered.len() / 2;
        let ch = tampered.as_bytes()[pos] as char;
        let repl = if ch == 'A' { 'B' } else { 'A' };
        tampered.replace_range(pos..pos + 1, &repl.to_string());
        assert!(matches!(
            v!(&svc, &tampered, "0", FP, ENV, "nas", ip("192.168.1.9"), 1_001),
            Err(ChallengeError::BadSignature) | Err(ChallengeError::Malformed)
        ));
    }

    #[test]
    fn wrong_proof_rejected() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        assert_eq!(
            v!(
                &svc,
                &issued.token,
                "not-a-number",
                FP,
                ENV,
                "nas",
                ip("192.168.1.9"),
                1_001
            ),
            Err(ChallengeError::BadProof)
        );
    }

    #[test]
    fn proof_is_bound_to_fingerprint() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let other = "fedcba9876543210";
        // 难度 1 时错误指纹有 1/16 概率碰巧也满足前导零，挑一个只对原指纹成立的解
        let nonce = (0u64..1_000_000)
            .map(|n| n.to_string())
            .find(|n| {
                proof_ok(&issued.token, FP, n, issued.difficulty)
                    && !proof_ok(&issued.token, other, n, issued.difficulty)
            })
            .expect("应能找到只对原指纹成立的解");
        // 换个环境（指纹不同）复用同一解题，PoW 不再成立
        assert_eq!(
            v!(
                &svc,
                &issued.token,
                &nonce,
                other,
                ENV,
                "nas",
                ip("192.168.1.9"),
                1_001
            ),
            Err(ChallengeError::BadProof)
        );
    }

    #[test]
    fn degenerate_fingerprints_rejected() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        for bad in [
            "",
            "0000000000000000",
            "zzzzzzzzzzzzzzzz",
            "0123456789abcde",
            "0123456789abcdef0",
        ] {
            assert_eq!(
                v!(&svc, &issued.token, &nonce, bad, ENV, "nas", ip("192.168.1.9"), 1_001),
                Err(ChallengeError::BadFingerprint),
                "指纹 {bad:?} 应被拒"
            );
        }
    }

    #[test]
    fn automated_environments_rejected() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        for bad in ["", "wd=1.cdp=0", "wd=0.cdp=1", "wd=0", "wd=x.cdp=0"] {
            assert_eq!(
                v!(&svc, &issued.token, &nonce, FP, bad, "nas", ip("192.168.1.9"), 1_001),
                Err(ChallengeError::Automated),
                "标记 {bad:?} 应被拒"
            );
        }
    }

    #[test]
    fn solution_is_single_use() {
        let svc = ChallengeService::new();
        let issued = svc.issue(&cfg(), "nas", Some(ip("192.168.1.9")), "/", 1_000);
        let nonce = solve(&issued.token, FP, issued.difficulty);
        v!(&svc, &issued.token, &nonce, FP, ENV, "nas", ip("192.168.1.9"), 1_001)
            .expect("首次应通过");
        assert_eq!(
            v!(&svc, &issued.token, &nonce, FP, ENV, "nas", ip("192.168.1.9"), 1_002),
            Err(ChallengeError::Replay)
        );
    }

    #[test]
    fn cookie_roundtrip_and_binding() {
        let svc = ChallengeService::new();
        let cookie = svc.issue_cookie(&cfg(), "nas", Some(ip("192.168.1.9")), 1_000);

        assert!(svc.verify_cookie(&cookie, "nas", Some(ip("192.168.1.9")), 1_059));
        assert!(!svc.verify_cookie(&cookie, "blog", Some(ip("192.168.1.9")), 1_059));
        assert!(!svc.verify_cookie(&cookie, "nas", Some(ip("192.168.1.10")), 1_059));
        assert!(!svc.verify_cookie(&cookie, "nas", Some(ip("192.168.1.9")), 1_060));
    }

    #[test]
    fn cookie_header_has_security_attributes() {
        let svc = ChallengeService::new();
        let cookie = svc.issue_cookie(&cfg(), "nas", None, 1_000);
        let header = svc.cookie_header(&cookie, 60, true);
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Secure"));
        assert!(!svc.cookie_header(&cookie, 60, false).contains("Secure"));
    }

    #[test]
    fn cookie_parser_picks_named_value() {
        let header = "a=1; homewaf_challenge=abc.def; b=2";
        assert_eq!(cookie_value(Some(header), COOKIE_NAME), Some("abc.def"));
        assert_eq!(cookie_value(Some(header), "missing"), None);
        assert_eq!(cookie_value(None, COOKIE_NAME), None);
    }

    #[test]
    fn base64url_roundtrip() {
        for input in [b"".as_slice(), b"a", b"ab", b"abc", b"hello world!"] {
            let enc = b64url_encode(input);
            assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='));
            assert_eq!(b64url_decode(&enc).as_deref(), Some(input));
        }
    }

    #[test]
    fn leading_zero_counter() {
        assert_eq!(count_leading_zero_hex(&[0x00, 0x00]), 4);
        assert_eq!(count_leading_zero_hex(&[0x0f]), 1);
        assert_eq!(count_leading_zero_hex(&[0xf0]), 0);
    }
}
