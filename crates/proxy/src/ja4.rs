//! JA4 TLS 客户端指纹。
//!
//! 按 FoxIO 的 [JA4 规范](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
//! 从原始 ClientHello 计算指纹，形如 `t13d1516h2_8daaf6152771_b186095e22b6`。
//!
//! 为什么必须自己解析原始字节：rustls 的 `ClientHello` 只暴露解析后的
//! cipher_suites / named_groups / alpn / signature_schemes，**不给扩展列表与
//! 版本号**，而 JA4 的 `a` 段需要版本位与扩展数、`c` 段需要对扩展列表做哈希。
//! 因此这里在 TLS 握手前嗅探一段原始字节，算完再放回流里。
//!
//! 采集到的指纹按「(客户端地址, 本地地址)」缓存，HTTP 层用同一对地址查回来。
//! 同一个 TCP 连接（含 keep-alive 的多次请求）指纹相同，这也是 JA4 的语义。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 缓存条目存活时间。超过后视为过期，避免长连接表无限增长。
const CACHE_TTL: Duration = Duration::from_secs(300);
/// 缓存条目上限，超过后按过期时间清理一次。
const CACHE_MAX: usize = 8192;
/// ClientHello 最多跨多少个 TLS 记录，防止异常握手把内存读爆。
const MAX_RECORDS: usize = 8;
/// 单条 TLS 记录体上限（TLS 规定 16KB）。
const MAX_RECORD_BODY: usize = 16 * 1024;

/// 进程内指纹缓存。
pub struct Ja4Cache {
    entries: Mutex<HashMap<(SocketAddr, SocketAddr), (String, Instant)>>,
}

impl Ja4Cache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 记录一条连接的指纹。
    pub fn insert(&self, peer: SocketAddr, local: SocketAddr, ja4: String) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        if map.len() >= CACHE_MAX {
            map.retain(|_, (_, at)| now.duration_since(*at) < CACHE_TTL);
        }
        map.insert((peer, local), (ja4, now));
    }

    /// 按地址对查指纹。过期的条目顺手删掉。
    pub fn lookup(&self, peer: SocketAddr, local: SocketAddr) -> Option<String> {
        let Ok(mut map) = self.entries.lock() else {
            return None;
        };
        let now = Instant::now();
        match map.get(&(peer, local)) {
            Some((ja4, at)) if now.duration_since(*at) < CACHE_TTL => Some(ja4.clone()),
            Some(_) => {
                map.remove(&(peer, local));
                None
            }
            None => None,
        }
    }
}

/// 全局缓存。监听回调与代理请求跑在不同的结构里，用进程级单例最省事。
pub fn cache() -> &'static Ja4Cache {
    static CACHE: OnceLock<Ja4Cache> = OnceLock::new();
    CACHE.get_or_init(Ja4Cache::new)
}

/// TLS 握手前嗅探 ClientHello 并记录指纹。
///
/// 挂在 pingora 的 pre-TLS 回调上：读到的字节用 `rewind` 原样放回，
/// 因此握手不受影响。读失败（客户端断开、非 TLS 流量）时不干预，
/// 交给后面的握手逻辑去报错。
pub struct Ja4Sniffer;

#[async_trait::async_trait]
impl pingora::listeners::PreTlsProcess for Ja4Sniffer {
    async fn process(
        &self,
        stream: &mut pingora::protocols::l4::stream::Stream,
    ) -> pingora::Result<()> {
        use pingora::protocols::GetSocketDigest;
        use tokio::io::AsyncReadExt;

        let Some(peer) = stream
            .get_socket_digest()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet().copied()))
        else {
            return Ok(());
        };
        let Some(local) = stream
            .get_socket_digest()
            .and_then(|d| d.local_addr().and_then(|a| a.as_inet().copied()))
        else {
            return Ok(());
        };

        // 一条 ClientHello 通常 500–2000 字节，12KB 足够容纳被拆成多条记录的极端情形
        let mut buf = vec![0u8; 12 * 1024];
        let n = match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        buf.truncate(n);

        if let Some(ja4) = from_records(&buf) {
            cache().insert(peer, local, ja4);
        }
        // 原样放回，握手照常进行
        stream.rewind(&buf);
        Ok(())
    }
}

/// 从原始 TLS 记录字节计算 JA4。
///
/// 输入可以是单条记录，也可是 ClientHello 被拆成多条记录的情形。
/// 非 TLS 握手、非 ClientHello、解析越界一律返回 `None`，调用方按"没有指纹"处理。
pub fn from_records(records: &[u8]) -> Option<String> {
    let body = collect_handshake(records)?;
    parse_client_hello(&body)
}

/// 把 TLS 记录里承载的握手消息拼起来，返回 ClientHello 的那一段。
fn collect_handshake(records: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut pos = 0;
    let mut records_seen = 0;
    while pos + 5 <= records.len() && records_seen < MAX_RECORDS {
        // 记录类型：0x16 = handshake
        if records[pos] != 0x16 {
            break;
        }
        let len = u16::from_be_bytes([records[pos + 3], records[pos + 4]]) as usize;
        if len > MAX_RECORD_BODY || pos + 5 + len > records.len() {
            break;
        }
        body.extend_from_slice(&records[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        records_seen += 1;

        // 握手头 4 字节：类型 + 3 字节长度。凑齐就能判断是否已经完整
        if body.len() >= 4 && body[0] == 0x01 {
            let want = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
            if body.len() >= 4 + want {
                body.truncate(4 + want);
                break;
            }
        }
    }
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    Some(body)
}

/// 解析 ClientHello 消息体（含 4 字节握手头）。
fn parse_client_hello(msg: &[u8]) -> Option<String> {
    let mut p = Reader::new(msg);
    p.skip(4)?; // handshake type + length
    let legacy_version = p.u16()?;
    p.skip(32)?; // random
    let session_len = p.u8()? as usize;
    p.skip(session_len)?; // session id
    let ciphers_len = p.u16()? as usize;
    if ciphers_len % 2 != 0 {
        return None;
    }
    let mut ciphers = Vec::with_capacity(ciphers_len / 2);
    for _ in 0..ciphers_len / 2 {
        ciphers.push(p.u16()?);
    }
    let comp_len = p.u8()? as usize;
    p.skip(comp_len)?; // compression methods
    let exts_len = p.u16()? as usize;
    let mut exts: Vec<(u16, &[u8])> = Vec::new();
    let ext_end = p.pos + exts_len;
    while p.pos + 4 <= ext_end {
        let kind = p.u16()?;
        let len = p.u16()? as usize;
        let data = p.take(len)?;
        exts.push((kind, data));
    }

    // 版本：优先 supported_versions（0x002b）里的最大值
    let version = exts
        .iter()
        .find(|(k, _)| *k == 0x002b)
        .and_then(|(_, data)| highest_supported_version(data))
        .unwrap_or(legacy_version);
    let has_sni = exts.iter().any(|(k, _)| *k == 0x0000);
    let alpn = exts
        .iter()
        .find(|(k, _)| *k == 0x0010)
        .map(|(_, data)| first_alpn(data))
        .unwrap_or_else(|| "00".to_string());

    let ciphers: Vec<u16> = ciphers.into_iter().filter(|c| !is_grease(*c)).collect();
    let ext_types: Vec<u16> = exts
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !is_grease(*k))
        .collect();

    // a 段：协议 + 版本 + 是否有 SNI + 套件数 + 扩展数 + ALPN 首末字符
    let a = format!(
        "t{}{}{:02}{:02}{}",
        version_str(version),
        if has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        ext_types.len().min(99),
        alpn,
    );

    // b 段：套件列表排序后的哈希
    let mut sorted_ciphers: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    sorted_ciphers.sort();
    let b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha12(&sorted_ciphers.join(","))
    };

    // c 段：扩展列表（去掉 SNI 与 ALPN）排序后，拼上签名算法
    let mut sorted_exts: Vec<u16> = ext_types
        .iter()
        .copied()
        .filter(|k| *k != 0x0000 && *k != 0x0010)
        .collect();
    sorted_exts.sort();
    let c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        let ext_part = sorted_exts
            .iter()
            .map(|k| format!("{k:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let sigs = exts
            .iter()
            .find(|(k, _)| *k == 0x000d)
            .map(|(_, data)| signature_algorithms(data))
            .unwrap_or_default();
        if sigs.is_empty() {
            sha12(&ext_part)
        } else {
            sha12(&format!("{ext_part}_{}", sigs.join(",")))
        }
    };

    Some(format!("{a}_{b}_{c}"))
}

fn highest_supported_version(data: &[u8]) -> Option<u16> {
    // 1 字节列表长度 + 若干 u16
    let len = *data.first()? as usize;
    let mut best: Option<u16> = None;
    for chunk in data
        .get(1..1 + len.min(data.len().saturating_sub(1)))?
        .chunks_exact(2)
    {
        let v = u16::from_be_bytes([chunk[0], chunk[1]]);
        if is_grease(v) {
            continue;
        }
        // 0x0304 是最大的正常值；DTLS 版本号（0xfeff 等）不参与比较
        if v <= 0x0304 && best.map(|b| v > b).unwrap_or(true) {
            best = Some(v);
        }
    }
    best
}

fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

/// ALPN 首值的首末字符；非字母数字时退化成十六进制表示的首末字符。
fn first_alpn(data: &[u8]) -> String {
    // 2 字节列表长度，然后逐个「1 字节长度 + 值」
    let Some(&first_len) = data.get(2) else {
        return "00".to_string();
    };
    let start = 3;
    let end = start + first_len as usize;
    let Some(value) = data.get(start..end) else {
        return "00".to_string();
    };
    if value.is_empty() {
        return "00".to_string();
    }
    let pick = |b: u8| -> char {
        if b.is_ascii_alphanumeric() {
            b as char
        } else {
            // 落在非 ASCII 区间的字节用十六进制低位近似，交由下面的分支覆盖
            b as char
        }
    };
    let all_alnum = value.iter().all(|b| b.is_ascii_alphanumeric());
    if all_alnum {
        let first = pick(value[0]);
        let last = pick(value[value.len() - 1]);
        format!("{first}{last}")
    } else {
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        let first = hex.chars().next().unwrap_or('0');
        let last = hex.chars().last().unwrap_or('0');
        format!("{first}{last}")
    }
}

fn signature_algorithms(data: &[u8]) -> Vec<String> {
    let len = data
        .get(0..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .unwrap_or(0);
    data.get(2..2 + len.min(data.len().saturating_sub(2)))
        .map(|list| {
            list.chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .filter(|v| !is_grease(*v))
                .map(|v| format!("{v:04x}"))
                .collect()
        })
        .unwrap_or_default()
}

/// GREASE 值：高低字节相同且低半字节为 0xa（0x0a0a、0x1a1a … 0xfafa）。
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) as u8 == v as u8
}

fn sha12(input: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    digest.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 简易顺序读取器，越界返回 `None`。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(v)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条 ClientHello 记录，便于验证解析与哈希。
    fn hello(
        ciphers: &[u16],
        exts: &[(u16, Vec<u8>)],
        legacy_version: u16,
        sni: bool,
        alpn: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&legacy_version.to_be_bytes());
        ch.extend_from_slice(&[7u8; 32]);
        ch.push(0); // session id 长度 0

        let mut cs = Vec::new();
        for c in ciphers {
            cs.extend_from_slice(&c.to_be_bytes());
        }
        ch.extend_from_slice(&(cs.len() as u16).to_be_bytes());
        ch.extend_from_slice(&cs);
        ch.push(1);
        ch.push(0); // 压缩方式：null

        let mut all: Vec<(u16, Vec<u8>)> = Vec::new();
        if sni {
            let mut d = Vec::new();
            d.extend_from_slice(&9u16.to_be_bytes());
            d.push(0);
            d.extend_from_slice(&5u16.to_be_bytes());
            d.extend_from_slice(b"a.com");
            all.push((0x0000, d));
        }
        if let Some(a) = alpn {
            let mut d = Vec::new();
            let inner = {
                let mut v = Vec::new();
                v.push(a.len() as u8);
                v.extend_from_slice(a);
                v
            };
            d.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            d.extend_from_slice(&inner);
            all.push((0x0010, d));
        }
        all.extend(exts.iter().cloned());

        let mut body = Vec::new();
        for (k, d) in &all {
            body.extend_from_slice(&k.to_be_bytes());
            body.extend_from_slice(&(d.len() as u16).to_be_bytes());
            body.extend_from_slice(d);
        }
        ch.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ch.extend_from_slice(&body);

        let mut msg = Vec::new();
        msg.push(0x01);
        let len = ch.len() as u32;
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend_from_slice(&ch);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.push(0x03);
        rec.push(0x01);
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    #[test]
    fn computes_known_fingerprint() {
        // 套件 1301,1302,1303,c02b,c02f；扩展 000a,000b,002b；签名算法 0403,0804
        let sigs = {
            let mut d = Vec::new();
            d.extend_from_slice(&4u16.to_be_bytes());
            d.extend_from_slice(&0x0403u16.to_be_bytes());
            d.extend_from_slice(&0x0804u16.to_be_bytes());
            d
        };
        let sv = {
            let mut d = Vec::new();
            d.push(4);
            d.extend_from_slice(&0x0304u16.to_be_bytes());
            d.extend_from_slice(&0x0303u16.to_be_bytes());
            d
        };
        let records = hello(
            &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            &[
                (0x000d, sigs),
                (0x002b, sv),
                (0x000a, vec![]),
                (0x000b, vec![]),
            ],
            0x0303,
            true,
            Some(b"h2"),
        );
        let ja4 = from_records(&records).expect("应能算出指纹");
        // a 段：t + 13 + d(有 SNI) + 05 个套件 + 06 个扩展(含 SNI/ALPN) + h2
        assert_eq!(ja4, "t13d0506h2_e133e205ac38_fb71836bce29", "{ja4}");
    }

    #[test]
    fn grease_values_are_ignored() {
        let records = hello(
            &[0x0a0a, 0x1301],
            &[(0x1a1a, vec![]), (0x000b, vec![])],
            0x0303,
            false,
            None,
        );
        let ja4 = from_records(&records).expect("应能算出指纹");
        assert!(ja4.starts_with("t12i0101"), "{ja4}");
    }

    #[test]
    fn alpn_falls_back_to_hex() {
        // 0xAB 0xCD → 十六进制 abcd，取首末 → "ad"
        let records = hello(
            &[0x1301],
            &[(0x000b, vec![])],
            0x0303,
            false,
            Some(&[0xab, 0xcd]),
        );
        let ja4 = from_records(&records).expect("应能算出指纹");
        assert!(ja4.contains("ad_"), "{ja4}");
        // 单字符 ALPN 首末同字符
        let records = hello(&[0x1301], &[(0x000b, vec![])], 0x0303, false, Some(b"h"));
        let ja4 = from_records(&records).expect("应能算出指纹");
        assert!(ja4.starts_with("t12i0102hh_"), "{ja4}");
    }

    #[test]
    fn empty_lists_get_zero_hashes() {
        let records = hello(&[], &[], 0x0303, false, None);
        let ja4 = from_records(&records).expect("应能算出指纹");
        assert_eq!(ja4, "t12i000000_000000000000_000000000000");
    }

    #[test]
    fn non_tls_input_is_rejected() {
        assert!(from_records(b"GET / HTTP/1.1\r\n").is_none());
        assert!(from_records(&[]).is_none());
        // 记录声明长度超过实际数据（被截断）时不给指纹
        assert!(from_records(&[0x16, 0x03, 0x01, 0x10, 0x00, 0x01]).is_none());
    }

    #[test]
    fn cache_returns_per_connection_value() {
        let c = Ja4Cache::new();
        let peer: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
        assert!(c.lookup(peer, local).is_none());
        c.insert(peer, local, "t13d1516h2_aaa_bbb".to_string());
        assert_eq!(c.lookup(peer, local).as_deref(), Some("t13d1516h2_aaa_bbb"));
        // 另一条连接互不干扰
        let other: SocketAddr = "10.0.0.6:5001".parse().unwrap();
        assert!(c.lookup(other, local).is_none());
    }
}
