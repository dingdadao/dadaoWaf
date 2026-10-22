//! 规则包格式、解析与验签。
//!
//! 规则包是「签名头 + 规则文档」的纯文本，签名覆盖签名行之后的**原始字节**：
//!
//! ```text
//! # homewaf-signature: ed25519:<base64>
//! {
//!   "format": "homewaf-rules",
//!   "version": "2026.10.1",
//!   "rules": [ ... ]
//! }
//! ```
//!
//! 为什么签名覆盖原始字节而不是「反序列化后再序列化」：后者会因键顺序、
//! 空白、Unicode 转义等差异产生不同字节，验签结果不可预测。原始字节方案
//! 允许 CDN 原样分发，任何改动都能被发现。
//!
//! 规则文档支持 JSON 与 YAML。未知字段会被忽略，方便订阅源附加描述、
//! CVE 编号等元数据而不破坏旧版本客户端。

use std::collections::HashSet;

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::Deserialize;

use crate::rule::{Action, Category, RuleMeta, RuleSource, Severity, Target, BUILTIN_RULES};

/// 签名头前缀。必须位于文件第一行。
pub const SIGNATURE_PREFIX: &str = "# homewaf-signature:";
/// 单个规则包最多规则数。防止恶意订阅源把内存与编译时间打爆。
pub const MAX_RULES: usize = 2_000;
/// 正则最大长度。
pub const MAX_PATTERN_LEN: usize = 512;
/// 单条规则最多关键词数。
pub const MAX_KEYWORDS: usize = 16;
/// 单个关键词最大长度。
pub const MAX_KEYWORD_LEN: usize = 64;
/// 规则 id / 名称长度上限。
pub const MAX_ID_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 128;

/// 规则包解析失败原因。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleFeedError {
    #[error("规则包为空")]
    Empty,
    #[error("规则包格式错误：{0}")]
    Format(String),
    #[error("缺少签名，但该订阅要求验签")]
    MissingSignature,
    #[error("公钥格式非法：{0}")]
    PublicKey(String),
    #[error("签名校验失败")]
    BadSignature,
    #[error("规则数量 {0} 超过上限 {MAX_RULES}")]
    TooManyRules(usize),
    #[error("规则 `{id}` 非法：{message}")]
    InvalidRule { id: String, message: String },
    #[error("规则 id `{0}` 重复")]
    DuplicateId(String),
}

/// 解析后的规则包。
#[derive(Debug, Clone)]
pub struct ParsedRuleFeed {
    pub format: Option<String>,
    pub version: Option<String>,
    pub channel: Option<String>,
    pub declared_name: Option<String>,
    pub rules: Vec<RuleMeta>,
}

#[derive(Debug, Deserialize)]
struct RuleFeedDocument {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    version: Option<VersionValue>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    rules: Vec<RuleDefinition>,
}

/// 版本号既可能是 `1` 也可能是 `"2026.10.1"`，两种都接受。
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VersionValue {
    Text(String),
    Number(u64),
}

impl VersionValue {
    fn into_string(self) -> String {
        match self {
            VersionValue::Text(s) => s,
            VersionValue::Number(n) => n.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuleDefinition {
    id: String,
    name: String,
    category: String,
    severity: String,
    pattern: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default = "default_action")]
    action: String,
}

fn default_action() -> String {
    "block".to_string()
}

/// 拆出签名与待验签的原始载荷。
///
/// 返回的 `&str` 指向 `input` 中签名行之后的字节，不做任何 trim——
/// 验签必须使用与发送方完全一致的载荷。
pub fn split_signature(input: &str) -> Result<(Option<Vec<u8>>, &str), RuleFeedError> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    if input.trim().is_empty() {
        return Err(RuleFeedError::Empty);
    }

    let Some((first, rest)) = input.split_once('\n') else {
        return Ok((None, input));
    };
    let first = first.trim_end_matches('\r');
    let Some(value) = first.strip_prefix(SIGNATURE_PREFIX) else {
        return Ok((None, input));
    };

    let value = value.trim();
    let (algo, encoded) = value
        .split_once(':')
        .ok_or_else(|| RuleFeedError::Format("签名头缺少算法前缀".to_string()))?;
    if !algo.eq_ignore_ascii_case("ed25519") {
        return Err(RuleFeedError::Format(format!(
            "不支持的签名算法 `{algo}`（仅支持 ed25519）"
        )));
    }
    let sig = decode_base64(encoded)
        .map_err(|e| RuleFeedError::Format(format!("签名不是合法 base64：{e}")))?;
    if sig.len() != 64 {
        return Err(RuleFeedError::Format(format!(
            "Ed25519 签名应为 64 字节，实际 {}",
            sig.len()
        )));
    }
    if rest.trim().is_empty() {
        return Err(RuleFeedError::Empty);
    }
    Ok((Some(sig), rest))
}

/// 校验 Ed25519 签名。`public_key` 形如 `ed25519:<base64>`，也接受裸 base64。
pub fn verify_signature(
    public_key: &str,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), RuleFeedError> {
    let key = parse_public_key(public_key)?;
    let verifier = UnparsedPublicKey::new(&signature::ED25519, key);
    verifier
        .verify(payload, signature)
        .map_err(|_| RuleFeedError::BadSignature)
}

fn parse_public_key(public_key: &str) -> Result<Vec<u8>, RuleFeedError> {
    let trimmed = public_key.trim();
    let encoded = match trimmed.split_once(':') {
        Some((algo, rest)) if algo.eq_ignore_ascii_case("ed25519") => rest,
        Some((algo, _)) => {
            return Err(RuleFeedError::PublicKey(format!(
                "不支持的算法 `{algo}`（仅支持 ed25519）"
            )))
        }
        None => trimmed,
    };
    let key = decode_base64(encoded)
        .map_err(|e| RuleFeedError::PublicKey(format!("公钥不是合法 base64：{e}")))?;
    if key.len() != 32 {
        return Err(RuleFeedError::PublicKey(format!(
            "Ed25519 公钥应为 32 字节，实际 {}",
            key.len()
        )));
    }
    Ok(key)
}

/// 解析规则文档。`feed_name` 会写进每条规则的来源。
pub fn parse_rules(payload: &str, feed_name: &str) -> Result<ParsedRuleFeed, RuleFeedError> {
    let trimmed = payload.strip_prefix('\u{feff}').unwrap_or(payload).trim();
    if trimmed.is_empty() {
        return Err(RuleFeedError::Empty);
    }

    let doc: RuleFeedDocument = if trimmed.starts_with('{') {
        serde_json::from_str(trimmed)
            .map_err(|e| RuleFeedError::Format(format!("JSON 解析失败：{e}")))?
    } else if trimmed.starts_with('[') {
        return Err(RuleFeedError::Format(
            "规则包必须是对象，顶层不能是数组".to_string(),
        ));
    } else {
        serde_yaml::from_str(trimmed)
            .map_err(|e| RuleFeedError::Format(format!("YAML 解析失败：{e}")))?
    };

    if let Some(format) = &doc.format {
        if format != "homewaf-rules" {
            return Err(RuleFeedError::Format(format!(
                "不支持的规则包格式 `{format}`（期望 homewaf-rules）"
            )));
        }
    }
    if doc.rules.len() > MAX_RULES {
        return Err(RuleFeedError::TooManyRules(doc.rules.len()));
    }
    if doc.rules.is_empty() {
        return Err(RuleFeedError::Format("规则包不包含任何规则".to_string()));
    }

    let mut seen = HashSet::with_capacity(doc.rules.len());
    let mut rules = Vec::with_capacity(doc.rules.len());
    for def in doc.rules {
        let rule = convert_rule(def, feed_name)?;
        if BUILTIN_RULES.iter().any(|r| r.id == rule.id) {
            return Err(RuleFeedError::DuplicateId(rule.id));
        }
        if !seen.insert(rule.id.clone()) {
            return Err(RuleFeedError::DuplicateId(rule.id));
        }
        rules.push(rule);
    }

    Ok(ParsedRuleFeed {
        format: doc.format,
        version: doc.version.map(VersionValue::into_string),
        channel: doc.channel.map(|c| c.to_ascii_lowercase()),
        declared_name: doc.name,
        rules,
    })
}

fn convert_rule(def: RuleDefinition, feed_name: &str) -> Result<RuleMeta, RuleFeedError> {
    let id = def.id.trim().to_string();
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(invalid(&id, format!("id 长度应为 1-{MAX_ID_LEN}")));
    }
    // 逗号会破坏事件表里用逗号拼接的规则列表；空白会让日志难以检索
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(invalid(
            &id,
            "id 只能包含字母、数字、`-`、`_`、`.`、`:`".to_string(),
        ));
    }

    let name = def.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(&id, format!("name 长度应为 1-{MAX_NAME_LEN}")));
    }

    let category = Category::parse(&def.category)
        .ok_or_else(|| invalid(&id, format!("未知分类 `{}`", def.category)))?;
    let severity = Severity::parse(&def.severity)
        .ok_or_else(|| invalid(&id, format!("未知级别 `{}`", def.severity)))?;
    let action =
        Action::parse(&def.action).ok_or_else(|| invalid(&id, format!("未知动作 `{}`", def.action)))?;

    let pattern = def.pattern.trim().to_string();
    if pattern.is_empty() {
        return Err(invalid(&id, "pattern 不能为空".to_string()));
    }
    if pattern.chars().count() > MAX_PATTERN_LEN {
        return Err(invalid(
            &id,
            format!("pattern 超过 {MAX_PATTERN_LEN} 字符"),
        ));
    }
    regex::Regex::new(&pattern).map_err(|e| invalid(&id, format!("正则非法：{e}")))?;

    if def.targets.is_empty() {
        return Err(invalid(&id, "targets 不能为空".to_string()));
    }
    let mut targets = Vec::with_capacity(def.targets.len());
    for target in &def.targets {
        let parsed = Target::parse(target)
            .ok_or_else(|| invalid(&id, format!("未知检测目标 `{target}`")))?;
        if !targets.contains(&parsed) {
            targets.push(parsed);
        }
    }

    if def.keywords.len() > MAX_KEYWORDS {
        return Err(invalid(
            &id,
            format!("keywords 超过 {MAX_KEYWORDS} 个"),
        ));
    }
    let mut keywords = Vec::with_capacity(def.keywords.len());
    for keyword in &def.keywords {
        let keyword = keyword.trim().to_lowercase();
        if keyword.is_empty() {
            return Err(invalid(&id, "keywords 不能包含空字符串".to_string()));
        }
        if keyword.chars().count() > MAX_KEYWORD_LEN {
            return Err(invalid(
                &id,
                format!("关键词超过 {MAX_KEYWORD_LEN} 字符"),
            ));
        }
        if !keywords.contains(&keyword) {
            keywords.push(keyword);
        }
    }

    Ok(RuleMeta {
        id,
        name,
        category,
        severity,
        pattern,
        targets,
        keywords,
        action,
        shadow: false,
        source: RuleSource::Feed(feed_name.to_string()),
    })
}

fn invalid(id: &str, message: String) -> RuleFeedError {
    RuleFeedError::InvalidRule {
        id: id.to_string(),
        message,
    }
}

/// 生成 Ed25519 签名密钥。
///
/// 返回 PKCS#8 DER 私钥字节和 `ed25519:<base64>` 公钥。
/// 私钥不落地由调用方负责——CLI 会以 0600 权限写入文件。
pub fn generate_signing_key() -> Result<(Vec<u8>, String), String> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "生成 Ed25519 密钥失败".to_string())?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "解析刚生成的 Ed25519 密钥失败".to_string())?;
    let public = format!("ed25519:{}", encode_base64(pair.public_key().as_ref()));
    Ok((pkcs8.as_ref().to_vec(), public))
}

/// 用 PKCS#8 DER 私钥给规则文档签名，返回完整的规则包文本。
pub fn sign_payload(key_pkcs8: &[u8], payload: &str) -> Result<String, String> {
    let pair = Ed25519KeyPair::from_pkcs8(key_pkcs8)
        .map_err(|_| "私钥格式非法（需要 PKCS#8 DER）".to_string())?;
    let signature = pair.sign(payload.as_bytes());
    Ok(format!(
        "{} ed25519:{}\n{}",
        SIGNATURE_PREFIX,
        encode_base64(signature.as_ref()),
        payload
    ))
}

/// 标准 base64 编码。仅用于测试/工具生成签名头。
pub fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0;

    for c in input.trim().chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            padding += 1;
            if padding > 2 {
                return Err("填充字符过多".to_string());
            }
            continue;
        }
        if padding > 0 {
            return Err("填充字符出现在数据中间".to_string());
        }
        let value = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("非法字符 `{c}`")),
        } as u32;

        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }

    if bits > 0 && acc != 0 {
        return Err("尾部填充位非零".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const DOC: &str = r#"{
        "format": "homewaf-rules",
        "version": "2026.10.1",
        "rules": [{
            "id": "feed-test-evil",
            "name": "测试恶意特征",
            "category": "custom",
            "severity": "high",
            "pattern": "evil-[a-z]{4}",
            "targets": ["query", "body"],
            "keywords": ["evil-"],
            "action": "block"
        }]
    }"#;

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn public_key_config(key: &Ed25519KeyPair) -> String {
        format!(
            "ed25519:{}",
            encode_base64(key.public_key().as_ref())
        )
    }

    fn signed_body(key: &Ed25519KeyPair, payload: &str) -> String {
        let sig = key.sign(payload.as_bytes());
        format!(
            "{SIGNATURE_PREFIX} ed25519:{}\n{payload}",
            encode_base64(sig.as_ref())
        )
    }

    #[test]
    fn base64_roundtrip() {
        for len in 0..70 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = encode_base64(&bytes);
            assert_eq!(decode_base64(&encoded).unwrap(), bytes, "长度 {len}");
        }
    }

    #[test]
    fn base64_rejects_invalid_input() {
        assert!(decode_base64("!!!!").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AB").is_err(), "尾部填充位必须为零");
    }

    #[test]
    fn parses_json_rules() {
        let parsed = parse_rules(DOC, "test-feed").unwrap();
        assert_eq!(parsed.version.as_deref(), Some("2026.10.1"));
        assert_eq!(parsed.format.as_deref(), Some("homewaf-rules"));
        assert_eq!(parsed.rules.len(), 1);
        let rule = &parsed.rules[0];
        assert_eq!(rule.id, "feed-test-evil");
        assert_eq!(rule.category, Category::Custom);
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.action, Action::Block);
        assert_eq!(rule.keywords, vec!["evil-".to_string()]);
        assert_eq!(rule.source, RuleSource::Feed("test-feed".to_string()));
        assert!(!rule.shadow);
    }

    #[test]
    fn parses_yaml_and_numeric_version() {
        let yaml = r#"
format: homewaf-rules
version: 42
channel: beta
name: yaml-feed
rules:
  - id: yaml-rule
    name: YAML 规则
    category: xss
    severity: medium
    pattern: "<svg[^>]*onload"
    targets: [query]
    keywords: ["<svg"]
    action: log
"#;
        let parsed = parse_rules(yaml, "yaml-feed").unwrap();
        assert_eq!(parsed.version.as_deref(), Some("42"));
        assert_eq!(parsed.channel.as_deref(), Some("beta"));
        assert_eq!(parsed.declared_name.as_deref(), Some("yaml-feed"));
        assert_eq!(parsed.rules[0].action, Action::Log);
    }

    #[test]
    fn signed_payload_verifies() {
        let key = keypair();
        let body = signed_body(&key, DOC);
        let (signature, payload) = split_signature(&body).unwrap();
        let signature = signature.expect("应识别到签名");
        assert_eq!(payload, DOC.trim_start());
        verify_signature(&public_key_config(&key), payload.as_bytes(), &signature).unwrap();

        let parsed = parse_rules(payload, "signed").unwrap();
        assert_eq!(parsed.rules.len(), 1);
    }

    #[test]
    fn generated_key_signs_and_verifies() {
        let (pkcs8, public) = generate_signing_key().unwrap();
        assert!(public.starts_with("ed25519:"));
        let body = sign_payload(&pkcs8, DOC).unwrap();
        let (signature, payload) = split_signature(&body).unwrap();
        verify_signature(&public, payload.as_bytes(), &signature.unwrap()).unwrap();
    }

    #[test]
    fn sign_rejects_malformed_key() {
        assert!(sign_payload(b"not a pkcs8 key", DOC).is_err());
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let key = keypair();
        let body = signed_body(&key, DOC);
        let (signature, _) = split_signature(&body).unwrap();
        let signature = signature.unwrap();
        let tampered = DOC.replace("evil-", "good-");
        let err = verify_signature(
            &public_key_config(&key),
            tampered.as_bytes(),
            &signature,
        )
        .unwrap_err();
        assert_eq!(err, RuleFeedError::BadSignature);
    }

    #[test]
    fn wrong_key_fails_signature() {
        let key = keypair();
        let other = keypair();
        let body = signed_body(&key, DOC);
        let (signature, payload) = split_signature(&body).unwrap();
        let err = verify_signature(
            &public_key_config(&other),
            payload.as_bytes(),
            &signature.unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, RuleFeedError::BadSignature);
    }

    #[test]
    fn missing_signature_is_detected() {
        let (signature, payload) = split_signature(DOC).unwrap();
        assert!(signature.is_none());
        assert_eq!(payload, DOC);
    }

    #[test]
    fn malformed_signature_header_is_rejected() {
        for header in [
            "# homewaf-signature: rsa:AAAA",
            "# homewaf-signature: ed25519:not-base64!",
            "# homewaf-signature: ed25519:AAAA",
        ] {
            let body = format!("{header}\n{DOC}");
            assert!(split_signature(&body).is_err(), "应拒绝 {header}");
        }
    }

    #[test]
    fn public_key_validation() {
        assert!(parse_public_key("ed25519:AAAA").is_err());
        assert!(parse_public_key("rsa:AAAA").is_err());
        let key = keypair();
        assert!(parse_public_key(&public_key_config(&key)).is_ok());
    }

    #[test]
    fn duplicate_rule_id_rejected() {
        let doc = DOC.replace(
            "\"rules\": [",
            "\"rules\": [{
                \"id\": \"feed-test-evil\",
                \"name\": \"重复\",
                \"category\": \"xss\",
                \"severity\": \"low\",
                \"pattern\": \"x\",
                \"targets\": [\"path\"]
            },",
        );
        let err = parse_rules(&doc, "dup").unwrap_err();
        assert!(matches!(err, RuleFeedError::DuplicateId(_)), "{err}");
    }

    #[test]
    fn builtin_id_collision_rejected() {
        let doc = DOC.replace("feed-test-evil", "sqli-union-select");
        let err = parse_rules(&doc, "collision").unwrap_err();
        assert!(matches!(err, RuleFeedError::DuplicateId(_)), "{err}");
    }

    #[test]
    fn invalid_rule_fields_rejected() {
        let cases = [
            DOC.replace("\"custom\"", "\"unknown-category\""),
            DOC.replace("\"high\"", "\"urgent\""),
            DOC.replace("\"block\"", "\"drop-table\""),
            DOC.replace("evil-[a-z]{4}", "(unclosed"),
            DOC.replace("[\"query\", \"body\"]", "[]"),
            DOC.replace("[\"query\", \"body\"]", "[\"telepathy\"]"),
            DOC.replace("\"id\": \"feed-test-evil\"", "\"id\": \"bad,id\""),
        ];
        for doc in cases {
            assert!(parse_rules(&doc, "bad").is_err(), "应拒绝：{doc}");
        }
    }

    #[test]
    fn too_many_rules_rejected() {
        let mut rules = Vec::new();
        for i in 0..=MAX_RULES {
            rules.push(format!(
                r#"{{"id":"r-{i}","name":"r{i}","category":"custom","severity":"low","pattern":"x","targets":["path"]}}"#
            ));
        }
        let doc = format!(r#"{{"rules":[{}]}}"#, rules.join(","));
        assert!(matches!(
            parse_rules(&doc, "big").unwrap_err(),
            RuleFeedError::TooManyRules(_)
        ));
    }

    #[test]
    fn empty_rule_pack_rejected() {
        assert!(matches!(
            parse_rules(r#"{"rules":[]}"#, "empty").unwrap_err(),
            RuleFeedError::Format(_)
        ));
        assert!(matches!(
            parse_rules("", "empty").unwrap_err(),
            RuleFeedError::Empty
        ));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let doc = r#"{
            "format": "homewaf-rules",
            "description": "附加说明",
            "rules": [{
                "id": "extra-field-rule",
                "name": "带附加字段的规则",
                "category": "custom",
                "severity": "low",
                "pattern": "extra",
                "targets": ["path"],
                "cve": "CVE-2026-0001",
                "references": ["https://example.com"]
            }]
        }"#;
        let parsed = parse_rules(doc, "meta").unwrap();
        assert_eq!(parsed.rules.len(), 1);
    }
}
