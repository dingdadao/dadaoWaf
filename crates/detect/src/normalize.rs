//! 归一化管线。
//!
//! 这是检测引擎的地基。规则写得再好，如果归一化不到位，攻击者只要换个编码
//! 就能绕过：`%27`、`%2527`、`&#39;`、`＇`（全角）、`un/**/ion` 指向的都是同一个 `'`。
//!
//! 设计原则：
//! - **多轮解码**：攻击者常做双重编码，`%2527` 要解两次才是 `'`
//! - **有界**：解码轮数有上限，防止 `%2525...` 无限展开
//! - **保留原文**：日志里同时记录原始与规范化结果，便于溯源

/// 归一化结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// 原始输入
    pub raw: String,
    /// URL 解码后（未做其他处理）
    pub decoded: String,
    /// 完整规范化：URL 解码 + HTML 实体 + Unicode 折叠 + 去注释 + 小写
    pub canonical: String,
}

impl Normalized {
    /// 是否与原文不同（说明做了变形，值得关注）。
    pub fn was_transformed(&self) -> bool {
        self.raw != self.canonical
    }
}

/// 默认解码轮数上限。三层编码足够覆盖现实攻击，再多就是刻意构造的噪音。
pub const MAX_DECODE_ROUNDS: usize = 3;

/// 完整归一化。
pub fn normalize(input: &str) -> Normalized {
    let decoded = decode_url_multi(input, MAX_DECODE_ROUNDS);

    let mut canonical = decoded.clone();
    canonical = decode_html_entities(&canonical);
    canonical = fold_unicode(&canonical);
    canonical = strip_sql_comments(&canonical);
    canonical = collapse_whitespace(&canonical);
    canonical = canonical.to_lowercase();

    Normalized {
        raw: input.to_string(),
        decoded,
        canonical,
    }
}

/// 多轮 URL 解码，直到结果不再变化或达到轮数上限。
pub fn decode_url_multi(input: &str, max_rounds: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_rounds {
        let next = decode_url_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// 单轮 URL 解码。`%XX` 与 `+`（空格）都处理，非法序列原样保留。
pub fn decode_url_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    // 非法转义原样保留，不要吞掉
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    // 解码后可能不是合法 UTF-8（比如 %FF），用替换字符兜底
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 解码常见 HTML 实体：命名实体与数字实体（十进制/十六进制）。
pub fn decode_html_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // 找分号，限制长度避免误吞正常文本
        let end = chars[i..]
            .iter()
            .take(10)
            .position(|&c| c == ';')
            .map(|p| i + p);

        let Some(end) = end else {
            out.push('&');
            i += 1;
            continue;
        };

        let entity: String = chars[i + 1..end].iter().collect();
        match resolve_entity(&entity) {
            Some(ch) => {
                out.push(ch);
                i = end + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }

    out
}

fn resolve_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        "nbsp" => return Some(' '),
        "tab" => return Some('\t'),
        "newline" => return Some('\n'),
        _ => {}
    }

    if let Some(num) = entity.strip_prefix('#') {
        if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
            return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
        }
        return num.parse::<u32>().ok().and_then(char::from_u32);
    }

    None
}

/// Unicode 折叠：全角 ASCII 转半角，全角空格转普通空格。
///
/// `ＵＮＩＯＮ`、`％`、`＇` 这些全角字符在多数正则里匹配不到，必须先折叠。
pub fn fold_unicode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            // 全角 ！ 到 ～ 对应 ASCII 0x21..0x7E
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            '\u{3000}' => ' ',
            _ => c,
        })
        .collect()
}

/// 去掉 SQL 注释，替换为空格。
///
/// `un/**/ion sel/**/ect` 是经典绕过手法，去注释后才能被规则命中。
/// 替换为空格而不是删除，避免把两个词粘连成新词。
pub fn strip_sql_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < bytes.len() {
        // /* ... */
        if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
            match find_close(&bytes, i + 2) {
                Some(end) => {
                    out.push(' ');
                    i = end + 2;
                    continue;
                }
                None => {
                    out.push('/');
                    i += 1;
                    continue;
                }
            }
        }
        // -- 行注释（SQL 标准，后面通常跟空格或行尾）
        if bytes[i] == '-' && i + 1 < bytes.len() && bytes[i + 1] == '-' {
            out.push(' ');
            // 跳到行尾
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // # 行注释（MySQL）
        if bytes[i] == '#' {
            out.push(' ');
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    out
}

fn find_close(chars: &[char], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < chars.len() {
        if chars[i] == '*' && chars[i + 1] == '/' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 合并连续空白为单个空格并 trim。
pub fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = false;
    for c in input.chars() {
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        normalize(s).canonical
    }

    // ============================================================
    // URL 解码
    // ============================================================

    #[test]
    fn decodes_basic_percent() {
        assert_eq!(decode_url_once("a%27b"), "a'b");
        assert_eq!(decode_url_once("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn decodes_plus_as_space() {
        assert_eq!(decode_url_once("a+b"), "a b");
    }

    #[test]
    fn keeps_invalid_percent() {
        assert_eq!(decode_url_once("100%"), "100%");
        assert_eq!(decode_url_once("%zz"), "%zz");
        assert_eq!(decode_url_once("%4"), "%4");
    }

    #[test]
    fn decodes_double_encoded() {
        // %2527 → %27 → '
        assert_eq!(decode_url_multi("%2527", 3), "'");
        // 三层
        assert_eq!(decode_url_multi("%252527", 3), "'");
    }

    #[test]
    fn decode_rounds_are_bounded() {
        // 五层编码只解三轮，不应无限展开
        let input = "%2525252527";
        let out = decode_url_multi(input, 3);
        assert_eq!(out, "%2527", "三轮后应剩两层编码未解");
    }

    #[test]
    fn invalid_utf8_after_decode_does_not_panic() {
        // %FF 不是合法 UTF-8
        let out = decode_url_once("a%FFb");
        assert!(out.starts_with('a'));
        assert!(out.ends_with('b'));
    }

    // ============================================================
    // HTML 实体
    // ============================================================

    #[test]
    fn decodes_named_entities() {
        assert_eq!(decode_html_entities("&lt;script&gt;"), "<script>");
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&apos;"), "'");
    }

    #[test]
    fn decodes_numeric_entities() {
        assert_eq!(decode_html_entities("&#39;"), "'");
        assert_eq!(decode_html_entities("&#x27;"), "'");
        assert_eq!(decode_html_entities("&#X3C;"), "<");
    }

    #[test]
    fn leaves_unknown_entity_alone() {
        assert_eq!(decode_html_entities("&unknown;"), "&unknown;");
        assert_eq!(decode_html_entities("a & b"), "a & b");
    }

    #[test]
    fn does_not_swallow_long_text_after_ampersand() {
        // 没有分号时不应把后面一大段当实体
        let s = "a & b and c; d";
        assert_eq!(decode_html_entities(s), s);
    }

    // ============================================================
    // Unicode 折叠
    // ============================================================

    #[test]
    fn folds_fullwidth_ascii() {
        assert_eq!(fold_unicode("ＵＮＩＯＮ"), "UNION");
        assert_eq!(fold_unicode("％２７"), "%27");
        assert_eq!(fold_unicode("＇"), "'");
    }

    #[test]
    fn folds_fullwidth_space() {
        assert_eq!(fold_unicode("a\u{3000}b"), "a b");
    }

    #[test]
    fn leaves_normal_chars_alone() {
        assert_eq!(fold_unicode("hello 中文"), "hello 中文");
    }

    // ============================================================
    // SQL 注释剥离
    // ============================================================

    #[test]
    fn strips_block_comments() {
        assert_eq!(strip_sql_comments("un/**/ion"), "un ion");
        assert_eq!(strip_sql_comments("sel/**/ect"), "sel ect");
    }

    #[test]
    fn strips_line_comments() {
        // 注释替换为空格，换行保留（它是语句分隔符）
        assert_eq!(strip_sql_comments("1' -- comment\nrest"), "1'  \nrest");
        assert_eq!(strip_sql_comments("1' # comment"), "1'  ");
    }

    #[test]
    fn unclosed_comment_kept() {
        assert_eq!(strip_sql_comments("a /* b"), "a /* b");
    }

    // ============================================================
    // 组合场景：真实绕过手法
    // ============================================================

    #[test]
    fn fullwidth_union_select_bypass() {
        assert!(canon("ＵＮＩＯＮ　ＳＥＬＥＣＴ").contains("union select"));
    }

    #[test]
    fn comment_between_keywords_bypass() {
        // 去注释后变成 "union select"
        let out = canon("union/**/select");
        assert!(out.contains("union select"), "实际: {out}");
    }

    #[test]
    fn double_encoded_quote() {
        assert_eq!(canon("%2527"), "'");
    }

    #[test]
    fn mixed_encoding_bypass() {
        // URL 编码 + HTML 实体 + 全角混用
        let out = canon("%26%23x27%3B");
        assert_eq!(out, "'");
    }

    #[test]
    fn case_is_folded() {
        assert_eq!(canon("SeLeCt"), "select");
    }

    #[test]
    fn whitespace_collapsed() {
        assert_eq!(canon("a   \t  b"), "a b");
    }

    #[test]
    fn was_transformed_flag() {
        assert!(normalize("%27").was_transformed());
        assert!(!normalize("plain").was_transformed());
    }

    #[test]
    fn empty_input_is_safe() {
        let n = normalize("");
        assert_eq!(n.canonical, "");
    }

    // ============================================================
    // 模糊测试（确定性伪随机，不依赖外部工具）
    // ============================================================

    #[test]
    fn random_input_never_panics() {
        // xorshift64，确定性可复现
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..5_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;

            let len = (seed % 300) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|i| ((seed >> ((i % 8) * 8)) & 0xFF) as u8)
                .collect();

            // 只测合法 UTF-8；非法字节在入口就该被拒
            if let Ok(s) = String::from_utf8(bytes) {
                let n = normalize(&s);
                // 归一化不会显著膨胀（解码都是变短的）
                assert!(
                    n.canonical.len() <= s.len() * 4 + 16,
                    "规范化后长度异常膨胀: {} -> {}",
                    s.len(),
                    n.canonical.len()
                );
            }
        }
    }

    #[test]
    fn pathological_repeats_do_not_panic() {
        let cases: Vec<String> = vec![
            "%".repeat(10_000),
            "&".repeat(10_000),
            "%25".repeat(10_000),
            "&#".repeat(10_000),
            "&#x".repeat(10_000),
            "<".repeat(10_000),
            "\u{FF01}".repeat(10_000),
            "..".repeat(10_000),
            "/*".repeat(10_000),
            "--".repeat(10_000),
        ];
        for s in cases {
            let n = normalize(&s);
            // 只要求不 panic 且结果是合法字符串
            assert!(n.canonical.len() < s.len() * 5 + 100);
        }
    }

    #[test]
    fn deeply_nested_encoding_is_bounded() {
        // 100 层 URL 编码，解码轮数上限必须挡住
        let mut s = "'".to_string();
        for _ in 0..100 {
            s = s.replace('%', "%25").replace('\'', "%27");
        }
        let n = normalize(&s);
        assert!(!n.canonical.is_empty());
        // 三轮解码后应该还剩大量未解码的 %
        assert!(
            n.canonical.contains('%'),
            "三轮解码不可能解完 100 层，应残留 %"
        );
    }

    #[test]
    fn mixed_encoding_chain_does_not_panic() {
        let cases = [
            "%25%32%35%32%37",
            "&#37;27",
            "%26%23x27%3B",
            "\u{FF05}\u{FF12}\u{FF17}",
            "%2525%2527",
        ];
        for s in cases {
            let _ = normalize(s);
        }
    }
}
