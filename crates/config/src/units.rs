//! 带单位的配置值：时长与体积。
//!
//! 配置文件里写 `30s`、`5m`、`2h`、`7d`，或 `10MB`、`2GB`。
//! 内部统一存 `std::time::Duration` 与字节数。

use std::fmt;
use std::time::Duration as StdDuration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 时长。配置写 `"30s"`，也接受纯数字（视为秒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(pub StdDuration);

impl Duration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(StdDuration::from_secs(secs))
    }

    pub const fn from_millis(ms: u64) -> Self {
        Self(StdDuration::from_millis(ms))
    }

    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        if secs == 0 {
            return write!(f, "{}ms", self.0.as_millis());
        }
        if secs % 86_400 == 0 {
            write!(f, "{}d", secs / 86_400)
        } else if secs % 3_600 == 0 {
            write!(f, "{}h", secs / 3_600)
        } else if secs % 60 == 0 {
            write!(f, "{}m", secs / 60)
        } else {
            write!(f, "{}s", secs)
        }
    }
}

/// 解析 `"30s"` / `"5m"` / `"2h"` / `"7d"` / `"100ms"` / `"30"`。
pub fn parse_duration(input: &str) -> Result<StdDuration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("时长不能为空".to_string());
    }

    // 纯数字视为秒
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(StdDuration::from_secs(secs));
    }

    let split_at = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("时长 `{s}` 缺少单位（支持 ms/s/m/h/d）"))?;

    let (num_part, unit_part) = s.split_at(split_at);
    let value: u64 = num_part
        .parse()
        .map_err(|_| format!("时长 `{s}` 的数字部分无法解析"))?;
    let unit = unit_part.trim();

    let duration = match unit {
        "ms" => StdDuration::from_millis(value),
        "s" => StdDuration::from_secs(value),
        "m" => StdDuration::from_secs(value.saturating_mul(60)),
        "h" => StdDuration::from_secs(value.saturating_mul(3_600)),
        "d" => StdDuration::from_secs(value.saturating_mul(86_400)),
        other => {
            return Err(format!(
                "未知时长单位 `{other}`（支持 ms/s/m/h/d，例如 30s、5m、2h、7d）"
            ))
        }
    };
    Ok(duration)
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DurationVisitor;

        impl Visitor<'_> for DurationVisitor {
            type Value = Duration;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("时长字符串（如 \"30s\"、\"5m\"、\"7d\"）或秒数")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_duration(v).map(Duration).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Duration(StdDuration::from_secs(v)))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v < 0 {
                    return Err(E::custom("时长不能为负数"));
                }
                Ok(Duration(StdDuration::from_secs(v as u64)))
            }
        }

        deserializer.deserialize_any(DurationVisitor)
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// 体积。配置写 `"10MB"`、`"2GB"`，也接受纯数字（视为字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Size(pub u64);

impl Size {
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        let v = self.0;
        if v >= GB && v % GB == 0 {
            write!(f, "{}GB", v / GB)
        } else if v >= MB && v % MB == 0 {
            write!(f, "{}MB", v / MB)
        } else if v >= KB && v % KB == 0 {
            write!(f, "{}KB", v / KB)
        } else {
            write!(f, "{v}B")
        }
    }
}

/// 解析 `"10MB"` / `"2GB"` / `"512KB"` / `"1024"`。进制为 1024。
pub fn parse_size(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("体积不能为空".to_string());
    }

    if let Ok(bytes) = s.parse::<u64>() {
        return Ok(bytes);
    }

    let split_at = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("体积 `{s}` 缺少单位（支持 B/KB/MB/GB/TB）"))?;

    let (num_part, unit_part) = s.split_at(split_at);
    let value: u64 = num_part
        .parse()
        .map_err(|_| format!("体积 `{s}` 的数字部分无法解析"))?;
    let unit = unit_part.trim().to_ascii_uppercase();

    let multiplier: u64 = match unit.as_str() {
        "B" => 1,
        "KB" | "K" => 1024,
        "MB" | "M" => 1024 * 1024,
        "GB" | "G" => 1024 * 1024 * 1024,
        "TB" | "T" => 1024 * 1024 * 1024 * 1024,
        other => {
            return Err(format!(
                "未知体积单位 `{other}`（支持 B/KB/MB/GB/TB，例如 10MB、2GB）"
            ))
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("体积 `{s}` 超出可表示范围"))
}

impl<'de> Deserialize<'de> for Size {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SizeVisitor;

        impl Visitor<'_> for SizeVisitor {
            type Value = Size;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("体积字符串（如 \"10MB\"、\"2GB\"）或字节数")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_size(v).map(Size).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Size(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v < 0 {
                    return Err(E::custom("体积不能为负数"));
                }
                Ok(Size(v as u64))
            }
        }

        deserializer.deserialize_any(SizeVisitor)
    }
}

impl Serialize for Size {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("30s").unwrap().as_secs(), 30);
        assert_eq!(parse_duration("5m").unwrap().as_secs(), 300);
        assert_eq!(parse_duration("2h").unwrap().as_secs(), 7_200);
        assert_eq!(parse_duration("7d").unwrap().as_secs(), 604_800);
        assert_eq!(parse_duration("100ms").unwrap().as_millis(), 100);
        assert_eq!(parse_duration("45").unwrap().as_secs(), 45);
        assert_eq!(parse_duration(" 30s ").unwrap().as_secs(), 30);
    }

    #[test]
    fn rejects_bad_duration() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("30x").is_err());
    }

    #[test]
    fn parses_size_units() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("2gb").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn rejects_bad_size() {
        assert!(parse_size("").is_err());
        assert!(parse_size("10XB").is_err());
    }

    #[test]
    fn duration_display_is_readable() {
        assert_eq!(Duration::from_secs(30).to_string(), "30s");
        assert_eq!(Duration::from_secs(300).to_string(), "5m");
        assert_eq!(Duration::from_secs(7_200).to_string(), "2h");
        assert_eq!(Duration::from_secs(604_800).to_string(), "7d");
    }
}
