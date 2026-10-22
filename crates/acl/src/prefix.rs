//! 按前缀长度分桶的前缀集合。
//!
//! 查找从最长前缀开始，首个命中即返回——这就是"最具体规则优先"。
//!
//! 为什么不用 radix tree：家用场景规则量级在千条以内，按长度分桶的哈希表
//! 实现更简单、更少出错，查找最坏 33 次（IPv4）但实际只查已配置的长度，
//! 通常 3-5 次。

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// 前缀集合。
#[derive(Debug, Clone)]
pub struct PrefixMap<V> {
    /// 下标即前缀长度，0..=32
    v4: Vec<HashMap<u32, V>>,
    /// 下标即前缀长度，0..=128
    v6: Vec<HashMap<u128, V>>,
    /// 非空前缀长度，降序（用于从最长前缀开始查找）
    v4_lens: Vec<usize>,
    v6_lens: Vec<usize>,
}

impl<V> Default for PrefixMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> PrefixMap<V> {
    pub fn new() -> Self {
        Self {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
            v4_lens: Vec::new(),
            v6_lens: Vec::new(),
        }
    }

    /// 插入一条前缀。返回被覆盖的旧值（同一前缀重复插入时）。
    pub fn insert(&mut self, net: IpNet, value: V) -> Option<V> {
        match net {
            IpNet::V4(v4net) => {
                let len = v4net.prefix_len() as usize;
                let key = u32::from(v4net.network());
                let old = self.v4[len].insert(key, value);
                if old.is_none() {
                    self.v4_lens.push(len);
                    self.v4_lens.sort_unstable_by(|a, b| b.cmp(a));
                }
                old
            }
            IpNet::V6(v6net) => {
                let len = v6net.prefix_len() as usize;
                let key = u128::from(v6net.network());
                let old = self.v6[len].insert(key, value);
                if old.is_none() {
                    self.v6_lens.push(len);
                    self.v6_lens.sort_unstable_by(|a, b| b.cmp(a));
                }
                old
            }
        }
    }

    /// 查找命中的最长前缀。
    pub fn lookup(&self, ip: IpAddr) -> Option<&V> {
        match ip {
            IpAddr::V4(v4) => {
                let raw = u32::from(v4);
                for &len in &self.v4_lens {
                    if let Some(v) = self.v4[len].get(&mask_v4(raw, len as u8)) {
                        return Some(v);
                    }
                }
                None
            }
            IpAddr::V6(v6) => {
                let raw = u128::from(v6);
                for &len in &self.v6_lens {
                    if let Some(v) = self.v6[len].get(&mask_v6(raw, len as u8)) {
                        return Some(v);
                    }
                }
                None
            }
        }
    }

    /// 规则总数。
    pub fn len(&self) -> usize {
        self.v4.iter().map(HashMap::len).sum::<usize>()
            + self.v6.iter().map(HashMap::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        for map in &mut self.v4 {
            map.clear();
        }
        for map in &mut self.v6 {
            map.clear();
        }
        self.v4_lens.clear();
        self.v6_lens.clear();
    }
}

/// 按前缀长度掩码 IPv4。
fn mask_v4(ip: u32, len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        ip & (!0u32 << (32 - len))
    }
}

/// 按前缀长度掩码 IPv6。
fn mask_v6(ip: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        ip & (!0u128 << (128 - len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exact_match() {
        let mut m = PrefixMap::new();
        m.insert(net("192.168.1.5/32"), "host");
        assert_eq!(m.lookup(ip("192.168.1.5")), Some(&"host"));
        assert_eq!(m.lookup(ip("192.168.1.6")), None);
    }

    #[test]
    fn prefix_match() {
        let mut m = PrefixMap::new();
        m.insert(net("10.0.0.0/8"), "ten");
        assert_eq!(m.lookup(ip("10.1.2.3")), Some(&"ten"));
        assert_eq!(m.lookup(ip("11.0.0.1")), None);
    }

    #[test]
    fn longest_prefix_wins() {
        let mut m = PrefixMap::new();
        m.insert(net("10.0.0.0/8"), "wide");
        m.insert(net("10.1.0.0/16"), "narrow");
        m.insert(net("10.1.2.0/24"), "narrowest");

        assert_eq!(m.lookup(ip("10.1.2.9")), Some(&"narrowest"));
        assert_eq!(m.lookup(ip("10.1.3.9")), Some(&"narrow"));
        assert_eq!(m.lookup(ip("10.2.0.1")), Some(&"wide"));
    }

    #[test]
    fn ipv6_prefix_match() {
        let mut m = PrefixMap::new();
        m.insert(net("2001:db8::/32"), "v6");
        assert_eq!(m.lookup(ip("2001:db8:1234::1")), Some(&"v6"));
        assert_eq!(m.lookup(ip("2001:db9::1")), None);
    }

    #[test]
    fn ipv6_128_exact() {
        let mut m = PrefixMap::new();
        m.insert(net("2001:db8::1/128"), "single");
        assert_eq!(m.lookup(ip("2001:db8::1")), Some(&"single"));
        assert_eq!(m.lookup(ip("2001:db8::2")), None);
    }

    #[test]
    fn default_route_matches_everything() {
        let mut m = PrefixMap::new();
        m.insert(net("0.0.0.0/0"), "all");
        assert_eq!(m.lookup(ip("1.2.3.4")), Some(&"all"));
        assert_eq!(m.lookup(ip("203.0.113.9")), Some(&"all"));
    }

    #[test]
    fn v4_and_v6_are_independent() {
        let mut m = PrefixMap::new();
        m.insert(net("0.0.0.0/0"), "v4");
        // IPv4 的默认路由不应匹配 IPv6
        assert_eq!(m.lookup(ip("2001:db8::1")), None);
    }

    #[test]
    fn overwrite_same_prefix() {
        let mut m = PrefixMap::new();
        assert_eq!(m.insert(net("10.0.0.0/8"), "first"), None);
        assert_eq!(m.insert(net("10.0.0.0/8"), "second"), Some("first"));
        assert_eq!(m.lookup(ip("10.1.1.1")), Some(&"second"));
        assert_eq!(m.len(), 1, "重复插入不应增加长度列表");
    }

    #[test]
    fn empty_map_returns_none() {
        let m: PrefixMap<u8> = PrefixMap::new();
        assert!(m.is_empty());
        assert_eq!(m.lookup(ip("1.2.3.4")), None);
    }

    #[test]
    fn mask_edges() {
        assert_eq!(mask_v4(0xFFFF_FFFF, 0), 0);
        assert_eq!(mask_v4(0xFFFF_FFFF, 32), 0xFFFF_FFFF);
        assert_eq!(mask_v6(u128::MAX, 0), 0);
        assert_eq!(mask_v6(u128::MAX, 128), u128::MAX);
    }
}
