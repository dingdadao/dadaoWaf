//! 检测性能基准。
//!
//! 跑法：`cargo run --release -p homewaf-detect --example bench`
//!
//! 为什么要单独测：41 条正则对每个请求跑一遍，成本直接决定吞吐量。
//! 之前 27k RPS 的性能数据是 15 条规则时测的，规则翻了近 3 倍后必须重测。

use std::time::Instant;

use homewaf_detect::{Engine, InspectionInput, Matcher, BUILTIN_RULES};

fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> f64 {
    // 预热，避免首次分配影响结果
    for _ in 0..100 {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();

    let per_op_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let per_op_us = per_op_ns / 1000.0;
    let qps = 1_000_000_000.0 / per_op_ns;

    println!(
        "{:<28} {:>9.2} μs/次   {:>10.0} 次/秒（单核）",
        name, per_op_us, qps
    );
    per_op_ns
}

fn main() {
    println!("HomeWAF 检测引擎基准（{} 条规则）\n", BUILTIN_RULES.len());

    let matcher = Matcher::new(BUILTIN_RULES);
    let engine = Engine::new(false, 50);

    // ---------- 1. 干净请求（最常见路径）----------
    let clean_short = "GET /api/v1/users?page=1&size=20";
    let clean_long = "a".repeat(2000);

    bench("干净短文本 (36B)", 200_000, || {
        let _ = matcher.scan(clean_short);
    });

    bench("干净长文本 (2KB)", 20_000, || {
        let _ = matcher.scan(&clean_long);
    });

    // ---------- 2. 可疑请求（关键词命中，要跑正则）----------
    let suspicious = "id=1 union select 1,2,3 from users";

    bench("可疑文本 (36B)", 100_000, || {
        let _ = matcher.scan(suspicious);
    });

    // ---------- 3. 完整检测流程（归一化 + 扫描）----------
    let input = InspectionInput {
        path: "/api/v1/users".to_string(),
        query: Some("page=1&size=20&sort=name".to_string()),
        user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()),
        ..Default::default()
    };

    bench("完整检测·干净请求", 50_000, || {
        let _ = engine.inspect(&input);
    });

    let attack = InspectionInput {
        path: "/api".to_string(),
        query: Some("id=1%20union%20select%201".to_string()),
        user_agent: Some("sqlmap/1.7".to_string()),
        ..Default::default()
    };

    bench("完整检测·攻击请求", 50_000, || {
        let _ = engine.inspect(&attack);
    });

    // ---------- 4. 归一化本身的开销 ----------
    let encoded = "%2527%2520or%25201%253D1%2520--%2520";

    bench("归一化·多重编码", 200_000, || {
        let _ = homewaf_detect::normalize(encoded);
    });

    println!("\n说明：");
    println!("  - 单核数字，实际吞吐随 worker 数线性放大");
    println!("  - 干净请求走预过滤快路径，不进正则");
    println!("  - 攻击请求要跑正则，是慢路径");
}
