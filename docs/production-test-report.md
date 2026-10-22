# 生产环境测试报告

- 测试对象：HomeWAF，生产环境 `10.0.0.31`（systemd `homewaf`）
- 测试时间：2026-10-22 15:40 — 2026-10-22 16:45（UTC）
- 测试角色：资深测试工程师（功能）、安全测试工程师（攻防用例）、性能测试工程师（压测）
- 被测版本：`homewaf 0.1.0`，x86_64-unknown-linux-gnu，二进制部署于 `/opt/homewaf/bin/homewaf`
- 启动参数：`serve --db /opt/homewaf/data/homewaf.db --listen 0.0.0.0:80 --tls-listen 0.0.0.0:443`
- 管理面：仅监听 `127.0.0.1:9443`
- 数据来源：管理 API、`access` / `upstream` / `security` 日志、SQLite 事件表、`ab` 压测输出

## 1. 结论

功能、安全、性能三项验收均达标，缺陷 8 项全部修复并完成复测，新版本已重新部署生产。

| 维度 | 用例/指标 | 结果 |
| --- | --- | --- |
| 功能 | 路由、应用 CRUD、配置回滚、热重载、健康检查、重试、雷池同步 | 全部通过 |
| 安全 | 14 条攻击用例（注入 / XSS / 命令注入 / 穿越 / SSRF / CRLF / Log4j / Shellshock / 伪造 XFF） | 全部按预期拦截 |
| 性能 | 持续 5 万请求，并发 50 | 3895 rps，p99 21ms，WAF 侧 0 错误、0 503 |

> 说明：雷池同步的「局域网」白名单规则命中内网来源时，按语义整段跳过应用层检测。安全用例执行期间临时停用该规则与自动封禁，
> 测试结束后已恢复为 `lei-83` 启用、`auto_ban` 启用。

## 2. 功能测试

| 编号 | 用例 | 预期 | 结果 |
| --- | --- | --- | --- |
| D1 | 上游对探测路径返回 404 时，主动健康检查不得把应用判为不可用 | 应用保持健康，请求 404 而非 503 | 通过 |
| D2 | `/api/system/info` 展示真实监听地址 | `listen=["0.0.0.0:80"]`、`tls_listen=["0.0.0.0:443"]` | 通过 |
| D3 | 路由支持 Nginx 风格运算符 `= /exact` | 创建成功，`/exact` 精确匹配 | 通过 |
| D4 | 非法正则路由 `~ ([` 必须拒绝且不污染数据库 | 400 并提示「配置无效，已回滚」，应用不存在 | 通过 |
| D5 | 坏上游（端口未监听）+ 好上游，GET 应重试到可用上游 | 6/6 返回 200 | 通过 |
| D6 | 路径含 CRLF（`/a%0d%0aSet-Cookie...`） | 400 拒绝并记录安全日志 | 通过 |
| — | 雷池配置同步幂等 | 8 应用 / 2 自定义规则 / 证书 4 个因无私钥跳过 | 通过 |
| — | 热重载 | `POST /api/reload` 200，配置即时生效 | 通过 |

## 3. 安全测试

执行前：暂停 `lei-83`（局域网白名单）与自动封禁；执行后恢复。基线正常请求返回 200。

| 用例 | 载荷 | 预期 | 结果 |
| --- | --- | --- | --- |
| SQL 布尔恒真 | `?id=1' OR '1'='1` | 403 | 403 `sqli-boolean-tautology` |
| SQL 联合查询 | `?id=1 UNION SELECT a,b FROM t` | 403 | 403 `sqli-union-select` |
| XSS | `?q=<script>alert(1)</script>` | 403 | 403 `xss-script-tag` |
| 命令注入 | `?cmd=;cat /etc/passwd` | 403 | 403 `cmdi-shell-separator` |
| 路径穿越 | `/%2e%2e%2f%2e%2e%2fetc%2fpasswd` | 403 | 403 `traversal-dotdot` |
| SSRF | `?url=http://169.254.169.254/latest/` | 403 | 403 `ssrf-cloud-metadata` |
| CRLF | `/a%0d%0aSet-Cookie: x=1` | 400 | 400 |
| Log4j JNDI（自定义头） | `X-Api-Version: ${jndi:ldap://127.0.0.1/a}` | 403 | 403 `log4j-jndi` |
| Log4j JNDI（UA） | `User-Agent: ${jndi:ldap://x/a}` | 403 | 403 `log4j-jndi` |
| Shellshock（自定义头） | `X-Test: () { :;}; /bin/bash -c id` | 403 | 403 `shellshock` |
| Shellshock（UA） | `User-Agent: () { :;}; /bin/bash -c id` | 403 | 403 `shellshock` |
| 扫描器 UA | `sqlmap/1.7.2` | 记录不拦截 | 200 + `scanner-user-agent` 事件 |
| 伪造 XFF 绕过 | `X-Forwarded-For: 127.0.0.1` + SQL 注入 | 403 | 403 |
| 未知 / 后缀伪造 Host | `evil.example.com`、`fn.niao.fun.evil.com` | 404 | 404 |

规则评分口径：High=50、Critical=80，拦截阈值 50；`Block` 类规则才计入拦截分，扫描器特征仅记录。

## 4. 性能测试

工具 `ab`，客户端与生产同网段；上游为 fnOS（`10.0.0.4:5666`）。

| 场景 | 并发 | 请求数 | RPS | p99 | 失败 |
| --- | --- | --- | --- | --- | --- |
| fn.niao.fun 基线 | 50 | 3 000 | 5822 | 16ms | 0 |
| 持续压测（修复后复测） | 50 | 50 000 | 3895 | 21ms | WAF 0 错误 |
| 持续压测（第二次复测） | 50 | 50 000 | 3896 | 21ms | WAF 0 错误 |
| pve 应用（上游较慢） | 50 | 2 000 | 867 | 193ms | 0 |
| waf 应用 | 50 | 5 000 | 6124 | 42ms | 0 |
| cretd 应用 | 50 | 5 000 | 4566 | 43ms | 0 |
| 1MB 请求体 POST | 10 | 300 | 108 | — | 0（WAF 侧） |

运行时资源：稳态 RSS 约 44 MB（压测后实测 44 868 KB），单进程。

持续压测期间共 86 个非 2xx，经 `upstream` 日志确认全部为**上游 fnOS 自身返回的 403**（WAF 原样透传），
WAF 未产生 502/503/504，未出现「无可用上游」突发，修复前的 6 049 个 503 已不再复现。

## 5. 缺陷清单与修复

| 编号 | 现象 | 根因 | 修复 | 复测 |
| --- | --- | --- | --- | --- |
| D1 | 上游对探测路径返回 404，应用被主动健康检查摘除，返回 503 | 雷池同步生成了严格期望状态 `[200,204,301,302]` | `leichi.rs` 同步时 `expect_status` 置空，按「非 5xx 即健康」；主动探测改为连续阈值（`unhealthy_threshold`/`healthy_threshold`） | 通过 |
| D2 | 系统信息页监听地址与实际不符 | `AdminState` 未携带启动参数 | 注入 `listen`/`tls_listen` 并在 `/api/system/info` 返回 | 通过 |
| D3 | 带运算符的路由被判非法 | 校验只接受以 `/` 开头的路径 | `validate.rs` 接受 `= `、`^~ `、`~ `、`~* ` 运算符 | 通过 |
| D4 | 非法配置写入后热重载失败，数据库残留坏应用 | 先落库后校验 | `upsert_app` 增加回滚：失败恢复旧快照并返回 400 | 通过 |
| D5 | 坏上游 + 好上游仍返回 502 | Pingora 连接类错误默认不可重试 | `fail_to_connect` 按应用 `retry`（enabled / connect_error / methods / attempts）显式 `set_retry(true)`，`upstream_peer` 重试时跳过已试槽位 | 6/6 200 |
| D6 | 路径含控制字符时返回 500 | 转发阶段构造非法 URI | 规范化路径中的控制字符直接 400 | 通过 |
| D7 | Log4j / Shellshock / SQL 布尔恒真未拦截 | ① Header 类目标从未被扫描（`InspectionInput.headers` 为空）；② 布尔恒真正则过窄；③ 生产命中雷池局域网白名单跳过检测 | 接入请求头检测（排除 host/cookie/UA/content-length）；正则支持带引号的恒真；补 `log4j-jndi`、`shellshock` 规则 | 全部 403 |
| D8 | 持续压测出现 503 突发 | 上游提前关闭连接被计为上游不可用，达到阈值后摘除上游 60s | `counts_as_upstream_failure` 排除 `ConnectionClosed`，仅真实连接/超时失败计健康度 | 5 万请求无 503 |

## 6. 部署与回滚

- 构建：`cargo zigbuild --release --target x86_64-unknown-linux-gnu -p homewaf`
- 质量门禁：`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 全绿
- 部署：上传 `homewaf.new` → 停服 → 替换 → 启动，`systemctl is-active` 为 `active`
- 回滚：保留上一版本二进制，异常时替换并重启即可；数据库为单文件 SQLite，可离线备份恢复

## 7. 遗留与限制

- 443 端口暂无可用证书（雷池 ACME 托管证书无私钥，按设计跳过同步），HTTPS 接入需先上传证书
- `ja4` 条件规则不支持的策略在同步时跳过（1 条），属预期
- 上游 fnOS 在持续高压下自身返回 403，属上游行为，不影响 WAF 判定
- 控制台暂无登录鉴权（差距分析已记录）
