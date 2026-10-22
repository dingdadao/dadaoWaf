# 开发工作日志

> 按时间节点记录已完成工作与下一步计划。最近更新：2026-10-22。

## 借鉴来源（后续迭代照此对标）

- **Demo 站**：https://demo.waf-ce.chaitin.cn:9443/sites/detail?id=77&tab=basicInfo
- **项目**：雷池 WAF 社区版（长亭科技），开源仓库 https://github.com/chaitin/SafeLine
- **前端形态**：React SPA，页面级 chunk 按需加载；已用 curl 抓回主 bundle（1MB）与 13 个统计相关 chunk 并提取出下述结构与文案。抓回文件在 `/tmp/sl/`（机器重启即失效），**以本文档摘录为准**。
- **API 前缀**：`/statistics`、`/statistics/security`（demo API 需登录，字段结构按 UI 反推）
- 各页签 i18n 键名：`page.traffic.analysis` 流量分析、`page.security.posture` 安全态势、`menu.report` 防护报告、`page.protection.dashboard` 防护大屏、`menu.statistics` 统计报表

## 雷池四页签拆解（#14 实现对标）

### ① 流量分析（page.traffic.analysis）

- KPI 卡片：请求次数、PV、UV、独立 IP、拦截次数、攻击 IP
- 衍生指标：4xx 率、**4xx 拦截率**（= WAF 拦截数 / 总请求）
- 图表：请求/拦截趋势曲线、外部来源域名 Top、外部来源页面 Top
- 地图：地图类型 中国/世界 切换；全部请求 / 仅拦截 切换
- 口径文案：独立 IP = 时间范围内来源 IP 去重（含放行与拦截）；UV = 按（IP+UA）session 统计

### ② 安全态势（page.security.posture）

- 攻击防护趋势（事件量+拦截量）
- Web 攻击分布（按攻击类型）
- 黑白名单规则命中分布
- 频率限制趋势、人机验证趋势、身份认证趋势、等候室趋势
- 实时事件流（当前日志滚动）

### ③ 防护报告（menu.report）

- 日报 / 周报列表 + 报告预览页 + CSV 导出（雷池开源版导出标注 coming soon，我们要做全）
- 报告内容：周期内请求/拦截汇总、攻击类型分布、攻击来源、Top 攻击 IP、规则命中统计

### ④ 防护大屏（page.protection.dashboard）

- 独立全屏页，从「数据统计」页一键启动（带启动确认）
- 指标卡：今日请求数、今日拦截、今日攻击 IP、今日独立 IP、实时 QPS
- 图表：30 天访问来源地区地图（世界/中国）、源站响应 vs WAF 响应、拦截分类/数量/查看 表格
- 自定义：明亮 / 暗黑主题、自定义标题、样式自定义

---

## 2026-10-22

### 10:15 — 规则摄入设计

- 起草 [rule-ingestion.md](rule-ingestion.md)：规则包格式（YAML + Ed25519 签名）、订阅更新、三层防投毒护栏的设计定稿。

### 16:39 — 初始提交（基线）

- `4a9f4dc` 初始提交：配置、路由、代理、检测、控制台。
- 基线能力：SQLite 唯一配置源；域名/路径路由（5 种模式 + 重写）；Pingora + rustls 代理（TLS 终结、HTTP/2、真实 IP 还原）；ACL 黑白名单 + IP 组订阅；41 条检测规则（11 类攻击）+ 归一化管线；负载均衡（4 种策略 + 健康检查）；控制台 9 页。
- 392 个测试，clippy 零警告。

### 17:00 前后 — 防护增强批次（任务 #1–#5）

- **CC 防护**：`crates/limit` 三层限流（全局/应用/路由）+ 并发连接数限制。
- **策略覆盖**：`proxy/src/policy.rs` 应用级/路由级策略覆盖链。
- **人机验证**：`proxy/src/challenge.rs` JS 挑战（工作量证明 + Cookie 下发），控制台可配置开关。
- **控制台**：限流/挑战配置页与统计优化。
- 注：该批次代码此前未纳入版本库，随本次提交一并入库。

### 17:41 — 规则包订阅批次（任务 #6–#10）

- `detect/src/feed.rs`：规则包格式解析 + Ed25519 验签。
- `proxy/src/rulefeed.rs`：订阅加载器（持久化、定时自动更新、变更幅度校验防投毒）。
- 管理 API + 控制台规则订阅页（增删改、手动更新、生效状态）。
- 配置模型/校验、README、产品规格、功能规格、差距分析同步更新。

### 18:10 — 流量指标采集与持久化（任务 #11，代码完成）

参照雷池「统计报表」四页签（流量分析/安全态势/防护报告/防护大屏）搭建真实数据底座：

- `proxy/src/metrics.rs`：分钟级桶聚合 —— 请求数、PV、UV（IP+UA FNV-1a）、独立 IP、状态码、拦截数、OS/浏览器分布、Top host/path/referer（64 条封顶防内存膨胀）；内存 Dashboard 快照（60s/120s/300s 分组）。
- `store`：`traffic_minutes` 幂等 upsert + `traffic_unique` 日级去重（WITHOUT ROWID，INSERT OR IGNORE），迟到日志 5 分钟回放窗口；`prune_traffic` 按保留期清理。
- `proxy/src/server.rs`：全链路埋点 —— ACL/自动封禁/CIDR/方法不允许/请求体过大/人机挑战/限流/检测拦截统一打 `blocked` 标记并写安全事件（新增 `EventKind::Challenge`），访问日志前记录指标。
- CLI 接线：指标实例共享给代理与控制台；落盘线程每 60s 重写最近 5 分钟。
- admin 增加 maxminddb 依赖，为 GeoIP 模块预留。
- proxy/store/admin 三 crate 168 个测试全绿；全工作区 **507 个测试全绿，0 失败**。

### 18:35 — 抓取雷池 demo 前端资源（对标资料入库）

- curl 抓回 SPA 外壳 + 主 bundle + 13 个统计页 chunk（ReqChart / Protection / Global / SourceIP / animated-svg 等）。
- 提取四页签完整结构、KPI 口径、图表清单、i18n 文案（已整理到本文档「雷池四页签拆解」节）。
- demo API 需登录无法直接读取数据，字段结构按 UI 反推。

### 18:40 — 提交推送

- `c1ac147` 功能补全：防护增强 + 规则包订阅 + 流量指标底座（31 文件，+7741 行），已推送 origin/master。

### 19:55 — GeoIP 模块（任务 #12）

- `crates/admin/src/geoip.rs`：maxminddb 读取 + 进程内 IP→归属地缓存（8192 条，换库即清空）。
  优先简体中文名称，解析国家 / 省份 / 城市 / 经纬度；内网、回环、链路本地与文档网段直接跳过，
  不进入查库与地图统计。
- 设置项 `geoip_db`（字符串路径）已注册：控制台「地理信息」可填 mmdb 路径，保存前校验可加载；
  启动时加载、保存后热切换，失败只告警，不影响代理与控制台其它功能。
- 新增 `GET /api/geoip`（加载状态）与 `GET /api/stats/geo?range=&app=`（在统计快照上批量解析，
  输出国家 / 省份 / 城市 Top 与地图打点）。代理热路径不查库，查询全部留在管理面，供 #13/#14 使用。
- 事件筛选补齐 `challenge` 类型（前端下拉与标签映射），此前只记录了事件但筛选不到。
- 测试：admin 44 个、全工作区 **515 个测试全绿**，clippy 零警告。

### 20:05 — 统计报表 API（任务 #13）

- `GET /api/stats?range=&app=`：在保留原有概览字段（apps/upstreams/hourly/categories 等）的基础上，
  追加 `range`、`app` 与完整 `traffic`（DashboardData：请求/PV/UV/独立 IP/拦截/状态码/OS/浏览器/
  Top host·path·referer/趋势序列/实时 OPS），前端概览无需改接口即可平滑迁移。
- `GET /api/security?range=`：安全态势聚合 —— 事件类型分布、按类型趋势、攻击类型分布、ACL 命中原因
  （黑名单/CIDR/方法限制等）、规则命中 Top、攻击来源 IP（带 GeoIP 归属地）与最近 20 条事件。
  范围上限 30 天，趋势桶按 1min / 5min / 1h 自适应。
- `GET /api/reports?days=`：按天合并流量与事件，输出日报列表（请求、拦截、拦截率、事件数）。
- `GET /api/reports/{day}`：日报详情（小时趋势、事件/攻击类型、规则与名单命中、来源 IP + 归属地、4xx/5xx 率）；
  `GET /api/reports/{day}/csv`：同一报告的 CSV 导出（BOM + 分段，Excel 直接打开）。
- `GET /api/screen`：大屏数据 —— 今日 KPI（请求/PV/UV/独立 IP/拦截/攻击 IP/拦截率/实时 QPS/峰值）、
  60 秒 OPS、30 天请求与事件趋势、攻击类型与拦截规则、Top 攻击 IP、24 小时访问来源地图（内存快照）
  与 30 天攻击来源地图（事件表），以及最近事件。
- `store` 新增聚合查询：`event_kind_counts`、`event_series_by_kind`、`event_ip_count`、
  `top_event_ips`、`acl_reason_counts`、`event_rule_strings_between`；全部走 SQL 分组，
  不在控制台里搬运整库事件。
- 代理侧 `DashboardData` 加 `Serialize`，原始 IP 列表 `#[serde(skip)]`，不下发前端。
- 测试：store 39、admin 49，clippy 零警告；5 个新接口冒烟全部 200，CSV 导出头与内容正确。

### 20:55 — 深色四页签控制台（任务 #14）

- 导航「概览」改名「统计报表」，深色主题只作用于统计容器，其它页面保持原浅色，避免表单可读性回归。
- **流量分析**：8 张 KPI（请求、PV、UV、独立 IP、拦截、攻击 IP、4xx 率、4xx 拦截率）；请求/拦截双线趋势（Catmull-Rom 平滑曲线，稀疏数据带圆点）；状态码环形图；OS/浏览器分布；Top host/path/referer；GeoIP 世界/中国点阵地图，支持「全部请求 / 仅拦截」切换。
- **安全态势**：4 张 KPI、攻击防护趋势多线图、攻击类型环形图、ACL 原因 / 规则 / 来源 IP 排行、最近事件流。
- **防护报告**：按天日报列表 + 报告预览（小时趋势、攻击类型、规则/名单命中、来源 IP、4xx/5xx 率）+ CSV 下载（BOM，Excel 直接打开）。
- **防护大屏**：独立全屏浮层，5 张 KPI、30 天趋势、攻击分类、来源地图（世界/中国）、最近事件；明/暗主题切换、自定义标题、Esc 退出。
- 地图底图为手写世界/中国粗略多边形 + 射线法点阵采样，离线渲染；GeoIP 未启用时保留底图并提示配置路径。
- 仅拦截地图口径由 `/api/stats/geo?mode=blocked` 提供，取事件表中处置为 `block` 的来源，与全部请求的内存快照口径区分。
- 修复 `challenge::tests::tampered_token_rejected` 偶发失败：base64url 末位含填充位，改写末字符可能解码出相同字节使签名仍有效；改为篡改 payload 中段，连续 10 次运行通过。

### 21:10 — 验证与文档（任务 #15）

- 浏览器逐页验证四页签：流量分析（KPI/趋势/环形图/排行/地图世界·中国与全部·仅拦截切换）、安全态势（多线趋势/类型分布/排行/事件流）、防护报告（列表/预览/CSV）、防护大屏（浮层开关、主题切换、地图切换），console 无错误。
- `cargo test --workspace`：519 个单元/集成/E2E 测试 + 2 个 doc-test 全绿；`cargo clippy --workspace --all-targets -- -D warnings` 零警告。
- 同步更新 README、功能差距分析、产品规格与本日志。

### 21:20 — 防护应用 / 攻击防护 / 系统设置与雷池规则兼容（任务 #16）

- **防护应用**：列表 + 详情两视图，详情对齐雷池站点页签（基本信息 / 转发规则 / 高级配置 / 应用路由）。
  应用模型新增 `description`、`group`、`access_mode`（`proxy` / `static` / `redirect`）、`static_site`、`redirect`；
  代理层新增本地静态文件与固定重定向，仍排在检测与 ACL 之后，静态根目录做 canonicalize 与软链接逃逸检查。
- **攻击防护**：`GET /api/attack/overview?range=` 汇总 KPI、趋势序列、类型/处置分布、Top IP（含归属地）、
  被攻击应用与命中规则；页面支持时间范围、应用/类型/处置/关键字筛选、分页、CSV 导出、10 秒自动刷新与一键封禁。
  事件查询扩展 `until` / `app` / `path` / `q`，`/api/events` 与导出共用同一套筛选参数。
- **封禁**：`POST /api/bans` 手动封禁（默认 60 分钟、上限 30 天），`manual` 标记使自动封禁关闭时仍生效，
  重启后按 reason 恢复；`GET /api/bans` 与解封沿用原接口。
- **系统设置**：四个页签（基本设置 / 防护引擎 / 规则管理 / 数据维护）。`GET /api/system/info` 返回版本、PID、
  启动时间、运行时长、监听地址、应用/规则/上游/事件/封禁计数；`GET /api/system/backup` 导出应用、全局设置、
  ACL 与自定义规则；`POST /api/system/prune` 按天清理事件。不包含共享计划、许可证与云端配额。
- **雷池（长亭）规则兼容**：新增 `custom_rules` 设置项与 `CustomRule` / `RuleCondition` 模型，字段对齐
  `name` / `is_enabled` / `pattern` / `action`（0 白名单、1 黑名单），`pattern` 外层 OR、内层 AND；
  `v` 兼容字符串、数组、数字与 `null`。控制台支持裸数组、`{"rules": [...]}`、`{"data": [...]}` 三种导入格式，
  支持追加（按 id 合并）与整体替换、导出与热重载。
- **规则求值**：`crates/proxy/src/custom_rule.rs` 支持 `src_ip`（CIDR）、`website`、`host`、`path`、`url`、
  `query`、`method`、`user_agent`、`content_type`、`cookie`、`header`（`sub_k`）等条件键，算子覆盖
  eq/ne/contain/prefix/suffix/regex；白名单命中放行并跳过检测、限流与自动封禁，黑名单命中直接 403 并记事件。
- **验证**：workspace 全量测试通过，clippy 零警告；导入雷池格式规则后热重载成功，`User-Agent: sqlmap` 请求被 403
  拦截并记录「自定义黑名单」事件，清空规则后恢复正常；浏览器逐页验证防护应用（列表与详情四页签切换）、
  攻击防护（KPI/趋势/分布/事件表与范围切换）、系统设置（基本设置/规则管理/防护引擎页签）均正常，console 无报错。
- **提交**：`66c0dc5` 已推送 `origin/master`。

---

## 下一步开发任务

### 近期（统计报表四页签，#12 → #15，已全部完成）

| 序号 | 任务 | 内容 | 状态 |
|------|------|------|------|
| #12 | GeoIP + 事件补齐 | admin 侧 GeoIP 模块（`geoip_db` 设置项、mmdb 缓存、快照时解析国家/城市/经纬度，不进代理热路径）；控制台事件筛选适配 `challenge` 事件类型 | ✅ |
| #13 | 统计 API | `/api/stats` 重做（range + app 参数 → 完整 DashboardData JSON）；`/api/security` 安全态势聚合；`/api/reports` 报告列表/详情/CSV；大屏数据接口；`geoip_db` 设置项注册 | ✅ |
| #14 | 深色四页签控制台 | 深色主题 + 流量分析/安全态势/防护报告/防护大屏；自绘 SVG 图表；点阵世界/中国地图；数字滚动动画；大屏全屏浮层 + 明/暗主题 + 自定义标题；导航「概览」改名「统计报表」 | ✅ |
| #15 | 验证与文档 | 全量测试、浏览器逐页验证四页签、README/差距分析/功能规格/日志更新 | ✅ |
| #16 | 防护应用 / 攻击防护 / 系统设置 | 应用列表+详情四页签与静态/重定向、攻击概览与筛选分页封禁、系统信息/备份/清理、雷池自定义规则导入导出与热重载 | ✅ |

### 远期遗留（差距分析中未排期）

- 控制台登录鉴权、多用户
- ACME 自动证书、多证书 SNI
- 告警通知（Webhook/邮件）
- Bot 识别 / JA4 指纹
- 静态资源缓存
- IP 信誉库联动
- 规则在线编辑器

### 当前进度估计

基线（初始提交）→ 防护增强 → 规则订阅 → 指标底座 → GeoIP → 统计 API → 深色四页签控制台与防护大屏 → 防护应用 / 攻击防护 / 系统设置，任务 #12–#16 已全部入库。整体功能完成度约 **75%**（对照差距分析）。
