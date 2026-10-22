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

### 21:35 — 控制台 UI 2.0：统一深色设计系统

- 全站统一深色主题，消除统计报表（深色）与其余页面（浅色）的割裂；`--s-*` 变量并入全局 tokens，
  修复攻击防护页 KPI/卡片因变量缺失导致的黑底黑字问题。
- 建立统一组件规范：卡片（`section.card` / `.dcard` 同一外观）、页签（`.stats-tabs` / `.sys-tabs`
  统一为底部高亮式）、表格（深色表头、行 hover）、按钮（默认/主色/危险）、输入框（深色底、聚焦环）、
  标签与状态色、空状态、分页、工具条 `.toolbar`。
- 侧边栏改为品牌标识 + 分组导航（监控 / 防护 / 订阅 / 运维），218px 深色渐变底；
  顶栏改为半透明毛玻璃 + 状态胶囊；内容区统一 28px 边距与页面切换动效。
- 攻击防护筛选区统一为 `.toolbar` 卡片；事件/应用表格在窄屏下卡片内横向滚动，不再撑破布局。
- 验证：浏览器逐页走查统计报表、攻击防护、防护应用（详情四页签）、系统设置（四页签），
  深色背景下文字与控件清晰、无重叠溢出，console 无 JS 报错。

### 22:05 — 对照雷池 Demo 对齐视觉与页面交互

- **配色对齐雷池**：全站改为炭黑 + 米黄（`--bg:#181818`、`--card:#232323`、`--border:#353535`、
  `--accent:#f1d6bf`），主按钮米黄底深色字，圆角统一 6px；清理统计页、大屏、表格、表单中遗留的蓝色系色值。
- **防护应用列表改为卡片网格**：工具条含搜索（应用名/端口/域名）、高级配置、添加应用；每张卡片展示
  名称/ID、接入方式与分组、域名、监听端口、上游/目标、路由数量，以及防护模式、攻击防护、CC 防护、
  BOT 防护（占位禁用）、详情/启停/删除操作。
- **新增应用级快捷开关后端**：`POST /api/apps/{id}/features` 单独更新 `AppFeatures`，避免整份配置回传；
  `PolicySet` 已按 `attack` 关闭全部检测分类、按 `cc` 关闭 CC 档位。防护模式使用应用 `policy.observe_mode`
  在「防护 / 观察」间切换，启停仍走原有的 `/enabled`。
- **详情页**：页签下方新增快捷操作条（防护模式、攻击防护、CC 防护、BOT/身份认证占位、启用禁用），
  基本信息页把原先一行统计提示改为「请求 / 拦截 / 攻击 IP / 独立 IP」24 小时指标卡。
- **系统设置重排为雷池式三页签**：防护配置（检测引擎性能、自定义规则、配置备份与数据清理、关联配置）、
  控制台管理（系统信息、接入端口、管理面）、系统日志（跳转日志/事件）。
- 验证：`cargo test --workspace` 全量通过、`cargo clippy --workspace --all-targets -- -D warnings` 零警告；
  浏览器逐页走查统计报表、防护应用（卡片开关与详情四页签）、攻击防护、系统设置三页签，
  控制台无 JS 报错；实测关闭攻击防护后 `sqlmap` UA + SQL 注入请求放行，重新开启后返回 403 并记录事件。

### 22:20 — 网页防篡改

- **配置模型**：`Application` 新增 `tamper`（`enabled` / `paths` / `action`），`action` 支持 `block`
  与 `log`；字段带 `serde(default)`，旧库与历史配置无需迁移。`paths` 支持相对静态站点根目录的路径，
  留空时默认保护整个 `static_site.root`。
- **基线存储**：新增 `tamper_baselines(app_id, path, size, digest, updated_at)` 表，主键 `(app_id, path)`；
  `ConfigStore` 增加 `replace_tamper_baseline`（事务内整体替换）、`tamper_baseline`、`all_tamper_baselines`
  与 `tamper_baseline_count`。
- **指纹与扫描**（`crates/proxy/src/tamper.rs`）：用 `ring` 计算 SHA-256，代码内转小写十六进制，不引入新依赖；
  建立基线时递归遍历受保护目录（跳过符号链接、超过 64MB 的文件、读不到的条目，单次最多 20000 个文件）；
  手动检查同时识别 `modified` / `added` / `deleted` 三类变化。
- **运行时校验**：`RuntimeState.tamper` 按应用 id 顺序缓存基线，`serve_static` 在返回 200 前比对大小与摘要；
  命中 `modified` / `added` 时按 `action` 记录事件并返回 403「文件已被篡改，访问被拒绝」；同一文件 60 秒内
  只记一条事件，避免刷日志。未建立基线或不在保护目录内的请求不拦截。
- **API**：`GET /api/apps/{id}/tamper` 返回启用状态、处置方式、目录、基线文件数、实际保护根目录与
  `live_check`（静态站点为实时拦截，反向代理应用只能手动检查）；`POST .../tamper/baseline` 重建基线并热重载；
  `POST .../tamper/scan` 返回变更列表并写入事件。
- **控制台**：应用详情新增「网页防篡改」页签，含启停、处置方式、监控目录、基线状态、建立/重建基线、
  立即检查与变更列表；保存配置前会先提交应用表单，避免基线使用旧配置。
- 验证：全量测试通过、clippy 零警告；实测静态应用建立基线后干净请求 200，改写 `index.html` 后代理返回 403，
  手动检查返回 1 条 `modified` 变更，还原文件后恢复 200；浏览器走查页签，基线文件数、检查结果与
  控制台错误均符合预期。
- 限制：反向代理应用不做请求级实时校验（仅手动检查）；变更文件只拦截、不回滚，未做自动恢复备份。

### 22:35 — 地理信息默认下载

- 系统设置「地理信息（GeoIP）」增加「下载默认库」按钮，默认下载源为
  `https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz`。
- 新增 `POST /api/geoip/download`：在 `spawn_blocking` 中下载并解压（`flate2`，单次上限：压缩包
  256MB、解压后 1GB），先写临时文件再 rename，落盘后用 `validate_db` 校验可加载，随后写入
  `geoip_db` 设置并立即换库，无需重启。
- 保存目录为数据库所在目录（默认 `./data/GeoLite2-City.mmdb`，`--db /tmp/x.db` 时为 `/tmp/GeoLite2-City.mmdb`）。
- 控制台首页改为 `Cache-Control: no-store`，升级二进制后浏览器不会再继续使用旧界面。
- 验证：实测下载返回 `{"ok":true,"path":"/tmp/GeoLite2-City.mmdb","enabled":true}`，文件 49MB，
  `/api/settings/geoip_db` 已写入新路径；全量测试与 clippy 均通过。

### 23:10 — 证书管理 / 多证书 SNI / 远程部署 API

- 新增 `certificates` 表（名称、证书与私钥 PEM、域名、有效期、默认标记），证书成为数据库配置的一部分，
  不再依赖 `tls.cert` / `tls.key` 两个文件路径。
- 代理新增 `crates/proxy/src/tls.rs`：`CertMap` 按精确域名与通配符（`*.example.com`，只匹配一级）建索引，
  `SniResolver` 实现 `ResolvesServerCert`，每次握手读取当前 `SharedState`，因此上传/更新/删除证书后
  热重载即生效，无需重启；应用在 `tls.mode = manual` 且绑定 `cert_id` 时覆盖应用域名。
- HTTPS 监听改为 `TlsSettings::with_callbacks` + `set_cert_resolver`；空证书库也允许启动（握手会失败并告警），
  上传证书后立即恢复。
- 证书解析用 `x509-parser` 读取 SAN / CN、`not_before` / `not_after`、issuer 与序列号；上传前用 rustls
  校验证书与私钥匹配，不匹配直接拒绝，避免把坏证书写进库导致整站握手失败。
- 控制台新增「证书管理」页：列表（域名、有效期、过期标记、默认标记）、上传/更新、删除、设为默认；
  应用详情「高级配置」中的证书 ID 文本框改为证书下拉，选中证书自动切换为手动指定。
- 远程部署：新增 `api_token` 设置项与控制台生成/轮换按钮（32 字节系统随机数），兼容雷池接口：
  `GET /api/CertAPI`、`DELETE /api/CertAPI`、`POST /api/UploadSSLCertAPI`（multipart：
  `crt_file` / `key_file` / `name` / `id`），鉴权头 `X-SLCE-API-Token`；未配置 token 时一律 401。
  离线环境没有 `multer`，multipart 用自写的 boundary 切分解析。
- 验证：全量测试 534 项通过、clippy 零警告；实测上传 `a.test.local`、`b.test.local`、`default.test.local`
  三张自签证书后，`openssl s_client -servername` 分别返回对应证书，未知 SNI 回落默认证书；应用绑定
  `app.test.local → 证书 #2` 后握手返回 `b.test.local`；进程不重启上传新证书立即生效；HTTPS 请求经
  代理到后端返回 200；雷池兼容接口完成带 token 的列表、multipart 上传、按 id 更新与删除，错误 token 返回 401；
  浏览器验证证书页列表/编辑器/API Token、应用详情证书下拉均正常，无 JS 报错。

### 23:55 — 雷池（SafeLine）配置同步

- 新增 `crates/admin/src/leichi.rs`：通过雷池开放 API 拉取站点、策略、IP 组与证书，统一映射到本项目的
  应用 / 自定义规则 / 证书库。鉴权头 `X-SLCE-API-Token`，内网自签证书跳过校验。
- 响应信封兼容：雷池不同接口包裹层数不一致（列表是 `data.nodes` / `data.data`，详情是多层 `data.data`），
  `unwrap_envelope` 改为循环剥离，只剥「仅含 data/err/msg 的对象」，避免误伤业务字段。
- **应用**：`id = lei-{站点ID}` 幂等 upsert；域名取 `server_names`（首个为主域名）；端口 `443_ssl` 解析为 443
  并启用 TLS 自动选证书；`mode` 1 视为停用、2 映射为观察模式；`upstreams` 保留完整 URL（https 上游关闭校验）；
  `load_balance.balance_type` 映射轮询 / IP Hash / 加权 / 最少连接，并启用主动健康检查（`/`、200/204/301/302）。
- **规则**：`id = lei-{策略ID}`，保持雷池 `pattern` 外层 OR / 内层 AND 与 `action` 0 白名单、1 黑名单语义；
  `src_ip` 的 `in` / `eq` 值为 IP 组 ID，同步时用 `/open/ipgroup/detail` 展开为 CIDR 列表；不支持的条件
  （如 `ja4`）整条跳过并给出警告。写入时按 id 合并到 `custom_rules`，本地手工规则不受影响。
- **证书**：仅导入带手动私钥（`manual.crt` / `manual.key` 均非空）的证书；ACME / 托管证书无法导出私钥，
  跳过并在报告中提示。IP 组只作为规则展开的数据源，不单独入库。
- **API**：`POST /api/leichi/sync`（`url` / `token` / `preview`；preview 只读不写，同步成功后自动热重载）、
  `GET /api/leichi/last`、`GET /api/leichi/config`；新增设置项 `leichi_url` / `leichi_token` / `leichi_last_sync`。
- **控制台**：系统设置新增「雷池同步」页签，填写地址与 Token 后可预览或执行同步，展示应用/规则/证书/IP 组
  统计、明细与警告，并显示上次同步报告。
- 验证（对 `https://10.0.0.14:9443` 实测）：8 个站点全部导入（`lei-1`…`lei-14`，其中 `qh.niao.fun` 为停用态），
  3 条策略导入 2 条（`ja4` 条件 1 条跳过），9 个有数据的 IP 组展开成功（含 1000+ 条内置情报组），
  4 张证书均为托管证书跳过；预览不落库、正式同步后 `/api/apps` 与 `custom_rules` 均可见，热重载返回 `apps=9`。

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
| #17 | 网页防篡改 | 应用级基线（SHA-256）、静态请求实时拦截与事件记录、手动扫描修改/新增/删除、控制台页签 | ✅ |
| #18 | 证书管理 | 证书库与 CRUD、SNI 多证书、应用绑定、默认证书、雷池兼容远程部署 API（`X-SLCE-API-Token`） | ✅ |
| #19 | 雷池配置同步 | `leichi.rs` 拉取站点/策略/IP 组/证书并映射为本项目应用与自定义规则，控制台「雷池同步」页签，支持预览与热重载 | ✅ |

### 远期遗留（差距分析中未排期）

- 控制台登录鉴权、多用户
- ACME 自动证书（多证书 SNI 已在 #18 实现）
- 告警通知（Webhook/邮件）
- Bot 识别 / JA4 指纹
- 静态资源缓存
- IP 信誉库联动
- 规则在线编辑器

### 当前进度估计

基线（初始提交）→ 防护增强 → 规则订阅 → 指标底座 → GeoIP → 统计 API → 深色四页签控制台与防护大屏 → 防护应用 / 攻击防护 / 系统设置 → 网页防篡改 → 证书管理 / 多证书 SNI / 远程部署 API → 雷池配置同步，任务 #12–#19 已全部入库。整体功能完成度约 **82%**（对照差距分析）。
