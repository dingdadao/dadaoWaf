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

### 00:30 — 生产部署（10.0.0.31）与压测

- 构建：Zig 0.14.1 + `cargo zigbuild --release --target x86_64-unknown-linux-gnu`，产物部署到
  `/opt/homewaf/bin/homewaf`，systemd 单元 `homewaf`（`--db /opt/homewaf/data/homewaf.db
  --listen 0.0.0.0:80 --tls-listen 0.0.0.0:443`，`Restart=always`）。替换顺序必须
  「传 `homewaf.new` → `stop` + `pkill -9 -x homewaf` → `mv` → `start`」，否则 `Text file busy`。
- 上线过程中修掉三个真实缺陷：
  1. **HTTPS 上游一律 502**：`HttpPeer::new(addr, tls, String::new())` 传了空 SNI，rustls 抛
     `Failed to parse domain:`。改为「显式 sni → 否则主机名/IP」，并按配置设置
     `verify_cert` / `verify_hostname`（内网自签上游关闭）。
  2. **自定义白名单只跳过封禁、仍会被检测 403**：白名单命中后改为整段跳过应用层检测（含 body 检测），
     与雷池「白名单直接放行」语义一致；黑名单仍是直接 403 + 事件。
  3. **80 端口反复 `is in use`**：Linux 上 `[::]:80` 是双栈，与 `0.0.0.0:80` 同时监听冲突。
     默认 `server.listen` 改为只 `0.0.0.0:80`，单元文件也只传 IPv4。
- 同步结果（对 `https://10.0.0.14:9443`）：应用 8/8（`fn` `pve` `waf` `cretd` `cf` `home` `ddoh` 启用，
  `qh` 停用）、规则 2/3（`ja4` 条件跳过）、IP 组 9 个、证书 4 张托管跳过。
- 压测（macOS 侧 `ab`，客户端 10.0.0.29，经 80 端口带 `Host` 头）：

  | 场景 | 请求数 | 并发 | 吞吐 | 失败 |
  |------|--------|------|------|------|
  | 四应用并发（waf/fn/cretd/cf） | 4×2000 | 4×40 | 1250–1342 rps/应用 | 1 个 403 来自 fnOS 自身 |
  | `waf.niao.fun` + `pve.niao.fun` 持续 | 2×20000 | 2×100 | 2615 / 720 rps | 0 |
  | `fn.niao.fun`（对比直连上游 7276 rps） | 2000 | 40 | 5047 rps | 4 个 403 来自 fnOS 自身 |

  压测期间进程无错误日志、无重启，RSS 48 MB → 58 MB（生产机总内存 512 MB），`/api/stats` 记录请求
  5.3 万次、状态分布与并发一致。
- 功能回归：SQLi / 路径穿越 / XSS 均 403 并记录事件，自动封禁按 300s → 1800s → 7200s 递增；
  启用雷池同步来的「局域网」白名单后同样请求直接放行（符合白名单优先语义）；`/api/events` 多维筛选、
  CSV 导出、`/api/stats`、`/api/attack/overview`、`/api/geoip`、`/api/system/info`、`/api/custom-rules/export`
  与首页（`Cache-Control: no-store`）全部 200。
- 已知限制：前端 443 无证书（雷池证书均为 ACME/托管，私钥不可导出），握手会失败，需在控制台上传
  证书后启用；`home.niao.fun` 经 WAF 返回 400 是 Home Assistant 的 `trusted_proxies` 未包含
  10.0.0.31，非本项目缺陷。

### 09:10 — 人机验证增强：PoW 成本墙 + 环境指纹 + 签名绑定（任务 #23）

- **不做滑块/图形验证码，也不做 JSVMP**：滑块与图片识别在 AI 视觉模型面前基本失守；JSVMP 需要自研
  编译器 + 解释器并持续对抗逆向，维护成本远超家用 WAF 的收益。改为三道成本低、可验证的叠加防线。
- **成本墙（PoW）**：`SHA-256(token.fp.nonce)` 前导零十六进制位达到难度（1–8，默认 4），浏览器本地计算、
  服务端一次哈希校验，零外部依赖；难度可配，抬高批量尝试成本。
- **环境指纹**：挑战页采集 `navigator.webdriver`、CDP 残留对象、屏幕尺寸/色深、时区、语言、CPU 核数、
  Canvas/WebGL 渲染特征，合成 16 位十六进制指纹；指纹参与 PoW 输入，服务端校验格式。`wd=1` / `cdp=1` /
  缺字段 / 未知字段一律按自动化拒绝（缺字段视为客户端故意隐瞒）。
- **签名绑定 + 一次性解**：挑战令牌与 Cookie 继续用 HMAC-SHA256 绑定应用 + 客户端 IP + 过期时间，
  密钥进程内随机生成、重启即失效；服务端记录 `sha256(token.nonce.fp)` 摘要（上限 8192，过期清理），
  同一解答二次提交按重放拒绝。
- 代码：`crates/proxy/src/challenge.rs` 新增 `Solution` 与 `BadFingerprint` / `Automated` / `Replay` 错误，
  `server.rs` 采集 `fp` / `env` 参数，`lib.rs` 导出；代理 111 个测试全绿，clippy 零警告。
- **实测**（`Host: nas.home.lan`）：
  - 首次访问 403 下发挑战（difficulty=4），客户端解出后 `303 + Set-Cookie`；带 Cookie 再访问 200 到达上游。
  - 同一解答重放 → 400；`env=wd=1.cdp=0` → 400「检测到自动化浏览器」；缺少 `env` → 400；
    指纹 `zzzz…` / 全零 → 400「环境指纹缺失或异常」。
  - 安全日志分别记录「下发人机验证」「人机验证通过」，失败原因按类型落入 DEBUG。
- **诚实局限**：用 CDP 驱动并剥离自动化标记的 Chrome（`navigator.webdriver=false`、无 `cdc_` 变量）能通过
  全部前端检查——这与「AI 可绕过验证码」的行业现实一致。指纹只抬高无头爬虫门槛，不承诺挡住定向人工操作；
  兜底仍是检测引擎评分、频率限制与自动封禁。

### 09:30 — 证书管理排查：API 上传正常，生产证书重新同步（任务 #24）

- 反馈「可以通过 API 添加/更新证书吗？接口有，但证书管理里看不到」。核对代码：`POST /api/UploadSSLCertAPI`
  （multipart / JSON，`X-SLCE-API-Token`）、`GET` / `DELETE /api/CertAPI` 与控制台 `/api/certs` 共用同一张
  `certificates` 表；本地实测上传、按 `id` 更新、删除均正常，接口与「证书管理」页面即时可见。
- 生产排查：`/api/certs` 为空，`PUT /api/certs/1..4` 空请求体均返回 404，确认库中无证书行；而
  `/api/leichi/last` 报告 `certs.imported = 4` 只是上次同步的历史快照，不反映之后的删除。重新同步后
  新证书 ID 从 6 起，说明此前确有 1–5 号行被删除。
- 另一个坑：生产从未生成 `api_token`，第三方上传会直接返回 401 `invalid api token`，容易被误认为「接口没实现」。
- 处理：对生产执行「预览 → 正式」雷池同步，4 张 ACME 证书（`download` / `speed` / `true.bbroot.com`、
  `*.niao.fun`）已入库并在控制台显示「缺私钥」；无密钥证书不参与 TLS 加载，未改变 443 行为。
- 改进：SLCE 三个接口的 401 文案改为「API Token 未配置或无效，请先在『证书管理』页生成」；证书页补充
  「尚未生成 Token 时第三方接口返回 401」与「雷池同步的 ACME 证书只登记证书链，补传私钥后才可用于 TLS」。
- 验证：admin 57 个测试全绿、clippy 零警告；本地重建后无 Token 上传返回新文案，证书页提示正常；
  生产控制台截图确认 4 张证书可见。使用前需先在「证书管理 → 第三方远程部署」生成 Token，且上传必须
  同时提供证书链与私钥。

### 09:55 — 二次生产部署、证书消失定案与优雅退出修复（任务 #25）

- 部署：改用 `rustup target add x86_64-unknown-linux-gnu` + Homebrew `zig@0.14`（cargo-zigbuild 0.24
  实际拉取 zig 0.17.0）交叉编译；停服前把 `homewaf.db*` 与旧二进制备份到
  `/opt/homewaf/backups/20261023-013613/`（`homewaf.prev`）。两次部署的二进制哈希：
  `e26c7723b13d61c3`（证书状态列布局修复前）→ `a243f3b193bad723`（最终，含 nowrap 状态列）。
- **证书消失定案：不是持久化缺陷**。本地把证书写入 `/tmp/homewaf-demo.db` 后直接 `kill -9` 再启动，
  证书仍在；代码中 `DELETE FROM certificates` 只出现在控制台 `DELETE /api/certs/{id}`（含 SLCE
  `DELETE /api/CertAPI`）路径，启动、重载、同步均无删除逻辑。生产
  `sqlite_sequence(certificates)=9` 说明历史上写入过 9 行；01:39:14–01:39:26 连续 4 次「配置已重载」
  正对应 4 张 ACME 证书被逐个删除（每次删除触发一次重载），与「重启丢证书」无关。
- **安全提醒**：生产控制台以 `HOMEWAF_ADMIN_INSECURE=1` 无 Token 监听 `0.0.0.0:9443`，记录里出现
  的四次删除也可能来自局域网内任意客户端。证书删除操作已补审计日志；控制台登录/Token 仍待排期。
- 修复 1：证书新增/更新/删除写入 `homewaf.security` 审计日志（ID、名称、域名、动作），下次再出现
  删除可直接从 journal 定位。
- 修复 2：Pingora 默认优雅退出宽限期 300 秒，`systemctl stop` 会干等 5 分钟、只能靠 `kill -9` 收场；
  在 `crates/proxy/src/server.rs` 把 `grace_period_seconds` 调为 10 秒。实测 SIGTERM 后 10 秒退出，
  日志完整落盘。
- 验证：clippy 零警告；本地证书在 SIGKILL 重启后仍存在（测试证书已清理）；审计日志实测输出
  `证书已保存 cert_id=5 …` 与 `证书已删除 cert_id=5 …`。
- 遗留：部署收尾时 10.0.0.31 再次失联，生产 `/api/certs` 当前为空；网络恢复后需重新执行「预览 →
  正式」雷池同步，把 4 张 ACME 证书补回（仍为「缺私钥」，只登记不参与 TLS）。

### 10:05 — 雷池开放 API 与证书同步语义（任务 #26）

- 反馈两件事：①「雷池同步」显示应用 8/8、IP 组 9/10，但证书管理为空；②在雷池的
  「配置同步 / 授权」抽屉里把地址指向 `https://10.0.0.14:9443`（雷池自己）并填 HomeWAF 的 Token，
  连通性测试报 `Login required [https://10.0.0.14:9443/api/open/cert]`。
- **根因一（配置方向反了）**：雷池「配置同步」是主从复制，从端必须是另一套雷池；测试连通性的动作是
  用 `X-SLCE-API-Token` 请求 `GET /api/open/cert`。要让它指向 HomeWAF，地址应填 **HomeWAF 管理端**
  （生产为 `http://10.0.0.31:9443`），Token 填 HomeWAF 在「证书管理 → 第三方远程部署」生成的 Token；
  填雷池自己的地址只会得到雷池侧的 `Login required`。
- **根因二（开放 API 不完整）**：此前只实现了 `UploadSSLCertAPI` / `CertAPI`（上传/列表/删除），
  没有 `/api/open/*`，与雷池开放 API 不一致。新增：
  - `GET /api/open/health` → `{"err":null,"msg":"success","data":{...}}`
  - `GET /api/open/cert` → `data.nodes[]`（`id` / `domains` / `issuer` / `not_after` / `type` / `has_key`）
  - `GET /api/open/cert/{id}` → `data.manual.{crt,key}`（无私钥时 `key` 为空）
  - `POST /api/open/cert` → 接受雷池的 `{"manual":{"crt","key"},"type":2}`、扁平 `{crt,key}` 与 multipart；
    带 `id` 更新，否则按证书主域名匹配已有证书做续期，都不命中才新增
  - `DELETE /api/open/cert/{id}`
  全部走 `X-SLCE-API-Token`，未配置或错误时返回雷池同款 401 `Login required`。
- **根因三（同步读不到证书）**：`leichi.rs` 只认 `manual.crt/key` 一种形状，且已存在证书按 PEM
  全等判断，雷池续期后 PEM 变化就会重复插入。现在兼容 `manual.*` 与顶层 `crt` / `key` / `key_pem`，
  按域名（大小写不敏感、支持逗号列表与通配符重叠）匹配已有行并原地更新；雷池对 ACME 证书不提供私钥时，
  若已有可用证书则保留旧行并给出 warning，避免用空私钥覆盖导致整站 TLS 失败。预览与正式共用同一套逻辑。
- **验证**：本地按雷池形状 POST 创建证书（id=6）→ 同域名再次 POST 原地续期（仍 id=6，序列号更新）→
  列表/详情/删除均正常，无 Token 返回 401；用 mock 雷池跑「预览 → 正式」同步，证书 id 保持不变，
  无键续期被跳过且现有证书仍可用。admin 60 个测试全绿、clippy 零警告。
- **诚实局限**：
  - 雷池的 ACME / 托管证书在服务端就不导出私钥，任何同步手段都只能拿到证书链。HomeWAF 照常登记并标
    「缺私钥」，但不参与 TLS；要用必须手动上传含私钥的证书（或后续实现 ACME 自动签发）。
  - 雷池「配置同步」的从端协议属于其私有实现（版本/license 校验等），本次只保证其连通性探测所需的
    `/api/open/cert` 可用；完整主从复制不承诺，HomeWAF 侧仍是单向「从雷池拉取」。
- **生产部署（10:10 网络恢复后）**：备份到 `/opt/homewaf/backups/<时间戳>/` 后替换二进制
  `a243f3b193bad723` → `49039b30248e4b10`，服务正常启动。执行「预览 → 正式」同步，4 张证书恢复为
  ID 10–13（仍为「缺私钥」）；再次同步仍是 4 张、ID 不变，确认按域名续期不会重复插入。控制台证书页
  已显示 4 行。开放接口实测：无 Token 401，带 Token 经回环与局域网地址均 200，`/api/open/cert` 返回
  4 个节点、`/api/open/cert/10` 的 `manual.key` 为空。
- **生产复测（10:20）**：
  - 代理与检测：正常请求 200；从生产机回环逐项复测，SQLi 命中 `sqli-union-select`（50 分）、
    XSS 命中 `xss-script-tag`（50 分）、路径穿越命中 `traversal-sensitive-file`（80 分），均 403、
    写事件并触发 127.0.0.1 自动封禁（300s），每项测试后已解封、封禁表最终为空。
    **从 10.0.0.0/24 发起攻击会是 200**（访问日志确认来源为 10.0.0.20），因为雷池同步来的
    「局域网」ACL 是整段放行，白名单优先属于预期语义；复测攻击面必须换非白名单源。
  - 开放 API：`POST /api/open/cert` 用临时自签证书创建 id=14，`GET /api/open/cert/14` 返回完整
    crt/key，`DELETE` 后证书表回到 4 张（ID 10–13）；删除默认证书后系统自动把默认指到 ID 10。
  - 控制台：统计/攻击/证书/系统设置各页 DOM 正常、无控制台报错；「系统设置 → 雷池同步」显示
    8/8 应用、4/4 证书、1/3 规则、9/10 IP 组，模式「已写入并热重载」。
  - TLS：4 张证书均缺私钥，`https://10.0.0.31:443`（SNI `waf.niao.fun`）仍握手失败，与日志
    `no server certificate chain resolved` 一致；HTTP 80 正常。
- **给雷池「配置同步」的正确填法**：地址填 HomeWAF 管理端 `http://10.0.0.31:9443`（不是雷池自己的
  `https://10.0.0.14:9443`），Token 填本次生产已生成的 HomeWAF Token；这样连通性测试请求的就是
  HomeWAF 的 `/api/open/cert`。但即便测试通过，雷池完整主从复制仍受其版本/license 校验限制，
  HomeWAF 只保证这套开放接口可用于第三方脚本与探测。

### 10:35 — Certd 自动签发证书推送支持与两个 Token 的用途（任务 #27）

- 需求澄清：目标是 **Certd 流水线自动签发证书后直接推到 HomeWAF**，不是让 HomeWAF 去雷池拉证书。
  核对 Certd v2 的 `SafelineAccess` 与 `SafelineDeployToWebsitePlugin` 源码后确认，它只调用：
  - 授权测试 / 远程列证书：`GET /api/open/cert`，请求头 `X-SLCE-API-TOKEN`，读取 `data.nodes[].id/domains`；
  - 部署证书：`POST /api/open/cert`，body 为 `{"manual":{"crt","key"},"type":2}`，选择已有证书时附加 `id`，
    新增时 `id` 为 0 或不传。
  这正是 #26 已实现的接口，HomeWAF 无需再改后端；本轮只补了控制台提示并做生产实测。
- **两个 Token 的区别（已写进界面）**：
  - **HomeWAF API Token**（证书管理 → 第三方证书推送）：给 Certd、第三方脚本、雷池「配置同步」探测用；
  - **雷池 API Token**（系统设置 → 雷池同步）：只给 HomeWAF 从雷池拉取应用/规则/IP 组/证书用，Certd 不需要。
- Certd 配置方法：授权类型选「长亭雷池授权」，URL 填 `http://10.0.0.31:9443`，ApiToken 填 HomeWAF
  API Token；流水线添加「雷池-更新证书」，证书 ID 填 0 新增，或选已有证书 ID 做续期。注意 Certd 的
  远程选择器要求证书列表非空（当前有 4 张），空库时需先手工上传一次或直接填 0。
- **生产实测（新二进制 `aa17d253e4b54a49`）**：
  - Certd 新增形状（`manual` + `type:2` + `id:0`）→ 创建 id=15，`has_key=true`，列表可见 → 删除后回到 4 张；
  - Certd 续期形状（同域名、带已有 id）→ 创建 id=16 后用新证书再次 POST，仍是 id=16、`updated_at` 更新
    → 删除后回到 4 张；未触碰真实证书 10–13。
  - 无 Token 仍 401；证书页出现「Certd：」说明和「HomeWAF API Token（Certd / 第三方脚本用）」标签；
    雷池同步页明确标注该处 Token 只用于从雷池拉取。
- **限制**：
  - HomeWAF 管理端只提供 HTTP，Certd 的 URL 必须填 `http://…:9443`；若 Certd 环境强制 HTTPS，需要在
    前面加 TLS 反向代理。
  - Certd 的「雷池」插件只覆盖证书接口；雷池的站点、IP 组等其它开放接口未实现，不要拿其它雷池插件
    直接指向 HomeWAF。
  - Certd 更新的是证书记录本身，防护应用通过证书 ID 绑定会自动跟随；更新含私钥的证书后才会真正参与
    TLS，更新成功后控制台会热重载。

### 10:40 — 手动 API 更新实测与并发删除排查

- 按用户要求直接调用生产 `http://10.0.0.31:9443/api/open/cert`（`X-SLCE-API-Token` 为证书页
  HomeWAF Token）做了一次完整实测，未触碰真实证书：
  - 新增临时证书 id=17（`manual-check.homewaf.local`，类型 2）→ 返回 `{"data":{"id":17},"err":null}`；
  - 带 `id=17` 再 POST 新证书 → 仍为 id=17，`not_after` 从 +1 天变为 +3 天，`updated_at` 更新；
  - 删除 id=17 → `data:null`；接口更新语义正常。
- **删除事件澄清**：用户确认 10:32 的 10–12 三次删除是本人手动操作，并非异常，本轮测试未触碰真实
  证书。id=17 是测试证书，脚本在创建后 0.4 秒内就执行了删除，所以控制台来不及显示；这也说明控制台
  证书页不会自动轮询，新增后需点「刷新」或重新进入页面。
- 为便于人工确认，随后又创建 id=18（`manual-check.homewaf.local`）并带 `id` 更新为 3 天有效期，
  `/api/certs` 与控制台刷新后均显示该证书（状态「可用」）；该测试证书先保留，待用户确认后再删除。
- 管理端仍是无鉴权监听，删除审计不记录来源 IP；这次虽为手动操作，但仍是实际风险。雷池同步预览仍可
  导入 4/4 证书，未自动执行正式同步。

### 10:45 — Certd 显示成功但 HomeWAF 无证书的定位

- 用户提供 Certd 日志：10:40:29 流水线「雷池-更新证书」向 `/api/open/cert` 发送 POST，HTTP 200，
  日志写「证书<1>更新成功,ID:1」，但 HomeWAF 仍看不到新证书。
- 生产核对（10:41–10:43）：
  - `GET /api/certs` 仍只有 id=18（`manual-check.homewaf.local`），没有新增/更新记录；
  - HomeWAF 代理访问日志最后一条是 10:17，之后没有 `/api/open/cert` 经过 80/443；
  - 用「雷池同步 → 预览」查 10.0.0.14：仍是 4 张原证书（`download/speed/true.bbroot.com`、
    `*.niao.fun`），全部为 ACME / 缺私钥，也没有这次 Certd 更新的内容。
- 结论：这个 200 既不来自 HomeWAF，也不来自当前同步的雷池。Certd 的「雷池」插件只要 HTTP 200 就报成功，
  不校验返回的证书 ID，因此请求实际打到了另一个兼容地址/旧实例。HomeWAF 的 API Token 已配置（64 位），
  雷池同步页的 Token 是 32 位，两者长度可直接区分。
- 正确配置：Certd 授权 URL 必须是 `http://10.0.0.31:9443`（不是 `https://10.0.0.14:9443`、不是
  `dns.niao.fun`、不是 80 端口），ApiToken 必须是证书管理页的 HomeWAF API Token（64 位），
  部署步骤证书 ID 填 0/留空；HomeWAF 会按域名续期，不会重复插入。
- 说明：`/api/open/cert` 成功时返回 `{"err":null,"data":{"id":…}}`；如果 Certd 日志里的 ID 与
  HomeWAF 返回不一致或列表没有新增，就说明请求没到 HomeWAF。
- 用户随后提供 Certd 授权截图，确认根因：URL 填的是 `http://10.0.0.30:9443`（DNS 配置中心，
  不是 HomeWAF），测试报 `ECONNREFUSED 10.0.0.30:9443`；ApiToken 也不是证书管理页那枚 64 位
  HomeWAF Token。正确填法：URL 改为 `http://10.0.0.31:9443`，Token 从「证书管理 → HomeWAF API Token」
  复制，点「测试」通过后再跑流水线；证书 ID 填 0/留空。截图中的 Token 不写入文档。
- 用户把 URL 改为 `http://10.0.0.31:9443` 后，Certd 测试返回
  `Login required 【http://10.0.0.31:9443/api/open/cert】`。这是 HomeWAF `open_unauthorized()` 的 401，
  说明网络与路径已经正确，仅 `X-SLCE-API-Token` 与库中 Token 不一致；换用证书管理页的 64 位
  HomeWAF API Token 即可。生产库确认该 Token 已配置（64 位）。

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
| #20 | 生产部署与压测 | 交叉编译部署到 10.0.0.31，修复上游 SNI / 白名单语义 / 双栈监听三个缺陷，压测 4 万+ 请求零错误 | ✅ |
| #21 | 生产验收测试 | 功能 / 安全 / 性能三项验收，修复健康检查误判、监听地址展示、运算符路由、配置回滚、连接重试、控制字符、Header 检测、健康度误计共 8 项缺陷并复测，详见 `docs/production-test-report.md` | ✅ |
| #22 | 雷池同步语义修正 | 策略改落「访问控制」规则（`lei-acl-*`）、IP 组按 reference 建订阅（`lei-ipgroup-*`，支持 allow 动作）、ACME 证书只登记证书链并在控制台标记「缺私钥」、订阅快照落库 + 到期跳过联网 + keep-last 回退、修复内网默认放行被误当白名单跳过检测 | ✅ |
| #23 | 人机验证增强 | PoW 成本墙 + 环境/自动化指纹 + HMAC 签名绑定与一次性解（防重放）；挑战页自采指纹，重放/自动化/缺失/非法指纹四类拒绝路径实测通过 | ✅ |
| #24 | 证书管理排查 | 确认上传/更新/删除 API 与页面共用证书表；生产重新同步 4 张 ACME 证书（缺私钥）；补齐 Token 未生成与 ACME 证书提示 | ✅ |
| #25 | 二次生产部署与退出修复 | Zig 交叉编译部署；证书消失定案为 API 删除而非持久化缺陷；证书变更补审计日志；Pingora 优雅退出宽限 300s → 10s | ✅ |
| #26 | 雷池开放 API 与证书同步 | 新增 `/api/open/health`、`/api/open/cert`（GET/POST）、`/api/open/cert/{id}`（GET/DELETE）对齐雷池；同步兼容 `manual`/顶层字段并按域名原地续期；无键续期保留现有证书 | ✅ |
| #27 | Certd 证书推送 | 对齐 Certd 雷池插件的 `GET/POST /api/open/cert`（`manual` + `type:2` + `id`）；控制台明确 HomeWAF Token 与雷池 Token 的用途；生产实测新增与按 ID 续期均通过 | ✅ |
| #28 | 订阅源合并 + 中文名称 | 控制台「IP 组订阅」「规则订阅」合并为一页「订阅源」，新增 `/api/subscriptions` 统一入口（`{kind, config}` 分派）；`IpGroup`/`RuleFeed` 增加 `label` 中文名称字段（展示用，不参与匹配），雷池同步写入组名；状态归一为 停用/异常/待拉取/正常 四档；刷新未到间隔时如实提示未联网 | ✅ |
| #29 | 生产部署（订阅源版本） | Zig 交叉编译 `7f0aea3d` 部署到 10.0.0.31（备份 `backups/20261023-115135/`）；8 应用 / 3513 条 ACL / 5 个 IP 组订阅中文名回填 / 1 张证书全部正常；回环实测 SQLi 与路径穿越 403 并触发自动封禁 | ✅ |
| #30 | 访问控制重构 + 事件日志明细 | 「访问控制」从「只能填网段」改为雷池式条件规则：条件组（外层或/内层且）+ 四种动作（放行/拦截/人机验证/仅记录）+ 应用范围 + 启停；条件字段支持 IP/网段、IP 组、路径、方法、UA、请求头、查询串、域名；历史 acl_rules 自动迁移为条件规则；事件新增请求方法/查询串/UA/规则名/请求 ID，日志新增主机/查询串/应用名/说明列并支持从事件按请求 ID 跳转 | ✅ |
| #31 | 生产部署（条件规则版本） | 交叉编译 `a33b1bc2` 部署到 10.0.0.31（备份 `backups/20261023-1444/`）；启动时自动把 `lei-acl-83-0` 迁成条件规则（`来源 IP 等于 10.0.0.0/24 → 放行`），acl_rules 清空；8 应用 / 5 个 IP 组 / 事件表自动补列；回环实测 SQLi 与路径穿越仍 403，规则名与请求 ID 正常落库 | ✅ |
| #32 | 黑白名单对齐雷池 | 页面拆白/黑/其他三栏带计数；列表补序号、状态开关、匹配方式、创建时间；新增 `match_mode`（任意/全部）与 `seq`/`created_at`，匹配按序号从新到旧；表单改为雷池布局（规则类型单选 + 匹配方式 + AND/OR 条件）；部署生产并验证 | ✅ |
| #33 | 检测黑名单（自定义检测规则） | 控制台可直接写正则特征规则（关键词预过滤 + 作用对象 + 分类 + 分值 + 动作），与内置规则共用匹配路径、参与评分与自动封禁；保存时校验正则/对象/分类；正则测试走服务端避免 JS 语法差异；已部署生产并验证 UA 特征拦截 403、事件记录规则名 | ✅ |

### 远期遗留（差距分析中未排期）

- 控制台登录鉴权、多用户
- ACME 自动证书（多证书 SNI 已在 #18 实现）
- 告警通知（Webhook/邮件）
- Bot 识别 / JA4 指纹
- 静态资源缓存
- IP 信誉库联动
- 规则在线编辑器

### 当前进度估计

基线（初始提交）→ 防护增强 → 规则订阅 → 指标底座 → GeoIP → 统计 API → 深色四页签控制台与防护大屏 → 防护应用 / 攻击防护 / 系统设置 → 网页防篡改 → 证书管理 / 多证书 SNI / 远程部署 API → 雷池配置同步 → 人机验证增强 → 证书管理排查 → 二次生产部署 → 雷池开放 API → Certd 证书推送 → 订阅源合并 → 生产部署 → 访问控制重构，任务 #12–#33 已全部入库。整体功能完成度约 **86%**（对照差距分析）。
