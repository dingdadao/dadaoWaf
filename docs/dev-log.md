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

---

## 下一步开发任务

### 近期（统计报表四页签，#12 → #15）

| 序号 | 任务 | 内容 | 对标 |
|------|------|------|------|
| #12 | GeoIP + 事件补齐 | admin 侧 GeoIP 模块（`geoip_db` 设置项、mmdb 缓存、快照时解析国家/城市/经纬度，不进代理热路径）；控制台事件筛选适配 `challenge` 事件类型 | 大屏「30天访问来源地区」地图 |
| #13 | 统计 API | `/api/stats` 重做（range + app 参数 → 完整 DashboardData JSON）；`/api/security` 安全态势聚合（攻击趋势/类型分布/黑白名单命中/限流/人机验证趋势 + 实时事件）；`/api/reports` 报告列表/详情/CSV；大屏数据接口；`geoip_db` 设置项注册 | 雷池 `/statistics`、`/statistics/security` |
| #14 | 深色四页签控制台 | 雷池风格深色主题 + 流量分析/安全态势/防护报告/防护大屏四页签；自绘 SVG 图表（Catmull-Rom 平滑曲线/环形图/渐变柱）；Natural Earth 点阵世界地图（中国/世界切换）；数字滚动动画；大屏全屏浮层 + 明/暗主题 + 自定义标题；导航「概览」改名「统计报表」 | 本文档「雷池四页签拆解」节 |
| #15 | 验证与文档 | 全量测试、浏览器逐页验证四页签、README/差距分析/功能规格更新 | — |

### 远期遗留（差距分析中未排期）

- 控制台登录鉴权、多用户
- ACME 自动证书、多证书 SNI
- 告警通知（Webhook/邮件）
- Bot 识别 / JA4 指纹
- 静态资源缓存
- IP 信誉库联动
- 规则在线编辑器

### 当前进度估计

基线（初始提交）→ 防护增强 → 规则订阅 → 指标底座已入库；统计报表四页签的前端与 API 是下一批次主体。整体功能完成度约 **55%–60%**（对照差距分析）。
