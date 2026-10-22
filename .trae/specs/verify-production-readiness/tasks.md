# Tasks
- [ ] Task 1: 修复 D5 重试：`fail_to_connect` 按应用重试策略设置可重试
- [ ] Task 2: 修复 D7 检测：请求头纳入 `InspectionInput.headers`，使 Header 规则生效
- [ ] Task 3: 质量门禁：`cargo clippy -D warnings` + `cargo test --workspace`
- [ ] Task 4: 交叉编译并部署生产，重启后确认服务 active
- [ ] Task 5: 功能复测 D1–D6（健康检查、监听地址、运算符路由、非法配置回滚、重试、控制字符拒绝）
- [ ] Task 6: 安全复测 D7（临时停用局域网白名单规则，测完恢复）：注入、JNDI、Shellshock、扫描器、敏感文件、伪造 XFF
- [ ] Task 7: 性能复测：持续 50k 请求确认无 503 突发，记录 rps/延迟/错误/RSS
- [ ] Task 8: 清理生产测试应用，恢复 auto_ban 与自定义规则状态
- [ ] Task 9: 编写 `docs/production-test-report.md` 并增补 `docs/dev-log.md`
- [ ] Task 10: 提交并推送 git

# Task Dependencies
- Task 3 依赖 Task 1、2
- Task 4 依赖 Task 3
- Task 5、6、7 依赖 Task 4
- Task 9 依赖 Task 5、6、7
- Task 10 依赖 Task 9
