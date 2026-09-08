# 白盒 0day 审计流程（原 researcher-blackbox-whitebox 本地版）

用户给出项目路径或源码时按本流程走。目标：理解代码意图，找开发者认知盲区。
黑盒部分不适用本文件。

- **Phase 0 建仓**：定位源码/克隆仓库，看 recent commits/issues/安全公告，建模块地图
- **Phase 1 理解意图**：入口 → 数据流 → 边界；先问「这段代码想干什么」
- **Phase 2 攻击面入口**：反序列化/表达式/模板/文件操作/网络请求/命令执行 sink
- **Phase 3 认证与授权边界**：权限检查在哪、能不能绕过、默认值安全吗
- **Phase 4 高价值链**：从 sink 反向回溯 source，找污点可达
- **Phase 5 PoC**：最小复现，本地跑通，不碰线上
- **Phase 6 报告**：按 `rules/report-format.md` 落 `报告/`

大型项目（Linux Kernel/Chromium/框架本身）优先 Phase 1+4：先吃透模块意图，
再追 sink 链；禁止无目标地全文通读。