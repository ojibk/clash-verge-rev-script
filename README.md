/**
 * Script.js 路径： C:\Users\Administrator\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles
 * ============================================================
 * Clash Verge Rev 规则注入脚本（生产级终极优化完美版 v260312）
 *
 * 功能：
 *   - 智能识别代理策略组（多级 fallback，排除危险组）
 *   - 注入拦截规则（Adobe / Corel / Autodesk 等激活/遥测）
 *   - 注入代理 / 直连规则
 *   - 进程级规则（需管理员权限 + TUN 模式）
 *   - 激进阻断模块（默认关闭，需谨慎开启）
 *   - Hosts 级 DNS 黑洞（欺骗补丁自检逻辑，可选模式）
 *   - 双哨兵精准清理旧规则（防堆叠）
 *   - 异常降级保护，详细运行日志
 *
 * 使用说明：
 *   1. 调整顶部的功能开关（true/false）
 *   2. 在对应数组中增删域名即可，无需动下方逻辑
 *   3. 保存后在 Clash Verge Rev 中重新加载配置文件
 *
 * 注意事项：
 *   - 进程规则（PROCESS-NAME）需要管理员权限 + TUN/Service 模式，
 *     系统代理模式下完全无效，建议仅作为辅助手段
 *   - 激进模式可能影响官网/云功能，请阅读注释后谨慎开启
 *   - no-resolve 仅对 IP 类规则（IP-CIDR/GEOIP）有意义，
 *     DOMAIN/* 类规则加 no-resolve 无效，本脚本已全部移除
 *   - REJECT-DROP 静默丢包，软件会等待超时（15-30s）后离线；
 *     如遇软件启动极慢，可将 REJECT-DROP 批量改为 REJECT
 *
 * 版本对比优化点（相对各前版）：
 *   [暂时移除] 规则去重改用 Set+filter 保序算法，防跨模块重复（[...new Set()] 仅现代引擎保序）
 *   [优化] SKIP_SCRIPT 分支先清理旧标记再插入，防止多次切换后堆叠
 *   [优化] HOSTS_MODE 提升至顶部开关区，统一配置入口
 *   [优化] 引入 pushSuffix/pushDomain/pushKeyword 辅助函数，规则组装更简洁
 *   [优化] 数据层按厂商/类别拆分为具名数组，维护成本大幅降低
 *   [优化] HOSTS 模式改用 modeMap 对象，替代 switch-case
 * ============================================================
 */
