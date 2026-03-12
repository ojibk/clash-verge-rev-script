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

function main(config) {

    // ==================== █ 配置区（按需调整） █ ====================

    const SKIP_SCRIPT         = false;           // false = 启用脚本 / true = 禁用脚本，直接返回原配置
    const ENABLE_BLOCK        = true;            // 激活/遥测/广告拦截模块（最高优先级）
    const ENABLE_PROXY        = true;            // 指定域名走代理模块
    const ENABLE_DIRECT       = true;            // 指定域名直连模块
    const ENABLE_PROCESS_RULE = true;            // 进程规则模块（需特殊权限，不可靠）
    const ENABLE_AGGRESSIVE   = false;           // 激进阻断模块（⚠️ 慎用，可能影响官网）
    const ENABLE_HOSTS_TRICK  = true;            // Hosts 黑洞欺骗模块

    // Hosts 模式：ipv4-loopback(127.0.0.1) / ipv4-blackhole(0.0.0.0) /
    //            dual-stack(127.0.0.1+::1)  / blackhole(0.0.0.0+::)
    // ⚠️ blackhole = IPv4+IPv6 双栈彻底断网，被劫持域名的软件会立即收到 ENETUNREACH（Linux/Android）
    //    或 WSAEADDRNOTAVAIL（Windows），连 TCP SYN 都不会发出，软件立即感知失败。
    //    如软件出现启动崩溃/功能异常，改为 ipv4-loopback（127.0.0.1）——
    //    本地无监听端口时返回 ECONNREFUSED，属欺骗式假响应，更温和。
    const HOSTS_MODE = "blackhole";

    // ==================== █ 防御性检查 █ ====================

    if (!config) return config;
    if (!Array.isArray(config.rules))           config.rules = [];
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];

    // ==================== █ SKIP_SCRIPT 分支 █ ====================
    // 先清理上次遗留标记，再插入新标记，防止多次切换后堆叠
    if (SKIP_SCRIPT) {
        config.rules = config.rules.filter(r => !String(r).includes("debug-script-disabled"));
        config.rules.unshift("DOMAIN,debug-script-disabled.marker.local,DIRECT");
        return config;
    }

    console.log("=".repeat(60));
    console.log("📊 脚本引擎启动（生产级终极优化版）");
    console.log(`配置名称: ${config.metadata?.name || "未知"}  |  备注: ${config["m_name"] || "无"}`);
    console.log("=".repeat(60));

    // ==================== █ 1. 智能识别代理策略组 █ ====================
    //
    // 逻辑：多级 fallback，兼容大多数订阅格式。
    // 找不到时使用静态默认值，不中断后续注入。

    let proxyGroupName = "节点选择"; // 静态默认值，识别失败时的兜底

    // 危险组名（绝对不应作为出口策略组，指向它会造成规则回环）
    const DANGEROUS_NAMES = ["GLOBAL", "DIRECT", "REJECT", "COMPATIBLE"];
    const DANGEROUS_CN    = ["全局"]; // 中文单独处理，toUpperCase 对中文无效

    function isSafeGroup(name) {
        if (!name) return false;
        if (DANGEROUS_NAMES.includes(name.toUpperCase())) return false;
        if (DANGEROUS_CN.some(d => name.includes(d)))     return false;
        if (/^global$/i.test(name))                        return false; // 大小写不敏感精确匹配
        return true;
    }

    if (config["proxy-groups"].length > 0) {
        // 关键词列表（不含 "Global" 以免命中内置回环组；不含 "默认" 以免命中指向 DIRECT 的同名分组）
        const KEYWORDS = [
            "节点选择", "手动选择", "选节点", "节点", "选择",
            "Proxy", "PROXY", "AUTO", "自动",
            "🚀", "飞机", "机场", "线路", "订阅"
        ];

        // 优先：关键词 + 类型 + 多节点（最可靠）
        let mainGroup = config["proxy-groups"].find(g => {
            if (!isSafeGroup(g?.name)) return false;
            const typeOk     = ["select", "url-test", "fallback"].includes(g.type);
            const nameMatch  = KEYWORDS.some(kw => g.name.includes(kw));
            const hasMany    = Array.isArray(g.proxies) && g.proxies.length > 3;
            const includeAll = (g["include-all"] === true || g["include-all"] === "true");
            return typeOk && (nameMatch || includeAll || hasMany);
        });

        // 次选：正则匹配（排除危险组）
        if (!mainGroup) {
            mainGroup = config["proxy-groups"].find(g =>
                isSafeGroup(g?.name) &&
                /代理|节点|选择|Proxy/i.test(g.name) &&
                Array.isArray(g.proxies) && g.proxies.length > 3
            );
        }

        // 保底：任意合法 select / url-test / fallback 类型
        if (!mainGroup) {
            mainGroup = config["proxy-groups"].find(g =>
                isSafeGroup(g?.name) && ["select", "url-test", "fallback"].includes(g.type)
            );
        }

        // 终极兜底：取第一个安全组，跳过 DIRECT/REJECT 等危险组
        // ⚠️ 不能直接取 [0]，订阅第一个组可能是 DIRECT，导致代理规则全部失效
        if (!mainGroup) {
            mainGroup = config["proxy-groups"].find(g => isSafeGroup(g?.name));
        }

        if (mainGroup?.name) {
            proxyGroupName = mainGroup.name;
            console.log(`✅ 代理组识别成功: [${proxyGroupName}]`);
        } else {
            console.warn("⚠️ 未找到合适代理组，使用默认值 [节点选择]");
        }
    } else {
        console.warn("⚠️ 配置中没有 proxy-groups，使用默认代理组名");
    }

    // ⚠️ Mihomo 规则语法中策略组名直接使用原始名称，空格/emoji 均无需引号
    // 引号包裹反而会让内核把引号字符视为组名的一部分，导致 proxy not found 报错
    const safeProxyName = proxyGroupName;

    // ==================== █ 2. 双哨兵清理（防旧规则堆叠） █ ====================
    //
    // 哨兵必须是合法的 Clash 三段式规则（TYPE,VALUE,ACTION）。
    // ⚠️ 纯注释字符串（如 "# START"）会被内核视为非法规则，导致配置加载失败。
    //
    // 哨兵格式：
    //   起始：DOMAIN,START-script-sentinel-marker.local,DIRECT
    //   结束：DOMAIN,END-script-sentinel-marker.local,DIRECT

    const SENTINEL_START = "DOMAIN,START-script-sentinel-marker.local,DIRECT";
    const SENTINEL_END   = "DOMAIN,END-script-sentinel-marker.local,DIRECT";

    const startIdx = config.rules.findIndex(r => typeof r === "string" && r.startsWith("DOMAIN,START-script-sentinel-marker"));
    const endIdx   = config.rules.findIndex(r => typeof r === "string" && r.startsWith("DOMAIN,END-script-sentinel-marker"));

    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
        console.log("♻️ 检测到旧哨兵区间，正在精准清理...");
        config.rules.splice(startIdx, endIdx - startIdx + 1);
    } else if (startIdx !== -1 || endIdx !== -1) {
        // 哨兵只剩一半（用户误删），清理孤立标记防止残留
        console.warn("⚠️ 哨兵标记不配对，清理孤立标记...");
        config.rules.splice(startIdx !== -1 ? startIdx : endIdx, 1);
    }

    // ==================== █ 3. 数据层（在此维护域名，无需动逻辑） █ ====================
    //
    // 辅助函数：批量生成规则，减少重复代码
    const pushSuffix  = (domains, action, pool) => domains.forEach(d => pool.push(`DOMAIN-SUFFIX,${d},${action}`));
    const pushDomain  = (domains, action, pool) => domains.forEach(d => pool.push(`DOMAIN,${d},${action}`));
    const pushKeyword = (words,   action, pool) => words.forEach(k   => pool.push(`DOMAIN-KEYWORD,${k},${action}`));

    // ── Adobe 激活 / 遥测核心拦截 ──────────────────────────────────────────
    // 📌 关于 REJECT vs REJECT-DROP：
    //    REJECT 快速拒绝，软件立即"死心"进入离线模式，启动无卡顿，推荐用于遥测/授权域名
    //    REJECT-DROP 静默丢包（15-30s 超时），仅用于破解补丁后门（backdoorSuffix/backdoorKeyword）
    //    和进程级规则，增加溯源难度并防止补丁快速切换备用链路
    const adobeSuffix = [
        "adobestats.io",                          // 统计上报主域
        "activate.adobe.com",                     // 激活核心
        "lmlicenses.wip4.adobe.com",              // WIP License Manager
        "prod.adobegenuine.com",                  // Genuine Integrity Service
        "na1e.services.adobe.com",                // Genuine 服务备用
        "adobedtm.com",                           // 部分遥测 / Tag Manager
        "crs.cr.adobe.com",                       // License check
        "cclibraries-defaults-cdn.adobe.com",     // CC Libraries 默认资源
        "adobesearch.adobe.io",                   // 搜索遥测
        "ffc-static-cdn.oobesaas.adobe.com",      // OOBE 静态资源
        "scdown.adobe.io",                        // CC 静默更新 / 正版验证
        "lcs-roaming.adobe.io",                   // 授权漫游检查
        "ims-na1.adobelogin.com",                 // Adobe ID 登录心跳
        "adobeid-na1.services.adobe.com",         // Adobe ID 服务
        "auth.services.adobe.com",                // 身份验证服务
        "cc-api-cp.adobe.io",                     // CC API 控制面板
        "cc-api-data.adobe.io",                   // CC 存储元数据校验
        "p13n.adobe.io",                          // 个性化遥测
        "ic.adobe.io",                            // Insight Collector
        "lcs-cops.adobe.io",                      // 云端授权策略
        "lcs-mobile.adobe.io",                    // 新版 CC 移动端授权
        "adobe-dns.adobe.com",                    // Adobe DNS 服务
        "adobe-dns-2.adobe.com",                  // Adobe DNS 备用节点 2
        "adobe-dns-3.adobe.com",                  // Adobe DNS 备用节点 3
        "practivate.adobe.com",                   // 预激活服务
        "lm.licenses.adobe.com",                  // License Manager
        "genuine.adobe.com",                      // 正版验证
        "oobesaas.adobe.com",                     // OOBE 验证（禁止弹登录框）
        "sstats.adobe.com",                       // 实时统计上报（新版 CC 框架）
        "entitlementauthz.adobe.com",             // 授权鉴权服务（2025-2026 新增）
        "assets.entitlement.adobe.com",           // 授权资产校验（2025-2026 新增）
    ];
    // 正则：拦截随机子域（遥测特征：8-12 位随机字符）
    const adobeRegex = [
        "DOMAIN-REGEX,^[A-Za-z0-9]{10}\\.adobe\\.io$,REJECT-DROP",
        "DOMAIN-REGEX,^[A-Za-z0-9]{10}\\.adobestats\\.io$,REJECT-DROP",
        "DOMAIN-REGEX,^[a-z0-9]{8,12}\\.adobe\\.io$,REJECT-DROP",
    ];
    // QUIC / UDP 拦截：强制 Adobe 回退至 HTTPS (TCP)，再被上方域名规则捕获
    const adobeUdpBlock = [
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT-DROP",           // 阻断 adobe.io 所有 QUIC 流量，强制回退 TCP
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT-DROP",    // 阻断统计域 QUIC 流量
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT-DROP",         // 阻断 adobe.com 所有 QUIC 流量
        "AND,((NETWORK,UDP),(DOMAIN-REGEX,^[A-Za-z0-9]{10}\\.adobe\\.io$)),REJECT-DROP", // 阻断随机子域 QUIC（遥测特征）
        "AND,((DST-PORT,443),(NETWORK,UDP),(DOMAIN-KEYWORD,adobe)),REJECT-DROP", // 兜底：443/UDP + adobe 关键词，覆盖未列举子域
    ];
    // Adobe WebSocket 遥测（2025-2026 新增：通过 WSS 绕过普通 HTTP 拦截）
    const adobeWsDomain = [
        "wss.adobe.io",                           // WebSocket 遥测通道（新版 CC 框架）
    ];

    // ── CorelDRAW 全家桶激活拦截 ────────────────────────────────────────
    // ⚠️ 不拦截整个 corel.com，否则官网无法访问（见 directRules）
    const corelSuffix = [
        "activation.corel.com",                   // 激活验证入口
        "licensing.corel.com",                    // 许可证服务
        "license1.corel.com",                     // 许可证服务器 1
        "license2.corel.com",                     // 许可证服务器 2
        "mc.corel.com",                           // 会员验证
        "ipm.corel.com",                          // In-Product Messaging 弹窗服务
        "ipm2.corel.com",                         // IPM 备用节点
        "telemetry.corel.com",                    // 统计上报
        "world.corel.com",                        // 消息推送 + 序列号黑名单检查
    ];

    // ── Autodesk (CAD / 3dsMax / Maya) 激活与遥测拦截 ──────────────────
    const autodeskSuffix = [
        "adlm.cloud.autodesk.com",               // 许可验证主域（最重要）
        "adlm-autodesk.com",                     // ADLM 独立许可域
        "licensing-autodesk.com",                // 许可证服务备用域
        "api.entitlements.autodesk.com",         // 授权 API 接口
        "telemetry.autodesk.com",                // 遥测上报
        "api.telemetry.autodesk.com",            // 遥测 API
        "usage.autodesk.com",                    // 使用统计上报
        "metric.autodesk.com",                   // 性能指标上报
        "crashreport.autodesk.com",              // 崩溃报告上传
        "dlm.autodesk.com",                      // Download Manager 版本检查
        "adsklicensing.com",                     // Autodesk 许可服务独立域
        "clic.autodesk.com",                     // 核心授权验证
        "genuine-software.autodesk.com",         // 正版验证服务
        "edge.activity.autodesk.com",            // 活动/行为追踪
        "developer.api.autodesk.com",            // 开发者 API（含许可验证）
        "autodesk.com.edgekey.net",              // Akamai CDN 节点（授权验证回源）
        "crp.autodesk.com",                      // 云渲染授权
        "autodesk.flexnetoperations.com",         // FlexNet 许可服务
    ];
    const autodeskDomain = [
        "ipm-aem.autodesk.com",                  // 弹窗消息（精确匹配，防误伤子域）
    ];
    // DOMAIN-KEYWORD 杀伤力较强，仅针对 Autodesk 特有模块关键词
    const autodeskKeyword = [
        "adlm",                                  // Autodesk Desktop Licensing Module
        "telemetry.autodesk",                    // Autodesk 遥测模块关键词兜底
        "entitlement.autodesk",                  // Autodesk 授权模块关键词兜底
    ];

    // ── 第三方破解补丁后门（高危，强烈建议保留） ──────────────────────
    // 这些域名会回传设备信息，甚至下发新的拦截指令
    const backdoorSuffix = [
        "966v26.com",                            // 破解补丁后门主域（回传设备信息）
        "vposy.com",                             // 知名破解补丁作者域名（Adobe/Office）
        "api.pzz.cn",                            // 国内破解补丁回传接口
        "cc-cdn.com",                            // 伪装成 Adobe CDN
    ];
    const backdoorKeyword = ["966v26"];

    // ── IDM / Bandicam / Wondershare 等其他软件激活拦截 ────────────────
    const idmSuffix = [
        "registeridm.com",                       // IDM 注册验证域
        // "internetdownloadmanager.com", // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        "secure.internetdownloadmanager.com",   // 序列号验证接口
        "mirror.internetdownloadmanager.com",    // 更新镜像服务器
        "mirror2.internetdownloadmanager.com",   // 更新镜像服务器
        "mirror3.internetdownloadmanager.com",   // 更新镜像服务器
        "idm-patch.com",                         // IDM 非官方补丁域（安全风险）
        "idm-update.com",                        // IDM 非官方更新域（安全风险）
    ];
    const idmKeyword = ["tonec"];

    const wondershareSuffix = [
        "activation.wondershare.com",             // Wondershare 激活验证入口
        "license.wondershare.com",                // 许可证验证服务
        "wondershare.cc",                         // Wondershare 海外追踪/统计域
        "wondershare.cn",                         // Wondershare 国内遥测/统计域
        // "iskysoft.com",  // ⚠️ 已注释：主域即官网，无已知专用验证子域，
        //                  //   拦截主域将导致官网无法访问。如有抓包确认的验证子域，请替换为精确条目。
        // "imyfone.com",   // ⚠️ 已注释：同上，主域即官网，无已知专用验证子域。
    ];

    const miscSoftwareSuffix = [
        // "bandicam.com",    // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "bandisoft.com",   // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "xmind.app",       // ⚠️ 已注释：主域误伤官网（含正版用户同步/分享功能），改用下方精确子域
        // "xmind.net",       // ⚠️ 已注释：主域误伤官网（XMind 8 下载/插件），改用下方精确子域
        // "listary.com",     // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // ⚠️ typora.io 是官网主域，直接拦截会导致插件/主题无法下载
        // 精确拦截授权验证子域，放行主站：typora.io / store.typora.io
    ];
    const miscSoftwareDomain = [
        // ── Bandisoft 家族 ──────────────────────────────────────────────────
        "cert.bandicam.com",    // Bandicam 正版证书/激活验证核心
        "ssl.bandisoft.com",    // Bandizip/Bandicam 全家桶授权验证核心
        "dl.bandisoft.com",     // 更新下载/版本心跳（不影响离线使用；如需更新可临时放开）

        // ── XMind ──────────────────────────────────────────────────────────
        // 来源：多份抓包记录及 hosts 屏蔽教程（CSDN / 博客园 / 52pojie）
        // XMind 2020+（Electron）与 XMind 8（Java）均通过以下域名验证授权：
        "www.xmind.app",        // XMind 2020+ 授权验证主接口（Electron 版）
        "www.xmind.net",        // XMind 8 授权验证接口（Java 版）/ 国际更新检查
        "www.xmind.cn",         // XMind 中文站授权验证 / 国内更新检查
        "dl2.xmind.cn",         // XMind 8 更新安装包下载服务器（弹出更新提示的来源）
        // ⚠️ 注意：XMind 2020+ 的 api.xmind.net / api.xmind.app 等 API 子域名
        // 无公开抓包资料确认，未贸然添加。如将来有抓包证据请补充于此。

        // ── Listary ────────────────────────────────────────────────────────
        // 来源：Listary 官网 / support 子域为唯一已确认的联网端点
        // 其他子域名（api.listary.com 等）无公开资料，不添加以免误判
        "support.listary.com",  // 激活/授权验证接口（精确匹配，防误伤主站）

        // ── WinRAR (RARLAB) ────────────────────────────────────────────────
        // 来源：CVE-2021-35052 安全报告；Wireshark/Burp 抓包记录；rarlab.com 官网
        "notifier.rarlab.com",  // 广告弹窗 / 试用到期通知页面（主要骚扰来源）
                                // CVE-2021-35052：该域名曾被中间人攻击利用执行任意代码
                                // 屏蔽此域名同时消除安全风险 + 关闭广告弹窗

        // ── Typora ─────────────────────────────────────────────────────────
        "license.typora.io",    // Typora 授权验证接口
        "verify.typora.io",     // Typora 激活校验
    ];

    // ── 微软 & Office 遥测（不影响正常使用）────────────────────────────
    // 微软遥测改用 REJECT（快速了断，减少 CPU 重传）
    const msTelemSuffix = [
        "telemetry.microsoft.com",               // Windows/Office 遥测主域
        "v20.events.data.microsoft.com",         // Windows 诊断数据 v2.0
        "v10.events.data.microsoft.com",         // Windows 诊断数据 v1.0
        "nexus.officeapps.live.com",             // Office 遥测上报
        "officeclient.microsoft.com",            // Office 客户端统计
        "vortex.data.microsoft.com",             // Windows 错误报告
        "settings-win.data.microsoft.com",       // Windows 设置同步遥测
        "watson.telemetry.microsoft.com",        // Watson 崩溃报告服务
    ];

    // ── 国产广告联盟 / 遥测 ──────────────────────────────────────────────
    const cnAdSuffix = [
        // WPS
        "ups.k0s.gk.kingsoft.com",               // WPS 升级推送服务
        "pcfg.wps.cn",                           // WPS 配置/广告下发
        "wps.com.cn",                            // WPS 国内统计域
        "wpsgold.wpscdn.cn",                     // WPS 广告资源 CDN
        // "sync.wps.cn",                        // ⚠️ 已注释：WPS 云文档同步，拦截后云同步失效
        // 海康威视（仅精确子域，主域不拦截）
        // ⚠️ 若使用海康摄像头/NVR/DVR 设备，建议注释以下三条：
        //   upgrade.hikvision.com  拦截后设备无法检测固件更新
        //   ezdns.hikvision.com    拦截后 DDNS 功能失效，远程访问中断
        //   cloudmsg.hikvision.com 拦截后萤石云/APP 推送通知失效
        "upgrade.hikvision.com",                 // 海康固件升级检查（可触发静默下载）
        "ezdns.hikvision.com",                   // 海康 DDNS 回传（拦截后远程访问中断）
        "cloudmsg.hikvision.com",                // 海康云消息推送
        // 向日葵远程（仅遥测子域，oray.com 主域不可拦截）
        "sunloginlog.oray.com",                  // 向日葵日志上报
        "report.oray.com",                       // 向日葵行为上报
        // ToDesk 远程
        "log.todesk.com",                        // ToDesk 日志上报
        "report.todesk.com",                     // ToDesk 遥测上报
        // 百度输入法
        "shurufa.baidu.com",                     // 百度输入法云服务
        "input.baidu.com",                       // 百度输入法联网同步
        // 搜狗输入法（精确子域补充，主域 sogou.com 不拦截）
        // "api.sogoucloud.com",                 // ⚠️ 已注释：搜狗输入法云端接口，域名拼写无公开抓包资料确认，待验证后启用
        // 腾讯 Bugly 崩溃上报 SDK（大量国产软件集成，含设备指纹）
        "bugly.qq.com",                          // 腾讯 Bugly 崩溃上报 SDK
        // 字节跳动系（抖音/剪映/头条/西瓜共用）
        "log.snssdk.com",                        // 字节系客户端日志上报（头条/西瓜等）
        "i.snssdk.com",                          // 字节跳动国内 SDK 遥测
        "log.byteoversea.com",                   // 字节跳动海外日志上报（抖音/剪映共用）
        // 剪映专业版（CapCut）
        "metrics.capcut.com",                    // 剪映遥测上报
        "log.capcut.com",                        // 剪映日志收集
        // QQ音乐
        // "qqmusic.qq.com",                     // ⚠️ 待验证：命名无遥测特征前缀，可能是功能性主域，抓包确认前暂不拦截
        "stat.music.qq.com",                     // QQ音乐统计上报
        // 酷狗音乐
        "log.kugou.com",                         // 酷狗日志上报
        // 酷我音乐
        "stat.kuwo.cn",                          // 酷我统计上报
        // 网易云音乐桌面版
        "log.music.163.com",                     // 网易云音乐日志上报
        // 哔哩哔哩桌面客户端
        "data.bilibili.com",                     // B站数据上报
        "api.log.bilibili.com",                  // B站日志接口
        // 小米 / MIUI（手机系统域名，PC 端不会主动请求；若代理手机热点流量则生效）
        "stat.miui.com",                         // 小米统计 SDK
        "data.miui.com",                         // MIUI 数据采集
        "tracking.miui.com",                     // MIUI 行为追踪
        "logservice.miui.com",                   // MIUI 日志服务
        "sdkconfig.ad.xiaomi.com",               // 小米广告 SDK 配置下发
        // 钉钉
        "analytics.dingtalk.com",                // 钉钉遥测上报
        // 飞书
        "log.feishu.cn",                         // 飞书日志上报
        // 迅雷
        "ad.xunlei.com",                         // 迅雷广告接口
        "etl.xl7.xunlei.com",                    // 迅雷遥测上报
        // 百度网盘
        "update.pan.baidu.com",                  // 百度网盘强制更新推送
        // 腾讯广告
        "e.qq.com",                              // 腾讯效果广告
        "gdt.qq.com",                            // 广点通广告联盟
        "l.qq.com",                              // 腾讯广告追踪链路
        "toptips.qq.com",                        // QQ 弹窗提示推送
        "minibrowser.qq.com",                    // QQ 内置迷你浏览器广告
        // 阿里 / 友盟
        "umeng.com",                             // 友盟统计 SDK 主域
        "umengcloud.com",                        // 友盟云端统计
        "alimama.com",                           // 阿里妈妈广告联盟
        "adashbc.ut.alibaba.com",                // 阿里广告投放接口
        "update.aliyun.com",                     // 阿里云客户端强制更新
        // 百度广告
        "pos.baidu.com",                         // 百度联盟广告投放
        "hm.baidu.com",                          // 百度统计（Heatmap）
        "cpro.baidu.com",                        // 百度内容推荐广告
        // 字节 / 穿山甲
        "pangle.io",                             // 穿山甲广告联盟（字节）
        "pangolin-sdk-toutiao.com",              // 穿山甲 SDK 上报域
        "ad.toutiao.com",                        // 头条广告投放接口
        // 360（若需访问 360 官网，请改为 DIRECT）
        "360.cn",                                // 360 主遥测域（若需访问官网请改 DIRECT）
        "360safe.com",                           // 360 安全云端检测
        "360tp.com",                             // 360 推广/广告追踪
        "360kuai.com",                           // 360 快速通道广告
        "qhres.com",                             // 奇虎资源 CDN（广告素材）
        "qhstatic.com",                          // 奇虎静态资源（广告框架）
        "qhimg.com",                             // 奇虎图片 CDN（广告图片）
        "qhupdate.com",                          // 360 强制更新推送
        // 2345 全家桶
        "2345.com",                              // 2345 导航/弹窗主域
        "2345.net",                              // 2345 备用域
        "2345p.com",                             // 2345 推广域
        "2345uns.com",                           // 2345 升级推送
        "50yc.com",                              // 2345 旗下游戏推广
        // 驱动精灵等
        "160.com",                               // 驱动人生关联广告域
        "updrv.com",                             // 驱动人生更新推送
        "drivergenius.com",                      // 驱动精灵遥测/推广
        // 鲁大师（主域已注释，保留子域精确拦截：游戏盒跑分后的广告全家桶）
        // "ludashi.com",                            // ⚠️ 注释主域：避免误伤官网，使用子域精确拦截
        "lms.ludashi.com",                           // 鲁大师游戏盒跑分后的广告全家桶
        // 金山毒霸
        "cmcm.com",                              // 猎豹移动广告联盟
        "ijinshan.com",                          // 金山猎豹旗下追踪域
        "duba.com",                              // 金山毒霸广告/弹窗
        // 搜狗（精确子域见 cnAdDomain）
        "inte.sogou.com",                        // 搜狗整合服务遥测
        "theta.sogou.com",                       // 搜狗 A/B 测试上报
        "sogoucdn.com",                          // 搜狗 CDN（广告素材）
        "ie.sogou.com",                          // 搜狗 IE 插件推广
        "metasogou.com",                         // 搜狗元数据追踪
        // Flash（已停服）
        "flash.cn",                              // Adobe Flash 国内分发域（已停服，防止残留弹窗）
        // PotPlayer（主域已注释，保留子域精确拦截侧边栏广告）
        // "daum.net",                               // ⚠️ 注释主域：韩国最大门户，拦截影响搜索/新闻/邮件
        "kakaocorp.com",                             // 关联公司统计上报
        "p1-pc.daum.net",                            // 精准拦截侧边栏广告
        "p2-pc.daum.net",                        // PotPlayer 侧边栏广告节点 2
        "p1-pc.pdk.daum.net",                    // PotPlayer 广告 CDN 节点
    ];
    const cnAdDomain = [
        // 搜狗精确域名（避免误伤 sogou.com 整体）
        "pinyin.sogou.com",                      // 搜狗拼音输入法弹窗
        "news.sogou.com",                        // 搜狗新闻推送
        "toast.sogou.com",                       // 搜狗 Toast 弹窗通知
        "timer.sogou.com",                       // 搜狗定时任务上报
        "update.sogou.com",                      // 搜狗强制更新
        "config.sogou.com",                      // 搜狗远程配置下发
        "py.sogou.com",                          // 搜狗拼音云服务
        "snapshot.sogou.com",                    // 搜狗快照追踪
    ];

    // ── Mozilla / Firefox 遥测（REJECT 快速了断，减少浏览器重试） ────────
    const mozillaSuffix = [
        "telemetry.mozilla.org",                 // Firefox 遥测主域
        "incoming.telemetry.mozilla.org",        // 遥测数据接收端点
        "experiments.mozilla.org",               // Firefox 实验性功能遥测
        "healthreport.mozilla.org",              // Firefox 健康报告上报
        "metrics.mozilla.com",                   // 指标统计
        "detectportal.firefox.com",              // Firefox 网络连接检测（会产生无意义请求）
    ];

    // ── Google / Chrome 隐私追踪 ────────────────────────────────────────
    const googleTrackSuffix = [
        "google-analytics.com",                  // Google Analytics 统计主域
        "analytics.google.com",                  // Google Analytics API
        "googletagmanager.com",                  // Google Tag Manager 标签管理
        // ⚠️ gvt1.com 是 Google 的 CDN 主域，Chrome 扩展下载 / 字体 / 浏览器更新均走此域
        // 直接拦截 gvt1.com 会导致扩展商店异常、字体加载失败、Chrome 无法更新
        // 精确拦截已知遥测子域，放行其余 CDN 流量
        "redirector.gvt1.com",                   // Chrome 遥测重定向节点
        "optimizationguide-pa.googleapis.com",   // Chrome 优化提示遥测
    ];
    const googleTrackKeyword = ["safebrowsing.google"]; // SafeBrowsing API 隐私追踪

    // ── YouTube 遥测（不影响正常播放） ──────────────────────────────────
    // ⚠️ s.youtube.com 同时承载观看历史，如需保留历史记录请注释此行
    const youtubeSuffix  = ["youtube-ui.l.google.com"];  // YouTube UI 遥测域
    const youtubeDomain  = ["s.youtube.com"];               // 观看历史/遥测（⚠️ 同时承载观看历史）
    const youtubeKeyword = ["youtubei.googleapis"];         // YouTube 内部 API 遥测关键词

    // ── 通用广告联盟（REJECT 快速了断） ─────────────────────────────────
    const genericAdSuffix = [
        "doubleclick.net",                       // Google DoubleClick 广告网络
        "scorecardresearch.com",                 // comScore 受众测量
        "adnxs.com",                             // Xandr（AppNexus）程序化广告
        "criteo.com",                            // Criteo 个性化重定向广告（全球主流电商广告网络）
        "taboola.com",                           // Taboola 内容推荐广告（各大新闻站底部"猜你喜欢"）
        "outbrain.com",                          // Outbrain 内容推荐广告（同上，竞品）
        "amazon-adsystem.com",                   // 亚马逊广告系统
        "mc.yandex.ru",                          // Yandex Metrica 用户行为统计（大量中文站接入）
        "mc.yandex.com",                         // Yandex Metrica 备用域
    ];

    // ── 关键词兜底（⚠️ 已注释：杀伤力过强，2025-2026 年严重泛化） ──────
    // telemetry/analytics/stats/metrics 已出现在大量合法 CDN 和第三方服务域名中
    // 例：video-stats.video.google.com / metrics.cloudflare.com / cdn.telemetry-static.com
    // 如需启用，建议仅保留最精确的词并放到所有具体规则之后
    // const globalKeyword = ["telemetry", "analytics", "stats", "metrics"];

    // ── 进程级规则 ───────────────────────────────────────────────────────
    // ⚠️ Windows 需要管理员权限 + TUN/Service 模式，系统代理模式无效
    //    进程名必须与任务管理器「详细信息」完全一致，含大小写和 .exe
    const processBlockRules = [
        // ── 正版验证类：保留 REJECT-DROP（让软件超时等待，不快速切换备用链路）────
        "AND,((PROCESS-NAME,AdobeGCClient.exe),(DST-PORT,443),(NETWORK,UDP)),REJECT-DROP", // 精准阻断 QUIC（443/UDP），防止绕过 TCP 拦截
        "AND,((PROCESS-NAME,AdobeGCClient.exe),(NETWORK,UDP)),REJECT-DROP",               // 兜底阻断所有 UDP（含非443端口），双重保障
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",        // Adobe 正版验证（最重要）
        "PROCESS-NAME,AdskLicensingService.exe,REJECT-DROP", // Autodesk 许可验证
        "PROCESS-NAME,AdskAccess.exe,REJECT-DROP",           // Autodesk 访问控制服务
        "PROCESS-NAME,AdskIdentityManager.exe,REJECT-DROP",  // Autodesk 身份认证管理器
        // ── 国产流氓软件：改用 REJECT（快速拒绝，用户感知更好，不卡死软件）────────
        "PROCESS-NAME,360sd.exe,REJECT",                    // 360 杀毒主进程
        "PROCESS-NAME,360tray.exe,REJECT",                  // 360 系统托盘弹窗进程
        "PROCESS-NAME,2345Mini.exe,REJECT",                 // 2345 迷你窗口/弹窗进程
        "PROCESS-NAME,2345Helper.exe,REJECT",               // 2345 后台辅助进程
        "PROCESS-NAME,DTLocker.exe,REJECT",                  // 驱动人生锁屏弹窗
        "PROCESS-NAME,LDSGameBox.exe,REJECT",                // 鲁大师游戏盒
        "PROCESS-NAME,SogouNews.exe,REJECT",                 // 搜狗新闻弹窗
        "PROCESS-NAME,DriverGenius.exe,REJECT",              // 驱动精灵
        "PROCESS-NAME,Ludashi.exe,REJECT",                   // 鲁大师主程序
        // "PROCESS-NAME,Wps.exe,REJECT",                    // ⚠️ 慎用：WPS 主进程，拦截后全部联网功能失效（包括文档云同步）
    ];
    const processProxyRules = [
        // `PROCESS-NAME,天若OCR.exe,${safeProxyName}`, // 进程代理示例，按需取消注释
    ];
    const processDirectRules = [
        "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",              // 强制直连，提升下载速度
    ];

    // ── 代理规则 ─────────────────────────────────────────────────────────
    // ⚠️ Google 风控：Gemini 检测出口 IP 漂移，google.com 与 gemini.google.com 必须命中同一策略组，否则可能触发 403 或账号异常
    const proxySuffixList = [
        "copilot.microsoft.com",                 // Microsoft Copilot AI 助手
        "linkedin.com",                          // 领英职场社交网络
        // "openai.com",           // 按需取消注释
        // "gemini.google.com",    // 按需取消注释（注意 google.com 需同组）
        // ── Steam 分流：商店走代理，下载走直连 ────────────────────────
        // store / community / static 是国内受阻的前端域，走代理提升访问体验
        // steampowered.com 根域含 content1~9 下载 CDN 子域，保留直连保证下载速度
        "store.steampowered.com",                // Steam 商店页面
        "steamcommunity.com",                    // Steam 社区 / 创意工坊 / 市场
        "steamstatic.com",                       // Steam 商店静态资源（封面/截图）
    ];

    // ── 直连规则 ─────────────────────────────────────────────────────────
    const directRules = [
        // Microsoft 全家桶直连（防止更新/登录/OneDrive 卡死）
        // DOMAIN-SUFFIX,microsoft.com 已覆盖所有 *.microsoft.com 子域，
        // 无需额外的 DOMAIN-KEYWORD,microsoft（冗余且存在误判风险）
        "DOMAIN-KEYWORD,windowsupdate,DIRECT",             // Windows Update 关键词兜底（覆盖非标子域）
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",              // 微软主域（含所有 *.microsoft.com 子域）
        "DOMAIN-SUFFIX,live.com,DIRECT",                   // 微软账户 / Hotmail
        "DOMAIN-SUFFIX,outlook.com,DIRECT",                // Outlook 邮件服务
        "DOMAIN-SUFFIX,onedrive.com,DIRECT",               // OneDrive 云存储
        "DOMAIN-SUFFIX,skype.com,DIRECT",                  // Skype 通信服务
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",        // Microsoft 365 身份认证
        "DOMAIN-SUFFIX,microsoftonline-p.com,DIRECT",      // Microsoft 365 认证备用域
        "DOMAIN-SUFFIX,msftauth.com,DIRECT",               // 微软统一身份验证
        "DOMAIN-SUFFIX,msftidentity.com,DIRECT",           // 微软身份服务
        "DOMAIN-SUFFIX,passport.net,DIRECT",               // 微软 Passport 认证（旧版）
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",          // Windows Update 更新服务主域
        "DOMAIN-SUFFIX,microsoftpersonalcontent.com,DIRECT", // 微软个人内容 CDN
        "DOMAIN-SUFFIX,msocsp.com,DIRECT",                 // 微软证书吊销列表（OCSP）
        "DOMAIN-SUFFIX,msedge.net,DIRECT",                 // Microsoft Edge CDN / 更新
        // NCSI（拦截后 Windows 右下角显示「无网络」）
        "DOMAIN,msftconnecttest.com,DIRECT",               // NCSI 连通性探测（拦截后系统托盘显示「无网络」）
        "DOMAIN,www.msftconnecttest.com,DIRECT",           // NCSI 备用探测域
        "DOMAIN,msftncsi.com,DIRECT",                      // NCSI 旧版探测域
        // Adobe 常用业务放行（字体/图库/作品展示）
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",            // Adobe Fonts 字体同步服务
        "DOMAIN-SUFFIX,stock.adobe.com,DIRECT",            // Adobe Stock 图库
        "DOMAIN-SUFFIX,behance.net,DIRECT",                // Behance 设计作品展示平台
        "DOMAIN-SUFFIX,behance.adobe.com,DIRECT",          // Behance Adobe 子域
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",            // Adobe Color 配色工具
        "DOMAIN,assets.adobe.com,DIRECT",                  // Adobe 静态资源 CDN
        // 欺骗式绕过：只给补丁一条生路完成自检，
        // 核心统计域已被 blockRules 封锁，即便联通也无法回传有效数据
        "DOMAIN,api.966v26.com,DIRECT",                    // ⚠️ 死代码：backdoorSuffix 已先行 REJECT-DROP，此处 DIRECT 永远不会被命中
        "DOMAIN,status.966v26.com,DIRECT",                 // ⚠️ 死代码：同上，保留作为设计意图存根（欺骗式绕过的注释说明见上方）
        // 官网放行
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",               // Autodesk 官网放行（下载/账户/论坛）
        "DOMAIN-SUFFIX,corel.com,DIRECT",                  // ⚠️ 不要拦截整个 corel.com
        // 常用工具直连
        "DST-PORT,123,DIRECT",                    // NTP 时间同步，防止证书失效
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",  // Steam 根域直连（含 content1~9 下载CDN子域，保证满速）
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",  // Steam 游戏内容分发 CDN（满速下载）
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",   // Steam 联机对战后端
        "DOMAIN-SUFFIX,pixpinapp.com,DIRECT",     // 截图贴图工具
        "DOMAIN-SUFFIX,pixpin.cn,DIRECT",         // 截图贴图工具
        "DOMAIN-SUFFIX,lanzou.com,DIRECT",        // 蓝奏云主域
        "DOMAIN-SUFFIX,lanzoui.com,DIRECT",       // 蓝奏云备用域 1
        "DOMAIN-SUFFIX,lanzoux.com,DIRECT",       // 蓝奏云备用域 2
        "DOMAIN-SUFFIX,masuit.com,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,masuit.net,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,masuit.org,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,423down.com,DIRECT",       // 知名绿色软件站
        "DOMAIN-SUFFIX,ghxi.com,DIRECT",          // 果核剥壳（绿色软件站）
        "DOMAIN-SUFFIX,mpyit.com,DIRECT",         // 殁漂遥软件分享站
        "DOMAIN-SUFFIX,25xianbao.com,DIRECT",     // 卡圈线报
        "DOMAIN-SUFFIX,dir28.com,DIRECT",         // 羊毛活动
    ];

    // ── 激进阻断规则（默认关闭，开启前请仔细阅读注释） ────────────────
    const aggressiveRules = [
        // 拦截所有 adobe.io 子域（含字体/素材/插件市场，慎用）
        "DOMAIN-REGEX,.*\\.adobe\\.io$,REJECT-DROP",          // ⚠️ 激进：所有 adobe.io 子域（含字体/素材/插件市场）
        // 多平台共用域（Zapier/Notion/GitHub Actions 也在用，慎用）
        "DOMAIN-SUFFIX,workflowusercontent.com,REJECT-DROP", // ⚠️ 激进：多平台共用（Zapier/Notion/GitHub Actions）
        // adsk.com 旧版遥测（影响官网/插件商店，慎用）
        "DOMAIN-SUFFIX,adsk.com,REJECT-DROP",                // ⚠️ 激进：Autodesk 旧版遥测（影响官网/插件商店）
        // 影响 Office 更新/模板下载
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",          // ⚠️ 激进：Office CDN 关键词（影响 Office 更新/模板下载）
        // 区域识别，影响 CC 登录
        "DOMAIN,geo.adobe.com,REJECT-DROP",                  // ⚠️ 激进：地理区域识别（影响 CC 登录）
        "DOMAIN,geo2.adobe.com,REJECT-DROP",                 // ⚠️ 激进：地理区域识别备用
        // 拦截后无法登录 Autodesk 账户
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",  // ⚠️ 激进：拦截后无法登录 Autodesk 账户
        "DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP", // ⚠️ 激进：授权端点，同上
        // 所有 adobe.io 子域（影响字体/素材同步/插件市场）
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",               // ⚠️ 激进：所有 adobe.io（影响字体/素材同步/插件市场）
        // IE 遗留检测（拦截后影响 ActiveX/老 OA/Windows NCSI）
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP",        // ⚠️ 激进：IE 遗留检测（影响 ActiveX/老 OA/NCSI）
    ];

    // ==================== █ 4. 规则组装与注入 █ ====================

    try {
        const pool = [];

        if (ENABLE_BLOCK) {
            // Adobe（遥测/授权域改用 REJECT，软件立即进入离线模式，避免启动卡顿）
            pushSuffix(adobeSuffix, "REJECT", pool);
            pool.push(...adobeRegex);
            pool.push(...adobeUdpBlock);
            pushDomain(adobeWsDomain, "REJECT", pool);
            // Corel
            pushSuffix(corelSuffix, "REJECT", pool);
            // Autodesk
            pushSuffix(autodeskSuffix, "REJECT", pool);
            pushDomain(autodeskDomain, "REJECT", pool);
            pushKeyword(autodeskKeyword, "REJECT", pool);
            // 破解补丁后门（保留 REJECT-DROP：增加溯源难度，防补丁快速切换备用链路）
            pushSuffix(backdoorSuffix, "REJECT-DROP", pool);
            pushKeyword(backdoorKeyword, "REJECT-DROP", pool);
            // IDM / Wondershare / 杂项
            pushSuffix(idmSuffix, "REJECT", pool);
            pushKeyword(idmKeyword, "REJECT", pool);
            pushSuffix(wondershareSuffix, "REJECT", pool);
            pushSuffix(miscSoftwareSuffix, "REJECT", pool);
            pushDomain(miscSoftwareDomain, "REJECT", pool);
            // 微软遥测（REJECT 快速了断）
            pushSuffix(msTelemSuffix, "REJECT", pool);
            // 国产广告 / 遥测（REJECT 快速拒绝，广告类无需静默超时）
            pushSuffix(cnAdSuffix, "REJECT", pool);
            pushDomain(cnAdDomain, "REJECT", pool);
            // 浏览器遥测（REJECT 快速了断）
            pushSuffix(mozillaSuffix, "REJECT", pool);
            pushSuffix(googleTrackSuffix, "REJECT", pool);
            pushKeyword(googleTrackKeyword, "REJECT", pool);
            // YouTube 遥测
            pushSuffix(youtubeSuffix, "REJECT-DROP", pool);
            pushDomain(youtubeDomain, "REJECT-DROP", pool);
            pushKeyword(youtubeKeyword, "REJECT-DROP", pool);
            // 通用广告联盟
            pushSuffix(genericAdSuffix, "REJECT", pool);
            // 关键词兜底（已注释，globalKeyword 变量已注释禁用，见数据层说明）
            // pushKeyword(globalKeyword, "REJECT", pool);
        }

        if (ENABLE_PROCESS_RULE) {
            if (Array.isArray(processBlockRules) && processBlockRules.length > 0) pool.push(...processBlockRules);
            if (Array.isArray(processProxyRules) && processProxyRules.length > 0) pool.push(...processProxyRules);
            if (Array.isArray(processDirectRules) && processDirectRules.length > 0) pool.push(...processDirectRules);
        }

        if (ENABLE_PROXY) {
            // action 参数此处传入策略组名（非 DIRECT/REJECT），Mihomo 语法合法
            pushSuffix(proxySuffixList, safeProxyName, pool);
        }

        if (ENABLE_DIRECT) {
            pool.push(...directRules);
        }

        if (ENABLE_AGGRESSIVE) {
            pool.push(...aggressiveRules);
        }

        const finalPool = [SENTINEL_START, ...pool, SENTINEL_END];

        // 插入到规则列表最前面（最高优先级）
        config.rules.unshift(...finalPool);

        console.log("=".repeat(60));
        console.log("✅ 规则注入成功");
        console.log(`   拦截模块:   ${ENABLE_BLOCK         ? "✅" : "❌"}`);
        console.log(`   进程规则:   ${ENABLE_PROCESS_RULE  ? "✅ (不可靠)" : "❌"}`);
        console.log(`   代理规则:   ${ENABLE_PROXY         ? "✅" : "❌"}`);
        console.log(`   直连规则:   ${ENABLE_DIRECT        ? "✅" : "❌"}`);
        console.log(`   激进模式:   ${ENABLE_AGGRESSIVE    ? "⚠️ 已开启" : "❌"}`);
        console.log(`   注入规则数: ${finalPool.length} 条（含首尾哨兵）`);
        console.log(`   总规则数:   ${config.rules.length} 条`);
        console.log(`   代理组:     [${proxyGroupName}]`);
        console.log("=".repeat(60));

    } catch (err) {
        // 降级：注入失败时不修改规则，确保网络正常
        console.error("❌ 规则注入失败，已降级返回原配置:", err);
        return config;
    }

    // ==================== █ 5. Hosts 级 DNS 黑洞 █ ====================
    //
    // 【DNS 内部处理流（来源：wiki.metacubex.one/en/config/dns/diagram）】
    //
    //   DNS 解析阶段（按优先级）：
    //     1. Hosts 匹配  → 命中则立即返回映射地址，不再向下执行
    //     2. fake-ip-filter 判断 → 域名在列表中则走真实 DNS 查询
    //     3. Fake-IP 生成 → 不在列表则分配 198.18.x.x 虚拟 IP
    //     → 结论：hosts 优先级高于 fake-ip-filter
    //
    //   三条拦截路径：
    //
    //   路径 A（系统代理模式）
    //     app → Mihomo DNS → hosts → 返回黑洞地址 → app 连接立即失败
    //
    //   路径 B（TUN 模式，需满足前提：dns-hijack: any:53）
    //     app → TUN → DNS 劫持 → hosts → 返回黑洞地址 → app 连接立即失败
    //     ⚠️ 若 TUN 未配置 dns-hijack，app 可绕过 Mihomo DNS 直接查询
    //        外部 DNS，hosts 将不生效
    //
    //   路径 C（硬编码 IP，完全绕过 DNS）
    //     app → 直接发起 IP 连接 → 路由规则匹配
    //     → DOMAIN-SUFFIX / DOMAIN 规则不触发（无域名可匹配）
    //     → PROCESS-NAME / IP-CIDR / NETWORK 规则触发 → REJECT-DROP
    //     ⚠️ 这是 backdoorSuffix REJECT-DROP 作为纵深防御的意义所在
    //
    //   各 HOSTS_MODE 的连接失败类型：
    //     0.0.0.0 / :: → ENETUNREACH（Linux/Android）/ WSAEADDRNOTAVAIL（Windows）
    //                    OS 直接拒绝路由，TCP SYN 不会发出
    //     127.0.0.1 / ::1 → ECONNREFUSED（本地无监听端口时服务端返回 RST）
    //                       欺骗式假响应，软件以为"到达了服务器"
    //
    // 模式说明（与顶部 HOSTS_MODE 对应）：
    //   ipv4-loopback  → 127.0.0.1          欺骗性拦截（ECONNREFUSED），更温和
    //   ipv4-blackhole → 0.0.0.0            彻底断网（ENETUNREACH）
    //   dual-stack     → 127.0.0.1 + ::1    IPv4/IPv6 双栈欺骗
    //   blackhole      → 0.0.0.0 + ::       IPv4/IPv6 双栈断网（默认，最彻底）
    //
    // 【hosts 值格式（来源：wiki.metacubex.one/en/config/dns/hosts）】
    //   单 IP：字符串 "0.0.0.0"
    //   多 IP：数组   ["0.0.0.0", "::"]
    //   域名重定向：字符串（不支持数组）
    //   → 单元素数组 ["0.0.0.0"] 与字符串 "0.0.0.0" 语义相同，
    //     但部分版本 Mihomo 对单元素数组解析行为未明确，
    //     本脚本统一使用字符串（单 IP）或数组（多 IP）

    if (ENABLE_HOSTS_TRICK) {
        try {

            // modeMap 值格式：
            //   单 IP 模式 → 字符串（避免单元素数组的解析歧义）
            //   双栈模式   → 数组（Mihomo hosts 明确支持多 IP 数组）
            const modeMap = {
                "ipv4-loopback":  "127.0.0.1",
                "ipv4-blackhole": "0.0.0.0",
                "dual-stack":     ["127.0.0.1", "::1"],
                "blackhole":      ["0.0.0.0", "::"],
            };
            const target = modeMap[HOSTS_MODE];
            if (!target) throw new Error(`未知 HOSTS_MODE: ${HOSTS_MODE}`);

            // 劫持域名列表（仅针对高危补丁回传域名）
            // Mihomo hosts 通配符说明（来源：wiki.metacubex.one/en/config/dns/hosts）：
            //   +.domain → 匹配主域本身 + 所有多级子域，等效 DOMAIN-SUFFIX
            //   *.domain → 仅匹配单级子域，不含主域和多级子域
            //   .domain  → 匹配所有多级子域，不含主域本身
            // "+.966v26.com" 单条理论上覆盖所有情况，保留显式条目作为兼容保障
            const hijackDomains = [
                "+.966v26.com",           // 匹配主域 + 所有多级子域（Mihomo 原生 + 通配符）
                "966v26.com",             // 主域（显式精确匹配，兼容旧版内核）
                "*.966v26.com",           // 单级通配符
                "api.966v26.com",         // 接口域（显式保留，双重保障）
                "status.966v26.com",      // 状态域（显式保留，双重保障）
            ];

            const customHosts = {};
            hijackDomains.forEach(d => { customHosts[d] = target; });

            // 顶层 hosts + DNS 模块双重注入
            // ⚠️ config.dns 可能不存在（订阅无 dns 块时为 undefined），
            //    必须先确保 dns 对象存在再操作子字段
            config.hosts = { ...(config.hosts || {}), ...customHosts };
            if (typeof config.dns === "undefined" || config.dns === null) {
                config.dns = {};
            }
            // ⚠️ 重要限制：此处写入 use-hosts: true 会被 Clash Verge Rev UI 设置覆盖。
            //
            //    Clash Verge Rev 的配置生效顺序：
            //      订阅 yaml → 脚本注入 → UI 设置覆盖 → 写入 clash-verge.yaml → Mihomo 加载
            //
            //    脚本在"脚本注入"阶段写入 use-hosts: true，但随后"UI 设置覆盖"
            //    阶段会将"使用 Hosts"开关的值（默认 false）写入合并配置，
            //    将脚本注入的值覆盖。脚本无法绕过此 UI 层覆盖。
            //
            //    → 必须在 Clash Verge Rev 设置 → DNS 覆写 → 手动开启"使用 Hosts"，
            //      hosts 黑洞才能真正生效。
            //
            //    注意：同页面还有"使用系统 Hosts"开关，无需开启。
            //      "使用系统 Hosts" 对应 Windows 自带的
            //      C:\Windows\System32\drivers\etc\hosts 文件，
            //      与脚本注入的 Mihomo hosts 是两套完全独立的机制。
            config.dns["use-hosts"] = true;
            config.dns.hosts = { ...(config.dns.hosts || {}), ...customHosts };

            // TUN 模式补丁：加入 fake-ip-filter，防止内核为劫持域名分配 Fake-IP
            // 说明：hosts 在 DNS 解析阶段优先于 fake-ip-filter，严格来说此处
            // 可省略，但作为双重保险保留——当 hosts 因配置问题未命中时，
            // fake-ip-filter 可阻止内核分配 198.18.x.x 虚拟 IP，避免补丁
            // 误以为"已获得可用地址"而继续发起连接尝试。
            // 使用 Set 合并保证顺序稳定，避免每次 reload 因顺序变化触发 DNS hash 重建导致连接瞬断
            if (!Array.isArray(config.dns["fake-ip-filter"])) {
                config.dns["fake-ip-filter"] = [];
            }
            const fakeIpSet = new Set(config.dns["fake-ip-filter"]);
            hijackDomains.forEach(d => fakeIpSet.add(d));
            config.dns["fake-ip-filter"] = [...fakeIpSet];

            const targetStr = Array.isArray(target) ? target.join(" / ") : target;
            console.log(`🛡️ Hosts 劫持成功 [${HOSTS_MODE}] → ${targetStr}`);
            console.log(`   劫持域名数: ${hijackDomains.length} 条`);

        } catch (e) {
            console.error("❌ Hosts 劫持注入失败:", e);
        }
    }

    return config; // 返回修改后的最终配置

} // function main 结束
