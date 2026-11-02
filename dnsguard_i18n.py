#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsguard_i18n.py — 引擎层中英对照

设计：中文是唯一源语言，引擎照常生成中文，在输出边界（HTTP 响应）整棵
payload 过一遍词典翻成英文。这样 dnsguard.py 的检测逻辑一行都不用改，
出问题时把这个模块摘掉就回到纯中文。

两层匹配：
    EN    精确匹配，用于固定文案（标题、建议、标签）
    PATS  模板匹配，用于带变量的句子。中文模板里的 {} 是占位符，
          加载时自动转成正则捕获组，英文模板里的 {} 按顺序回填。

匹配不上的原样返回中文——宁可漏翻，不能乱翻。
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------- 精确匹配

EN: dict[str, str] = {
    # ---- 隐私结论标题
    "DNS 已加密：链路上看不到你查了什么域名":
        "DNS is encrypted: the path cannot see which domains you resolve",
    "DNS 是明文的：谁都能看到你访问的每个域名":
        "DNS is plaintext: anyone can see every domain you visit",
    "DNS 由本地代理接管：加不加密看代理配置":
        "DNS is intercepted by a local proxy; encryption depends on the proxy config",
    "加密 DNS 已配置，点「开始体检」验证是否真的生效":
        "Encrypted DNS is configured — click \u201cRun check\u201d to verify it actually works",
    "加密 DNS 已配置，且检测到 TLS 连接：大概率已生效":
        "Encrypted DNS is configured and a TLS connection was observed: likely active",
    "配了加密 DNS，但没看到加密连接：很可能仍走明文":
        "Encrypted DNS is configured but no encrypted connection was seen: likely still plaintext",
    "已配置加密 DNS，但还没有证据证明它真的生效":
        "Encrypted DNS is configured, but there is no evidence it is actually active",
    "系统可能已自动升级到加密 DNS，但未证实":
        "The system may have upgraded to encrypted DNS automatically, but this is unconfirmed",
    "没有可用的 DNS 配置，无法判断是否加密":
        "No usable DNS configuration found; cannot determine whether it is encrypted",
    "DNS 被本地软件接管，系统级 DoH 开关不影响实际解析":
        "DNS is intercepted by local software; the system DoH switch does not affect actual resolution",

    # ---- 摘要里的固定句
    "配置层已确认（DoH 模板与网卡开关都在），行为层要等完整体检才能下结论。":
        "Configuration is confirmed (DoH template and adapter switch both present); behaviour requires a full check.",
    "注册表里有 DoH 模板和开关，但行为层没测到加密特征，存在静默回落到明文 53 的可能。":
        "The registry has the DoH template and switch, but no encrypted behaviour was observed; it may still fall back to plaintext 53.",
    "未读到有效的网卡 DNS 配置，请检查网络连接后重试。":
        "No valid adapter DNS configuration was read. Check your network connection and retry.",

    # ---- 状态标签
    "已加密（行为已验证）": "Encrypted (verified)",
    "已加密（未证实）": "Encrypted (unproven)",
    "已配置加密（未证实）": "Encrypted configured (unproven)",
    "系统自动加密（未证实）": "Auto-encrypted (unproven)",
    "代理接管": "Proxy interception",
    "明文 DNS": "Plaintext DNS",
    "无法判定": "Indeterminate",

    # ---- 暴露 / 风险等级
    "私密": "Private",
    "基本可控": "Mostly controlled",
    "部分暴露": "Partially exposed",
    "高度暴露": "Highly exposed",
    "低风险": "Low risk",
    "需留意": "Needs attention",
    "中风险": "Medium risk",
    "高风险": "High risk",

    # ---- 评分构成
    "DNS 仍是明文": "DNS is still plaintext",
    "无法判断通道": "Channel cannot be determined",
    "代理接管，加密未知": "Proxy interception, encryption unknown",
    "没有浏览器级加密兜底": "No browser-level encryption fallback",
    "IPv6 DNS 仍为明文": "IPv6 DNS is still plaintext",
    "IPv6 DoH 的 443 不可达": "IPv6 DoH port 443 unreachable",

    # ---- 通道
    "系统解析（浏览器与所有应用默认走这条）":
        "System resolution (default path for browsers and all apps)",
    "IPv6 解析（Windows 会并行查询）": "IPv6 resolution (Windows queries both in parallel)",
    "由代理接管，加密与否取决于代理配置":
        "Intercepted by proxy; encryption depends on proxy config",
    "加密（HTTPS/DoH）": "Encrypted (HTTPS/DoH)",
    "已观测到加密连接": "Encrypted connection observed",
    "配置已开，但未观测到加密连接": "Configured, but no encrypted connection observed",
    "明文 UDP/53": "Plaintext UDP/53",
    "已配置 DoH（443 可达）": "DoH configured (443 reachable)",
    "已配置 DoH，但 443 不可达": "DoH configured, but 443 unreachable",
    "明文 UDP/53（IPv6，无 DoH 模板）": "Plaintext UDP/53 (IPv6, no DoH template)",
    "加密（仅对该浏览器有效）": "Encrypted (this browser only)",
    "域名（若代理上游仍是明文 UDP）": "Domains (if proxy upstream is still plaintext UDP)",
    "仅 DoH 服务商": "DoH provider only",
    "理论上仅 DoH 服务商": "Theoretically the DoH provider only",
    "链路上所有人": "Everyone on the path",
    "仅该 DoH 服务商": "That DoH provider only",

    # ---- 观察者
    "运营商 / 上游网络": "ISP / upstream network",
    "同一 Wi-Fi 下的其他设备": "Other devices on the same Wi-Fi",
    "本地代理软件": "Local proxy software",
    "DoH 服务商": "DoH provider",
    "运营商 / 路由器": "ISP / router",
    "访问的域名": "Domains visited",
    "查询时间": "Query times",
    "你的内网 IP": "Your LAN IP",
    "访问频率": "Access frequency",
    "可篡改返回结果": "Can tamper with responses",
    "连接目标": "Connection targets",
    "流量大小与时间": "Traffic volume and timing",
    "明文 UDP/53 直接经过网关，路由器固件、管理后台、蹭网者都能记录":
        "Plaintext UDP/53 passes through the gateway; router firmware, its admin panel, "
        "and anyone piggybacking the network can log it",
    "跨网明文传输，可被记录、限速、注入广告页或直接返回错误 IP":
        "Crosses the network in plaintext: can be logged, throttled, ad-injected, "
        "or answered with a wrong IP",
    "公共 Wi-Fi 下尤为明显，ARP 嗅探即可拿到你的全部查询":
        "Especially obvious on public Wi-Fi: ARP sniffing reveals every query",
    "代理接管后，域名先交给它，是否加密取决于它的上游配置":
        "The proxy receives each domain first; encryption depends on its upstream config",
    "加密后只有解析器知道你查了什么，这是加密 DNS 的信任代价":
        "Once encrypted, only the resolver knows what you query — the trust cost of encrypted DNS",
    "只能看到你在连哪个解析器，看不到具体域名":
        "Can see which resolver you contact, but not the domains",

    # ---- 泄露项标题
    "域名全量暴露": "Full domain exposure",
    "可被静默篡改": "Silent tampering possible",
    "时间与频率画像": "Timing and frequency profiling",
    "可被精准封锁": "Targeted blocking possible",
    "IPv6 旁路：IPv4 加密了，IPv6 还在明文":
        "IPv6 bypass: IPv4 is encrypted, IPv6 is not",
    "IPv6 DoH 模板在，但 443 连不上": "IPv6 DoH template exists but 443 is unreachable",
    "加密未证实，可能仍在明文回落": "Encryption unproven; may still fall back to plaintext",
    "你访问的每个域名都以明文出现，包括子域名和 API 端点（如 api.weixin.qq.com、passport.jd.com），"
    "观察者不需要解密就能拼出你在用什么服务、看什么内容。":
        "Every domain you visit appears in plaintext, including subdomains and API endpoints "
        "(e.g. api.weixin.qq.com, passport.jd.com). An observer can reconstruct which services "
        "you use and what you read without decrypting anything.",
    "中间人可以返回任意 IP，把页面导向广告页或钓鱼站；HTTPS 证书告警往往是唯一的提示。":
        "A man-in-the-middle can return any IP and steer you to an ad page or phishing site; "
        "an HTTPS certificate warning is often the only hint.",
    "查询时间和频率能推断作息、通勤、是否在家，比内容本身更容易被用于画像。":
        "Query timing and frequency reveal your routine, commute and whether you are home — "
        "easier to profile than content itself.",
    "只对特定域名丢包或返回 NXDOMAIN，其他域名照常——本报告第 3 节能直接测出这种选择性拦截。":
        "Drops packets or returns NXDOMAIN for specific domains only, while others resolve "
        "normally — section 3 of this report detects exactly this kind of selective blocking.",
    "Windows 只有在「服务器 IP 已注册模板 + 网卡开关打开 + 443 可达」三者同时成立时才走加密，"
    "任一环失败都会静默回落到明文 53，配置存在不等于生效。":
        "Windows only uses encryption when all three hold: the server IP has a registered "
        "template, the adapter switch is on, and 443 is reachable. Any failure silently falls "
        "back to plaintext 53 — being configured is not the same as being active.",

    # ---- 建议
    "开启加密 DNS：设置 → 网络和 Internet → 以太网/WLAN → DNS 服务器分配 → 加密（DoH），"
    "或直接用下面的「一键开启」":
        "Enable encrypted DNS: Settings → Network & Internet → Ethernet/WLAN → DNS server "
        "assignment → Encryption (DoH), or use the one-click option below",
    "只给浏览器开 DoH 不够：系统里其他应用（更新程序、客户端）仍在明文查询":
        "Browser-only DoH is not enough: other apps (updaters, clients) still query in plaintext",
    "在代理软件里把 nameserver 改成 https:// 或 tls:// 形式，系统 DNS 设置不参与":
        "In your proxy software, change nameserver to an https:// or tls:// form; "
        "system DNS settings do not apply",
    "先在「设置 → 网络和 Internet → 属性 → DNS 服务器分配」里确认加密显示为已开启，"
    "再重启 DNS 客户端服务（net stop dnscache & net start dnscache）后复查":
        "First confirm encryption shows as on in Settings → Network & Internet → Properties → "
        "DNS server assignment, then restart the DNS client service "
        "(net stop dnscache & net start dnscache) and check again",
    "换用不转发 ECS 的解析器（Cloudflare 1.1.1.1 / Quad9 9.9.9.9）可减少网段泄露":
        "Switch to a resolver that does not forward ECS (Cloudflare 1.1.1.1 / Quad9 9.9.9.9) "
        "to reduce subnet leakage",
    "IPv6 的 DNS 也要一起加密：把网卡 IPv6 DNS 改成支持 DoH 的地址"
    "（阿里 2400:3200::1 / 腾讯 2402:4e00::），或直接清空 IPv6 DNS，让解析回落到已加密的 IPv4":
        "Encrypt IPv6 DNS too: set the adapter IPv6 DNS to a DoH-capable address "
        "(Alibaba 2400:3200::1 / Tencent 2402:4e00::), or clear IPv6 DNS entirely so resolution "
        "falls back to the encrypted IPv4 path",
    "当前解析通道已加密，保持即可；每月复查一次确认没有回落到明文":
        "The current path is encrypted — leave it as is, and re-check monthly to confirm "
        "it has not fallen back to plaintext",
    "开启 DoH 后重新体检，确认第 4 节变成「已验证通过」":
        "Re-run the check after enabling DoH to confirm section 4 shows \u201cverified\u201d",
    "代理接管时应在代理软件里配置 nameserver，而不是改 Windows 设置":
        "With a proxy in place, configure nameserver in the proxy software rather than in Windows",
    "出现非公网地址解析，优先排查路由器 DNS 与 hosts，其次联系运营商":
        "Non-public addresses were resolved — check the router DNS and hosts file first, "
        "then contact your ISP",
    "未发现明确劫持特征，建议每月跑一次体检":
        "No clear hijack signature found; running this check monthly is recommended",

    # ---- DoH 状态
    "DoH 已配置且行为层验证通过": "DoH configured and verified behaviourally",
    "DoH 已配置，但行为层无法证明（明文与加密结果相同，属正常）":
        "DoH configured, but behaviour cannot prove it (plaintext and encrypted results match — normal)",
    "DoH 已配置，明文 DNS 不可达 -> 实际只能走加密通道":
        "DoH configured and plaintext DNS unreachable — only the encrypted path works",
    "系统未配置 DoH，但行为显示解析走的是加密通道":
        "No DoH configured, but behaviour shows resolution uses an encrypted path",
    "未检测到 DoH 生效迹象，DNS 仍为明文":
        "No sign of DoH being active; DNS is still plaintext",
    "这类地址由代理/DNS 转发软件提供，是否加密取决于该软件自身的配置":
        "This address is provided by proxy/DNS forwarding software; encryption depends on its config",
    "验证方法：在该软件的配置里看 nameserver/upstream 是否写成 https:// 或 tls://":
        "How to verify: check whether nameserver/upstream in that software is written as "
        "https:// or tls://",
    "建议：把 DNS 指向只允许 DoH 的地址后再测，观察 443 是否可达而 53 不可达":
        "Suggestion: point DNS at a DoH-only address and re-test, checking that 443 is "
        "reachable while 53 is not",
    "明文 DNS（UDP 53）可被链路中间人直接查看和篡改":
        "Plaintext DNS (UDP 53) can be read and tampered with by anyone on the path",
    "开启：python dnsguard.py doh on --url <你的DoH地址> --ip <该服务IP>":
        "Enable: python dnsguard.py doh on --url <your DoH URL> --ip <that service IP>",

    # ---- 判定原因
    "代理 fake-ip，不能据此判断劫持":
        "Proxy fake-ip — this alone cannot prove hijacking",
    "本地 DNS 对该域名无响应（超时），而公共明文 DNS 正常 -> 针对性拦截/故障":
        "Local DNS did not respond (timeout) while public plaintext DNS worked — "
        "targeted blocking or a local fault",
    "本地明文 DNS 返回 NXDOMAIN，而其他通道有正常解析结果":
        "Local plaintext DNS returned NXDOMAIN while other paths resolved normally",
    "系统解析失败（DNS 不可达或被重置）":
        "System resolution failed (DNS unreachable or reset)",
    "系统结果与加密基准一致、与明文不同 -> 加密解析已生效":
        "System result matches the encrypted baseline and differs from plaintext — encryption is active",
    "与加密基准一致": "Matches the encrypted baseline",
    "解析经本地代理转发，与直连基准的差异通常来自出口线路/CDN 调度，不能据此判定劫持":
        "Resolved through a local proxy; differences from the direct baseline usually come "
        "from the egress route or CDN steering, not hijacking",
    "系统与明文一致，但各加密基准自己也不一致 -> CDN 就近调度，不是篡改":
        "System matches plaintext, but the encrypted baselines disagree with each other — "
        "CDN steering, not tampering",
    "系统与明文结果一致，但与加密基准不同。常见于运营商透明 DNS 或 CDN 就近调度；"
    "若返回的是公网地址、域名也能正常打开，多数属于后者":
        "System matches plaintext but differs from the encrypted baseline. Common with ISP "
        "transparent DNS or CDN steering; if the address is public and the site loads, "
        "it is usually the latter",
    "明文 DNS 不可达但系统仍能解析 -> 只能是通过加密通道解析":
        "Plaintext DNS unreachable yet the system still resolves — must be the encrypted path",
    "与加密基准不同（可能是 CDN 就近调度，需人工判断）":
        "Differs from the encrypted baseline (possibly CDN steering; needs manual judgement)",
    "缺少加密基准，无法交叉验证":
        "No encrypted baseline available; cannot cross-validate",

    # ---- 解析器
    "dnssec-failed.org 仍返回 A 记录：解析器不验 DNSSEC，伪造应答发现不了":
        "dnssec-failed.org still returns an A record: the resolver does not validate DNSSEC, "
        "so forged answers go undetected",
    "TLS 握手失败": "TLS handshake failed",
    "不可用": "Unavailable",
    "本地代理 DNS": "Local proxy DNS",
    "当前解析器不验证 DNSSEC，换 Cloudflare(1.1.1.1) 或 Quad9(9.9.9.9) 可让伪造应答被直接丢弃":
        "The current resolver does not validate DNSSEC; switching to Cloudflare (1.1.1.1) or "
        "Quad9 (9.9.9.9) makes forged answers get dropped",

    # ---- 进度标签
    "判定 DoH 状态": "Determining DoH status",
    "分析隐私暴露面": "Analysing privacy exposure",
    "测量各解析器": "Measuring resolvers",
    "生成报告": "Generating report",

    # ---- 其他
    "真正是否加密取决于代理的上游（nameserver 写成 https:// 或 tls:// 才是加密）":
        "Whether traffic is really encrypted depends on the proxy upstream "
        "(only an https:// or tls:// nameserver is encrypted)",
    "配置层：未发现网卡级 DoH 模板": "Config layer: no adapter-level DoH template found",
    "IPv6 DNS：未配置，不会走 IPv6 明文通道":
        "IPv6 DNS: not configured, so no IPv6 plaintext path",
    "系统版本低于 Windows 10 21H2（build 19044），系统级 DoH 不被支持，注册表写了也不会生效":
        "The OS is older than Windows 10 21H2 (build 19044); system-level DoH is unsupported "
        "and registry settings will have no effect",
    "（已开启）": " (on)",
    "（未开启）": " (off)",
    "开": "on",
    "关/未设置": "off/unset",
    "已注册 DoH 模板": "DoH template registered",
    "已注册 DoH 模板，443 可达": "DoH template registered, 443 reachable",
    "已注册 DoH 模板，但 443 不可达": "DoH template registered, but 443 unreachable",
    "，443 可达": ", 443 reachable",
    "，但 443 不可达": ", but 443 unreachable",
    "未注册 DoH 模板，只能走明文 UDP/53": "No DoH template; plaintext UDP/53 only",
    "系统自动 DoH": "System auto DoH",
}

# ---------------------------------------------------------------- 模板匹配

_PATS_RAW: list[tuple[str, str]] = [
    # ---- 隐私摘要
    ("系统解析走 {} 的加密通道（443/TLS），明文 53 已不是实际解析路径。",
     "System resolution uses the encrypted channel of {} (443/TLS); plaintext 53 is no longer the actual path."),
    ("系统 DNS 为 {}（{}），明文 53 端口可直连，查询会以未加密形式经过 {} 和运营商。",
     "System DNS is {} ({}); plaintext port 53 is directly reachable, so queries travel "
     "unencrypted through {} and the ISP."),
    ("解析指向 {}，查询在本机内完成、不出网卡，路由器和运营商看不到；"
     "但是否真正加密取决于代理软件的上游配置。",
     "Resolution points to {}; queries complete on this machine and never leave the NIC, so the "
     "router and ISP cannot see them — but whether it is really encrypted depends on the proxy's upstream config."),
    ("注册表里有 DoH 模板，并且存在到 {}:443 的活动连接，这是 DoH 生效时的典型特征。",
     "The registry has a DoH template and there is an active connection to {}:443 — the typical "
     "signature of DoH being active."),
    ("模板和开关都写进了注册表，可是没检测到 {}:443 的加密连接，而明文 53 仍然通——"
     "Windows 正在静默回落到明文。",
     "Both template and switch are in the registry, but no encrypted connection to {}:443 was "
     "detected while plaintext 53 still works — Windows is silently falling back to plaintext."),
    ("Windows 自动 DoH 已开启，且 {} 是已知支持 DoH 的解析器，实际通道需行为验证。",
     "Windows auto DoH is on and {} is a known DoH-capable resolver; the actual path still "
     "needs behavioural verification."),

    # ---- 证据
    ("解析器是 {}（{}），由本机软件提供，查询不出网卡",
     "The resolver is {} ({}), provided by local software; queries never leave the NIC"),
    ("明文 53 仍可直连 {}，但系统实际没走这条路——所以「端口通不通」不能用来判断加密是否生效",
     "Plaintext 53 is still reachable at {}, but the system does not use it — so port "
     "reachability cannot tell you whether encryption is active"),
    ("明文 53 可达：{} 对 UDP/53 有响应，说明明文通道仍然通",
     "Plaintext 53 reachable: {} responds to UDP/53, so the plaintext path still works"),
    ("明文 53 不可达：{} 不响应 UDP/53，只能走加密通道",
     "Plaintext 53 unreachable: {} does not respond to UDP/53, so only the encrypted path works"),
    ("检测到 {} 条到 {}:443 的 TCP 连接（{}），是 DoH 走加密通道的直接特征",
     "{} TCP connection(s) to {}:443 detected ({}), a direct signature of DoH over TLS"),
    ("未检测到任何到 {}:443 的 TCP 连接，DoH 大概率没被启用",
     "No TCP connection to {}:443 detected; DoH is most likely not enabled"),
    ("{}:443 可达，具备开启 DoH 的网络条件",
     "{}:443 is reachable, so the network conditions for DoH are met"),
    ("{}:443 不可达，即使配置了 DoH 也会回落明文",
     "{}:443 is unreachable, so even a configured DoH would fall back to plaintext"),
    ("配置层：{} 个网卡写有 DoH 模板 {}", "Config layer: {} adapter(s) carry DoH template {}"),
    ("IPv6 DNS {}：{}", "IPv6 DNS {}: {}"),
    ("IPv6 DNS：{}（内网/本地地址，不出网卡）",
     "IPv6 DNS: {} (private/local address, never leaves the NIC)"),
    ("{}：DNS={}，DoH 开关={}（DohFlags={}）", "{}: DNS={}, DoH switch={} (DohFlags={})"),
    ("{}：DNS={}，DoH 开关={}", "{}: DNS={}, DoH switch={}"),
    ("（DohFlags={}）", " (DohFlags={})"),
    ("系统：Windows {} build {}", "System: Windows {} build {}"),
    ("配置层：系统自动 DoH（EnableAutoDoh）={}", "Config layer: system auto DoH (EnableAutoDoh)={}"),
    ("{}：DoH={}", "{}: DoH={}"),
    ("（{}）", " ({})"),
    ("行为层：{}", "Behaviour layer: {}"),

    # ---- 建议
    ("{}:443 被阻断，考虑换一个 443 可达的 DoH 服务商",
     "{}:443 is blocked; consider a DoH provider whose 443 is reachable"),
    ("{} 在本地 DNS 上被静默丢弃：换用加密 DNS 后可绕过该拦截",
     "{} is silently dropped by local DNS; switching to encrypted DNS bypasses this blocking"),
    ("实测 {}（{}）延迟最低且支持 DoH，可考虑换用",
     "{} ({}) measured the lowest latency and supports DoH — worth switching to"),
    ("{} 个域名被解析器明确标记为拦截（EDE），属主动过滤而非网络故障",
     "{} domain(s) were explicitly flagged as blocked by the resolver (EDE) — active filtering, "
     "not a network fault"),

    # ---- 通道路径
    ("本机 → 本地代理 127.0.0.1:{} → 上游", "Host → local proxy 127.0.0.1:{} → upstream"),
    ("本机 ⇄ {}:443 (TLS) → {}", "Host ⇄ {}:443 (TLS) → {}"),
    ("本机 → {}:443 (TLS, {})", "Host → {}:443 (TLS, {})"),
    ("本机 → {} → 运营商 → {}:53", "Host → {} → ISP → {}:53"),
    ("本机 ⇄ [{}]:443 (TLS) → {}", "Host ⇄ [{}]:443 (TLS) → {}"),
    ("本机 → {} → [{}]:53 (IPv6)", "Host → {} → [{}]:53 (IPv6)"),
    ("{} 自带 DoH", "{} built-in DoH"),

    # ---- 观察者
    ("路由器 / 网关 {}", "Router / gateway {}"),
    ("目标 IP {}:443", "Target IP {}:443"),

    # ---- 泄露项
    ("网段泄露（ECS /{}）", "Subnet leak (ECS /{})"),
    ("当前解析器会把你的大致网段转发给权威服务器，{}。",
     "The current resolver forwards your approximate subnet to authoritative servers, {}."),
    ("网卡上的 IPv6 DNS 是 {}，没有注册 DoH 模板，Windows 只能对它用明文 UDP/53。"
     "支持 IPv6 的应用会同时走这条通道，域名照样以明文送到路由器/运营商——"
     "加密 DNS 只覆盖了 IPv4，等于漏了一半。",
     "The adapter's IPv6 DNS is {}, with no DoH template registered, so Windows can only use "
     "plaintext UDP/53 for it. IPv6-capable apps take this path in parallel, sending domains in "
     "plaintext to the router and ISP — encrypted DNS covers only IPv4, leaving half the traffic exposed."),
    ("{} 的 443 端口不可达，Windows 会静默回落到明文 53。换个 IPv6 地址或修好 IPv6 出口。",
     "Port 443 is unreachable at {}, so Windows silently falls back to plaintext 53. "
     "Use a different IPv6 address or fix the IPv6 egress."),

    # ---- 评分构成
    ("上游泄露网段 ECS /{}", "Upstream subnet leak ECS /{}"),

    # ---- 判定
    ("解析到非公网地址 {}，典型劫持/广告注入特征",
     "Resolved to non-public address {} — typical of hijacking or ad injection"),
    ("解析器自己说：{} -> 主动拦截，不是网络故障",
     "The resolver itself reports: {} — active blocking, not a network fault"),
    ("探针返回 rcode={}，无法判定", "Probe returned rcode={}; indeterminate"),

    # ---- DoH 状态
    ("当前生效 DNS：{}", "Effective DNS: {}"),
    ("模板：{}", "Template: {}"),
    ("明文 DNS {} 仍可直连且结果与加密一致，无法从结果区分通道",
     "Plaintext DNS {} is still reachable and its results match the encrypted path, so the "
     "channel cannot be told apart from results alone"),
    ("存在残留配置 {}，建议先清理", "Leftover configuration {} found; clean it up first"),

    # ---- 解析器
    ("可用 {}ms", "{}ms"),
    ("已配置 DoH: {}  (DohFlags={})", "DoH configured: {}  (DohFlags={})"),
    ("自定义{}", "Custom {}"),
    ("完成 {}", "Done {}"),
    ("未知网卡({})", "Unknown adapter({})"),
    ("解析器没有使用客户端子网（scope /{} 只表示答案适用范围），不泄露网段",
     "The resolver does not use client subnets (scope /{} only marks answer applicability); "
     "no subnet is leaked"),
    ("解析器把你的 /{} 网段转发给了权威服务器（scope /{}），上游能看到你大概在哪个片区",
     "The resolver forwards your /{} subnet to authoritative servers (scope /{}), so upstream "
     "can tell roughly which region you are in"),
]


def _build(zh: str, en: str) -> tuple[re.Pattern[str], list[str]]:
    """中文模板里的 {} 转捕获组，英文模板按 {} 切成段，回填时逐段拼接"""
    zh_segs = zh.split("{}")
    rx = re.compile("(.+?)".join(re.escape(s) for s in zh_segs), re.S)
    return rx, en.split("{}")


PATS = [_build(zh, en) for zh, en in _PATS_RAW]


# ---------------------------------------------------------------- 对外接口

def tr(text: str, _depth: int = 0) -> str:
    """单条翻译：先精确匹配，再模板匹配，都不中则原样返回。

    模板捕获到的值也会递归翻一遍——否则 provider 之类的子字段会以中文
    形式嵌进英文句子里。
    """
    if not text:
        return text
    hit = EN.get(text)
    if hit is not None:
        return hit
    if _depth > 3:
        return text
    for rx, segs in PATS:
        m = rx.fullmatch(text)
        if not m:
            continue
        groups = m.groups()
        if len(segs) != len(groups) + 1:      # 模板占位符数量对不上，放弃
            continue
        vals = [tr(g, _depth + 1) for g in groups]
        out = segs[0]
        for i, v in enumerate(vals):
            out += v + segs[i + 1]
        return out
    return text


def tr_deep(obj: Any) -> Any:
    """递归翻译 dict / list / str，其余类型原样返回"""
    if isinstance(obj, str):
        return tr(obj)
    if isinstance(obj, dict):
        return {k: tr_deep(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [tr_deep(v) for v in obj]
    return obj


def coverage(sample: Any) -> dict:
    """调试用：统计一份 payload 里还有多少中文没翻"""
    zh = re.compile(r"[\u4e00-\u9fa5]")
    miss: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, str):
            if zh.search(o) and tr(o) == o:
                miss.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)

    walk(sample)
    return {"miss": sorted(set(miss))}


if __name__ == "__main__":
    import json
    import sys

    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        miss = coverage(data)["miss"]
        print(f"{path}: 未覆盖 {len(miss)} 条")
        for m in miss:
            print("  ·", m[:110])
