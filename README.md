# DNS Guard · 需求与搭建说明

> 一个给"不会用 Wireshark 的人"用的 DNS 劫持体检工具
> 版本 v0.4.5 · 桌面客户端 · by parkerli · Windows 优先

---

## 1. 为什么做这个

### 1.1 真实痛点

普通用户遇到网络异常时，能拿到的诊断信息只有两种：

- **太浅**：「换个 DNS 试试」「清一下缓存」——不知道到底有没有问题
- **太深**：Wireshark 抓包，几百个包刷屏，看 `dns.qry.name`、`dns.flags.rcode`，还得会写过滤器

中间那段没人做：**给一个能直接看懂的结论，并且能验证"我改完到底生效没有"。**

### 1.2 具体场景（来自真实使用）

| 场景 | 用户困惑 | 工具应回答 |
|---|---|---|
| 开了 VPN 连不上，关了反而正常 | 是不是被运营商劫持了 | 哪些域名被篡改/丢弃，证据是什么 |
| 按教程设了 DoH | 设置完不知道成功没 | DoH 是否真的在生效，还是只是写了个注册表 |
| 装过 Clash 又关了 | 系统里还留着 198.18.0.2 | 这是残留配置还是仍在接管 |
| 网页偶尔跳广告页 | 是劫持还是网站自己弹的 | 解析结果是否被替换成非公网地址 |

### 1.3 设计原则

1. **结论优先**：先给「有没有问题」，再给证据，最后给操作
2. **可证伪**：每条结论必须能对应到具体的解析结果差异，不做玄学判断
3. **不改系统**：默认只读；任何写操作必须显式命令 + 备份 + 可回滚
4. **零依赖**：只用标准库，避免"装个工具先装 20 个包"

---

## 2. 需求清单

### P0 · 必须有

| 编号 | 需求 | 验收标准 |
|---|---|---|
| F1 | 读取当前系统 DNS 配置 | 列出所有网卡的 DNS、网关、配置来源（手动/DHCP） |
| F2 | 探测 DNS 服务器可用性 | 对每个配置的 DNS 发探针，标出无响应的残留配置 |
| F3 | 三层解析交叉验证 | 系统解析 / 本地明文 DNS / 多个 DoH 基准，逐域名比对 |
| F4 | 劫持特征识别 | 能区分：正常、加密生效、明文被篡改、NXDOMAIN 劫持、非公网地址、选择性丢包 |
| F5 | hosts 文件审计 | 列出非回环映射并提示确认 |
| F6 | 风险评分与结论 | 0–100 分 + 等级 + 逐条建议 |
| F7 | 一键开启 DoH（用户自填地址） | 备份 → 写配置 → 刷缓存 → **自动验证** → 报告结果 |
| F8 | 一键回滚 | 恢复到开启前的 DNS 与 DoH 状态 |
| F9 | 报告输出 | 终端可读 + JSON + HTML |

### P1 · 应该有

| 编号 | 需求 | 说明 |
|---|---|---|
| F10 | 代理接管识别 | 识别 fake-ip 网段、本地代理端口，避免把代理当劫持 |
| F11 | 公共明文 DNS 对照 | 区分「本地链路拦截」与「域名本身无解析」 |
| F12 | 指定网卡 | `--iface WLAN`，避免污染未连接网卡的配置 |
| F13 | 自定义 DoH 基准 | `--doh-baseline`，可加自己的解析器 |

### P2 · 可以后做

- 被动监听模式（scapy 抓 53 端口，做成"傻瓜版 Wireshark"）
- 路由器 DNS 检测（读 UPnP / 登录管理页）
- TLS 证书与解析 IP 一致性校验
- 常驻托盘 + 异常告警
- 图形界面

---

## 3. 检测原理

### 3.1 为什么不用抓包也能判断

DNS 劫持的本质是**"你问 A，它答 B"**。抓包看到的是"问了什么、答了什么"，
但判断对错需要**另一个可信答案**做参照。

所以核心不是抓包，是**三方对照**：

```
        你的浏览器
            │  ① 系统解析（getaddrinfo，含 hosts / 缓存 / 代理）
            ▼
    ┌───────────────┐
    │  Windows DNS  │
    │   客户端服务   │
    └───────┬───────┘
            │ ② 明文 UDP/TCP 53
            ▼
    ┌───────────────┐        ┌──────────────────┐
    │ 路由器/运营商  │        │  ③ DoH 加密基准   │
    │     DNS       │        │  Cloudflare/Google│
    └───────────────┘        │  AliDNS/DNSPod    │
            │                └──────────────────┘
            ▼                         │
      实际返回的 IP  ◄──── 比对 ────► 多数派答案
```

- ① 和 ③ 一致 → 解析链路正常（或加密已生效）
- ① 等于 ② 且 ② ≠ ③ → 明文被篡改
- ② 无响应但 ① 有结果 → 只能走了加密通道
- ② 无响应且 ③ 正常，① 也失败 → 该域名被本地链路针对性丢弃

### 3.2 判定决策表

按优先级从上往下匹配：

| 优先级 | 条件 | 判定 | 严重度 |
|---|---|---|---|
| 1 | 系统解析结果落在 `198.18.0.0/15` | `proxy_fakeip` 代理接管 | info |
| 2 | 解析到私网/保留地址（10.x、127.x、0.0.0.0） | `bogon` 劫持/广告注入 | critical |
| 3 | 本地 DNS 超时 + 公共 DNS 正常 + 系统解析失败 | `selective_drop` 针对性拦截 | high |
| 4 | 本地 DNS 返回 NXDOMAIN，其他通道有结果 | `nxdomain_hijack` | high |
| 5 | 系统结果与加密基准有交集 | `normal` / `doh_active` | good |
| 6 | 系统结果 == 明文结果 ≠ 加密基准 | `plain_tampered` | high |
| 7 | 明文不可达但系统能解析 | `doh_probably` 加密生效 | good |
| 8 | 与基准不同但无法定性 | `mismatch` 需人工判断 | low |

### 3.3 明文 or 加密：怎么判断

"有没有被劫持"和"我的查询是不是明文"是两个问题。后者靠**配置层 + 行为层 + 旁证**三重判断：

| 层 | 证据 | 能得出什么 |
|---|---|---|
| 配置 | 网卡 `DohTemplate` / `DohFlags`、`EnableAutoDoh`、解析器是否在已知 DoH 列表 | 有没有开加密 |
| 行为 | 系统结果是否与加密基准一致、明文 53 是否还可达 | 加密是否真的在生效 |
| 旁证 | 是否存在到解析器 443 的长连接、443/853 可达性 | 配置是否只是写了个注册表 |
| 边界 | 浏览器自带 DoH（Chrome/Edge Local State、Firefox prefs.js） | 只保护浏览器，还是保护整机 |

判定结果分五档：`已加密（行为已验证）` / `已配置加密（未证实）` / `系统自动加密（未证实）` / `代理接管（未知）` / `明文 DNS`。
只有前两档有行为证据，其余都要在报告里写清楚"为什么不能确定"。

### 3.4 IPv6 是独立的 DNS 通道，必须单独看

只查 IPv4 会漏掉一半真相：网卡上完全可以「IPv4 指向 DoH 解析器、IPv6 还是路由器下发的地址」，
而 Windows 解析时会同时走两套。这时域名照样以明文送到路由器，加密等于白配。

两个坑：

- **IPv6 DNS 不在 `Tcpip6\...\NameServer` 里**。DHCPv6 / RA 下发的地址只体现在
  `netsh interface ipv6 show dnsservers` 的输出里，查注册表会得到空值。
- **`fec0:0:0:ffff::1%1` 是 Windows 的"未配置"占位符**，不是真的 DNS，必须过滤掉；
  `fd00::/8`（ULA）通常是代理软件的 fake DNS，`2000::/3`（全球单播）才是真的出网。

判定规则：存在全球单播 IPv6 DNS 且没有对应 DoH 模板时，记一条「IPv6 旁路」泄露并扣分。

### 3.5 DNSSEC 与 EDE：把"疑似"变成"明确"

- **DNSSEC 验签**：查 `dnssec-failed.org`。返回 `SERVFAIL` 说明解析器真的验签，篡改会被丢弃；
  返回 A 记录说明它不验签，伪造应答发现不了。这是零成本的"链路可信度"指标。
- **EDE（RFC 8914）**：解析器可以在失败时附带原因码。`EDE 15 Blocked` / `16 Censored` / `17 Filtered`
  等于对方自己承认在拦，比"超时 → 疑似拦截"强得多。

### 3.6 已知误判来源（必须写进报告说明）

| 现象 | 是否劫持 | 处理方式 |
|---|---|---|
| 同一域名不同 DNS 返回不同 IP | 否，CDN 就近调度 | 与基准取交集即判正常 |
| 返回 `198.18.x.x` | 否，代理 fake-ip | 单独归类，不计入评分 |
| 企业内网域名解析到 10.x | 否，内网 DNS | 只对公网域名评分 |
| 跨境域名解析差异 | 通常不是运营商劫持 | 归为 overseas，权重 ×0.6 |
| DNS 缓存未过期 | 可能误判 | 提供 `--flush` |

---

## 4. 技术方案

### 4.1 模块划分

```
dnsguard.py
├── DNS 协议层    _encode_qname / _read_name / dns_udp / dns_tcp
│                 （手写报文，不依赖 dnspython）
├── DoH 客户端    doh_query（JSON API，urllib + ssl）
├── 系统信息层    get_adapters / get_hosts_entries / probe_server
│                 （Windows 走 winreg，Linux/macOS 走 resolv.conf）
├── 判定层        judge_domain / consensus_of / score_findings
├── 执行层        doh_enable / doh_disable（备份 + 写入 + 回滚）
├── 报告层        Out（终端）/ render_html
└── CLI          argparse 子命令：check / doh / verify
```

### 4.2 关键实现点

**手写 DNS 报文**（避免第三方依赖）

```python
# 查询：12 字节头 + QNAME + QTYPE/QCLASS
struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_qname(name) + struct.pack("!HH", 1, 1)
```

**名称压缩指针**必须处理，否则解析 CNAME 链会崩：

```python
if ln & 0xC0 == 0xC0:                     # 0b11xxxxxx 表示指针
    ptr = ((ln & 0x3F) << 8) | data[off+1]
    sub, _ = _read_name(data, ptr, depth+1)   # 递归跟随，带深度保护
```

**TC 截断位**要回退 TCP，否则大响应会拿到残缺数据：

```python
if res["truncated"]:
    res = dns_tcp(server, name, qtype, timeout)
```

**多基准取多数派**，避免单个 DoH 服务异常导致误判：

```python
buckets.setdefault(frozenset(ips), []).append(provider)
best = max(buckets.items(), key=lambda kv: len(kv[1]))
```

### 4.3 一键 DoH 的执行链

```
校验参数(https + 合法IP)
  → 挑选"DNS 有应答"的网卡（跳过未连接网卡）
  → 备份当前配置到 backup/doh_backup_<时间>.json
  → 注册模板  HKLM\...\Dnscache\Parameters\DohWellKnownServers\<IP>\DohTemplate
  → 写网卡开关 HKLM\...\DohInterfaceSettings\Doh\<GUID>\DohFlags=1, DohTemplate=<URL>
  → netsh interface ipv4 set dnsservers name=<idx> source=static address=<IP>
  → ipconfig /flushdns + 重启 Dnscache 服务
  → 验证（配置层 + 行为层）→ 输出结论
```

**IPv6 也要一起配**：`doh on` 默认会按内置表把对应 IPv6 地址一起写进去
（阿里 `2400:3200::1`、腾讯 `2402:4e00::`、Cloudflare `2606:4700:4700::1111`、Google `2001:4860:4860::8888`），
包括 IPv6 的 DoH 模板注册、`netsh interface ipv6 set dnsservers` 和 `Tcpip6` 注册表。
不想要 IPv6 就传 `--ip6 none`。回滚时会连 IPv6 一起还原。

**为什么必须验证**：写注册表成功 ≠ DoH 生效。
Windows 只有在「服务器 IP 已注册模板 + 网卡开关打开 + 该 IP 的 443 可达」三者同时满足时才走加密，
任何一环失败都会**静默回落到明文 53**——这正是"设置完不知道成功没"的根因。

### 4.4 权限与安全

| 操作 | 权限 | 风险控制 |
|---|---|---|
| `check` | 普通用户 | 只读，无副作用 |
| `doh on` | 管理员 | 强制备份 + 交互确认 + `--dry-run` 预览 |
| `doh off` | 管理员 | 从备份还原，可重复执行 |

---

## 5. 搭建步骤

### 5.1 环境

- Python 3.9+（Windows 10/11 建议 3.11+）
- 无需 pip 安装任何包

```bash
python -V
```

### 5.2 目录结构

```
dns-guard/
├── dnsguard.py          检测引擎 + CLI（单文件，零依赖）
├── dnsguard_app.py      可视化界面（本地 Web UI，只监听 127.0.0.1）
├── build.py             打包脚本（--protect 走加密模式）
├── pack.py              生成加密载荷 payload.bin
├── boot.py              加密版启动器（内存解密执行）
├── make_icon.py         生成图标（仅构建期需要 Pillow）
├── assets/              icon.ico / icon.png
├── reports/             自动生成 report_<时间>.json / .html
├── backup/              自动生成 doh_backup_<时间>.json
└── dist/                打包产物 DNSGuard.exe
```

### 5.3 跑起来

```bash
cd dns-guard

# 体检
python dnsguard.py check

# 体检 + 生成 HTML 报告（可直接双击看）
python dnsguard.py check --html --json

# 只看某个网卡
python dnsguard.py check --public-dns 119.29.29.29
```

### 5.4 一键开启 DoH（地址自己填）

```bash
# 1) 先看计划，不改任何东西
python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5 --dry-run

# 2) 以管理员身份打开终端，正式执行（会要求输入 yes）
python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5

# 3) 只对无线网卡生效
python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5 --iface WLAN

# 4) 后悔了，一键还原
python dnsguard.py doh off
```

常用 DoH 地址对照（`--url` 与 `--ip` 必须配套）：

| 服务商 | DoH 地址 | 对应 IP |
|---|---|---|
| 阿里 | `https://dns.alidns.com/dns-query` | `223.5.5.5` |
| 腾讯 | `https://doh.pub/dns-query` | `119.29.29.29` |
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `1.1.1.1` |
| Google | `https://dns.google/dns-query` | `8.8.8.8` |

> 注意：Windows 的 DoH 是按 **IP** 注册模板的，URL 与 IP 不匹配会静默回落到明文。

### 5.5 桌面客户端（推荐）

```bash
python dnsguard_app.py                 # 默认：独立窗口（WebView2），没有地址栏和标签页
python dnsguard_app.py --ui app        # 退化方案：Edge 无地址栏窗口
python dnsguard_app.py --ui browser    # 最保守：默认浏览器
python dnsguard_app.py --no-browser --port 8899   # 只起服务
```

窗口标题是 `DNS Guard · parkerli`，任务栏图标取自 exe 图标，右键菜单已禁用，
看起来就是一个普通桌面程序，不会出现浏览器标签页。

界面里能直接看到：隐私状态与"谁能看到你访问什么"的链路图、解析一致性表格、
解析器测速与 DNSSEC 状态、一键开启/回滚 DoH、导出 HTML/JSON、复制诊断摘要。

### 5.6 打包成 exe

```bash
pip install pyinstaller pywebview pillow
python build.py             # 普通打包，约 16 MB
python build.py --protect   # 加密打包，源码不在 exe 里
# 产物：dist/DNSGuard.exe（双击即用）
```

**加密打包做了什么**：`pack.py` 把 `dnsguard.py` / `dnsguard_app.py` 压缩后用 RC4 加密成
`payload.bin`，`boot.py` 在内存里解密再执行。exe 的 PyInstaller 归档里只有 `boot` 和
`payload.bin`，没有任何 `.pyc` 可供 `pyinstxtractor` + 反编译器还原。

**但要说清楚**：Python 程序做不到真正防逆向。运行时要解密，内存就能被 dump。
这一层挡的是"随手拿工具一键反编译"，挡不住专门分析的人。真要更强，只能用
Nuitka 编译成机器码（需要 C 编译器，构建慢且对 pywebview 支持一般）。

### 5.7 定期体检（可选）

任务计划程序 → 创建基本任务 → 每天 09:00 → 程序填 `python.exe`，
参数填 `dnsguard.py check --json`，起始位置填 `dns-guard` 目录。

---

## 6. 输出怎么读

```
== 3. 解析一致性交叉验证 ==
域名                系统解析                本地DNS       公共DNS       判定
example.com         -                       超时          104.20.23.154 selective_drop
www.baidu.com       110.242.69.21,...       110.242.70.57 110.242.69.21 normal
```

| 列 | 含义 |
|---|---|
| 系统解析 | 浏览器真正拿到的结果（含 hosts/缓存/代理） |
| 本地DNS | 直接问当前配置的 DNS 服务器（明文 53） |
| 公共DNS | 问一个公认可靠的明文 DNS，作为"本地链路是否正常"的对照 |
| 判定 | 见 3.2 决策表 |

**四种典型组合**

| 系统解析 | 本地DNS | 公共DNS | 说明 |
|---|---|---|---|
| 有结果 | 同系统 | 同系统 | 一切正常 |
| 有结果 | 不同 | 同系统 | 系统走了别的通道（DoH/代理），且结果是可信的 |
| 无结果 | 超时 | 有结果 | 该域名被本地链路针对性拦截 |
| 有结果 | 同系统 | 不同 | 明文被篡改，系统也吃到了篡改结果 |

---

## 7. 分享前要做的检查

| 项 | 状态 | 说明 |
|---|---|---|
| 单文件、免安装 | ✅ | `dist/DNSGuard-v0.4.3-win64.zip`：exe + 使用说明 + LICENSE |
| 首次运行提示 | ✅ | 一次性「使用须知」，同意后才进界面 |
| 无数据外传 | ✅ | 全部本机完成，不上报 |
| 写操作可回滚 | ✅ | 改 DNS 前自动备份 |
| 只读目录可用 | ✅ | 报告/备份目录写不进去时自动落到 `%LOCALAPPDATA%\DNSGuard` |
| 无 WebView2 时 | ✅ | 自动退到 Edge `--app` 窗口 |
| **代码签名** | ❌ | 没买证书，SmartScreen 会提示"未知发布者"，用户需点「仍要运行」 |
| **杀软误报** | ⚠️ | PyInstaller 单文件常被启发式误报，建议自己先传 VirusTotal 看一眼 |
| **干净机器实测** | ❌ | 只在开发机验证过；建议在一台没装 Python 的 Win10/11 上跑一遍 |

另外两条不是技术问题：

- **别宣传"翻墙/突破封锁"**。这个工具只做劫持检测和 DoH 配置，一旦往那个方向讲，性质就变了。
- **公开分发建议开源**。16 MB 的闭源 exe 改系统 DNS，很难让人放心；源码 + 可复现构建反而更容易被接受。

## 8. 边界与风险

- **不替代抓包**：能定性"结果被替换"，不能定位"在哪一跳被替换"。需要定位时仍要抓包或做 traceroute。
- **不绕过封锁**：工具只做检测与加密 DNS 配置，不提供任何流量代理能力。
- **DNSSEC 仅做展示**：`AD` 位在 DoH 响应里返回，但完整链验证未实现（P2）。
- **评分是启发式**：用于快速分流，不构成安全结论。
- **写操作影响全局**：改 DNS 会影响整机联网，务必先 `--dry-run` 再执行，出问题立刻 `doh off`。
- **测速受代理影响**：代理接管时，测出来的延迟只是"本机到代理"，界面里会明确标注，不要拿它当解析器排名。
- **DoH 能力探测会做一次无证书校验的 TLS 握手**：只用于区分"不支持 DoH"和"证书链异常"，不传任何数据。

---

## 9. 参考与差异

做之前对比过几个同类项目，取舍如下：

| 项目 | 值得学的 | 本工具的取舍 |
|---|---|---|
| [farrokhi/dnsdiag](https://github.com/farrokhi/dnsdiag) | `dnseval` 横向比解析器（avg/抖动/丢包）、`dnstraceroute` 定位劫持跳数、EDE 解读 | 抄了测量指标与 EDE 解读；不做逐跳 traceroute（需要原始套接字/管理员） |
| [OONI Probe](https://github.com/ooni/probe) | 控制组 vs 实验组的测量方法论、结果可复核 | 抄了三方对照的思路；不接入 OONI 上报网络 |
| [dnscheck.tools](https://dnscheck.tools) | DNSSEC/EDNS/ECS 的单项检查与"一句话结论" | 抄了 DNSSEC 探针与 ECS 检测；结论仍以中文人话为主 |
| namebench / GRC DNS Benchmark | 解析器测速与推荐 | 抄了预热 + 多轮取均值的做法 |
| luoye663/dns-detector | 关注"解析器在哪、出口在哪" | 只做 PTR 反查（不把 IP 发给第三方，避免隐私工具自己泄露隐私） |

差异点：**结论优先 + 可回滚的一键 DoH + 明文/隐私专项**，而不是再做一个 dig 前端。

## 10. 路线图

| 阶段 | 内容 |
|---|---|
| v0.3 | 被动监听（scapy 抓 53），把"响应 IP 与基准不符"的包高亮出来 |
| v0.4 | 路由器 DNS 检测（UPnP / 常见管理页指纹） |
| v0.5 | 托盘常驻 + 解析异常实时告警 |
| v1.0 | 图形界面 + 一键生成可分享的诊断报告 |
