# 需求与技术方案

收录需求清单、模块划分、关键实现细节与同类项目对比。面向维护者与二次开发者。

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