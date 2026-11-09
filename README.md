
# DNS Guard

> 给不会用 Wireshark 的人用的 DNS 劫持体检工具 —— 直接告诉你解析有没有被篡改、DoH 是不是真的生效。

Windows 优先 · 桌面客户端 / CLI · Python 3.9+ 零第三方依赖 · 源码完整开放 · [MIT](LICENSE)

---

## 它能回答什么

- 开了 VPN 反而连不上、网页偶尔跳广告：**哪些域名被改了，证据是什么**
- 照教程设了 DoH：**是真的在走加密，还是只写了个注册表**
- 装过 Clash 又关了：系统里的 `198.18.0.2` 是残留配置还是仍在接管
- IPv4 配好了 IPv6 却还在明文外发：**IPv6 旁路泄露**

核心做法不是抓包，而是**三方对照**：系统解析 / 本地明文 DNS / 多个 DoH 加密基准逐域名比对，
给出 0–100 分风险评分、逐条证据和建议。默认只读，任何写操作都要显式命令、自动备份、可一键回滚。

---

## 快速开始

### 方式一：直接下载（推荐）

从 [Releases](https://github.com/Parkerlimps/dns-guard/releases) 下载 `DNSGuard-v0.4.8-win64.zip`，
解压后双击 `DNSGuard.exe` 即可，目标机器不需要装 Python。

> 没有代码签名，首次运行 SmartScreen 会提示「未知发布者」，需点「仍要运行」；
> PyInstaller 单文件也可能被杀软启发式误报，介意的话可以自己用源码构建。

### 方式二：源码运行

```bash
git clone https://github.com/Parkerlimps/dns-guard.git
cd dns-guard

python dnsguard.py check                  # 体检，只读
python dnsguard.py check --html --json    # 顺带生成 HTML / JSON 报告
python dnsguard_app.py                    # 桌面界面（独立窗口，只监听 127.0.0.1）
```

界面右上角 `EN` 可切英文。窗口模式还可加 `--ui app`（Edge 无地址栏窗口）、
`--ui browser`（默认浏览器）、`--no-browser --port 8899`（只起服务）。

### 一键开启 DoH（会改系统配置）

```bash
# 1) 先看计划，不改任何东西
python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5 --dry-run

# 2) 管理员身份执行，会要求输入 yes
python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5

# 3) 后悔了，一键还原
python dnsguard.py doh off
```

`--url` 与 `--ip` 必须配套，不匹配会**静默回落到明文 53**：

| 服务商 | `--url` | `--ip` |
|---|---|---|
| 阿里 | `https://dns.alidns.com/dns-query` | `223.5.5.5` |
| 腾讯 | `https://doh.pub/dns-query` | `119.29.29.29` |
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `1.1.1.1` |
| Google | `https://dns.google/dns-query` | `8.8.8.8` |

`doh on` 会连同 IPv6 一起配置（不需要就传 `--ip6 none`），并在写入后**自动验证**是否真的生效。

### 打包自己的 exe

```bash
pip install pyinstaller pywebview pillow
python build.py    # 产物 dist/DNSGuard.exe
```

---

## 安全与信任

这个工具要读系统 DNS 配置、写 DoH 注册表、部分操作需要管理员权限，所以：

- **默认只读**：`check` 无副作用；写操作强制备份 + 确认 + `--dry-run` 预览，随时 `doh off` 还原
- **无数据外传**：全部本机完成，不上报；PTR 反查也不把 IP 发给第三方
- **源码完整开放**：无加密、无混淆，打包脚本一并公开，可自行构建后与 Release 产物对比

**已知限制**：不替代抓包（能定性"结果被替换"，不能定位在哪一跳）；评分是启发式，不构成安全结论；
DNSSEC 仅做展示；不提供任何流量代理或绕过封锁的能力；改 DNS 影响整机联网，务必先 `--dry-run`。

---

## 文档

| 文档 | 内容 |
|---|---|
| [docs/PRINCIPLES.md](docs/PRINCIPLES.md) | 检测原理、三方对照、判定决策表、误判来源 |
| [docs/DESIGN.md](docs/DESIGN.md) | 需求清单、模块划分、关键实现、i18n 方案、同类项目对比 |
| [docs/USAGE.md](docs/USAGE.md) | 完整命令、输出怎么读、语言切换、定期体检、打包细节 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 后续计划 |

---

## 反馈

提 Issue 时请附上 `python dnsguard.py check --json` 的输出（**先自己过一眼**，可能含你访问过的域名）、
Windows 版本、是否开着代理或 VPN，以及期望与实际看到的结果。

## 许可证

[MIT](LICENSE) © 2026 parkerli — 可自由使用、修改、分发、商用，保留版权声明即可。
