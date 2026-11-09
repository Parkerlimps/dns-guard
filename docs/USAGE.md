# 完整使用说明

收录环境搭建、命令参数、报告解读与反馈方式。快速上手请直接看仓库首页 README。

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
├── build.py             打包脚本（PyInstaller 单文件）
├── dnsguard_i18n.py     中英对照表（引擎输出的英文在边界替换）
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

### 5.6 语言切换（中文 / English）

界面右上角有 `EN` 按钮，点击切到英文；英文界面下按钮显示 `中文`。默认中文，
选择记在 `localStorage`，也可以直接用 URL 参数进入某一语言：

```bash
http://127.0.0.1:8765/?lang=en    # 英文
http://127.0.0.1:8765/?lang=zh    # 中文
```

**实现方式**分两层，都在输出边界做替换，检测逻辑里没有一句 `if lang == ...`：

| 层 | 覆盖范围 | 位置 |
|---|---|---|
| 引擎层 | 结论、摘要、证据、建议、通道、判定原因 | `dnsguard_i18n.py` |
| 界面层 | 卡片标题、按钮、表头、状态标签 | `dnsguard_app.py` 的 `EN` 字典 |

中文是唯一源语言。`dnsguard_i18n.py` 里 `EN` 处理固定文案，`PATS` 处理带变量的
句子——中文模板里的 `{}` 在加载时自动转成正则捕获组，所以不需要在 400 多个
f-string 上逐个打补丁。匹配不上的原样返回中文，宁可漏翻不会乱翻。

想检查覆盖率：

```bash
python dnsguard_i18n.py payload.json
```

**已知不覆盖**：体检日志面板（`<details>` 里那段）是 CLI 的原始输出，和
`python dnsguard.py check` 共用，仍是中文。网卡名、DNS 服务商名保持系统原名。

### 5.7 打包成 exe

```bash
pip install pyinstaller pywebview pillow
python build.py             # 打包，约 16 MB
# 产物：dist/DNSGuard.exe（双击即用）
```

`build.py` 内部就是一条 PyInstaller 命令：`--onefile --windowed`，带图标和版本信息，
`--collect-all` 把 pywebview / pythonnet 的运行时一起收进来，所以 exe 不依赖目标机器的 Python。

源码完整包含在仓库里，没有做任何加密或混淆。这是有意的取舍：DNS Guard 要读系统 DNS 配置、
改 DoH 注册表、需要管理员权限，用户凭什么相信一个看不见内容的 exe 不会把查询记录传出去？
代码可读是这类工具最基本的信任来源。

> 早期版本试过 RC4 加密载荷 + 内存解密（`pack.py` / `boot.py`），v0.4.8 已移除。
> 那层保护挡不住真正想逆向的人——密钥和密文躺在同一个 exe 里——却会让杀软启发式
> 更容易把「无签名 + 运行时解密 + 单文件」判定为可疑，反而抬高了普通用户的使用门槛。

### 5.8 定期体检（可选）

任务计划程序 → 创建基本任务 → 每天 09:00 → 程序填 `python.exe`，
参数填 `dnsguard.py check --json`，起始位置填 `dns-guard` 目录。

---

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
| 判定 | 见 [检测原理 · 判定决策表](PRINCIPLES.md) 中的 3.2 |

**四种典型组合**

| 系统解析 | 本地DNS | 公共DNS | 说明 |
|---|---|---|---|
| 有结果 | 同系统 | 同系统 | 一切正常 |
| 有结果 | 不同 | 同系统 | 系统走了别的通道（DoH/代理），且结果是可信的 |
| 无结果 | 超时 | 有结果 | 该域名被本地链路针对性拦截 |
| 有结果 | 同系统 | 不同 | 明文被篡改，系统也吃到了篡改结果 |

---

---

## 12. 反馈

提 Issue 时请附上：

- `python dnsguard.py check --json` 的输出（**先自己过一眼**，里面可能包含你访问过的域名）
- Windows 版本、是否开着代理或 VPN
- 期望看到什么、实际看到什么