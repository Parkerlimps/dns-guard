#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsguard.py — DNS 劫持体检 + 一键 DoH 助手

设计目标：不会用 Wireshark 的人也能看懂自己有没有被 DNS 劫持，
以及"我设的 DoH 到底生效没有"。

零第三方依赖，Python 3.8+，Windows 优先（Linux/macOS 降级可用）。

常用命令
--------
  python dnsguard.py check                          # 体检
  python dnsguard.py check --html --json            # 体检并生成报告
  python dnsguard.py doh on --url https://dns.alidns.com/dns-query --ip 223.5.5.5
                                                    # 一键开启系统级 DoH（需管理员）
  python dnsguard.py doh on ... --yes               # 跳过交互确认
  python dnsguard.py doh on ... --dry-run           # 只打印计划
  python dnsguard.py doh off                        # 回滚到开启前的状态
  python dnsguard.py verify --url ... --ip ...      # 单独验证 DoH 是否生效

判定原理（三层交叉验证）
------------------------
  第一层 系统解析：getaddrinfo，浏览器真正走的路径（含 hosts / 缓存 / 代理接管）
  第二层 明文 DNS：直接 UDP/TCP 53 问当前配置的服务器，看它给什么
  第三层 加密基准：DoH 问多个公共服务，取多数派作为"正确答案"
  三者比对即可区分：正常 / 加密生效 / 明文被篡改 / 本地链路选择性拦截
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

VERSION = "0.4.7"
IS_WIN = os.name == "nt"


def _app_dir() -> str:
    """打包成 exe 后，报告要落在 exe 旁边，而不是 PyInstaller 的临时解包目录"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = _app_dir()


def _writable_dir(preferred: str, name: str) -> str:
    """exe 可能被放在 Program Files 这类只读目录，落盘位置要能降级"""
    try:
        os.makedirs(preferred, exist_ok=True)
        probe = os.path.join(preferred, ".probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("1")
        os.remove(probe)
        return preferred
    except OSError:
        alt = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                           "DNSGuard", name)
        try:
            os.makedirs(alt, exist_ok=True)
        except OSError:
            pass
        return alt


REPORT_DIR = _writable_dir(os.path.join(BASE_DIR, "reports"), "reports")
BACKUP_DIR = _writable_dir(os.path.join(BASE_DIR, "backup"), "backup")

# ---------------------------------------------------------------- 常量表

DOH_PROVIDERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query?name={name}&type=A",
    "Google": "https://dns.google/resolve?name={name}&type=A",
    "AliDNS": "https://dns.alidns.com/resolve?name={name}&type=1",
    "DNSPod": "https://doh.pub/dns-query?name={name}&type=A",
}

DEFAULT_PUBLIC_DNS = "223.5.5.5"

# 各家 DoH 服务对应的 IPv6 地址（用于把 IPv6 一起加密）
DOH_IPV6 = {
    "223.5.5.5": "2400:3200::1",          # 阿里 dns.alidns.com
    "223.6.6.6": "2400:3200::1",
    "119.29.29.29": "2402:4e00::",        # 腾讯 doh.pub
    "1.1.1.1": "2606:4700:4700::1111",    # Cloudflare
    "1.0.0.1": "2606:4700:4700::1001",
    "8.8.8.8": "2001:4860:4860::8888",    # Google
    "9.9.9.9": "2620:fe::fe",             # Quad9
}


def resolve_doh_ipv6(ip: str, url: str) -> str:
    """先查内置表，再尝试从 DoH 主机名的 AAAA 记录推一个"""
    if ip in DOH_IPV6:
        return DOH_IPV6[ip]
    host = ""
    m = re.match(r"^https://([^/]+)", url)
    if m:
        host = m.group(1)
    if not host:
        return ""
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)
    except Exception:
        return ""
    for info in infos:
        addr = info[4][0].split("%")[0]
        try:
            ip6 = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip6 in ipaddress.ip_network("2000::/3"):
            return addr
    return ""

FAKE_IP_NETS = [ipaddress.ip_network(n) for n in ("198.18.0.0/15", "198.19.0.0/16")]

BOGON_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
        "224.0.0.0/4", "240.0.0.0/4",
    )
]

TEST_DOMAINS = [
    ("www.baidu.com", "domestic"),
    ("www.qq.com", "domestic"),
    ("www.taobao.com", "domestic"),
    ("www.jd.com", "domestic"),
    ("www.bilibili.com", "domestic"),
    ("example.com", "neutral"),
    ("www.iana.org", "neutral"),
    ("github.com", "overseas"),
]

PROXY_PORTS = [7890, 7891, 7892, 7897, 1080, 10808, 10809, 2080, 9090]

C_OK, C_WARN, C_BAD, C_DIM, C_HEAD, C_END = (
    "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1;36m", "\033[0m")

STATUS_TAG = {"ok": "[ OK ]", "warn": "[WARN]", "bad": "[ BAD]", "info": "[INFO]", "na": "[ -- ]"}


# ---------------------------------------------------------------- 输出工具

def _w(text: str) -> int:
    """终端显示宽度（中文算 2 列）"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _w(text))


def _fit(text: str, width: int) -> str:
    """按显示宽度截断并补齐，避免长 IP 串把表格挤歪"""
    if _w(text) <= width - 1:
        return _pad(text, width)
    out, cur = "", 0
    for ch in text:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if cur + cw > width - 1:
            break
        out += ch
        cur += cw
    return out + "…" + " " * max(0, width - cur - 1)


class Out:
    def __init__(self, color: bool = True):
        self.color = color

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{C_END}" if self.color else text

    def raw(self, text: str = "") -> None:
        print(text)

    def title(self, text: str) -> None:
        self.raw()
        bar = "=" * max(0, 58 - _w(text))
        self.raw(self._c(f"== {text} {bar}", C_HEAD))

    def item(self, status: str, text: str) -> None:
        tag = STATUS_TAG.get(status, "[????]")
        code = {"ok": C_OK, "warn": C_WARN, "bad": C_BAD, "info": C_DIM, "na": C_DIM}.get(status, "")
        self.raw(f"  {self._c(tag, code)} {text}")

    def kv(self, key: str, value: str) -> None:
        self.raw(f"         {key}: {value}")

    def note(self, text: str) -> None:
        self.raw(f"         {self._c(text, C_DIM)}")


# ---------------------------------------------------------------- DNS 协议层

def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        try:
            b = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode("ascii")
        except Exception:
            b = label.encode("utf-8")
        if not b or len(b) > 63:
            raise ValueError(f"非法域名标签: {label!r}")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if off >= len(data):
            raise ValueError("名称截断")
        ln = data[off]
        if ln == 0:
            return ".".join(labels), off + 1
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("指针截断")
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if depth > 16:
                raise ValueError("压缩指针成环")
            sub, _ = _read_name(data, ptr, depth + 1)
            if sub:
                labels.append(sub)
            return ".".join(labels), off + 2
        if ln & 0xC0:
            raise ValueError("非法标签长度")
        labels.append(data[off + 1: off + 1 + ln].decode("latin-1"))
        off += 1 + ln


def _parse_response(data: bytes, rtt_ms: float) -> dict:
    if len(data) < 12:
        raise ValueError("响应过短")
    _rid, flags, qd, an, ns_count, ar = struct.unpack("!HHHHHH", data[:12])
    res = {
        "rcode": flags & 0x0F,
        "truncated": bool((flags >> 9) & 1),
        "ad": bool((flags >> 5) & 1),
        "answers": [],
        "rtt_ms": round(rtt_ms, 1),
        "ecs": None,
        "edns": False,
        "ede": None,
    }
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    for idx in range(an + ns_count + ar):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off: off + 10])
        off += 10
        rdata = data[off: off + rdlen]
        if rtype == 41:                      # OPT：EDNS(0) 伪记录
            res["edns"] = True
            p = 0
            while p + 4 <= len(rdata):
                ocode, olen = struct.unpack("!HH", rdata[p: p + 4])
                p += 4
                if ocode == 8 and olen >= 4:  # EDNS Client Subnet
                    fam, src, scope = struct.unpack("!HBB", rdata[p: p + 4])
                    res["ecs"] = {"family": fam, "source": src, "scope": scope}
                elif ocode == 15 and olen >= 2:   # RFC 8914 Extended DNS Error
                    code = struct.unpack("!H", rdata[p: p + 2])[0]
                    res["ede"] = {"code": code,
                                  "text": rdata[p + 2: p + olen].decode("utf-8", "replace")}
                p += olen
        elif idx < an:
            value = None
            if rtype == 1 and rdlen == 4:
                value = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (5, 12):
                try:
                    value, _ = _read_name(data, off)
                except Exception:
                    value = None
            res["answers"].append({"name": name, "type": rtype, "ttl": ttl, "data": value})
        off += rdlen
    return res


def _build_query(qid: int, name: str, qtype: int) -> bytes:
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + _encode_qname(name) + struct.pack("!HH", qtype, 1))


def _udp_exchange(server: str, pkt: bytes, qid: int, timeout: float) -> dict:
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.time()
    try:
        sock.sendto(pkt, (server, 53))
        data = b""
        for _ in range(3):
            data, _addr = sock.recvfrom(4096)
            if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == qid:
                break
        else:
            raise TimeoutError("响应 ID 不匹配")
    finally:
        sock.close()
    return _parse_response(data, (time.time() - t0) * 1000)


def dns_udp(server: str, name: str, qtype: int = 1, timeout: float = 3.0) -> dict:
    qid = random.randint(0, 0xFFFF)
    res = _udp_exchange(server, _build_query(qid, name, qtype), qid, timeout)
    if res["truncated"]:
        res = dns_tcp(server, name, qtype, timeout)
    return res


def dns_udp_ecs(server: str, name: str = "www.baidu.com", timeout: float = 3.0) -> dict:
    """带 EDNS Client Subnet 的查询：用来验证解析器会不会把你的网段泄露给权威服务器"""
    qid = random.randint(0, 0xFFFF)
    opt = (b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 8)
           + struct.pack("!HHHBB", 8, 4, 1, 0, 0))
    pkt = (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
           + _encode_qname(name) + struct.pack("!HH", 1, 1) + opt)
    return _udp_exchange(server, pkt, qid, timeout)


def dns_tcp(server: str, name: str, qtype: int = 1, timeout: float = 4.0) -> dict:
    qid = random.randint(0, 0xFFFF)
    pkt = _build_query(qid, name, qtype)
    t0 = time.time()
    with socket.create_connection((server, 53), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(pkt)) + pkt)
        head = sock.recv(2)
        if len(head) < 2:
            raise ValueError("TCP 响应过短")
        want = struct.unpack("!H", head)[0]
        buf = b""
        while len(buf) < want:
            chunk = sock.recv(want - len(buf))
            if not chunk:
                break
            buf += chunk
    return _parse_response(buf, (time.time() - t0) * 1000)


def doh_query(url_tpl: str, name: str, timeout: float = 6.0, insecure: bool = False) -> dict:
    url = url_tpl.format(name=name) if "{name}" in url_tpl else url_tpl
    req = urllib.request.Request(
        url, headers={"accept": "application/dns-json", "user-agent": f"dnsguard/{VERSION}"})
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    ips, cnames = [], []
    for ans in payload.get("Answer", []) or []:
        atype = str(ans.get("type", "")).upper()
        if atype in ("1", "A"):
            ips.append(ans.get("data"))
        elif atype in ("5", "CNAME"):
            cnames.append(ans.get("data"))
    return {
        "rcode": int(payload.get("Status", 0)),
        "ips": [ip for ip in ips if ip],
        "cnames": cnames,
        "ad": bool(payload.get("AD", False)),
        "rtt_ms": round((time.time() - t0) * 1000, 1),
    }


# ---------------------------------------------------------------- 系统信息

def _reg_read(path: str, name: str):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _reg_subkeys(path: str) -> list[str]:
    import winreg
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _run(cmd: list[str], timeout: float = 20.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return ""
    raw = (p.stdout or b"") + (p.stderr or b"")
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _iface_name(guid: str) -> str:
    p = (r"SYSTEM\CurrentControlSet\Control\Network"
         r"\{4D36E972-E325-11CE-BFC1-08002BE10318}\%s\Connection" % guid)
    return _reg_read(p, "Name") or f"未知网卡({guid.strip('{}')[:8]})"


def _netsh_indices() -> dict[str, int]:
    if not IS_WIN:
        return {}
    mapping = {}
    for line in _run(["netsh", "interface", "ipv4", "show", "interfaces"]).splitlines():
        m = re.match(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(.+?)\s*$", line)
        if m:
            mapping[m.group(2)] = int(m.group(1))
    return mapping


def _split_ips(text: str) -> list[str]:
    return [x for x in re.split(r"[\s,;]+", (text or "").strip()) if x]


def get_adapters() -> list[dict]:
    adapters: list[dict] = []
    if not IS_WIN:
        servers = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip().startswith("nameserver"):
                        servers.append(line.split()[1])
        except OSError:
            pass
        return [{"guid": "default", "name": "system", "static": servers, "dhcp": [],
                 "gateway": "", "doh_flags": None, "doh_template": None, "index": None}]

    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    base6 = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
    indices = _netsh_indices()
    for guid in _reg_subkeys(base):
        path = f"{base}\\{guid}"
        path6 = f"{base6}\\{guid}"
        static = _split_ips(_reg_read(path, "NameServer") or "")
        dhcp = _split_ips(_reg_read(path, "DhcpNameServer") or "")
        # IPv6 的 DNS 在另一个键下面，漏掉它就会出现"IPv4 加密了、IPv6 还在明文"的错觉
        static6 = _split_ips(_reg_read(path6, "NameServer") or "")
        dhcp6 = _split_ips(_reg_read(path6, "DhcpNameServer") or "")
        if not (static or dhcp or static6 or dhcp6):
            continue
        gw = _reg_read(path, "DhcpDefaultGateway")
        if isinstance(gw, list):
            gw = gw[0] if gw else ""
        doh_path = (r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                    r"\DohInterfaceSettings\Doh\%s" % guid)
        name = _iface_name(guid)
        adapters.append({
            "guid": guid, "name": name,
            "static": static, "dhcp": dhcp, "gateway": gw or "",
            "static6": static6, "dhcp6": dhcp6,
            "doh_flags": _reg_read(doh_path, "DohFlags"),
            "doh_template": _reg_read(doh_path, "DohTemplate"),
            "index": indices.get(name),
        })

    v6map = get_ipv6_dns()
    for ad in adapters:
        ad["dns6"] = v6map.get(ad["name"], [])
    return adapters


def get_known_doh_templates() -> dict[str, str]:
    if not IS_WIN:
        return {}
    base = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers"
    return {ip: (_reg_read(f"{base}\\{ip}", "DohTemplate") or "") for ip in _reg_subkeys(base)}


def get_ipv6_dns() -> dict[str, list[str]]:
    """读取每个网卡实际生效的 IPv6 DNS。

    注意：DHCPv6 / RA 下发的 IPv6 DNS 不会写进 Tcpip6 的 NameServer，
    只查注册表会漏掉，必须问 netsh。输出是本地化的，所以只按接口名 + IPv6 字面量解析。
    """
    if not IS_WIN:
        return {}
    result: dict[str, list[str]] = {}
    current = ""
    txt = _run(["netsh", "interface", "ipv6", "show", "dnsservers"], timeout=15)
    for line in txt.splitlines():
        m = re.match(r'^\s*(?:接口|Interface)\s+"(.+?)"', line)
        if m:
            current = m.group(1)
            result.setdefault(current, [])
            continue
        if not current:
            continue
        for token in re.findall(r'(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*', line):
            addr = token.split("%")[0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if ip.version != 6 or ip.is_link_local or ip.is_loopback:
                continue
            if str(ip).startswith("fec0:"):        # Windows 的"未配置"占位符
                continue
            if str(ip) not in result[current]:
                result[current].append(str(ip))
    return {k: v for k, v in result.items() if v}


def get_hosts_entries() -> list[tuple[str, str]]:
    path = r"C:\Windows\System32\drivers\etc\hosts" if IS_WIN else "/etc/hosts"
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    entries.extend((parts[0], host) for host in parts[1:])
    except OSError:
        pass
    return entries


def is_admin() -> bool:
    if not IS_WIN:
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def detect_local_proxy() -> list[int]:
    found = []
    for port in PROXY_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                found.append(port)
        except OSError:
            pass
        finally:
            s.close()
    return found


def resolve_system(name: str, timeout: float = 5.0) -> list[str]:
    def _do():
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        seen, out = set(), []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            return pool.submit(_do).result(timeout=timeout)
        except Exception:
            return []


# ---------------------------------------------------------------- 判定逻辑

def ip_in(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def classify_ips(ips: list[str]) -> dict:
    fake = [ip for ip in ips if ip_in(ip, FAKE_IP_NETS)]
    bogon = [ip for ip in ips if ip_in(ip, BOGON_NETS) and ip not in fake]
    return {"fake": fake, "bogon": bogon,
            "public": [ip for ip in ips if ip not in fake and ip not in bogon]}


def consensus_of(doh_results: dict[str, list[str]]) -> tuple[set[str], list[str]]:
    buckets: dict[frozenset, list[str]] = {}
    for provider, ips in doh_results.items():
        if ips:
            buckets.setdefault(frozenset(ips), []).append(provider)
    if not buckets:
        return set(), []
    best = max(buckets.items(), key=lambda kv: len(kv[1]))
    return set(best[0]), best[1]


def probe_server(server: str, timeout: float = 2.0) -> dict:
    """探测某个 DNS 服务器是否可用（用 baidu 做探针）"""
    try:
        res = dns_udp(server, "www.baidu.com", timeout=timeout)
        return {"alive": True, "rcode": res["rcode"], "rtt_ms": res["rtt_ms"]}
    except Exception as exc:
        return {"alive": False, "error": type(exc).__name__}


def judge_domain(row: dict) -> dict:
    sys_ips = row["sys_ips"]
    plain = row["plain"]
    public = row["public"]
    consensus = row["consensus"]

    cls = classify_ips(sys_ips)

    if cls["fake"]:
        return {"verdict": "proxy_fakeip", "severity": "info",
                "reason": "代理 fake-ip，不能据此判断劫持"}
    if cls["bogon"]:
        return {"verdict": "bogon", "severity": "critical",
                "reason": f"解析到非公网地址 {', '.join(cls['bogon'])}，典型劫持/广告注入特征"}
    ede = plain.get("ede") or {}
    if int(ede.get("code", 0)) in (15, 16, 17, 18) and (consensus or public.get("ips")):
        return {"verdict": "ede_blocked", "severity": "high",
                "reason": f"解析器自己说：{ede_text(ede)} -> 主动拦截，不是网络故障"}
    if plain.get("timeout") and public.get("ok") and not sys_ips:
        return {"verdict": "selective_drop", "severity": "high",
                "reason": "本地 DNS 对该域名无响应（超时），而公共明文 DNS 正常 -> 针对性拦截/故障"}
    if plain.get("ok") and plain.get("rcode") == 3 and (consensus or public.get("ips")):
        return {"verdict": "nxdomain_hijack", "severity": "high",
                "reason": "本地明文 DNS 返回 NXDOMAIN，而其他通道有正常解析结果"}
    if not sys_ips:
        return {"verdict": "failed", "severity": "medium",
                "reason": "系统解析失败（DNS 不可达或被重置）"}
    if consensus and set(sys_ips) & consensus:
        if plain.get("ok") and plain.get("ips") and not (set(plain["ips"]) & consensus):
            return {"verdict": "doh_active", "severity": "good",
                    "reason": "系统结果与加密基准一致、与明文不同 -> 加密解析已生效"}
        return {"verdict": "normal", "severity": "good", "reason": "与加密基准一致"}
    if plain.get("ok") and plain.get("ips") and set(plain["ips"]) == set(sys_ips) and row.get("proxy_takeover"):
        return {"verdict": "proxy_route", "severity": "info",
                "reason": "解析经本地代理转发，与直连基准的差异通常来自出口线路/CDN 调度，不能据此判定劫持"}
    if plain.get("ok") and plain.get("ips") and set(plain["ips"]) == set(sys_ips) and consensus:
        if not row.get("consensus_unanimous", True):
            return {"verdict": "cdn_variance", "severity": "info",
                    "reason": "系统与明文一致，但各加密基准自己也不一致 -> CDN 就近调度，不是篡改"}
        return {"verdict": "plain_differs", "severity": "medium",
                "reason": "系统与明文结果一致，但与加密基准不同。常见于运营商透明 DNS 或 CDN 就近调度；"
                          "若返回的是公网地址、域名也能正常打开，多数属于后者"}
    if not plain.get("ok") and sys_ips and consensus:
        return {"verdict": "doh_probably", "severity": "good",
                "reason": "明文 DNS 不可达但系统仍能解析 -> 只能是通过加密通道解析"}
    if consensus:
        return {"verdict": "mismatch", "severity": "low",
                "reason": "与加密基准不同（可能是 CDN 就近调度，需人工判断）"}
    return {"verdict": "unknown", "severity": "info", "reason": "缺少加密基准，无法交叉验证"}


def score_findings(rows: list[dict], hosts: list[tuple[str, str]]) -> tuple[int, str]:
    score = 100
    for row in rows:
        kind = row["judge"]["verdict"]
        weight = 1.0 if row["kind"] == "domestic" else 0.6
        if kind == "bogon":
            score -= int(35 * weight)
        elif kind in ("nxdomain_hijack", "selective_drop", "ede_blocked"):
            score -= int(22 * weight)
        elif kind == "plain_differs":
            score -= int(4 * weight)
        elif kind == "failed":
            score -= int(5 * weight)
        elif kind == "mismatch":
            score -= int(6 * weight)
    suspicious = [h for h in hosts if not h[0].startswith(("127.", "0.0.0.0", "::1"))]
    score -= min(len(suspicious) * 6, 18)
    score = max(0, min(100, score))
    level = "低风险" if score >= 90 else "需留意" if score >= 70 else "中风险" if score >= 45 else "高风险"
    return score, level


# ---------------------------------------------------------------- 隐私暴露分析
#
# 目的：回答一个比"有没有被劫持"更常见的问题 —— "我的 DNS 到底是不是明文，
# 谁在看我在访问什么"。判定不靠猜，靠三件事：
#   1) 配置层：网卡有没有 DoH 模板、DohFlags 是否打开、系统自动 DoH 开关
#   2) 行为层：系统解析结果是否与加密基准一致 / 明文 53 是否还可达
#   3) 旁证：是否观测到与解析器 443 的长连接（DoH 生效时的典型特征）

PUBLIC_RESOLVERS = {
    "223.5.5.5": ("阿里 AliDNS", "https://dns.alidns.com/dns-query"),
    "223.6.6.6": ("阿里 AliDNS", "https://dns.alidns.com/dns-query"),
    "119.29.29.29": ("腾讯 DNSPod", "https://doh.pub/dns-query"),
    "1.1.1.1": ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    "1.0.0.1": ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    "8.8.8.8": ("Google", "https://dns.google/dns-query"),
    "8.8.4.4": ("Google", "https://dns.google/dns-query"),
    "9.9.9.9": ("Quad9", "https://dns.quad9.net/dns-query"),
    "180.76.76.76": ("百度 DNS", ""),
    "114.114.114.114": ("114DNS", ""),
}


def resolver_info(ip: str) -> tuple[str, str]:
    return PUBLIC_RESOLVERS.get(ip, ("未知 / 运营商 DNS", ""))


def _probe_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


DOH_CONN_STATES = {"ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT_1",
                   "FIN_WAIT_2", "LAST_ACK", "SYN_SENT"}


def _tcp_remote_hits(port: int = 443) -> list[tuple[str, str]]:
    """列出到 port 的 TCP 连接（含 TIME_WAIT）。

    Windows 的 DoH 连接很可能是"查完就关"，只剩 TIME_WAIT 回收记录；
    只统计 ESTABLISHED 会把加密生效误判成回落明文。
    """
    if not IS_WIN:
        return []
    hits: list[tuple[str, str]] = []
    for line in _run(["netstat", "-ano", "-p", "TCP"], timeout=10).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].upper() == "TCP":
            state = parts[3].upper()
            if state not in DOH_CONN_STATES:
                continue
            remote = parts[2]
            if remote.endswith(f":{port}"):
                hits.append((remote.rsplit(":", 1)[0].strip("[]"), state))
    return hits


def browser_doh_state() -> list[dict]:
    """浏览器自带 DoH 与系统 DoH 是两条独立通道，必须分开看"""
    found: list[dict] = []
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    chromium = [
        ("Chrome", os.path.join(local, r"Google\Chrome\User Data\Local State")),
        ("Edge", os.path.join(local, r"Microsoft\Edge\User Data\Local State")),
        ("Brave", os.path.join(local, r"BraveSoftware\Brave-Browser\User Data\Local State")),
    ]
    for app, path in chromium:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                conf = (json.load(fh).get("dns_over_https") or {})
            mode = str(conf.get("mode") or "off").lower()
            uri = str(conf.get("templates") or "").split()[0] if conf.get("templates") else ""
            found.append({"app": app, "mode": mode, "uri": uri})
        except Exception:
            continue

    if os.path.isdir(roaming):
        prof_root = os.path.join(roaming, r"Mozilla\Firefox\Profiles")
        if os.path.isdir(prof_root):
            for prof in os.listdir(prof_root):
                prefs = os.path.join(prof_root, prof, "prefs.js")
                if not os.path.exists(prefs):
                    continue
                try:
                    with open(prefs, encoding="utf-8", errors="replace") as fh:
                        txt = fh.read()
                    m = re.search(r'user_pref\("network\.trr\.mode",\s*(\d)\)', txt)
                    u = re.search(r'user_pref\("network\.trr\.uri",\s*"([^"]*)"\)', txt)
                    if m:
                        mode_num = int(m.group(1))
                        found.append({
                            "app": "Firefox",
                            "mode": {2: "secure", 3: "secure", 5: "off"}.get(mode_num, "off"),
                            "uri": (u.group(1) if u else ""),
                        })
                        break
                except Exception:
                    continue
    return found


def analyze_privacy(adapters, liveness, rows, proxy_ports, local_live,
                    plain_server, deep: bool = True) -> dict:
    gateways = list(dict.fromkeys([a["gateway"] for a in adapters if a.get("gateway")]))
    gw_txt = gateways[0] if gateways else "默认网关"

    servers: list[str] = []
    for ad in adapters:
        for srv in (ad["static"] or ad["dhcp"]):
            if srv not in servers:
                servers.append(srv)

    doh_adapters = [a for a in adapters if a.get("doh_template")]
    auto_doh = _reg_read(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh") if IS_WIN else None
    enc_rows = [r for r in rows if r["judge"]["verdict"] in ("doh_active", "doh_probably")]
    browsers = browser_doh_state()
    browser_enc = [b for b in browsers if b["mode"] in ("secure", "automatic") and b["uri"]]
    target = local_live[0] if local_live else (plain_server or (servers[0] if servers else None))
    provider, provider_doh = resolver_info(target or "")
    if local_live and not provider_doh:
        provider = "本地代理 DNS"

    # ---- 1. 旁证探测（443/853 可达性 + 443 连接 + ECS），要先于判定做
    reach = {"target": target, "doh_443": None, "dot_853": None, "plain_53": None,
             "tls_conn": [], "tls_states": []}
    if deep and target:
        # 必须制造一次缓存未命中：getaddrinfo 命中缓存时根本不会发查询，
        # 也就看不到 DoH 的 443 连接，会误判成"没加密"
        resolve_system(f"probe-{random.randint(100000, 999999)}.example.com", timeout=3.0)
        reach["doh_443"] = _probe_port(target, 443)
        reach["dot_853"] = _probe_port(target, 853)
        reach["plain_53"] = bool(liveness.get(target, {}).get("alive"))
        conns = [c for c in _tcp_remote_hits(443) if c[0] == target]
        reach["tls_conn"] = [ip for ip, _st in conns]
        reach["tls_states"] = sorted({st for _ip, st in conns})

    # ---- 2. 主通道状态
    doh_on = bool(doh_adapters) and (auto_doh == 2
                                     or any(a.get("doh_flags") in (1, 2) for a in doh_adapters))
    if local_live:
        state, level, label = "proxy", "warn", "代理接管"
    elif enc_rows:
        state, level, label = "encrypted", "ok", "已加密（行为已验证）"
    elif doh_on and reach["tls_conn"]:
        state, level, label = "encrypted", "ok", "已加密（已观测到 TLS 连接）"
    elif doh_on:
        state, level, label = "encrypted_unproven", "warn", "已配置加密（未证实）"
    elif auto_doh == 2 and provider_doh:
        state, level, label = "auto_doh", "warn", "系统自动加密（未证实）"
    elif servers:
        state, level, label = "plaintext", "bad", "明文 DNS"
    else:
        state, level, label = "unknown", "info", "无法判断"

    ecs = {"tested": False, "server": target, "leaked": False, "source": 0, "detail": ""}
    if deep and target:
        try:
            res = dns_udp_ecs(target, "www.baidu.com", timeout=3.0)
            ecs["tested"] = True
            if res.get("ecs"):
                src = int(res["ecs"].get("source") or 0)
                scope = int(res["ecs"].get("scope") or 0)
                ecs["source"] = src
                # RFC 7871：SOURCE=0 表示解析器没有把你的网段带给权威服务器，
                # SCOPE 只表示这个答案的适用范围，不能当成泄露
                ecs["leaked"] = src > 0
                if src > 0:
                    ecs["detail"] = (f"解析器把你的 /{src} 网段转发给了权威服务器（scope /{scope}），"
                                     f"上游能看到你大概在哪个片区")
                else:
                    ecs["detail"] = (f"解析器没有使用客户端子网（scope /{scope} 只表示答案适用范围），"
                                     f"不泄露网段")
            else:
                ecs["detail"] = "响应里没有 ECS 字段，不会泄露网段" if res.get("edns") else "该解析器不支持 EDNS"
        except Exception as exc:
            ecs["detail"] = f"探测失败：{type(exc).__name__}"

    # ---- 2.5 IPv6 DNS：最容易漏的一条明文旁路
    v6_servers: list[str] = []
    for ad in adapters:
        for s6 in ad.get("dns6") or []:
            if s6 not in v6_servers:
                v6_servers.append(s6)
    v6_public, v6_local = [], []
    for s6 in v6_servers:
        try:
            ip6 = ipaddress.ip_address(s6)
        except ValueError:
            continue
        (v6_public if ip6 in ipaddress.ip_network("2000::/3") else v6_local).append(s6)
    # 逐个 IPv6 DNS 看：有没有注册 DoH 模板、443 通不通
    known_tpl = get_known_doh_templates()
    v6_status: list[dict] = []
    for s6 in v6_public:
        tpl = known_tpl.get(s6, "")
        v6_status.append({"ip": s6, "template": tpl,
                          "reachable": _probe_port(s6, 443, 2.5) if deep else None})
    v6_encrypted = bool(v6_status) and all(x["template"] for x in v6_status)
    v6_weak = any(x["template"] and x["reachable"] is False for x in v6_status)
    # 只有"确实没有模板"才算明文旁路；有模板但 443 不通是另一类问题
    v6_leak = bool(v6_public) and not v6_encrypted and \
        state in ("encrypted", "encrypted_unproven", "auto_doh")

    # ---- 3. 通道清单
    channels: list[dict] = []
    if state == "proxy":
        channels.append({
            "name": "系统解析（浏览器与所有应用默认走这条）",
            "encrypted": None,
            "path": f"本机 → 本地代理 127.0.0.1:{proxy_ports[0] if proxy_ports else '?'} → 上游",
            "state_text": "由代理接管，加密与否取决于代理配置",
            "sees": "域名（若代理上游仍是明文 UDP）",
        })
    elif state == "encrypted":
        channels.append({
            "name": "系统解析（浏览器与所有应用默认走这条）",
            "encrypted": True,
            "path": f"本机 ⇄ {target}:443 (TLS) → {provider}",
            "state_text": "加密（HTTPS/DoH）",
            "sees": "仅 DoH 服务商",
        })
    elif state in ("encrypted_unproven", "auto_doh"):
        tpl = (doh_adapters[0].get("doh_template") if doh_adapters else provider_doh) or "—"
        proven = bool(reach.get("tls_conn"))
        channels.append({
            "name": "系统解析（浏览器与所有应用默认走这条）",
            "encrypted": True if proven else None,
            "path": f"本机 → {target}:443 (TLS, {tpl})",
            "state_text": "已观测到加密连接" if proven else "配置已开，但未观测到加密连接",
            "sees": "理论上仅 DoH 服务商",
        })
    else:
        channels.append({
            "name": "系统解析（浏览器与所有应用默认走这条）",
            "encrypted": False,
            "path": f"本机 → {gw_txt} → 运营商 → {target or '?'}:53",
            "state_text": "明文 UDP/53",
            "sees": "链路上所有人",
        })

    if v6_public:
        if v6_encrypted:
            channels.append({
                "name": "IPv6 解析（Windows 会并行查询）",
                "encrypted": True,
                "path": f"本机 ⇄ [{v6_public[0]}]:443 (TLS) → {provider}",
                "state_text": "已配置 DoH（443 可达）" if not v6_weak else "已配置 DoH，但 443 不可达",
                "sees": "仅 DoH 服务商",
            })
        else:
            channels.append({
                "name": "IPv6 解析（Windows 会并行查询）",
                "encrypted": False,
                "path": f"本机 → {gw_txt} → [{v6_public[0]}]:53 (IPv6)",
                "state_text": "明文 UDP/53（IPv6，无 DoH 模板）",
                "sees": "链路上所有人",
            })

    for b in browsers:
        if b["mode"] in ("secure", "automatic") and b["uri"]:
            channels.append({
                "name": f"{b['app']} 自带 DoH",
                "encrypted": True,
                "path": f"{b['app']} ⇄ {b['uri'].split('/')[2] if '//' in b['uri'] else b['uri']} (TLS)",
                "state_text": "加密（仅对该浏览器有效）",
                "sees": "仅该 DoH 服务商",
            })

    # ---- 4. 谁能看到什么
    observers: list[dict] = []
    if state in ("plaintext", "unknown"):
        if gateways:
            observers.append({
                "name": f"路由器 / 网关 {gw_txt}", "level": "bad",
                "can_see": ["访问的域名", "查询时间", "你的内网 IP"],
                "note": "明文 UDP/53 直接经过网关，路由器固件、管理后台、蹭网者都能记录",
            })
        observers.append({
            "name": "运营商 / 上游网络", "level": "bad",
            "can_see": ["访问的域名", "访问频率", "可篡改返回结果"],
            "note": "跨网明文传输，可被记录、限速、注入广告页或直接返回错误 IP",
        })
        observers.append({
            "name": "同一 Wi-Fi 下的其他设备", "level": "warn",
            "can_see": ["访问的域名"],
            "note": "公共 Wi-Fi 下尤为明显，ARP 嗅探即可拿到你的全部查询",
        })
    elif state == "proxy":
        observers.append({
            "name": "本地代理软件", "level": "warn",
            "can_see": ["访问的域名", "连接目标"],
            "note": "代理接管后，域名先交给它，是否加密取决于它的上游配置",
        })
    else:
        observers.append({
            "name": "DoH 服务商", "level": "info",
            "can_see": ["访问的域名"],
            "note": "加密后只有解析器知道你查了什么，这是加密 DNS 的信任代价",
        })
        observers.append({
            "name": "运营商 / 路由器", "level": "ok",
            "can_see": [f"目标 IP {target}:443", "流量大小与时间"],
            "note": "只能看到你在连哪个解析器，看不到具体域名",
        })

    # ---- 5. 泄露清单
    leaks: list[dict] = []
    if state in ("plaintext", "unknown"):
        leaks.append({
            "title": "域名全量暴露", "severity": "critical",
            "detail": "你访问的每个域名都以明文出现，包括子域名和 API 端点（如 api.weixin.qq.com、passport.jd.com），"
                      "观察者不需要解密就能拼出你在用什么服务、看什么内容。",
        })
        leaks.append({
            "title": "可被静默篡改", "severity": "high",
            "detail": "中间人可以返回任意 IP，把页面导向广告页或钓鱼站；HTTPS 证书告警往往是唯一的提示。",
        })
        leaks.append({
            "title": "时间与频率画像", "severity": "medium",
            "detail": "查询时间和频率能推断作息、通勤、是否在家，比内容本身更容易被用于画像。",
        })
        leaks.append({
            "title": "可被精准封锁", "severity": "medium",
            "detail": "只对特定域名丢包或返回 NXDOMAIN，其他域名照常——本报告第 3 节能直接测出这种选择性拦截。",
        })
    if ecs["leaked"]:
        leaks.append({
            "title": f"网段泄露（ECS /{ecs['source']}）", "severity": "medium",
            "detail": f"当前解析器会把你的大致网段转发给权威服务器，{ecs['detail']}。",
        })
    if v6_leak:
        leaks.append({
            "title": "IPv6 旁路：IPv4 加密了，IPv6 还在明文", "severity": "high",
            "detail": f"网卡上的 IPv6 DNS 是 {', '.join(v6_public[:2])}，没有注册 DoH 模板，"
                      f"Windows 只能对它用明文 UDP/53。支持 IPv6 的应用会同时走这条通道，"
                      f"域名照样以明文送到路由器/运营商——加密 DNS 只覆盖了 IPv4，等于漏了一半。",
        })
    elif v6_weak:
        leaks.append({
            "title": "IPv6 DoH 模板在，但 443 连不上", "severity": "medium",
            "detail": f"{', '.join(x['ip'] for x in v6_status if x['reachable'] is False)} 的 443 端口不可达，"
                      f"Windows 会静默回落到明文 53。换个 IPv6 地址或修好 IPv6 出口。",
        })
    if state in ("encrypted_unproven", "auto_doh"):
        leaks.append({
            "title": "加密未证实，可能仍在明文回落", "severity": "medium",
            "detail": "Windows 只有在「服务器 IP 已注册模板 + 网卡开关打开 + 443 可达」三者同时成立时才走加密，"
                      "任一环失败都会静默回落到明文 53，配置存在不等于生效。",
        })

    # ---- 6. 评分（每一笔扣分都记下来，界面直接显示"为什么是这个分"）
    score = 100
    breakdown: list[dict] = []

    def _deduct(delta: int, label: str) -> None:
        nonlocal score
        score -= delta
        breakdown.append({"label": label, "delta": -delta})

    if state == "plaintext":
        _deduct(52, "DNS 仍是明文")
    elif state == "unknown":
        _deduct(34, "无法判断通道")
    elif state == "encrypted_unproven":
        _deduct(20, "加密已配置但未证实")
    elif state == "auto_doh":
        _deduct(20, "系统自动加密未证实")
    elif state == "proxy":
        _deduct(24, "代理接管，加密未知")
    if state != "encrypted" and not browser_enc:
        _deduct(8, "没有浏览器级加密兜底")
    if ecs["leaked"]:
        _deduct(10, f"上游泄露网段 ECS /{ecs['source']}")
    if v6_leak:
        _deduct(12, "IPv6 DNS 仍为明文")
    elif v6_weak:
        _deduct(6, "IPv6 DoH 的 443 不可达")
    score = max(0, min(100, score))
    exposure = "low" if score >= 85 else "medium" if score >= 65 else "high" if score >= 40 else "critical"
    exposure_label = {"low": "私密", "medium": "基本可控", "high": "部分暴露", "critical": "高度暴露"}[exposure]

    # ---- 7. 结论文字
    if state == "encrypted":
        headline = "DNS 已加密：链路上看不到你查了什么域名"
        summary = f"系统解析走 {target} 的加密通道（443/TLS），明文 53 已不是实际解析路径。"
    elif state == "plaintext":
        headline = "DNS 是明文的：谁都能看到你访问的每个域名"
        summary = (f"系统 DNS 为 {target}（{provider}），明文 53 端口可直连，"
                   f"查询会以未加密形式经过 {gw_txt} 和运营商。")
    elif state == "proxy":
        headline = "DNS 由本地代理接管：加不加密看代理配置"
        summary = (f"解析指向 {', '.join(local_live)}，查询在本机内完成、不出网卡，"
                   f"路由器和运营商看不到；但是否真正加密取决于代理软件的上游配置。")
    elif state == "encrypted_unproven":
        if not deep:
            headline = "加密 DNS 已配置，点「开始体检」验证是否真的生效"
            summary = "配置层已确认（DoH 模板与网卡开关都在），行为层要等完整体检才能下结论。"
        elif reach.get("tls_conn"):
            headline = "加密 DNS 已配置，且检测到 TLS 连接：大概率已生效"
            summary = (f"注册表里有 DoH 模板，并且存在到 {target}:443 的活动连接，"
                       f"这是 DoH 生效时的典型特征。")
        elif reach.get("plain_53"):
            headline = "配了加密 DNS，但没看到加密连接：很可能仍走明文"
            summary = (f"模板和开关都写进了注册表，可是没检测到 {target}:443 的加密连接，"
                       f"而明文 53 仍然通——Windows 正在静默回落到明文。")
        else:
            headline = "已配置加密 DNS，但还没有证据证明它真的生效"
            summary = "注册表里有 DoH 模板和开关，但行为层没测到加密特征，存在静默回落到明文 53 的可能。"
    elif state == "auto_doh":
        headline = "系统可能已自动升级到加密 DNS，但未证实"
        summary = f"Windows 自动 DoH 已开启，且 {target} 是已知支持 DoH 的解析器，实际通道需行为验证。"
    else:
        headline = "没有可用的 DNS 配置，无法判断是否加密"
        summary = "未读到有效的网卡 DNS 配置，请检查网络连接后重试。"

    evidence = []
    if enc_rows:
        evidence.append("行为层：" + "；".join(sorted({r["judge"]["reason"] for r in enc_rows}))[:180])
    if state == "proxy":
        evidence.append(f"解析器是 {target}（{provider}），由本机软件提供，查询不出网卡")
        evidence.append("真正是否加密取决于代理的上游（nameserver 写成 https:// 或 tls:// 才是加密）")
    else:
        if reach["plain_53"] is True:
            if state == "encrypted":
                evidence.append(f"明文 53 仍可直连 {target}，但系统实际没走这条路"
                                f"——所以「端口通不通」不能用来判断加密是否生效")
            else:
                evidence.append(f"明文 53 可达：{target} 对 UDP/53 有响应，说明明文通道仍然通")
        if reach["plain_53"] is False and target:
            evidence.append(f"明文 53 不可达：{target} 不响应 UDP/53，只能走加密通道")
        if reach["tls_conn"]:
            states = "/".join(reach.get("tls_states") or [])
            evidence.append(f"检测到 {len(reach['tls_conn'])} 条到 {target}:443 的 TCP 连接"
                            f"（{states}），是 DoH 走加密通道的直接特征")
        else:
            evidence.append(f"未检测到任何到 {target}:443 的 TCP 连接，DoH 大概率没被启用")
        if reach["doh_443"]:
            evidence.append(f"{target}:443 可达，具备开启 DoH 的网络条件")
        if reach["doh_443"] is False and target:
            evidence.append(f"{target}:443 不可达，即使配置了 DoH 也会回落明文")
    if doh_adapters:
        evidence.append(f"配置层：{len(doh_adapters)} 个网卡写有 DoH 模板 {doh_adapters[0].get('doh_template')}")
    elif IS_WIN:
        evidence.append("配置层：未发现网卡级 DoH 模板")

    if v6_public:
        for x in v6_status:
            if x["template"]:
                state6 = "已注册 DoH 模板" + ("，443 可达" if x["reachable"] else "，但 443 不可达")
            else:
                state6 = "未注册 DoH 模板，只能走明文 UDP/53"
            evidence.append(f"IPv6 DNS {x['ip']}：{state6}")
    elif v6_local:
        evidence.append(f"IPv6 DNS：{', '.join(v6_local)}（内网/本地地址，不出网卡）")
    else:
        evidence.append("IPv6 DNS：未配置，不会走 IPv6 明文通道")

    for ad in [a for a in adapters if (a["static"] or a["dhcp"])][:3]:
        flag = ad.get("doh_flags")
        evidence.append(
            f"{ad['name']}：DNS={','.join(ad['static'] or ad['dhcp'])}，"
            f"DoH 开关={'开' if flag in (1, 2) else '关/未设置'}"
            + (f"（DohFlags={flag}）" if flag is not None else ""))

    if IS_WIN:
        build = platform.version().split(".")[-1]
        try:
            build_no = int(build)
        except ValueError:
            build_no = 0
        evidence.append(f"系统：Windows {platform.release()} build {platform.version()}")
        if 0 < build_no < 19044:
            evidence.append("系统版本低于 Windows 10 21H2（build 19044），系统级 DoH 不被支持，"
                            "注册表写了也不会生效")
    if auto_doh is not None:
        evidence.append(f"配置层：系统自动 DoH（EnableAutoDoh）={auto_doh}"
                        + ("（已开启）" if auto_doh == 2 else "（未开启）"))
    for b in browsers:
        evidence.append(f"{b['app']}：DoH={b['mode']}" + (f"（{b['uri']}）" if b["uri"] else ""))

    # ---- 8. 建议
    advice: list[str] = []
    if state == "plaintext":
        advice.append("开启加密 DNS：设置 → 网络和 Internet → 以太网/WLAN → DNS 服务器分配 → 加密（DoH），"
                      "或直接用下面的「一键开启」")
        advice.append("只给浏览器开 DoH 不够：系统里其他应用（更新程序、客户端）仍在明文查询")
    if state == "proxy":
        advice.append("在代理软件里把 nameserver 改成 https:// 或 tls:// 形式，系统 DNS 设置不参与")
    if state in ("encrypted_unproven", "auto_doh"):
        advice.append("先在「设置 → 网络和 Internet → 属性 → DNS 服务器分配」里确认加密显示为已开启，"
                      "再重启 DNS 客户端服务（net stop dnscache & net start dnscache）后复查")
    if ecs["leaked"]:
        advice.append("换用不转发 ECS 的解析器（Cloudflare 1.1.1.1 / Quad9 9.9.9.9）可减少网段泄露")
    if v6_public and not v6_encrypted:
        advice.append("IPv6 的 DNS 也要一起加密：把网卡 IPv6 DNS 改成支持 DoH 的地址"
                      "（阿里 2400:3200::1 / 腾讯 2402:4e00::），或直接清空 IPv6 DNS，"
                      "让解析回落到已加密的 IPv4")
    if reach["doh_443"] is False and target:
        advice.append(f"{target}:443 被阻断，考虑换一个 443 可达的 DoH 服务商")
    if not advice:
        advice.append("当前解析通道已加密，保持即可；每月复查一次确认没有回落到明文")

    return {
        "state": state, "level": level, "label": label,
        "score": score, "exposure": exposure, "exposure_label": exposure_label,
        "breakdown": breakdown, "partial": not deep,
        "headline": headline, "summary": summary,
        "target": target, "provider": provider, "provider_doh": provider_doh,
        "gateways": gateways, "servers": servers,
        "channels": channels, "observers": observers, "leaks": leaks,
        "ecs": ecs, "reach": reach, "browsers": browsers,
        "v6_public": v6_public, "v6_local": v6_local, "v6_leak": v6_leak,
        "v6_encrypted": v6_encrypted, "v6_weak": v6_weak, "v6_status": v6_status,
        "evidence": evidence, "advice": advice,
        "auto_doh": auto_doh,
    }


# ---------------------------------------------------------------- 解析器体检
#
# 参考 dnsdiag(dnseval/dnsping) 与 dnscheck.tools 的做法：
#   · 延迟不只看平均，还要看抖动与丢包
#   · DNSSEC 用"故意签名错误"的域名做探针，能直接问出解析器到底验不验签
#   · EDE(RFC 8914) 让解析器自己说明失败原因，把"疑似拦截"升级成"明确拦截"

EDE_TEXT = {
    0: "其他原因", 1: "不支持的 DNSKEY 算法", 2: "不支持的 DS 摘要类型", 3: "返回了陈旧答案",
    4: "答案被伪造", 5: "DNSSEC 状态不确定", 6: "DNSSEC 签名无效（Bogus）", 7: "签名已过期",
    8: "签名尚未生效", 9: "缺少 DNSKEY", 10: "缺少 RRSIG", 11: "未设置 Zone Key 位",
    12: "缺少 NSEC 记录", 13: "缓存中的错误", 14: "解析器未就绪", 15: "被拦截",
    16: "被审查", 17: "被过滤", 18: "被禁止", 19: "陈旧的 NXDOMAIN 答案",
    20: "非权威应答", 21: "不支持该请求", 22: "权威服务器不可达", 23: "网络错误", 24: "数据无效",
}

# 服务商的 DoT 端点（IP, SNI）。腾讯的 DoT 在 dot.pub/1.12.12.12，不在 119.29.29.29 上
DOT_ENDPOINTS = {
    "223.5.5.5": ("223.5.5.5", "dns.alidns.com"),
    "119.29.29.29": ("1.12.12.12", "dot.pub"),
    "1.1.1.1": ("1.1.1.1", "one.one.one.one"),
    "8.8.8.8": ("8.8.8.8", "dns.google"),
    "9.9.9.9": ("9.9.9.9", "dns.quad9.net"),
    "114.114.114.114": ("114.114.114.114", None),
}

BENCH_RESOLVERS = [
    ("223.5.5.5", "阿里 AliDNS"),
    ("119.29.29.29", "腾讯 DNSPod"),
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("9.9.9.9", "Quad9"),
    ("114.114.114.114", "114DNS"),
]


def ede_text(ede: dict | None) -> str:
    if not ede:
        return ""
    label = EDE_TEXT.get(int(ede.get("code", -1)), f"代码 {ede.get('code')}")
    extra = (ede.get("text") or "").strip()
    return f"EDE {ede.get('code')} {label}" + (f"（{extra}）" if extra else "")


def ptr_of(ip: str, server: str = DEFAULT_PUBLIC_DNS) -> str:
    """反查解析器主机名：能看出是公共解析器还是运营商的 *.dial.* 地址"""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        res = dns_udp(server, rev, qtype=12, timeout=2.0)
        names = [a["data"] for a in res["answers"] if a["type"] == 12 and a["data"]]
        return names[0].rstrip(".") if names else ""
    except Exception:
        return ""


def check_dnssec(server: str, timeout: float = 3.0) -> dict:
    """用 dnssec-failed.org 判断解析器是否真的做 DNSSEC 验签"""
    info = {"tested": False, "validating": None, "ad": False, "detail": "", "ede": None}
    if not server:
        return info
    try:
        bad = dns_udp(server, "dnssec-failed.org", timeout=timeout)
    except Exception:
        info["detail"] = "探针域名无响应，无法判断 DNSSEC 能力"
        return info
    info["tested"] = True
    info["ede"] = bad.get("ede")
    try:
        good = dns_udp(server, "cloudflare.com", timeout=timeout)
        info["ad"] = bool(good.get("ad"))
    except Exception:
        pass

    if bad["rcode"] == 2:
        info["validating"] = True
        info["detail"] = "dnssec-failed.org 返回 SERVFAIL：解析器真的验签，篡改过的应答会被丢弃"
    elif bad["rcode"] == 0 and any(a["type"] == 1 for a in bad["answers"]):
        info["validating"] = False
        info["detail"] = "dnssec-failed.org 仍返回 A 记录：解析器不验 DNSSEC，伪造应答发现不了"
    else:
        info["detail"] = f"探针返回 rcode={bad['rcode']}，无法判定"
    return info


def probe_dot(ip: str, host: str | None = None, name: str = "example.com",
              timeout: float = 3.0) -> bool:
    """真的握一次 TLS 并发一条查询，比"853 端口开着"靠谱。

    host 是 SNI：部分 DoT 服务（如 dns.google）不带 SNI 会直接拒绝。
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 853), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                qid = random.randint(0, 0xFFFF)
                pkt = _build_query(qid, name, 1)
                tls.sendall(struct.pack("!H", len(pkt)) + pkt)
                head = tls.recv(2)
                if len(head) < 2:
                    return False
                want = struct.unpack("!H", head)[0]
                buf = b""
                while len(buf) < want:
                    chunk = tls.recv(want - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                return len(buf) >= 12
    except Exception:
        return False


def bench_resolver(ip: str, name: str, rounds: int = 3, timeout: float = 2.0) -> dict:
    """dnseval 式测量：首次查询做预热，之后取 avg/min/max/抖动/丢包"""
    domains = ["www.baidu.com", "www.qq.com", "www.taobao.com", "example.com"]
    rtts: list[float] = []
    lost = 0
    ede = None
    for i in range(rounds + 1):
        try:
            res = dns_udp(ip, domains[i % len(domains)], timeout=timeout)
            if i:
                rtts.append(float(res["rtt_ms"]))
            if res.get("ede") and not ede:
                ede = res["ede"]
        except Exception:
            if i:
                lost += 1
    avg = round(statistics.fmean(rtts), 1) if rtts else None

    doh_url = resolver_info(ip)[1]
    doh_ok, doh_note = False, ""
    if doh_url:
        try:
            doh_ok = bool(doh_query(doh_url, "example.com", timeout=3.0)["ips"])
        except Exception as exc:                               # noqa: BLE001
            msg = str(exc).upper()
            if "CERTIFICATE" in msg or "SSL" in msg:
                try:
                    doh_ok = bool(doh_query(doh_url, "example.com", timeout=3.0, insecure=True)["ips"])
                    doh_note = "证书校验失败"
                except Exception:
                    doh_note = "TLS 握手失败"
            else:
                doh_note = "不可用"

    return {
        "ip": ip, "name": name, "ok": bool(rtts),
        "avg": avg,
        "min": round(min(rtts), 1) if rtts else None,
        "max": round(max(rtts), 1) if rtts else None,
        "jitter": round(statistics.pstdev(rtts), 1) if len(rtts) > 1 else 0.0,
        "loss": int(round(100 * lost / max(1, rounds))),
        "samples": len(rtts),
        "ede": ede,
        "doh_ok": doh_ok,
        "doh_note": doh_note,
        "doh_url": doh_url,
        "dot_ok": probe_dot(*DOT_ENDPOINTS.get(ip, (ip, None))),
        "dot_target": DOT_ENDPOINTS.get(ip, (ip, None))[0],
        "ptr": ptr_of(ip),
    }


def analyze_resolvers(current: str | None, deep: bool = True,
                      proxied: bool = False) -> dict:
    if not deep:
        return {"rows": [], "dnssec": {}, "recommend": None, "current": current, "proxied": proxied}
    with ThreadPoolExecutor(max_workers=len(BENCH_RESOLVERS)) as pool:
        rows = list(pool.map(lambda item: bench_resolver(*item), BENCH_RESOLVERS))

    alive = [r for r in rows if r["ok"]]
    alive.sort(key=lambda r: (r["avg"] is None, r["avg"] or 999))
    dead = [r for r in rows if not r["ok"]]
    rows = alive + dead

    enc = [r for r in alive if r["doh_ok"]]
    recommend = min(enc, key=lambda r: r["avg"]) if enc else (alive[0] if alive else None)
    dnssec = check_dnssec(current) if current else {}
    return {
        "rows": rows, "current": current, "dnssec": dnssec, "proxied": proxied,
        "fastest": alive[0] if alive else None,
        "recommend": recommend,
        "encrypted_capable": len(enc),
    }


# ---------------------------------------------------------------- 体检主流程

def run_check(out: Out, use_html: bool = False, json_out: bool = False,
              extra_doh: list[str] | None = None, flush: bool = False,
              public_dns: str = DEFAULT_PUBLIC_DNS,
              progress=None) -> dict:
    started = datetime.now()
    out.raw(f"DNS Guard v{VERSION}  ·  DNS 劫持体检")
    out.raw(f"时间 {started:%Y-%m-%d %H:%M:%S}   系统 {platform.system()} {platform.release()}")

    if flush and IS_WIN:
        _run(["ipconfig", "/flushdns"], timeout=15)

    # ---- 1. 系统 DNS 配置
    out.title("1. 系统 DNS 配置")
    adapters = get_adapters()
    known_templates = get_known_doh_templates()

    all_servers: list[str] = []
    for ad in adapters:
        all_servers.extend(ad["static"] or ad["dhcp"])
    all_servers = list(dict.fromkeys(all_servers))

    with ThreadPoolExecutor(max_workers=max(1, len(all_servers))) as pool:
        liveness = dict(zip(all_servers, pool.map(probe_server, all_servers)))

    for ad in adapters:
        servers = ad["static"] or ad["dhcp"]
        mode = "手动" if ad["static"] else "DHCP 下发"
        out.item("info", f"{ad['name']}  ({mode})")
        for srv in servers:
            state = liveness.get(srv, {})
            if state.get("alive"):
                rtt = state.get("rtt_ms", 0)
                out.kv("DNS", f"{srv}  {out._c(f'可用 {rtt}ms', C_OK)}")
            else:
                out.kv("DNS", f"{srv}  {out._c('无响应（残留或不可达）', C_WARN)}")
        if ad.get("dns6"):
            out.kv("DNS(IPv6)", ", ".join(ad["dns6"])
                   + "  " + out._c("明文，未加密", C_WARN))
        if ad["gateway"]:
            out.kv("网关", ad["gateway"])
        if ad["doh_template"]:
            out.item("ok", f"已配置 DoH: {ad['doh_template']}  (DohFlags={ad['doh_flags']})")
        else:
            out.item("na", "未配置系统级 DoH（DohFlags 缺失）")

    proxy_ports = detect_local_proxy()
    if proxy_ports:
        out.item("warn", f"检测到本地端口监听: {', '.join(map(str, proxy_ports))}（可能是代理/DNS 转发软件）")

    live_servers = [s for s in all_servers if liveness.get(s, {}).get("alive")]
    local_live = [s for s in live_servers if s.startswith("127.") or ip_in(s, FAKE_IP_NETS)]
    local_dead = [s for s in all_servers if (s.startswith("127.") or ip_in(s, FAKE_IP_NETS))
                  and not liveness.get(s, {}).get("alive")]
    if local_live:
        out.item("warn", f"DNS 指向本机/虚拟地址 {', '.join(local_live)} 且可响应：解析由本地软件接管，系统级 DoH 通常无效")
    if local_dead:
        out.item("info", f"残留配置 {', '.join(local_dead)} 已无响应（软件已退出），当前不影响解析")

    # ---- 2. hosts
    out.title("2. hosts 文件")
    hosts = get_hosts_entries()
    suspicious_hosts = [h for h in hosts if not h[0].startswith(("127.", "0.0.0.0", "::1"))]
    if not hosts:
        out.item("ok", "无自定义映射")
    else:
        out.item("info", f"共 {len(hosts)} 条映射")
        for ip, host in hosts[:6]:
            out.kv(host, ip)
        if suspicious_hosts:
            out.item("warn", f"{len(suspicious_hosts)} 条指向非本机地址，请确认是否自己添加")
        else:
            out.item("ok", "均为本机回环映射，正常")

    # ---- 3. 交叉验证
    out.title("3. 解析一致性交叉验证")
    providers = dict(DOH_PROVIDERS)
    for idx, url in enumerate(extra_doh or []):
        providers[f"自定义{idx + 1}"] = url

    plain_server = next((s for s in live_servers
                         if not s.startswith("127.") and not ip_in(s, FAKE_IP_NETS)), None)
    if plain_server:
        out.note(f"本地 DNS 取 {plain_server}；公共明文 DNS 取 {public_dns}；加密基准 {len(providers)} 个")
    else:
        out.item("warn", "没有可用的本地明文 DNS，将只做系统解析与加密基准比对")

    # 解析器测速与域名比对互不依赖，丢到后台并行跑，省一半时间
    resolver_pool = ThreadPoolExecutor(max_workers=1)
    resolver_future = resolver_pool.submit(analyze_resolvers, plain_server, True, bool(local_live))

    rows: list[dict] = []
    total_steps = len(TEST_DOMAINS) + 4
    done_count = 0
    done_lock = threading.Lock()

    def check_domain(item):
        nonlocal done_count
        domain, kind = item
        sys_ips = resolve_system(domain)

        plain = {"ok": False, "ips": [], "rcode": None, "timeout": False}
        if plain_server:
            try:
                res = dns_udp(plain_server, domain, timeout=3.0)
                plain = {"ok": True, "rcode": res["rcode"],
                         "ips": [a["data"] for a in res["answers"] if a["type"] == 1 and a["data"]],
                         "timeout": False, "ede": res.get("ede")}
            except TimeoutError:
                plain = {"ok": False, "ips": [], "rcode": None, "timeout": True}
            except Exception:
                plain = {"ok": False, "ips": [], "rcode": None, "timeout": False}

        pub = {"ok": False, "ips": [], "rcode": None,
               "skipped": bool(public_dns and public_dns == plain_server)}
        if public_dns and public_dns != plain_server:
            try:
                res = dns_udp(public_dns, domain, timeout=3.0)
                pub = {"ok": True, "rcode": res["rcode"],
                       "ips": [a["data"] for a in res["answers"] if a["type"] == 1 and a["data"]]}
            except Exception:
                pass

        doh_results: dict[str, list[str]] = {}
        with ThreadPoolExecutor(max_workers=len(providers)) as pool:
            futs = {p: pool.submit(doh_query, tpl, domain) for p, tpl in providers.items()}
            for p, fut in futs.items():
                try:
                    doh_results[p] = fut.result(timeout=10)["ips"]
                except Exception:
                    doh_results[p] = []
        consensus, agreeing = consensus_of(doh_results)

        answered = [p for p, ips in doh_results.items() if ips]
        row = {"domain": domain, "kind": kind, "sys_ips": sys_ips, "plain": plain,
               "public": pub, "doh": doh_results, "consensus": consensus, "agreeing": agreeing,
               "consensus_unanimous": bool(answered) and len(agreeing) == len(answered),
               "proxy_takeover": bool(local_live)}
        row["judge"] = judge_domain(row)
        with done_lock:
            done_count += 1
            if progress:
                progress(done_count, total_steps, f"完成 {domain}")
        return row

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(check_domain, TEST_DOMAINS))

    head = (f"  {_fit('域名', 20)}{_fit('系统解析', 22)}{_fit('本地DNS', 16)}"
            f"{_fit('公共DNS', 16)}判定")
    out.raw(out._c(head, C_DIM))
    for row in rows:
        j = row["judge"]
        sys_txt = ",".join(row["sys_ips"][:2]) or "-"
        plain_txt = (",".join(row["plain"]["ips"][:1]) if row["plain"].get("ips")
                     else "超时" if row["plain"].get("timeout")
                     else f"rcode={row['plain']['rcode']}" if row["plain"].get("ok") else "-")
        pub_txt = (",".join(row["public"]["ips"][:1]) if row["public"].get("ips")
                   else "同本地" if row["public"].get("skipped")
                   else "超时" if row["public"] and not row["public"].get("ok") else "-")
        color = {"good": C_OK, "low": C_DIM, "info": C_DIM,
                 "medium": C_WARN, "high": C_BAD, "critical": C_BAD}.get(j["severity"], "")
        out.raw(f"  {_fit(row['domain'], 20)}{_fit(sys_txt, 22)}{_fit(plain_txt, 16)}"
                f"{_fit(pub_txt, 16)}{out._c(j['verdict'], color)}")
    out.note("normal=正常  doh_active/doh_probably=加密解析生效  plain_tampered/nxdomain_hijack/bogon=疑似劫持")
    out.note("selective_drop=本地DNS对该域名无响应而公共DNS正常（针对性拦截）")

    # ---- 4. DoH 状态
    out.title("4. DoH 是否真的生效")
    if progress:
        progress(len(TEST_DOMAINS), total_steps, "判定 DoH 状态")
    doh_status = judge_doh_status(adapters, local_live, local_dead, rows, plain_server)
    out.item(doh_status["level"], doh_status["headline"])
    for line in doh_status["details"]:
        out.note(line)

    # ---- 5. 隐私暴露（明文 or 加密）
    out.title("5. DNS 隐私暴露：你的查询是不是明文")
    if progress:
        progress(len(TEST_DOMAINS) + 1, total_steps, "分析隐私暴露面")
    privacy = analyze_privacy(adapters, liveness, rows, proxy_ports, local_live, plain_server)
    out.item(privacy["level"], privacy["headline"])
    out.kv("暴露等级", f"{privacy['exposure_label']}  ·  {privacy['score']}/100")
    out.kv("结论", privacy["summary"])
    for ch in privacy["channels"]:
        flag = "加密" if ch["encrypted"] else ("未知" if ch["encrypted"] is None else "明文")
        out.kv(f"通道·{ch['name']}", f"[{flag}] {ch['path']}")
    if privacy["observers"]:
        out.kv("谁能看到", "、".join(o["name"] for o in privacy["observers"]))
    if privacy["leaks"]:
        for leak in privacy["leaks"]:
            out.item("warn" if leak["severity"] != "critical" else "bad", f"{leak['title']}：{leak['detail']}")
    if privacy["ecs"]["tested"]:
        out.kv("ECS", privacy["ecs"]["detail"])
    for line in privacy["evidence"]:
        out.note("证据 · " + line)

    # ---- 6. 解析器体检（DNSSEC / 测速 / 能力）
    out.title("6. 解析器体检：DNSSEC、延迟与加密能力")
    if progress:
        progress(len(TEST_DOMAINS) + 3, total_steps, "测量各解析器")
    try:
        resolvers = resolver_future.result(timeout=120)
    except Exception:
        resolvers = analyze_resolvers(plain_server, proxied=bool(local_live))
    finally:
        resolver_pool.shutdown(wait=False)
    ds = resolvers.get("dnssec") or {}
    if ds.get("tested"):
        out.item("ok" if ds.get("validating") else "warn", ds.get("detail", ""))
        if ds.get("ede"):
            out.note(ede_text(ds["ede"]))
    else:
        out.item("info", ds.get("detail", "无法判断 DNSSEC 能力"))
    if resolvers.get("proxied"):
        out.note("当前解析经代理接管，下面的延迟只代表本机到代理，不代表真实解析器速度")

    head = (f"  {_fit('解析器', 24)}{_fit('平均', 9)}{_fit('抖动', 9)}"
            f"{_fit('丢包', 8)}{_fit('DoH', 6)}DoT")
    out.raw(out._c(head, C_DIM))
    for r in resolvers.get("rows", []):
        label = f"{r['name']} {r['ip']}"
        if r["ok"]:
            line = (f"  {_fit(label, 24)}{_fit(str(r['avg']) + 'ms', 9)}"
                    f"{_fit(str(r['jitter']) + 'ms', 9)}{_fit(str(r['loss']) + '%', 8)}"
                    f"{_fit('可用' if r['doh_ok'] else '-', 6)}{'可用' if r['dot_ok'] else '-'}")
        else:
            line = f"  {_fit(label, 24)}{_fit('无响应', 9)}"
        out.raw(line)
    out.note("DoH 走 443（HTTPS），DoT 走 853（TLS 专口）；853 常被网络拦截，显示 - 不代表服务商不支持")
    out.note("DoT 按各家自己的端点实测：腾讯在 dot.pub(1.12.12.12)，不在 119.29.29.29 上")
    rec = resolvers.get("recommend")
    if rec:
        out.item("ok", f"推荐 {rec['name']}（{rec['ip']}，{rec['avg']}ms"
                       f"{'，支持 DoH' if rec['doh_ok'] else ''}）")

    res_advice: list[str] = []
    if ds.get("validating") is False:
        res_advice.append("当前解析器不验证 DNSSEC，换 Cloudflare(1.1.1.1) 或 Quad9(9.9.9.9) "
                          "可让伪造应答被直接丢弃")
    if rec and plain_server and rec["ip"] != plain_server:
        res_advice.append(f"实测 {rec['name']}（{rec['ip']}）延迟最低且支持 DoH，可考虑换用")
    blocked = [r["domain"] for r in rows
               if int((r["plain"].get("ede") or {}).get("code", 0)) in (15, 16, 17, 18)]
    if blocked:
        res_advice.append(f"{len(blocked)} 个域名被解析器明确标记为拦截（EDE），属主动过滤而非网络故障")

    # ---- 7. 结论
    out.title("7. 结论")
    score, level = score_findings(rows, hosts)
    color = C_OK if score >= 90 else C_WARN if score >= 70 else C_BAD
    out.raw(f"  抗劫持评分: {out._c(f'{score}/100  {level}', color)}")
    pv_color = {"ok": C_OK, "warn": C_WARN, "bad": C_BAD}.get(privacy["level"], C_DIM)
    pv_text = f"{privacy['score']}/100  {privacy['exposure_label']}"
    out.raw(f"  隐私评分: {out._c(pv_text, pv_color)}")
    if privacy.get("breakdown"):
        parts = "  ".join(f"{b['delta']:+d} {b['label']}" for b in privacy["breakdown"])
        out.note(f"评分构成: 100  {parts}  = {privacy['score']}")

    bad = [r for r in rows if r["judge"]["severity"] in ("high", "critical")]
    if bad:
        out.item("bad", f"{len(bad)} 个域名出现异常特征:")
        for r in bad:
            out.kv(r["domain"], r["judge"]["reason"])
    else:
        out.item("ok", "未发现明确的 DNS 劫持特征")

    tips = (build_advice(rows, doh_status, proxy_ports, local_live)
            + privacy["advice"] + res_advice)
    has_bad = any(r["judge"]["severity"] in ("high", "critical") for r in rows)
    if privacy["state"] != "encrypted" or has_bad:
        tips = [t for t in tips if "当前配置健康" not in t]
    for tip in tips:
        out.raw(f"  · {tip}")

    if progress:
        progress(total_steps, total_steps, "生成报告")

    payload = {
        "version": VERSION, "time": started.isoformat(timespec="seconds"),
        "score": score, "level": level, "adapters": adapters, "hosts": hosts,
        "proxy_ports": proxy_ports, "doh_status": doh_status, "rows": rows,
        "liveness": liveness, "plain_server": plain_server, "public_dns": public_dns,
        "privacy": privacy, "resolvers": resolvers,
        "advice": tips,
    }
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = started.strftime("%Y%m%d_%H%M%S")
    if json_out:
        path = os.path.join(REPORT_DIR, f"report_{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
        out.raw(f"\n  JSON 报告: {path}")
    if use_html:
        path = os.path.join(REPORT_DIR, f"report_{stamp}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(payload))
        out.raw(f"  HTML 报告: {path}")
    return payload


def judge_doh_status(adapters, local_live, local_dead, rows, plain_server) -> dict:
    configured = [a for a in adapters if a.get("doh_template")]
    evidence = []
    if any(r["judge"]["verdict"] == "doh_active" for r in rows):
        evidence.append("行为层：系统结果与加密基准一致，且与明文 DNS 不同")
    if any(r["judge"]["verdict"] == "doh_probably" for r in rows):
        evidence.append("行为层：明文 DNS 不可达，系统仍能解析")

    if local_live:
        return {"state": "proxy", "level": "warn",
                "headline": "DNS 被本地软件接管，系统级 DoH 开关不影响实际解析",
                "details": [f"当前生效 DNS：{', '.join(local_live)}",
                            "这类地址由代理/DNS 转发软件提供，是否加密取决于该软件自身的配置",
                            "验证方法：在该软件的配置里看 nameserver/upstream 是否写成 https:// 或 tls://"],
                "evidence": evidence}
    if configured:
        if evidence:
            return {"state": "active", "level": "ok",
                    "headline": "DoH 已配置且行为层验证通过",
                    "details": [f"模板：{configured[0]['doh_template']}"] + evidence,
                    "evidence": evidence}
        if plain_server:
            return {"state": "configured_unproven", "level": "warn",
                    "headline": "DoH 已配置，但行为层无法证明（明文与加密结果相同，属正常）",
                    "details": [f"模板：{configured[0]['doh_template']}",
                                f"明文 DNS {plain_server} 仍可直连且结果与加密一致，无法从结果区分通道",
                                "建议：把 DNS 指向只允许 DoH 的地址后再测，观察 443 是否可达而 53 不可达"],
                    "evidence": evidence}
        return {"state": "configured_no_plain", "level": "ok",
                "headline": "DoH 已配置，明文 DNS 不可达 -> 实际只能走加密通道",
                "details": [f"模板：{configured[0]['doh_template']}"], "evidence": evidence}
    if evidence:
        return {"state": "implicit", "level": "ok",
                "headline": "系统未配置 DoH，但行为显示解析走的是加密通道",
                "details": evidence, "evidence": evidence}
    details = ["明文 DNS（UDP 53）可被链路中间人直接查看和篡改",
               "开启：python dnsguard.py doh on --url <你的DoH地址> --ip <该服务IP>"]
    if local_dead:
        details.insert(0, f"存在残留配置 {', '.join(local_dead)}，建议先清理")
    return {"state": "off", "level": "bad",
            "headline": "未检测到 DoH 生效迹象，DNS 仍为明文",
            "details": details, "evidence": evidence}


def build_advice(rows, doh_status, proxy_ports, local_live) -> list[str]:
    advice = []
    drops = [r["domain"] for r in rows if r["judge"]["verdict"] == "selective_drop"]
    if drops:
        advice.append(f"{', '.join(drops)} 在本地 DNS 上被静默丢弃：换用加密 DNS 后可绕过该拦截")
    if doh_status["state"] == "off":
        advice.append("开启 DoH 后重新体检，确认第 4 节变成「已验证通过」")
    if doh_status["state"] == "proxy":
        advice.append("代理接管时应在代理软件里配置 nameserver，而不是改 Windows 设置")
    if any(r["judge"]["verdict"] == "bogon" for r in rows):
        advice.append("出现非公网地址解析，优先排查路由器 DNS 与 hosts，其次联系运营商")
    if not advice:
        advice.append("未发现明确劫持特征，建议每月跑一次体检")
    return advice


# ---------------------------------------------------------------- DoH 开关

def _backup_state(target_ip: str) -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(BACKUP_DIR, f"doh_backup_{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"time": stamp, "target_ip": target_ip, "adapters": get_adapters(),
                   "known_templates": get_known_doh_templates()}, fh,
                  ensure_ascii=False, indent=2, default=str)
    return path


def _pick_targets(adapters: list[dict], only: str | None = None) -> tuple[list[dict], list[dict]]:
    """只对"DNS 服务器能应答"的网卡下手，避免污染未连接的网卡配置"""
    candidates = [a for a in adapters if a["static"] or a["dhcp"]]
    if only:
        candidates = [a for a in candidates if only.lower() in a["name"].lower()] or candidates
    live, dead = [], []
    for ad in candidates:
        servers = ad["static"] or ad["dhcp"]
        alive = any(probe_server(s, 1.5).get("alive") for s in servers)
        (live if alive else dead).append(ad)
    return (live or dead), dead


def doh_enable(url: str, ip: str, out: Out, assume_yes: bool = False,
               dry_run: bool = False, only: str | None = None,
               ip6: str | None = None) -> int:
    if not re.match(r"^https://[^\s]+$", url):
        out.item("bad", "DoH 地址必须以 https:// 开头")
        return 2
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        out.item("bad", f"DNS 服务器 IP 不合法: {ip}")
        return 2
    if not IS_WIN:
        out.item("bad", "当前版本仅支持 Windows 系统级 DoH 配置")
        return 2

    if ip6 is None:
        ip6 = resolve_doh_ipv6(ip, url)
    if ip6:
        try:
            if ipaddress.ip_address(ip6).version != 6:
                raise ValueError
        except ValueError:
            out.item("bad", f"IPv6 地址不合法: {ip6}")
            return 2

    adapters = get_adapters()
    targets, dead = _pick_targets(adapters, only)
    out.title("DoH 一键开启 · 执行计划")
    out.kv("DoH 地址", url)
    out.kv("DNS 服务器", ip)
    out.kv("IPv6 服务器", ip6 or "不配置（IPv6 仍为明文）")
    out.kv("影响网卡", ", ".join(a["name"] for a in targets) or "无")
    if dead:
        out.kv("跳过网卡", ", ".join(a["name"] for a in dead) + "（DNS 无响应，视为未连接）")
    out.kv("备份目录", BACKUP_DIR)
    out.raw("  步骤：备份 -> 注册 DoH 模板 -> 写网卡 DoH 开关 -> 设网卡 DNS -> 刷缓存 -> 验证")

    if dry_run:
        out.item("info", "dry-run 模式，未做任何修改")
        return 0
    if not is_admin():
        out.item("bad", "需要管理员权限，请以管理员身份运行终端后重试")
        out.note(f"手动路径：设置 -> 网络和 Internet -> 网卡 -> DNS 服务器分配 -> 加密 -> {url}")
        return 3
    if not assume_yes and input("  确认执行? 输入 yes 继续: ").strip().lower() != "yes":
        out.item("info", "已取消")
        return 1

    backup = _backup_state(ip)
    out.item("ok", f"已备份当前配置: {backup}")

    import winreg
    wk = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\%s" % ip
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, wk, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "DohTemplate", 0, winreg.REG_SZ, url)
        out.item("ok", f"已注册 DoH 模板 -> {ip}")
    except OSError as exc:
        out.item("bad", f"注册 DoH 模板失败: {exc}")
        return 4

    if ip6:
        wk6 = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\%s" % ip6
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, wk6, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "DohTemplate", 0, winreg.REG_SZ, url)
            out.item("ok", f"已注册 DoH 模板 -> {ip6}")
        except OSError as exc:
            out.item("warn", f"注册 IPv6 DoH 模板失败: {exc}")

    for ad in targets:
        path = (r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                r"\DohInterfaceSettings\Doh\%s" % ad["guid"])
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "DohFlags", 0, winreg.REG_QWORD, 1)
                winreg.SetValueEx(key, "DohTemplate", 0, winreg.REG_SZ, url)
            out.item("ok", f"{ad['name']}: DoH 开关已写入")
        except OSError as exc:
            out.item("warn", f"{ad['name']}: 写 DoH 开关失败 {exc}")

    for ad in targets:
        if ad.get("index") is not None:
            _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                  f"name={ad['index']}", "source=static", f"address={ip}", "register=primary"])
        reg_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % ad["guid"]
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "NameServer", 0, winreg.REG_SZ, ip)
        except OSError:
            pass
        if ip6:
            if ad.get("index") is not None:
                _run(["netsh", "interface", "ipv6", "set", "dnsservers",
                      f"name={ad['index']}", "source=static", f"address={ip6}", "register=primary"])
            reg6 = (r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
                    r"\Interfaces\%s" % ad["guid"])
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg6, 0, winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "NameServer", 0, winreg.REG_SZ, ip6)
            except OSError:
                pass
            out.item("ok", f"{ad['name']}: IPv6 DNS 已设为 {ip6}")

    _run(["ipconfig", "/flushdns"], timeout=15)
    _run(["net", "stop", "dnscache"], timeout=20)
    _run(["net", "start", "dnscache"], timeout=20)
    out.item("ok", "已刷新缓存并重启 DNS 客户端服务")

    out.title("验证")
    return verify_doh(url, ip, out)


def verify_doh(url: str, ip: str, out: Out) -> int:
    adapters = get_adapters()
    hits = [a for a in adapters if (a.get("doh_template") or "") == url]
    if hits:
        out.item("ok", f"配置层：{len(hits)} 个网卡已记录模板 {url}")
    else:
        out.item("bad", "配置层：未找到对应 DoH 模板，写入可能失败")
        return 5

    active = False
    for domain in ("www.baidu.com", "www.qq.com", "github.com"):
        sys_ips = resolve_system(domain)
        try:
            plain = dns_udp(ip, domain, timeout=3.0)
            plain_ips = [a["data"] for a in plain["answers"] if a["type"] == 1]
            plain_ok = True
        except Exception:
            plain_ips, plain_ok = [], False
        try:
            base = doh_query(DOH_PROVIDERS["AliDNS"], domain)["ips"]
        except Exception:
            base = []

        if sys_ips and not plain_ok:
            out.item("ok", f"行为层：{domain} 明文不可达但系统仍解析成功 -> 加密通道生效")
            active = True
        elif sys_ips and plain_ok and base and (set(sys_ips) & set(base)) and not (set(plain_ips) & set(base)):
            out.item("ok", f"行为层：{domain} 系统结果等于加密基准、异于明文 -> 加密通道生效")
            active = True
        elif sys_ips and plain_ok and set(sys_ips) == set(plain_ips):
            out.item("warn", f"行为层：{domain} 系统结果与明文一致，无法证明加密生效")
        else:
            out.item("info", f"行为层：{domain} 结果不具区分度")

    if active:
        out.item("ok", "结论：DoH 已生效")
        return 0
    out.item("warn", "结论：配置已写入但行为层无法证明，建议重启后再测")
    return 1


def doh_disable(out: Out) -> int:
    if not IS_WIN:
        return 2
    if not is_admin():
        out.item("bad", "需要管理员权限")
        return 3
    backups = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith("doh_backup_")) \
        if os.path.isdir(BACKUP_DIR) else []
    if not backups:
        out.item("bad", "找不到备份文件，无法自动回滚")
        return 4
    path = os.path.join(BACKUP_DIR, backups[-1])
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out.title(f"回滚到 {data['time']}")
    out.kv("备份", path)

    import winreg
    for ad in data.get("adapters", []):
        static = ad.get("static") or []
        guid = ad["guid"]
        if ad.get("index") is not None:
            if static:
                _run(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={ad['index']}",
                      "source=static", f"address={static[0]}", "register=primary"])
            else:
                _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                      f"name={ad['index']}", "source=dhcp"])
        reg_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % guid
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "NameServer", 0, winreg.REG_SZ, " ".join(static))
        except OSError:
            pass

        v6 = ad.get("dns6") or []
        if ad.get("index") is not None:
            if v6:
                _run(["netsh", "interface", "ipv6", "set", "dnsservers",
                      f"name={ad['index']}", "source=static",
                      f"address={v6[0]}", "register=primary"])
            else:
                _run(["netsh", "interface", "ipv6", "set", "dnsservers",
                      f"name={ad['index']}", "source=dhcp"])
        reg6 = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\%s" % guid
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg6, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "NameServer", 0, winreg.REG_SZ, " ".join(v6))
        except OSError:
            pass
        if v6:
            out.item("ok", f"{ad['name']}: IPv6 DNS 已恢复为 {v6[0]}")
        doh_path = (r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                    r"\DohInterfaceSettings\Doh\%s" % guid)
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, doh_path)
        except OSError:
            pass
        out.item("ok", f"{ad['name']}: 已恢复")

    _run(["ipconfig", "/flushdns"], timeout=15)
    _run(["net", "stop", "dnscache"], timeout=20)
    _run(["net", "start", "dnscache"], timeout=20)
    out.item("ok", "已回滚并刷新缓存")
    return 0


# ---------------------------------------------------------------- HTML 报告

def render_html(payload: dict) -> str:
    rows = payload["rows"]
    score = payload["score"]
    color = "#0f9d58" if score >= 90 else "#e8a33d" if score >= 70 else "#d93025"
    trs = []
    for r in rows:
        j = r["judge"]
        badge = {"good": "#0f9d58", "low": "#6b7280", "info": "#6b7280",
                 "medium": "#e8a33d", "high": "#d93025", "critical": "#d93025"}[j["severity"]]
        sys_txt = "<br>".join(r["sys_ips"][:3]) or "-"
        p = r["plain"]
        plain_txt = "<br>".join(p.get("ips", [])[:2]) if p.get("ips") else ("超时" if p.get("timeout") else f"rcode={p.get('rcode')}")
        pb = r["public"]
        pub_txt = "<br>".join(pb.get("ips", [])[:2]) if pb.get("ips") else "超时"
        trs.append(f"<tr><td><b>{r['domain']}</b></td><td>{sys_txt}</td><td>{plain_txt}</td>"
                   f"<td>{pub_txt}</td><td><span class='badge' style='background:{badge}'>{j['verdict']}</span>"
                   f"<div class='why'>{j['reason']}</div></td></tr>")
    doh = payload["doh_status"]
    adapters_html = "".join(
        f"<div>{a['name']}：{' '.join(a['static'] or a['dhcp']) or '无'}"
        f"{'（DoH: ' + a['doh_template'] + '）' if a.get('doh_template') else ''}</div>"
        for a in payload["adapters"])

    pv = payload.get("privacy") or {}
    pv_color = {"ok": "#0f9d58", "warn": "#e8a33d", "bad": "#d93025", "info": "#6b7280"}.get(pv.get("level"), "#6b7280")
    pv_channels = "".join(
        f"<li><b>{c['name']}</b> — {c['state_text']}<div class='why'>{c['path']}</div></li>"
        for c in pv.get("channels", []))
    pv_observers = "".join(
        f"<li><b>{o['name']}</b>（能看到：{'、'.join(o['can_see'])}）<div class='why'>{o['note']}</div></li>"
        for o in pv.get("observers", []))
    pv_leaks = "".join(
        f"<li><b>{leak['title']}</b><div class='why'>{leak['detail']}</div></li>"
        for leak in pv.get("leaks", [])) or "<li>没有发现明文泄露点</li>"
    pv_evidence = "".join(f"<li>{e}</li>" for e in pv.get("evidence", []))
    advice_html = "".join(f"<li>{a}</li>" for a in payload.get("advice", []))

    rs = payload.get("resolvers") or {}
    ds = rs.get("dnssec") or {}
    dnssec_txt = (("验证中" if ds.get("validating") else "不验证")
                  if ds.get("tested") else "未知")
    dnssec_color = "#0f9d58" if ds.get("validating") else "#e8a33d"
    res_rows = "".join(
        f"<tr><td><b>{r['name']}</b><div class='why'>{r['ip']}"
        f"{(' · ' + r['ptr']) if r.get('ptr') else ''}</div></td>"
        f"<td>{r['avg']} ms</td><td>{r['jitter']} ms</td><td>{r['loss']}%</td>"
        f"<td>{'✓' if r['doh_ok'] else '—'}</td><td>{'✓' if r['dot_ok'] else '—'}</td></tr>"
        for r in rs.get("rows", []) if r.get("ok"))

    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS 体检报告</title><style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f7f8fa;color:#1f2328;margin:0;padding:32px 16px}}
.wrap{{max-width:1000px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:28px 32px}}
h1{{font-size:20px;margin:0 0 4px}} .meta{{color:#6b7280;font-size:13px}}
.score{{display:flex;align-items:baseline;gap:10px;margin:20px 0 4px}}
.score b{{font-size:42px;color:{color};line-height:1}} .score span{{color:#6b7280;font-size:14px}}
h2{{font-size:15px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #eef0f3}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;color:#6b7280;font-weight:500;padding:8px 6px;border-bottom:1px solid #eef0f3}}
td{{padding:10px 6px;border-bottom:1px solid #f3f4f6;vertical-align:top;font-variant-numeric:tabular-nums}}
.badge{{color:#fff;font-size:11px;padding:2px 8px;border-radius:20px;white-space:nowrap}}
.why{{color:#6b7280;font-size:12px;margin-top:5px;line-height:1.5}}
.card{{background:#f9fafb;border:1px solid #eef0f3;border-radius:10px;padding:14px 16px;font-size:13px;line-height:1.8}}
.privacy{{border-left:4px solid {pv_color};background:#fbfcfd;border-radius:10px;padding:16px 18px;margin:8px 0 0}}
.privacy .big{{font-size:16px;font-weight:600;color:{pv_color}}}
.privacy .sub{{color:#4b5563;font-size:13px;margin-top:6px;line-height:1.7}}
.pill{{display:inline-block;background:#eef2f7;color:#374151;font-size:11px;padding:2px 9px;border-radius:20px;margin-right:6px}}
ul{{margin:6px 0 0 18px;padding:0}} li{{margin:4px 0}}
</style></head><body><div class="wrap">
<h1>DNS 体检报告</h1>
<div class="meta">{payload['time']} · DNS Guard v{payload['version']} · by parkerli</div>
<div class="score"><b>{score}</b><span>/100 · {payload['level']} · 抗劫持评分</span></div>

<h2>隐私暴露：你的 DNS 是明文吗</h2>
<div class="privacy">
  <div class="big">{pv.get('headline', '')}</div>
  <div class="sub">{pv.get('summary', '')}</div>
  <div style="margin-top:10px">
    <span class="pill">暴露等级 {pv.get('exposure_label', '-')}</span>
    <span class="pill">隐私评分 {pv.get('score', '-')}/100</span>
    <span class="pill">当前解析器 {pv.get('target') or '未知'} · {pv.get('provider', '')}</span>
  </div>
  {('<div class="why" style="margin-top:8px">隐私评分构成：100 '
    + '  '.join(f"{b['delta']:+d} {b['label']}" for b in pv.get('breakdown') or [])
    + f" = {pv.get('score')}</div>") if pv.get('breakdown') else ''}
</div>

<h2>解析通道</h2><div class="card"><ul>{pv_channels}</ul></div>
<h2>谁能看到你在访问什么</h2><div class="card"><ul>{pv_observers}</ul></div>
<h2>泄露了什么</h2><div class="card"><ul>{pv_leaks}</ul></div>
<h2>判定证据</h2><div class="card"><ul>{pv_evidence}</ul></div>

<h2>DoH 状态</h2>
<div class="card"><b>{doh['headline']}</b><ul>{''.join(f'<li>{d}</li>' for d in doh['details'])}</ul></div>
<h2>解析器体检</h2>
<div class="card">
  <div><b style="color:{dnssec_color}">DNSSEC：{dnssec_txt}</b>
    <div class="why">{ds.get('detail', '未测试')}</div></div>
</div>
<table style="margin-top:10px"><thead><tr><th>解析器</th><th>平均</th><th>抖动</th><th>丢包</th><th>DoH</th><th>DoT</th></tr></thead>
<tbody>{res_rows}</tbody></table>

<h2>解析一致性交叉验证</h2>
<table><thead><tr><th>域名</th><th>系统解析</th><th>本地 DNS</th><th>公共 DNS</th><th>判定</th></tr></thead>
<tbody>{''.join(trs)}</tbody></table>
<h2>系统 DNS 配置</h2><div class="card">{adapters_html}</div>
<h2>建议</h2><div class="card"><ul>{advice_html}</ul></div>
<div class="meta" style="margin-top:22px;text-align:center;font-size:11.5px;color:#98a0ad">
  DNS Guard v{payload['version']} · © parkerli</div>
</div></body></html>"""


# ---------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="关闭彩色输出")

    parser = argparse.ArgumentParser(prog="dnsguard", parents=[common],
                                     description="DNS 劫持体检 + 一键 DoH 助手")
    sub = parser.add_subparsers(dest="cmd")

    p_check = sub.add_parser("check", parents=[common], help="体检（默认）")
    p_check.add_argument("--html", action="store_true", help="生成 HTML 报告")
    p_check.add_argument("--json", action="store_true", help="生成 JSON 报告")
    p_check.add_argument("--flush", action="store_true", help="体检前清空 DNS 缓存")
    p_check.add_argument("--public-dns", default=DEFAULT_PUBLIC_DNS, help="公共明文 DNS，用于对照")
    p_check.add_argument("--doh-baseline", action="append", default=[], help="追加自定义 DoH 基准")

    p_doh = sub.add_parser("doh", parents=[common], help="DoH 开关")
    p_doh_sub = p_doh.add_subparsers(dest="action")
    p_on = p_doh_sub.add_parser("on", parents=[common], help="一键开启")
    p_on.add_argument("--url", required=True, help="DoH 地址，如 https://dns.alidns.com/dns-query")
    p_on.add_argument("--ip", required=True, help="该 DoH 服务对应的 DNS 服务器 IP，如 223.5.5.5")
    p_on.add_argument("--yes", action="store_true", help="跳过交互确认")
    p_on.add_argument("--iface", default=None, help="只对名称匹配的网卡生效，如 --iface WLAN")
    p_on.add_argument("--ip6", default=None,
                      help="同时配置的 IPv6 DNS（默认按内置表自动匹配，传 none 则跳过 IPv6）")
    p_on.add_argument("--dry-run", action="store_true", help="只打印计划，不修改")
    p_doh_sub.add_parser("off", parents=[common], help="回滚到最近一次备份")

    p_verify = sub.add_parser("verify", parents=[common], help="验证 DoH 是否生效")
    p_verify.add_argument("--url", required=True)
    p_verify.add_argument("--ip", required=True)

    args = parser.parse_args(argv)
    no_color = getattr(args, "no_color", False)
    out = Out(color=not no_color and sys.stdout.isatty())

    if args.cmd in (None, "check"):
        run_check(out, use_html=getattr(args, "html", False), json_out=getattr(args, "json", False),
                  extra_doh=getattr(args, "doh_baseline", []), flush=getattr(args, "flush", False),
                  public_dns=getattr(args, "public_dns", DEFAULT_PUBLIC_DNS))
        return 0
    if args.cmd == "doh":
        if args.action == "on":
            ip6 = args.ip6
            if ip6 and ip6.lower() in ("none", "no", "off", ""):
                ip6 = ""
            return doh_enable(args.url, args.ip, out, assume_yes=args.yes,
                              dry_run=args.dry_run, only=args.iface, ip6=ip6)
        if args.action == "off":
            return doh_disable(out)
        p_doh.print_help()
        return 2
    if args.cmd == "verify":
        return verify_doh(args.url, args.ip, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
