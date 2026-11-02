#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsguard_app.py — DNS Guard 可视化界面

本机起一个只监听 127.0.0.1 的小服务，用浏览器当界面。
不依赖 tkinter / 不依赖任何第三方包，PyInstaller 打包后双击即用。

  python dnsguard_app.py              # 打开界面
  python dnsguard_app.py --no-browser # 只起服务，自己开浏览器
  python dnsguard_app.py --port 8899  # 指定端口
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import dnsguard as dg

APP_NAME = "DNS Guard"


# ---------------------------------------------------------------- 任务状态

class Job:
    """同一时刻只跑一个任务（体检 / 开启 DoH / 回滚），前端轮询取进度"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.kind = ""
        self.status = "idle"          # idle | running | done | error
        self.progress = 0
        self.total = 1
        self.label = ""
        self.log: list[str] = []
        self.payload: dict | None = None
        self.error = ""

    def start(self, kind: str, total: int = 1) -> None:
        with self.lock:
            self.kind = kind
            self.status = "running"
            self.progress = 0
            self.total = max(1, total)
            self.label = ""
            self.log = []
            self.payload = None
            self.error = ""

    def push(self, text: str) -> None:
        with self.lock:
            self.log.append(text)
            if len(self.log) > 600:
                del self.log[:200]

    def set_progress(self, done: int, total: int, label: str = "") -> None:
        with self.lock:
            self.progress = done
            self.total = max(1, total)
            if label:
                self.label = label

    def finish(self, payload: dict | None = None) -> None:
        with self.lock:
            self.status = "done"
            self.progress = self.total
            self.payload = payload

    def fail(self, message: str) -> None:
        with self.lock:
            self.status = "error"
            self.error = message

    def snapshot(self, since: int = 0) -> dict:
        with self.lock:
            return {
                "kind": self.kind, "status": self.status,
                "progress": self.progress, "total": self.total, "label": self.label,
                "log": self.log[since:], "log_total": len(self.log),
                "payload": self.payload, "error": self.error,
            }


JOB = Job()
LAST: dict = {}
LAST_LOCK = threading.Lock()


class JobOut(dg.Out):
    """把终端输出接到任务日志里，界面可以实时看到每一步"""

    def __init__(self, job: Job) -> None:
        super().__init__(color=False)
        self.job = job

    def raw(self, text: str = "") -> None:
        self.job.push(text)


# ---------------------------------------------------------------- 业务动作

def quick_state() -> dict:
    adapters = dg.get_adapters()
    servers: list[str] = []
    for ad in adapters:
        for srv in (ad["static"] or ad["dhcp"]):
            if srv not in servers:
                servers.append(srv)

    liveness: dict[str, dict] = {}
    if servers:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(8, len(servers))) as pool:
            liveness = dict(zip(servers, pool.map(lambda s: dg.probe_server(s, 1.2), servers)))

    live = [s for s in servers if liveness.get(s, {}).get("alive")]
    local_live = [s for s in live if s.startswith("127.") or dg.ip_in(s, dg.FAKE_IP_NETS)]
    plain_server = next((s for s in live
                         if not s.startswith("127.") and not dg.ip_in(s, dg.FAKE_IP_NETS)), None)
    proxy_ports = dg.detect_local_proxy()

    privacy = dg.analyze_privacy(adapters, liveness, [], proxy_ports, local_live,
                                 plain_server, deep=False)
    return {
        "version": dg.VERSION,
        "admin": dg.is_admin(),
        "adapters": adapters,
        "servers": servers,
        "live": live,
        "proxy_ports": proxy_ports,
        "plain_server": plain_server,
        "privacy": privacy,
        "backup_available": _has_backup(),
        "report_dir": dg.REPORT_DIR,
    }


def _has_backup() -> bool:
    try:
        return any(f.startswith("doh_backup_") for f in os.listdir(dg.BACKUP_DIR))
    except OSError:
        return False


def do_scan() -> None:
    JOB.start("scan", total=len(dg.TEST_DOMAINS) + 3)
    out = JobOut(JOB)
    try:
        payload = dg.run_check(
            out, use_html=False, json_out=False,
            progress=lambda done, total, label: JOB.set_progress(done, total, label))
        with LAST_LOCK:
            LAST.clear()
            LAST.update(payload)
        JOB.push("体检完成")
        JOB.finish(payload)
    except Exception as exc:                                   # noqa: BLE001
        JOB.push(f"体检失败: {exc}")
        JOB.push(traceback.format_exc(limit=2))
        JOB.fail(f"{type(exc).__name__}: {exc}")


def do_doh(action: str, url: str = "", ip: str = "", ip6: str | None = None) -> None:
    JOB.start("doh", total=1)
    out = JobOut(JOB)
    try:
        if action == "plan":
            code = dg.doh_enable(url, ip, out, assume_yes=True, dry_run=True, ip6=ip6)
        elif action == "apply":
            if not dg.is_admin():
                JOB.fail("需要管理员权限：请点「以管理员身份重启」后重试")
                return
            code = dg.doh_enable(url, ip, out, assume_yes=True, ip6=ip6)
        elif action == "rollback":
            if not dg.is_admin():
                JOB.fail("需要管理员权限：请点「以管理员身份重启」后重试")
                return
            code = dg.doh_disable(out)
        else:
            JOB.fail(f"未知操作 {action}")
            return
        JOB.finish({"code": code})
    except Exception as exc:                                   # noqa: BLE001
        JOB.push(traceback.format_exc(limit=2))
        JOB.fail(f"{type(exc).__name__}: {exc}")


def write_report(fmt: str) -> dict:
    with LAST_LOCK:
        payload = dict(LAST)
    if not payload:
        return {"ok": False, "error": "还没有体检结果，先跑一次体检"}
    os.makedirs(dg.REPORT_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    paths = {}
    if fmt in ("html", "both"):
        path = os.path.join(dg.REPORT_DIR, f"report_{stamp}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(dg.render_html(payload))
        paths["html"] = path
    if fmt in ("json", "both"):
        path = os.path.join(dg.REPORT_DIR, f"report_{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
        paths["json"] = path
    return {"ok": True, "paths": paths}


def elevate() -> dict:
    """以管理员身份重新拉起自己（打包成 exe 时就是 exe 本身）"""
    import ctypes
    if dg.is_admin():
        return {"ok": False, "error": "已经是管理员权限"}
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, f"--port {PORT}"
    else:
        exe, params = sys.executable, f'"{os.path.abspath(__file__)}" --port {PORT}'
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    except Exception as exc:                                   # noqa: BLE001
        return {"ok": False, "error": f"提权失败: {exc}"}
    if rc <= 32:
        return {"ok": False, "error": f"提权被取消或失败 (code={rc})"}
    threading.Timer(1.0, lambda: os._exit(0)).start()
    return {"ok": True}


# ---------------------------------------------------------------- HTTP 层

class Handler(BaseHTTPRequestHandler):
    server_version = "DNSGuardUI"

    def log_message(self, *_args) -> None:      # 静音访问日志
        pass

    # -- 工具
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        return host in ("127.0.0.1", "localhost")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data: dict, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            return {}

    # -- GET
    def do_GET(self) -> None:                                  # noqa: N802
        if not self._host_ok():
            self._send(403, b"forbidden", "text/plain")
            return
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, PAGE.replace("__VERSION__", dg.VERSION).encode("utf-8"),
                       "text/html; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if path == "/api/quick":
            try:
                self._json(quick_state())
            except Exception as exc:                           # noqa: BLE001
                self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
            return
        if path == "/api/job":
            since = 0
            if "?" in self.path:
                for part in self.path.split("?", 1)[1].split("&"):
                    if part.startswith("since="):
                        try:
                            since = int(part.split("=", 1)[1])
                        except ValueError:
                            since = 0
            self._json(JOB.snapshot(since))
            return
        self._send(404, b"not found", "text/plain")

    # -- POST
    def do_POST(self) -> None:                                 # noqa: N802
        if not self._host_ok():
            self._send(403, b"forbidden", "text/plain")
            return
        path = urlparse(self.path).path
        body = self._read_json()

        if path == "/api/scan":
            if JOB.status == "running":
                self._json({"ok": False, "error": "已有任务在跑"})
                return
            threading.Thread(target=do_scan, daemon=True).start()
            self._json({"ok": True})
            return

        if path == "/api/doh":
            if JOB.status == "running":
                self._json({"ok": False, "error": "已有任务在跑"})
                return
            action = str(body.get("action") or "")
            url = str(body.get("url") or "").strip()
            ip = str(body.get("ip") or "").strip()
            ip6 = str(body.get("ip6") or "").strip() or None
            if action in ("plan", "apply") and not (url and ip):
                self._json({"ok": False, "error": "DoH 地址与 IP 都要填"})
                return
            threading.Thread(target=do_doh, args=(action, url, ip, ip6), daemon=True).start()
            self._json({"ok": True})
            return

        if path == "/api/report":
            self._json(write_report(str(body.get("format") or "both")))
            return

        if path == "/api/open":
            target = str(body.get("path") or dg.REPORT_DIR)
            try:
                if os.path.isdir(target):
                    os.startfile(target)                       # noqa: S606
                elif os.path.exists(target):
                    os.startfile(target)                       # noqa: S606
                else:
                    os.startfile(dg.REPORT_DIR)                # noqa: S606
                self._json({"ok": True})
            except Exception as exc:                           # noqa: BLE001
                self._json({"ok": False, "error": str(exc)})
            return

        if path == "/api/elevate":
            self._json(elevate())
            return

        if path == "/api/quit":
            self._json({"ok": True})
            threading.Timer(0.3, lambda: os._exit(0)).start()
            return

        self._send(404, b"not found", "text/plain")


# ---------------------------------------------------------------- 端口 / 启动

def pick_port(preferred: int = 8765) -> int:
    for port in range(preferred, preferred + 60):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


PORT = 8765


EDGE_PATHS = [
    r"C://Program Files (x86)//Microsoft//Edge//Application//msedge.exe",
    r"C://Program Files//Microsoft//Edge//Application//msedge.exe",
]


def _find_edge() -> str | None:
    import shutil
    for path in EDGE_PATHS:
        if os.path.exists(path):
            return path
    return shutil.which("msedge")


def run_window(url: str) -> bool:
    """独立窗口（WebView2），没有地址栏和标签页，就是一个客户端"""
    try:
        import webview
    except Exception:                                          # noqa: BLE001
        return False
    try:
        win = webview.create_window(
            f"{APP_NAME} · parkerli", url,
            width=1180, height=880, min_size=(1000, 680),
            background_color="#f4f5f7", text_select=True,
        )

        def _on_loaded(*_args) -> None:
            try:
                win.evaluate_js(
                    "document.addEventListener('contextmenu', e => e.preventDefault());"
                    "window.scrollTo(0, 0);")
            except Exception:                                  # noqa: BLE001
                pass

        win.events.loaded += _on_loaded
        webview.start(debug=False)
        return True
    except Exception:                                          # noqa: BLE001
        return False


def run_app_window(url: str) -> bool:
    """没有 WebView2 时退一步：用 Edge 的 --app 模式开一个无地址栏窗口"""
    edge = _find_edge()
    if not edge:
        return False
    profile = os.path.join(os.environ.get("LOCALAPPDATA", dg.BASE_DIR), "DNSGuard", "browser")
    try:
        subprocess.Popen([
            edge, f"--app={url}", "--window-size=1180,880",
            f"--user-data-dir={profile}", "--no-first-run",
            "--disable-features=msEdgeSidebar",
        ], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True
    except Exception:                                          # noqa: BLE001
        return False


NOTICE = (
    "DNS Guard 只做两件事：检测 DNS 是否被劫持、按你的意愿配置加密 DNS。\n\n"
    "· 体检是只读的，不会修改任何配置\n"
    "· 只有你点「一键开启」才会改 DNS，且会先备份、可回滚\n"
    "· 不联网上报，不收集任何数据\n"
    "· 改 DNS 会影响整机联网，请自行确认风险\n\n"
    "本软件按「现状」提供，作者不对使用后果承担责任。\n"
    "点「确定」表示你已了解，此提示只出现一次。"
)


def _accept_notice() -> bool:
    """首次运行的一次性使用须知；已同意过就直接跳过"""
    marker_dir = os.path.join(os.environ.get("LOCALAPPDATA") or dg.BASE_DIR, "DNSGuard")
    marker = os.path.join(marker_dir, ".accepted")
    if os.path.exists(marker):
        return True
    try:
        import ctypes
        rc = ctypes.windll.user32.MessageBoxW(None, NOTICE, "DNS Guard · 使用须知", 0x00000001)
        if rc != 1:                    # IDOK
            return False
        os.makedirs(marker_dir, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(dg.VERSION)
        return True
    except Exception:                  # noqa: BLE001
        return True                    # 非 Windows 或弹窗失败就别拦着


def main(argv: list[str] | None = None) -> int:
    global PORT
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    parser = argparse.ArgumentParser(description="DNS Guard 桌面客户端")
    parser.add_argument("--port", type=int, default=0, help="监听端口，默认自动挑选")
    parser.add_argument("--ui", choices=["window", "app", "browser"], default="window",
                        help="window=独立窗口（默认） app=Edge 无地址栏窗口 browser=默认浏览器")
    parser.add_argument("--no-browser", action="store_true", help="只起服务，不打开界面")
    args = parser.parse_args(argv)

    if not args.no_browser and not _accept_notice():
        return 0

    PORT = args.port or pick_port()
    os.makedirs(dg.REPORT_DIR, exist_ok=True)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        _fatal(f"端口 {PORT} 无法监听：{exc}")
        return 1

    url = f"http://127.0.0.1:{PORT}/"
    print(f"{APP_NAME} 已启动：{url}")

    if args.no_browser:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    threading.Thread(target=server.serve_forever, daemon=True).start()

    if args.ui == "window" and run_window(url):
        return 0
    if args.ui in ("window", "app") and run_app_window(url):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0

    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


def _fatal(message: str) -> None:
    print(message)
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)
    except Exception:                                          # noqa: BLE001
        pass


# ---------------------------------------------------------------- 前端页面

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Guard · parkerli</title>
<style>
:root{
  --bg:#f4f5f7; --card:#ffffff; --line:#e6e8ec; --line2:#eef0f3;
  --text:#14171c; --muted:#6a7280; --faint:#98a0ad;
  --accent:#2f6df6; --accent-soft:#eaf0fe;
  --ok:#0f8a4d; --okbg:#e8f6ee; --okline:#bfe6cf;
  --warn:#b07800; --warnbg:#fdf4dd; --warnline:#f0dca6;
  --bad:#c9342a; --badbg:#fdecea; --badline:#f5c9c4;
  --info:#5b6472; --infobg:#eef1f5;
  --r:16px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--text); font-size:13.5px; line-height:1.6;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased;
}
.mono{font-family:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;font-variant-numeric:tabular-nums}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px 56px}

/* header */
header{position:sticky;top:0;z-index:20;background:rgba(244,245,247,.86);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.hbar{max-width:1080px;margin:0 auto;padding:14px 24px;display:flex;align-items:center;gap:12px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(140deg,#3b7bf7,#2354d8);display:flex;align-items:center;justify-content:center;box-shadow:0 2px 6px rgba(47,109,246,.28)}
.logo svg{width:19px;height:19px}
.htitle{font-size:15px;font-weight:650;letter-spacing:.2px}
.hsub{font-size:12px;color:var(--muted);margin-top:-2px}
.byline{font-size:10.5px;font-weight:400;color:var(--faint);margin-left:7px;letter-spacing:.4px}
.spacer{flex:1}
.chip{display:inline-flex;align-items:center;gap:5px;height:26px;padding:0 10px;border-radius:20px;font-size:12px;background:#fff;border:1px solid var(--line);color:var(--muted)}
.chip.admin{background:var(--okbg);border-color:var(--okline);color:var(--ok)}
.chip.warn{background:var(--warnbg);border-color:var(--warnline);color:var(--warn)}
.btn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 14px;border-radius:9px;border:1px solid var(--line);background:#fff;color:var(--text);font-size:13px;font-family:inherit;cursor:pointer;transition:.15s}
.btn:hover{border-color:#cfd4dc;background:#fafbfc}
.btn:active{transform:translateY(.5px)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:550}
.btn.primary:hover{background:#255fe0;border-color:#255fe0}
.btn.ghost{background:transparent}
.btn.danger{color:var(--bad);border-color:var(--badline)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn.sm{height:27px;padding:0 10px;font-size:12px;border-radius:7px}

/* progress */
.pbar{height:2px;background:transparent;overflow:hidden}
.pbar i{display:block;height:100%;width:0;background:var(--accent);transition:width .3s ease}

/* cards */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:22px 24px;box-shadow:0 1px 2px rgba(16,24,40,.035)}
.card + .card{margin-top:16px}
.card h3{margin:0 0 14px;font-size:13.5px;font-weight:650;color:var(--text);display:flex;align-items:center;gap:8px}
.card h3 .cnt{font-weight:400;color:var(--faint);font-size:12px}
.card h3 .line{flex:1;height:1px;background:var(--line2)}

/* hero */
.hero{margin-top:20px;padding:0;overflow:hidden}
.hero-in{display:grid;grid-template-columns:1fr 188px;gap:0}
.hero-l{padding:24px 26px}
.kicker{font-size:12px;color:var(--faint);letter-spacing:.4px;text-transform:uppercase}
.hero h1{margin:6px 0 8px;font-size:22px;line-height:1.35;font-weight:680;letter-spacing:-.2px}
.hero-sub{margin:0;color:var(--muted);font-size:13px;max-width:600px}
.hero-r{border-left:1px solid var(--line2);display:flex;flex-direction:column;align-items:center;justify-content:center;background:#fcfcfd;padding:18px}
.ring{position:relative;width:112px;height:112px}
.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .num b{font-size:26px;font-weight:680;line-height:1}
.ring .num span{font-size:10.5px;color:var(--faint);margin-top:3px}
.ring-cap{margin-top:10px;font-size:12px;color:var(--muted);text-align:center}

/* status pill */
.state{display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 12px;border-radius:20px;font-size:12.5px;font-weight:600}
.state .dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.s-ok{background:var(--okbg);color:var(--ok);border:1px solid var(--okline)}
.s-warn{background:var(--warnbg);color:var(--warn);border:1px solid var(--warnline)}
.s-bad{background:var(--badbg);color:var(--bad);border:1px solid var(--badline)}
.s-info{background:var(--infobg);color:var(--info);border:1px solid var(--line)}

/* chain */
.chain{display:flex;align-items:stretch;gap:0;margin-top:20px;padding:16px;background:#fbfcfd;border:1px solid var(--line2);border-radius:12px}
.hop{flex:1;min-width:0;text-align:center;padding:0 4px}
.hop .ico{width:34px;height:34px;margin:0 auto 7px;border-radius:10px;background:#fff;border:1px solid var(--line);display:flex;align-items:center;justify-content:center;position:relative}
.hop .ico svg{width:17px;height:17px;stroke:#4b5563}
.hop.exposed .ico{border-color:var(--badline);background:var(--badbg)}
.hop.exposed .ico svg{stroke:var(--bad)}
.hop.safe .ico{border-color:var(--okline);background:var(--okbg)}
.hop.safe .ico svg{stroke:var(--ok)}
.hop .t{font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hop .s{font-size:11px;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hop .tag{display:inline-block;margin-top:5px;font-size:10.5px;padding:1px 7px;border-radius:10px}
.hop .tag.eye{background:var(--badbg);color:var(--bad)}
.hop .tag.lock{background:var(--okbg);color:var(--ok)}
.hop .tag.q{background:var(--infobg);color:var(--info)}
.seg{width:46px;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--faint);flex:none}
.seg .ln{width:100%;height:1.5px;background:repeating-linear-gradient(90deg,#c9cfd8 0 5px,transparent 5px 9px);position:relative}
.seg .ln.solid{background:#d7dce4;background-image:none}
.seg .lb{font-size:9.5px;margin-top:6px;white-space:nowrap;color:var(--faint)}
.seg.locked .ln{background:#bfe6cf;background-image:none}
.seg.locked .lb{color:var(--ok)}
.seg.plain .ln{background:repeating-linear-gradient(90deg,#f0b7b0 0 5px,transparent 5px 9px)}
.seg.plain .lb{color:var(--bad)}

/* stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:0 1px 2px rgba(16,24,40,.03)}
.stat .k{font-size:11.5px;color:var(--faint)}
.stat .v{font-size:19px;font-weight:660;margin-top:3px;letter-spacing:-.2px}
.stat .d{font-size:11.5px;color:var(--muted);margin-top:1px}
.c-ok{color:var(--ok)} .c-warn{color:var(--warn)} .c-bad{color:var(--bad)} .c-muted{color:var(--muted)}

/* two col */
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
.cols .card{margin-top:0}

/* list rows */
.row{display:flex;gap:10px;padding:11px 0;border-top:1px solid var(--line2)}
.row:first-child{border-top:none;padding-top:2px}
.row .bullet{width:6px;height:6px;border-radius:50%;margin-top:7px;flex:none;background:var(--faint)}
.row .bullet.ok{background:var(--ok)} .row .bullet.warn{background:var(--warn)}
.row .bullet.bad{background:var(--bad)} .row .bullet.info{background:var(--faint)}
.row .body{min-width:0;flex:1}
.row .ttl{font-weight:600;font-size:13px}
.row .txt{color:var(--muted);font-size:12.5px;margin-top:2px}
.row .path{font-size:11.5px;color:var(--faint);margin-top:3px;font-family:"Cascadia Mono",Consolas,monospace;word-break:break-all}
.tag{display:inline-block;font-size:10.5px;padding:1px 7px;border-radius:9px;margin-left:6px;vertical-align:1px;font-weight:500}
.tag.ok{background:var(--okbg);color:var(--ok)} .tag.warn{background:var(--warnbg);color:var(--warn)}
.tag.bad{background:var(--badbg);color:var(--bad)} .tag.info{background:var(--infobg);color:var(--info)}

/* table */
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;font-weight:550;color:var(--faint);font-size:11.5px;padding:0 8px 8px;border-bottom:1px solid var(--line2);white-space:nowrap}
td{padding:10px 8px;border-bottom:1px solid var(--line2);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fbfcfd}
td.dom{font-weight:600;white-space:nowrap}
td.ip{font-family:"Cascadia Mono",Consolas,monospace;font-size:11.5px;color:#374151;word-break:break-all;max-width:190px}
.badge{display:inline-block;font-size:11px;padding:1.5px 8px;border-radius:10px;white-space:nowrap;font-weight:550}
.why{color:var(--faint);font-size:11.5px;margin-top:4px;line-height:1.5}
.empty{color:var(--faint);font-size:12.5px;padding:8px 0}

/* resolver bench */
.res{display:flex;align-items:center;gap:12px;padding:9px 0;border-top:1px solid var(--line2)}
.res:first-of-type{border-top:none}
.res .nm{width:148px;flex:none;font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.res .nm small{display:block;font-weight:400;color:var(--faint);font-size:10.5px;font-family:"Cascadia Mono",Consolas,monospace}
.res .bwrap{flex:1;height:6px;background:#f0f2f5;border-radius:6px;overflow:hidden;min-width:60px}
.res .bwrap i{display:block;height:100%;border-radius:6px;background:#9fb3d9;transition:width .5s ease}
.res.best .bwrap i{background:var(--accent)}
.res.best .nm{color:var(--accent)}
.res .ms{width:60px;text-align:right;font-size:12px;font-variant-numeric:tabular-nums;color:#374151;flex:none}
.res .cap{width:104px;text-align:right;font-size:11px;color:var(--faint);flex:none}
.res .fl{width:92px;text-align:right;flex:none}
.mini{display:inline-block;font-size:10px;padding:0 6px;border-radius:8px;background:var(--okbg);color:var(--ok);margin-left:3px;font-weight:550}
.mini.warn{background:var(--warnbg);color:var(--warn)}

/* advice */
.adv{display:flex;gap:9px;padding:8px 0;font-size:13px;color:#2b3138}
.adv .n{width:18px;height:18px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-size:10.5px;font-weight:700;display:flex;align-items:center;justify-content:center;flex:none;margin-top:2px}

/* doh */
.doh-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
label.f{display:block;font-size:11.5px;color:var(--faint);margin-bottom:5px}
input.f,select.f{width:100%;height:34px;padding:0 11px;border:1px solid var(--line);border-radius:9px;background:#fff;font-size:12.5px;font-family:inherit;color:var(--text);outline:none}
input.f:focus,select.f:focus{border-color:#b9c9f2;box-shadow:0 0 0 3px rgba(47,109,246,.1)}
.warnbox{background:var(--warnbg);border:1px solid var(--warnline);color:#7a5300;border-radius:10px;padding:10px 13px;font-size:12px;line-height:1.65;margin-top:14px}
.actions{display:flex;gap:9px;margin-top:16px;flex-wrap:wrap}

/* log */
.logbox{margin-top:16px}
.logbox summary{cursor:pointer;font-size:12.5px;color:var(--muted);list-style:none;display:flex;align-items:center;gap:6px;user-select:none}
.logbox summary::-webkit-details-marker{display:none}
.logbox summary:hover{color:var(--text)}
pre.log{margin:10px 0 0;padding:13px 15px;background:#fbfcfd;border:1px solid var(--line2);border-radius:10px;max-height:230px;overflow:auto;font-family:"Cascadia Mono",Consolas,monospace;font-size:11.5px;line-height:1.65;color:#4b5563;white-space:pre-wrap;word-break:break-all}

/* footer */
footer{margin-top:26px;display:flex;align-items:center;gap:10px;color:var(--faint);font-size:11.5px;flex-wrap:wrap}
footer .spacer{flex:1}

/* toast */
#toast{position:fixed;left:50%;bottom:28px;transform:translate(-50%,14px);background:#1b1f26;color:#fff;font-size:12.5px;padding:9px 16px;border-radius:10px;opacity:0;pointer-events:none;transition:.22s;z-index:50;max-width:80vw}
#toast.on{opacity:1;transform:translate(-50%,0)}

@media (max-width:860px){
  .hero-in{grid-template-columns:1fr}
  .hero-r{border-left:none;border-top:1px solid var(--line2)}
  .stats{grid-template-columns:repeat(2,1fr)}
  .cols,.doh-grid{grid-template-columns:1fr}
  .chain{flex-wrap:wrap;gap:10px}
  .seg{display:none}
  .hop{flex:1 0 40%}
}
</style>
</head>
<body>
<header>
  <div class="hbar">
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
    </div>
    <div>
      <div class="htitle">DNS Guard<span class="byline">by parkerli</span></div>
      <div class="hsub">DNS 劫持体检 · 明文/加密自查</div>
    </div>
    <div class="spacer"></div>
    <span class="chip" id="permChip">检测权限…</span>
    <span class="chip mono">v__VERSION__</span>
    <button class="btn primary" id="scanBtn" onclick="startScan()">开始体检</button>
  </div>
  <div class="pbar"><i id="pbar"></i></div>
</header>

<div class="wrap">
  <!-- 隐私主卡 -->
  <section class="card hero">
    <div class="hero-in">
      <div class="hero-l">
        <div class="kicker">DNS 隐私状态</div>
        <h1 id="heroTitle">正在读取系统 DNS 配置…</h1>
        <p class="hero-sub" id="heroSub">读取网卡、注册表与浏览器设置，判断查询是否以明文发出。</p>
        <div id="heroState" style="margin-top:14px"></div>
        <div id="heroCta" style="margin-top:16px;display:none">
          <button class="btn primary" onclick="startScan()">开始体检</button>
          <span style="margin-left:10px;color:var(--faint);font-size:12px">约 15 秒 · 只读，不改任何配置</span>
        </div>
        <div id="scoreBreak" style="margin-top:10px;font-size:12px;color:var(--muted);line-height:1.7"></div>
        <div class="chain" id="chain"></div>
      </div>
      <div class="hero-r">
        <div class="ring">
          <svg width="112" height="112" viewBox="0 0 112 112">
            <circle cx="56" cy="56" r="47" fill="none" stroke="#eceef2" stroke-width="9"/>
            <circle id="ringArc" cx="56" cy="56" r="47" fill="none" stroke="#c9ced8" stroke-width="9"
                    stroke-linecap="round" stroke-dasharray="295.3" stroke-dashoffset="295.3"
                    style="transition:stroke-dashoffset .6s ease,stroke .3s"/>
          </svg>
          <div class="num"><b id="ringNum">--</b><span>隐私评分</span></div>
        </div>
        <div class="ring-cap" id="ringCap">等待体检</div>
      </div>
    </div>
  </section>

  <!-- 四个指标 -->
  <div class="stats" id="stats">
    <div class="stat"><div class="k">抗劫持评分</div><div class="v c-muted" id="stRisk">--</div><div class="d" id="stRiskD">越高越安全</div></div>
    <div class="stat"><div class="k">异常域名</div><div class="v c-muted" id="stBad">--</div><div class="d" id="stBadD">共 8 个测试域名</div></div>
    <div class="stat"><div class="k">加密通道</div><div class="v c-muted" id="stDoh">--</div><div class="d" id="stDohD">DoH 是否生效</div></div>
    <div class="stat"><div class="k">代理接管</div><div class="v c-muted" id="stProxy">--</div><div class="d" id="stProxyD">fake-ip / 本地端口</div></div>
  </div>

  <!-- 通道 + 谁能看到 -->
  <div class="cols">
    <section class="card">
      <h3>解析通道<span class="line"></span></h3>
      <div id="channels"><div class="empty">等待体检…</div></div>
    </section>
    <section class="card">
      <h3>谁能看到你在访问什么<span class="line"></span></h3>
      <div id="observers"><div class="empty">等待体检…</div></div>
    </section>
  </div>

  <!-- 泄露 -->
  <section class="card">
    <h3>明文 DNS 会泄露什么<span class="cnt" id="leakCnt"></span><span class="line"></span></h3>
    <div id="leaks"><div class="empty">等待体检…</div></div>
  </section>

  <!-- 证据 -->
  <section class="card">
    <h3>判定依据<span class="line"></span></h3>
    <div id="evidence"><div class="empty">等待体检…</div></div>
  </section>

  <!-- 解析器体检 -->
  <section class="card">
    <h3>解析器体检<span class="cnt" id="resCnt"></span><span class="line"></span></h3>
    <div id="resolvers"><div class="empty">等待体检…</div></div>
  </section>

  <!-- 表格 -->
  <section class="card">
    <h3>解析一致性交叉验证<span class="cnt" id="tblCnt"></span><span class="line"></span></h3>
    <div id="table"><div class="empty">等待体检…</div></div>
  </section>

  <!-- 建议 -->
  <section class="card">
    <h3>建议<span class="line"></span></h3>
    <div id="advice"><div class="empty">等待体检…</div></div>
  </section>

  <!-- DoH -->
  <section class="card">
    <h3>一键开启加密 DNS（DoH）<span class="line"></span></h3>
    <div class="doh-grid">
      <div>
        <label class="f">服务商</label>
        <select class="f" id="dohProvider" onchange="fillProvider()"></select>
      </div>
      <div>
        <label class="f">IPv4 DNS（必须与地址配套）</label>
        <input class="f mono" id="dohIp" placeholder="223.5.5.5">
      </div>
      <div style="grid-column:1/-1">
        <label class="f">IPv6 DNS（留空则不配置 IPv6，IPv6 仍为明文）</label>
        <input class="f mono" id="dohIp6" placeholder="2400:3200::1">
      </div>
      <div style="grid-column:1/-1">
        <label class="f">DoH 地址</label>
        <input class="f mono" id="dohUrl" placeholder="https://dns.alidns.com/dns-query">
      </div>
    </div>
    <div class="warnbox">
      会修改系统 DNS（IPv4 与 IPv6 一起）并重启 DNS 客户端服务，影响整机联网。执行前自动备份，可随时一键回滚。
      Windows 的 DoH 按 IP 注册模板，<b>URL 与 IP 不匹配会静默回落到明文</b>；IPv6 也要填地址才会一起加密。
    </div>
    <div class="actions">
      <button class="btn" onclick="dohAction('plan')">先看执行计划</button>
      <button class="btn primary" onclick="dohAction('apply')">开启并验证</button>
      <button class="btn danger" id="rbBtn" onclick="dohAction('rollback')">回滚到开启前</button>
    </div>
  </section>

  <details class="logbox">
    <summary>▸ 体检日志 <span class="mono" id="logHint" style="color:var(--faint)"></span></summary>
    <pre class="log" id="log"></pre>
  </details>

  <footer>
    <span>© parkerli · DNS Guard v__VERSION__ · 只读体检，写操作前自动备份</span>
    <span class="spacer"></span>
    <button class="btn sm" onclick="copySummary()">复制诊断摘要</button>
    <button class="btn sm" onclick="saveReport('html')">导出 HTML 报告</button>
    <button class="btn sm" onclick="saveReport('json')">导出 JSON</button>
    <button class="btn sm" onclick="openFolder()">打开报告目录</button>
    <button class="btn sm" id="elevBtn" onclick="elevate()" style="display:none">以管理员身份重启</button>
    <button class="btn sm ghost" onclick="quit()">退出</button>
  </footer>
</div>
<div id="toast"></div>

<script>
const S = {quick:null, payload:null, job:null, seen:0};

const PROVIDERS = [
  {name:'阿里 AliDNS', url:'https://dns.alidns.com/dns-query', ip:'223.5.5.5', ip6:'2400:3200::1'},
  {name:'腾讯 DNSPod', url:'https://doh.pub/dns-query', ip:'119.29.29.29', ip6:'2402:4e00::'},
  {name:'Cloudflare', url:'https://cloudflare-dns.com/dns-query', ip:'1.1.1.1', ip6:'2606:4700:4700::1111'},
  {name:'Google', url:'https://dns.google/dns-query', ip:'8.8.8.8', ip6:'2001:4860:4860::8888'},
  {name:'自定义', url:'', ip:'', ip6:''}
];

const VERDICT = {
  normal:['正常','ok'], doh_active:['加密生效','ok'], doh_probably:['加密生效','ok'],
  proxy_fakeip:['代理 fake-ip','info'], proxy_route:['代理转发','info'],
  cdn_variance:['CDN 差异','info'], plain_differs:['明文与基准不同','warn'],
  bogon:['非公网地址','bad'], nxdomain_hijack:['NXDOMAIN 劫持','bad'],
  plain_tampered:['明文被篡改','bad'], selective_drop:['选择性拦截','bad'],
  failed:['解析失败','warn'], mismatch:['与基准不同','warn'], unknown:['无法判定','info'],
  ede_blocked:['明确拦截','bad']
};

const ICONS = {
  device:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  router:'<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M17 6a5 5 0 00-4-4M17 10a9 9 0 00-4-8"/>',
  proxy:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 010 18 15 15 0 010-18"/>',
  cloud:'<path d="M17.5 19a4.5 4.5 0 000-9 6 6 0 00-11.6 1.5A3.5 3.5 0 006.5 19h11z"/>',
  dns:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'
};

function icon(name, cls){
  return `<svg class="${cls||''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
    stroke-linecap="round" stroke-linejoin="round">${ICONS[name]||ICONS.device}</svg>`;
}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(msg){
  const t=document.getElementById('toast'); t.textContent=msg; t.classList.add('on');
  clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('on'),2600);
}

async function api(path, body){
  const res = await fetch(path, {
    method: body===undefined?'GET':'POST',
    headers:{'Content-Type':'application/json'},
    body: body===undefined?undefined:JSON.stringify(body)
  });
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}

/* ---------- 渲染 ---------- */
function stateClass(level){ return {ok:'s-ok',warn:'s-warn',bad:'s-bad',info:'s-info'}[level]||'s-info'; }
function scoreColor(v){ return v>=85?'#0f8a4d':v>=65?'#c98a00':'#c9342a'; }

function renderPrivacy(pv){
  if(!pv) return;
  document.getElementById('heroTitle').textContent = pv.headline || '—';
  document.getElementById('heroSub').textContent = pv.summary || '';

  const lv = pv.level||'info';
  document.getElementById('heroState').innerHTML =
    `<span class="state ${stateClass(lv)}"><span class="dot"></span>${esc(pv.label||'')}</span>
     <span class="chip" style="margin-left:8px">暴露等级 ${esc(pv.exposure_label||'-')}</span>
     <span class="chip mono" style="margin-left:4px">${esc(pv.target||'-')}${pv.provider?' · '+esc(pv.provider):''}</span>`;

  const arc = document.getElementById('ringArc');
  const num = document.getElementById('ringNum');
  const v = Number(pv.score||0);
  if(pv.partial){
    num.textContent = '--';
    num.style.color = 'var(--faint)';
    arc.setAttribute('stroke', '#dfe3ea');
    arc.style.strokeDashoffset = '295.3';
    document.getElementById('ringCap').textContent = '待行为验证';
  }else{
    num.textContent = v;
    num.style.color = scoreColor(v);
    arc.setAttribute('stroke', scoreColor(v));
    arc.style.strokeDashoffset = String(295.3 * (1 - v/100));
    document.getElementById('ringCap').textContent = v>=85?'链路私密':v>=65?'基本可控':v>=40?'部分暴露':'高度暴露';
  }

  const bd = pv.breakdown || [];
  const bEl = document.getElementById('scoreBreak');
  if(bEl){
    bEl.innerHTML = pv.partial ? '配置层初判 · 行为层尚未验证，点「开始体检」跑一次完整检测' : (bd.length
      ? '隐私评分构成：<b style="color:var(--text)">100</b> ' + bd.map(b=>`<span style="color:var(--bad)">${b.delta>0?'+':''}${b.delta} ${esc(b.label)}</span>`).join('  ')
        + ` = <b style="color:${scoreColor(v)}">${v}</b>` : '');
  }

  renderChain(pv);
}

function renderChain(pv){
  const ch0 = (pv.channels||[])[0] || {};
  const enc = ch0.encrypted === true;
  const unknown = ch0.encrypted === null;
  const proxy = pv.state==='proxy';
  const gw = (pv.gateways&&pv.gateways[0]) || '网关';
  const tgt = pv.target || 'DNS';

  let hops, segs;
  if(proxy){
    hops = [
      {t:'你的设备', s:'浏览器 / 应用', i:'device', cls:'', tag:''},
      {t:'本地代理', s:'127.0.0.1', i:'proxy', cls:'safe', tag:['q','不出网卡']},
      {t:'代理上游', s:'加密与否未知', i:'cloud', cls:'', tag:['q','取决于配置']},
      {t:'解析器', s:tgt, i:'dns', cls:'', tag:''}
    ];
    segs = [['solid','本机'],['solid','代理'],['solid','出网卡']];
  } else if(enc){
    hops = [
      {t:'你的设备', s:'浏览器 / 应用', i:'device', cls:'', tag:''},
      {t:'路由器', s:gw, i:'router', cls:'safe', tag:['lock','看不到域名']},
      {t:'运营商', s:'链路中间人', i:'cloud', cls:'safe', tag:['lock','看不到域名']},
      {t:'DNS 解析器', s:tgt, i:'dns', cls:'safe', tag:['lock','TLS 解密']}
    ];
    segs = [['locked','加密'],['locked','加密'],['locked','TLS 443']];
  } else if(unknown){
    hops = [
      {t:'你的设备', s:'浏览器 / 应用', i:'device', cls:'', tag:''},
      {t:'路由器', s:gw, i:'router', cls:'', tag:['q','待验证']},
      {t:'运营商', s:'链路中间人', i:'cloud', cls:'', tag:['q','待验证']},
      {t:'DNS 解析器', s:tgt, i:'dns', cls:'', tag:['q','TLS 未确认']}
    ];
    segs = [['','待验证'],['','待验证'],['','443?']];
  } else {
    hops = [
      {t:'你的设备', s:'浏览器 / 应用', i:'device', cls:'', tag:''},
      {t:'路由器', s:gw, i:'router', cls:'exposed', tag:['eye','可见']},
      {t:'运营商', s:'链路中间人', i:'cloud', cls:'exposed', tag:['eye','可见']},
      {t:'DNS 解析器', s:tgt, i:'dns', cls:'exposed', tag:['eye','明文 53']}
    ];
    segs = [['plain','明文'],['plain','明文'],['plain','UDP 53']];
  }

  let html = '';
  hops.forEach((h,idx)=>{
    if(idx>0){
      const [c,lb] = segs[idx-1]||['',''];
      html += `<div class="seg ${c}"><div class="ln ${c==='solid'?'solid':''}"></div><div class="lb">${esc(lb)}</div></div>`;
    }    html += `<div class="hop ${h.cls}">
      <div class="ico">${icon(h.i)}</div>
      <div class="t">${esc(h.t)}</div>
      <div class="s">${esc(h.s)}</div>
      ${h.tag?`<span class="tag ${h.tag[0]}">${esc(h.tag[1])}</span>`:''}
    </div>`;
  });
  document.getElementById('chain').innerHTML = html;
}

function renderStats(p){
  if(!p) return;
  const bad = (p.rows||[]).filter(r=>['high','critical'].includes(r.judge.severity));
  const risk = document.getElementById('stRisk');
  risk.textContent = p.score;
  risk.className = 'v ' + (p.score>=90?'c-ok':p.score>=70?'c-warn':'c-bad');
  document.getElementById('stRiskD').textContent = p.level + ' · 越高越安全';

  const badEl = document.getElementById('stBad');
  badEl.textContent = bad.length;
  badEl.className = 'v ' + (bad.length?'c-bad':'c-ok');
  document.getElementById('stBadD').textContent = `共 ${(p.rows||[]).length} 个测试域名`;

  const dohEl = document.getElementById('stDoh');
  const ds = p.doh_status||{};
  const pvState = (p.privacy||{}).state;
  if(pvState === 'encrypted'){ ds.state = 'active'; }
  else if(pvState === 'proxy'){ ds.state = 'proxy'; }
  else if(pvState === 'plaintext'){ ds.state = 'off'; }
  else if(pvState === 'encrypted_unproven' || pvState === 'auto_doh'){ ds.state = 'configured_unproven'; }
  const DOH_V = {active:'已生效',configured_unproven:'未证实',configured_no_plain:'已生效',
    implicit:'加密生效',proxy:'代理接管',off:'未启用'};
  const DOH_D = {active:'行为层已验证',configured_unproven:'配置已开，未证实',
    configured_no_plain:'明文不可达，只能走加密',implicit:'系统未配置但已加密',
    proxy:'系统级 DoH 不生效',off:'仍是明文 UDP/53'};
  dohEl.textContent = DOH_V[ds.state] || '未知';
  dohEl.className = 'v ' + (['active','implicit','configured_no_plain'].includes(ds.state)?'c-ok':
    ds.state==='off'?'c-bad':'c-warn');
  document.getElementById('stDohD').textContent = DOH_D[ds.state] || 'DoH 是否生效';

  const px = document.getElementById('stProxy');
  const ports = p.proxy_ports||[];
  px.textContent = ports.length ? ports.length+' 个端口' : '未发现';
  px.className = 'v ' + (ports.length?'c-warn':'c-ok');
  document.getElementById('stProxyD').textContent = ports.length ? ports.join(' / ') : '无代理监听';
}

function renderChannels(pv){
  const box = document.getElementById('channels');
  const chs = pv.channels||[];
  if(!chs.length){ box.innerHTML = '<div class="empty">无数据</div>'; return; }
  box.innerHTML = chs.map(c=>{
    const tone = c.encrypted===true?'ok':c.encrypted===false?'bad':'warn';
    const word = c.encrypted===true?'加密':c.encrypted===false?'明文':'未知';
    return `<div class="row">
      <div class="bullet ${tone}"></div>
      <div class="body">
        <div class="ttl">${esc(c.name)}<span class="tag ${tone}">${word}</span></div>
        <div class="txt">${esc(c.state_text)} · 可见范围：${esc(c.sees)}</div>
        <div class="path">${esc(c.path)}</div>
      </div></div>`;
  }).join('');
}

function renderObservers(pv){
  const box = document.getElementById('observers');
  const obs = pv.observers||[];
  if(!obs.length){ box.innerHTML = '<div class="empty">无数据</div>'; return; }
  box.innerHTML = obs.map(o=>{
    const tone = {bad:'bad',warn:'warn',ok:'ok',info:'info'}[o.level]||'info';
    return `<div class="row">
      <div class="bullet ${tone}"></div>
      <div class="body">
        <div class="ttl">${esc(o.name)}</div>
        <div class="txt">能看到：${(o.can_see||[]).map(esc).join('、')}</div>
        <div class="path">${esc(o.note)}</div>
      </div></div>`;
  }).join('');
}

function renderLeaks(pv){
  const box = document.getElementById('leaks');
  const leaks = pv.leaks||[];
  document.getElementById('leakCnt').textContent = leaks.length?`${leaks.length} 项`:'';
  if(!leaks.length){ box.innerHTML = '<div class="empty">没有发现明文泄露点。</div>'; return; }
  box.innerHTML = leaks.map(l=>{
    const tone = l.severity==='critical'?'bad':l.severity==='high'?'bad':l.severity==='medium'?'warn':'info';
    const word = {critical:'严重',high:'高',medium:'中',low:'低'}[l.severity]||'';
    return `<div class="row">
      <div class="bullet ${tone}"></div>
      <div class="body">
        <div class="ttl">${esc(l.title)}<span class="tag ${tone}">${word}</span></div>
        <div class="txt">${esc(l.detail)}</div>
      </div></div>`;
  }).join('');
}

function renderEvidence(pv){
  const box = document.getElementById('evidence');
  const ev = pv.evidence||[];
  if(!ev.length){ box.innerHTML = '<div class="empty">无数据</div>'; return; }
  box.innerHTML = ev.map(e=>`<div class="row"><div class="bullet info"></div>
    <div class="body"><div class="txt" style="margin-top:0">${esc(e)}</div></div></div>`).join('');
}

function renderResolvers(res){
  const box = document.getElementById('resolvers');
  const cap = document.getElementById('resCnt');
  const rows = (res && res.rows) || [];
  if(!rows.length){ box.innerHTML = '<div class="empty">等待体检…</div>'; cap.textContent=''; return; }
  const ds = res.dnssec || {};
  const alive = rows.filter(r=>r.ok);
  const max = Math.max.apply(null, alive.map(r=>r.avg||1).concat([1]));
  const bestIp = res.recommend && res.recommend.ip;

  let html = '';
  if(ds.tested){
    const good = !!ds.validating;
    html += `<div class="row" style="padding-top:0"><div class="bullet ${good?'ok':'warn'}"></div>
      <div class="body"><div class="ttl">DNSSEC ${good?'验证中':'不验证'}
        <span class="tag ${good?'ok':'warn'}">${good?'可发现伪造':'伪造无法发现'}</span></div>
        <div class="txt">${esc(ds.detail||'')}</div></div></div>`;
  }
  if(res.proxied){
    html += `<div class="warnbox" style="margin:2px 0 10px">当前解析经代理接管，下面的延迟只代表本机到代理，不代表解析器真实速度</div>`;
  }
  html += alive.map(r=>{
    const w = Math.max(3, Math.round(100 * (r.avg||max) / max));
    const isBest = r.ip === bestIp;
    return `<div class="res ${isBest?'best':''}">
      <div class="nm">${esc(r.name)}${isBest?' ★':''}<small>${esc(r.ip)}</small></div>
      <div class="bwrap"><i style="width:${w}%"></i></div>
      <div class="ms">${r.avg}ms</div>
      <div class="cap">抖动 ${r.jitter} · 丢 ${r.loss}%</div>
      <div class="fl">${r.doh_ok?'<span class="mini" title="DoH 走 443">DoH</span>':(r.doh_note?'<span class="mini warn">证书异常</span>':'')}${r.dot_ok?`<span class="mini" title="DoT 实测端点 ${esc(r.dot_target||r.ip)}:853">DoT</span>`:''}</div>
    </div>`;
  }).join('');
  html += `<div class="why" style="margin-top:10px;line-height:1.7">DoH 走 443（HTTPS），DoT 走 853（TLS 专口）。
    853 常被网络直接拦截，所以显示为空不一定是不支持。腾讯的 DoT 在 dot.pub（1.12.12.12），不在 119.29.29.29 上。</div>`;
  const dead = rows.filter(r=>!r.ok);
  if(dead.length){
    html += `<div class="empty" style="margin-top:8px">无响应：${dead.map(r=>esc(r.name)).join('、')}</div>`;
  }
  cap.textContent = ds.tested ? (ds.validating ? 'DNSSEC 已验证' : 'DNSSEC 未验证') : '';
  box.innerHTML = html;
}

async function copySummary(){
  const p = S.payload;
  if(!p){ toast('先跑一次体检'); return; }
  const pv = p.privacy || {}, rs = p.resolvers || {}, ds = rs.dnssec || {};
  const L = [];
  L.push(`DNS Guard v__VERSION__ 诊断摘要  ${new Date().toLocaleString()}`);
  L.push(`结论：${pv.headline||''}`);
  L.push(`隐私评分 ${pv.score}/100（${pv.exposure_label||'-'}）｜抗劫持评分 ${p.score}/100 ${p.level}`);
  if((pv.breakdown||[]).length){
    L.push('评分构成：100 ' + pv.breakdown.map(b=>`${b.delta} ${b.label}`).join(' ') + ` = ${pv.score}`);
  }
  L.push(`当前解析器：${pv.target||'-'}${pv.provider?'（'+pv.provider+'）':''}`);
  L.push(`DNSSEC：${ds.tested?(ds.validating?'验证中':'不验证'):'未知'} ${ds.detail||''}`);
  (pv.channels||[]).forEach(c=>L.push(`通道｜${c.name}：${c.state_text} ${c.path}`));
  (pv.leaks||[]).forEach(l=>L.push(`泄露｜${l.title}：${l.detail}`));
  (pv.evidence||[]).forEach(e=>L.push(`证据｜${e}`));
  const bad = (p.rows||[]).filter(r=>['high','critical'].includes(r.judge.severity));
  bad.forEach(r=>L.push(`异常｜${r.domain}：${r.judge.verdict} — ${r.judge.reason}`));
  const text = L.join('\n');
  try{
    await navigator.clipboard.writeText(text);
    toast('诊断摘要已复制，可直接贴给客服/运维');
  }catch(e){
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
    toast('诊断摘要已复制');
  }
}

function renderTable(p){
  const box = document.getElementById('table');
  const rows = (p&&p.rows)||[];
  document.getElementById('tblCnt').textContent = rows.length?`${rows.length} 个域名`:'';
  if(!rows.length){ box.innerHTML = '<div class="empty">等待体检…</div>'; return; }
  const head = `<tr><th style="width:150px">域名</th><th>系统解析</th><th>本地 DNS</th><th>公共 DNS</th><th style="width:230px">判定</th></tr>`;
  const body = rows.map(r=>{
    const v = VERDICT[r.judge.verdict]||[r.judge.verdict,'info'];
    const color = {ok:'#0f8a4d',warn:'#b07800',bad:'#c9342a',info:'#5b6472'}[v[1]];
    const sys = (r.sys_ips||[]).slice(0,2).join('<br>')||'-';
    const pl = r.plain||{};
    const plt = (pl.ips&&pl.ips.length)?pl.ips.slice(0,2).join('<br>'):(pl.timeout?'超时':(pl.ok?`rcode=${pl.rcode}`:'-'));
    const pb = r.public||{};
    const pbt = (pb.ips&&pb.ips.length)?pb.ips.slice(0,2).join('<br>'):(pb.skipped?'同本地':'超时');
    return `<tr>
      <td class="dom">${esc(r.domain)}</td>
      <td class="ip">${sys}</td>
      <td class="ip">${plt}</td>
      <td class="ip">${pbt}</td>
      <td><span class="badge" style="background:${color}1a;color:${color}">${esc(v[0])}</span>${(r.plain&&r.plain.ede)?`<span class="tag bad" style="margin-left:4px">EDE ${r.plain.ede.code}</span>`:''}
          <div class="why">${esc(r.judge.reason)}</div></td>
    </tr>`;
  }).join('');
  box.innerHTML = `<table><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function renderAdvice(p){
  const box = document.getElementById('advice');
  const list = (p&&p.advice)||[];
  if(!list.length){ box.innerHTML = '<div class="empty">等待体检…</div>'; return; }
  box.innerHTML = list.map((a,i)=>`<div class="adv"><div class="n">${i+1}</div><div>${esc(a)}</div></div>`).join('');
}

function renderAll(){
  const p = S.payload;
  if(p){
    renderPrivacy(p.privacy);
    renderStats(p);
    renderChannels(p.privacy);
    renderObservers(p.privacy);
    renderLeaks(p.privacy);
    renderEvidence(p.privacy);
    renderResolvers(p.resolvers);
    renderTable(p);
    renderAdvice(p);
    const rb = document.getElementById('rbBtn');
    rb.disabled = !(S.quick && S.quick.backup_available);
    const cta = document.getElementById('heroCta');
    if(cta) cta.style.display = 'none';
    if(window.scrollY < 60) window.scrollTo(0, 0);
  }
}

/* ---------- 交互 ---------- */
/* ---------- 开发预览：?demo=plain / ?demo=enc ---------- */
function demoPayload(kind){
  const plain = kind!=='enc';
  const gw = '192.168.1.1', tgt = '223.5.5.5';
  const pv = plain ? {
    state:'plaintext', level:'bad', label:'明文 DNS', score:40, exposure:'critical', exposure_label:'高度暴露',
    breakdown:[{label:'DNS 仍是明文', delta:-52},{label:'没有浏览器级加密兜底', delta:-8}],
    headline:'DNS 是明文的：谁都能看到你访问的每个域名',
    summary:'系统 DNS 为 223.5.5.5（阿里 AliDNS），明文 53 端口可直连，查询会以未加密形式经过 192.168.1.1 和运营商。',
    target:tgt, provider:'阿里 AliDNS', gateways:[gw],
    channels:[{name:'系统解析（浏览器与所有应用默认走这条）', encrypted:false,
      path:'本机 → 192.168.1.1 → 运营商 → 223.5.5.5:53', state_text:'明文 UDP/53', sees:'链路上所有人'}],
    observers:[
      {name:'路由器 / 网关 192.168.1.1', level:'bad', can_see:['访问的域名','查询时间','你的内网 IP'],
       note:'明文 UDP/53 直接经过网关，路由器固件、管理后台、蹭网者都能记录'},
      {name:'运营商 / 上游网络', level:'bad', can_see:['访问的域名','访问频率','可篡改返回结果'],
       note:'跨网明文传输，可被记录、限速、注入广告页或直接返回错误 IP'},
      {name:'同一 Wi-Fi 下的其他设备', level:'warn', can_see:['访问的域名'],
       note:'公共 Wi-Fi 下尤为明显，ARP 嗅探即可拿到你的全部查询'}],
    leaks:[
      {title:'域名全量暴露', severity:'critical', detail:'你访问的每个域名都以明文出现，包括子域名和 API 端点（如 api.weixin.qq.com、passport.jd.com），观察者不需要解密就能拼出你在用什么服务、看什么内容。'},
      {title:'可被静默篡改', severity:'high', detail:'中间人可以返回任意 IP，把页面导向广告页或钓鱼站；HTTPS 证书告警往往是唯一的提示。'},
      {title:'时间与频率画像', severity:'medium', detail:'查询时间和频率能推断作息、通勤、是否在家，比内容本身更容易被用于画像。'},
      {title:'可被精准封锁', severity:'medium', detail:'只对特定域名丢包或返回 NXDOMAIN，其他域名照常——本报告第 3 节能直接测出这种选择性拦截。'}],
    evidence:['明文 53 可达：223.5.5.5 对 UDP/53 有响应，说明明文通道仍然通',
      '223.5.5.5:443 可达，具备开启 DoH 的网络条件','配置层：未发现网卡级 DoH 模板',
      '配置层：系统自动 DoH（EnableAutoDoh）=0（未开启）','Edge：DoH=off'],
    advice:['开启加密 DNS：设置 → 网络和 Internet → 以太网/WLAN → DNS 服务器分配 → 加密（DoH）',
      '只给浏览器开 DoH 不够：系统里其他应用（更新程序、客户端）仍在明文查询']
  } : {
    state:'encrypted', level:'ok', label:'已加密（行为已验证）', score:100, exposure:'low', exposure_label:'私密', breakdown:[],
    headline:'DNS 已加密：链路上看不到你查了什么域名',
    summary:'系统解析走 223.5.5.5 的加密通道（443/TLS），明文 53 已不是实际解析路径。',
    target:tgt, provider:'阿里 AliDNS', gateways:[gw],
    channels:[{name:'系统解析（浏览器与所有应用默认走这条）', encrypted:true,
      path:'本机 ⇄ 223.5.5.5:443 (TLS) → 阿里 AliDNS', state_text:'加密（HTTPS/DoH）', sees:'仅 DoH 服务商'}],
    observers:[
      {name:'DoH 服务商', level:'info', can_see:['访问的域名'],
       note:'加密后只有解析器知道你查了什么，这是加密 DNS 的信任代价'},
      {name:'运营商 / 路由器', level:'ok', can_see:['目标 IP 223.5.5.5:443','流量大小与时间'],
       note:'只能看到你在连哪个解析器，看不到具体域名'}],
    leaks:[],
    evidence:['行为层：系统结果与加密基准一致、与明文不同 -> 加密解析已生效',
      '检测到与 223.5.5.5:443 的活动 TCP 连接，符合 DoH 长连接特征',
      '配置层：2 个网卡写有 DoH 模板 https://dns.alidns.com/dns-query'],
    advice:['当前解析通道已加密，保持即可；每月复查一次确认没有回落到明文']
  };
  const rows = ['www.baidu.com','www.qq.com','github.com'].map((d,i)=>({
    domain:d, kind:i===2?'overseas':'domestic',
    sys_ips: plain?['110.242.69.21','110.242.68.66']:['110.242.69.21'],
    plain: plain?{ok:true,ips:['110.242.69.21'],rcode:0}:{ok:true,ips:['203.0.113.9'],rcode:0},
    public:{ok:true,ips:['110.242.69.21'],rcode:0},
    judge: plain
      ? {verdict: i===2?'plain_tampered':'normal', severity: i===2?'high':'good',
         reason: i===2?'系统结果等于明文结果，且与加密基准不一致 -> 仍走明文且疑似被篡改':'与加密基准一致'}
      : {verdict:'doh_active', severity:'good', reason:'系统结果与加密基准一致、与明文不同 -> 加密解析已生效'}
  }));
  return {
    score: plain?62:100, level: plain?'需留意':'低风险', rows,
    doh_status:{state: plain?'off':'active', level: plain?'bad':'ok',
      headline: plain?'未检测到 DoH 生效迹象，DNS 仍为明文':'DoH 已配置且行为层验证通过',
      details: plain?['明文 DNS（UDP 53）可被链路中间人直接查看和篡改']:['模板：https://dns.alidns.com/dns-query']},
    proxy_ports:[], privacy:pv, advice:pv.advice,
    resolvers:{current:tgt, proxied:false,
      dnssec:{tested:true, validating:false,
        detail:'dnssec-failed.org 仍返回 A 记录：解析器不验 DNSSEC，伪造应答发现不了'},
      recommend:{ip:'1.1.1.1', name:'Cloudflare', avg:18.4},
      rows:[
        {name:'Cloudflare', ip:'1.1.1.1', ok:true, avg:18.4, jitter:1.2, loss:0, doh_ok:true, dot_ok:true},
        {name:'114DNS', ip:'114.114.114.114', ok:true, avg:19.8, jitter:0.9, loss:0, doh_ok:false, dot_ok:false},
        {name:'阿里 AliDNS', ip:'223.5.5.5', ok:true, avg:21.0, jitter:0.8, loss:0, doh_ok:true, dot_ok:false},
        {name:'腾讯 DNSPod', ip:'119.29.29.29', ok:true, avg:24.6, jitter:2.1, loss:0, doh_ok:true, dot_ok:false},
        {name:'Google', ip:'8.8.8.8', ok:true, avg:56.2, jitter:4.4, loss:0, doh_ok:true, dot_ok:true}
      ]}
  };
}

async function boot(){
  const sel = document.getElementById('dohProvider');
  if(sel){
    sel.innerHTML = PROVIDERS.map((p,i)=>`<option value="${i}">${p.name}</option>`).join('');
    fillProvider();
  }
  if(location.search.includes('demo=')){
    const d = demoPayload(location.search.includes('demo=enc')?'enc':'plain');
    S.payload = d;
    renderAll();
    document.getElementById('heroSub').textContent = d.privacy.summary;
    document.getElementById('permChip').textContent = '预览模式';
    return;
  }
  try{
    const q = await api('/api/quick');
    S.quick = q;
    const perm = document.getElementById('permChip');
    perm.textContent = q.admin ? '管理员权限' : '普通权限';
    perm.className = 'chip ' + (q.admin?'admin':'warn');
    document.getElementById('elevBtn').style.display = q.admin ? 'none' : '';
    renderPrivacy(q.privacy);
    renderChannels(q.privacy);
    renderObservers(q.privacy);
    renderLeaks(q.privacy);
    renderEvidence(q.privacy);
    document.getElementById('heroSub').textContent = q.privacy.summary || '';

  }catch(e){ toast('读取系统信息失败：'+e.message); }

  // 不自动体检：只有用户点了按钮才跑
  try{
    const j = await api('/api/job?since=0');
    if(j.status==='running'){ setBusy(true); startPolling(); return; }
    if(j.status==='done' && j.payload){
      S.payload = j.payload;
      S.seen = j.log_total||0;
      document.getElementById('log').textContent = (j.log||[]).join('\n');
      renderAll();
      document.getElementById('heroSub').textContent =
        '上次体检结果 · ' + (j.payload.time||'').replace('T',' ') + '，点「重新体检」可刷新';
      return;
    }
  }catch(e){}

  // 空闲态：只展示配置层初判，等用户点「开始体检」
  const cta = document.getElementById('heroCta');
  if(cta) cta.style.display = '';
  setBusy(false);
  document.getElementById('scanBtn').textContent = '开始体检';
}

function fillProvider(){
  const i = Number(document.getElementById('dohProvider').value||0);
  const p = PROVIDERS[i]||PROVIDERS[0];
  document.getElementById('dohUrl').value = p.url;
  document.getElementById('dohIp').value = p.ip;
  const ip6 = document.getElementById('dohIp6');
  if(ip6) ip6.value = p.ip6 || '';
}

async function startScan(){
  try{
    const r = await api('/api/scan', {});
    if(!r.ok){ toast(r.error||'无法开始体检'); return; }
    S.seen = 0; S.payload = null;
    document.getElementById('log').textContent = '';
    const cta = document.getElementById('heroCta');
    if(cta) cta.style.display = 'none';
    setBusy(true);
    startPolling();
  }catch(e){ toast('体检启动失败：'+e.message); }
}

function setBusy(on, text){
  const b = document.getElementById('scanBtn');
  b.disabled = on;
  b.textContent = text || (on ? '体检中…' : (S.payload ? '重新体检' : '开始体检'));
}

/* 定时器驱动轮询：不会因为一次请求未返回就永久停摆 */
let POLL = null, INFLIGHT = false, WATCHDOG = null;

function stopPolling(){
  if(POLL){ clearInterval(POLL); POLL = null; }
  if(WATCHDOG){ clearTimeout(WATCHDOG); WATCHDOG = null; }
}

function startPolling(){
  stopPolling();
  INFLIGHT = false;
  POLL = setInterval(tick, 500);
  tick();
  WATCHDOG = setTimeout(()=>{
    if(POLL){
      stopPolling();
      setBusy(false);
      toast('任务超时，可能仍在后台执行，可点「重新体检」查看');
    }
  }, 150000);
}

async function tick(){
  if(INFLIGHT) return;
  INFLIGHT = true;
  try{
    const j = await api('/api/job?since='+S.seen);
    S.job = j;
    S.seen = j.log_total || 0;

    const pct = Math.round(100 * (j.progress||0) / Math.max(1,j.total||1));
    document.getElementById('pbar').style.width = (j.status==='running'? pct : (j.status==='done'?100:0)) + '%';
    document.getElementById('logHint').textContent = j.status==='running' ? (j.label||'') : '';

    const logEl = document.getElementById('log');
    if(j.log && j.log.length){
      logEl.textContent += (logEl.textContent?'\n':'') + j.log.join('\n');
      logEl.scrollTop = logEl.scrollHeight;
    }

    if(j.status==='running'){
      setBusy(true, `体检中 ${j.progress||0}/${j.total||1}`);
      return;
    }

    stopPolling();
    if(j.kind==='scan' && j.status==='done' && j.payload){
      S.payload = j.payload;
      renderAll();
      document.getElementById('heroSub').textContent = j.payload.privacy.summary || '';
    }
    setBusy(false);
    if(j.status==='error'){
      toast(j.error || '任务失败');
    }else if(j.kind==='doh' && j.status==='done'){
      const code = (j.payload&&j.payload.code);
      toast(code===0 ? 'DoH 操作完成，正在重新体检…' : 'DoH 操作结束（返回码 '+code+'），请看日志');
      if(code===0){ setTimeout(startScan, 800); }
    }
    setTimeout(()=>{ document.getElementById('pbar').style.width='0'; }, 1200);
  }catch(e){
    /* 网络抖动就跳过这一拍，定时器继续 */
  }finally{
    INFLIGHT = false;
  }
}

async function dohAction(action){
  const url = document.getElementById('dohUrl').value.trim();
  const ip = document.getElementById('dohIp').value.trim();
  const ip6El = document.getElementById('dohIp6');
  const ip6 = ip6El ? ip6El.value.trim() : '';
  if(action!=='rollback' && (!url || !ip)){ toast('请填写 DoH 地址和 IP'); return; }
  try{
    const r = await api('/api/doh', {action, url, ip, ip6});
    if(!r.ok){ toast(r.error||'操作失败'); return; }
    S.seen = 0;
    document.getElementById('log').textContent = '';
    setBusy(true);
    startPolling();
  }catch(e){ toast('操作失败：'+e.message); }
}

async function saveReport(fmt){
  try{
    const r = await api('/api/report', {format:fmt});
    if(!r.ok){ toast(r.error||'导出失败'); return; }
    const path = r.paths[fmt] || Object.values(r.paths)[0];
    toast('已导出：'+path);
  }catch(e){ toast('导出失败：'+e.message); }
}

async function openFolder(){
  try{ await api('/api/open', {}); }catch(e){ toast('打开失败'); }
}

async function elevate(){
  try{
    const r = await api('/api/elevate', {});
    if(!r.ok) toast(r.error||'提权失败');
  }catch(e){ toast('提权失败'); }
}

async function quit(){
  try{ await api('/api/quit', {}); }catch(e){}
  document.body.innerHTML = '<div style="padding:80px;text-align:center;color:#6a7280;font-family:sans-serif">DNS Guard 已退出，可以关闭这个页面了。</div>';
}

boot();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
