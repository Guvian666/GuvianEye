# -*- coding: utf-8 -*-
"""
GuvianEye 公网暴露面巡检 · 本地 Web 控制台 (零依赖)
================================================================
双击「启动控制台.bat」或执行 python app.py 即可:
  1) 启动本地服务 (默认 127.0.0.1:8899)
  2) 自动打开浏览器, 之后全部操作在图形界面完成

功能
  · 目标清单在线编辑
  · 扫描参数配置(端口范围 / 基线标签 / 并发 / 超时)
  · 一键扫描 / 中止, 实时进度与日志
  · 结果概览 + 高危端口处置建议
  · 历史记录与周度趋势
  · 报告在线查看 / 输出目录一键打开
  · 邮件推送设置与测试
  · 每周定时任务一键注册/卸载

安全: 默认只监听 127.0.0.1, 局域网无法访问。
      如确需远程访问, 用 --host 0.0.0.0 并自行做好网络隔离。
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import mimetypes
import os
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

BASE_DIR = Path(__file__).resolve().parent
WEBUI_DIR = BASE_DIR / "webui"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import scanner  # noqa: E402
import reporter  # noqa: E402

try:
    import notify  # noqa: E402
except Exception:
    notify = None

APP_VERSION = "2.0.0"

# 持久化日志：控制台的内存日志一重启就没了, 排查「昨天的邮件为什么失败」时
# 会完全找不到线索。这里同时落一份到 logs/console.log。
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "console.log"


def _append_logfile(line: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 2 * 1024 * 1024:
            LOG_FILE.write_text(
                LOG_FILE.read_text(encoding="utf-8", errors="replace")[-512 * 1024:],
                encoding="utf-8")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write("%s  %s\n" % (time.strftime("%Y-%m-%d"), line))
    except Exception:
        pass


# ==========================================================================
# 运行状态(线程安全)
# ==========================================================================
class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.stop_flag = False
        self.started_at = 0.0
        self.logs = collections.deque(maxlen=800)
        self.progress = {"done": 0, "total": 0, "percent": 0, "rate": 0,
                         "open": 0, "elapsed": 0, "eta": 0}
        self.phase = "空闲"
        self.last = None
        self.last_error = ""
        self.last_mail = None          # {"ok","message","time","recipients"}
        self.thread = None

    # ---- 写 ----
    def log(self, msg: str) -> None:
        line = str(msg).rstrip()
        if not line:
            return
        stamped = "%s  %s" % (time.strftime("%H:%M:%S"), line)
        with self.lock:
            self.logs.append(stamped)
        _append_logfile(stamped)

    def set_mail_result(self, ok: bool, message: str, recipients=None) -> None:
        with self.lock:
            self.last_mail = {"ok": bool(ok), "message": str(message),
                              "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                              "recipients": list(recipients or [])}
        _append_logfile("[邮件] %s %s" % ("OK" if ok else "FAILED", message))

    def set_progress(self, p: dict) -> None:
        with self.lock:
            self.progress = dict(p)

    def set_phase(self, phase: str) -> None:
        with self.lock:
            self.phase = phase

    # ---- 读 ----
    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "phase": self.phase,
                "started_at": self.started_at,
                "elapsed": round(time.time() - self.started_at, 1) if self.running else 0,
                "progress": dict(self.progress),
                "logs": list(self.logs)[-250:],
                "last": self.last,
                "last_error": self.last_error,
                "last_mail": self.last_mail,
                "version": APP_VERSION,
            }


STATE = AppState()


# ==========================================================================
# 后台扫描
# ==========================================================================
def _build_last(res: dict) -> dict:
    doc = res.get("doc") or {}
    summary = res.get("summary") or {}
    s = doc.get("summary", {})
    must_fix = []
    for h in doc.get("hosts", []):
        for p in h.get("open_ports", []):
            if p.get("risk") in ("CRITICAL", "HIGH"):
                act, why = reporter.remediation_of(p["port"], p.get("risk", "LOW"))
                must_fix.append({"ip": h["ip"], "port": p["port"],
                                 "service": p.get("service", ""),
                                 "risk": p.get("risk", ""),
                                 "is_new": bool(p.get("is_new")),
                                 "action": act, "why": why})
    must_fix.sort(key=lambda x: (reporter.RISK_ORDER.get(x["risk"], 9), x["port"]))

    new_ports = sorted(summary.get("new", []),
                       key=lambda x: (reporter.RISK_ORDER.get(x.get("risk", "LOW"), 9),
                                      x["port"]))
    gone_ports = summary.get("gone", [])

    return {
        "scan_time": doc.get("scan_time", ""),
        "elapsed_sec": doc.get("elapsed_sec", 0),
        "hosts_total": doc.get("hosts_total", 0),
        "ports_scanned": doc.get("ports_scanned", 0),
        "probes": doc.get("probes", 0),
        "scan_label": doc.get("scan_label", ""),
        "baseline_time": doc.get("baseline_time", ""),
        "summary": s,
        "quality": doc.get("quality") or {},
        "expected_diff": doc.get("expected_diff") or {},
        "warnings": res.get("warnings", []),
        "paths": res.get("paths", {}),
        "must_fix": must_fix[:200],
        "new_ports": new_ports[:200],
        "gone_ports": gone_ports[:200],
        "report_url": ("/report/" + Path(res["paths"]["html"]).name
                       if res.get("paths", {}).get("html") else ""),
        "unreachable_ratio": doc.get("unreachable_ratio", 0),
    }


def _scan_worker(cfg: dict, target_path: Path, only: str, mode: str, expr: str,
                 label: str, use_mail: bool, dry_run: bool,
                 verify_after: bool = False) -> None:
    phase_map = {"[1/4]": "存活预判中", "[2/4]": "端口扫描中",
                 "[3/4]": "指纹识别中", "[4/4]": "生成报告中"}

    def on_log(msg):
        STATE.log(msg)
        text = str(msg)
        for k, v in phase_map.items():
            if k in text:
                STATE.set_phase(v)
                break

    def on_progress(p):
        STATE.set_progress(p)

    def should_stop():
        return STATE.stop_flag

    # ★ 窗口标题防呆: 扫描期间明确告诉用户"别关这个窗口"。
    #   实测痛点: 用户在收尾/复核阶段误关窗口 → 进程死亡 → 成果丢失。
    set_console_title(TITLE_BUSY)

    _ui = cfg.get("ui") or {}
    auto_exit = bool(_ui.get("auto_exit_after_scan"))
    try:
        auto_exit_delay = max(0, int(_ui.get("auto_exit_delay", 8) or 0))
    except Exception:
        auto_exit_delay = 8

    def _auto_exit_if_needed():
        """勾选了「扫描完成后自动退出」时, 留缓冲后关闭整个控制台进程。"""
        if not auto_exit:
            return
        STATE.log("[提示] 已勾选「扫描完成后自动退出」, %d 秒后自动关闭本窗口…"
                  % auto_exit_delay)
        STATE.log("        报告已保存在 reports/ , 关闭窗口不影响查看。")
        try:
            time.sleep(auto_exit_delay)
        except Exception:
            pass
        os._exit(0)

    try:
        targets = scanner.load_targets(target_path, only)
        ports = scanner.build_ports(mode, expr, cfg)
        STATE.log("目标 %d 台, 端口 %d 个, 基线标签 %s"
                  % (len(targets), len(ports), scanner.sanitize_label(label)))

        res = asyncio.run(scanner.execute_scan(
            cfg, targets, ports, label,
            on_log=on_log, on_progress=on_progress, should_stop=should_stop,
            dry_run=dry_run))
    except scanner.Cancelled:
        STATE.log("[!] 扫描已被用户中止")
        with STATE.lock:
            STATE.running = False
            STATE.phase = "已中止"
        set_console_title(TITLE_IDLE)
        return
    except Exception as exc:
        STATE.log("[!] 扫描失败: %s" % exc)
        STATE.log(traceback.format_exc().strip().splitlines()[-1])
        with STATE.lock:
            STATE.running = False
            STATE.phase = "失败"
            STATE.last_error = str(exc)
        set_console_title(TITLE_IDLE)
        return

    if dry_run:
        STATE.log("[演练] 配置检查通过, 未发送任何报文")
        with STATE.lock:
            STATE.running = False
            STATE.phase = "空闲"
        set_console_title(TITLE_DONE if auto_exit else TITLE_IDLE)
        _auto_exit_if_needed()
        return

    # 邮件
    if use_mail:
        if notify is None:
            STATE.set_mail_result(False, "邮件模块 notify.py 加载失败, 无法发送")
            STATE.log("[!] 邮件发送失败: notify.py 不可用")
        else:
            only_changed = cfg["mail"].get("send_when_changed_only")
            summary = res.get("summary") or {}
            if only_changed and not (summary.get("new") or summary.get("gone")
                                     or summary.get("new_hosts")):
                STATE.set_mail_result(True, "本次无变化, 按配置跳过发送")
                STATE.log("[邮件] 本次无变化, 按配置跳过发送")
            else:
                recips = cfg["mail"].get("recipients") or []
                try:
                    notify.send(cfg["mail"], res["doc"], summary,
                                res["paths"]["html"] or None, res["paths"]["csv"])
                    STATE.set_mail_result(True, "已发送至 %s" % ", ".join(recips),
                                          recips)
                    STATE.log("[邮件] 已发送至 %s" % ", ".join(recips))
                except Exception as exc:
                    STATE.set_mail_result(False, str(exc), recips)
                    for ln in ("邮件发送失败: %s" % exc).splitlines():
                        STATE.log("[!] %s" % ln)

    # ★ 扫描完成后自动做定向复核(界面上的勾选项)。
    #   为什么放在这里: 漏报最集中的就是「历史清单里有、这一轮却没扫到」的那批端口。
    #   主扫描一结束就趁热用极低并发复核一遍, 用户不用再手动双击 一键复核.bat,
    #   也不会忘。复核失败不影响已完成的扫描结果(报告早已落盘)。
    if verify_after and res.get("doc"):
        vcfg = cfg.get("verify") or {}
        try:
            with STATE.lock:
                STATE.phase = "复核中"
            STATE.log("")
            STATE.log("=" * 62)
            STATE.log("  扫描完成, 接着做定向复核(已勾选「扫描后自动复核」)")
            STATE.log("  对照基线 %s ｜ %d 轮"
                      % (scanner.sanitize_label(str(vcfg.get("from_label") or "default")),
                         max(1, min(20, int(vcfg.get("rounds") or 5)))))
            STATE.log("=" * 62)
            rc = asyncio.run(scanner.verify_missing(
                cfg,
                prev_label=str(vcfg.get("from_label") or "default"),
                rounds=max(1, min(20, int(vcfg.get("rounds") or 5))),
                delay=max(0.0, float(vcfg.get("delay", 2.0) or 0)),
                on_log=STATE.log))
            STATE.log("[复核] 结束 (返回码 %d)" % rc)
        except Exception as exc:
            STATE.log("[!] 自动复核失败(不影响已完成的扫描结果): %s" % exc)

    with STATE.lock:
        STATE.last = _build_last(res)
        STATE.running = False
        STATE.phase = "空闲"
    STATE.log("扫描流程结束")

    # ★ 收尾提示: 把窗口标题改成"可以安全关闭", 用户一眼就知道现在能关了。
    #   若勾选了「自动退出」, 标题直接给完成提示, 缓冲几秒后自动关窗。
    set_console_title(TITLE_DONE)
    _auto_exit_if_needed()


# ==========================================================================
# 控制台窗口标题 —— 让用户一眼知道「现在能不能关窗口」
# ==========================================================================
def set_console_title(text: str) -> None:
    """修改承载本进程的那个控制台窗口的标题。

    为什么需要它: 用户最容易犯的错就是"以为跑完了，顺手把黑窗口关了"，
    结果进程被杀、成果丢失（2026-10-14 实测踩过一次 77 分钟的坑）。
    扫描一结束就把标题改成明确提示，是成本最低、最有效的防呆手段。
    非 Windows 或没有控制台时静默失败，不影响任何功能。
    """
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(str(text))
    except Exception:
        pass


TITLE_IDLE = "GuvianEye Console"
TITLE_BUSY = "GuvianEye - 正在运行中, 请勿关闭本窗口"
TITLE_DONE = "GuvianEye - 已完成, 可以安全关闭本窗口"


def start_scan(cfg: dict, target_path: Path, only: str, mode: str, expr: str,
               label: str, use_mail: bool, dry_run: bool,
               verify_after: bool = False) -> tuple:
    with STATE.lock:
        if STATE.running:
            return False, "已有扫描任务在运行"
        STATE.running = True
        STATE.stop_flag = False
        STATE.started_at = time.time()
        STATE.logs.clear()
        STATE.progress = {"done": 0, "total": 0, "percent": 0, "rate": 0,
                          "open": 0, "elapsed": 0, "eta": 0}
        STATE.phase = "启动中"
        STATE.last_error = ""

    t = threading.Thread(target=_scan_worker,
                         args=(cfg, target_path, only, mode, expr, label,
                               use_mail, dry_run, verify_after),
                         name="scan-worker", daemon=True)
    STATE.thread = t
    t.start()
    return True, "已启动"


# ==========================================================================
# 配置读写
# ==========================================================================
def load_cfg() -> dict:
    return scanner.make_config(BASE_DIR / "config.json")


def save_cfg(patch: dict) -> dict:
    cfg = load_cfg()
    merged = scanner.deep_merge(cfg, patch)
    (BASE_DIR / "config.json").write_text(
        json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return merged


def cfg_for_ui(cfg: dict) -> dict:
    mail = dict(cfg.get("mail", {}))
    masked = dict(mail)
    masked["auth_code_set"] = bool(mail.get("auth_code"))
    masked["auth_code"] = ""          # 不回传明文
    return {
        "ports": cfg.get("ports", {}),
        "scan": cfg.get("scan", {}),
        "verify": cfg.get("verify", {}),
        "ui": cfg.get("ui", {}),
        "report": cfg.get("report", {}),
        "mail": masked,
        "baseline_label": cfg.get("baseline_label", "default"),
        "targets_file": cfg.get("targets_file", "targets.txt"),
        "max_expand_per_token": scanner.MAX_EXPAND_PER_TOKEN,
        "max_total_targets": scanner.MAX_TOTAL_TARGETS,
    }


# ==========================================================================
# HTTP 处理
# ==========================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "GuvianEye/" + APP_VERSION
    protocol_version = "HTTP/1.1"

    # ---------- 基础 ----------
    def log_message(self, fmt, *args):
        pass  # 静默, 避免刷屏

    def _send(self, code: int, body: bytes, ctype: str,
              extra: dict = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, msg: str, code: int = 400) -> None:
        self._json({"ok": False, "error": msg}, code)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---------- 路由 ----------
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        try:
            if p in ("/", "/index.html"):
                return self._static("index.html")
            if p.startswith("/static/"):
                return self._static(p[len("/static/"):])
            if p.startswith("/report/"):
                return self._report(unquote(p[len("/report/"):]))
            if p == "/api/state":
                return self._json(STATE.snapshot())
            if p == "/api/config":
                cfg = load_cfg()
                return self._json({"ok": True, "config": cfg_for_ui(cfg),
                                   "raw_ports_mode": cfg["ports"].get("mode")})
            if p == "/api/targets":
                f = BASE_DIR / load_cfg().get("targets_file", "targets.txt")
                return self._json({"ok": True,
                                   "content": f.read_text(encoding="utf-8")
                                   if f.exists() else ""})
            if p == "/api/history":
                hist = scanner.load_history(BASE_DIR / "baseline")
                return self._json({"ok": True, "history": list(reversed(hist))[:60]})
            if p == "/api/reports":
                return self._json({"ok": True, "reports": self._report_list()})
            if p == "/api/task":
                return self._json({"ok": True, "task": self._task_status()})
            if p == "/api/health":
                return self._json({"ok": True, "version": APP_VERSION})
            return self._err("未知路径: %s" % p, 404)
        except Exception as exc:
            return self._json({"ok": False, "error": str(exc),
                               "trace": traceback.format_exc()[-800:]}, 500)

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path
        try:
            data = self._body()
            if p == "/api/targets":
                return self._save_targets(data)
            if p == "/api/config":
                return self._save_config(data)
            if p == "/api/scan/start":
                return self._scan_start(data)
            if p == "/api/scan/stop":
                STATE.stop_flag = True
                STATE.log("[!] 已请求中止, 等待当前批次结束…")
                return self._json({"ok": True})
            if p == "/api/preflight":
                return self._preflight()
            if p == "/api/verify":
                return self._verify(data)
            if p == "/api/mail/test":
                return self._mail_test()
            if p == "/api/task/register":
                return self._task_register(data)
            if p == "/api/task/remove":
                return self._task_remove()
            if p == "/api/open-dir":
                return self._open_dir(data)
            return self._err("未知路径: %s" % p, 404)
        except Exception as exc:
            return self._json({"ok": False, "error": str(exc),
                               "trace": traceback.format_exc()[-800:]}, 500)

    # ---------- 静态 ----------
    def _static(self, rel: str):
        rel = rel.lstrip("/").replace("\\", "/")
        if ".." in rel:
            return self._err("非法路径", 400)
        f = WEBUI_DIR / rel
        if not f.exists() or not f.is_file():
            return self._err("资源不存在: %s" % rel, 404)
        ctype = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return self._send(200, f.read_bytes(), ctype)

    def _report(self, name: str):
        name = os.path.basename(name)
        f = BASE_DIR / load_cfg()["report"]["dir"] / name
        if not f.exists() or not f.is_file():
            return self._err("报告不存在", 404)
        return self._send(200, f.read_bytes(), "text/html; charset=utf-8")

    def _report_list(self) -> list:
        d = BASE_DIR / load_cfg()["report"]["dir"]
        out = []
        if d.exists():
            for f in sorted(d.glob("report_*.html"), reverse=True)[:40]:
                st = f.stat()
                out.append({"name": f.name, "size": st.st_size,
                            "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime(st.st_mtime)),
                            "url": "/report/" + f.name})
        return out

    # ---------- 业务 ----------
    def _save_targets(self, data: dict):
        content = str(data.get("content", ""))
        f = BASE_DIR / load_cfg().get("targets_file", "targets.txt")
        f.write_text(content, encoding="utf-8")
        tmp = BASE_DIR / "_targets_check.txt"
        tmp.write_text(content, encoding="utf-8")
        try:
            ips = scanner.load_targets(tmp)
            return self._json({"ok": True, "count": len(ips), "targets": ips})
        except SystemExit as exc:
            return self._json({"ok": False, "error": str(exc)}, 400)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass

    def _save_config(self, data: dict):
        patch = {}
        if isinstance(data.get("scan"), dict):
            patch["scan"] = {k: v for k, v in data["scan"].items()
                             if not k.startswith("_")}
        if isinstance(data.get("ports"), dict):
            patch["ports"] = {k: v for k, v in data["ports"].items()
                              if not k.startswith("_")}
        if "baseline_label" in data:
            patch["baseline_label"] = str(data["baseline_label"])
        if isinstance(data.get("mail"), dict):
            mail = data["mail"]
            cur = load_cfg().get("mail", {})
            new_mail = {k: v for k, v in mail.items()
                        if k in ("enabled", "smtp_host", "smtp_port", "use_ssl",
                                 "sender", "recipients", "send_when_changed_only")}
            if mail.get("auth_code"):          # 只有填了才覆盖
                new_mail["auth_code"] = mail["auth_code"]
            elif not cur.get("auth_code"):
                new_mail["auth_code"] = ""
            patch["mail"] = new_mail
        cfg = save_cfg(patch)
        return self._json({"ok": True, "config": cfg_for_ui(cfg),
                           "raw_ports_mode": cfg["ports"].get("mode")})

    def _scan_start(self, data: dict):
        cfg = load_cfg()
        mode = str(data.get("mode") or cfg["ports"].get("mode") or "all")
        expr = str(data.get("expr") or "")
        label = str(data.get("label") or cfg.get("baseline_label") or "default")
        only = str(data.get("only") or "")
        use_mail = bool(data.get("mail"))
        dry_run = bool(data.get("dry_run"))
        # 前端没传时沿用 config 里的设置, 传了就落盘
        _va = data.get("verify_after")
        verify_after = (bool(_va) if _va is not None
                        else bool((cfg.get("verify") or {}).get("after_scan")))

        # 端口表达式 / 模式先落到 config, 保证下次打开界面状态一致
        if expr:
            save_cfg({"ports": {"mode": "custom", "ranges": expr}})
            cfg = load_cfg()
            mode = "custom"
        elif mode:
            save_cfg({"ports": {"mode": mode}})
            cfg = load_cfg()
        if label:
            save_cfg({"baseline_label": label})
            cfg = load_cfg()
        if _va is not None:
            save_cfg({"verify": {"after_scan": verify_after}})
            cfg = load_cfg()
        # 「扫描完成后自动退出控制台」也落盘, 下次打开界面状态一致
        _ax = data.get("auto_exit_after_scan")
        if _ax is not None:
            save_cfg({"ui": {"auto_exit_after_scan": bool(_ax)}})
            cfg = load_cfg()
        # 「跳过补扫」(ui.skip_rescan) 同样落盘, 但**只清本次运行的轮数**,
        # 不动 scan 段里的调参(见 scanner.execute_scan)
        _sr = data.get("skip_rescan")
        if _sr is not None:
            save_cfg({"ui": {"skip_rescan": bool(_sr)}})
            cfg = load_cfg()

        target_path = BASE_DIR / cfg.get("targets_file", "targets.txt")
        try:
            n = len(scanner.load_targets(target_path, only))
        except SystemExit as exc:
            return self._json({"ok": False, "error": str(exc)}, 400)
        if n == 0:
            return self._err("目标清单为空, 请先在「扫描」页填写 IP")

        try:
            pn = len(scanner.build_ports(mode, expr, cfg))
        except ValueError as exc:
            return self._err(str(exc))

        ok, msg = start_scan(cfg, target_path, only, mode, expr, label,
                             use_mail, dry_run, verify_after)
        return self._json({"ok": ok, "message": msg,
                           "targets": n, "ports": pn,
                           "verify_after": verify_after,
                           "skip_rescan":
                               bool((cfg.get("ui") or {}).get("skip_rescan")),
                           "auto_exit_after_scan":
                               bool((cfg.get("ui") or {}).get("auto_exit_after_scan"))},
                          200 if ok else 409)

    def _preflight(self):
        """网络预检: 只测可达性/RTT/链路承载能力, 不碰真实业务端口。

        换网络(办公网 -> 手机热点等)后必做。后台线程跑, 输出直接进控制台日志区。
        """
        if STATE.running:
            return self._err("扫描进行中, 请先等待完成或点【停止】", 409)
        cfg = load_cfg()
        target_path = BASE_DIR / cfg.get("targets_file", "targets.txt")
        try:
            targets = scanner.load_targets(target_path)
        except SystemExit as exc:
            return self._json({"ok": False, "error": str(exc)}, 400)
        if not targets:
            return self._err("目标清单为空")

        STATE.log("")
        STATE.log("=" * 62)
        STATE.log("  开始网络预检 —— 只探测链路能力, 不扫描真实业务端口")
        STATE.log("  当前并发 %d / 超时 %.2fs"
                  % (cfg["scan"]["concurrency"], cfg["scan"]["connect_timeout"]))
        STATE.log("=" * 62)

        # ★ 预检也要占用 running —— 实测教训: 预检和扫描并发跑时两者都会打满
        #   出口链路, 互相干扰并加剧目标侧限速, 会让扫描结果更不准。
        with STATE.lock:
            STATE.running = True
            STATE.stop_flag = False
            STATE.started_at = time.time()
            STATE.phase = "网络预检中"

        def worker():
            try:
                rc = asyncio.run(scanner.preflight(cfg, targets, on_log=STATE.log))
                STATE.log("[预检] 结束 (返回码 %d%s)"
                          % (rc, "; 有红灯项, 见上方 [!!]" if rc else ""))
            except Exception as exc:
                STATE.log("[预检] 失败: %s" % exc)
                STATE.log(traceback.format_exc()[-500:])
            finally:
                with STATE.lock:
                    STATE.running = False
                    STATE.phase = "空闲"

        STATE.thread = threading.Thread(target=worker, daemon=True,
                                        name="preflight-worker")
        STATE.thread.start()
        return self._json({"ok": True, "message": "预检已启动, 请看下方日志"})

    def _verify(self, data: dict):
        """定向复核: 复核「历史基线清单里有、上一轮却没扫到」的端口。

        为什么要它: 扫描漏报最多的地方就是"历史上有、这轮没有"的那批端口 ——
        它们既可能是真关闭了, 也可能是被源 IP 限速吞掉了。复核用**极低并发**
        (单机 4 连接)+ 多轮重探 + 对照组, 专门把这两种情况分开。

        现在可以直接在控制台点按钮/勾选自动执行, 不必再双击 一键复核.bat。
        """
        if STATE.running:
            return self._err("已有任务(扫描/预检/复核)在运行, 请先等待完成或点【停止】", 409)

        cfg = load_cfg()
        vcfg = cfg.get("verify") or {}
        from_label = str(data.get("from") or vcfg.get("from_label") or "default")
        try:
            rounds = max(1, min(20, int(data.get("rounds") or vcfg.get("rounds") or 5)))
        except (TypeError, ValueError):
            rounds = 5
        try:
            _d = data.get("delay")
            delay = max(0.0, float(_d if _d is not None else vcfg.get("delay", 2.0)))
        except (TypeError, ValueError):
            delay = 2.0

        # 落盘, 保证下次打开界面时状态一致
        save_cfg({"verify": {"from_label": from_label,
                             "rounds": rounds, "delay": delay}})
        cfg = load_cfg()

        with STATE.lock:
            STATE.running = True
            STATE.stop_flag = False
            STATE.started_at = time.time()
            STATE.logs.clear()
            STATE.progress = {"done": 0, "total": 0, "percent": 0, "rate": 0,
                              "open": 0, "elapsed": 0, "eta": 0}
            STATE.phase = "复核中"
            STATE.last_error = ""

        STATE.log("")
        STATE.log("=" * 62)
        STATE.log("  开始定向复核 —— 复核历史清单中上一轮未扫到的端口")
        STATE.log("  对照基线 %s ｜ %d 轮 ｜ 轮间隔 %.1fs"
                  % (scanner.sanitize_label(from_label), rounds, delay))
        STATE.log("=" * 62)

        def worker():
            try:
                rc = asyncio.run(scanner.verify_missing(
                    cfg, prev_label=from_label, rounds=rounds, delay=delay,
                    on_log=STATE.log))
                STATE.log("[复核] 结束 (返回码 %d)" % rc)
                if rc == 4:
                    STATE.log("[复核] 提示: 返回码 4 通常表示「找不到对照基线」或"
                              "「缺少 expected_ports.json」, 请看上方说明。")
            except Exception as exc:
                STATE.log("[复核] 失败: %s" % exc)
                STATE.log(traceback.format_exc()[-500:])
                with STATE.lock:
                    STATE.last_error = str(exc)
            finally:
                with STATE.lock:
                    STATE.running = False
                    STATE.phase = "空闲"

        STATE.thread = threading.Thread(target=worker, daemon=True,
                                        name="verify-worker")
        STATE.thread.start()
        return self._json({"ok": True, "message": "定向复核已启动, 请看下方日志",
                           "from": from_label, "rounds": rounds})

    def _mail_test(self):
        if notify is None:
            return self._err("notify.py 不可用")
        m = load_cfg()["mail"]
        if not m.get("auth_code"):
            return self._err("尚未配置 SMTP 授权码, 请先在「设置」页填写并保存")
        recips = m.get("recipients") or [m.get("sender")]
        try:
            got = notify.send_test(m)
            STATE.set_mail_result(True, "测试邮件已发送至 %s" % ", ".join(got), got)
            STATE.log("[邮件] 测试发送成功 → %s" % ", ".join(got))
            return self._json({"ok": True,
                               "message": "测试邮件已发送至 " + ", ".join(got)})
        except Exception as exc:
            mailerr = getattr(notify, "MailError", RuntimeError)
            human = (str(exc) if isinstance(exc, mailerr)
                     else notify._classify(exc, m)[1])
            STATE.set_mail_result(False, human, recips)
            for ln in ("测试邮件发送失败: %s" % human).splitlines():
                STATE.log("[!] %s" % ln)
            return self._json({"ok": False, "error": human}, 400)

    # ---------- 定时任务 ----------
    TASK_NAME = "PublicExposureWeeklyScan"

    def _task_status(self) -> dict:
        if sys.platform != "win32":
            return {"supported": False, "message": "仅支持 Windows 任务计划程序"}
        try:
            r = subprocess.run(
                ["schtasks", "/Query", "/TN", self.TASK_NAME, "/FO", "LIST"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace")
            if r.returncode != 0:
                return {"supported": True, "registered": False}
            info = {}
            for line in (r.stdout or "").splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    info[k.strip()] = v.strip()
            return {"supported": True, "registered": True,
                    "next_run": info.get("下次运行时间") or info.get("Next Run Time", ""),
                    "status": info.get("状态") or info.get("Status", ""),
                    "raw": info}
        except Exception as exc:
            return {"supported": True, "registered": False, "error": str(exc)}

    def _task_register(self, data: dict):
        if sys.platform != "win32":
            return self._err("仅支持 Windows 任务计划程序")
        day = str(data.get("day") or "MON")
        tm = str(data.get("time") or "09:00")
        mode = str(data.get("mode") or "all")
        script = BASE_DIR / "run_weekly.bat"
        if not script.exists():
            return self._err("找不到 run_weekly.bat")
        # 去重: 先删同名任务
        subprocess.run(["schtasks", "/Delete", "/TN", self.TASK_NAME, "/F"],
                       capture_output=True, text=True, timeout=20)
        # schtasks 的 /ST 需要 HH:mm, /SC WEEKLY /D 接受 MON/TUE…
        r = subprocess.run(
            ["schtasks", "/Create", "/TN", self.TASK_NAME, "/TR",
             '"%s" %s nopause' % (script, mode),
             "/SC", "WEEKLY", "/D", day, "/ST", tm, "/F"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return self._json({"ok": False,
                               "error": (r.stdout or "") + (r.stderr or "")}, 400)
        return self._json({"ok": True, "message": "已注册: 每周 %s %s 执行 %s 模式"
                           % (day, tm, mode)})

    def _task_remove(self):
        r = subprocess.run(["schtasks", "/Delete", "/TN", self.TASK_NAME, "/F"],
                           capture_output=True, text=True, timeout=20,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return self._json({"ok": False,
                               "error": (r.stdout or "") + (r.stderr or "")}, 400)
        return self._json({"ok": True, "message": "定时任务已删除"})

    def _open_dir(self, data: dict):
        which = str(data.get("which") or "reports")
        cfg = load_cfg()
        d = BASE_DIR / (cfg["report"]["dir"] if which == "reports"
                        else cfg["report"]["baseline_dir"])
        try:
            if sys.platform == "win32":
                os.startfile(str(d))          # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(d)])
            else:
                subprocess.Popen(["xdg-open", str(d)])
            return self._json({"ok": True, "message": "已打开: %s" % d})
        except Exception as exc:
            return self._err("打开失败: %s" % exc)


# ==========================================================================
# 启动
# ==========================================================================
BANNER = r"""
  ______                     _              _____ _
 |  ____|                   | |            |  ___| |
 | |__  __  ___ __   ___ _ __| |_ __ _  ___| |__ | | __ _  ___
 |  __| \ \/ / '_ \ / _ \ '__| __/ _` |/ __|  __|| |/ _` |/ _ \
 | |____ >  <| |_) |  __/ |  | || (_| | (__| |___| | (_| |  __/
 |______/_/\_\ .__/ \___|_|   \__\__,_|\___\____|_|\__,_|\___|
             | |   Public Exposure Scanner  ·  Local Console
             |_|   v%s
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="GuvianEye 公网暴露面巡检 · 本地 Web 控制台")
    ap.add_argument("--host", default="127.0.0.1",
                    help="监听地址, 默认 127.0.0.1(仅本机)。填 0.0.0.0 可局域网访问")
    ap.add_argument("--port", type=int, default=8899, help="监听端口, 默认 8899")
    ap.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = ap.parse_args()

    if not WEBUI_DIR.exists():
        print("[!] 缺少 webui 目录, 无法启动界面")
        return 1

    port = args.port
    httpd = None
    for i in range(20):                      # 端口被占用则往后顺延
        try:
            httpd = ThreadingHTTPServer((args.host, port + i), Handler)
            port = port + i
            break
        except OSError:
            continue
    if httpd is None:
        print("[!] 无法绑定端口 %d ~ %d" % (args.port, args.port + 19))
        return 1

    print(BANNER % APP_VERSION)
    set_console_title(TITLE_IDLE)
    print("  控制台地址 : http://%s:%d" % (args.host, port))
    print("  工作目录   : %s" % BASE_DIR)
    print("  基线标签   : %s" % load_cfg().get("baseline_label", "default"))
    if args.host not in ("127.0.0.1", "localhost"):
        print("\n  ⚠ 已监听 %s —— 局域网内其他设备可访问, 请确认网络环境可信。"
              % args.host)
        print("    本服务没有登录鉴权, 切勿暴露到公网。")
    if not load_cfg()["mail"].get("auth_code"):
        print("\n  提示: 邮件推送尚未配置授权码, 可在「设置」页填写后再扫描。")
    print("\n  窗口使用提示: 扫描运行期间请勿关闭本窗口;")
    print("  扫描完成时标题会变成「已完成, 可以安全关闭本窗口」, 那时再关即可。")
    print("\n  按 Ctrl+C 退出\n" + "-" * 66)

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(
            "http://127.0.0.1:%d/" % port)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        set_console_title(TITLE_DONE)
        print("\n  正在退出…(本窗口现在可以安全关闭)")
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
