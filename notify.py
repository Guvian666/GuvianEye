# -*- coding: utf-8 -*-
"""
邮件推送模块
通过 SMTP 发送巡检摘要 + HTML报告/CSV 附件。

QQ 邮箱注意: auth_code 必须是「SMTP 授权码」, 不是登录密码。
获取方式: QQ邮箱 → 设置 → 账户 → POP3/IMAP/SMTP服务 → 开启并生成授权码。
"""

from __future__ import annotations

import html
import mimetypes
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path

RISK_LABEL = {"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低"}

# 附件合计上限：多数邮箱 20~25MB，超过基本必被拒
MAX_ATTACH_BYTES = 20 * 1024 * 1024
# 重试次数与退避基数（秒）：2s、4s
MAIL_ATTEMPTS = 3
MAIL_BACKOFF = 2


class MailError(RuntimeError):
    """邮件发送失败。message 直接面向使用者，包含可执行的排查步骤。"""


def _fmt_new(items: list, limit: int = 30) -> str:
    if not items:
        return '<p style="color:#067647"><b>与上周基线相比无新增开放端口。</b></p>'
    rows = []
    for it in items[:limit]:
        color = "#d92d20" if it.get("risk") == "CRITICAL" else (
            "#b54708" if it.get("risk") == "HIGH" else "#475467")
        rows.append(
            '<tr>'
            '<td style="padding:5px 10px;border-bottom:1px solid #eef2f7;font-family:Consolas,monospace">%s</td>'
            '<td style="padding:5px 10px;border-bottom:1px solid #eef2f7;font-weight:700">%s</td>'
            '<td style="padding:5px 10px;border-bottom:1px solid #eef2f7">%s</td>'
            '<td style="padding:5px 10px;border-bottom:1px solid #eef2f7;color:%s;font-weight:600">%s</td>'
            '</tr>' % (html.escape(it["ip"]), it["port"],
                       html.escape(it.get("service") or "-"),
                       color, RISK_LABEL.get(it.get("risk"), it.get("risk", ""))))
    tail = ""
    if len(items) > limit:
        tail = ('<p style="color:#667085;font-size:12px">… 其余 %d 条详见附件报告</p>'
                % (len(items) - limit))
    return ('<table style="width:100%;border-collapse:collapse;font-size:13px">'
            '<thead><tr style="background:#f5f8fc;text-align:left">'
            '<th style="padding:7px 10px">IP</th><th style="padding:7px 10px">端口</th>'
            '<th style="padding:7px 10px">服务</th><th style="padding:7px 10px">风险</th>'
            '</tr></thead><tbody>%s</tbody></table>%s' % ("".join(rows), tail))


def build_body(doc: dict, summary: dict) -> str:
    s = doc["summary"]
    crit_new = [x for x in summary["new"] if x.get("risk") in ("CRITICAL", "HIGH")]
    head_color = "#d92d20" if crit_new else ("#b54708" if summary["new"] else "#067647")
    if crit_new:
        head_txt = "⚠ 发现 %d 个新增高危/严重端口 —— 建议今日内确认处置" % len(crit_new)
    elif summary["new"]:
        head_txt = "发现 %d 个新增开放端口（中低风险），请确认业务必要性" % len(summary["new"])
    else:
        head_txt = "✅ 暴露面与上周一致，无新增端口"

    def card(k, v, color="#16202c", sub=""):
        return ('<td style="padding:0 6px"><div style="background:#fff;border:1px solid #d9e2ec;'
                'border-radius:9px;padding:12px 14px">'
                '<div style="font-size:12px;color:#64748b">%s</div>'
                '<div style="font-size:22px;font-weight:700;color:%s">%s</div>'
                '<div style="font-size:11px;color:#94a3b8">%s</div></div></td>'
                % (k, color, v, sub))

    anomaly = [h["ip"] for h in doc["hosts"] if h.get("anomaly")]
    anomaly_html = ""
    if anomaly:
        anomaly_html = ('<div style="background:#fff4e5;border-left:4px solid #dc6803;'
                        'padding:10px 14px;border-radius:7px;margin:14px 0;font-size:13px">'
                        '<b>%d 台主机返回异常结果</b>（开放端口数超阈值，疑似运营商安全墙统一'
                        '应答或蜜罐），其结论不可直接采信：%s</div>'
                        % (len(anomaly), "、".join(html.escape(x) for x in anomaly)))

    return """<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;background:#eef2f7;font-family:'Microsoft YaHei',Arial,sans-serif;
 color:#16202c;font-size:14px">
<div style="max-width:820px;margin:0 auto;padding:20px">
  <div style="background:linear-gradient(120deg,#0b3d6b,#1570ef);color:#fff;
   border-radius:11px;padding:20px 24px">
    <div style="font-size:19px;font-weight:700">GuvianEye 公网暴露面巡检周报</div>
    <div style="font-size:12.5px;opacity:.9;margin-top:6px">
      扫描时间 %s ｜ 耗时 %.1f 秒 ｜ 资产 %d 台 ｜ 探测 %s 次
    </div>
  </div>

  <div style="color:%s;font-size:15px;font-weight:700;margin:16px 0 12px">%s</div>

  <table style="width:100%%;border-collapse:separate;border-spacing:0"><tr>
    %s%s%s
  </tr></table>

  %s

  <div style="background:#fff;border:1px solid #d9e2ec;border-radius:10px;
   padding:16px 18px;margin-top:16px">
    <div style="font-weight:700;font-size:15px;margin-bottom:10px">本周新增开放端口</div>
    %s
  </div>

  <div style="color:#64748b;font-size:12px;margin-top:18px;line-height:1.9">
    完整报告（含搜索/筛选/每台主机明细）见附件 HTML 文件，双击即可在浏览器打开。<br>
    本报告由 TCP connect 实际探测生成，仅用于自有或已获授权资产的暴露面管理。
  </div>
</div></body></html>""" % (
        html.escape(doc["scan_time"]), doc["elapsed_sec"], doc["hosts_total"],
        format(doc["probes"], ","),
        head_color, head_txt,
        card("开放端口", s["open_total"], "#1570ef", "全部资产合计"),
        card("严重 / 高危", "%d / %d" % (s["critical_total"], s["high_total"]), "#d92d20",
             "需优先收敛"),
        card("新增 / 消失", "%d / %d" % (s["new_ports"], s["gone_ports"]), "#16202c",
             "对比上周基线"),
        anomaly_html,
        _fmt_new(sorted(summary["new"],
                        key=lambda x: ({"CRITICAL": 0, "HIGH": 1}.get(x.get("risk"), 2), x["port"]))),
    )


class StageError(Exception):
    """携带「失败发生在哪一步」的包装异常, 供 _classify 精准判因。

    为什么需要它: QQ 邮箱在授权码错误时**不会**返回标准的 535 认证失败,
    而是直接掐断连接, smtplib 抛的是 SMTPServerDisconnected("Connection
    unexpectedly closed")。只看异常类型会把「密码错了」误判成「网络断了」,
    给出完全错误的排查方向。所以必须按阶段区分。
    """

    def __init__(self, stage: str, original: BaseException):
        self.stage = stage            # connect / starttls / login / send
        self.original = original
        super().__init__(str(original))


def _classify(exc: BaseException, cfg: dict) -> tuple:
    """把 SMTP 异常翻译成「可重试? + 人话排查建议」。

    返回 (retryable, message)。认证类错误一律不重试 —— 反复用错授权码登录
    会被风控判定为异常行为，可能触发临时封禁。
    """
    stage = getattr(exc, "stage", None)
    orig = getattr(exc, "original", None) or exc
    code = getattr(orig, "smtp_code", None)
    try:
        code = int(code) if code is not None else None
    except (TypeError, ValueError):
        code = None
    raw = str(orig)
    low = raw.lower()

    # ---- 登录阶段失败：连接已建立，只是凭证没通过 ----
    # 注意 QQ 断连式报错，必须靠 stage 判断，不能靠异常类型
    if (stage == "login"
            or isinstance(orig, smtplib.SMTPAuthenticationError)
            or code in (534, 535)):
        return (False,
                "SMTP 登录被拒绝 —— 授权码无效或已失效。\n"
                "      ① 必须填 QQ 邮箱的「SMTP 授权码」(16 位)，不是登录密码；\n"
                "      ② QQ邮箱 → 设置 → 账户 → POP3/IMAP/SMTP服务 → 重新生成；\n"
                "      ③ 改过 QQ 密码会让旧授权码全部作废。\n"
                "      (提示: QQ 在授权码错误时通常直接断开连接，报错文字会显示成"
                "「连接意外关闭 / Connection unexpectedly closed」，"
                "本质就是密码不对，不是网络问题)")

    # ---- 发件人 / 收件人 ----
    if "recipient" in low or isinstance(orig, smtplib.SMTPRecipientsRefused):
        return (False, "收件人被拒绝：%s\n"
                       "      请检查 mail.recipients 中的地址是否真实存在。" % raw)
    if isinstance(orig, smtplib.SMTPSenderRefused):
        return (False, "发件人被拒绝。mail.sender 必须与登录邮箱完全一致"
                       "（当前填写：%s）。" % cfg.get("sender", "未配置"))

    # ---- 服务器限流（可重试）----
    if code in (421, 450, 451, 452) or any(
            k in low for k in ("too many", "rate", "frequency", "try again")):
        return (True, "服务器限流（SMTP %s）：发送过于频繁。" % (code or "4xx"))

    # ---- 被判定垃圾邮件 / 内容被拒 ----
    if code == 550 or any(k in low for k in ("denied", "rejected", "spam", "content")):
        return (False,
                "邮件被服务器拒绝（SMTP %s）—— 通常是判定为垃圾邮件或发送过于频繁。\n"
                "      QQ 免费邮箱对「发信频率」和「每日发信量」都有限制，\n"
                "      若你同时跑着多个定时推送任务（共用同一个发件邮箱），很容易撞上。\n"
                "      建议：错开发送时间，或换一个专用发件邮箱。" % (code or "550"))

    # ---- 连接与超时（可重试）----
    if isinstance(orig, (TimeoutError, socket.timeout)) or "timed out" in low:
        return (True, "连接 SMTP 超时 —— 很可能是出口防火墙拦截了 465/587 端口。")
    if isinstance(orig, ssl.SSLError):
        return (True, "TLS 握手失败 —— 若持续出现，检查出口是否有设备在中间劫持证书。")
    if isinstance(orig, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError)):
        what = "建立连接时" if stage == "connect" else "投递过程中"
        return (True, "与 SMTP 服务器的连接在%s被中断：%s" % (what, raw))
    if isinstance(orig, OSError):
        return (True, "网络错误：%s" % raw)
    if isinstance(orig, smtplib.SMTPException):
        return (True, "SMTP 错误：%s" % raw)
    return (True, "未知错误：%s" % raw)


def _deliver(cfg: dict, msg: EmailMessage) -> None:
    """建立连接并投递。每一步单独包一层 StageError, 便于精确定位失败环节。"""
    host = cfg.get("smtp_host", "smtp.qq.com")
    port = int(cfg.get("smtp_port", 465))
    timeout = int(cfg.get("timeout", 30))
    ctx = ssl.create_default_context()

    try:
        if cfg.get("use_ssl", True):
            conn = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            conn = smtplib.SMTP(host, port, timeout=timeout)
    except Exception as exc:                            # noqa: BLE001
        raise StageError("connect", exc) from exc

    try:
        if not cfg.get("use_ssl", True):
            try:
                conn.starttls(context=ctx)
            except Exception as exc:                    # noqa: BLE001
                raise StageError("starttls", exc) from exc
        try:
            conn.login(cfg["sender"], cfg["auth_code"])
        except Exception as exc:                        # noqa: BLE001
            raise StageError("login", exc) from exc
        try:
            conn.send_message(msg)
        except Exception as exc:                        # noqa: BLE001
            raise StageError("send", exc) from exc
    finally:
        try:
            conn.quit()
        except Exception:                               # noqa: BLE001
            pass


def _build_message(cfg: dict, doc: dict, summary: dict,
                   html_path, csv_path) -> EmailMessage:
    recipients = cfg.get("recipients") or [cfg["sender"]]
    crit_new = [x for x in summary["new"] if x.get("risk") in ("CRITICAL", "HIGH")]
    prefix = "【紧急】" if crit_new else ("【变化】" if summary["new"] else "【正常】")
    subject = "%sGuvianEye 公网暴露面巡检 %s — 新增%d 严重%d" % (
        prefix, doc["scan_time"][:10], doc["summary"]["new_ports"],
        doc["summary"]["critical_total"])

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("暴露面巡检", cfg["sender"]))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["X-Scanner"] = "public-exposure-scanner/2.0"

    msg.set_content(
        "GuvianEye 公网暴露面巡检周报\n"
        "扫描时间: %s\n资产: %d 台\n开放端口: %d\n本周新增: %d\n严重/高危: %d / %d\n"
        "详见 HTML 附件。\n" % (
            doc["scan_time"], doc["hosts_total"], doc["summary"]["open_total"],
            doc["summary"]["new_ports"], doc["summary"]["critical_total"],
            doc["summary"]["high_total"]))
    msg.add_alternative(build_body(doc, summary), subtype="html")

    for p in (html_path, csv_path):
        if not p:
            continue
        p = Path(p)
        if not p.exists():
            continue
        ctype, _ = mimetypes.guess_type(str(p))
        maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
        msg.add_attachment(p.read_bytes(), maintype=maintype, subtype=subtype,
                           filename=p.name)
    return msg


def _require_ready(cfg: dict, need_auth: bool = True) -> None:
    if not cfg.get("sender"):
        raise MailError("mail.sender 未配置，无法发送邮件。")
    if need_auth and not cfg.get("auth_code"):
        raise MailError(
            "mail.auth_code 为空，邮件无法发送（报告本身已正常生成）。\n"
            "      请到 QQ邮箱 → 设置 → 账户 → POP3/IMAP/SMTP服务 开启并生成"
            "「SMTP 授权码」后填入（注意不是登录密码）。")


def _deliver_with_retry(cfg: dict, msg: EmailMessage) -> None:
    """投递 + 重试 + 失败时抛 MailError(含可操作说明)。"""
    last_msg = ""
    for attempt in range(1, MAIL_ATTEMPTS + 1):
        try:
            _deliver(cfg, msg)
            return
        except Exception as exc:                       # noqa: BLE001
            retryable, human = _classify(exc, cfg)
            last_msg = human
            if not retryable or attempt >= MAIL_ATTEMPTS:
                raise MailError("[第 %d/%d 次尝试失败] %s"
                                % (attempt, MAIL_ATTEMPTS, human)) from exc
            time.sleep(MAIL_BACKOFF * attempt)
    raise MailError(last_msg or "邮件发送失败(原因未知)")


def send_test(cfg: dict) -> list:
    """发送一封测试邮件，验证 SMTP 配置。返回收件人列表。"""
    _require_ready(cfg)
    recipients = cfg.get("recipients") or [cfg["sender"]]
    msg = EmailMessage()
    msg["Subject"] = "【测试】GuvianEye 公网暴露面巡检控制台邮件通道正常"
    msg["From"] = formataddr(("暴露面巡检", cfg["sender"]))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["X-Scanner"] = "public-exposure-scanner/2.0"
    msg.set_content("这是一封测试邮件。收到它说明 SMTP 配置正确, "
                    "周度巡检报告可以正常推送。")
    _deliver_with_retry(cfg, msg)
    return recipients


def send(cfg: dict, doc: dict, summary: dict, html_path, csv_path) -> None:
    """发送巡检邮件。带附件体积检查 + 重试 + 可操作的错误说明。

    失败时抛出 MailError，其 message 可直接展示给使用者。
    """
    _require_ready(cfg)

    # 附件体积预检：超限的话直接给出明确建议，而不是等服务器拒绝
    total = 0
    for p in (html_path, csv_path):
        if p and Path(p).exists():
            total += Path(p).stat().st_size
    if total > MAX_ATTACH_BYTES:
        raise MailError(
            "附件合计 %.1f MB，超过多数邮箱的 20MB 上限。\n"
            "      建议改用较小的端口范围（如 --mode web）生成报告后再发。"
            % (total / 1048576.0))

    _deliver_with_retry(cfg, _build_message(cfg, doc, summary, html_path, csv_path))


