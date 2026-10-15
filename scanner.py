# -*- coding: utf-8 -*-
"""
GuvianEye 公网暴露面巡检引擎 (Public Exposure Scanner)
================================================

特性:
  * 纯标准库实现, 零第三方依赖, Windows / Linux 通吃
  * asyncio 全异步 TCP connect 扫描, 单主机全量 65535 端口约 3~5 分钟
  * 三态判定: open(开放) / closed(关闭, 收到 RST) / filtered(被过滤, 无响应)
  * 开放端口二次确认 + 横幅抓取 + TLS 证书指纹 + HTTP Header/Title 指纹
  * 异常主机识别: 全端口应答 / 超阈值开放, 判定为安全设备统一应答或蜜罐, 避免假阳性
  * 基线留存与周度 diff: 自动比对上周结果, 输出新增 / 消失端口
  * 输出 JSON 基线 + CSV 明细 + 自包含 HTML 报告, 可选邮件推送

用法:
  python scanner.py                  # 按 config.json 全量扫描
  python scanner.py --mode common    # 快速模式(约260个高价值端口)
  python scanner.py --only 1.2.3.4   # 只扫指定 IP
  python scanner.py --ports 1-1024,3306,6379
  python scanner.py --mail           # 扫描完成后邮件推送
  python scanner.py --dry-run        # 不发包, 只演练流程与配置

依赖: Python 3.8+ (仅标准库)
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

__version__ = "2.0.0"

# 匹配 ping 输出中的时延: "时间=23ms" / "时间<1ms" / "time=23ms"
_ICMP_RTT_RE = re.compile(r"[=<]\s*(\d+)\s*ms", re.I)


class Cancelled(Exception):
    """扫描被调用方主动中止"""

# --------------------------------------------------------------------------
# 端口知识库
# --------------------------------------------------------------------------

PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    500: "isakmp", 512: "rexec", 513: "rlogin", 514: "rsh", 515: "lpd", 520: "rip",
    548: "afp", 554: "rtsp", 587: "smtp-sub", 623: "ipmi", 631: "ipp", 636: "ldaps",
    646: "ldp", 873: "rsync", 902: "vmware", 989: "ftps-data", 990: "ftps", 993: "imaps",
    995: "pop3s", 1025: "nfs-or-iis", 1080: "socks", 1099: "rmi", 1194: "openvpn",
    1433: "mssql", 1434: "mssql-browser", 1521: "oracle", 1701: "l2tp", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd-peer",
    3128: "squid", 3260: "iscsi", 3268: "ldap-gc", 3269: "ldap-gc-ssl", 3306: "mysql",
    3389: "ms-wbt-rdp", 3690: "svn", 4369: "erlang-epmd", 4443: "https-alt", 4444: "msf",
    4848: "glassfish", 5000: "http-alt", 5001: "http-alt", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc-1",
    5984: "couchdb", 5985: "winrm-http", 5986: "winrm-https", 6000: "x11",
    6379: "redis", 6443: "k8s-api", 7001: "weblogic", 7002: "weblogic-ssl",
    7070: "realserver", 7443: "https-alt", 8000: "http-alt", 8001: "http-alt",
    8008: "http-alt", 8009: "ajp", 8010: "http-alt", 8043: "https-alt", 8069: "zabbix",
    8080: "http-proxy", 8081: "http-alt", 8082: "http-alt", 8083: "http-alt",
    8086: "influxdb", 8088: "http-alt", 8090: "http-alt", 8161: "activemq",
    8180: "http-alt", 8181: "http-alt", 8200: "http-alt", 8443: "https-alt",
    8500: "consul", 8529: "arangodb", 8530: "wsus", 8531: "wsus-ssl", 8888: "http-alt",
    8899: "http-alt", 8983: "solr", 9000: "http-alt", 9001: "http-alt", 9042: "cassandra",
    9090: "http-alt", 9092: "kafka", 9100: "printer", 9200: "elasticsearch",
    9300: "es-transport", 9418: "git", 9443: "https-alt", 9600: "http-alt",
    9999: "http-alt", 10000: "webmin", 10250: "kubelet", 10443: "https-alt",
    11211: "memcached", 12443: "https-alt", 15672: "rabbitmq-mgmt", 16379: "redis-alt",
    27017: "mongodb", 27018: "mongodb-alt", 50000: "sap", 50070: "hdfs-namenode",
    61616: "activemq-openwire",
}

# 严重: 未授权访问即可直接获取数据 / 执行命令 / 接管主机
SEV_CRITICAL = {
    23, 445, 512, 513, 514, 873, 1433, 1521, 2049, 2181, 2375, 2376, 2379, 2380,
    3306, 3389, 5432, 5555, 5900, 5901, 5984, 6379, 7001, 7002, 8161, 9042, 9200,
    9300, 10250, 11211, 16379, 27017, 27018, 50070, 61616, 4848, 6443, 8500,
}
# 高: 常规但必须严格限制暴露, 常被用于横向 / 爆破 / 信息收集
SEV_HIGH = {
    20, 21, 22, 25, 110, 111, 135, 137, 138, 139, 143, 161, 162, 389, 465, 587,
    623, 636, 993, 995, 1080, 1194, 1434, 1723, 1883, 2222, 3128, 3260, 3268,
    3269, 4369, 5000, 5601, 5672, 5985, 5986, 6000, 7070, 8009, 8069, 8081, 8086,
    8529, 8888, 8899, 8983, 9000, 9001, 9090, 9092, 9418, 10000, 15672, 50000,
}

# 需要尝试 TLS 握手的端口
TLS_PORTS = {
    443, 465, 636, 989, 990, 993, 995, 2083, 2376, 3269, 4443, 5061, 5986, 6443,
    7002, 7443, 8043, 8443, 8531, 8834, 9043, 9443, 10443, 12443,
}

# 需要发 HTTP 探测报文的端口
WEB_PORTS = {
    80, 81, 88, 443, 3000, 4443, 5000, 5001, 7001, 7080, 7443, 8000, 8001, 8008,
    8010, 8043, 8080, 8081, 8082, 8083, 8086, 8088, 8090, 8161, 8180, 8181,
    8200, 8443, 8500, 8888, 8899, 8983, 9000, 9001, 9090, 9200, 9300, 9443,
    9600, 9999, 10000, 10443, 11211, 15672, 50070, 8069, 5985,
}

# 数据型协议: 端口开放本身就是高危泄露
DATA_LEAK_PORTS = {
    6379: "Redis", 27017: "MongoDB", 27018: "MongoDB", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 2375: "Docker API", 2379: "etcd",
    2181: "ZooKeeper", 5984: "CouchDB", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 1521: "Oracle", 9042: "Cassandra", 50070: "HDFS",
    8500: "Consul", 10250: "Kubelet", 6443: "Kubernetes API",
}

# ~260 个高价值端口, 用于 common 快速模式
COMMON_PORTS = sorted({
    20, 21, 22, 23, 25, 53, 67, 69, 79, 80, 81, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 512, 513, 514,
    515, 520, 548, 554, 587, 623, 631, 636, 646, 873, 902, 989, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1080, 1090, 1099, 1158, 1194, 1433, 1434, 1521,
    1527, 1528, 1701, 1720, 1723, 1883, 1900, 2000, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2100, 2181, 2222, 2231, 2375, 2376, 2379, 2380, 2401, 2443, 2480,
    2601, 2604, 3000, 3128, 3260, 3268, 3269, 3306, 3310, 3311, 3389, 3460, 3527,
    3541, 3542, 3551, 3689, 3690, 3703, 3986, 4000, 4001, 4045, 4369, 4443, 4444,
    4445, 4786, 4848, 4899, 4900, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5061,
    5101, 5190, 5222, 5269, 5280, 5298, 5357, 5432, 5433, 5440, 5500, 5510, 5544,
    5550, 5555, 5560, 5566, 5580, 5601, 5631, 5632, 5666, 5672, 5683, 5800, 5801,
    5802, 5803, 5900, 5901, 5902, 5903, 5984, 5985, 5986, 6000, 6001, 6002, 6003,
    6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129,
    6156, 6160, 6161, 61616, 6200, 6201, 6222, 6346, 6347, 6379, 6389, 6443, 6481,
    6502, 6510, 6543, 6566, 6588, 6620, 6646, 6666, 6667, 6668, 6669, 6679, 6697,
    6881, 6901, 6969, 7000, 7001, 7002, 7003, 7004, 7005, 7007, 7019, 7025, 7070,
    7071, 7080, 7100, 7106, 7200, 7201, 7272, 7402, 7443, 7474, 7496, 7510, 7547,
    7627, 7676, 7680, 7687, 7700, 7777, 7778, 7801, 7878, 7902, 7920, 7937, 7938,
    7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8020, 8021, 8022, 8023,
    8031, 8042, 8043, 8045, 8050, 8069, 8074, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8098, 8100, 8118, 8123, 8128,
    8140, 8160, 8161, 8172, 8180, 8181, 8182, 8192, 8193, 8194, 8200, 8222, 8243,
    8254, 8280, 8291, 8300, 8333, 8334, 8400, 8402, 8443, 8444, 8500, 8529, 8530,
    8531, 8545, 8554, 8649, 8686, 8728, 8800, 8834, 8839, 8850, 8879, 8880, 8888,
    8889, 8899, 8920, 8983, 8990, 8994, 9000, 9001, 9002, 9009, 9010, 9020, 9042,
    9043, 9050, 9060, 9080, 9081, 9090, 9091, 9092, 9098, 9100, 9119, 9200, 9201,
    9207, 9220, 9290, 9300, 9306, 9312, 9333, 9344, 9350, 9389, 9418, 9443, 9444,
    9495, 9500, 9535, 9536, 9593, 9594, 9600, 9612, 9666, 9696, 9900, 9901, 9987,
    9999, 10000, 10001, 10010, 10024, 10025, 10050, 10051, 10110, 10250, 10255,
    10256, 10443, 10554, 10809, 10880, 10990, 11000, 11095, 11110, 11211, 11371,
    11720, 12000, 12174, 12222, 12345, 12443, 12701, 13000, 13306, 13389, 13720,
    13782, 14000, 14001, 14141, 14238, 14344, 14441, 14936, 15000, 15002, 15200,
    15345, 15426, 15567, 15660, 15672, 16000, 16010, 16020, 16030, 16113, 16379,
    16384, 16680, 16992, 16993, 17001, 17185, 17200, 17219, 17500, 17777, 18000,
    18001, 18002, 18010, 18101, 18200, 18330, 18668, 18753, 19000, 19283, 19315,
    19780, 19801, 19842, 19999, 20000, 20002, 20031, 20033, 20080, 20222, 20560,
    20689, 20828, 21000, 21010, 21212, 21412, 21554, 22000, 22222, 22273, 22305,
    22555, 22986, 23000, 23001, 23023, 23424, 23456, 23554, 24000, 24242, 24444,
    24554, 24800, 25000, 25565, 25672, 25999, 26000, 26208, 27000, 27015, 27017,
    27018, 27352, 27353, 27355, 28001, 28017, 28080, 28201, 28784, 29000, 29999,
    30000, 30005, 30303, 30718, 30951, 31038, 31337, 32100, 32768, 32769, 32770,
    32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
    32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
    40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152,
    49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50050,
    50070, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848,
    52869, 54045, 54328, 55055, 55555, 55600, 56737, 56738, 57294, 57797, 58080,
    60020, 60443, 61532, 61616, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389,
})

WEB_ONLY_PORTS = sorted(WEB_PORTS | SEV_CRITICAL | SEV_HIGH | {8080, 8443, 3389, 22, 21, 23, 445, 1433, 3306, 5432, 6379, 27017, 9200, 11211, 5900, 2049, 873})

# ★ 业务端口集 (BUSINESS_PORTS)
# 来源: 实际运维中**真实出现过**的业务端口, 而不是教科书式的端口表。
# 这些端口未必是"通用常见端口" —— 4430 / 8003 / 8005 / 8006 / 8012 / 8015 / 8016 /
# 8017 / 8018 / 8030 全都不在 COMMON_PORTS 里, 但它们是**实际在用**的业务端口。
# 一旦因为目标侧限速被漏掉, 后果比漏掉一个通用端口严重得多(远程实验室、考试中台、
# VPN 服务、智慧校园用的正是这批端口)。
# 把它们并入重点补扫集, 就是「结合历史清单、但不照搬历史结论」的落地方式:
#   扫描范围照样是全量 65535 端口(不因为历史清单而缩小视野),
#   只是对这批业务端口额外做低速多轮兜底(不让限速把它们吞掉)。
BUSINESS_PORTS = sorted({
    80, 123, 443, 1723, 1883, 3306, 4430,
    8001, 8002, 8003, 8005, 8006, 8007, 8008, 8009,
    8010, 8012, 8014, 8015, 8016, 8017, 8018, 8030, 8031,
    8080, 8090, 8093,
})

# 重点端口集: 补扫阶段的默认目标。
# 现实中的暴露面 99% 集中在常见服务端口与 Web 端口上(含大量非标 Web 端口,
# 如 443/8001/8008/8009/8080/8081/8443/9000 等)。全量 65535 端口补扫代价过高,
# 而这些"重点端口"恰恰是最容易因为目标侧限速而漏报的 —— 补扫收益最高、成本最低。
# 需要连冷门端口一起补扫时, 把 config 的 rescan_scope 设为 "all"。
PRIORITY_PORTS = sorted(set(COMMON_PORTS) | set(WEB_ONLY_PORTS) | set(BUSINESS_PORTS))


def risk_of(port: int) -> str:
    if port in SEV_CRITICAL:
        return "CRITICAL"
    if port in SEV_HIGH:
        return "HIGH"
    if port < 1024:
        return "MEDIUM"
    return "LOW"


def svc_of(port: int) -> str:
    return PORT_NAMES.get(port, "")


# --------------------------------------------------------------------------
# 进度显示
# --------------------------------------------------------------------------

# 补扫阶段的 phase 名。这几个阶段的探测量事先无法预知, 因此**不计入**主扫描进度百分比,
# 否则 done 与 total 同步增长会让进度永远停在 100%(实测踩过: 用户以为卡死)。
RESCAN_PHASES = {"补扫", "补扫+", "后置补扫"}


class Progress:
    """进度计数器。sink 为空时写终端(stderr); 传入 sink 时回调给调用方(供 GUI/Web 使用)。"""

    def __init__(self, total: int, label: str = "扫描中", sink=None,
                 rescan_counts: bool = False):
        self.total = max(total, 1)
        self.done = 0
        self.open_cnt = 0
        self.label = label
        self.phase = ""
        self.sink = sink
        self.rescan_done = 0      # 补扫阶段额外发出的探测次数(不计入主扫描进度)
        # rescan_counts=True 表示"这个 Progress 本身就是在跑补扫, 总量已知" ——
        # 例如全局后置补扫(目标数 x 端口数 x 轮数, 事先能算出来)。
        # 这种情况补扫就是它的正经工作, 必须正常计入百分比。
        self.rescan_counts = rescan_counts
        self._t0 = time.time()
        self._last = 0.0
        self._started = False

    def snapshot(self) -> dict:
        el = time.time() - self._t0
        # ★ 主扫描进度只按主扫描算。补扫是"追加工作", 总量事先无法预知,
        #   如果把它算进 done/total(旧实现), 两者会同步增长, 百分比会永远锁死在 100%,
        #   用户就会看到"进度 100% 却还在转圈、也没有报告"。
        #   现在: 主扫描走百分比(补扫期间封顶 99.9%), 补扫单独用 rescan 计数展示。
        pct = self.done * 100.0 / self.total
        if self.rescan_done:
            pct = min(pct, 99.9)
        rate = self.done / el if el > 0 else 0
        rsn_rate = self.rescan_done / el if el > 0 else 0
        hit = bool(self.rescan_done)
        return {
            "done": self.done,
            "total": self.total,
            "percent": round(pct, 2),
            "rate": round(rate, 1),
            "open": self.open_cnt,
            "elapsed": round(el, 1),
            "eta": 0 if hit else (int((self.total - self.done) / rate) if rate > 0 else 0),
            "phase": self.phase or self.label,
            "finishing": hit,
            "rescan": self.rescan_done,
            "rescan_rate": round(rsn_rate, 1),
        }

    def bump(self, n: int = 1, opened: int = 0, phase: str = "") -> None:
        if phase:
            self.phase = phase
        if phase in RESCAN_PHASES and not self.rescan_counts:
            # 主扫描进度: 补扫是"追加工作", 只累加补扫计数, 不动 done/total
            self.rescan_done += n
        else:
            self.done += n
        self.open_cnt += opened
        # 兜底: 万一主扫描阶段 done 超过 total, 动态扩容总数, 避免出现 >100%
        if self.done > self.total:
            self.total = self.done
        now = time.time()
        if now - self._last < 0.4 and self.done < self.total:
            return
        self._last = now
        self._started = True
        if self.sink:
            try:
                self.sink(self.snapshot())
            except Exception:
                pass
            return
        snap = self.snapshot()
        extra = ("  [补扫中 已追加 %d 次探测]" % snap["rescan"]) if snap["rescan"] else ""
        sys.stderr.write(
            "\r  %s %6.2f%%  %s/%s  %.0f port/s  开放:%d  用时%ds  剩余~%ds%s   "
            % (self.phase or self.label, snap["percent"], snap["done"], snap["total"],
               snap["rate"], self.open_cnt, int(snap["elapsed"]), snap["eta"], extra))
        sys.stderr.flush()

    def finish(self) -> None:
        if self.sink:
            try:
                self.sink(self.snapshot())
            except Exception:
                pass
            return
        if self._started:
            sys.stderr.write("\r" + " " * 110 + "\r")
            sys.stderr.flush()


# --------------------------------------------------------------------------
# 扫描原语
# --------------------------------------------------------------------------

# 探测结果统计(进程级)。用于在报告里区分「目标无响应」与「本机侧异常」。
PROBE_STATS: dict = collections.Counter()


def _make_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        # 主动 RST 关闭, 避免大量 TIME_WAIT 耗尽本机临时端口
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    return s


async def probe_tcp(loop, ip: str, port: int, timeout: float):
    """返回 (state, rtt_ms)

    state:
      open     收到 SYN-ACK, 端口开放(确定性结论)
      closed   收到 RST, 主机在线且端口关闭(确定性结论)
      filtered 无任何响应, 被防火墙丢弃 / 主机离线(不确定性结论)
    rtt_ms 仅在连接成功时有值, 用于自适应超时。

    所有结果同时计入 PROBE_STATS —— 漏报排查时必须能区分
    「目标真的没响应」和「本机侧出了状况(临时端口耗尽/连接被本地栈中止)」。
    后者若被统一记成 filtered, 会表现为"目标端口没开", 属于最危险的假阴性。
    """
    sock = _make_socket()
    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
    except asyncio.TimeoutError:
        sock.close()
        PROBE_STATS["timeout"] += 1
        return "filtered", None
    except ConnectionRefusedError:
        sock.close()
        PROBE_STATS["closed"] += 1
        return "closed", None
    except ConnectionResetError:
        sock.close()
        PROBE_STATS["closed"] += 1
        return "closed", None
    except OSError as exc:
        sock.close()
        eno = getattr(exc, "errno", None)
        # 10061 = WSAECONNREFUSED / 111 = ECONNREFUSED / 61 = macOS
        if eno in (10061, 111, 61):
            PROBE_STATS["closed"] += 1
            return "closed", None
        PROBE_STATS["errno:%s" % eno] += 1
        return "filtered", None
    except asyncio.CancelledError:
        sock.close()
        raise
    rtt = (time.perf_counter() - t0) * 1000.0
    try:
        sock.close()
    except OSError:
        pass
    PROBE_STATS["open"] += 1
    return "open", rtt


async def icmp_ping(ip: str, timeout_ms: int = 1000):
    """调用系统 ping 做一次 ICMP 探测(Windows 下无需管理员权限)。
    返回 (是否可达, rtt_ms)。仅作为"主机是否在线"与 RTT 的辅助信号, 失败不影响主流程。"""
    if sys.platform == "win32":
        args = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout_ms / 1000.0 + 2.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            return False, None
        if proc.returncode != 0:
            return False, None
        m = _ICMP_RTT_RE.search(out.decode("utf-8", "replace"))
        return True, (float(m.group(1)) if m else None)
    except Exception:
        return False, None


def _extract_cert_info(ssl_obj) -> dict:
    info = {}
    try:
        der = ssl_obj.getpeercert(binary_form=True)
        if der:
            info["cert_sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    try:
        info["tls_version"] = ssl_obj.version()
    except Exception:
        pass
    try:
        cipher = ssl_obj.cipher()
        if cipher:
            info["cipher"] = cipher[0]
    except Exception:
        pass
    # 可选: 若本机装了 cryptography, 顺带解出证书主体与有效期
    try:
        from cryptography import x509  # type: ignore
        der = ssl_obj.getpeercert(binary_form=True)
        if der:
            c = x509.load_der_x509_certificate(der)
            info["subject"] = c.subject.rfc4514_string()
            info["issuer"] = c.issuer.rfc4514_string()
            info["not_after"] = str(c.not_valid_after_utc)[:19]
            info["self_signed"] = c.subject == c.issuer
    except Exception:
        pass
    return info


# 需要客户端先说话的协议端口(被动读拿不到横幅, 才值得再发一次探测报文)
PING_PROBE_PORTS = {6379, 11211, 3306, 5432, 1433, 1521, 27017, 9300, 5672,
                    1883, 9042, 5984, 8500, 2379, 2181, 50070, 10000}


async def fingerprint(ip: str, port: int, timeout: float, do_tls: bool = True) -> dict:
    """对已确认开放的端口做服务指纹识别。

    整个函数受 timeout 总预算约束(deadline), 避免在高位端口上叠加多次等待。
    """
    res: dict = {"banner": "", "tls": {}, "http": {}, "product": ""}
    deadline = time.monotonic() + max(0.5, timeout)

    def remain(cap: float) -> float:
        return max(0.25, min(cap, deadline - time.monotonic()))

    is_tls = do_tls and port in TLS_PORTS

    # ---- TLS 握手 ----
    if is_tls:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except Exception:
            ctx = None
        if ctx is not None:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=None),
                    remain(3.0))
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    res["tls"] = _extract_cert_info(ssl_obj)
                res["product"] = res["tls"].get("tls_version", "")
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.8)
                except Exception:
                    pass
            except Exception:
                pass

    # ---- 明文握手 / 横幅 ----
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), remain(2.5))

        banner = b""
        # 被动读: SSH / FTP / SMTP / MySQL / Redis 等会主动吐 banner
        try:
            banner = await asyncio.wait_for(reader.read(1024), remain(1.5))
        except Exception:
            banner = b""

        # 主动探测: Web 端口发 HTTP; 少数客户端先说的协议发一行探测
        if not banner and port in WEB_PORTS:
            try:
                writer.write(
                    ("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (SecScan)\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n" % ip).encode())
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(4096), remain(2.0))
            except Exception:
                pass
        elif not banner and port in PING_PROBE_PORTS:
            try:
                writer.write(b"PING\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), remain(1.2))
            except Exception:
                pass

        if banner:
            text = banner.decode("utf-8", "replace").strip()
            res["banner"] = text[:400].replace("\r", " ").replace("\n", " | ")
            low = text.lower()
            if low.startswith("http/"):
                for line in text.splitlines():
                    ll = line.lower()
                    if ll.startswith("server:"):
                        res["http"]["server"] = line.split(":", 1)[1].strip()[:160]
                    if ll.startswith("x-powered-by:"):
                        res["http"]["x_powered_by"] = line.split(":", 1)[1].strip()[:160]
                    if ll.startswith("location:"):
                        res["http"]["location"] = line.split(":", 1)[1].strip()[:200]
                tl = low.find("<title>")
                if tl >= 0:
                    tr = low.find("</title>", tl)
                    if tr > tl:
                        res["http"]["title"] = text[tl + 7:tr].strip()[:160]
            for kw in ("ssh-", "ftp", "smtp", "imap", "pop3", "mysql", "mariadb",
                       "redis", "mongodb", "elastic", "-err", "httpd", "nginx",
                       "microsoft", "mssql", "postgres", "amqp", "memcached"):
                if kw in low:
                    res["product"] = kw
                    break
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 0.8)
        except Exception:
            pass
    except Exception:
        pass

    return res


# --------------------------------------------------------------------------
# 单主机扫描
# --------------------------------------------------------------------------

# 存活预判端口: 覆盖面要广, 否则会把"只开了个别端口"的主机误判为离线
DISCOVERY_PORTS = [80, 443, 22, 3389, 8080, 8443, 8000, 8001, 7001, 8888, 81, 9200]

# ---- 网络预检用 ----
# 探测集: 只挑最常见的服务端口, 用于快速判断"这个网络到底通不通"并实测 RTT
PROBE_SET = sorted(set(DISCOVERY_PORTS) | {21, 25, 53, 110, 143, 445, 1433, 3306,
                                           5432, 6379, 8081, 8443, 9000, 9443})
# 压测集: 高位、几乎不可能有业务监听的端口。用来测出口链路能扛多大并发,
# 因为预期它们全是静默丢弃, 所以不会惊动任何真实业务。
STRESS_PORTS = list(range(30000, 30500))

# 后置补扫端口集: 业务端口 ∪ 存活预判端口。
# "后置补扫"是在全部主机主扫描**结束之后**、等限速窗口过去, 再统一做的低速兜底。
# 它只扫这一小撮端口(约 35 个), 所以即便逐台低速重探也很快, 却能有效挽回那批
# "只扫到 80、443 和业务端口全丢"的假阴性。
POST_RESCAN_PORTS = sorted(set(BUSINESS_PORTS) | set(DISCOVERY_PORTS))
_POST_SET = set(POST_RESCAN_PORTS)

# 定向复核(verify)的单机并发。刻意压到极低 —— 复核的目的不是快, 而是让
# 目标侧不触发限速, 从而拿到"到底开没开"的可信答案。
VERIFY_PER_HOST = 4


async def discover_host(ip: str, timeout: float) -> tuple:
    """并发探测一组常见端口, 返回 (status, rtt_ms)

    status = up     至少一个端口有应答(开放或拒绝), 主机确定在线
             silent 全部无响应, 主机可能离线, 也可能全端口被过滤
    注意: 该结果仅作参考, 扫描结束后会依据实际发现的开放端口做最终判定。
    """
    loop = asyncio.get_running_loop()
    tasks = [probe_tcp(loop, ip, p, timeout) for p in DISCOVERY_PORTS]
    res = await asyncio.gather(*tasks, return_exceptions=True)
    for r in res:
        if isinstance(r, BaseException):
            continue
        if r[0] in ("open", "closed"):
            return "up", r[1]
    return "silent", None


async def sweep_ports(ip: str, ports: list, per_host: int, timeout: float,
                      loop, progress: Progress = None, should_stop=None,
                      phase: str = ""):
    """对一组端口做一轮完整扫描。

    返回 (open_ports, closed_cnt, filtered_ports)
      open_ports     dict{port: {...}}  收到 SYN-ACK
      closed_cnt     int                收到 RST
      filtered_ports list               无任何响应 / 本机侧异常(不确定性)
    """
    open_ports: dict = {}
    closed_cnt = 0
    filtered: list = []
    for i in range(0, len(ports), per_host):
        if should_stop and should_stop():
            raise Cancelled("用户中止扫描")
        chunk = ports[i:i + per_host]
        tasks = [probe_tcp(loop, ip, p, timeout) for p in chunk]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        opened = 0
        for p, r in zip(chunk, results):
            if isinstance(r, BaseException):
                filtered.append(p)
                continue
            st = r[0]
            if st == "open":
                open_ports[p] = {"port": p, "service": svc_of(p), "risk": risk_of(p)}
                opened += 1
            elif st == "closed":
                closed_cnt += 1
            else:
                filtered.append(p)
        if progress is not None:
            progress.bump(len(chunk), opened, phase=phase)
    return open_ports, closed_cnt, filtered


async def scan_host(ip: str, ports: list, cfg: dict, per_host: int,
                    progress: Progress, timeout: float, should_stop=None) -> dict:
    """扫描单台主机。

    [主扫描] 全量端口一遍。
    [补扫]   针对无响应(filtered)的**重点端口**再扫若干轮。
             存在的意义: 目标侧普遍存在基于源 IP 的探测限速 —— 主扫描以高并发猛冲时
             会触发限速, 真实开放的端口(尤其是 443 与各种非标 Web 端口)被静默丢弃,
             表现为"明明开放却扫不出来"。补扫降低并发、拉长超时、多轮重试, 把这类
             假阴性挽回回来。补扫只覆盖重点端口集, 成本可控。
    """
    loop = asyncio.get_running_loop()
    scfg = cfg

    open_ports, closed_cnt, filtered = await sweep_ports(
        ip, ports, per_host, timeout, loop, progress, should_stop, phase="扫描")

    rescan_rounds = int(scfg.get("rescan_filtered", 0) or 0)
    prio_rounds = int(scfg.get("rescan_priority_rounds", 0) or 0)
    rdelay = float(scfg.get("rescan_delay", 0.4) or 0.0)
    rslow = max(1, int(scfg.get("rescan_slowdown", 4) or 4))
    rtf = float(scfg.get("rescan_timeout_factor", 1.6) or 1.6)
    rescan_scope = str(scfg.get("rescan_scope", "priority") or "priority")
    recovered = 0
    rescan_probes = 0

    if (rescan_rounds or prio_rounds) and filtered:
        prio_set = None if rescan_scope == "all" else set(PRIORITY_PORTS)
        scope_ports = [p for p in filtered if prio_set is None or p in prio_set]
        sub = max(8, per_host // rslow)

        async def _rounds(batch, rounds, phase):
            nonlocal recovered, rescan_probes
            cur = list(batch)
            for r in range(rounds):
                if not cur or (should_stop and should_stop()):
                    break
                if r > 0 or rdelay:
                    await asyncio.sleep(rdelay)
                to = max(timeout, 1.0) * (rtf ** (r + 1))
                op, _c, still = await sweep_ports(
                    ip, cur, sub, to, loop, progress, should_stop, phase=phase)
                rescan_probes += len(cur)
                for p, info in op.items():
                    open_ports[p] = info
                    recovered += 1
                cur = still
            return cur

        left = await _rounds(scope_ports, rescan_rounds, "补扫")
        if prio_rounds:
            # 重点端口若仍无响应, 再追加若干轮(顺序打乱, 避开周期性静默窗口)
            left_prio = [p for p in left if prio_set is None or p in prio_set]
            random.shuffle(left_prio)
            left = await _rounds(left_prio, prio_rounds, "补扫+")

        # 已挽回的端口不再计入 filtered; 未纳入补扫范围的非重点端口保持 filtered
        newly_open = set(open_ports)
        filtered = [p for p in filtered if p not in newly_open]

    return {
        "ip": ip,
        "open_ports": sorted(open_ports.values(), key=lambda x: x["port"]),
        "closed_count": closed_cnt,
        "filtered_count": len(filtered),
        "scanned_ports": len(ports),
        "rescan_recovered": recovered,
        "rescan_probes": rescan_probes,
        # 仍无响应、且属于「后置补扫端口集」的端口(数量很小, ≤35)。
        # 交给主流程在全部主机扫完之后、限速窗口过去时统一做低速兜底。
        "filtered_biz": sorted(p for p in filtered if p in _POST_SET),
    }


async def confirm_ports(ip: str, ports: list, timeout: float, per_host: int,
                        rounds: int = 2) -> tuple:
    """对已判定为开放的端口做二次确认。

    改为**多轮表决 + 宽松保留**: 只要任意一轮收到 SYN-ACK 就判为确认。
    原因: 目标侧限速会导致同一次扫描里"扫到时开放、复核时无响应",
    若按"必须每轮都通"来卡, 会把这些真实开放端口误删成假阴性 —— 这正是
    用户遇到的"443 明明开放却扫不出来"的成因之一。
    返回 (confirmed, dropped, hits) hits=端口被确认的次数, 供报告展示。
    """
    loop = asyncio.get_running_loop()
    rounds = max(1, int(rounds or 1))
    hits: dict = {p["port"]: 0 for p in ports}
    for _ in range(rounds):
        for i in range(0, len(ports), per_host):
            chunk = ports[i:i + per_host]
            tasks = [probe_tcp(loop, ip, p["port"], timeout) for p in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for p, r in zip(chunk, results):
                if not isinstance(r, BaseException) and r[0] == "open":
                    hits[p["port"]] = hits.get(p["port"], 0) + 1
    confirmed, dropped = [], []
    for p in ports:
        if hits.get(p["port"], 0) > 0:
            p["confirm_hits"] = hits[p["port"]]
            p["confirm_rounds"] = rounds
            confirmed.append(p)
        else:
            dropped.append(p["port"])
    return confirmed, dropped, hits


# --------------------------------------------------------------------------
# 端口清单构建
# --------------------------------------------------------------------------

def build_ports(mode: str = "", expr: str = "", cfg: dict = None) -> list:
    """构造端口清单。mode: all/common/web/custom; expr 优先级最高(如 1-1024,3306)"""
    cfg = cfg or DEFAULT_CFG
    if expr:
        raw = expr
    else:
        mode = mode or cfg["ports"].get("mode", "all")
        if mode == "all":
            raw = "1-65535"
        elif mode == "common":
            return list(COMMON_PORTS)
        elif mode == "web":
            return list(WEB_ONLY_PORTS)
        elif mode == "custom":
            lst = cfg["ports"].get("list") or []
            rng = cfg["ports"].get("ranges") or ""
            out = set(int(x) for x in lst)
            out |= parse_ranges(rng)
            return sorted(p for p in out if 0 < p < 65536)
        else:
            raise ValueError("未知端口模式: %s" % mode)

    ports = sorted(parse_ranges(raw))
    ports = [p for p in ports if 0 < p < 65536]
    if not ports:
        raise ValueError("端口清单为空, 请检查端口模式 / 表达式")
    return ports


# --------------------------------------------------------------------------
# 目标解析: 支持 单 IP / CIDR 网段 / 区间
# --------------------------------------------------------------------------
# 现场常见写法(资产清单里常按网段给):
#     192.0.2.144                  单个地址
#     198.51.100.0/24                 CIDR 网段
#     198.51.100.1-198.51.100.50        区间(两端写全)
#     198.51.100.1-50                 区间(尾段简写, 等价于上面那行)
#
# ★ 安全阀: 一条表达式最多展开多少个 IP。没有这个限制, 手滑写个 /8 会
#   当场生成 1600 万个目标 —— 探测总量再乘 65535 个端口, 内存和网络都会炸。
MAX_EXPAND_PER_TOKEN = 4096        # 单条表达式展开上限
MAX_TOTAL_TARGETS = 20000          # 整个清单展开后的总目标数上限


def _ip_to_int(s: str) -> int:
    return int(ipaddress.IPv4Address(s.strip()))


def _int_to_ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def expand_target_token(token: str, max_expand: int = MAX_EXPAND_PER_TOKEN) -> list:
    """把一条目标表达式展开成 IPv4 字符串列表。

    支持: 单 IP / CIDR / 区间。非法或超限时抛 ValueError, 由调用方决定是跳过还是中止。
    """
    tok = (token or "").strip()
    if not tok:
        return []

    # ---- ① CIDR 网段 ----
    if "/" in tok:
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError as exc:
            raise ValueError("非法网段 %s (%s)" % (tok, exc))
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("只支持 IPv4 网段, 不支持 IPv6: %s" % tok)
        n = net.num_addresses
        # /31 与 /32 没有网络地址/广播地址的概念, 全部可用;
        # /30 及更小的网段按惯例扣掉网络号与广播地址。
        if net.prefixlen >= 31:
            usable = n
        else:
            usable = max(0, n - 2)
        if usable == 0:
            raise ValueError("网段 %s 没有可用主机地址" % tok)
        if usable > max_expand:
            raise ValueError(
                "网段 %s 含 %d 个可用地址, 超过单条上限 %d。请拆成更小的网段, "
                "或改大单条上限(谨慎: /16≈6.5 万、/8≈1600 万, 会拖垮本机)"
                % (tok, usable, max_expand))
        return [str(a) for a in (net if net.prefixlen >= 31 else net.hosts())]

    # ---- ② 区间 ----
    if "-" in tok:
        left, _, right = tok.partition("-")
        left, right = left.strip(), right.strip()
        if not left or not right:
            raise ValueError("区间写法不完整: %s (应为 起始IP-结束IP 或 起始IP-尾段号)" % tok)
        try:
            a = _ip_to_int(left)
        except ValueError:
            raise ValueError("区间起点不是合法 IPv4: %s" % left)
        if right.isdigit():
            # 尾段简写: 198.51.100.1-50 -> 用起点的前三段拼出终点
            if "." not in left:
                raise ValueError("区间 %s 无法推断终点, 请写全 IP" % tok)
            head = left.rsplit(".", 1)[0]
            try:
                b = _ip_to_int("%s.%s" % (head, right))
            except ValueError:
                raise ValueError("区间终点非法: %s.%s" % (head, right))
        else:
            try:
                b = _ip_to_int(right)
            except ValueError:
                raise ValueError("区间终点不是合法 IPv4: %s" % right)
        if a > b:
            a, b = b, a
        cnt = b - a + 1
        if cnt > max_expand:
            raise ValueError(
                "区间 %s 含 %d 个地址, 超过单条上限 %d, 请拆小或改大单条上限"
                % (tok, cnt, max_expand))
        return [_int_to_ip(x) for x in range(a, b + 1)]

    # ---- ③ 单个地址 ----
    try:
        ipaddress.IPv4Address(tok)
    except ValueError:
        raise ValueError("不是合法 IPv4, 也不是网段/区间: %s" % tok)
    return [tok]


def load_targets(path: Path, only: str = "",
                 max_expand: int = MAX_EXPAND_PER_TOKEN,
                 max_total: int = MAX_TOTAL_TARGETS) -> list:
    """读取目标清单。每行可写 单 IP / 网段 / 区间, 支持逗号或空格分隔。

    解析失败的行只跳过并告警(不中断整批), 但展开总数超上限会直接中止 ——
    宁可让用户改清单, 也不能让本机被一个手滑的 /8 拖死。
    """
    if not path.exists():
        raise SystemExit("[!] 目标文件不存在: %s" % path)
    seen, out = set(), []
    expanded_notes = []
    for lineno, raw in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for token in line.replace(",", " ").split():
            if token in seen:
                continue
            try:
                ips = expand_target_token(token, max_expand)
            except ValueError as exc:
                sys.stderr.write("[!] 第 %d 行 跳过: %s\n" % (lineno, exc))
                continue
            if len(ips) > 1:
                expanded_notes.append("%s -> %d 个地址" % (token, len(ips)))
            for ip in ips:
                if ip in seen:
                    continue
                seen.add(ip)
                out.append(ip)
            if len(out) > max_total:
                raise SystemExit(
                    "[!] 目标展开后已超过 %d 个, 已中止。请确认清单里是否有过大的网段 "
                    "(如 /16、/8); 确实需要可调大上限后重试。" % max_total)
    if expanded_notes:
        sys.stderr.write("[i] 网段/区间已展开: %s\n" % "; ".join(expanded_notes))
    if only:
        wanted = set()
        for t in only.replace(",", " ").split():
            try:
                wanted.update(expand_target_token(t, max_expand))
            except ValueError as exc:
                sys.stderr.write("[!] --only 跳过: %s\n" % exc)
        out = [x for x in out if x in wanted]
    if not out:
        raise SystemExit("[!] 目标清单为空")
    return out


def parse_ranges(raw: str) -> set:
    out = set()
    for part in str(raw).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.update(range(lo, hi + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return out


# --------------------------------------------------------------------------
# 基线 diff
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r"[^0-9A-Za-z_\-\u4e00-\u9fff]+")


def sanitize_label(label: str) -> str:
    return _LABEL_RE.sub("_", (label or "").strip())[:40] or "default"


# --------------------------------------------------------------------------
# 执行网络指纹
# --------------------------------------------------------------------------
# 基线是"按执行网络分档"的, 但分档名(--label)是**人手填的** —— 忘了切网络却沿用
# 上一次的标签(例如人在办公网、标签却填 mobile), 工具原本完全察觉不到, 结果就会把
# "办公网扫出来的一堆不可达"写成 mobile 档的基线, 污染后续对比。
# 因此给每次扫描记录本机执行网络的指纹(内网地址 + 出口公网地址), 与基线不一致时告警。
_SRC_CACHE: dict = {}


def detect_source_ips(timeout: float = 3.0) -> dict:
    """探测本机执行网络指纹。返回 {"local": "...", "public": "..."}。

    local  : 用 UDP connect 取出网卡地址(不实际发包), 瞬时完成, 必定可用。
    public : 出口公网地址, 需要外部服务; 失败就留空(不影响扫描)。
             多个源**并行**探(串行时第一个源超时会把开扫拖慢好几秒)。
    """
    if _SRC_CACHE:
        return dict(_SRC_CACHE)
    out = {"local": "", "public": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            out["local"] = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        pass

    def _probe(url: str):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(64).decode("utf-8", "ignore").strip()
        except Exception:
            return ""

    urls = ("https://api.ipify.org", "https://ifconfig.me/ip",
            "https://api.ip.sb/ip")
    try:
        import threading
        box: dict = {}

        def _run(u):
            box[u] = _probe(u)

        ts = [threading.Thread(target=_run, args=(u,), daemon=True) for u in urls]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout + 0.5)
        for u in urls:
            ip = (box.get(u) or "").strip()
            if ip and len(ip) <= 45 and " " not in ip:
                out["public"] = ip
                break
    except Exception:
        pass

    _SRC_CACHE.update(out)
    return dict(out)


def baseline_path(baseline_dir: Path, label: str) -> Path:
    """基线按「扫描出口网络」分档。不同网络下结果可能不同(部分公网地址
    在办公网被策略阻断), 混用会产生大量虚假的"新增/消失"。"""
    label = sanitize_label(label)
    if label == "default":
        return baseline_dir / "latest.json"
    return baseline_dir / ("latest_%s.json" % label)


def load_baseline(baseline_dir: Path, label: str = "default") -> dict:
    latest = baseline_path(baseline_dir, label)
    if not latest.exists():
        return {}
    try:
        return json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return {}


def diff_against(current: list, baseline: dict) -> dict:
    prev = {}
    for h in (baseline or {}).get("hosts", []):
        prev[h["ip"]] = {p["port"]: p for p in h.get("open_ports", [])}

    summary = {"new": [], "gone": [], "new_hosts": [], "quiet_hosts": []}
    for h in current:
        ip = h["ip"]
        cur_ports = {p["port"] for p in h["open_ports"]}
        h["prev_ports"] = sorted(prev.get(ip, {}).keys())
        if ip not in prev:
            h["diff"] = "new_host"
            summary["new_hosts"].append(ip)
        else:
            old_ports = set(prev[ip].keys())
            added = sorted(cur_ports - old_ports)
            removed = sorted(old_ports - cur_ports)
            h["new_ports"] = added
            h["gone_ports"] = removed
            h["diff"] = "changed" if (added or removed) else "same"
            if not cur_ports and old_ports:
                summary["quiet_hosts"].append(ip)
        for p in h["open_ports"]:
            p["is_new"] = p["port"] in set(h.get("new_ports") or [])
            if p["is_new"]:
                summary["new"].append({"ip": ip, **p})
        for gp in h.get("gone_ports") or []:
            summary["gone"].append({"ip": ip, "port": gp, "service": svc_of(gp),
                                    "risk": risk_of(gp)})
    return summary


# --------------------------------------------------------------------------
# 历史期望清单对照 (历史基线清单)
# --------------------------------------------------------------------------
# 设计原则: 「结合历史清单, 但不照搬历史清单的结论」。
#   * 扫描范围永远是全量 65535 端口 —— 历史清单不参与"扫哪些端口"的决策,
#     否则历史清单里没有的端口(新上线的服务)就永远扫不到。
#   * 历史清单只用于【扫完之后对照一趟】: 历史上开放过、这次没扫到的, 标为
#     【疑似漏报】并单独列出 —— 它不等于"已关闭", 需要人工或从其他网络复核。
# --------------------------------------------------------------------------

def expected_path() -> Path:
    return BASE_DIR / "expected_ports.json"


def load_expected() -> dict:
    """加载历史期望清单, 返回 {ip: {name, ports, live, state, note}}"""
    p = expected_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for ip, item in (raw.get("hosts") or {}).items():
        # 字段名: ports / state; ports_hist / state_hist 是旧版字段, 继续兼容
        ports = set(int(x) for x in (item.get("ports") or []))
        ports |= set(int(x) for x in (item.get("ports_hist") or []))
        ports |= set(int(x) for x in (item.get("hist_ports") or []))
        out[ip] = {
            "name": item.get("name", ""),
            "ports": ports,
            "live": (item.get("state") or item.get("state_hist") or "") == "normal",
            "state": item.get("state") or item.get("state_hist", ""),
            "note": item.get("note", ""),
        }
    return out


def expected_diff(current: list, expected: dict) -> dict:
    """本次扫描结果 vs 历史清单。只做提示, 不下结论。"""
    res = {"missing": [], "extra": [], "hit": [], "offline_ok": [], "not_scanned": []}
    for h in current:
        ip = h["ip"]
        exp = expected.get(ip)
        if not exp:
            continue
        cur = {p["port"] for p in h["open_ports"]}
        if not exp["live"]:
            if cur:
                res["extra"].append({
                    "ip": ip, "name": exp["name"], "ports": sorted(cur),
                    "reason": "历史基线中该目标『%s』, 本次却扫到端口" % (exp["state"] or "未知")})
            else:
                res["offline_ok"].append({"ip": ip, "name": exp["name"],
                                          "state": exp["state"]})
            continue
        if h.get("discovery") != "up":
            res["not_scanned"].append({"ip": ip, "name": exp["name"],
                                       "ports": sorted(exp["ports"])})
            continue
        miss = sorted(exp["ports"] - cur)
        add = sorted(cur - exp["ports"])
        if miss:
            res["missing"].append({"ip": ip, "name": exp["name"], "ports": miss,
                                   "still_open": sorted(exp["ports"] & cur)})
        if add:
            res["extra"].append({"ip": ip, "name": exp["name"], "ports": add})
        if not miss and not add:
            res["hit"].append({"ip": ip, "name": exp["name"], "ports": sorted(cur)})
    res["missing_ports"] = sum(len(x["ports"]) for x in res["missing"])
    res["extra_ports"] = sum(len(x["ports"]) for x in res["extra"])
    res["hit_hosts"] = len(res["hit"])
    res["not_scanned_ports"] = sum(len(x["ports"]) for x in res["not_scanned"])
    return res


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


DEFAULT_CFG = {
    "targets_file": "targets.txt",
    "baseline_label": "default",
    "ports": {"mode": "all", "ranges": "", "list": []},
    "scan": {
        # ★ 「不被漏扫」最关键的一个旋钮。探测速率 ≈ concurrency ÷ 实际超时;
        #   过高会触发目标侧对源 IP 的探测限速(表现为「明明开放却扫不出来」)。
        #   1000(≈500 SYN/s) 是准确性与耗时的折中; 若「疑似漏报」持续偏多, 继续下调。
        "concurrency": 1000, "connect_timeout": 2.0, "adaptive_timeout": True,
        "min_timeout": 0.8, "retry_filtered": 0,
        "confirm_open": True, "confirm_rounds": 3, "host_discovery": True,
        "icmp_check": True, "skip_unreachable": False,
        # 重点端口补扫: 挽回因目标侧限速而漏掉的真实开放端口(尤其是 443 与非标 Web 端口)
        "rescan_filtered": 2,          # 对重点端口全量补扫轮数
        "rescan_priority_rounds": 2,   # 重点端口额外追加轮数(顺序打乱)
        "rescan_delay": 1.5,           # 轮间冷却秒数, 让目标侧限速窗口重置
        "rescan_slowdown": 4,          # 补扫并发 = per_host / 该值
        "rescan_timeout_factor": 1.6,  # 补扫超时 = 主扫描超时 * 该值^(轮次)
        "rescan_scope": "priority",    # priority=只补重点端口; all=补全部无响应端口(慢)
        # ★ 打乱端口顺序: 目标侧限速多半是「扫描过程中逐渐生效」的, 顺序扫会让
        # 后半段(443 与高位业务端口)被整片吞掉。打乱后损失分散, 更容易被补扫捞回。
        "shuffle_ports": True,
        # ★ 全局后置补扫(post_rescan_*): 在**全部主机主扫描结束之后**, 先冷却一段,
        # 等目标侧对源 IP 的限速窗口过去, 再对「业务端口」做低速多轮兜底。
        # 这是「只扫到 80、443 与业务端口全丢」这类症状的直接对症手段。
        "post_rescan_rounds": 1,           # 后置补扫轮数(0=关闭); 实测第 2 轮起挽回基本为 0
        "post_rescan_delay": 90,           # 主扫描结束后先冷却多少秒
        "post_rescan_slowdown": 6,         # 后置补扫并发 = per_host / 该值
        "post_rescan_timeout_factor": 1.5,  # 后置补扫超时 = 主超时 * 该值^(轮次)
        # 分批执行: 把目标切成小批, 批间冷却。降低单次探测压力, 显著减少
        # 目标侧限速(以及手机热点/家用宽带出口 NAT 表打满)导致的漏报。
        "batch_size": 0,               # 0=不分批; 目标较多(如 >20 台)时建议设 8
        "batch_gap": 0,                # 批间冷却秒数(仅 batch_size>0 时生效)
        "banner_grab": True, "tls_grab": True, "banner_timeout": 2.5,
        "anomaly_threshold": 500, "unreachable_warn_ratio": 0.35,
    },
    # ★ 定向复核(verify): 对「历史基线清单里有、上一轮却没扫到」的端口做
    # 低并发多轮重探, 判断它到底是真关闭, 还是被源 IP 限速吞掉的漏报。
    # 2026-10-14 起可以在控制台里勾选「扫描完自动复核」, 不必再双击 一键复核.bat。
    "verify": {
        "from_label": "default",    # 对照哪一份基线(上一轮扫描用的标签)
        "rounds": 5,                # 复核轮数
        "delay": 2.0,               # 轮间隔秒数
        "after_scan": False,        # 主扫描完成后是否自动接跑复核(界面上的勾选项)
    },
    # ★ 界面行为(ui): 控制台窗口的收尾提示。
    # 实测痛点: 用户不知道扫描什么时候"真的结束、可以关窗口了", 常常在收尾阶段
    # 误关窗口 → 进程死亡 → 成果丢失。所以扫描结束时把窗口标题改成明确提示。
    "ui": {
        "auto_exit_after_scan": False,  # 勾选后: 扫描完成自动关闭控制台进程
        "auto_exit_delay": 8,           # 自动退出前的缓冲秒数(留给用户看结果)
        # 勾选后: 本次扫描跳过全部补扫(机内补扫 + 全局后置补扫), 只跑一遍主扫描。
        # 用途: 测试/验证链路、追求速度时的开关。代价是弱网或被限速时容易漏报
        # 443 等真实开放端口 —— 正式巡检不要开。
        # 实现: 只在本次运行内把补扫轮数清零, **不改动**下面 scan 段的调参。
        "skip_rescan": False,
    },
    "report": {"dir": "reports", "baseline_dir": "baseline",
               "keep_reports": 30, "title": "GuvianEye 公网暴露面巡检报告"},
    "mail": {"enabled": False, "smtp_host": "smtp.qq.com", "smtp_port": 465,
             "use_ssl": True, "sender": "", "auth_code": "",
             "recipients": [], "send_when_changed_only": False},
}


def make_config(config_path=None, overrides=None) -> dict:
    """读取 config.json 并与默认值 / 运行时覆盖项合并"""
    p = Path(config_path) if config_path else (BASE_DIR / "config.json")
    cfg = DEFAULT_CFG
    if p.exists():
        try:
            cfg = deep_merge(DEFAULT_CFG, json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            cfg = DEFAULT_CFG
    if overrides:
        cfg = deep_merge(cfg, overrides)
    return cfg


# --------------------------------------------------------------------------
# 历史记录(供周度趋势图使用)
# --------------------------------------------------------------------------

def history_path(baseline_dir: Path) -> Path:
    return baseline_dir / "history.json"


def load_history(baseline_dir: Path) -> list:
    p = history_path(baseline_dir)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def make_history_entry(doc: dict) -> dict:
    s = doc["summary"]
    return {
        "scan_time": doc["scan_time"],
        "label": doc.get("scan_label", "default"),
        "open_total": s["open_total"],
        "critical_total": s["critical_total"],
        "high_total": s["high_total"],
        "new_ports": s["new_ports"],
        "gone_ports": s["gone_ports"],
        "hosts_total": doc["hosts_total"],
        "ports_scanned": doc["ports_scanned"],
        "elapsed_sec": doc["elapsed_sec"],
        "silent_hosts": s.get("silent_hosts", 0),
        "report_file": doc.get("report_file", ""),
    }


def append_history(baseline_dir: Path, doc: dict, limit: int = 300) -> list:
    hist = load_history(baseline_dir)
    hist.append(make_history_entry(doc))
    hist = hist[-limit:]
    history_path(baseline_dir).write_text(
        json.dumps(hist, ensure_ascii=False, indent=2), encoding="utf-8")
    return hist


# --------------------------------------------------------------------------
# 扫描主流程(CLI 与 Web 控制台共用)
# --------------------------------------------------------------------------

async def preflight(cfg: dict, targets: list, on_log=None) -> int:
    """换网络后的「能不能扫 / 该用多大并发」预检。

    在动手全量扫描之前先跑这一步, 回答三个问题:
      1. 这些目标在当前网络下到底通不通 —— 办公网/家用宽带常有部分公网资产根本不通,
         直接开扫会把这些目标判成"无开放端口", 得出完全错误的结论。
      2. 实测 RTT 是多少 —— 决定 connect_timeout / min_timeout 该设多少。
      3. 当前并发下本机 + 出口链路(手机热点 / 运营商 NAT)扛不扛得住 —— 决定
         concurrency 该设多少, 并直接推算全量扫描要跑多久。

    关键是第 3 步: 用一批"几乎必然静默丢弃"的高位端口做压力测试, 只测吞吐与本机侧
    异常(errno), 不碰任何真实业务端口, 因此可以放心跑。
    """
    def log(msg=""):
        if on_log:
            try:
                on_log(msg)
            except Exception:
                pass
        else:
            print(msg)

    scfg = cfg["scan"]
    concurrency = int(scfg.get("concurrency", 4000))
    base_timeout = float(scfg.get("connect_timeout", 1.2))
    per_host = max(8, min(256, concurrency // max(1, len(targets))))

    log("=" * 78)
    log("  网络预检 —— 换网络后必须先跑这一步")
    log("=" * 78)
    log("  目标 %d 台  |  当前 config 并发 %d  |  超时 %.2fs"
        % (len(targets), concurrency, base_timeout))
    log("-" * 78)

    # ---- [1/3] ICMP 可达性 ----
    log("[1/3] ICMP 可达性 ...")
    icmp = await asyncio.gather(*[icmp_ping(ip) for ip in targets])
    alive_icmp, rtt_icmp = [], {}
    for ip, (ok, rtt) in zip(targets, icmp):
        if ok:
            alive_icmp.append(ip)
            if rtt:
                rtt_icmp[ip] = float(rtt)
    dead = [ip for ip in targets if ip not in set(alive_icmp)]
    log("      ICMP 可达 %d/%d 台%s"
        % (len(alive_icmp), len(targets),
           ("；不可达: " + ", ".join(dead[:8]) + ("..." if len(dead) > 8 else ""))
           if dead else ""))

    # ---- [2/3] TCP 探测 + RTT 实测(低并发, 只碰常见端口) ----
    log("[2/3] TCP 探测与 RTT 实测 (每台 %d 个端口, 低并发) ..." % len(PROBE_SET))
    loop = asyncio.get_running_loop()
    port_map, rtt_tcp, tcp_open = {}, {}, {}
    for ip in targets:
        res = await asyncio.gather(
            *[probe_tcp(loop, ip, p, max(2.0, base_timeout)) for p in PROBE_SET],
            return_exceptions=True)
        best, opened = None, []
        for p, r in zip(PROBE_SET, res):
            if isinstance(r, BaseException):
                continue
            if r[0] == "open":
                opened.append(p)
                if r[1] is not None:
                    best = r[1] if best is None else min(best, r[1])
            elif r[0] == "closed":
                best = best
        if best is not None:
            rtt_tcp[ip] = best
        tcp_open[ip] = sorted(opened)
        port_map[ip] = "up" if opened else ""
    responsive = [ip for ip in targets if tcp_open.get(ip) or ip in rtt_tcp]
    log("      有 TCP 响应 %d/%d 台" % (len(responsive), len(targets)))
    show = [(ip, tcp_open[ip]) for ip in targets if tcp_open.get(ip)]
    if show:
        log("      探测到的开放端口(样例):")
        for ip, ps in show[:12]:
            log("        %-17s %s" % (ip, " ".join(map(str, ps))))
        if len(show) > 12:
            log("        ... 其余 %d 台见正式报告" % (len(show) - 12))
    all_rtt = sorted(list(rtt_tcp.values()) or list(rtt_icmp.values()))
    if all_rtt:
        log("      RTT: 最小 %.1fms / 中位 %.1fms / 最大 %.1fms"
            % (all_rtt[0], all_rtt[len(all_rtt) // 2], all_rtt[-1]))

    # ---- [3/3] 并发压力测试(只打高位静默端口, 不碰业务) ----
    log("[3/3] 并发压力测试 (%d 个静默端口 x %d 台, 单主机并发 %d) ..."
        % (len(STRESS_PORTS), len(targets), per_host))
    PROBE_STATS.clear()
    prog = Progress(len(targets) * len(STRESS_PORTS), "压测", sink=lambda s: None)
    t0 = time.time()
    await asyncio.gather(*[
        sweep_ports(ip, STRESS_PORTS, per_host, base_timeout, loop, prog, None, "压测")
        for ip in targets])
    el = max(0.001, time.time() - t0)
    stats = dict(PROBE_STATS)
    probes = sum(stats.values()) or 1
    errno_n = sum(v for k, v in stats.items() if k.startswith("errno:"))
    rate = probes / el
    log("      完成 %s 次探测, 耗时 %.1fs, 吞吐 %.0f port/s"
        % (format(probes, ","), el, rate))
    if errno_n:
        log("      [!] 本机侧异常(errno) %d 次 —— 并发过高, 出口链路已扛不住"
            % errno_n)
    else:
        log("      本机侧异常(errno) 0 次 —— 当前并发下链路健康")

    # ---- 推荐参数 ----
    total_probes = len(targets) * 65535
    rescan_extra = int(total_probes * 0.03)
    rec_conc = concurrency
    reason = "保持"
    if errno_n > 0:
        rec_conc = max(400, int(concurrency * 0.5))
        reason = "出现 errno, 减半"
    elif len(targets) <= 4 and concurrency < 2000:
        rec_conc = 2000
        reason = "主机少, 可以提高"

    # 超时按实测 RTT 分档: 自适应超时会用 5xRTT, 下限由 min_timeout 兜底
    med = (all_rtt[len(all_rtt) // 2] / 1000.0) if all_rtt else 0.0
    if med and med <= 0.05:
        rec_timeout, rec_min, band = 1.0, 0.5, "近距(≤50ms), 用默认即可"
    elif med and med <= 0.2:
        rec_timeout, rec_min, band = 1.5, 0.8, "中距(50~200ms), 略放宽"
    elif med:
        rec_timeout, rec_min, band = 2.5, 1.2, "远距/跨运营商(>200ms), 必须放宽"
    else:
        rec_timeout, rec_min, band = base_timeout, 0.5, "未测到 RTT, 沿用配置"

    # 注意: 分批执行**不降低瞬时并发**(每批仍然跑满 concurrency), 只会把总耗时
    # 放大 (主机数 ÷ batch_size) 倍。真正能"降载"的旋钮只有一个 —— concurrency。
    # 所以这里只给 concurrency / 超时的建议, 不主动推分批。
    # 耗时给区间: 上限按压测超时(最慢), 下限按自适应超时收紧后的实际值(多数主机会命中)
    eta_slow = (total_probes + rescan_extra) / max(1.0, rate) + len(targets) * 0.4
    eff_to = max(rec_min, min(rec_timeout, (med * 5.0) if med else rec_timeout))
    rate_fast = rate * (base_timeout / max(0.1, eff_to))
    eta_fast = (total_probes + rescan_extra) / max(1.0, rate_fast) + len(targets) * 0.4

    log("-" * 78)
    log("  推荐参数 (可直接填进 config.json 的 scan 段):")
    log("    concurrency          %d      (%s)" % (rec_conc, reason))
    log("    connect_timeout      %.1f" % rec_timeout)
    log("    min_timeout          %.1f    (%s)" % (rec_min, band))
    log("    batch_size           0        不分批(分批只会成倍拉长耗时, 不降瞬时并发)")
    log("  预计全量耗时: 约 %.0f ~ %.0f 分钟 (含补扫)" % (eta_fast / 60.0, eta_slow / 60.0))
    log("  提示: concurrency 每降一半, 耗时约翻倍, 但触发目标侧限速的概率显著下降。")
    log("-" * 78)

    # ---- 结论与红灯提示 ----
    unreach = len(targets) - len(responsive)
    bad = []
    if unreach / max(1, len(targets)) > 0.35:
        bad.append("有 %d/%d 台在当前网络下完全无响应(占 %.0f%%), 这些目标扫了也没有意义, "
                   "请先确认本网络是否真的能到达它们"
                   % (unreach, len(targets), 100.0 * unreach / len(targets)))
    if errno_n:
        bad.append("压测出现本机侧异常, 说明当前并发超出链路能力, 直接全量扫会产生大量假阴性")
    if not all_rtt:
        bad.append("没有实测到任何 RTT, 说明当前网络对这批目标基本不通")
    if bad:
        log("  [!!] 先解决以下问题再开扫:")
        for b in bad:
            log("       · %s" % b)
    else:
        log("  [OK] 网络状况正常, 可以开扫。")
    log("")
    log("  开扫命令(注意 --label 必须换成本次执行网络的新名字, 不要复用办公网的标签):")
    log("    python scanner.py --label mobile --mail")
    log("  建议先跑一次小规模验证(2 分钟, 流量几 MB), 结果正常再全量:")
    log("    python scanner.py --label mobile --mode common --no-mail")
    log("=" * 78)
    return 0 if not bad else 4


# --------------------------------------------------------------------------
# 定向复核: 「历史期望有、上一轮却没扫到」的端口 —— 到底是真关闭, 还是假阴性?
# --------------------------------------------------------------------------
# 为什么需要它:
#   上一轮报告说"某端口没开放", 但这个结论本身不一定可信 —— 目标侧的源 IP 限速
#   会把真实开放的端口静默丢弃。直接重跑全量代价大, 而且未必能回答这个问题。
#   定向复核只做一件事: 对那批"有疑问"的端口, 用极低速 + 多轮探测, 并且
#   **同时探测该主机已知开放的端口作为对照**, 从而把三种情况区分开:
#     · 复核端口有命中                   -> 确认开放, 上一轮是漏报
#     · 对照端口通 / 复核端口全程无响应   -> 主机确实可达, 该端口很可能是真关闭
#     · 对照端口也不通 / ICMP 也不通       -> 本机当前到不了这台主机, 本次复核无效
#   第三种情况最容易骗人: 不设对照, 就会把"网络不通"误读成"端口已关闭"。
# --------------------------------------------------------------------------

def load_verify_history(report_dir: Path, current: Path = None) -> list:
    """加载历次定向复核结果, 用于「跨批次取并集」。

    为什么要取并集:
      目标侧的限速 / 策略阻断是**概率性**的 —— 某一次没测到, 不等于永远测不到。
      把历次复核(办公网、手机热点、jumphost 等不同网络; 不同时段)的结果并起来,
      "确认开放"的覆盖率会明显高于任何单次, 这是目前唯一能不靠猜、
      把漏报压到最低的办法。

    返回 [(文件名, doc), ...], 按时间升序。
    """
    out = []
    if not report_dir or not report_dir.exists():
        return out
    for f in sorted(report_dir.glob("verify_*.json")):
        if f.name.endswith(".raw.json"):          # 判定修正前的原始备份, 跳过
            continue
        if current is not None:
            try:
                if f.resolve() == Path(current).resolve():
                    continue
            except Exception:
                pass
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("jobs"):
            out.append((f.name, d))
    return out


def collect_history_hits(history: list) -> dict:
    """把历次复核里"命中过"的 (ip, port) 汇总起来。

    返回 {(ip, port): [来源批次时间, ...]}
    """
    hits = {}
    for fname, d in history:
        src = d.get("verify_time") or fname
        lab = d.get("prev_label") or ""
        src = ("%s%s" % (src, ("/" + lab) if lab else ""))
        for hj in (d.get("jobs") or []):
            ip = hj.get("ip")
            if not ip:
                continue
            for p, v in (hj.get("hit") or {}).items():
                try:
                    pn, vn = int(p), int(v or 0)
                except Exception:
                    continue
                if vn > 0:
                    hits.setdefault((ip, pn), []).append(src)
    return hits


def judge_verify(job: dict, rounds: int) -> None:
    """根据命中情况判定单台主机的复核结论(就地写回 job)。

    ★ 判定的关键: 只有「对照端口 **全部** 可通」时, 才能说复核端口"很可能真关闭"。
      实测遇到过反例 —— 同一台机(远程实验室)的对照端口 80/8012/8014/8015/8016 通,
      而 8001/8005/8006/8007/8008/8010/8017/8018 不通。这种"半通"状态下, 复核端口
      "不通"什么都证明不了: 它既可能是真关闭, 也可能是这台机自身在选择性过滤。
      硬判成"真关闭", 就会制造出一个看起来很有说服力的错误结论。
    """
    def hit_of(d, p):
        return d.get(str(p), d.get(p, 0))

    miss_hit = sum(1 for p in job["miss"] if hit_of(job["hit"], p) > 0)
    ctrl_total = len(job["ctrl"])
    ctrl_hit = sum(1 for p in job["ctrl"] if hit_of(job["ctrl_hit"], p) > 0)
    job["ctrl_total"] = ctrl_total
    job["ctrl_hit_n"] = ctrl_hit

    ctrl_all_ok = bool(ctrl_total) and ctrl_hit == ctrl_total
    # 有些主机在上一轮里一个端口都没扫到(它当时根本不可达), 因此没有"对照端口"可用。
    # 但本轮它既然有端口响应了(哪怕响应的是我们要复核的端口), 就说明「本机 → 该主机」的
    # 链路在同一时刻是通的 —— 同一台机的其他端口能通, 就是最天然的对照组。
    # 实测样本: VPN备用地址 192.0.2.30 的 1723/4430 全通, 而 80/443 全不通,
    # 若因"无对照端口"就判『本次无效』, 等于白测一轮。
    live_ports = sorted(set(p for p in job["miss"] if hit_of(job["hit"], p) > 0)
                        | set(p for p in job["ctrl"] if hit_of(job["ctrl_hit"], p) > 0))
    host_up = bool(live_ports) or bool(job.get("icmp"))
    self_ctrl_ok = (not ctrl_total) and bool(live_ports)
    job["live_ports"] = live_ports
    job["self_ctrl_ok"] = self_ctrl_ok

    if miss_hit:
        job["verdict"] = "confirm_open"
        job["verdict_text"] = "★ 确认开放 (上一轮漏报)"
    elif job.get("hist_open"):
        job["verdict"] = "history_open"
        job["verdict_text"] = ("★ 历次复核确认过开放 (本轮未复现, 属网络波动)")
    elif ctrl_all_ok:
        job["verdict"] = "closed"
        job["verdict_text"] = "很可能真关闭 (对照端口全部可通)"
    elif ctrl_total and ctrl_hit > 0:
        job["verdict"] = "unstable"
        job["verdict_text"] = ("无法判定 (对照端口 %d/%d 通, 本机可达性在波动)"
                               % (ctrl_hit, ctrl_total))
    elif host_up:
        job["verdict"] = "filtered"
        job["verdict_text"] = "本机在线, 但复核端口全部不通 —— 无法判定真假"
    else:
        job["verdict"] = "unreachable"
        job["verdict_text"] = "本机不可达, 本次复核无效"

    # ---- 逐端口判定 ----
    # 主机级结论只能说明"这台机部分端口确认开放"。同一台机上往往还混着几个 0/N 的端口,
    # 那些端口到底"真关闭"还是"无法判定", 必须单个说清, 否则会被主机级结论盖掉。
    # 实测样本(远程实验室 192.0.2.13): 8003/8009/8090 全通, 而 8030/8031 全不通,
    # 对照端口 13/13 全通 —— 这时 8030/8031 才能理直气壮地说"很可能真关闭"。
    hist = job.get("hist_open") or {}
    port_verdict = {}
    for p in job["miss"]:
        h = hit_of(job["hit"], p)
        if h > 0:
            pv = ("open", "★ 开放 %d/%d" % (h, rounds))
        elif hist.get(p) or hist.get(str(p)):
            pv = ("history", "★ 历次复核确认过开放")
        elif ctrl_all_ok:
            pv = ("closed", "很可能真关闭 (对照 %d/%d 全通)" % (ctrl_hit, ctrl_total))
        elif self_ctrl_ok:
            pv = ("closed", "很可能真关闭 (同主机另 %d 个端口全通)" % len(live_ports))
        elif ctrl_total:
            pv = ("unstable", "无法判定 (对照仅 %d/%d 通)" % (ctrl_hit, ctrl_total))
        elif host_up:
            pv = ("unstable", "无法判定 (仅 ICMP 通, TCP 无参照)")
        else:
            pv = ("unreachable", "本次无效 (本机不可达)")
        port_verdict[str(p)] = {"verdict": pv[0], "text": pv[1], "hit": h}
    job["port_verdict"] = port_verdict
    job["ctrl_all_ok"] = ctrl_all_ok


async def verify_missing(cfg: dict, prev_label: str = "default",
                         rounds: int = 5, delay: float = 2.0,
                         on_log=None) -> int:
    # ---- 控制台文本同时落盘 ----
    # 用户踩过的坑: 手工脚本跑完窗口一闪而过, 屏幕上那些结论全丢了。
    # 所以复核的每一行输出都同时写进 reports\复核结果_<时间戳>.txt,
    # 双击 一键复核.bat 跑完即使关了窗口, 结论也还在。
    _rdir = BASE_DIR / cfg["report"]["dir"]
    _rdir.mkdir(parents=True, exist_ok=True)
    txt_path = _rdir / ("复核结果_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S"))

    def log(m=""):
        if on_log:
            try:
                on_log(m)
            except Exception:
                pass
        else:
            print(m)
        try:
            with open(txt_path, "a", encoding="utf-8") as fh:
                fh.write(str(m) + "\n")
        except Exception:
            pass

    expected = load_expected()
    if not expected:
        log("[!] 未找到 expected_ports.json —— 无法确定要复核哪些端口。")
        return 4

    report_dir = BASE_DIR / cfg["report"]["dir"]
    verify_hist = load_verify_history(report_dir)

    baseline_dir = BASE_DIR / cfg["report"]["baseline_dir"]
    prev = load_baseline(baseline_dir, prev_label)
    if not prev:
        log("[!] 未找到基线 %s。" % baseline_path(baseline_dir, prev_label).name)
        log("    用 --verify-from <标签> 指定上一轮用的基线标签 (例如 jumphost)。")
        return 4

    prev_open = {h["ip"]: {p["port"] for p in h.get("open_ports", [])}
                 for h in prev.get("hosts", [])}

    jobs = []
    for ip, exp in sorted(expected.items()):
        if not exp["live"]:
            continue
        got = prev_open.get(ip, set())
        miss = sorted(exp["ports"] - got)
        if miss:
            jobs.append({"ip": ip, "name": exp["name"],
                         "miss": miss, "ctrl": sorted(got)})

    log("=" * 104)
    log("  定向复核 · 对照基线 %s  (%s)"
        % (baseline_path(baseline_dir, prev_label).name, prev.get("scan_time", "?")))
    log("  待复核 %d 台主机 | %d 轮 | 轮间隔 %.1fs | 单机并发 %d | 探测超时待定"
        % (len(jobs), rounds, delay, VERIFY_PER_HOST))
    log("=" * 104)
    if not jobs:
        log("  历史期望与上一轮结果完全一致, 无需复核。")
        return 0

    for j in jobs:
        j["hit"] = {p: 0 for p in j["miss"]}
        j["ctrl_hit"] = {p: 0 for p in j["ctrl"]}
        j["hist_open"] = {}
        j["banner"] = {}
        j["icmp"] = None
        j["icmp_rtt"] = None

    loop = asyncio.get_running_loop()
    timeout = max(2.0, float(cfg["scan"].get("connect_timeout", 2.0)) * 1.5)
    log("  探测超时 %.1fs (刻意放宽, 移动网络/弱网下不要收紧)" % timeout)
    log("")

    for r in range(rounds):
        if r:
            await asyncio.sleep(delay)

        async def one(j):
            ip = j["ip"]
            if j["ctrl"]:
                op, _c, _f = await sweep_ports(ip, j["ctrl"], VERIFY_PER_HOST,
                                               timeout, loop, None, None, phase="对照")
                for p in j["ctrl"]:
                    if p in op:
                        j["ctrl_hit"][p] += 1
            if j["miss"]:
                op2, _c2, _f2 = await sweep_ports(ip, j["miss"], VERIFY_PER_HOST,
                                                  timeout, loop, None, None, phase="复核")
                for p in j["miss"]:
                    if p in op2:
                        j["hit"][p] += 1
                        j["banner"][p] = op2[p]

        # 对照端口每轮都重探 —— 对照必须与复核处于"同一时刻"才有可比性
        await asyncio.gather(*[one(j) for j in jobs])
        line = "  ".join("%s:%d" % (j["ip"].split(".")[-1],
                                    sum(1 for p in j["miss"] if j["hit"][p]))
                         for j in jobs)
        log("      第 %d/%d 轮完成   命中(按主机末位): %s" % (r + 1, rounds, line))

    icmps = await asyncio.gather(*[icmp_ping(j["ip"]) for j in jobs])
    for j, item in zip(jobs, icmps):
        j["icmp"], j["icmp_rtt"] = bool(item[0]), item[1]

    # ---- 跨批次并集: 历次复核里命中过的端口, 本轮即使没复现也认定为"确认开放过" ----
    hist_hits = collect_history_hits(verify_hist)
    hist_only = []
    for j in jobs:
        for p in j["miss"]:
            src = hist_hits.get((j["ip"], p))
            if src and j["hit"][p] == 0:
                j["hist_open"][p] = src
                hist_only.append("%s:%s" % (j["ip"], p))
    if verify_hist:
        log("  跨批次并集: 已并入 %d 份历史复核结果" % len(verify_hist))
    if hist_only:
        log("      其中 %d 个端口在历史复核中确认过开放、本轮未复现: %s"
            % (len(hist_only), ", ".join(hist_only[:8])
               + (" ..." if len(hist_only) > 8 else "")))

    # ---- 判定 ----
    for j in jobs:
        judge_verify(j, rounds)

    log("")
    log("=" * 104)
    log("  复核结论")
    log("=" * 104)
    log("  %-16s %-22s %-30s %-14s %s"
        % ("主机", "系统", "复核端口(历史有/本次无)", "对照端口", "结论"))
    log("  " + "-" * 100)
    for j in jobs:
        if j["ctrl"]:
            ctrl_txt = "%d/%d 通" % (sum(1 for p in j["ctrl"] if j["ctrl_hit"][p] > 0),
                                     len(j["ctrl"]))
        elif j.get("live_ports"):
            ctrl_txt = "同机另 %d 口全通" % len(j["live_ports"])
        else:
            ctrl_txt = "无对照端口"
        log("  %-16s %-22s %-30s %-14s %s"
            % (j["ip"], j["name"][:20], ",".join(map(str, j["miss"]))[:28],
               ctrl_txt, j["verdict_text"]))

    log("")
    log("  逐端口判定 (命中轮数 / 总轮数):")
    for j in jobs:
        if j["verdict"] == "unreachable":
            log("      %-16s %s" % (j["ip"], "本次无效 —— 本机不可达, 换网络重测"))
            continue
        for p in j["miss"]:
            pv = (j.get("port_verdict") or {}).get(str(p)) or {}
            mark = pv.get("text") or "?"
            tag = ("  服务=%s 风险=%s" % (j["banner"][p].get("service", ""),
                                         j["banner"][p].get("risk", ""))
                   if p in j["banner"] else "")
            log("      %-16s %-6s %-34s %d/%d%s"
                % (j["ip"], p, mark, j["hit"][p], rounds, tag))

    # 单独把"真关闭"的端口拎出来说一句 —— 这是用户最想知道的另一半答案
    _pv = lambda j, p: ((j.get("port_verdict") or {}).get(str(p)) or {})
    really_closed = [("%s:%s" % (j["ip"], p))
                     for j in jobs for p in j["miss"]
                     if _pv(j, p).get("verdict") == "closed"]
    if really_closed:
        log("")
        log("  对照条件成立、复核端口 0/%d 全不通 → 判定为『很可能真关闭』共 %d 个:"
            % (rounds, len(really_closed)))
        log("      %s" % ", ".join(really_closed))
        log("      (对照端口每轮都同时重探, 保证与复核端口处于同一时刻; 可据此从资产清单中剔除)")
    unknown_ports = [("%s:%s" % (j["ip"], p))
                     for j in jobs for p in j["miss"]
                     if _pv(j, p).get("verdict") in ("unstable", "filtered", "unreachable")]
    if unknown_ports:
        log("")
        log("  ⚠ 仍然无法判定真假的端口 %d 个 (对照端口没全通, 0 命中说明不了问题):"
            % len(unknown_ports))
        log("      %s" % ", ".join(unknown_ports))
        log("      建议: 换另一个网络(手机热点)再复核一次, 两次结果取并集后再下结论。")

    doc = {
        "verify_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prev_label": sanitize_label(prev_label),
        "prev_scan_time": prev.get("scan_time", ""),
        "hist_batches": len(verify_hist),
        "rounds": rounds, "delay": delay, "timeout": timeout,
        "jobs": [{
            "ip": j["ip"], "name": j["name"], "miss": j["miss"], "ctrl": j["ctrl"],
            "hit": j["hit"], "ctrl_hit": j["ctrl_hit"],
            "icmp": j["icmp"], "icmp_rtt": j["icmp_rtt"],
            "verdict": j["verdict"], "verdict_text": j["verdict_text"],
            "ctrl_all_ok": j.get("ctrl_all_ok", False),
            "self_ctrl_ok": j.get("self_ctrl_ok", False),
            "live_ports": j.get("live_ports") or [],
            "port_verdict": j.get("port_verdict") or {},
            "hist_open": {str(k): v for k, v in (j.get("hist_open") or {}).items()},
            "banner": {str(k): v for k, v in j["banner"].items()},
        } for j in jobs],
    }
    report_dir = BASE_DIR / cfg["report"]["dir"]
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jpath = report_dir / ("verify_%s.json" % stamp)
    jpath.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    hpath = report_dir / ("verify_%s.html" % stamp)
    try:
        hpath.write_text(verify_html(doc), encoding="utf-8")
    except Exception as exc:
        log("      [!] HTML 复核报告生成失败: %s" % exc)
        hpath = None

    log("")
    log("-" * 104)
    n_ok = sum(1 for j in jobs if j["verdict"] == "confirm_open")
    n_hist = sum(1 for j in jobs if j["verdict"] == "history_open")
    n_closed = sum(1 for j in jobs if j["verdict"] == "closed")
    n_unstable = sum(1 for j in jobs if j["verdict"] == "unstable")
    n_filt = sum(1 for j in jobs if j["verdict"] == "filtered")
    n_unreach = sum(1 for j in jobs if j["verdict"] == "unreachable")
    ports_confirmed = sum(
        1 for j in jobs for p in j["miss"]
        if j["hit"][p] > 0 or p in (j.get("hist_open") or {}))
    log("  汇总: 本轮确认开放 %d 台 / 历史已确证(本轮未复现) %d 台 / 很可能真关闭 %d 台"
        % (n_ok, n_hist, n_closed))
    log("        可达性波动无法判定 %d 台 / TCP 全无应答 %d 台 / 本机不可达 %d 台"
        % (n_unstable, n_filt, n_unreach))
    if ports_confirmed:
        log("  ★ 累计已确证开放的端口: %d 个 —— 这是确定性结论(收到过 SYN-ACK),"
            " 可直接写入资产清单。" % ports_confirmed)
    # 端口级口径 —— 主机级"很可能真关闭 0 台"容易被误读(每台机都至少有一个端口确认开放),
    # 所以真假到底各有多少, 必须按端口再说一遍。
    pc_open = sum(1 for j in jobs for p in j["miss"] if _pv(j, p).get("verdict") == "open")
    pc_hist = sum(1 for j in jobs for p in j["miss"]
                  if _pv(j, p).get("verdict") == "history")
    pc_closed = len(really_closed)
    pc_unk = len(unknown_ports)
    log("  端口级口径: 本轮确认开放 %d + 历史已确证 %d = 累计 %d 个 / 很可能真关闭 %d 个 /"
        " 无法判定 %d 个"
        % (pc_open, pc_hist, pc_open + pc_hist, pc_closed, pc_unk))
    if n_unreach:
        log("  ⚠ 有 %d 台在当前网络下完全不可达 —— 它们的结果不能说明任何问题,"
            % n_unreach)
        log("    请换到能到达这些目标的网络后重新复核(否则会把『网络不通』误读成『端口关闭』)。")
    log("  复核数据: %s" % jpath)
    if hpath:
        log("  复核报告: %s" % hpath)
    log("  文本结果: %s   (窗口关了也能在这找回)" % txt_path)
    log("-" * 104)
    return 0


def verify_html(doc: dict) -> str:
    """定向复核的可读 HTML 报告(自包含, 可直接转发)。"""
    def esc(x):
        return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    VC = {"confirm_open": "#c0392b", "history_open": "#e74c3c", "closed": "#27ae60",
          "unstable": "#8e44ad", "filtered": "#e67e22", "unreachable": "#7f8c8d"}
    KLABEL = {"confirm_open": "本轮确认开放(漏报)", "history_open": "历史已确证开放",
              "closed": "很可能真关闭",
              "unstable": "可达性波动, 无法判定", "filtered": "TCP 全无应答",
              "unreachable": "本机不可达"}
    ORDER = ["confirm_open", "history_open", "closed", "unstable", "filtered",
             "unreachable"]

    def hit_of(d, p):
        return d.get(str(p), d.get(p, 0))

    CV = {"open": "#c0392b", "history": "#e67e22", "closed": "#27ae60",
          "unstable": "#8e44ad", "filtered": "#e67e22", "unreachable": "#7f8c8d"}

    rows = []
    closed_all = []
    unknown_all = []
    for j in doc["jobs"]:
        col = VC.get(j["verdict"], "#888")
        pvs = j.get("port_verdict") or {}
        cells = []
        for p in j["miss"]:
            pv = pvs.get(str(p)) or {}
            kind = pv.get("verdict") or ("open" if hit_of(j["hit"], p) else "unstable")
            if kind == "closed":
                closed_all.append("%s:%s" % (j["ip"], p))
            elif kind in ("unstable", "filtered", "unreachable"):
                unknown_all.append("%s:%s" % (j["ip"], p))
            mark = {"open": " ✓", "history": " ◆"}.get(kind, "")
            cells.append('<span class="chip k-%s" title="%s">%s <b>%d/%d</b>%s</span>'
                         % (kind, esc(pv.get("text") or ""), p,
                            hit_of(j["hit"], p), doc["rounds"], mark))
        miss_cells = "".join(cells) or "—"
        if j.get("ctrl"):
            ctrl_cells = "".join(
                '<span class="chip%s">%s%s</span>'
                % (" ok" if hit_of(j["ctrl_hit"], p) else "", p,
                   " ✓" if hit_of(j["ctrl_hit"], p) else "")
                for p in j["ctrl"])
        elif j.get("live_ports"):
            # 上一轮这台机一个端口都没扫到, 没有对照端口可用;
            # 用"本轮同一台机上已经响应的端口"充当对照组 —— 路径通不通, 这就是证据。
            ctrl_cells = ('<span class="muted">无历史对照 ── 以同主机本轮已响应的端口为参照:</span><br>'
                          + "".join('<span class="chip ok">%s ✓</span>' % p
                                    for p in j["live_ports"]))
        else:
            ctrl_cells = "—"
        rows.append(
            '<tr><td>%s<br><span class="muted">%s</span></td><td>%s</td>'
            '<td>%s</td><td><b style="color:%s">%s</b></td></tr>'
            % (esc(j["ip"]), esc(j["name"]), miss_cells, ctrl_cells,
               col, esc(j["verdict_text"])))

    port_line = ""
    if closed_all:
        port_line += ('<br>⑦ <b>对照条件成立、复核端口 0 命中</b> 的端口共 <b>%d</b> 个, '
                      '已判定为「很可能真关闭」, 可据此从资产清单中剔除或下线:'
                      '<div class="locks">%s</div>'
                      % (len(closed_all),
                         "".join('<code class="ok">%s</code>' % esc(x)
                                 for x in closed_all)))
    if unknown_all:
        port_line += ('<br>⑧ <b>仍无法判定真假</b>的端口共 <b>%d</b> 个 (对照端口没全通, '
                      '0 命中说明不了问题) —— 建议换另一个网络再复核一次, 两次取并集:'
                      '<div class="locks">%s</div>'
                      % (len(unknown_all),
                         "".join('<code>%s</code>' % esc(x) for x in unknown_all)))
    self_ctrl_hosts = [j["ip"] for j in doc["jobs"] if j.get("self_ctrl_ok")]
    if self_ctrl_hosts:
        port_line += ('<br>⑨ 其中 %d 台主机在上一轮里一个端口都没扫到、没有历史对照端口, '
                      '本轮改以「同一台主机上已响应的端口」作为对照组(见上表第 3 列): '
                      '%s' % (len(self_ctrl_hosts),
                              ", ".join(esc(x) for x in self_ctrl_hosts)))

    n = {}
    for j in doc["jobs"]:
        n[j["verdict"]] = n.get(j["verdict"], 0) + 1

    cards = "".join(
        '<div class="card" style="border-color:%s"><div class="k">%s</div>'
        '<div class="v">%d 台</div></div>' % (VC[k], KLABEL[k], n.get(k, 0))
        for k in ORDER)

    tpl = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>定向复核报告 · __VT__</title><style>
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
 background:#f5f6f8;color:#222;margin:0;padding:28px}
.wrap{max-width:1220px;margin:0 auto}
h1{font-size:20px;margin:0 0 6px;line-height:1.5}
.meta{color:#666;font-size:13px;margin-bottom:18px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#fff;border-radius:10px;padding:14px 18px;flex:1;min-width:150px;
 box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #999}
.card .k{font-size:12.5px;color:#777}
.card .v{font-size:22px;font-weight:700;margin-top:4px}
table{width:100%;background:#fff;border-collapse:collapse;border-radius:10px;
 overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:13.5px}
th,td{padding:11px 13px;text-align:left;border-bottom:1px solid #eceef1;vertical-align:top}
th{background:#fafbfc;font-size:12.5px;color:#666;font-weight:600}
.muted{color:#888;font-size:12px}
.chip{display:inline-block;background:#eef1f5;border-radius:6px;padding:3px 8px;
 margin:2px 4px 2px 0;font-size:12.5px}
.chip.ok{background:#fdecea;color:#c0392b;font-weight:600}
.chip.k-open{background:#fdecea;color:#c0392b;font-weight:600}
.chip.k-history{background:#fef5e7;color:#d35400;font-weight:600}
.chip.k-closed{background:#eafaf1;color:#1e8449}
.chip.k-unstable{background:#f4ecf7;color:#7d3c98}
.chip.k-filtered{background:#fef5e7;color:#b9770e}
.chip.k-unreachable{background:#f2f3f4;color:#7f8c8d}
.locks{margin:6px 0 2px}
.locks code{display:inline-block;background:#eef1f5;border-radius:5px;padding:2px 7px;
 margin:3px 5px 0 0;font-size:12.5px;color:#333}
.locks code.ok{background:#eafaf1;color:#1e8449}
.note{background:#fff;border-radius:10px;padding:16px 20px;margin-top:20px;font-size:13px;
 line-height:2;box-shadow:0 1px 3px rgba(0,0,0,.08)}
</style></head><body><div class="wrap">
<h1>定向复核 · 历史清单里「上一轮没扫到」的端口, 到底是真关闭还是漏报?</h1>
<div class="meta">__META__</div>
<div class="cards">__CARDS__</div>
<table><thead><tr><th style="width:170px">主机</th>
<th>复核端口(历史有 / 本次无) · 命中轮数</th>
<th style="width:230px">对照端口(上次已确认开放, 标红=通)</th>
<th style="width:250px">结论</th></tr></thead>
<tbody>__ROWS__</tbody></table>
<div class="note"><b>怎么读这张表</b><br>
① <b>复核端口命中 ≥1 轮</b> → 收到过 SYN-ACK, 是确定性结论, 上一轮确实漏报了;<br>
② <b>复核端口 0 命中、且对照端口「全部」可通</b> → 同一时刻同一源 IP, 对照全通而它全不通,
说明该端口很可能是真的关闭(或已被策略收口), 不是网络问题;<br>
③ <b>对照端口只通了一部分</b> → 说明这台主机自身可达性在波动 / 被选择性过滤,
此时「不通」什么都证明不了, 必须换网络或换时段重测;<br>
④ <b>对照端口一个都不通</b> → 当前执行网络到不了这台主机, 本次复核<b>不能</b>得出任何结论;<br>
⑤ 复核用极低并发(单机 __PH__) + 放宽超时(__TO__s), 目的就是不让目标侧限速, 以拿到可信答案;<br>
⑥ <b>带 ◆ 标记的端口</b> → 本轮没测到, 但<b>历次复核(含其他网络)测到过</b>, 同样是确定性结论,
   也应写入资产清单。限速与策略阻断都是概率性的, <b>多换几个网络反复复核、取并集</b>,
   覆盖率会明显高于任何单次扫描 —— 这也是目前把漏报压到最低的唯一可靠办法。__PORTLINE__</div>
</div></body></html>"""

    meta = ("复核时间 <b>%s</b> ｜ 对照基线 <b>%s</b> (%s) ｜ %d 轮 × 轮间隔 %.1fs ｜ "
            "探测超时 %.1fs ｜ 并入历史复核 <b>%d</b> 份"
            % (esc(doc["verify_time"]), esc(doc["prev_label"]),
               esc(doc["prev_scan_time"]), doc["rounds"], doc["delay"],
               doc["timeout"], doc.get("hist_batches", 0)))

    return (tpl.replace("__VT__", esc(doc["verify_time"]))
               .replace("__META__", meta)
               .replace("__CARDS__", cards)
               .replace("__ROWS__", "".join(rows))
               .replace("__PH__", str(VERIFY_PER_HOST))
               .replace("__TO__", "%.1f" % doc["timeout"])
               .replace("__PORTLINE__", port_line))
async def execute_scan(cfg: dict, targets: list, ports: list, label: str = "default",
                       on_log=None, on_progress=None, should_stop=None,
                       dry_run: bool = False) -> dict:
    """执行一次完整巡检。

    参数
      cfg          完整配置字典(见 DEFAULT_CFG)
      on_log(str)  日志回调, 不传则打印到终端
      on_progress  进度回调, 收到 dict(done/total/percent/rate/open/elapsed/eta)
      should_stop  返回 True 时中止扫描(抛出 Cancelled)

    返回
      {"ok","cancelled","dry_run","info","doc","summary","warnings","paths","exit_code"}
    """
    def log(msg: str = "") -> None:
        if on_log:
            try:
                on_log(msg)
            except Exception:
                pass
        else:
            print(msg)

    def stop_requested() -> bool:
        return bool(should_stop and should_stop())

    label = sanitize_label(label)
    # 在扫描一开始就把"执行网络指纹"记下来。用户手填的 --label 可能与实际网络不符,
    # 这个指纹是客观证据, 用来在换网络却忘了换标签时给告警。
    src_ips = {"local": "", "public": ""} if dry_run else detect_source_ips()
    if src_ips.get("local") or src_ips.get("public"):
        log("  执行网络指纹: 本机 %s ｜ 出口 %s ｜ 基线标签 %s"
            % (src_ips.get("local") or "?", src_ips.get("public") or "?",
               label))
    scfg = cfg["scan"]
    # ★ 界面上的「跳过补扫」(ui.skip_rescan): 复制一份 scan 配置并把补扫轮数清零。
    #   为什么用复制而不是原地改: config.json 里那套 rescan/post_rescan 参数是调好的,
    #   不能因为一次"测试跑"就永久清零。这里只影响本次 execute_scan 的 scfg。
    skip_rescan = bool((cfg.get("ui") or {}).get("skip_rescan"))
    if skip_rescan:
        scfg = dict(scfg)
        scfg["rescan_filtered"] = 0
        scfg["rescan_priority_rounds"] = 0
        scfg["post_rescan_rounds"] = 0
    concurrency = int(scfg["concurrency"])
    per_host = max(32, min(768, concurrency // max(1, len(targets))))
    base_timeout = float(scfg["connect_timeout"])
    adaptive = bool(scfg.get("adaptive_timeout", True))
    min_to = float(scfg.get("min_timeout", 0.5))
    total_probes = len(targets) * len(ports)

    info = {
        "targets": len(targets), "ports": len(ports), "probes": total_probes,
        "per_host": per_host, "global_concurrency": per_host * len(targets),
        "base_timeout": base_timeout, "adaptive": adaptive, "label": label,
        "mode": cfg["ports"].get("mode", "all"),
    }
    if dry_run:
        return {"ok": True, "cancelled": False, "dry_run": True, "info": info,
                "doc": None, "summary": None, "warnings": [], "paths": {},
                "exit_code": 0}

    t0 = time.time()
    results = []
    warnings = []
    status_map, rtt_map = {}, {}

    # ---- [1/4] 主机存活预判 ----
    if scfg.get("host_discovery"):
        log("[1/4] 主机存活预判 ...")
        disc = await asyncio.gather(
            *[discover_host(ip, max(1.2, base_timeout)) for ip in targets])
        for ip, item in zip(targets, disc):
            status_map[ip] = item[0]
            if item[1] is not None:
                rtt_map[ip] = float(item[1])

        if scfg.get("icmp_check", True):
            icmp = await asyncio.gather(*[icmp_ping(ip) for ip in targets])
            alive = 0
            for ip, (ok, rtt) in zip(targets, icmp):
                if ok:
                    status_map[ip] = "up"
                    alive += 1
                    if rtt and ip not in rtt_map:
                        rtt_map[ip] = float(rtt)
            log("      ICMP 可达 %d 台" % alive)

        silent = [ip for ip, s in status_map.items() if s != "up"]
        log("      有响应 %d 台, 全部无响应 %d 台%s"
            % (len(targets) - len(silent), len(silent),
               (" -> " + ", ".join(silent)) if silent else ""))
        if rtt_map:
            rtts = sorted(rtt_map.values())
            log("      实测 RTT: 最小 %.1fms / 中位 %.1fms / 最大 %.1fms"
                % (rtts[0], rtts[len(rtts) // 2], rtts[-1]))
        if scfg.get("skip_unreachable") and silent:
            targets = [ip for ip in targets if ip not in set(silent)]
            log("      已按配置跳过无响应主机, 实际扫描 %d 台" % len(targets))

    if stop_requested():
        raise Cancelled("用户中止扫描")

    # ---- 自适应超时: 用实测 RTT 收紧超时, 是提速的最大杠杆 ----
    def host_timeout(ip: str) -> float:
        if not adaptive:
            return base_timeout
        rtt = rtt_map.get(ip)
        if rtt is not None:
            return max(min_to, min(base_timeout, rtt * 5.0))
        if status_map.get(ip) == "up":
            return min(base_timeout, max(min_to, 0.8))
        return base_timeout

    # ---- [2/4] 端口扫描 ----
    log("[2/4] 端口扫描 ...")
    PROBE_STATS.clear()
    if scfg.get("shuffle_ports", True) and len(ports) > 64:
        # ★ 打乱端口顺序 —— 针对「扫描过程中逐渐生效的限速」。
        # 目标侧的探测限速往往不是一开始就生效, 而是在累积若干个 SYN 之后才触发。
        # 若按 1→65535 顺序扫, 一旦触发, 之后**整片**端口全部被静默丢弃 ——
        # 这正是典型的限速症状: 80(最靠前)扫到了, 443 与 8000+ 的业务端口整片丢失。
        # 打乱顺序后, 被丢弃的端口会分散在整个区间, 配合多轮补扫更容易累积命中,
        # 且能避免"后半段全丢"这种系统性偏差。
        ports = random.sample(ports, len(ports))
        log("      已打乱端口顺序 (避免顺序扫描被『整片限速』吞掉后半段)")
    batch = max(0, int(scfg.get("batch_size", 0) or 0))
    gap = max(0.0, float(scfg.get("batch_gap", 0) or 0))
    prog = Progress(len(targets) * len(ports), "扫描中", sink=on_progress)
    raw_results = []
    if batch and len(targets) > batch:
        chunks = [targets[i:i + batch] for i in range(0, len(targets), batch)]
        log("      分 %d 批执行, 每批 %d 台, 批间冷却 %.0f 秒 (降低单次探测压力)"
            % (len(chunks), batch, gap))
        for idx, chunk in enumerate(chunks, 1):
            if stop_requested():
                raise Cancelled("用户中止扫描")
            head = ", ".join(chunk[:3]) + ("..." if len(chunk) > 3 else "")
            log("      [批 %d/%d] %d 台目标: %s" % (idx, len(chunks), len(chunk), head))
            tasks = [scan_host(ip, ports, scfg, per_host, prog, host_timeout(ip),
                               should_stop) for ip in chunk]
            raw_results += await asyncio.gather(*tasks)
            if idx < len(chunks) and gap:
                log("      批间冷却 %.0f 秒, 让目标侧限速窗口重置 ..." % gap)
                await asyncio.sleep(gap)
    else:
        tasks = [scan_host(ip, ports, scfg, per_host, prog, host_timeout(ip), should_stop)
                 for ip in targets]
        raw_results = await asyncio.gather(*tasks)
    prog.finish()
    if not on_progress:
        sys.stderr.write("\r" + " " * 110 + "\r")
    recovered = sum(int(h.get("rescan_recovered", 0)) for h in raw_results)
    log("      主扫描完成, 耗时 %.1f 秒%s"
        % (time.time() - t0, ("; 机内补扫挽回 %d 个开放端口" % recovered) if recovered else ""))

    # ---- ★ 中间态落盘(checkpoint): 主扫描一结束就先把原始成果写盘 ----
    # 为什么必须这么做(实测教训, 2026-10-14):
    #   某次大批量目标 x 65535 端口的主扫描跑满 77 分钟, 完成后进入「后置补扫」阶段,
    #   结果窗口在 15:38 被关掉 —— 因为全程只在最后的 [4/4] 一次性落盘,
    #   77 分钟的扫描成果**全部随进程一起消失**, reports/ 里一个文件都没有。
    #   主扫描是整个流程里最贵的一段(占 95% 以上耗时), 只要它跑完,
    #   结果就必须立刻能从磁盘上拿回来 —— 后面的补扫/确认/指纹/出报告
    #   都属于"锦上添花", 任何一个环节挂掉都不该拖累已经拿到的数据。
    _ckpt_path = None
    try:
        _rdir = BASE_DIR / cfg["report"]["dir"]
        _rdir.mkdir(parents=True, exist_ok=True)
        _ckpt_path = _rdir / ("_checkpoint_%s.json" % label)
        _ckpt = {
            "kind": "checkpoint",
            "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": ("主扫描完成后的中间态快照。若本次流程在后续阶段(后置补扫/二次确认/"
                     "指纹/出报告)中断, 可直接用 --from-checkpoint 从这份快照重建报告, "
                     "无需重跑 77 分钟。"),
            "scan_label": label,
            "elapsed_sec": round(time.time() - t0, 1),
            "targets": targets,
            "ports_scanned": len(ports),
            "probes": total_probes,
            "source_local_ip": src_ips.get("local", ""),
            "source_public_ip": src_ips.get("public", ""),
            "status_map": status_map,
            "rtt_map": rtt_map,
            "probe_stats": dict(PROBE_STATS),
            "hosts": raw_results,
        }
        _ckpt_path.write_text(json.dumps(_ckpt, ensure_ascii=False, indent=2),
                              encoding="utf-8")
        log("      [存档] 中间态已落盘: %s (主扫描成果已安全, 后续阶段即使中断也能恢复)"
            % _ckpt_path.name)
    except Exception as _exc:
        _ckpt_path = None
        log("      [!] 中间态落盘失败(不影响本次扫描, 但中断后无法恢复): %s" % _exc)

    # ---- [2.5/5] 全局后置补扫: 等限速窗口过去, 再统一低速兜底 ----
    # 为什么必须有这一步(来自实测教训):
    #   目标侧对源 IP 的探测限速是「扫描过程中逐渐生效」的 —— 端口按 1→65535 顺序推进,
    #   80(小端口)几乎总能扫到, 443 有时能扫到, 8000+ 的业务端口则经常整片丢失。
    #   而每台主机自己的机内补扫紧跟在主扫描之后, 此时限速往往还没解除, 挽回有限。
    #   把兜底整体后移 + 加一段冷却, 让限速窗口先过去, 挽回率会明显提升。
    post_rounds = int(scfg.get("post_rescan_rounds", 0) or 0)
    post_delay = float(scfg.get("post_rescan_delay", 90) or 0)
    post_slow = max(1, int(scfg.get("post_rescan_slowdown", 6) or 6))
    post_rtf = float(scfg.get("post_rescan_timeout_factor", 1.5) or 1.5)
    post_recovered = 0
    post_probes = 0
    post_rounds_done = 0
    post_pending = {h["ip"]: list(h.get("filtered_biz") or [])
                    for h in raw_results if h.get("filtered_biz")}
    if post_rounds and post_pending and not stop_requested():
        total_left = sum(len(v) for v in post_pending.values())
        log("[2.5/5] 全局后置补扫: %d 台主机仍有 %d 个业务端口无响应"
            % (len(post_pending), total_left))
        log("      冷却 %.0f 秒, 让目标侧对源 IP 的探测限速窗口先重置 ..." % post_delay)
        if post_delay:
            await asyncio.sleep(post_delay)
        loop = asyncio.get_running_loop()
        hindex = {h["ip"]: h for h in raw_results}
        sub = max(4, per_host // post_slow)
        prog2 = Progress(total_left * post_rounds, "后置补扫", sink=on_progress,
                         rescan_counts=True)
        for r in range(post_rounds):
            if stop_requested() or not post_pending:
                break
            batch_now = {ip: pl for ip, pl in post_pending.items() if pl}
            if not batch_now:
                break
            if r > 0:
                cool = max(5.0, post_delay * 0.5)
                log("      [后置补扫 %d/%d 轮] 冷却 %.0f 秒后低调重探 %d 个端口 (超时 %.1fs) ..."
                    % (r + 1, post_rounds, cool,
                       sum(len(v) for v in batch_now.values()),
                       max(2.0, base_timeout * (post_rtf ** (r + 1)))))
                await asyncio.sleep(cool)
            else:
                log("      [后置补扫 1/%d 轮] 低调重探 %d 个端口 (并发/台 %d, 超时 %.1fs) ..."
                    % (post_rounds, sum(len(v) for v in batch_now.values()), sub,
                       max(2.0, base_timeout * post_rtf)))
            to = max(2.0, base_timeout * (post_rtf ** (r + 1)))
            post_probes += sum(len(v) for v in batch_now.values())

            async def _post_one(ip, plist, _to=to, _sub=sub):
                op, _c, still = await sweep_ports(ip, plist, _sub, _to, loop,
                                                  prog2, should_stop, phase="后置补扫")
                return ip, op, still

            got = await asyncio.gather(
                *[_post_one(ip, pl) for ip, pl in batch_now.items()],
                return_exceptions=True)
            nxt = {}
            for item in got:
                if isinstance(item, BaseException):
                    continue
                ip, op, still = item
                host = hindex[ip]
                if op:
                    have = {p["port"] for p in host["open_ports"]}
                    for p, pf in op.items():
                        if p not in have:
                            host["open_ports"].append(pf)
                            have.add(p)
                            post_recovered += 1
                    host["open_ports"].sort(key=lambda x: x["port"])
                    host["filtered_count"] = max(0, int(host.get("filtered_count", 0)) - len(op))
                    host["filtered_biz"] = [p for p in (host.get("filtered_biz") or [])
                                            if p not in op]
                left = [p for p in still if p not in op]
                if left:
                    nxt[ip] = left
            post_pending = nxt
            post_rounds_done = r + 1
        prog2.finish()
        log("      后置补扫结束: 挽回 %d 个开放端口%s"
            % (post_recovered,
               (", 仍有 %d 个业务端口无响应" % sum(len(v) for v in post_pending.values()))
               if post_pending else ""))
    elif post_rounds:
        log("[2.5/5] 全局后置补扫: 无待补业务端口, 跳过")

    probe_stats = dict(PROBE_STATS)

    # ---- [3/4] 开放端口二次确认 + 服务指纹 ----
    confirm_rounds = max(1, int(scfg.get("confirm_rounds", 2) or 1))
    log("[3/4] 开放端口二次确认(%d 轮表决)与服务指纹 ..." % confirm_rounds)
    threshold = int(scfg.get("anomaly_threshold", 500))
    for host in raw_results:
        ip = host["ip"]
        abnormal = len(host["open_ports"]) >= threshold
        if abnormal:
            host["anomaly"] = (
                "该主机返回开放端口数达 %d 个, 超过阈值 %d, "
                "极可能是运营商安全墙 / 负载设备对全部端口统一应答, 结果不可信"
                % (len(host["open_ports"]), threshold))
        if scfg.get("confirm_open") and host["open_ports"] and not abnormal:
            confirmed, dropped, _hits = await confirm_ports(
                ip, host["open_ports"], max(1.5, base_timeout * 1.5), per_host,
                rounds=confirm_rounds)
            host["unconfirmed_ports"] = dropped
            host["open_ports"] = confirmed
        else:
            host["unconfirmed_ports"] = []

    # 指纹跨主机一次性并发, 避免按主机串行导致总耗时叠加
    fp_jobs = []
    if scfg.get("banner_grab"):
        for host in raw_results:
            if host.get("anomaly"):
                continue
            for p in host["open_ports"]:
                fp_jobs.append((host, p))
    if fp_jobs:
        bt = float(scfg["banner_timeout"])
        tls_on = bool(scfg.get("tls_grab", True))
        fps = await asyncio.gather(
            *[fingerprint(h["ip"], p["port"], bt, tls_on) for h, p in fp_jobs],
            return_exceptions=True)
        for (host, p), fp in zip(fp_jobs, fps):
            if isinstance(fp, BaseException):
                continue
            p["banner"] = fp.get("banner", "")
            p["tls"] = fp.get("tls", {})
            p["http"] = fp.get("http", {})
            p["product"] = fp.get("product", "")

    for host in raw_results:
        # 最终存活判定: 只要扫出开放端口, 主机必然在线, 覆盖预判结果
        host["discovery"] = "up" if host["open_ports"] else status_map.get(host["ip"], "")
        host["rtt_ms"] = round(rtt_map.get(host["ip"], 0.0), 1)
        results.append(host)

    results.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))

    # ---- 基线 diff ----
    baseline_dir = BASE_DIR / cfg["report"]["baseline_dir"]
    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline = load_baseline(baseline_dir, label)
    prev_scope = baseline.get("ports_scanned", -1) if baseline else -1
    scope_changed = bool(baseline) and int(prev_scope) != len(ports)
    if scope_changed:
        for h in results:
            h["diff"] = "unknown"
        summary = {"new": [], "gone": [], "new_hosts": [], "quiet_hosts": [],
                   "scope_changed": True}
        log("  [!] 端口范围与上次基线不一致(本次 %d / 上次 %s), 已跳过变化对比"
            % (len(ports), prev_scope))
    else:
        summary = diff_against(results, baseline)

    ts = datetime.now()
    unreachable = [h["ip"] for h in results if h.get("discovery") != "up"]
    unreach_ratio = (len(unreachable) / len(results)) if results else 0.0

    # ---- 历史期望清单对照 (历史基线清单) ----
    expected = load_expected()
    exp_diff = expected_diff(results, expected) if expected else {}
    if exp_diff:
        log("      历史清单对照: 完全一致 %d 台 / 疑似漏报 %d 台(%d 个端口) / 新增 %d 处 / 无响应未核对 %d 台"
            % (exp_diff.get("hit_hosts", 0), len(exp_diff.get("missing") or []),
               exp_diff.get("missing_ports", 0), len(exp_diff.get("extra") or []),
               len(exp_diff.get("not_scanned") or [])))

    # ---- 探测质量: 把"无响应"背后的真实构成摊开, 不让漏报被静默吞掉 ----
    errno_items = {k: v for k, v in probe_stats.items() if k.startswith("errno:")}
    total_probes_done = sum(probe_stats.values()) or 1
    quality = {
        "probes_total": total_probes_done,
        "open": int(probe_stats.get("open", 0)),
        "closed": int(probe_stats.get("closed", 0)),
        "timeout": int(probe_stats.get("timeout", 0)),
        "errno": errno_items,
        "errno_total": sum(errno_items.values()),
        "timeout_ratio": round(probe_stats.get("timeout", 0) / total_probes_done, 4),
        "rescan_recovered": sum(int(h.get("rescan_recovered", 0)) for h in results),
        "rescan_probes": sum(int(h.get("rescan_probes", 0)) for h in results),
        "post_rescan_recovered": post_recovered,
        "post_rescan_probes": post_probes,
        "post_rescan_rounds": post_rounds_done,
        "post_rescan_left": sum(len(v) for v in post_pending.values()),
        "unconfirmed_total": sum(len(h.get("unconfirmed_ports") or []) for h in results),
    }
    # errno 22/10022(WSAEINVAL) 只在极端拥塞/被限速的瞬间出现, 是"本机侧被打爆"的信号
    local_side_suspect = any(k in ("errno:22", "errno:10022", "errno:10048",
                                   "errno:10055", "errno:24")
                             for k in errno_items)

    doc = {
        "scan_time": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_sec": round(time.time() - t0, 1),
        "hosts_total": len(results),
        "ports_scanned": len(ports),
        "probes": total_probes,
        "scan_label": label,
        "source_local_ip": src_ips.get("local", ""),
        "source_public_ip": src_ips.get("public", ""),
        "unreachable_ratio": round(unreach_ratio, 3),
        "hosts": results,
        "probe_stats": probe_stats,
        "quality": quality,
        "expected_diff": exp_diff,
        "baseline_time": baseline.get("scan_time", ""),
        "scope_changed": scope_changed,
        "summary": {
            "open_total": sum(len(h["open_ports"]) for h in results),
            "critical_total": sum(1 for h in results for p in h["open_ports"]
                                  if p["risk"] == "CRITICAL"),
            "high_total": sum(1 for h in results for p in h["open_ports"]
                              if p["risk"] == "HIGH"),
            "new_ports": len(summary["new"]),
            "gone_ports": len(summary["gone"]),
            "new_hosts": len(summary["new_hosts"]),
            "anomaly_hosts": sum(1 for h in results if h.get("anomaly")),
            "silent_hosts": sum(1 for h in results if h.get("discovery") != "up"),
            "no_open_hosts": sum(1 for h in results if not h["open_ports"]),
        },
    }

    # ---- [4/4] 报告与基线 ----
    log("[4/4] 生成报告与基线 ...")
    report_dir = BASE_DIR / cfg["report"]["dir"]
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = ts.strftime("%Y%m%d_%H%M%S")

    json_out = report_dir / ("scan_%s.json" % stamp)
    json_out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_out = report_dir / ("scan_%s.csv" % stamp)
    write_csv(csv_out, doc)

    html_out = report_dir / ("report_%s.html" % stamp)
    try:
        import reporter
        # 趋势图必须包含「本次」这个点, 否则永远差一个数据点画不出线
        chart_history = load_history(baseline_dir) + [make_history_entry(doc)]
        reporter.render(doc, summary, html_out, cfg["report"].get("title", ""),
                        chart_history)
        doc["report_file"] = html_out.name
    except Exception as exc:
        log("      [!] HTML 报告生成失败: %s" % exc)
        html_out = None
        doc["report_file"] = ""

    payload = json.dumps(doc, ensure_ascii=False, indent=2)
    bpath = baseline_path(baseline_dir, label)
    bpath.write_text(payload, encoding="utf-8")
    dated = ts.strftime("%Y-%m-%d") + ("" if label == "default" else "_" + label)
    (baseline_dir / ("%s.json" % dated)).write_text(payload, encoding="utf-8")
    append_history(baseline_dir, doc)

    # ---- 正式报告已落地, 中间态快照完成使命, 清掉避免误用 ----
    if _ckpt_path is not None:
        try:
            _ckpt_path.unlink()
        except OSError:
            pass

    # 清理过期报告
    keep = int(cfg["report"].get("keep_reports", 26))
    for prefix in ("scan_", "report_"):
        files = sorted(report_dir.glob(prefix + "*"))
        for f in files[:-keep] if len(files) > keep else []:
            try:
                f.unlink()
            except OSError:
                pass

    # ---- 警告收集(供界面与报告共同使用) ----
    if unreach_ratio >= float(scfg.get("unreachable_warn_ratio", 0.35)) and results:
        warnings.append(
            "本次 %d/%d 台主机完全无响应(占 %.0f%%)。本工具无法区分「目标确实离线」"
            "与「你当前的执行网络被策略阻断」两种情况, 请务必人工确认。"
            "建议改从不受限的网络执行, 并用 --label / 基线标签为不同网络分别建立基线。"
            % (len(unreachable), len(results), unreach_ratio * 100))
    if summary["new"]:
        crit_new = [x for x in summary["new"]
                    if x.get("risk") in ("CRITICAL", "HIGH")]
        if crit_new:
            warnings.append(
                "发现 %d 个本周新增的高危/严重开放端口, 建议今日内确认处置。"
                % len(crit_new))
    if scope_changed:
        warnings.append("端口范围与上次基线不一致, 本次已跳过周度变化对比。")

    # ---- 执行网络一致性告警: 标签是手填的, 用客观指纹来兜底 ----
    prev_pub = (baseline or {}).get("source_public_ip") or ""
    prev_loc = (baseline or {}).get("source_local_ip") or ""
    cur_pub = src_ips.get("public") or ""
    cur_loc = src_ips.get("local") or ""
    if baseline and (prev_pub or prev_loc) and (cur_pub or cur_loc):
        net_changed = bool(prev_pub and cur_pub and prev_pub != cur_pub)
        if not net_changed and prev_loc and cur_loc and prev_loc != cur_loc:
            net_changed = True
        if net_changed:
            warnings.append(
                "★ 本次执行网络与上次基线不是同一个网络(出口 %s -> %s, 本机 %s -> %s), "
                "但用的都是同一个基线标签「%s」。不同网络的可达性差异会被误读成"
                "「端口新增/消失」——请为每个网络用各自的基线标签(--label), "
                "本次结果建议单独归档, 不要与另一网络的结果互相比较。"
                % (prev_pub or "?", cur_pub or "?", prev_loc or "?", cur_loc or "", label))
    elif src_ips.get("public") and unreach_ratio >= float(
            scfg.get("unreachable_warn_ratio", 0.35)):
        warnings.append(
            "本次从出口 %s 执行, 且 %d/%d 台主机完全无响应 —— 这两件事同时出现时, "
            "「无响应」多半是执行网络受限造成的, 而不是目标真的离线。"
            % (src_ips["public"], len(unreachable), len(results)))

    # ---- 漏报风险告警: 让"扫不出来"变成看得见的告警, 而不是静默的 filtered ----
    if quality["rescan_recovered"]:
        warnings.append(
            "重点端口补扫额外挽回了 %d 个开放端口 —— 说明主扫描确实漏报了它们"
            "(典型成因是目标侧对本机源 IP 的探测限速, 或本机并发过高)。"
            "结果已并入报告; 若希望减少这类漏报, 可适当下调 scan.concurrency "
            "(如 1500)并保持补扫开启。" % quality["rescan_recovered"])
    if local_side_suspect:
        warnings.append(
            "探测过程中出现本机侧异常(如 %s), 说明并发过高已把本机连接栈/临时端口"
            "打到临界。建议降低 scan.concurrency(如 1500)后重扫, 否则会出现假阴性。"
            % ", ".join(sorted(errno_items)))
    if quality["unconfirmed_total"]:
        warnings.append(
            "有 %d 个端口在扫描阶段命中、但二次确认未通过, 已列为「存疑端口」保留在"
            "报告中。目标侧限速会造成这种现象, 请人工复核, 不要直接当作未开放。"
            % quality["unconfirmed_total"])
    if (quality["timeout_ratio"] >= 0.999 and doc["summary"]["open_total"] == 0 and results):
        warnings.append(
            "本次 %.1f%% 的探测无任何响应, 且未发现任何开放端口。请确认当前执行网络"
            "确实可达这些目标(本工具无法区分「目标静默丢包」与「本网络被阻断」)。"
            % (quality["timeout_ratio"] * 100))
    if skip_rescan:
        warnings.append(
            "本次已勾选「跳过补扫」: 只跑了一遍主扫描, 速度快但**准确性下降** —— "
            "弱网或被源 IP 限速时, 443 等真实开放端口可能被漏掉。"
            "正式巡检请取消该勾选后再扫一次。")
    elif not (scfg.get("rescan_filtered", 0) or scfg.get("rescan_priority_rounds", 0)):
        warnings.append(
            "本次未启用重点端口补扫(rescan_filtered=0), 弱网或被限速时容易漏报 443 等"
            "真实开放端口。建议在 config.json 打开补扫。")
    if quality.get("post_rescan_recovered"):
        warnings.append(
            "全局后置补扫额外挽回了 %d 个开放端口 —— 这批端口在主扫描阶段是被『扫到一半"
            "才生效的限速』吞掉的(典型特征是只扫到 80、443 与高位业务端口整片丢失)。"
            "结果已并入报告。若这类挽回数量持续偏高, 说明 concurrency 仍然偏大, "
            "建议再降一档重扫。" % quality["post_rescan_recovered"])
    if quality.get("post_rescan_left"):
        warnings.append(
            "全局后置补扫结束后, 仍有 %d 个业务端口无响应。它们既可能是真关闭, "
            "也可能是本网络对该目标的策略阻断 —— 本工具无法区分, 请换网络复核后再下结论。"
            % quality["post_rescan_left"])
    if exp_diff.get("missing"):
        warnings.append(
            "★ 与历史基线清单对照: 有 %d 台主机、共 %d 个『历史上开放过』的端口本次"
            "未扫到, 已列入报告【疑似漏报】区。这不等同于『已关闭』—— 更可能是本次"
            "执行网络/限速造成的假阴性, 请优先复核: %s"
            % (len(exp_diff["missing"]), exp_diff.get("missing_ports", 0),
               "; ".join("%s(%s)" % (x["ip"], "/".join(map(str, x["ports"])))
                         for x in exp_diff["missing"][:6])))

    paths = {
        "html": str(html_out) if html_out else "",
        "csv": str(csv_out),
        "json": str(json_out),
        "baseline": str(bpath),
    }

    return {"ok": True, "cancelled": False, "dry_run": False, "info": info,
            "doc": doc, "summary": summary, "warnings": warnings,
            "paths": paths, "exit_code": 2 if summary["new"] else 0}


async def run(args) -> int:
    """命令行入口"""
    cfg = make_config(args.config)
    scfg = cfg["scan"]
    if args.turbo:
        scfg = deep_merge(scfg, {"concurrency": 8000, "connect_timeout": 0.8,
                                 "min_timeout": 0.4})
    if args.safe:
        scfg = deep_merge(scfg, {"adaptive_timeout": False})
    # 运行时覆盖(换网络后调参不必改 config.json)
    ov = {}
    if getattr(args, "concurrency", 0):
        ov["concurrency"] = int(args.concurrency)
    if getattr(args, "timeout", 0):
        ov["connect_timeout"] = float(args.timeout)
    if getattr(args, "batch_size", -1) is not None and getattr(args, "batch_size", -1) >= 0:
        ov["batch_size"] = int(args.batch_size)
    if getattr(args, "batch_gap", -1) is not None and getattr(args, "batch_gap", -1) >= 0:
        ov["batch_gap"] = float(args.batch_gap)
    if getattr(args, "post_delay", -1) is not None and getattr(args, "post_delay", -1) >= 0:
        ov["post_rescan_delay"] = float(args.post_delay)
    if getattr(args, "post_rounds", -1) is not None and getattr(args, "post_rounds", -1) >= 0:
        ov["post_rescan_rounds"] = int(args.post_rounds)
    if getattr(args, "confirm_rounds", 0):
        ov["confirm_rounds"] = int(args.confirm_rounds)
    if ov:
        scfg = deep_merge(scfg, ov)
    cfg = deep_merge(cfg, {"scan": scfg})

    targets = load_targets(Path(args.targets) if args.targets
                           else (BASE_DIR / cfg["targets_file"]), args.only,
                           max_expand=int(getattr(args, "max_expand",
                                                  MAX_EXPAND_PER_TOKEN) or MAX_EXPAND_PER_TOKEN))
    ports = build_ports(args.mode, args.ports, cfg)
    label = sanitize_label(args.label or cfg.get("baseline_label", "default"))

    # 预检模式: 只测网络与链路能力, 不扫描真实业务端口
    if getattr(args, "preflight", False):
        return await preflight(cfg, targets)

    # 定向复核模式: 只复核「历史期望有、上一轮没扫到」的端口, 并带对照
    if getattr(args, "verify", False):
        return await verify_missing(
            cfg,
            prev_label=(getattr(args, "verify_from", "") or "default"),
            rounds=max(1, int(getattr(args, "verify_rounds", 5) or 5)),
            delay=max(0.0, float(getattr(args, "verify_delay", 2.0) or 0.0)))

    # 从中间态快照重建: 主扫描成果已在磁盘上, 只补做确认/指纹/出报告
    _ck = getattr(args, "from_checkpoint", "") or ""
    if _ck:
        _rdir = BASE_DIR / cfg["report"]["dir"]
        _cp = find_checkpoint(_rdir, _ck)
        if _cp is None:
            print("[!] 没找到中间态快照。请确认 %s 下存在 _checkpoint_*.json" % _rdir)
            print("    (快照只在主扫描跑完、且流程尚未跑完时存在; 正常扫完的会已自动清理)")
            return 2
        return await rebuild_from_checkpoint(cfg, _cp)

    print("=" * 78)
    print("  GuvianEye 公网暴露面巡检  v%s" % __version__)
    print("=" * 78)
    print("  目标主机   : %d 台" % len(targets))
    print("  端口范围   : %s  (%d 个)" % (
        args.ports or (args.mode or cfg["ports"].get("mode", "all")), len(ports)))
    print("  基线标签   : %s   (基线文件 %s)"
          % (label, baseline_path(BASE_DIR / cfg["report"]["baseline_dir"],
                                  label).name))
    print("  探测总量   : %s 次 TCP connect" % format(len(targets) * len(ports), ","))
    _ph = max(32, min(768, int(cfg["scan"]["concurrency"]) // max(1, len(targets))))
    print("  并发       : 全局 %d  /  单主机 %d" % (_ph * len(targets), _ph))
    print("  最大超时   : %.2fs    开放二次确认: %s(%d轮)    自适应超时: %s" % (
        float(cfg["scan"]["connect_timeout"]),
        "开" if cfg["scan"]["confirm_open"] else "关",
        int(cfg["scan"].get("confirm_rounds", 2) or 1),
        "开" if cfg["scan"].get("adaptive_timeout", True) else "关"))
    _skip = bool((cfg.get("ui") or {}).get("skip_rescan"))
    _rs = int(cfg["scan"].get("rescan_filtered", 0) or 0)
    _rp = int(cfg["scan"].get("rescan_priority_rounds", 0) or 0)
    if _skip:
        print("  重点端口补扫: 已跳过 (本次勾选「跳过补扫」, 速度优先, 准确性下降)")
    else:
        print("  重点端口补扫: %s (%s)" % (
            ("开 %d+%d 轮" % (_rs, _rp)) if (_rs or _rp) else "关",
            "仅重点端口" if cfg["scan"].get("rescan_scope", "priority") == "priority"
            else "全部无响应端口"))
    _bs = int(cfg["scan"].get("batch_size", 0) or 0)
    if _bs and len(targets) > _bs:
        print("  分批执行   : 每批 %d 台, 批间冷却 %.0f 秒 (共 %d 批)"
              % (_bs, float(cfg["scan"].get("batch_gap", 60) or 0),
                 (len(targets) + _bs - 1) // _bs))
    _pr = int(cfg["scan"].get("post_rescan_rounds", 0) or 0)
    if _skip:
        print("  后置补扫   : 已跳过 (同上)")
    else:
        print("  后置补扫   : %s" % (
            ("开 %d 轮, 主扫描后先冷却 %.0f 秒再低速重探业务端口(%d 个)"
             % (_pr, float(cfg["scan"].get("post_rescan_delay", 90) or 0),
            len(POST_RESCAN_PORTS))) if _pr else
        "关 (弱网/被限速时会漏报 443 与高位业务端口, 建议开启)"))
    _exp = load_expected()
    if _exp:
        print("  历史清单   : 已加载 %d 台期望(历史基线), 扫描后自动对照" % len(_exp))
    print("-" * 78)

    if args.dry_run:
        print("[演练] 不发送任何报文, 流程与配置检查通过。")
        return 0

    try:
        res = await execute_scan(cfg, targets, ports, label)
    except Cancelled:
        print("\n[!] 扫描已中止")
        return 130

    doc, summary, s = res["doc"], res["summary"], res["doc"]["summary"]
    print("-" * 78)
    print("  扫描完成  耗时 %.1fs" % doc["elapsed_sec"])
    print("  开放端口合计 : %d   (严重 %d / 高 %d)"
          % (s["open_total"], s["critical_total"], s["high_total"]))
    print("  相对上周     : 新增 %d  消失 %d" % (s["new_ports"], s["gone_ports"]))
    print("  无开放端口   : %d 台 (其中 %d 台全程无响应, 可能离线或全端口被过滤)"
          % (s.get("no_open_hosts", 0), s.get("silent_hosts", 0)))
    if s["anomaly_hosts"]:
        print("  异常主机     : %d 台 (结果不可信, 需人工核对)" % s["anomaly_hosts"])
    q = doc.get("quality") or {}
    if q:
        print("  探测质量     : 开放 %d / 关闭 %d / 无响应 %d (%.0f%%)%s"
              % (q.get("open", 0), q.get("closed", 0), q.get("timeout", 0),
                 q.get("timeout_ratio", 0) * 100,
                 ("  | 本机侧异常 %d" % q["errno_total"]) if q.get("errno_total") else ""))
        if q.get("rescan_recovered"):
            print("  补扫挽回     : %d 个开放端口 (额外 %d 次探测)"
                  % (q["rescan_recovered"], q.get("rescan_probes", 0)))
        if q.get("post_rescan_recovered"):
            print("  后置补扫挽回 : %d 个开放端口 (额外 %d 次探测, %d 轮)"
                  % (q["post_rescan_recovered"], q.get("post_rescan_probes", 0),
                     q.get("post_rescan_rounds", 0)))
        if q.get("post_rescan_left"):
            print("  后置补扫后仍无响应: %d 个业务端口 (需换网络复核)"
                  % q["post_rescan_left"])
        if q.get("unconfirmed_total"):
            print("  存疑端口     : %d 个 (扫描命中但复核未过, 见报告)"
                  % q["unconfirmed_total"])
    ed = doc.get("expected_diff") or {}
    if ed:
        print("-" * 78)
        print("  历史清单对照(历史基线): 完全一致 %d 台 / 疑似漏报 %d 台(%d 端口) / "
              "新增 %d 处 / 无响应未核对 %d 台"
              % (ed.get("hit_hosts", 0), len(ed.get("missing") or []),
                 ed.get("missing_ports", 0), len(ed.get("extra") or []),
                 len(ed.get("not_scanned") or [])))
        for x in (ed.get("missing") or [])[:15]:
            print("       [疑似漏报] %-16s %-24s %s"
                  % (x["ip"], x["name"][:22], "/".join(map(str, x["ports"]))))
        for x in (ed.get("extra") or [])[:15]:
            print("       [新增    ] %-16s %-24s %s"
                  % (x["ip"], x["name"][:22], "/".join(map(str, x["ports"]))))
    print("-" * 78)
    if summary["new"]:
        print("  [!!] 本周新增开放端口:")
        for n in summary["new"][:40]:
            print("       %-16s %-6s %-14s %s"
                  % (n["ip"], n["port"], n.get("service", ""), n["risk"]))
        if len(summary["new"]) > 40:
            print("       ... 其余 %d 条见报告" % (len(summary["new"]) - 40))
        print("-" * 78)
    for w in res["warnings"]:
        print("  [!!] %s" % w)
    print("-" * 78)
    print("  报告 : %s" % (res["paths"]["html"] or res["paths"]["json"]))
    print("  CSV  : %s" % res["paths"]["csv"])
    print("  基线 : %s" % res["paths"]["baseline"])

    # 邮件
    want_mail = args.mail or (cfg["mail"].get("enabled") and not args.no_mail)
    if want_mail:
        only_changed = cfg["mail"].get("send_when_changed_only")
        if only_changed and not (summary["new"] or summary["gone"] or summary["new_hosts"]):
            print("  [邮件] 本周无变化, 按配置跳过发送")
        else:
            try:
                import notify
                notify.send(cfg["mail"], doc, summary,
                            res["paths"]["html"] or None, res["paths"]["csv"])
                print("  [邮件] 已发送至 %s" % ", ".join(cfg["mail"]["recipients"]))
            except Exception as exc:
                lines = str(exc).splitlines() or [str(exc)]
                print("  [!] 邮件发送失败: %s" % lines[0])
                for ln in lines[1:]:
                    print("      %s" % ln.strip())
                print("      (报告与基线已正常落盘, 可手动发送)")
                return 3

    return res["exit_code"]


def _console_log(msg: str = "") -> None:
    """重建流程用的简单日志: 带时间戳直接打到终端并落 console.log。"""
    line = "%s  %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
        with open(BASE_DIR / "logs" / "console.log", "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def find_checkpoint(report_dir: Path, which: str = "latest") -> Path:
    """定位中间态快照。which='latest' 取最新一份, 否则按文件名/IP 部分匹配。"""
    if not report_dir.exists():
        return None
    files = sorted(report_dir.glob("_checkpoint_*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    if which in ("", "latest"):
        return files[0]
    for f in files:
        if which == f.name or which in f.name:
            return f
    return None


async def rebuild_from_checkpoint(cfg: dict, ckpt_path: Path) -> dict:
    """从中间态快照重建完整报告 —— 用于主扫描跑完后流程中断的场景。

    快照里已经包含主扫描的全部成果(主机、开放端口、探测统计), 这里只补做
    「二次确认 + 服务指纹 + 基线 diff + 出报告」这几步轻量工作。因为不再需要
    重扫 65535 个端口, 整个过程通常只要几十秒到几分钟。
    """
    data = json.loads(ckpt_path.read_text(encoding="utf-8"))
    scfg = cfg["scan"]
    label = sanitize_label(data.get("scan_label") or "default")
    results = data.get("hosts") or []
    status_map = data.get("status_map") or {}
    rtt_map = data.get("rtt_map") or {}
    saved_probes = data.get("probe_stats") or {}
    t0 = time.time()

    log = _console_log
    log("=" * 70)
    log("  从中间态快照重建报告")
    log("=" * 70)
    log("  快照文件 : %s" % ckpt_path.name)
    log("  存档时间 : %s" % data.get("saved_at", "?"))
    log("  基线标签 : %s" % label)
    log("  主机 %d 台  |  已扫端口 %d 个  |  已发现开放 %d 个"
        % (len(results), int(data.get("ports_scanned", 0)),
           sum(len(h.get("open_ports") or []) for h in results)))
    src_ips = {"local": data.get("source_local_ip", ""),
               "public": data.get("source_public_ip", "")}
    if src_ips["public"] or src_ips["local"]:
        log("  执行网络 : 本机 %s ｜ 出口 %s" % (src_ips["local"] or "?", src_ips["public"] or "?"))

    # ---- 二次确认 + 指纹(与正常流程一致, 只是数据来自快照) ----
    confirm_rounds = max(1, int(scfg.get("confirm_rounds", 2) or 1))
    per_host = max(32, min(768, int(scfg["concurrency"]) // max(1, len(results))))
    base_timeout = float(scfg["connect_timeout"])
    threshold = int(scfg.get("anomaly_threshold", 500))
    log("[1/3] 开放端口二次确认(%d 轮表决) ..." % confirm_rounds)
    for host in results:
        ip = host["ip"]
        abnormal = len(host.get("open_ports") or []) >= threshold
        if abnormal:
            host["anomaly"] = (
                "该主机返回开放端口数达 %d 个, 超过阈值 %d, "
                "极可能是运营商安全墙 / 负载设备对全部端口统一应答, 结果不可信"
                % (len(host["open_ports"]), threshold))
        if scfg.get("confirm_open") and host.get("open_ports") and not abnormal:
            confirmed, dropped, _hits = await confirm_ports(
                ip, host["open_ports"], max(1.5, base_timeout * 1.5), per_host,
                rounds=confirm_rounds)
            host["unconfirmed_ports"] = dropped
            host["open_ports"] = confirmed
        else:
            host.setdefault("unconfirmed_ports", [])

    log("[2/3] 服务指纹 ...")
    fp_jobs = []
    if scfg.get("banner_grab"):
        for host in results:
            if host.get("anomaly"):
                continue
            for p in host.get("open_ports") or []:
                if not p.get("banner"):
                    fp_jobs.append((host, p))
    if fp_jobs:
        bt = float(scfg["banner_timeout"])
        tls_on = bool(scfg.get("tls_grab", True))
        fps = await asyncio.gather(
            *[fingerprint(h["ip"], p["port"], bt, tls_on) for h, p in fp_jobs],
            return_exceptions=True)
        for (host, p), fp in zip(fp_jobs, fps):
            if isinstance(fp, BaseException):
                continue
            p["banner"] = fp.get("banner", "")
            p["tls"] = fp.get("tls", {})
            p["http"] = fp.get("http", {})
            p["product"] = fp.get("product", "")

    for host in results:
        host["discovery"] = "up" if host.get("open_ports") else status_map.get(host["ip"], "")
        host["rtt_ms"] = round(rtt_map.get(host["ip"], 0.0), 1)
    results.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))

    log("[3/3] 生成报告与基线 ...")
    baseline_dir = BASE_DIR / cfg["report"]["baseline_dir"]
    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline = load_baseline(baseline_dir, label)
    prev_scope = baseline.get("ports_scanned", -1) if baseline else -1
    scope_changed = bool(baseline) and int(prev_scope) != int(data.get("ports_scanned", 0))
    if scope_changed:
        for h in results:
            h["diff"] = "unknown"
        summary = {"new": [], "gone": [], "new_hosts": [], "quiet_hosts": [],
                   "scope_changed": True}
    else:
        summary = diff_against(results, baseline)

    ts = datetime.now()
    unreachable = [h["ip"] for h in results if h.get("discovery") != "up"]
    unreach_ratio = (len(unreachable) / len(results)) if results else 0.0
    expected = load_expected()
    exp_diff = expected_diff(results, expected) if expected else {}

    probe_stats = dict(saved_probes)
    errno_items = {k: v for k, v in probe_stats.items() if k.startswith("errno:")}
    total_probes_done = sum(probe_stats.values()) or 1
    quality = {
        "probes_total": total_probes_done,
        "open": int(probe_stats.get("open", 0)),
        "closed": int(probe_stats.get("closed", 0)),
        "timeout": int(probe_stats.get("timeout", 0)),
        "errno": errno_items,
        "errno_total": sum(errno_items.values()),
        "timeout_ratio": round(probe_stats.get("timeout", 0) / total_probes_done, 4),
        "rescan_recovered": sum(int(h.get("rescan_recovered", 0)) for h in results),
        "rescan_probes": sum(int(h.get("rescan_probes", 0)) for h in results),
        "post_rescan_recovered": 0, "post_rescan_probes": 0,
        "post_rescan_rounds": 0, "post_rescan_left": 0,
        "rebuilt_from_checkpoint": True,
        "checkpoint_saved_at": data.get("saved_at", ""),
        "unconfirmed_total": sum(len(h.get("unconfirmed_ports") or []) for h in results),
    }
    local_side_suspect = any(k in ("errno:22", "errno:10022", "errno:10048",
                                   "errno:10055", "errno:24") for k in errno_items)
    doc = {
        "scan_time": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_sec": round(float(data.get("elapsed_sec", 0.0)), 1),
        "hosts_total": len(results),
        "ports_scanned": int(data.get("ports_scanned", 0)),
        "probes": int(data.get("probes", 0)),
        "scan_label": label,
        "source_local_ip": src_ips.get("local", ""),
        "source_public_ip": src_ips.get("public", ""),
        "unreachable_ratio": round(unreach_ratio, 3),
        "hosts": results,
        "probe_stats": probe_stats,
        "quality": quality,
        "expected_diff": exp_diff,
        "baseline_time": baseline.get("scan_time", ""),
        "scope_changed": scope_changed,
        "rebuilt_from_checkpoint": True,
        "summary": {
            "open_total": sum(len(h.get("open_ports") or []) for h in results),
            "critical_total": sum(1 for h in results for p in (h.get("open_ports") or [])
                                  if p["risk"] == "CRITICAL"),
            "high_total": sum(1 for h in results for p in (h.get("open_ports") or [])
                              if p["risk"] == "HIGH"),
            "new_ports": len(summary["new"]),
            "gone_ports": len(summary["gone"]),
            "new_hosts": len(summary["new_hosts"]),
            "anomaly_hosts": sum(1 for h in results if h.get("anomaly")),
            "silent_hosts": sum(1 for h in results if h.get("discovery") != "up"),
            "no_open_hosts": sum(1 for h in results if not (h.get("open_ports") or [])),
        },
    }

    warnings = ["★ 这份报告来自中间态快照(%s), 不是完整流程的产物。" % ckpt_path.name,
                "  主扫描已完成并落盘, 但后置补扫阶段未跑完 —— 因此「全局后置补扫挽回」"
                "一栏恒为 0, 且可能存在因限速而未扫出的端口。若需要更完整的结论, "
                "建议在网络空闲时用更低并发重扫一次。"]
    if unreach_ratio >= float(scfg.get("unreachable_warn_ratio", 0.35)) and results:
        warnings.append(
            "本次 %d/%d 台主机完全无响应(占 %.0f%%)。本工具无法区分「目标确实离线」"
            "与「你当前的执行网络被策略阻断」两种情况, 请务必人工确认。"
            % (len(unreachable), len(results), unreach_ratio * 100))
    if scope_changed:
        warnings.append("端口范围与上次基线不一致, 本次已跳过周度变化对比。")
    if quality["rescan_recovered"]:
        warnings.append(
            "重点端口补扫额外挽回了 %d 个开放端口 —— 说明主扫描确实漏报了它们, "
            "建议下调 scan.concurrency(如 800) 后重扫。" % quality["rescan_recovered"])
    if local_side_suspect:
        warnings.append("探测过程中出现本机侧异常(%s), 建议降低并发后重扫。"
                        % ", ".join(sorted(errno_items)))
    if quality["unconfirmed_total"]:
        warnings.append("有 %d 个端口二次确认未通过, 已列为「存疑端口」保留在报告中。"
                        % quality["unconfirmed_total"])

    report_dir = BASE_DIR / cfg["report"]["dir"]
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = "rebuilt_" + ts.strftime("%Y%m%d_%H%M%S")
    json_out = report_dir / ("scan_%s.json" % stamp)
    json_out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    csv_out = report_dir / ("scan_%s.csv" % stamp)
    write_csv(csv_out, doc)
    html_out = report_dir / ("report_%s.html" % stamp)
    try:
        import reporter
        chart_history = load_history(baseline_dir) + [make_history_entry(doc)]
        reporter.render(doc, summary, html_out, cfg["report"].get("title", ""), chart_history)
        doc["report_file"] = html_out.name
    except Exception as exc:
        log("      [!] HTML 报告生成失败: %s" % exc)
        html_out = None
        doc["report_file"] = ""

    payload = json.dumps(doc, ensure_ascii=False, indent=2)
    bpath = baseline_path(baseline_dir, label)
    bpath.write_text(payload, encoding="utf-8")
    dated = ts.strftime("%Y-%m-%d") + ("" if label == "default" else "_" + label)
    (baseline_dir / ("%s.json" % dated)).write_text(payload, encoding="utf-8")
    append_history(baseline_dir, doc)
    try:  # 快照已完成使命, 但改名保留一份, 避免手滑删掉后无从追溯
        ckpt_path.rename(ckpt_path.with_suffix(".done.json"))
    except OSError:
        pass

    log("-" * 70)
    log("  重建完成  用时 %.1fs" % (time.time() - t0))
    log("  开放端口合计 : %d" % doc["summary"]["open_total"])
    log("  报告 : %s" % (html_out or json_out))
    log("  CSV  : %s" % csv_out)
    log("-" * 70)
    return {"ok": True, "cancelled": False, "doc": doc, "summary": summary,
            "warnings": warnings,
            "paths": {"json": str(json_out), "csv": str(csv_out),
                      "html": str(html_out) if html_out else "",
                      "baseline": str(bpath)},
            "exit_code": 0}


def write_csv(path: Path, doc: dict) -> None:
    import csv as _csv
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = _csv.writer(f)
        w.writerow(["IP", "端口", "服务", "风险等级", "是否本周新增", "协议/横幅",
                    "HTTP Server", "页面标题", "TLS版本", "证书SHA256", "证书主体"])
        for h in doc["hosts"]:
            if not h["open_ports"]:
                w.writerow([h["ip"], "", "", "", "", "（无开放端口）", "", "", "", "", ""])
                continue
            for p in h["open_ports"]:
                tls = p.get("tls") or {}
                http = p.get("http") or {}
                w.writerow([
                    h["ip"], p["port"], p.get("service", ""), p.get("risk", ""),
                    "是" if p.get("is_new") else "",
                    (p.get("banner") or "")[:300],
                    http.get("server", ""), http.get("title", ""),
                    tls.get("tls_version", ""), tls.get("cert_sha256", ""),
                    tls.get("subject", ""),
                ])


def main() -> int:
    ap = argparse.ArgumentParser(
        description="GuvianEye 公网暴露面巡检 (Public Exposure Scanner)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python scanner.py --preflight            ★换网络后先跑: 网络预检+推荐参数\n"
               "  python scanner.py --label mobile --mail  从手机热点执行全量扫描\n"
               "  python scanner.py --mode common          快速模式(约600端口)\n"
               "  python scanner.py --only 1.2.3.4         仅扫指定 IP\n"
               "  python scanner.py --ports 1-1024,3306,6379\n"
               "  python scanner.py --concurrency 1200 --batch-size 8\n"
               "  python scanner.py --dry-run              只演练不发包\n")
    ap.add_argument("--config", default=str(BASE_DIR / "config.json"))
    ap.add_argument("--targets", default="")
    ap.add_argument("--ports", default="", help="端口表达式, 如 1-1024,3306,6379")
    ap.add_argument("--mode", default="", choices=["", "all", "common", "web", "custom"])
    ap.add_argument("--only", default="", help="仅扫描指定 IP, 逗号分隔")
    ap.add_argument("--max-expand", type=int, default=MAX_EXPAND_PER_TOKEN,
                    help="单条网段/区间表达式最多展开多少个地址(默认 %d)。"
                         "防止手滑写 /8 当场生成上千万目标。" % MAX_EXPAND_PER_TOKEN)
    ap.add_argument("--preflight", action="store_true",
                    help="★ 网络预检: 只测可达性/RTT/链路承载能力并推荐参数, "
                         "不扫描真实业务端口。换网络后必须先跑这一步")
    ap.add_argument("--verify", action="store_true",
                    help="★ 定向复核: 只复核「历史基线清单有、上一轮没扫到」的端口, "
                         "并同时探测该主机已知开放的端口作对照, 判定是真关闭还是漏报")
    ap.add_argument("--verify-from", default="",
                    help="定向复核的对照基线标签(上一轮用哪个标签扫的就填哪个, 如 jumphost)")
    ap.add_argument("--verify-rounds", type=int, default=5,
                    help="定向复核轮数(默认 5; 轮数越多越能识破间歇性限速)")
    ap.add_argument("--verify-delay", type=float, default=2.0,
                    help="定向复核轮间隔秒数(默认 2.0)")
    ap.add_argument("--concurrency", type=int, default=0,
                    help="运行时覆盖全局并发(优先级高于 config.json)")
    ap.add_argument("--timeout", type=float, default=0.0,
                    help="运行时覆盖连接超时秒数")
    ap.add_argument("--batch-size", type=int, default=-1,
                    help="运行时覆盖分批大小; 0=不分批")
    ap.add_argument("--batch-gap", type=float, default=-1,
                    help="运行时覆盖批间冷却秒数")
    ap.add_argument("--post-delay", type=float, default=-1,
                    help="运行时覆盖后置补扫前的冷却秒数(默认 90)")
    ap.add_argument("--post-rounds", type=int, default=-1,
                    help="运行时覆盖后置补扫轮数; 0=关闭")
    ap.add_argument("--confirm-rounds", type=int, default=0,
                    help="运行时覆盖开放端口二次确认轮数(默认 2)")
    ap.add_argument("--label", default="",
                    help="基线标签, 按「执行网络」分档(如 office / jumphost / mobile)。"
                         "不同网络下可达性不同, 混用会产生虚假的新增/消失")
    ap.add_argument("--mail", action="store_true", help="扫描完成后发送邮件")
    ap.add_argument("--no-mail", action="store_true", help="强制不发邮件")
    ap.add_argument("--turbo", action="store_true",
                    help="极速模式: 更高并发 + 更短超时(网络稳定时最快)")
    ap.add_argument("--safe", action="store_true",
                    help="保守模式: 关闭自适应超时, 全部主机用最大超时")
    ap.add_argument("--dry-run", action="store_true", help="只演练不发包")
    ap.add_argument("--from-checkpoint", default="",
                    help="从中间态快照(_checkpoint_*.json)重建报告, 不重新扫描。"
                         "传文件名或 'latest' 自动找最新的一份。")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] 已被用户中断")
        return 130


if __name__ == "__main__":
    sys.exit(main())
