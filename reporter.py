# -*- coding: utf-8 -*-
"""
HTML 报告渲染器 (v2)
================================================================
在 v1 基础上补齐四件事:
  1. 领导版一页摘要 —— 顶部直接给结论与待处置事项, 可一键切换到「简报模式」
  2. 周度趋势图     —— 内联 SVG 折线, 展示开放端口总数的逐周变化
  3. 高危端口处置建议 —— 内置知识库, 每个高危端口给具体动作
  4. 视觉排版升级   —— 重做层次、配色与留白

报告为单文件自包含(内嵌 CSS/JS/SVG), 不联网也能正常打开。
"""

from __future__ import annotations

import html
import json
from pathlib import Path

RISK_LABEL = {"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低"}
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# --------------------------------------------------------------------------
# 高危端口处置建议知识库: 端口 -> (处置动作, 风险说明)
# --------------------------------------------------------------------------
REMEDIATION = {
    21: ("关闭公网 FTP，或改用 SFTP", "FTP 明文传输凭证，且常被用于匿名上传与爆破"),
    22: ("限制源 IP 白名单，禁用密码登录改密钥", "公网 SSH 是爆破首要目标，建议只放行运维网段"),
    23: ("立即关闭", "Telnet 全程明文，凭证可被直接嗅探"),
    25: ("关闭对外中继，仅允许内网", "开放中继会导致垃圾邮件，并损害 IP 信誉"),
    110: ("关闭或限制源 IP", "POP3 明文暴露，邮箱凭证可被嗅探"),
    135: ("关闭公网暴露", "MSRPC 是永恒之蓝类漏洞的主要入口"),
    137: ("关闭公网暴露", "NetBIOS 名称服务可泄露主机名与域信息"),
    138: ("关闭公网暴露", "NetBIOS 数据报服务，可被用于信息收集"),
    139: ("关闭公网暴露", "NetBIOS 会话服务，横向移动入口"),
    143: ("关闭或限制源 IP", "IMAP 明文暴露，凭证可被嗅探"),
    161: ("关闭开放，或升级为 SNMPv3", "默认团体名 public 可读取设备全部配置"),
    389: ("关闭公网暴露", "LDAP 可匿名查询目录结构，泄露账号信息"),
    443: ("确认是否为对外业务所需", "HTTPS 通常需暴露，但应核查证书有效性与 TLS 版本"),
    445: ("立即关闭公网暴露", "SMB 是勒索软件传播的头号通道（永恒之蓝 / 永恒浪漫）"),
    465: ("关闭或限制源 IP", "邮件提交端口，开放可被用于发信滥用"),
    587: ("关闭或限制源 IP", "邮件提交端口，开放可被用于发信滥用"),
    623: ("关闭公网暴露", "IPMI 存在大量高危漏洞，且常为弱口令"),
    636: ("关闭或限制源 IP", "LDAPS 对外暴露会扩大目录服务攻击面"),
    873: ("立即关闭，或加认证", "Rsync 无认证即可同步整站文件"),
    1433: ("立即关闭公网暴露", "MSSQL 可被爆破，sa 弱口令直接接管数据库"),
    1434: ("关闭公网暴露", "SQL Server 浏览器服务会泄露实例信息"),
    1521: ("立即关闭公网暴露", "Oracle 监听器可被爆破，历史漏洞多"),
    1723: ("关闭公网暴露", "PPTP 已被证明不安全，凭证可被破解"),
    2049: ("立即关闭", "NFS 无认证挂载，可直接读取服务器文件"),
    2181: ("立即关闭", "ZooKeeper 未授权可读取全部节点数据，甚至执行命令"),
    2375: ("立即关闭", "Docker API 未授权 = 直接获取宿主机 root 权限"),
    2376: ("限制源 IP 并启用证书认证", "Docker TLS API 仍是高危管理面"),
    2379: ("立即关闭", "etcd 未授权可读取集群全部密钥与配置"),
    3306: ("立即关闭公网暴露，或限制源 IP", "MySQL 可被爆破，建议只允许应用服务器访问"),
    3389: ("收敛到 VPN 后访问", "RDP 是勒索软件入侵第一入口，务必关闭公网直接暴露"),
    5432: ("立即关闭公网暴露", "PostgreSQL 可被爆破，且存在 trust 认证风险"),
    5555: ("立即关闭", "ADB 未授权可直接在设备上执行命令"),
    5601: ("关闭或加认证", "Kibana 未授权可读取全部日志与索引"),
    5672: ("限制源 IP 并改默认口令", "RabbitMQ 弱口令可被用于消息投毒"),
    5900: ("立即关闭", "VNC 常为无认证或弱口令，可直接接管桌面"),
    5984: ("立即关闭或加认证", "CouchDB 未授权可读写全部数据库"),
    5985: ("关闭公网暴露", "WinRM HTTP 明文，且可直接远程执行命令"),
    5986: ("限制源 IP", "WinRM HTTPS 仍是高危远程管理通道"),
    6379: ("立即关闭公网暴露", "Redis 未授权 = 可直接写 SSH 公钥获取服务器权限"),
    6443: ("立即关闭", "Kubernetes API 未授权可完全接管集群"),
    7001: ("升级 Weblogic 并打补丁", "反序列化漏洞历史极多，公网暴露风险极高"),
    8009: ("关闭 AJP，或配置 secret", "Tomcat AJP Ghostcat 漏洞可读取任意文件"),
    8080: ("确认业务必要性，务必加认证", "常为管理后台或中间件默认页，无认证即可操作"),
    8161: ("关闭或加认证", "ActiveMQ 管理台弱口令可被利用"),
    8443: ("确认业务必要性", "备用 HTTPS 端口，常被用于暴露管理后台"),
    8500: ("立即关闭", "Consul 未授权可读取全部服务注册信息与 KV 配置"),
    8888: ("确认业务必要性并加认证", "常见于宝塔面板 / Jupyter，弱口令即可接管"),
    9000: ("确认业务必要性", "常见于 FastCGI / PHP-FPM，配置不当可导致 RCE"),
    9042: ("立即关闭", "Cassandra 未授权可读写全部数据"),
    9200: ("立即关闭公网暴露", "Elasticsearch 未授权可读取全部索引（数据泄露重灾区）"),
    9300: ("立即关闭", "ES 集群传输端口，暴露可被拉入集群"),
    10000: ("立即关闭公网暴露", "Webmin 可被爆破，历史 RCE 漏洞多"),
    10250: ("立即关闭", "Kubelet API 未授权可在容器内执行命令"),
    11211: ("立即关闭公网暴露", "Memcached 未授权可读缓存，且可被用于放大攻击"),
    15672: ("关闭或加认证", "RabbitMQ 管理后台弱口令可直接操作消息队列"),
    27017: ("立即关闭公网暴露", "MongoDB 未授权访问是数据泄露的头号来源"),
    27018: ("立即关闭公网暴露", "MongoDB 副本集端口，同样存在未授权风险"),
    50070: ("立即关闭", "HDFS NameNode 未授权可浏览并下载全部文件"),
}

GENERIC_REMEDIATION = {
    "CRITICAL": ("建议立即关闭公网暴露，或限制为白名单源 IP",
                 "该端口属于可直接导致数据泄露或主机接管的高危服务"),
    "HIGH": ("建议收敛到内网 / VPN，或限制源 IP 白名单",
             "该端口属于应严格限制暴露的高风险服务"),
    "MEDIUM": ("确认业务必要性，不需要则关闭", "系统级服务端口，非必要不应暴露在公网"),
    "LOW": ("确认业务必要性", "非常规高位端口，建议核实用途"),
}


def remediation_of(port: int, risk: str) -> tuple:
    if port in REMEDIATION:
        return REMEDIATION[port]
    return GENERIC_REMEDIATION.get(risk, GENERIC_REMEDIATION["LOW"])


# --------------------------------------------------------------------------
# 样式
# --------------------------------------------------------------------------
CSS = """
:root{
  --bg:#f2f5f9; --card:#fff; --line:#dde5ee; --line2:#eef3f8;
  --txt:#111c2b; --txt2:#3d4d5e; --muted:#6b7b8d;
  --accent:#0b5fa5; --accent2:#1478c9; --accent-soft:#e9f2fb;
  --red:#cf2b1f; --red-soft:#fdecea; --red-line:#f3b7b1;
  --org:#c26a02; --org-soft:#fff4e6; --org-line:#f2cd9b;
  --grn:#0a7a4a; --grn-soft:#e8f7ef; --grn-line:#b8e3cc;
  --blu:#1468cc; --blu-soft:#eaf2ff;
  --shadow:0 1px 3px rgba(16,32,48,.05),0 8px 24px -18px rgba(16,32,48,.22);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--txt);
 font-family:"Microsoft YaHei","PingFang SC","Hiragino Sans GB","Segoe UI",Roboto,Arial,sans-serif;
 font-size:13.5px;line-height:1.65;-webkit-font-smoothing:antialiased}
.wrap{max-width:1440px;margin:0 auto;padding:24px 22px 64px}
a{color:var(--accent)}

header{background:linear-gradient(118deg,#08345c 0%,#0b5fa5 52%,#1a86cf 100%);
 color:#fff;border-radius:14px;padding:26px 30px;position:relative;overflow:hidden;
 box-shadow:0 10px 30px -12px rgba(8,52,92,.5)}
header::after{content:"";position:absolute;right:-70px;top:-90px;width:280px;height:280px;
 border-radius:50%;background:rgba(255,255,255,.07)}
header::before{content:"";position:absolute;right:60px;bottom:-120px;width:200px;height:200px;
 border-radius:50%;background:rgba(255,255,255,.05)}
header h1{margin:0 0 10px;font-size:22px;letter-spacing:.6px;font-weight:700;position:relative}
header .meta{font-size:12.5px;opacity:.93;position:relative;line-height:2}
header .meta b{font-weight:600}
header .meta span.sep{opacity:.4;margin:0 7px}
.badge{display:inline-block;padding:3px 11px;border-radius:20px;font-size:11.5px;
 margin-left:10px;background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.32);
 vertical-align:3px;font-weight:500}

section.box{background:var(--card);border:1px solid var(--line);border-radius:12px;
 padding:18px 20px;margin-bottom:16px;box-shadow:var(--shadow)}
section.box>h2{margin:0 0 14px;font-size:15px;display:flex;align-items:center;gap:9px;
 font-weight:700;letter-spacing:.3px}
section.box>h2::before{content:"";width:3px;height:15px;border-radius:2px;
 background:linear-gradient(180deg,var(--accent2),var(--accent));flex:none}
section.box>h2 .cnt{font-size:12px;font-weight:400;color:var(--muted);margin-left:auto}

.brief{background:linear-gradient(180deg,#fbfdff,#f5f9fd);border:1px solid #cfe0f0}
.verdict{display:flex;gap:14px;align-items:flex-start;padding:15px 18px;border-radius:10px;
 margin-bottom:14px;border-left:4px solid}
.verdict.bad{background:var(--red-soft);border-color:var(--red)}
.verdict.warn{background:var(--org-soft);border-color:var(--org)}
.verdict.ok{background:var(--grn-soft);border-color:var(--grn)}
.verdict .ico{font-size:20px;line-height:1.2;flex:none}
.verdict .t{font-size:15.5px;font-weight:700;margin-bottom:5px}
.verdict .d{font-size:13px;color:var(--txt2)}
.bullets{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.bullet{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.bullet .bk{font-size:12px;color:var(--muted);margin-bottom:5px}
.bullet .bv{font-size:14.5px;font-weight:700;line-height:1.5}
.bullet .bd{font-size:12px;color:var(--muted);margin-top:4px}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:15px 17px;
 box-shadow:var(--shadow);position:relative;overflow:hidden}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#cbd8e6}
.card.c-red::before{background:var(--red)} .card.c-org::before{background:var(--org)}
.card.c-grn::before{background:var(--grn)} .card.c-blu::before{background:var(--blu)}
.card.c-acc::before{background:var(--accent2)}
.card .k{font-size:12px;color:var(--muted);margin-bottom:7px}
.card .v{font-size:26px;font-weight:800;line-height:1.1;font-variant-numeric:tabular-nums;
 letter-spacing:-.5px}
.card .s{font-size:11.5px;color:var(--muted);margin-top:5px}
.card.c-red .v{color:var(--red)} .card.c-org .v{color:var(--org)}
.card.c-grn .v{color:var(--grn)} .card.c-blu .v{color:var(--blu)}

.alert{border-radius:10px;padding:13px 16px;margin-bottom:11px;border-left:4px solid;
 font-size:13px;line-height:1.75}
.alert:last-child{margin-bottom:0}
.alert.warn{background:var(--org-soft);border-color:var(--org)}
.alert.bad{background:var(--red-soft);border-color:var(--red)}
.alert.ok{background:var(--grn-soft);border-color:var(--grn)}
.alert.info{background:var(--blu-soft);border-color:var(--blu)}
.alert b{font-weight:700}
.alert code{background:rgba(0,0,0,.06);padding:1px 5px;border-radius:4px;
 font-family:Consolas,Monaco,monospace;font-size:12px}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}
.chip{background:#fff;border:1px solid var(--line);border-radius:6px;padding:3px 9px;
 font-size:12px;font-family:Consolas,Monaco,monospace}
.chip.new{border-color:var(--red-line);background:var(--red-soft);color:#8f1d13;font-weight:600}
.chip.gone{border-color:var(--grn-line);background:var(--grn-soft);color:#04522f}

.trend-wrap{width:100%;overflow-x:auto}
.trend-empty{padding:34px;text-align:center;color:var(--muted);font-size:13px;
 background:#fafcfe;border:1px dashed var(--line);border-radius:10px}
svg .ax{font-size:11px;fill:#8a99aa;font-family:Consolas,Monaco,monospace}
svg .pt-lbl{font-size:11.5px;font-weight:700;fill:#0b5fa5}
svg .xl{font-size:11px;fill:#8a99aa}

.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:12px}
.toolbar input[type=text]{flex:1;min-width:200px;padding:8px 12px;border:1px solid var(--line);
 border-radius:8px;font-size:13px;outline:none;background:#fff;font-family:inherit;color:var(--txt)}
.toolbar input[type=text]:focus{border-color:var(--accent2);box-shadow:0 0 0 3px rgba(20,120,201,.12)}
.seg{display:flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff}
.seg button{border:0;background:transparent;padding:8px 14px;font-size:12.5px;cursor:pointer;
 color:var(--muted);border-right:1px solid var(--line);font-family:inherit;transition:.12s}
.seg button:last-child{border-right:0}
.seg button:hover{background:#f6f9fc}
.seg button.on{background:var(--accent);color:#fff;font-weight:600}
.tbl-scroll{max-height:660px;overflow:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{background:#f6f9fc;text-align:left;padding:10px 11px;font-weight:700;color:var(--txt2);
 border-bottom:2px solid var(--line);position:sticky;top:0;z-index:2;white-space:nowrap}
td{padding:9px 11px;border-bottom:1px solid var(--line2);vertical-align:top}
tbody tr:nth-child(even){background:#fcfdfe}
tbody tr:hover{background:#f3f8fd}
tbody tr.row-new{background:var(--red-soft)}
tbody tr.row-new:hover{background:#fbe4e0}
td.mono,th.mono{font-family:Consolas,Monaco,"Courier New",monospace;font-size:12px}
.ip{font-weight:700;white-space:nowrap;font-family:Consolas,Monaco,monospace}
.pt{font-weight:800;font-size:13.5px;font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:1.5px 8px;border-radius:5px;font-size:11px;
 font-weight:700;white-space:nowrap}
.t-CRITICAL{background:var(--red-soft);color:#9c1f16;border:1px solid var(--red-line)}
.t-HIGH{background:var(--org-soft);color:#9a4a02;border:1px solid var(--org-line)}
.t-MEDIUM{background:var(--blu-soft);color:#124f9e;border:1px solid #c0d8f7}
.t-LOW{background:#f1f5f9;color:#556274;border:1px solid #dde4ec}
.t-new{background:var(--red);color:#fff;border:1px solid var(--red)}
.t-none{background:var(--grn-soft);color:#04522f;border:1px solid var(--grn-line)}
.bn{color:#4a5a6b;max-width:420px;overflow:hidden;text-overflow:ellipsis;
 white-space:nowrap;font-family:Consolas,Monaco,monospace;font-size:11.5px}
.fix{font-size:12px;color:var(--txt2);max-width:330px}
.fix b{color:var(--accent);display:block;font-size:12.5px;margin-bottom:2px}
.muted{color:var(--muted)}
.qtbl{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:6px;
  border:1px solid var(--line);border-radius:8px;overflow:hidden}
.qtbl td{padding:8px 12px;border-bottom:1px solid var(--line)}
.qtbl tr:last-child td{border-bottom:none}
.qtbl td:last-child{text-align:right;font-variant-numeric:tabular-nums}
.ctbl{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:6px;
  border:1px solid var(--line);border-radius:8px;overflow:hidden}
.ctbl td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;
  vertical-align:top}
.ctbl tr:last-child td{border-bottom:none}
.ctbl .chip{margin:0}
.hostbar{display:inline-block;height:10px;border-radius:5px;
 background:linear-gradient(90deg,var(--accent2),var(--accent));min-width:3px}
.empty{padding:30px;text-align:center;color:var(--grn);font-weight:600}
.legend{font-size:11.5px;color:var(--muted);margin-top:11px;line-height:1.8}

.rm-list{display:flex;flex-direction:column;gap:9px}
.rm{display:flex;gap:13px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;
 background:#fff;align-items:flex-start}
.rm.cri{border-left:4px solid var(--red);background:linear-gradient(90deg,#fff9f8,#fff)}
.rm.hig{border-left:4px solid var(--org);background:linear-gradient(90deg,#fffcf6,#fff)}
.rm .p{font-family:Consolas,Monaco,monospace;font-weight:800;font-size:14px;
 min-width:74px;flex:none;color:var(--txt)}
.rm .body{flex:1}
.rm .act{font-weight:700;font-size:13px;color:var(--txt);margin-bottom:3px}
.rm .why{font-size:12px;color:var(--muted)}
.rm .who{font-family:Consolas,Monaco,monospace;font-size:11.5px;color:var(--muted);
 max-width:230px;flex:none;text-align:right;word-break:break-all}

footer{margin-top:26px;color:var(--muted);font-size:11.5px;text-align:center;line-height:2}
.modebtn{position:fixed;right:20px;bottom:20px;z-index:99;background:var(--accent);color:#fff;
 border:0;border-radius:24px;padding:11px 20px;font-size:13px;cursor:pointer;font-family:inherit;
 box-shadow:0 6px 20px -6px rgba(11,95,165,.6);font-weight:600}
.modebtn:hover{background:#0a4f8a}

body.brief .full-only{display:none!important}
body.brief .wrap{max-width:1100px}

@media (max-width:860px){
  .wrap{padding:14px 12px 60px}
  header{padding:20px 18px} header h1{font-size:18px}
  .bn{max-width:150px} .cards{grid-template-columns:repeat(2,1fr)}
  .rm .who{display:none}
}
"""

JS = r"""
const DATA = __DATA__;
const RL={'CRITICAL':'严重','HIGH':'高','MEDIUM':'中','LOW':'低'};
const RO={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3};
let MODE='all', TAB='detail', Q='';

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

const ROWS=(()=>{
  const o=[];
  DATA.hosts.forEach(h=>{
    (h.open_ports||[]).forEach(p=>{
      o.push({ip:h.ip,port:p.port,service:p.service||'',risk:p.risk||'LOW',
        is_new:!!p.is_new,banner:p.banner||'',
        server:(p.http&&p.http.server)||'',title:(p.http&&p.http.title)||'',
        tls:(p.tls&&p.tls.tls_version)||'',cert:(p.tls&&p.tls.cert_sha256)||'',
        subject:(p.tls&&p.tls.subject)||'',anomaly:h.anomaly||'',
        fix:(DATA.fix[String(p.port)]||DATA.fix['_'+p.risk]||['确认业务必要性',''])});
    });
  });
  return o;
})();

function match(r){
  if(MODE==='new'&&!r.is_new)return false;
  if(MODE==='crit'&&r.risk!=='CRITICAL')return false;
  if(MODE==='high'&&!(r.risk==='CRITICAL'||r.risk==='HIGH'))return false;
  if(Q){const h=[r.ip,r.port,r.service,r.banner,r.server,r.title,r.subject,r.fix[0]]
    .join(' ').toLowerCase(); if(h.indexOf(Q)<0)return false;}
  return true;
}

function renderDetail(){
  const rows=ROWS.filter(match).sort((a,b)=>
    RO[a.risk]-RO[b.risk]||a.port-b.port||a.ip.localeCompare(b.ip));
  const body=document.getElementById('tbody');
  if(!rows.length){body.innerHTML='<tr><td colspan="8" class="empty">\u6ca1\u6709\u7b26\u5408\u6761\u4ef6\u7684\u8bb0\u5f55 \u2705</td></tr>';
    document.getElementById('cnt').textContent='\u5171 0 \u6761';return;}
  body.innerHTML=rows.map(r=>{
    const bn=r.banner?esc(r.banner):'<span class="muted">\u2014</span>';
    let ex=[];
    if(r.server)ex.push('Server: '+esc(r.server));
    if(r.title)ex.push('Title: '+esc(r.title));
    if(r.tls)ex.push('TLS '+esc(r.tls));
    if(r.subject)ex.push(esc(r.subject));
    const fp=ex.length?'<div class="bn">'+ex.join(' \u00b7 ')+'</div>':'';
    const an=r.anomaly?'<div class="bn" style="color:#c26a02">\u26a0 \u5f02\u5e38\u4e3b\u673a\uff08\u7ed3\u679c\u4e0d\u53ef\u4fe1\uff09</div>':'';
    return '<tr class="'+(r.is_new?'row-new':'')+'">'
      +'<td class="ip">'+esc(r.ip)+'</td>'
      +'<td class="pt">'+r.port+'</td>'
      +'<td>'+esc(r.service||'\u2014')+'</td>'
      +'<td><span class="tag t-'+r.risk+'">'+(RL[r.risk]||r.risk)+'</span></td>'
      +'<td>'+(r.is_new?'<span class="tag t-new">\u65b0\u589e</span>':'<span class="muted">\u2014</span>')+'</td>'
      +'<td><div class="bn">'+bn+'</div>'+fp+an+'</td>'
      +'<td class="fix"><b>'+esc(r.fix[0])+'</b>'+esc(r.fix[1])+'</td>'
      +'<td class="mono">'+esc(r.cert?r.cert.slice(0,14)+'\u2026':'')+'</td>'
      +'</tr>';
  }).join('');
  document.getElementById('cnt').textContent='\u5171 '+rows.length+' \u6761';
}

function renderSummary(){
  const hs=DATA.hosts.filter(h=>{
    if(!Q)return true;
    return [h.ip,(h.open_ports||[]).map(p=>p.port+' '+(p.service||'')).join(' ')]
      .join(' ').toLowerCase().indexOf(Q)>=0;});
  const body=document.getElementById('tbody');
  if(!hs.length){body.innerHTML='<tr><td colspan="10" class="empty">\u6ca1\u6709\u7b26\u5408\u6761\u4ef6\u7684\u4e3b\u673a \u2705</td></tr>';
    document.getElementById('cnt').textContent='\u5171 0 \u53f0';return;}
  const mx=Math.max(1,...hs.map(h=>(h.open_ports||[]).length));
  body.innerHTML=hs.map(h=>{
    const ps=h.open_ports||[];
    const crit=ps.filter(p=>p.risk==='CRITICAL').length;
    const high=ps.filter(p=>p.risk==='HIGH').length;
    const nw=ps.filter(p=>p.is_new).length;
    const list=ps.length?ps.map(p=>'<span class="chip'+(p.is_new?' new':'')+'">'+p.port
      +(p.service?'/'+esc(p.service):'')+'</span>').join(''):'<span class="muted">\u65e0\u5f00\u653e\u7aef\u53e3</span>';
    let flag='<span class="tag t-none">\u6b63\u5e38</span>';
    if(h.anomaly)flag='<span class="tag t-HIGH">\u5f02\u5e38</span>';
    else if(crit)flag='<span class="tag t-CRITICAL">\u4e25\u91cd '+crit+'</span>';
    else if(nw)flag='<span class="tag t-new">\u65b0\u589e '+nw+'</span>';
    else if(high)flag='<span class="tag t-HIGH">\u9ad8 '+high+'</span>';
    const reach=h.discovery==='up'?'<span style="color:#0a7a4a">\u5728\u7ebf</span>'
      :'<span style="color:#c26a02">\u65e0\u54cd\u5e94</span>';
    return '<tr class="'+(nw?'row-new':'')+'">'
      +'<td class="ip">'+esc(h.ip)+'</td>'
      +'<td>'+reach+'</td><td>'+flag+'</td>'
      +'<td class="pt">'+ps.length+'</td>'
      +'<td>'+(crit?('<b style="color:#cf2b1f">'+crit+'</b>'):'0')+'</td>'
      +'<td>'+(high||'0')+'</td>'
      +'<td>'+(nw?('<b style="color:#cf2b1f">'+nw+'</b>'):'0')+'</td>'
      +'<td><span class="hostbar" style="width:'+(ps.length/mx*100)+'px"></span></td>'
      +'<td colspan="2">'+list+'</td></tr>';
  }).join('');
  document.getElementById('cnt').textContent='\u5171 '+hs.length+' \u53f0';
}

function render(){
  if(TAB==='detail'){
    document.getElementById('thead').innerHTML=
      '<tr><th>IP \u5730\u5740</th><th>\u7aef\u53e3</th><th>\u670d\u52a1</th><th>\u98ce\u9669</th>'
      +'<th>\u5bf9\u6bd4\u4e0a\u5468</th><th>\u6a2a\u5e45 / \u6307\u7eb9</th>'
      +'<th>\u5904\u7f6e\u5efa\u8bae</th><th>\u8bc1\u4e66\u6307\u7eb9</th></tr>';
    renderDetail();
  }else{
    document.getElementById('thead').innerHTML=
      '<tr><th>IP \u5730\u5740</th><th>\u53ef\u8fbe\u6027</th><th>\u72b6\u6001</th>'
      +'<th>\u5f00\u653e\u6570</th><th>\u4e25\u91cd</th><th>\u9ad8\u5371</th>'
      +'<th>\u672c\u5468\u65b0\u589e</th><th>\u5360\u6bd4</th>'
      +'<th colspan="2">\u5f00\u653e\u7aef\u53e3</th></tr>';
    renderSummary();
  }
}
function setMode(m){MODE=m;document.querySelectorAll('#modebar button').forEach(b=>
  b.classList.toggle('on',b.dataset.m===m));render();}
function setTab(t){TAB=t;document.querySelectorAll('#tabbar button').forEach(b=>
  b.classList.toggle('on',b.dataset.t===t));render();}
function toggleBrief(){const b=document.body.classList.toggle('brief');
  const el=document.getElementById('briefbtn');
  if(el)el.textContent=b?'\u663e\u793a\u5b8c\u6574\u62a5\u544a':'\u5207\u6362\u7b80\u62a5\u6a21\u5f0f';}

document.addEventListener('DOMContentLoaded',()=>{
  const q=document.getElementById('q');
  if(q)q.addEventListener('input',e=>{Q=e.target.value.trim().toLowerCase();render();});
  document.querySelectorAll('#modebar button').forEach(b=>
    b.addEventListener('click',()=>setMode(b.dataset.m)));
  document.querySelectorAll('#tabbar button').forEach(b=>
    b.addEventListener('click',()=>setTab(b.dataset.t)));
  render();
});
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _chips(items, cls, limit=60):
    out = []
    for it in items[:limit]:
        out.append('<span class="chip %s">%s:%s</span>'
                   % (cls, _esc(it["ip"]), it["port"]))
    if len(items) > limit:
        out.append('<span class="chip">… 其余 %d 条见下方明细</span>' % (len(items) - limit))
    return "".join(out)


# --------------------------------------------------------------------------
# 周度趋势图 (内联 SVG, 无外部依赖)
# --------------------------------------------------------------------------
def trend_svg(history: list, label: str) -> str:
    series = [h for h in (history or []) if h.get("label", "default") == label][-14:]
    if len(series) < 2:
        return ('<div class="trend-empty">至少需要 <b>2 次</b>扫描记录才能绘制趋势曲线。'
                '再跑一轮周度巡检，这里就会出现开放端口数的逐周变化图。</div>')

    W, H = 1180, 260
    PL, PR, PT, PB = 58, 26, 30, 40
    IW, IH = W - PL - PR, H - PT - PB
    vals = [int(h.get("open_total", 0)) for h in series]
    n = len(vals)
    vmax = max(vals)
    top = max(1, int(vmax * 1.3) if vmax else 1)

    def X(i):
        return PL + (IW * i / (n - 1))

    def Y(v):
        return PT + IH - (IH * v / top)

    parts = ['<svg viewBox="0 0 %d %d" width="100%%" '
             'style="min-width:760px;height:auto;display:block" role="img" '
             'aria-label="开放端口周度趋势">' % (W, H)]
    parts.append('<defs><linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">'
                 '<stop offset="0%" stop-color="#1478c9" stop-opacity=".26"/>'
                 '<stop offset="100%" stop-color="#1478c9" stop-opacity=".02"/>'
                 '</linearGradient></defs>')

    for k in range(5):
        v = top * k / 4.0
        y = Y(v)
        parts.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#e6edf5" stroke-width="1"/>'
                     % (PL, y, W - PR, y))
        parts.append('<text class="ax" x="%d" y="%.1f" text-anchor="end">%d</text>'
                     % (PL - 10, y + 4, round(v)))

    pts = " ".join("%.1f,%.1f" % (X(i), Y(v)) for i, v in enumerate(vals))
    area = "%.1f,%.1f " % (X(0), Y(0)) + pts + " %.1f,%.1f" % (X(n - 1), Y(0))
    parts.append('<polygon points="%s" fill="url(#ga)"/>' % area)
    parts.append('<polyline points="%s" fill="none" stroke="#0b5fa5" stroke-width="2.4" '
                 'stroke-linejoin="round" stroke-linecap="round"/>' % pts)

    for i, h in enumerate(series):
        v = vals[i]
        cx, cy = X(i), Y(v)
        nw = int(h.get("new_ports", 0))
        color = "#cf2b1f" if nw else "#0b5fa5"
        parts.append('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="#fff" stroke="%s" '
                     'stroke-width="2.4"><title>%s 开放 %d 个端口，本周新增 %d</title></circle>'
                     % (cx, cy, 5.0 if nw else 4.0, color, _esc(h.get("scan_time", "")), v, nw))
        parts.append('<text class="pt-lbl" x="%.1f" y="%.1f" text-anchor="middle">%d</text>'
                     % (cx, cy - 12, v))
        parts.append('<text class="xl" x="%.1f" y="%d" text-anchor="middle">%s</text>'
                     % (cx, H - 14, _esc(str(h.get("scan_time", ""))[5:10])))

    parts.append('</svg>')
    return "".join(parts)


# --------------------------------------------------------------------------
# 领导版摘要
# --------------------------------------------------------------------------
def brief_html(doc: dict, summary: dict, history: list) -> str:
    s = doc["summary"]
    new_sorted = sorted(summary["new"],
                        key=lambda x: (RISK_ORDER.get(x.get("risk", "LOW"), 9), x["port"]))
    crit_new = [x for x in new_sorted if x.get("risk") in ("CRITICAL", "HIGH")]
    must_fix = [p for h in doc["hosts"] for p in h["open_ports"]
                if p.get("risk") in ("CRITICAL", "HIGH")]

    if crit_new:
        cls, ico = "bad", "⚠"
        verdict = "发现 %d 个本周新增的高危 / 严重端口，暴露面正在扩大" % len(crit_new)
        detail = ("这是最需要立刻处置的信号。建议今日内确认这些端口是否为误开放、"
                  "临时调试端口或配置回退，确认后立即关闭或限制源 IP。")
    elif summary["new"]:
        cls, ico = "warn", "●"
        verdict = "暴露面小幅变化：本周新增 %d 个开放端口（均为中低风险）" % len(summary["new"])
        detail = "风险可控，但建议逐个确认业务必要性，避免长期无主端口堆积。"
    elif doc.get("unreachable_ratio", 0) >= 0.35:
        cls, ico = "warn", "●"
        verdict = "本周未发现新增端口，但本次扫描数据可信度偏低"
        detail = ("有 %d 台主机完全无响应，可能是当前执行网络被策略阻断，"
                  "而非目标真的没有开放端口。建议改从不受限的网络复扫后再下结论。"
                  % s.get("silent_hosts", 0))
    else:
        cls, ico = "ok", "✓"
        verdict = "暴露面保持收敛，本周未发现新增开放端口"
        detail = ("与上周基线一致%s。建议保持现有收敛策略，继续每周巡检。"
                  % ("，且已有 %d 个端口完成收敛" % s["gone_ports"] if s["gone_ports"] else ""))

    series = [h for h in (history or []) if h.get("label", "default") == doc.get("scan_label")]
    if len(series) >= 2:
        delta = series[-1]["open_total"] - series[-2]["open_total"]
        if delta > 0:
            arrow, trend = "↑", "较上次增加 %d 个，暴露面扩大" % delta
        elif delta < 0:
            arrow, trend = "↓", "较上次减少 %d 个，暴露面收敛" % abs(delta)
        else:
            arrow, trend = "→", "与上次持平"
    else:
        arrow, trend = "—", "本次为首次扫描，正在建立基线"

    if must_fix:
        fix_txt = "%d 个高危暴露点待处置" % len(must_fix)
        fix_sub = "涉及 %d 台主机" % len({h["ip"] for h in doc["hosts"]
                                      for p in h["open_ports"]
                                      if p.get("risk") in ("CRITICAL", "HIGH")})
    else:
        fix_txt = "无高危暴露点"
        fix_sub = "当前开放端口均属中低风险"

    ratio = doc.get("unreachable_ratio", 0)
    if ratio >= 0.35:
        conf, conf_sub = "偏低", "%d 台主机无响应，疑受执行网络限制" % s.get("silent_hosts", 0)
    elif ratio > 0:
        conf, conf_sub = "中", "%d 台主机无响应，建议留意" % s.get("silent_hosts", 0)
    else:
        conf, conf_sub = "高", "全部目标均有响应"

    bullets = [
        ("暴露面趋势", "%s %s" % (arrow, trend), "开放端口总数当前 %d 个" % s["open_total"]),
        ("待处置事项", fix_txt, fix_sub),
        ("本次数据可信度", conf, conf_sub),
    ]
    bullet_html = "".join(
        '<div class="bullet"><div class="bk">%s</div><div class="bv">%s</div>'
        '<div class="bd">%s</div></div>' % (_esc(k), _esc(v), _esc(d))
        for k, v, d in bullets)

    return ('<div class="verdict %s"><div class="ico">%s</div><div>'
            '<div class="t">%s</div><div class="d">%s</div></div></div>'
            '<div class="bullets">%s</div>'
            % (cls, ico, _esc(verdict), _esc(detail), bullet_html))


# --------------------------------------------------------------------------
# 处置建议清单
# --------------------------------------------------------------------------
def remediation_html(doc: dict) -> str:
    items = []
    for h in doc["hosts"]:
        for p in h["open_ports"]:
            if p.get("risk") in ("CRITICAL", "HIGH"):
                items.append((h["ip"], p))
    items.sort(key=lambda t: (RISK_ORDER.get(t[1].get("risk"), 9), t[1]["port"]))
    if not items:
        return ('<div class="alert ok"><b>本次未发现严重 / 高风险开放端口。</b>'
                '所有已开放端口均属中低风险，保持常规跟踪即可。</div>')

    rows = []
    for ip, p in items:
        act, why = remediation_of(p["port"], p.get("risk", "LOW"))
        crit = p.get("risk") == "CRITICAL"
        rows.append(
            '<div class="rm %s">'
            '<div class="p">%d<span class="tag t-%s" style="display:block;margin-top:4px;'
            'text-align:center">%s</span></div>'
            '<div class="body"><div class="act">%s</div><div class="why">%s</div></div>'
            '<div class="who">%s</div></div>'
            % ("cri" if crit else "hig", p["port"], p.get("risk", "LOW"),
               RISK_LABEL.get(p.get("risk"), ""), _esc(act), _esc(why), _esc(ip)))
    return '<div class="rm-list">%s</div>' % "".join(rows)


# --------------------------------------------------------------------------
# 端口明细表 · 服务端预渲染
#
# 为什么要在服务端先把表格铺好，而不是只交给前端 JS：
#   · 报告是要通过邮件推送的，多数邮件客户端（Outlook / QQ邮箱网页版预览等）
#     **会直接屏蔽 <script>**。只靠 JS 渲染的话，收件人打开附件看到的可能是一张空表。
#   · 前端 JS 万一出问题（历史上真的出过一次语法错误），整张表会静默变空，
#     没人会注意到报告里少了东西。
# 所以策略是：服务端先把「全部端口」这份静态 HTML 铺进页面兜底，
# 前端 JS 加载成功后再接管，用于切换页签 / 筛选 / 搜索。
# --------------------------------------------------------------------------
DETAIL_THEAD = (
    "<tr><th>IP 地址</th><th>端口</th><th>服务</th><th>风险</th>"
    "<th>对比上周</th><th>横幅 / 指纹</th><th>处置建议</th><th>证书指纹</th></tr>"
)


def detail_rows_html(doc: dict) -> str:
    """把全部开放端口渲染成静态 <tr>，与前端 renderDetail() 的输出保持一致。"""
    items = []
    for h in doc.get("hosts", []):
        for p in h.get("open_ports", []):
            items.append((h, p))
    items.sort(key=lambda t: (RISK_ORDER.get(t[1].get("risk"), 9),
                              t[1]["port"], t[0]["ip"]))
    if not items:
        return ('<tr><td colspan="8" class="empty">'
                '本次未发现任何开放端口 &#9989;</td></tr>')

    out = []
    for h, p in items:
        risk = p.get("risk", "LOW")
        act, why = remediation_of(p["port"], risk)
        banner = _esc(p.get("banner") or "") or '<span class="muted">—</span>'
        http = p.get("http") or {}
        tls = p.get("tls") or {}
        extra = []
        if http.get("server"):
            extra.append("Server: " + _esc(http["server"]))
        if http.get("title"):
            extra.append("Title: " + _esc(http["title"]))
        if tls.get("tls_version"):
            extra.append("TLS " + _esc(tls["tls_version"]))
        if tls.get("subject"):
            extra.append(_esc(tls["subject"]))
        fp = ('<div class="bn">%s</div>' % " · ".join(extra)) if extra else ""
        an = ('<div class="bn" style="color:#c26a02">'
              '&#9888; 异常主机（结果不可信）</div>') if h.get("anomaly") else ""
        cert = tls.get("cert_sha256") or ""
        out.append(
            '<tr class="%s">'
            '<td class="ip">%s</td>'
            '<td class="pt">%d</td>'
            '<td>%s</td>'
            '<td><span class="tag t-%s">%s</span></td>'
            '<td>%s</td>'
            '<td><div class="bn">%s</div>%s%s</td>'
            '<td class="fix"><b>%s</b>%s</td>'
            '<td class="mono">%s</td>'
            '</tr>'
            % ("row-new" if p.get("is_new") else "",
               _esc(h["ip"]), p["port"],
               _esc(p.get("service") or "—"),
               risk, RISK_LABEL.get(risk, risk),
               ('<span class="tag t-new">新增</span>' if p.get("is_new")
                else '<span class="muted">—</span>'),
               banner, fp, an,
               _esc(act), _esc(why),
               _esc(cert[:14] + "…" if cert else "")))
    return "".join(out)


def quality_html(doc: dict) -> str:
    """「探测质量」区块。

    这一块存在的唯一目的：把「扫不出来」背后的真实构成摊在台面上。
    过去 filtered 是个黑洞 —— 端口到底是被防火墙丢了、被目标限速了、还是本机自己
    出了问题，报告里一个字都没有，使用者只能看到"没开放"，从而得出错误结论。
    """
    q = doc.get("quality") or {}
    if not q:
        return ('<p class="muted">本次报告未记录探测质量数据（可能是旧版本扫描器生成的）。</p>')
    total = q.get("probes_total", 0) or 1

    def row(label, val, style=""):
        st = ' style="%s"' % style if style else ""
        return ('<tr><td class="muted">%s</td><td%s>%s</td></tr>'
                % (_esc(label), st, val))

    def cnt(n):
        return "%s <span class='muted'>(%.1f%%)</span>" % (format(int(n), ","),
                                                          100.0 * int(n) / total)

    rows = [
        row("探测总量（含补扫）", format(int(total), ",")),
        row("开放 · 收到 SYN-ACK", cnt(q.get("open", 0))),
        row("关闭 · 收到 RST", cnt(q.get("closed", 0))),
        row("无响应 · 静默丢包", cnt(q.get("timeout", 0))),
        row("本机侧异常（errno）", format(int(q.get("errno_total", 0)), ","),
            "color:var(--red)" if q.get("errno_total") else ""),
        row("补扫挽回的真实开放端口", "<b>%d</b>" % int(q.get("rescan_recovered", 0))),
        row("后置补扫挽回的真实开放端口<b>*</b>",
            "<b>%d</b>" % int(q.get("post_rescan_recovered", 0))),
        row("后置补扫后仍无响应的业务端口",
            "<b>%d</b>" % int(q.get("post_rescan_left", 0))),
        row("存疑端口（复核未通过）", "<b>%d</b>" % int(q.get("unconfirmed_total", 0))),
    ]

    errno_items = q.get("errno") or {}
    errno_html = ""
    if errno_items:
        errno_html = ('<p style="margin:10px 0 0">本机侧异常明细：'
                      + "、".join("%s × %s" % (_esc(k), format(v, ","))
                                  for k, v in sorted(errno_items.items()))
                      + "。出现这些说明并发已把本机连接栈打到临界，结果是<b>假阴性</b>，"
                        "请降低 scan.concurrency 后重扫。</p>")

    unconf = []
    for h in doc.get("hosts", []):
        for p in (h.get("unconfirmed_ports") or []):
            unconf.append((h["ip"], p))
    unconf_html = ""
    if unconf:
        unconf_html = (
            '<p style="margin:14px 0 6px"><b>存疑端口</b>（扫描阶段命中、二次确认未通过）'
            '—— 目标侧限速会造成这类现象，请人工复核，'
            '<b>不要直接当作未开放</b>：</p>'
            '<div class="chips">%s</div>'
            % "".join('<span class="chip">%s : %s</span>'
                      % (_esc(ip), p) for ip, p in sorted(unconf)))

    note = ('<p class="muted" style="margin-top:12px">判读要点：'
            '「开放」是确定性结论（收到 SYN-ACK 即成立）；'
            '「无响应」是<b>不确定性</b>结论 —— 它既可能是端口关闭，也可能是被防火墙'
            '静默丢弃，还可能是目标或路径对本机源 IP 做了<b>探测限速</b>。'
            '补扫挽回的端口数量越多，说明主扫描的漏报越严重。</p>')

    return ('<table class="qtbl">%s</table>%s%s%s'
            % ("".join(rows), errno_html, unconf_html, note))


def expected_html(doc: dict) -> str:
    """「与历史清单对照」区块。

    回答的是使用者最关心的那个问题：「这次是不是又漏扫了？」
    历史清单只用于**对照**，不参与扫描范围的决策 —— 扫描永远是全量 65535 端口，
    否则历史清单里没有的新上线服务就永远扫不到。
    """
    ed = doc.get("expected_diff") or {}
    if not ed:
        return ('<p class="muted">本次未加载历史清单，无法做「与历史基线清单对照」。'
                '如需启用，把既有资产清单整理成工具目录下的 <b>expected_ports.json</b> 即可。</p>')

    miss = ed.get("missing") or []
    extra = ed.get("extra") or []
    notscan = ed.get("not_scanned") or []
    hit = int(ed.get("hit_hosts", 0))

    cards = [
        ("c-grn", "与历史完全一致", "%d 台" % hit, "本次扫到的端口 == 历史期望"),
        ("c-org", "疑似漏报", "%d 台 / %d 端口" % (len(miss), ed.get("missing_ports", 0)),
         "历史开放过，本次未扫到"),
        ("c-org", "新增暴露面", "%d 台 / %d 端口" % (len(extra), ed.get("extra_ports", 0)),
         "本次扫到，历史清单里没有"),
        ("c-blu", "无响应未核对", "%d 台" % len(notscan), "主机不可达，无法比对"),
    ]
    cards_html = "".join(
        '<div class="card %s"><div class="k">%s</div><div class="v">%s</div>'
        '<div class="s">%s</div></div>' % (c, _esc(k), _esc(v), _esc(sb))
        for c, k, v, sb in cards)

    def chips(ports):
        return "".join('<span class="chip">%s</span>' % _esc(str(p)) for p in ports)

    miss_html = ""
    if miss:
        rows = []
        for x in miss:
            still = x.get("still_open") or []
            ref = ("本次仍扫到：" + "、".join(map(str, still))) if still else "本次该主机完全没扫到端口"
            rows.append('<tr><td>%s</td><td>%s</td><td>%s</td><td class="muted">%s</td></tr>'
                        % (_esc(x["ip"]), _esc(x.get("name", "")),
                           chips(x["ports"]), _esc(ref)))
        miss_html = (
            '<p style="margin:16px 0 6px"><b>【疑似漏报】历史上开放过、但本次未扫到的端口</b>'
            ' —— 这<b>不等于「已关闭」</b>。更可能的原因是目标侧对源 IP 的<b>探测限速</b>'
            '把这批端口静默丢弃了（典型特征是「只扫到 80，443 与高位业务端口整片丢失」）。'
            '请优先换网络或复核后再下结论：</p>'
            '<table class="ctbl"><tr><td class="muted">主机</td><td class="muted">系统</td>'
            '<td class="muted">未扫到的端口</td><td class="muted">参照</td></tr>%s</table>'
            % "".join(rows))

    extra_html = ""
    if extra:
        rows = []
        for x in extra:
            rows.append('<tr><td>%s</td><td>%s</td><td>%s</td><td class="muted">%s</td></tr>'
                        % (_esc(x["ip"]), _esc(x.get("name", "")), chips(x["ports"]),
                           _esc(x.get("reason", "本次扫到、历史清单里没有"))))
        extra_html = (
            '<p style="margin:16px 0 6px"><b>【新增 / 需确认】</b>本次扫到、但历史清单里没有的端口。'
            '可能是新上线业务，<b>也可能是上一轮扫描的误报</b>，需人工确认：</p>'
            '<table class="ctbl"><tr><td class="muted">主机</td><td class="muted">系统</td>'
            '<td class="muted">端口</td><td class="muted">说明</td></tr>%s</table>'
            % "".join(rows))

    notscan_html = ""
    if notscan:
        notscan_html = (
            '<p style="margin:16px 0 6px"><b>【无法比对】</b>以下主机本次完全无响应，'
            '无法判断是「确实离线」还是「本次执行网络不可达」，因此它们的历史端口'
            '既不能算漏报、也不能算关闭：</p><div class="chips">%s</div>'
            % "".join('<span class="chip">%s : %s</span>'
                      % (_esc(x["ip"]), "、".join(map(str, x["ports"])) or "无")
                      for x in notscan))

    note = ('<p class="muted" style="margin-top:14px">判读要点：本表<b>不会</b>改变扫描范围 —— '
            '扫描永远覆盖全部 65535 个端口，历史清单只在「扫完之后对照一趟」。'
            '这样既能借历史清单发现漏扫，又不会因为历史清单而漏掉新上线的服务。</p>')

    return ('<div class="cards">%s</div>%s%s%s%s'
            % (cards_html, miss_html, extra_html, notscan_html, note))


# --------------------------------------------------------------------------
# 主渲染
# --------------------------------------------------------------------------
def render(doc: dict, summary: dict, out_path: Path, title: str = "",
           history: list = None) -> None:
    s = doc["summary"]
    title = title or "GuvianEye 公网暴露面巡检报告"
    label = doc.get("scan_label") or "default"
    history = history or []

    new_sorted = sorted(summary["new"],
                        key=lambda x: (RISK_ORDER.get(x.get("risk", "LOW"), 9), x["port"]))
    crit_new = [x for x in new_sorted if x.get("risk") in ("CRITICAL", "HIGH")]

    alerts = []
    if doc.get("scope_changed"):
        alerts.append('<div class="alert info"><b>本次扫描的端口范围与上次基线不一致</b>，'
                      '已自动跳过「与上周对比」的变化分析。这样可以避免把「换了个扫描范围」'
                      '误读成「端口新增 / 消失」。如需可靠的周度对比，请保持每周使用相同的端口范围。</div>')
    if crit_new:
        alerts.append('<div class="alert bad"><b>发现 %d 个本周新增的高危 / 严重端口</b> —— '
                      '这是暴露面扩大最需要立刻处置的信号，请优先确认是否为误开放或临时调试端口。'
                      '<div class="chips">%s</div></div>' % (len(crit_new), _chips(crit_new, "new")))
    elif summary["new"]:
        alerts.append('<div class="alert warn"><b>发现 %d 个本周新增开放端口</b>（均为中低风险），'
                      '建议确认业务必要性。<div class="chips">%s</div></div>'
                      % (len(summary["new"]), _chips(new_sorted, "new")))
    else:
        alerts.append('<div class="alert ok"><b>与上周基线相比无新增开放端口</b>，'
                      '暴露面保持收敛。继续保持。</div>')
    if summary["gone"]:
        alerts.append('<div class="alert ok"><b>%d 个端口已从开放转为关闭</b>（收敛成果）'
                      '<div class="chips">%s</div></div>'
                      % (len(summary["gone"]), _chips(summary["gone"], "gone")))

    silent = [h["ip"] for h in doc["hosts"] if h.get("discovery") != "up"]
    if silent:
        ratio = doc.get("unreachable_ratio") or (len(silent) / max(1, len(doc["hosts"])))
        if ratio >= 0.35:
            alerts.append(
                '<div class="alert bad"><b>%d/%d 台主机完全无响应（占 %.0f%%），本报告结论可能不可靠</b><br>'
                '本工具无法区分以下两种情况，请务必人工确认：<br>'
                '&nbsp;&nbsp;（a）目标确实离线，或全端口被目标侧防火墙静默丢弃；<br>'
                '&nbsp;&nbsp;（b）<b>本次扫描的执行网络（办公网 / 内网出口）对这批地址做了策略阻断</b>。<br>'
                '若无法确认，请改从不受限的网络（如公网跳板机）执行，'
                '并用基线标签为不同网络分别建立基线，避免数据互相污染。<br>'
                '无响应清单：%s</div>'
                % (len(silent), len(doc["hosts"]), ratio * 100,
                   "、".join(_esc(x) for x in silent)))
        else:
            alerts.append(
                '<div class="alert warn"><b>%d 台主机全程无任何响应</b>'
                '（既无 SYN-ACK 也无 RST）。这些主机可能已下线，也可能在本次执行网络下不可达。'
                '其「无开放端口」的结论<b>不等于安全</b>，只是本次探测无证据：%s</div>'
                % (len(silent), "、".join(_esc(x) for x in silent)))

    total_closed = sum(h.get("closed_count", 0) for h in doc["hosts"])
    if doc["hosts"] and total_closed == 0:
        alerts.append(
            '<div class="alert info"><b>本次扫描环境说明</b>：全部目标在整个扫描过程中'
            '<b>未返回任何 TCP RST</b>，说明边界设备采用「静默丢弃」策略。因此'
            '「端口已关闭」与「端口被防火墙过滤」在报文层面无法区分，本报告统一记为 filtered。'
            '这不影响开放端口的判定（开放是确定性结论），但意味着无法用本报告推断'
            '目标是否真的关掉了某个端口。</div>')

    new_hosts = summary.get("new_hosts") or []
    if new_hosts:
        alerts.append('<div class="alert warn"><b>%d 台主机首次纳入基线</b>，暂无历史对比数据：%s</div>'
                      % (len(new_hosts), "、".join(_esc(x) for x in new_hosts)))

    baseline_time = doc.get("baseline_time") or "首次运行，无基线"
    meta = ('扫描时间 <b>%s</b><span class="sep">｜</span>耗时 <b>%.1f 秒</b>'
            '<span class="sep">｜</span>探测 <b>%s</b> 次 TCP connect'
            '<span class="sep">｜</span>端口范围 <b>%s</b>'
            '<span class="sep">｜</span>基线标签 <b>%s</b>'
            '<span class="sep">｜</span>上次基线 <b>%s</b>'
            % (_esc(doc["scan_time"]), doc["elapsed_sec"], format(doc["probes"], ","),
               _esc(str(doc["ports_scanned"]) + " 个"), _esc(label), _esc(baseline_time)))

    cards = [
        ("c-acc", "扫描主机", str(doc["hosts_total"]), "基线内资产总数"),
        ("c-blu", "开放端口合计", str(s["open_total"]),
         "%d 台主机无开放端口" % s.get("no_open_hosts", 0)),
        ("c-red", "严重 / 高危", "%d / %d" % (s["critical_total"], s["high_total"]), "需优先收敛"),
        ("c-red", "本周新增", str(s["new_ports"]), "对比上周基线"),
        ("c-grn", "本周消失", str(s["gone_ports"]), "已收敛端口"),
        ("c-org", "异常 / 无响应", "%d / %d" % (s["anomaly_hosts"], s.get("silent_hosts", 0)),
         "结果需人工核对"),
    ]
    cards_html = "".join(
        '<div class="card %s"><div class="k">%s</div><div class="v">%s</div>'
        '<div class="s">%s</div></div>' % (c, _esc(k), _esc(v), _esc(sub))
        for c, k, v, sub in cards)

    fix_cnt = sum(1 for h in doc["hosts"] for p in h["open_ports"]
                  if p.get("risk") in ("CRITICAL", "HIGH"))

    shell = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title><style>__CSS__</style></head><body><div class="wrap">

<header>
  <h1>__TITLE__<span class="badge">__HOSTS__ 台资产 · 每周巡检</span></h1>
  <div class="meta">__META__</div>
</header>

<section class="box brief">
  <h2>执行摘要 · 一页读完<span class="cnt">面向管理层</span></h2>
  __BRIEF__
</section>

<div class="cards">__CARDS__</div>

<section class="box">
  <h2>开放端口周度趋势<span class="cnt">基线标签：__LABEL__</span></h2>
  <div class="trend-wrap">__TREND__</div>
</section>

<section class="box full-only">
  <h2>探测质量与漏报自查<span class="cnt">为什么"明明开放却扫不出来"</span></h2>
  __QUALITY__
</section>

<section class="box full-only">
  <h2>与历史清单对照<span class="cnt">历史基线清单 · 本次是不是又漏扫了</span></h2>
  __EXPECTED__
</section>

<section class="box full-only">
  <h2>风险提示与变化分析</h2>
  __ALERTS__
  <div class="legend">说明：风险等级按端口性质划分 ——
  <b>严重</b>=未授权访问即可直接泄露数据或接管主机；<b>高</b>=须严格限制暴露；
  <b>中</b>=系统级服务端口；<b>低</b>=其余高位端口。</div>
</section>

<section class="box">
  <h2>高危端口处置建议<span class="cnt">__FIXCNT__</span></h2>
  __REMED__
</section>

<section class="box full-only">
  <h2>端口明细<span class="cnt" id="cnt"></span></h2>
  <div class="toolbar">
    <div class="seg" id="tabbar">
      <button data-t="detail" class="on">端口明细</button>
      <button data-t="summary">主机汇总</button>
    </div>
    <div class="seg" id="modebar">
      <button data-m="all" class="on">全部</button>
      <button data-m="new">仅本周新增</button>
      <button data-m="high">仅高危及以上</button>
      <button data-m="crit">仅严重</button>
    </div>
    <input type="text" id="q" placeholder="搜索 IP / 端口 / 服务 / 横幅 / 处置建议…">
  </div>
  <div class="tbl-scroll">
    <table><thead id="thead">__THEAD__</thead><tbody id="tbody">__TROWS__</tbody></table>
  </div>
</section>

<footer>
  本报告由「GuvianEye 公网暴露面巡检工具」自动生成 ｜ 数据来源：TCP connect 实际探测（非被动情报 / CDN 指纹）
  <br>仅用于自有或已获授权资产的暴露面管理，请勿用于未授权扫描。
</footer>
</div>
<button class="modebtn" id="briefbtn" onclick="toggleBrief()">切换简报模式</button>
<script>__JS__</script>
</body></html>"""

    # ---- 前端数据 ----
    fix_map = {str(p): list(remediation_of(p, "LOW")) for p in REMEDIATION}
    fix_map.update({("_" + k): list(v) for k, v in GENERIC_REMEDIATION.items()})
    payload = json.dumps({
        "scan_time": doc["scan_time"],
        "fix": fix_map,
        "quality": doc.get("quality") or {},
        "expected": doc.get("expected_diff") or {},
        "hosts": [{
            "ip": h["ip"], "anomaly": h.get("anomaly", ""),
            "discovery": h.get("discovery", ""), "rtt_ms": h.get("rtt_ms", 0),
            "unconfirmed": h.get("unconfirmed_ports") or [],
            "open_ports": [{
                "port": p["port"], "service": p.get("service", ""),
                "risk": p.get("risk", "LOW"), "is_new": bool(p.get("is_new")),
                "banner": p.get("banner", ""), "http": p.get("http") or {},
                "tls": p.get("tls") or {},
            } for p in h["open_ports"]],
        } for h in doc["hosts"]],
    }, ensure_ascii=False).replace("</", "<\\/")

    out = (shell
           .replace("__CSS__", CSS)
           .replace("__TITLE__", _esc(title))
           .replace("__HOSTS__", str(doc["hosts_total"]))
           .replace("__META__", meta)
           .replace("__BRIEF__", brief_html(doc, summary, history))
           .replace("__CARDS__", cards_html)
           .replace("__LABEL__", _esc(label))
           .replace("__TREND__", trend_svg(history, label))
           .replace("__QUALITY__", quality_html(doc))
           .replace("__EXPECTED__", expected_html(doc))
           .replace("__ALERTS__", "".join(alerts))
           .replace("__FIXCNT__", "%d 项" % fix_cnt)
           .replace("__REMED__", remediation_html(doc))
           .replace("__THEAD__", DETAIL_THEAD)
           .replace("__TROWS__", detail_rows_html(doc))
           .replace("__JS__", JS.replace("__DATA__", payload)))

    block_fix = [h["ip"] for h in doc["hosts"] if h.get("anomaly")]
    if block_fix:
        out = out.replace(
            "<footer>",
            '<div class="alert warn" style="margin-top:14px"><b>异常主机</b>：%s '
            '返回的开放端口数超过阈值，通常意味着运营商安全墙 / 负载设备对全部端口'
            '统一应答，或目标为蜜罐。这些主机的结论<b>不可直接采信</b>。</div><footer>'
            % "、".join(_esc(x) for x in block_fix))

    out_path.write_text(out, encoding="utf-8")
