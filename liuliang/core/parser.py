# -*- coding: utf-8 -*-
"""
日志解析模块

这个模块只干一件事：把日志文件里的一行行文本，变成一个个字典。

比如这样一行日志：
    1.2.3.4 - - [10/Oct/2026:13:55:36 +0800] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"

会被变成这样一个字典：
    {"ip": "1.2.3.4", "time": "2026-10-10 13:55:36", "method": "GET",
     "path": "/index.html", "status": 200, "size": 2326, "agent": "Mozilla/5.0"}

后面的统计和检测都只认这个字典，不用再去碰原始文本了。
"""

import json
import re
from datetime import datetime
from urllib.parse import urlparse

# ----------------------------------------------------------------------
# 下面几个是"正则表达式"，可以理解成一种"按模板找东西"的工具
# ----------------------------------------------------------------------

# combined 格式用的模板，最常见的一种，带 referer 和 user-agent
# (?P<ip>\S+) 的意思是：找一段不含空格的字符，把它存成 ip
# \S 表示"不是空格的字符"，+ 表示"一个或多个"，\s+ 表示"一个或多个空格"
PATTERN_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"\s*$'
)

# common 格式用的模板，比上面那个简单，没有 referer 和 user-agent
PATTERN_COMMON = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s*$'
)

# 请求行模板，用来把 "GET /index.html HTTP/1.1" 拆成三部分
# 注意 path 用的是 .+? 不是 \S+，因为有些攻击语句里带空格，比如
# "GET /item?id=1 UNION SELECT x HTTP/1.1"，用 \S+ 会把后面的注入语句截掉
PATTERN_REQUEST = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<path>.+?)\s+(?P<protocol>HTTP/[\d.]+)\s*$'
)

# 有些扫描器发的请求没写协议，比如就一个 "GET /xxx"
PATTERN_REQUEST_NOPROTO = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>.+?)\s*$')

# 日志里的时间长这样：10/Oct/2026:13:55:36 +0800
# 下面这串是告诉 Python 每个部分是什么意思，%d 是日，%b 是英文月份缩写，%z 是时区
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line):
    """
    解析一行日志，成功就返回一个字典，失败就返回 None。

    先试 combined 格式，不行再试 common，再不行试 json。
    三种都不匹配就返回 None，主程序会把它记成"解析失败的行"。
    """
    line = line.strip()
    if line == "":
        return None

    # 第一种：combined 格式
    m = PATTERN_COMBINED.match(line)
    if m:
        return _make_entry(m, line, referer=m.group("referer"),
                           agent=m.group("agent"))

    # 第二种：common 格式
    m = PATTERN_COMMON.match(line)
    if m:
        return _make_entry(m, line, referer="", agent="")

    # 第三种：json 格式，一行一个 json 对象
    if line.startswith("{"):
        return _parse_json_line(line)

    return None


def _make_entry(m, raw, referer, agent):
    """
    把正则匹配到的结果，填进一个字典里。

    参数 m 是正则匹配的结果，用 m.group("名字") 就能取出对应那段文本。
    参数 raw 是原始那行日志，留着后面导出证据的时候要用。
    """
    # 先建一个字典，key 就是各个字段名
    entry = {
        "ip": m.group("ip"),
        "ident": m.group("ident"),
        "user": m.group("user"),
        "time_raw": m.group("time"),   # 原始时间文本
        "time": None,                  # 转成 datetime 之后的时间，转失败就是 None
        "method": "",
        "path": "",
        "protocol": "",
        "status": 0,
        "size": 0,
        "referer": "",
        "agent": "",
        "raw": raw,
    }

    # 时间转换，用 try 是因为万一格式不对，不能让整个程序崩掉
    try:
        entry["time"] = datetime.strptime(m.group("time"), TIME_FORMAT)
    except ValueError:
        entry["time"] = _try_other_time_format(m.group("time"))

    # 拆请求行，比如 "GET /index.html HTTP/1.1"
    request = m.group("request")
    rm = PATTERN_REQUEST.match(request)
    if rm:
        entry["method"] = rm.group("method")
        entry["path"] = rm.group("path")
        entry["protocol"] = rm.group("protocol")
    else:
        # 没写协议的畸形请求，尽力拆一下
        rm2 = PATTERN_REQUEST_NOPROTO.match(request)
        if rm2:
            entry["method"] = rm2.group("method")
            entry["path"] = rm2.group("path")
            entry["protocol"] = "-"
        else:
            # 实在拆不出来就按空格切，第一段当方法，其余当路径
            parts = request.split()
            entry["method"] = parts[0] if len(parts) > 0 else "-"
            entry["path"] = " ".join(parts[1:]) if len(parts) > 1 else "-"
            entry["protocol"] = "-"

    # 状态码要转成整数，后面比较大小要用
    # 比如 400 <= status < 500 可以判断是不是 4xx
    try:
        entry["status"] = int(m.group("status"))
    except ValueError:
        entry["status"] = 0

    # 响应大小，有些日志这里写的是减号 "-"，表示没有内容，那就记 0
    size_text = m.group("size")
    if size_text.isdigit():
        entry["size"] = int(size_text)
    else:
        entry["size"] = 0

    # 日志里没有 referer 或 UA 的时候会写成一个减号 "-"
    # 存成空字符串更好看，前端显示出来不会是一堆减号
    entry["referer"] = "" if referer == "-" else referer
    entry["agent"] = "" if agent == "-" else agent

    return entry


def _try_other_time_format(time_text):
    """
    有些日志的时间格式不太标准，这里再试几种常见的。
    都失败了就返回 None，不影响其它字段。
    """
    formats = ["%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    for f in formats:
        try:
            return datetime.strptime(time_text, f)
        except ValueError:
            continue
    return None


def _parse_json_line(line):
    """
    解析 json 格式的日志行。

    Nginx 可以配置成直接输出 json，一行一个，长这样：
    {"remote_addr":"1.2.3.4","request_method":"GET","status":"200"}
    """
    try:
        obj = json.loads(line)
    except ValueError:
        return None

    # json 的字段名各家配得不一样，所以每个字段都试几个可能的名字
    def pick(*keys):
        for k in keys:
            if k in obj and obj[k] not in (None, "", "-"):
                return str(obj[k])
        return ""

    entry = {
        "ip": pick("remote_addr", "ip", "client_ip"),
        "ident": "-",
        "user": pick("remote_user", "user") or "-",
        "time_raw": pick("time_local", "time", "timestamp"),
        "time": None,
        "method": pick("request_method", "method"),
        "path": pick("request_uri", "uri", "path", "request"),
        "protocol": pick("server_protocol", "protocol") or "HTTP/1.1",
        "status": 0,
        "size": 0,
        "referer": pick("http_referer", "referer", "referrer"),
        "agent": pick("http_user_agent", "user_agent", "agent"),
        "raw": line,
    }

    entry["time"] = _try_other_time_format(entry["time_raw"])

    try:
        entry["status"] = int(pick("status", "status_code") or 0)
    except ValueError:
        entry["status"] = 0

    try:
        entry["size"] = int(pick("body_bytes_sent", "size", "bytes") or 0)
    except ValueError:
        entry["size"] = 0

    return entry


def parse_file(file_path, max_lines=0):
    """
    解析整个日志文件，返回一个结果字典。

    返回的字典长这样：
    {
        "entries": [ {...}, {...}, ... ],   # 解析成功的，每一个是一行日志变来的字典
        "total": 12000,                     # 一共读了多少行
        "failed": 0,                        # 有多少行没解析出来
        "success_rate": 100.0,              # 成功率，百分数
        "format_detected": "combined",      # 判断出来是哪种格式
        "parse_errors": [],                 # 前 20 条解析失败的行，方便排查
    }

    参数 max_lines 是最多解析几行，填 0 表示不限。
    """
    entries = []        # 存解析成功的
    errors = []         # 存解析失败的
    total = 0           # 一共读了多少行
    failed = 0          # 失败了多少行

    # 数一下三种格式各命中了多少，最后看哪个最多，就认为这个文件是哪种格式
    format_count = {"combined": 0, "common": 0, "json": 0}

    # 打开文件，一行一行读
    # encoding 用 utf-8，errors="replace" 表示遇到乱码字符就替换掉，不会报错中断
    f = open(file_path, "r", encoding="utf-8", errors="replace")
    for line in f:
        # 如果设了上限并且已经够了，就停
        if max_lines > 0 and total >= max_lines:
            break

        # 空行跳过
        if line.strip() == "":
            continue

        total = total + 1

        entry = parse_line(line)
        if entry is None:
            # 这行没解析出来，记一下然后继续，不能因为一行坏日志让整个文件解析失败
            failed = failed + 1
            # 错误最多存 20 条，不然日志一大就撑爆内存了
            if len(errors) < 20:
                errors.append({"line": total, "content": line.strip()[:200]})
            continue

        # 判断这行属于哪种格式
        if entry["agent"] != "" or entry["referer"] != "":
            format_count["combined"] = format_count["combined"] + 1
        elif entry["raw"].startswith("{"):
            format_count["json"] = format_count["json"] + 1
        else:
            format_count["common"] = format_count["common"] + 1

        entries.append(entry)
    f.close()

    # 看哪种格式命中的最多
    detected = "unknown"
    most = 0
    for name in format_count:
        if format_count[name] > most:
            most = format_count[name]
            detected = name

    # 算成功率，注意要防止除以 0
    if total > 0:
        rate = round(len(entries) / total * 100, 2)
    else:
        rate = 0.0

    return {
        "entries": entries,
        "total": total,
        "failed": failed,
        "success_rate": rate,
        "format_detected": detected,
        "parse_errors": errors,
    }


def parse_text(text, max_lines=0):
    """
    解析一段日志文本，用于页面上直接粘贴日志的情况。
    逻辑和 parse_file 一样，只是数据来源从文件变成了字符串。
    """
    entries = []
    errors = []
    total = 0
    failed = 0
    format_count = {"combined": 0, "common": 0, "json": 0}

    # split("\n") 把一整段文本按换行符切成列表
    lines = text.split("\n")
    for line in lines:
        if max_lines > 0 and total >= max_lines:
            break
        if line.strip() == "":
            continue

        total = total + 1
        entry = parse_line(line)
        if entry is None:
            failed = failed + 1
            if len(errors) < 20:
                errors.append({"line": total, "content": line.strip()[:200]})
            continue

        if entry["agent"] != "" or entry["referer"] != "":
            format_count["combined"] = format_count["combined"] + 1
        elif entry["raw"].startswith("{"):
            format_count["json"] = format_count["json"] + 1
        else:
            format_count["common"] = format_count["common"] + 1

        entries.append(entry)

    detected = "unknown"
    most = 0
    for name in format_count:
        if format_count[name] > most:
            most = format_count[name]
            detected = name

    if total > 0:
        rate = round(len(entries) / total * 100, 2)
    else:
        rate = 0.0

    return {
        "entries": entries,
        "total": total,
        "failed": failed,
        "success_rate": rate,
        "format_detected": detected,
        "parse_errors": errors,
    }


def get_time_range(result):
    """
    找出这批日志里最早和最晚的时间。
    返回 (最早时间, 最晚时间)，如果一条有效时间都没有就返回 (None, None)。
    """
    times = []
    for e in result["entries"]:
        if e["time"] is not None:
            times.append(e["time"])

    if len(times) == 0:
        return None, None

    return min(times), max(times)


def normalize_path(path):
    """
    把 URL 整理一下，让统计更准。

    主要干两件事：
    1. 去掉问号后面的参数，这样 /search?q=1 和 /search?q=2 算同一个页面
    2. 把纯数字的 id 换成 {id}，这样 /user/1001 和 /user/1002 算同一个页面
       不然 Top10 URL 会被一堆 /user/xxxx 占满，看不出重点
    """
    if path is None or path == "" or path == "-":
        return "-"

    # urlparse 能把 "http://a.com/x?y=1" 拆开，.path 就是 "/x"
    p = urlparse(path).path
    if p == "":
        p = "/"

    # 把 /user/1001 这种数字换成 /user/{id}
    p = re.sub(r'/\d+(?=/|$)', '/{id}', p)
    # 把长串十六进制（像 md5 那种）换成 {hash}
    p = re.sub(r'/[0-9a-fA-F]{8,}(?=/|$)', '/{hash}', p)

    if p == "":
        return "/"
    return p


def is_valid_ip(ip):
    """
    判断一个字符串像不像 IP 地址，用来过滤掉脏数据。
    """
    if ip is None or ip == "" or ip == "-":
        return False

    # IPv4 长这样 192.168.1.1，按点切成 4 段
    if "." in ip:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            # 每段都必须是数字，并且在 0 到 255 之间
            if not p.isdigit():
                return False
            if int(p) < 0 or int(p) > 255:
                return False
        return True

    # IPv6 里面有冒号，这里简单认为带冒号就算
    if ":" in ip:
        return True

    return False
