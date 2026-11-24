# -*- coding: utf-8 -*-
"""
异常检测模块

从 config/rules.json 读规则，改配置就能改检测行为，不用动代码。

做这几类检测：
1. 单个 IP 访问次数太高（可能在扫描或者爆破）
2. 单个 IP 短时间内突然爆发（自动化工具的特征）
3. 4xx/5xx 错误率异常
4. 可疑的 User-Agent（sqlmap、nmap 这些扫描器）
5. 带攻击特征的请求（路径遍历、SQL 注入、XSS、命令注入等 12 条规则）
6. 异常的请求方法（PUT、DELETE、TRACE 之类）

检测结果统一用字典表示，一条结果长这样：
{
    "category": "单IP高频访问",       # 属于哪一类检测
    "rule_id": "HF-IP",              # 命中的规则编号
    "severity": "high",              # 危害等级 critical/high/medium/low
    "target": "45.155.205.19",       # 主体，一般是 IP 或者 URL
    "count": 2421,                   # 命中了多少次
    "detail": "这个IP一共...",        # 人能看懂的说明
    "evidence": ["原始日志..."],      # 证据样本
    "first_seen": "2026-10-29 ...",  # 第一次出现的时间
    "last_seen": "2026-10-31 ...",   # 最后一次出现的时间
}
"""

import json
import os
import re
from collections import Counter
from datetime import timedelta

from .parser import is_valid_ip

# 规则文件的路径，就是项目根目录下 config/rules.json
DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "rules.json"
)

# 每条检测结果最多保留几条证据样本
EVIDENCE_LIMIT = 5

# 危害等级排序用，数字越大越严重
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_rules(rules_path=DEFAULT_RULES_PATH):
    """
    读规则文件，顺便把里面的正则都编译好。

    正则编译是什么意思呢？就是提前把正则表达式变成一个"能用的工具"，
    后面用它去匹配文本就很快。如果每次匹配都临时编译一遍，日志一大会很慢。

    返回 (原始配置字典, 编译好的正则字典)
    """
    f = open(rules_path, "r", encoding="utf-8")
    config = json.load(f)
    f.close()

    compiled = {}

    # 编译攻击特征规则，key 记成 "attack::规则ID"
    rules = config.get("attack_signature", {}).get("rules", [])
    for rule in rules:
        try:
            compiled["attack::" + rule["id"]] = re.compile(rule["pattern"])
        except re.error:
            # 某一条规则写错了，打印出来提醒一下，但不影响其它规则
            print("规则 " + rule["id"] + " 的正则写错了，跳过")

    # 编译可疑 UA 规则，key 记成 "ua::0" "ua::1" 这样
    ua_patterns = config.get("suspicious_user_agent", {}).get("patterns", [])
    for i, pattern in enumerate(ua_patterns):
        try:
            compiled["ua::" + str(i)] = re.compile(pattern, re.IGNORECASE)
        except re.error:
            print("UA 规则 " + pattern + " 写错了，跳过")

    return config, compiled


def detect(entries, rules_path=DEFAULT_RULES_PATH):
    """
    总入口。把所有检测都跑一遍，返回一个结果字典。

    返回：
    {
        "findings": [ {...}, {...} ],        # 检测出来的异常，每条是一个字典
        "attack_requests": [ {...}, ... ],   # 命中攻击特征的具体请求，导出 CSV 用
        "summary": {"critical": 5, "high": 13, ...},   # 各等级有多少条
        "by_category": [ {...} ],            # 按类别统计
        "high_risk_ips": [ {...} ],          # 高危 IP 排行
    }
    """
    config, compiled = load_rules(rules_path)

    findings = []           # 所有检测结果
    attack_requests = []    # 命中攻击特征的原始请求

    # 每一类检测都可以单独开关，开关在 rules.json 里的 enabled 字段
    # config.get(名字, {}).get("enabled", False) 的意思是取这个开关，取不到就当关闭
    if config.get("high_frequency_ip", {}).get("enabled", False):
        findings = findings + check_high_frequency(entries, config)

    if config.get("burst_ip", {}).get("enabled", False):
        findings = findings + check_burst(entries, config)

    if config.get("error_rate", {}).get("enabled", False):
        findings = findings + check_error_rate(entries, config)

    if config.get("suspicious_user_agent", {}).get("enabled", False):
        findings = findings + check_suspicious_ua(entries, config, compiled)

    if config.get("attack_signature", {}).get("enabled", False):
        result = check_attack_signature(entries, config, compiled)
        findings = findings + result["findings"]
        attack_requests = result["attack_requests"]

    if config.get("http_abnormal", {}).get("enabled", False):
        findings = findings + check_abnormal_method(entries, config)

    # 排个序，严重的排前面，同样严重的按命中次数从多到少
    # sort 的 key 是一个元组，先按等级数字，再按命中次数的负数（负数是让大的排前面）
    findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f["severity"], 0),
        -f["count"]
    ))

    return {
        "findings": findings,
        "attack_requests": attack_requests,
        "summary": count_summary(findings),
        "by_category": count_by_category(findings),
        "high_risk_ips": rank_high_risk_ips(findings, attack_requests),
    }


def count_summary(findings):
    """
    数一下每个危害等级各有多少条，前端那四个数字卡片用的就是这个。
    """
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        level = f["severity"]
        if level in summary:
            summary[level] = summary[level] + 1
        summary["total"] = summary["total"] + 1
    return summary


def count_by_category(findings):
    """
    按检测类别统计数量，用来画饼图。
    """
    counter = Counter()
    for f in findings:
        counter[f["category"]] = counter[f["category"]] + 1

    result = []
    for name, count in counter.most_common():
        result.append({"name": name, "value": count})
    return result


def check_high_frequency(entries, config):
    """
    检测一：单个 IP 访问次数太高。

    道理很简单，正常用户看个网站点几十下就走了，
    如果一个 IP 来了几千次，那基本就是扫描器或者在撞密码。
    """
    cfg = config.get("high_frequency_ip", {})
    threshold = cfg.get("threshold", 300)       # 超过多少次算异常
    top_n = cfg.get("top_n", 10)
    severity = cfg.get("severity", "high")
    category = cfg.get("name", "单IP高频访问")

    # 数每个 IP 来了多少次
    ip_counter = Counter()
    # 数每个 IP 有多少次是错误请求（4xx 和 5xx）
    error_counter = Counter()
    # 每个 IP 访问了多少个不同的路径
    paths_of_ip = {}
    # 每个 IP 主要用的 UA
    agents_of_ip = {}
    # 每个 IP 的访问时间，用来算首次和末次
    times_of_ip = {}

    for e in entries:
        ip = e["ip"]
        if ip == "":
            continue

        ip_counter[ip] = ip_counter[ip] + 1
        if e["status"] >= 400:
            error_counter[ip] = error_counter[ip] + 1

        # setdefault 表示这个 key 不存在就先建一个空的
        paths_of_ip.setdefault(ip, set())
        paths_of_ip[ip].add(e["path"])

        if e["agent"] != "":
            agents_of_ip.setdefault(ip, Counter())
            agents_of_ip[ip][e["agent"][:50]] = agents_of_ip[ip][e["agent"][:50]] + 1

        if e["time"] is not None:
            times_of_ip.setdefault(ip, [])
            times_of_ip[ip].append(e["time"])

    findings = []
    ranked = ip_counter.most_common(top_n)
    for ip, count in ranked:
        # 没到阈值就不报
        if count < threshold:
            break

        error_count = error_counter[ip]
        error_rate = error_count / count * 100 if count > 0 else 0

        # 主要用的 UA，取出现最多的那个
        main_agent = "-"
        if ip in agents_of_ip and len(agents_of_ip[ip]) > 0:
            main_agent = agents_of_ip[ip].most_common(1)[0][0]

        # 首次和末次时间
        first_seen = ""
        last_seen = ""
        if ip in times_of_ip and len(times_of_ip[ip]) > 0:
            times = sorted(times_of_ip[ip])
            first_seen = times[0].strftime("%Y-%m-%d %H:%M:%S")
            last_seen = times[-1].strftime("%Y-%m-%d %H:%M:%S")

        detail = ("这个IP一共请求了 " + str(count) + " 次，错误率 " +
                  ("%.1f" % error_rate) + "%，访问了 " +
                  str(len(paths_of_ip[ip])) + " 个不同的路径，主要UA：" + main_agent)

        findings.append({
            "category": category,
            "rule_id": "HF-IP",
            "severity": severity,
            "target": ip,
            "count": count,
            "detail": detail,
            "evidence": [ip + " 一共请求 " + str(count) + " 次，其中 " +
                         str(error_count) + " 次是错误请求"],
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    return findings


def check_burst(entries, config):
    """
    检测二：单个 IP 在很短时间内突然爆发大量请求。

    这个是"高频检测"的补充。有些扫描器总共请求不算特别多，
    但它是一秒钟十几个地砸过来，这种情况也要抓出来。

    用的方法叫滑动窗口：想象有个固定长度的窗口在时间轴上往右滑，
    窗口里最多能装多少条请求，就是"某段时间内的最大请求数"。
    """
    cfg = config.get("burst_ip", {})
    window_seconds = cfg.get("window_seconds", 60)   # 窗口长度，默认 60 秒
    threshold = cfg.get("threshold", 60)             # 窗口内超过多少次算异常
    top_n = cfg.get("top_n", 10)
    severity = cfg.get("severity", "high")
    category = cfg.get("name", "单IP短时间突发访问")

    # 先把每个 IP 的访问时间都收集起来
    times_of_ip = {}
    for e in entries:
        if e["ip"] == "" or e["time"] is None:
            continue
        times_of_ip.setdefault(e["ip"], [])
        times_of_ip[e["ip"]].append(e["time"])

    results = []
    for ip in times_of_ip:
        times = sorted(times_of_ip[ip])

        # 下面这就是滑动窗口
        # left 是窗口的左边界，right 是右边界，都是下标
        left = 0
        best_count = 0       # 窗口里最多有过多少条
        best_start = None    # 那个窗口的开始时间
        best_end = None      # 那个窗口的结束时间

        for right in range(len(times)):
            # 如果当前窗口跨度超过了设定的秒数，就把左边界往右挪
            while (times[right] - times[left]).total_seconds() > window_seconds:
                left = left + 1
            # 现在 left 到 right 之间的请求都在 window_seconds 秒内
            size = right - left + 1
            if size > best_count:
                best_count = size
                best_start = times[left]
                best_end = times[right]

        if best_count >= threshold:
            results.append((ip, best_count, best_start, best_end))

    # 按窗口内请求数从多到少排
    results.sort(key=lambda x: -x[1])

    findings = []
    for item in results[:top_n]:
        ip = item[0]
        peak = item[1]
        start = item[2]
        end = item[3]

        # 算一下相当于每分钟多少次
        seconds = (end - start).total_seconds()
        if seconds <= 0:
            seconds = 1
        per_minute = peak / seconds * 60

        detail = (str(window_seconds) + " 秒内最多发起了 " + str(peak) +
                  " 次请求（相当于每分钟 " + ("%.0f" % per_minute) +
                  " 次），这是自动化扫描的典型特征")

        findings.append({
            "category": category,
            "rule_id": "BURST-IP",
            "severity": severity,
            "target": ip,
            "count": peak,
            "detail": detail,
            "evidence": [ip + " 在 " + start.strftime("%m-%d %H:%M:%S") +
                         " 到 " + end.strftime("%H:%M:%S") +
                         " 之间发了 " + str(peak) + " 次请求"],
            "first_seen": start.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": end.strftime("%Y-%m-%d %H:%M:%S"),
        })

    return findings


def check_error_rate(entries, config):
    """
    检测三：错误率异常，分三个角度看。

    1. 全站 4xx 比例是不是太高（可能被批量扫描）
    2. 全站 5xx 比例是不是太高（服务端可能出问题了）
    3. 某个 IP 的错误率是不是特别高（这个 IP 可能在乱撞）
    """
    cfg = config.get("error_rate", {})
    global_4xx = cfg.get("global_4xx_threshold", 15.0)
    global_5xx = cfg.get("global_5xx_threshold", 5.0)
    per_ip_rate = cfg.get("per_ip_error_rate", 50.0)
    per_ip_min = cfg.get("per_ip_min_requests", 50)
    top_n = cfg.get("top_n", 10)
    severity = cfg.get("severity", "medium")
    category = cfg.get("name", "4xx/5xx错误率异常")

    total = len(entries)
    findings = []
    if total == 0:
        return findings

    # 数全站的 4xx 和 5xx
    count_4xx = 0
    count_5xx = 0
    for e in entries:
        if 400 <= e["status"] < 500:
            count_4xx = count_4xx + 1
        elif 500 <= e["status"] < 600:
            count_5xx = count_5xx + 1

    rate_4xx = count_4xx / total * 100
    rate_5xx = count_5xx / total * 100

    if rate_4xx > global_4xx:
        findings.append({
            "category": category,
            "rule_id": "ERR-4XX",
            "severity": severity,
            "target": "全站",
            "count": count_4xx,
            "detail": ("全站 4xx 错误有 " + str(count_4xx) + " 次，占 " +
                       ("%.2f" % rate_4xx) + "%，超过了设定的 " +
                       str(global_4xx) + "%"),
            "evidence": ["4xx 占比 " + ("%.2f" % rate_4xx) + "% 超过阈值 " +
                         str(global_4xx) + "%"],
            "first_seen": "",
            "last_seen": "",
        })

    if rate_5xx > global_5xx:
        findings.append({
            "category": category,
            "rule_id": "ERR-5XX",
            "severity": "high",
            "target": "全站",
            "count": count_5xx,
            "detail": ("全站 5xx 错误有 " + str(count_5xx) + " 次，占 " +
                       ("%.2f" % rate_5xx) + "%，超过阈值 " +
                       str(global_5xx) + "%，需要排查服务端"),
            "evidence": ["5xx 占比 " + ("%.2f" % rate_5xx) + "% 超过阈值 " +
                         str(global_5xx) + "%"],
            "first_seen": "",
            "last_seen": "",
        })

    # 再看每个 IP 的错误率
    total_of_ip = Counter()
    error_of_ip = Counter()
    for e in entries:
        if e["ip"] == "":
            continue
        total_of_ip[e["ip"]] = total_of_ip[e["ip"]] + 1
        if e["status"] >= 400:
            error_of_ip[e["ip"]] = error_of_ip[e["ip"]] + 1

    ranked = []
    for ip in total_of_ip:
        count = total_of_ip[ip]
        # 请求太少的 IP 不算，不然只访问 2 次全错了也算 100%，那是噪声
        if count < per_ip_min:
            continue
        error_count = error_of_ip[ip]
        rate = error_count / count * 100
        if rate >= per_ip_rate:
            ranked.append((ip, count, error_count, rate))

    # 按错误率从高到低排
    ranked.sort(key=lambda x: -x[3])

    for item in ranked[:top_n]:
        ip = item[0]
        count = item[1]
        error_count = item[2]
        rate = item[3]

        findings.append({
            "category": category,
            "rule_id": "ERR-IP",
            # 错误率超过 80% 就升级成 high
            "severity": "high" if rate >= 80 else severity,
            "target": ip,
            "count": error_count,
            "detail": ("这个IP一共 " + str(count) + " 次请求，其中 " +
                       str(error_count) + " 次返回错误，错误率 " +
                       ("%.1f" % rate) + "%"),
            "evidence": [ip + "：" + str(error_count) + "/" + str(count) +
                         " 出错，错误率 " + ("%.1f" % rate) + "%"],
            "first_seen": "",
            "last_seen": "",
        })

    return findings


def check_suspicious_ua(entries, config, compiled):
    """
    检测四：可疑的 User-Agent。

    User-Agent 是浏览器告诉网站"我是谁"的一段文字。
    正常浏览器会写 Mozilla/5.0 ... Chrome/120 这种，
    而扫描器会写 sqlmap、nmap、Nikto 这种自己的名字，等于自报家门。
    还有些请求干脆不写 UA，那也可疑。
    """
    cfg = config.get("suspicious_user_agent", {})
    severity = cfg.get("severity", "medium")
    category = cfg.get("name", "可疑User-Agent")

    # 找出所有编译好的 UA 规则的 key
    ua_keys = []
    for key in compiled:
        if key.startswith("ua::"):
            ua_keys.append(key)

    # 用字典记录每个 UA 命中了多少次、涉及哪些 IP
    # key 是 UA 文本，value 又是一个字典
    hits = {}

    for e in entries:
        ua = e["agent"].strip()
        # 空 UA 也当成可疑处理
        if ua == "":
            ua = "-"

        # 拿这个 UA 去试每一条规则
        matched_rule = None
        for key in ua_keys:
            if compiled[key].search(ua):
                matched_rule = key
                break

        # 一条都没命中，但 UA 是空的，也算可疑
        if matched_rule is None and ua == "-":
            matched_rule = "空UA"

        if matched_rule is None:
            continue

        # 记下来，最多存 80 个字符
        short_ua = ua[:80]
        if short_ua not in hits:
            hits[short_ua] = {
                "count": 0,
                "ips": set(),
                "rule": matched_rule,
                "sample": e["raw"][:200],
                "first": None,
                "last": None,
            }

        hits[short_ua]["count"] = hits[short_ua]["count"] + 1
        hits[short_ua]["ips"].add(e["ip"])

        if e["time"] is not None:
            if hits[short_ua]["first"] is None or e["time"] < hits[short_ua]["first"]:
                hits[short_ua]["first"] = e["time"]
            if hits[short_ua]["last"] is None or e["time"] > hits[short_ua]["last"]:
                hits[short_ua]["last"] = e["time"]

    # 转成列表，按命中次数从多到少排
    items = []
    for ua in hits:
        items.append((ua, hits[ua]))
    items.sort(key=lambda x: -x[1]["count"])

    findings = []
    for ua, info in items[:20]:
        # 空 UA 显示成"空 User-Agent"，不然界面上就是个减号不好看
        label = "空 User-Agent" if ua == "-" else ua

        first_seen = ""
        last_seen = ""
        if info["first"] is not None:
            first_seen = info["first"].strftime("%Y-%m-%d %H:%M:%S")
        if info["last"] is not None:
            last_seen = info["last"].strftime("%Y-%m-%d %H:%M:%S")

        findings.append({
            "category": category,
            "rule_id": "UA",
            "severity": severity,
            "target": label,
            "count": info["count"],
            "detail": ("命中了扫描器或自动化工具的特征，涉及 " +
                       str(len(info["ips"])) + " 个IP"),
            "evidence": [info["sample"]],
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    return findings


def check_attack_signature(entries, config, compiled):
    """
    检测五：带攻击特征的请求。

    这一块是核心。规则在 rules.json 里的 attack_signature.rules，
    一共有 12 条，比如：
    - 路径遍历：URL 里有 ../../ 想读系统文件
    - SQL 注入：URL 里有 UNION SELECT 或者 ' or '1'='1
    - 命令注入：URL 里有 ;cat 或者 |whoami

    方法是拿每条日志的 URL（也可以加上 referer 和 UA）去跟这些正则比对，
    命中了就记一条。

    返回 {"findings": 汇总结果, "attack_requests": 命中的原始请求明细}
    """
    cfg = config.get("attack_signature", {})
    rules = cfg.get("rules", [])
    # 默认扫哪些字段，一般是 path，也可以配 referer 和 agent
    default_fields = cfg.get("scan_fields", ["path"])
    default_severity = cfg.get("severity", "critical")
    category = cfg.get("name", "疑似攻击特征请求")

    # 找出每条规则对应的编译好的正则
    # 每条规则可以自己指定扫哪些字段（scan_fields），没指定就用默认的
    rule_list = []
    for rule in rules:
        pattern = compiled.get("attack::" + rule["id"])
        if pattern is None:
            continue
        fields = rule.get("scan_fields", default_fields)
        rule_list.append((rule, pattern, fields))

    # 按规则 ID 汇总
    grouped = {}
    # 命中的原始请求，导出 CSV 用
    attack_requests = []

    for e in entries:
        for rule, pattern, fields in rule_list:
            # 把要扫的字段拼成一段文本，用换行隔开
            # 用换行隔开是为了避免跨字段误判，比如 UA 的结尾和 URL 的开头连在一起
            blob = ""
            for field in fields:
                value = e.get(field, "")
                if value is None:
                    value = ""
                blob = blob + str(value) + "\n"

            if blob.strip() == "":
                continue

            # search 是在文本里找，找到了就返回一个结果，找不到返回 None
            if pattern.search(blob):
                rule_id = rule["id"]

                if rule_id not in grouped:
                    grouped[rule_id] = {
                        "rule": rule,
                        "count": 0,
                        "ips": Counter(),
                        "samples": [],
                        "first": None,
                        "last": None,
                    }

                g = grouped[rule_id]
                g["count"] = g["count"] + 1
                g["ips"][e["ip"]] = g["ips"][e["ip"]] + 1

                if len(g["samples"]) < EVIDENCE_LIMIT:
                    g["samples"].append(e["raw"][:220])

                if e["time"] is not None:
                    if g["first"] is None or e["time"] < g["first"]:
                        g["first"] = e["time"]
                    if g["last"] is None or e["time"] > g["last"]:
                        g["last"] = e["time"]

                # 记一条明细
                attack_requests.append({
                    "rule_id": rule_id,
                    "type": rule["type"],
                    "severity": rule.get("severity", default_severity),
                    "ip": e["ip"],
                    "time": e["time"].strftime("%Y-%m-%d %H:%M:%S") if e["time"] is not None else e["time_raw"],
                    "method": e["method"],
                    "url": e["path"],
                    "status": e["status"],
                    "user_agent": e["agent"][:120],
                    "raw": e["raw"][:300],
                })

                # 一条请求只归到第一个命中的规则，不然同一条会被重复计数
                break

    # 按命中次数排序，转成 findings
    items = []
    for rule_id in grouped:
        items.append((rule_id, grouped[rule_id]))
    items.sort(key=lambda x: -x[1]["count"])

    findings = []
    for rule_id, g in items:
        rule = g["rule"]

        # 列出最主要的几个来源 IP
        top_ips = []
        for ip, count in g["ips"].most_common(3):
            top_ips.append(ip + "(" + str(count) + ")")

        first_seen = ""
        last_seen = ""
        if g["first"] is not None:
            first_seen = g["first"].strftime("%Y-%m-%d %H:%M:%S")
        if g["last"] is not None:
            last_seen = g["last"].strftime("%Y-%m-%d %H:%M:%S")

        findings.append({
            "category": category,
            "rule_id": rule_id,
            "severity": rule.get("severity", default_severity),
            "target": rule["type"],
            "count": g["count"],
            "detail": (rule["description"] + "；涉及 " + str(len(g["ips"])) +
                       " 个IP，主要来源：" + "、".join(top_ips)),
            "evidence": g["samples"],
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    return {"findings": findings, "attack_requests": attack_requests}


def check_abnormal_method(entries, config):
    """
    检测六：异常的请求方法。

    正常网站就用 GET（看页面）和 POST（提交表单），
    如果有人发 PUT、DELETE、TRACE 这种，多半是在探测服务器开了什么功能。
    """
    cfg = config.get("http_abnormal", {})
    # 允许的方法列表，转成大写存起来
    allowed = []
    for m in cfg.get("allowed_methods", ["GET", "POST", "HEAD"]):
        allowed.append(m.upper())
    severity = cfg.get("severity", "medium")
    top_n = cfg.get("top_n", 10)
    category = cfg.get("name", "异常HTTP方法")

    # 数每种方法用了多少次，顺便记下涉及哪些 IP 和一条样本
    counter = Counter()
    ips_of_method = {}
    sample_of_method = {}

    for e in entries:
        method = e["method"].upper()
        if method == "":
            method = "-"
        counter[method] = counter[method] + 1
        ips_of_method.setdefault(method, set())
        ips_of_method[method].add(e["ip"])
        if method not in sample_of_method:
            sample_of_method[method] = e["raw"][:200]

    findings = []
    for method, count in counter.most_common(top_n):
        # 在允许名单里的跳过，空的和减号也跳过
        if method in allowed:
            continue
        if method == "-" or method == "":
            continue

        evidence = []
        if method in sample_of_method:
            evidence.append(sample_of_method[method])

        findings.append({
            "category": category,
            "rule_id": "METHOD-" + method,
            "severity": severity,
            "target": method,
            "count": count,
            "detail": ("不常见的请求方法 " + method + " 出现了 " + str(count) +
                       " 次，涉及 " + str(len(ips_of_method[method])) +
                       " 个IP，可能是在探测服务端开放了哪些功能"),
            "evidence": evidence,
            "first_seen": "",
            "last_seen": "",
        })

    return findings


def rank_high_risk_ips(findings, attack_requests, top_n=10):
    """
    把各个检测里出现的 IP 汇总起来，按危险程度排个名。

    评分办法：命中次数越多分越高，危害等级越高分越高。
    严重的一次算 4 分，高危 3 分，中危 2 分，低危 1 分，再乘以一个跟次数有关的系数。

    注意这里要用 is_valid_ip 过滤一下，
    因为 findings 里的 target 有的是 UA 字符串，不是 IP，不能混进来。
    """
    score_of_ip = {}

    def add(ip, severity, count, category):
        if not is_valid_ip(ip):
            return
        if ip not in score_of_ip:
            score_of_ip[ip] = {
                "ip": ip,
                "score": 0,
                "hits": 0,
                "categories": set(),
                "max_severity": "low",
            }
        rec = score_of_ip[ip]
        level = SEVERITY_ORDER.get(severity, 1)
        # 次数越多系数越大，但用 //10 是为了不让次数特别多的把分数撑爆
        rec["score"] = rec["score"] + level * max(1, count // 10 + 1)
        rec["hits"] = rec["hits"] + count
        rec["categories"].add(category)
        if level > SEVERITY_ORDER.get(rec["max_severity"], 1):
            rec["max_severity"] = severity

    # 来源是两类：以 IP 为主体的检测结果，和攻击请求里的来源 IP
    for f in findings:
        add(f["target"], f["severity"], f["count"], f["category"])

    for r in attack_requests:
        add(r["ip"], r["severity"], 1, "疑似攻击特征请求")

    # 集合不能转成 JSON，先转成列表
    result = []
    for ip in score_of_ip:
        rec = score_of_ip[ip]
        rec["categories"] = sorted(rec["categories"])
        result.append(rec)

    # 按分数从高到低排
    result.sort(key=lambda x: -x["score"])
    return result[:top_n]
