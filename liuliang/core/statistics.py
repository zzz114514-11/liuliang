# -*- coding: utf-8 -*-
"""
统计分析模块

拿解析好的日志（一堆字典）算各种指标，最后打包成一个大字典返回给前端。

主要算这些：
1. 访问量趋势（时间跨度小就按小时，跨度大就按天）
2. Top 10 访问 IP
3. Top 10 访问 URL
4. 状态码分布
5. 请求方法分布

另外顺手算了流量、UV/PV、24 小时热度这些。

统计的时候大量用到 Counter，它是 Python 自带的一个计数工具，
用法很简单：Counter(一个列表)，它就自动帮你数每个元素出现了几次。
"""

from collections import Counter
from datetime import datetime, timedelta

from .parser import normalize_path

# Top 榜取前几名
TOP_N = 10


def analyze(entries, top_n=TOP_N):
    """
    总入口。把下面所有统计都跑一遍，装进一个字典返回。

    参数 entries 是解析好的日志列表，每个元素是一个字典。
    """
    return {
        "overview": count_overview(entries),
        "trend": count_trend(entries),
        "top_ips": count_top_ips(entries, top_n),
        "top_urls": count_top_urls(entries, top_n),
        "status_distribution": count_status(entries),
        "status_detail": count_status_detail(entries, top_n),
        "method_distribution": count_method(entries),
        "hour_distribution": count_hour(entries),
        "top_agents": count_top_agents(entries, top_n),
        "top_referers": count_top_referers(entries, top_n),
    }


def count_overview(entries):
    """
    算几个总体指标：总共多少请求、多少个不同 IP、多少流量、错误率之类的。
    """
    total = len(entries)

    # set 是集合，特点是里面不会有重复元素，用它来数有多少个不同的 IP
    ips = set()
    urls = set()
    total_bytes = 0

    # 分别数 2xx 3xx 4xx 5xx 各有多少条
    count_2xx = 0
    count_3xx = 0
    count_4xx = 0
    count_5xx = 0

    for e in entries:
        if e["ip"] != "":
            ips.add(e["ip"])
        urls.add(normalize_path(e["path"]))
        total_bytes = total_bytes + e["size"]

        status = e["status"]
        if 200 <= status < 300:
            count_2xx = count_2xx + 1
        elif 300 <= status < 400:
            count_3xx = count_3xx + 1
        elif 400 <= status < 500:
            count_4xx = count_4xx + 1
        elif 500 <= status < 600:
            count_5xx = count_5xx + 1

    # 算错误率，记得防住除以 0 的情况
    if total > 0:
        error_rate = round((count_4xx + count_5xx) / total * 100, 2)
        avg_per_ip = round(total / len(ips), 2) if len(ips) > 0 else 0.0
    else:
        error_rate = 0.0
        avg_per_ip = 0.0

    # 找最早和最晚的时间，用来算时间跨度
    times = []
    for e in entries:
        if e["time"] is not None:
            times.append(e["time"])

    start_time = None
    end_time = None
    duration_hours = 0.0
    if len(times) > 0:
        start_time = min(times)
        end_time = max(times)
        # total_seconds() 得到相差的秒数，除以 3600 换成小时
        duration_hours = round((end_time - start_time).total_seconds() / 3600, 2)

    # 每秒请求数
    if duration_hours > 0:
        qps = round(total / (duration_hours * 3600), 2)
    else:
        qps = 0.0

    return {
        "total_requests": total,                      # 总请求数，也就是 PV
        "unique_ips": len(ips),                       # 不同 IP 数，也就是 UV
        "unique_urls": len(urls),
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / 1024 / 1024, 2),
        "count_2xx": count_2xx,
        "count_3xx": count_3xx,
        "count_4xx": count_4xx,
        "count_5xx": count_5xx,
        "error_rate": error_rate,
        "avg_requests_per_ip": avg_per_ip,
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else None,
        "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else None,
        "duration_hours": duration_hours,
        "qps": qps,
    }


def count_trend(entries):
    """
    算访问量随时间的变化，用来画折线图。

    如果日志时间跨度在 2 天以内，就按小时分组；超过 2 天就按天分组，
    不然跨度一个月的话横轴会有七百多个小时的点，图画出来没法看。
    """
    # 先挑出有时间的数据
    timed = []
    for e in entries:
        if e["time"] is not None:
            timed.append(e)

    if len(timed) == 0:
        return {"granularity": "hour", "labels": [], "total": [], "error": []}

    # 找最早和最晚时间
    times = []
    for e in timed:
        times.append(e["time"])
    start = min(times)
    end = max(times)

    # 看跨度几天，决定按小时还是按天
    span_days = (end - start).days
    if span_days <= 2:
        granularity = "hour"
        time_format = "%Y-%m-%d %H:00"
    else:
        granularity = "day"
        time_format = "%Y-%m-%d"

    # 用字典统计每个时间段有多少条
    # key 是时间字符串，比如 "2026-10-29 14:00"，value 是这段时间的访问数
    bucket = {}
    error_bucket = {}

    for e in timed:
        key = e["time"].strftime(time_format)
        # setdefault 的意思是：如果这个 key 还不存在，就先设成 0
        bucket.setdefault(key, 0)
        bucket[key] = bucket[key] + 1

        # 4xx 和 5xx 算错误请求，单独记一份，画图上用红色虚线
        if e["status"] >= 400:
            error_bucket.setdefault(key, 0)
            error_bucket[key] = error_bucket[key] + 1

    # 把时间补齐，中间没有访问的时间段也要有个 0，不然折线图会断开
    labels = _fill_time_axis(sorted(bucket.keys()), granularity)

    total_list = []
    error_list = []
    for key in labels:
        total_list.append(bucket.get(key, 0))
        error_list.append(error_bucket.get(key, 0))

    return {
        "granularity": granularity,
        "labels": labels,
        "total": total_list,
        "error": error_list,
    }


def _fill_time_axis(keys, granularity):
    """
    把时间轴补齐。

    比如日志里 10 点和 12 点有访问，11 点没有，
    那也要把 11 点列出来（值是 0），不然折线图会直接从 10 点连到 12 点。
    """
    if len(keys) == 0:
        return []

    if granularity == "hour":
        fmt = "%Y-%m-%d %H:00"
        step_seconds = 3600        # 一小时 3600 秒
    else:
        fmt = "%Y-%m-%d"
        step_seconds = 86400      # 一天 86400 秒

    try:
        current = datetime.strptime(keys[0], fmt)
        last = datetime.strptime(keys[-1], fmt)
    except ValueError:
        return keys

    result = []
    # 加个上限保护，万一日志时间跨度特别大，别把浏览器卡死
    guard = 0
    while current <= last and guard < 5000:
        result.append(current.strftime(fmt))
        current = current + timedelta(seconds=step_seconds)
        guard = guard + 1

    if len(result) == 0:
        return keys
    return result


def count_top_ips(entries, top_n=TOP_N):
    """
    统计访问次数最多的前 N 个 IP。

    顺便算一下每个 IP 的错误率和流量，方便判断它是不是扫描器。
    """
    # Counter 会自动数每个 IP 出现几次
    ip_counter = Counter()
    error_counter = Counter()
    bytes_counter = Counter()

    for e in entries:
        ip = e["ip"]
        if ip == "":
            continue
        ip_counter[ip] = ip_counter[ip] + 1
        bytes_counter[ip] = bytes_counter[ip] + e["size"]
        if e["status"] >= 400:
            error_counter[ip] = error_counter[ip] + 1

    total = len(entries)
    if total == 0:
        total = 1

    # most_common(n) 直接返回数量最多的前 n 个，格式是 [(元素, 次数), ...]
    result = []
    for ip, count in ip_counter.most_common(top_n):
        error_count = error_counter[ip]
        result.append({
            "ip": ip,
            "count": count,
            "percent": round(count / total * 100, 2),
            "error_count": error_count,
            "error_rate": round(error_count / count * 100, 2) if count > 0 else 0.0,
            "bytes": bytes_counter[ip],
        })
    return result


def count_top_urls(entries, top_n=TOP_N):
    """
    统计访问次数最多的前 N 个 URL。

    这里用 normalize_path 处理过，所以 /user/1001 和 /user/1002 会合并成 /user/{id}。
    """
    url_counter = Counter()
    error_counter = Counter()

    for e in entries:
        url = normalize_path(e["path"])
        url_counter[url] = url_counter[url] + 1
        if e["status"] >= 400:
            error_counter[url] = error_counter[url] + 1

    total = len(entries)
    if total == 0:
        total = 1

    result = []
    for url, count in url_counter.most_common(top_n):
        result.append({
            "url": url,
            "count": count,
            "percent": round(count / total * 100, 2),
            "error_count": error_counter[url],
        })
    return result


def count_status(entries):
    """
    按状态码首位归类，分成 2xx、3xx、4xx、5xx 几类，用来画饼图。

    2xx 是成功，3xx 是重定向，4xx 是客户端错误（比如 404 找不到），
    5xx 是服务端错误（比如 500 服务器内部错误）。
    """
    # 先给每一类都准备一个计数器，初值都是 0
    cats = {
        "2xx 成功": 0,
        "3xx 重定向": 0,
        "4xx 客户端错误": 0,
        "5xx 服务端错误": 0,
        "其它": 0,
    }

    for e in entries:
        s = e["status"]
        if 200 <= s < 300:
            cats["2xx 成功"] = cats["2xx 成功"] + 1
        elif 300 <= s < 400:
            cats["3xx 重定向"] = cats["3xx 重定向"] + 1
        elif 400 <= s < 500:
            cats["4xx 客户端错误"] = cats["4xx 客户端错误"] + 1
        elif 500 <= s < 600:
            cats["5xx 服务端错误"] = cats["5xx 服务端错误"] + 1
        else:
            cats["其它"] = cats["其它"] + 1

    # 前端画饼图要的是 [{"name": 名字, "value": 数量}, ...] 这种格式
    # 数量为 0 的不返回，不然饼图上会出现一个 0% 的块
    result = []
    for name in cats:
        if cats[name] > 0:
            result.append({"name": name, "value": cats[name]})
    return result


def count_status_detail(entries, top_n=TOP_N):
    """
    状态码明细，精确到 200、301、404、500 这种具体的码。
    """
    counter = Counter()
    for e in entries:
        counter[e["status"]] = counter[e["status"]] + 1

    result = []
    for status, count in counter.most_common(top_n):
        # 前端要字符串，所以转成 str
        result.append({"name": str(status), "value": count})
    return result


def count_method(entries):
    """
    统计各种请求方法（GET、POST 之类）各用了多少次。
    """
    counter = Counter()
    for e in entries:
        method = e["method"]
        if method == "":
            method = "-"
        counter[method] = counter[method] + 1

    result = []
    for method, count in counter.most_common():
        result.append({"name": method, "value": count})
    return result


def count_hour(entries):
    """
    统计 0 点到 23 点每个小时各有多少访问，用来看是不是半夜有人扫。

    返回 24 个元素，从 "00:00" 到 "23:00"，就算某个小时一条访问都没有也返回 0。
    """
    counter = Counter()
    for e in entries:
        if e["time"] is not None:
            # .hour 能直接取出小时数，是 0 到 23 之间的整数
            counter[e["time"].hour] = counter[e["time"].hour] + 1

    result = []
    for h in range(24):
        result.append({
            "hour": "%02d:00" % h,      # %02d 表示不足两位前面补 0，比如 5 变成 05
            "value": counter[h],
        })
    return result


def count_top_agents(entries, top_n=TOP_N):
    """
    统计最常见的 User-Agent，看看访问者都用的什么浏览器。

    UA 字符串很长，截断一下，不然图表上显示不下。
    """
    counter = Counter()
    for e in entries:
        if e["agent"] != "":
            counter[_short_text(e["agent"], 60)] = counter[_short_text(e["agent"], 60)] + 1

    total = len(entries)
    if total == 0:
        total = 1

    result = []
    for agent, count in counter.most_common(top_n):
        result.append({
            "agent": agent,
            "count": count,
            "percent": round(count / total * 100, 2),
        })
    return result


def count_top_referers(entries, top_n=TOP_N):
    """
    统计访问来源（从哪个页面跳过来的）。
    """
    counter = Counter()
    for e in entries:
        if e["referer"] != "":
            counter[e["referer"]] = counter[e["referer"]] + 1

    result = []
    for referer, count in counter.most_common(top_n):
        result.append({"referer": referer, "count": count})
    return result


def _short_text(text, limit):
    """
    把太长的文本截断，后面加个省略号。
    """
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."
