# -*- coding: utf-8 -*-
"""
结果导出模块

把检测结果写成 CSV 格式的字符串。

CSV 就是逗号分隔的文本，每行一条记录，字段之间用逗号隔开，
Excel 能直接打开。

有个坑要注意：直接用 utf-8 编码存 CSV，Excel 打开中文会乱码。
解决办法是在文件开头写一个特殊标记叫 BOM，Excel 看到它就知道这是 utf-8。
这个标记就是 "\ufeff" 这一个字符。
"""

import csv
import io
import os
from datetime import datetime


def export_findings(result):
    """
    导出异常汇总：每条检测结果一行。

    参数 result 是 detector.detect() 返回的那个大字典。
    """
    # StringIO 可以理解成"内存里的一个文件"，csv.writer 往里面写
    buf = io.StringIO()
    writer = csv.writer(buf)

    # 先写表头
    writer.writerow([
        "检测类别", "规则ID", "危害等级", "目标", "命中次数",
        "说明", "首次出现", "最后出现", "证据样本"
    ])

    # 再写每一行数据
    for f in result["findings"]:
        # evidence 是个列表，用竖线连起来写成一格
        evidence = " | ".join(f["evidence"]) if len(f["evidence"]) > 0 else ""
        writer.writerow([
            f["category"],
            f["rule_id"],
            f["severity"],
            f["target"],
            f["count"],
            f["detail"],
            f["first_seen"],
            f["last_seen"],
            evidence,
        ])

    # getvalue() 把内存文件里的内容取出来，就是一段字符串
    return buf.getvalue()


def export_attack_requests(result):
    """
    导出命中攻击特征的具体请求，一条请求一行。
    这个最有用，安全人员拿到可以直接看到是谁在什么时候打了什么 URL。
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow([
        "规则ID", "攻击类型", "危害等级", "来源IP", "时间",
        "请求方法", "请求URL", "状态码", "User-Agent"
    ])

    for r in result["attack_requests"]:
        writer.writerow([
            r.get("rule_id", ""),
            r.get("type", ""),
            r.get("severity", ""),
            r.get("ip", ""),
            r.get("time", ""),
            r.get("method", ""),
            r.get("url", ""),
            r.get("status", ""),
            r.get("user_agent", ""),
        ])

    return buf.getvalue()


def export_high_risk_ips(result):
    """
    导出高危 IP 排行。
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["IP", "风险评分", "命中请求数", "最高危害等级", "涉及检测类别"])

    for r in result["high_risk_ips"]:
        # categories 是个列表，用顿号连起来
        writer.writerow([
            r["ip"],
            r["score"],
            r["hits"],
            r["max_severity"],
            "、".join(r["categories"]),
        ])

    return buf.getvalue()


def export(result, kind="findings"):
    """
    统一的导出入口。

    kind 可以是：
        findings  异常汇总
        attacks   攻击请求明细
        ips       高危 IP 排行
        all       三样都要，拼在一起
    """
    if kind == "findings":
        return export_findings(result)
    if kind == "attacks":
        return export_attack_requests(result)
    if kind == "ips":
        return export_high_risk_ips(result)
    if kind == "all":
        return "\n\n".join([
            "异常发现汇总",
            export_findings(result),
            "攻击特征请求明细",
            export_attack_requests(result),
            "高危IP排行",
            export_high_risk_ips(result),
        ])

    # 都不是就报错，让调用的人知道写错了
    raise ValueError("没有这种导出类型：" + kind)


def save(content, directory="output", prefix="anomaly"):
    """
    把 CSV 内容存成文件，返回文件路径。

    文件名里带上时间，比如 anomaly_20261102_193000.csv，
    这样多次导出不会相互覆盖。
    """
    # 目录不存在就建一个，exist_ok=True 表示已存在也不报错
    os.makedirs(directory, exist_ok=True)

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(directory, prefix + "_" + now + ".csv")

    # utf-8-sig 这种编码会自动在文件开头写上 BOM，Excel 打开就不乱码了
    f = open(path, "w", encoding="utf-8-sig", newline="")
    f.write(content)
    f.close()

    return path
