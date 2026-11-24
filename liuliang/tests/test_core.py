# -*- coding: utf-8 -*-
"""
单元测试

单元测试就是写一堆小函数，分别验证每个功能对不对。
以后改了代码，跑一遍测试就知道有没有改坏。

运行：
    python tests/test_core.py
    或者：python -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

# 把项目根目录加到搜索路径里，这样才能 import core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(BASE, "config", "rules.json")
DEMO = os.path.join(BASE, "data", "sample_access.log")


# ----------------------------------------------------------------------
# 测试用的几行日志
# ----------------------------------------------------------------------

# combined 格式，最完整的那种
COMBINED_LINE = (
    '192.168.1.100 - - [10/Oct/2026:13:55:36 +0800] '
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"https://www.google.com/" "Mozilla/5.0 (Windows NT 10.0)"'
)

# common 格式，没有 referer 和 UA
COMMON_LINE = (
    '10.0.0.5 - admin [10/Oct/2026:13:56:00 +0800] '
    '"POST /login HTTP/1.1" 302 128'
)

# json 格式
JSON_LINE = ('{"remote_addr":"8.8.8.8","time_local":"2026-10-10T13:57:00",'
             '"request_method":"GET","request_uri":"/api","status":200,'
             '"body_bytes_sent":"512","http_user_agent":"curl/8.0"}')

# 一条乱写的，应该解析失败
BAD_LINE = 'this is not a valid log line at all'

# 带 SQL 注入的
SQLI_LINE = (
    '45.155.205.19 - - [10/Oct/2026:14:00:00 +0800] '
    '"GET /item?id=1 UNION SELECT username,password FROM users HTTP/1.1" 500 200 '
    '"-" "sqlmap/1.7.11#stable"'
)

# 带路径遍历的
TRAVERSAL_LINE = (
    '89.248.165.201 - - [10/Oct/2026:14:01:00 +0800] '
    '"GET /../../../../etc/passwd HTTP/1.1" 404 162 "-" "Nikto/2.5.0"'
)

# 一条完全正常的，用来验证不会误报
NORMAL_UA_LINE = (
    '223.104.3.7 - - [10/Oct/2026:14:02:00 +0800] '
    '"GET /products HTTP/1.1" 200 4096 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"'
)


# ----------------------------------------------------------------------
# 测试解析
# ----------------------------------------------------------------------

class TestParser(unittest.TestCase):

    def test_parse_combined(self):
        """combined 格式的每个字段都要对"""
        e = core.parse_line(COMBINED_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["ip"], "192.168.1.100")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["path"], "/index.html")
        self.assertEqual(e["status"], 200)
        self.assertEqual(e["size"], 2326)
        self.assertEqual(e["protocol"], "HTTP/1.1")
        self.assertIn("Mozilla", e["agent"])
        self.assertIn("google.com", e["referer"])
        self.assertIsNotNone(e["time"])
        self.assertEqual(e["time"].year, 2026)
        self.assertEqual(e["time"].month, 10)
        self.assertEqual(e["time"].hour, 13)

    def test_parse_common(self):
        """common 格式没有 UA 和 referer"""
        e = core.parse_line(COMMON_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["ip"], "10.0.0.5")
        self.assertEqual(e["user"], "admin")
        self.assertEqual(e["method"], "POST")
        self.assertEqual(e["status"], 302)
        self.assertEqual(e["agent"], "")

    def test_parse_json(self):
        e = core.parse_line(JSON_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["ip"], "8.8.8.8")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["path"], "/api")
        self.assertEqual(e["status"], 200)

    def test_parse_invalid(self):
        """乱写的行应该返回 None，不能报错"""
        self.assertIsNone(core.parse_line(BAD_LINE))
        self.assertIsNone(core.parse_line(""))
        self.assertIsNone(core.parse_line("   "))

    def test_parse_text_stats(self):
        """三行里有两行能解析出来，成功率应该是 66.67%"""
        text = "\n".join([COMBINED_LINE, COMMON_LINE, BAD_LINE, ""])
        r = core.parse_text(text)
        self.assertEqual(r["total"], 3)
        self.assertEqual(len(r["entries"]), 2)
        self.assertEqual(r["failed"], 1)
        self.assertEqual(r["success_rate"], 66.67)
        self.assertEqual(len(r["parse_errors"]), 1)

    def test_normalize_path(self):
        """数字 id 要被折叠成 {id}"""
        self.assertEqual(core.normalize_path("/user/1001"), "/user/{id}")
        self.assertEqual(core.normalize_path("/user/1002"), "/user/{id}")
        self.assertEqual(core.normalize_path("/article/256"), "/article/{id}")
        self.assertEqual(core.normalize_path("/static/a.css"), "/static/a.css")
        self.assertEqual(core.normalize_path("-"), "-")

    def test_is_valid_ip(self):
        self.assertTrue(core.is_valid_ip("192.168.1.1"))
        self.assertTrue(core.is_valid_ip("8.8.8.8"))
        self.assertFalse(core.is_valid_ip("999.1.1.1"))
        self.assertFalse(core.is_valid_ip("abc"))
        self.assertFalse(core.is_valid_ip(""))

    def test_parse_demo_file(self):
        """演示日志应该全部解析成功"""
        if not os.path.exists(DEMO):
            return      # 演示日志还没生成就跳过
        r = core.parse_file(DEMO)
        self.assertGreaterEqual(r["total"], 10000)
        self.assertEqual(r["failed"], 0)
        self.assertEqual(r["format_detected"], "combined")
        self.assertEqual(r["success_rate"], 100.0)


# ----------------------------------------------------------------------
# 测试统计
# ----------------------------------------------------------------------

class TestStatistics(unittest.TestCase):

    def setUp(self):
        """setUp 会在每个测试方法跑之前先执行，这里准备好 5 条日志"""
        self.entries = []
        for line in [COMBINED_LINE, COMMON_LINE, SQLI_LINE,
                     TRAVERSAL_LINE, NORMAL_UA_LINE]:
            e = core.parse_line(line)
            if e is not None:
                self.entries.append(e)
        self.stats = core.analyze_statistics(self.entries)

    def test_overview(self):
        o = self.stats["overview"]
        self.assertEqual(o["total_requests"], 5)
        self.assertEqual(o["unique_ips"], 5)
        self.assertEqual(o["count_2xx"], 2)
        self.assertEqual(o["count_4xx"], 1)
        self.assertEqual(o["count_5xx"], 1)

    def test_top_ips(self):
        ips = self.stats["top_ips"]
        self.assertTrue(len(ips) <= 10)
        self.assertEqual(ips[0]["count"], 1)

    def test_status_distribution(self):
        d = {}
        for item in self.stats["status_distribution"]:
            d[item["name"]] = item["value"]
        self.assertEqual(d.get("2xx 成功"), 2)
        self.assertEqual(d.get("4xx 客户端错误"), 1)
        self.assertEqual(d.get("5xx 服务端错误"), 1)
        self.assertEqual(d.get("3xx 重定向"), 1)

    def test_method_distribution(self):
        d = {}
        for item in self.stats["method_distribution"]:
            d[item["name"]] = item["value"]
        self.assertEqual(d.get("GET"), 4)
        self.assertEqual(d.get("POST"), 1)

    def test_trend(self):
        self.assertGreater(len(self.stats["trend"]["labels"]), 0)
        # 标签数量和数值数量要一样，不然图会画错
        self.assertEqual(len(self.stats["trend"]["labels"]),
                         len(self.stats["trend"]["total"]))

    def test_hour_distribution(self):
        """24 小时热度应该正好是 24 个元素"""
        self.assertEqual(len(self.stats["hour_distribution"]), 24)


# ----------------------------------------------------------------------
# 测试异常检测
# ----------------------------------------------------------------------

class TestDetector(unittest.TestCase):

    def detect_one(self, line):
        """小工具：检测单独一行日志"""
        e = core.parse_line(line)
        return core.detect_anomalies([e], RULES)

    def rule_ids(self, result):
        ids = []
        for f in result["findings"]:
            ids.append(f["rule_id"])
        return ids

    def test_detect_sqli(self):
        """UNION SELECT 要能被抓到"""
        r = self.detect_one(SQLI_LINE)
        self.assertIn("SQLI-001", self.rule_ids(r))
        self.assertEqual(len(r["attack_requests"]), 1)

    def test_detect_traversal(self):
        """../../ 要能被抓到"""
        r = self.detect_one(TRAVERSAL_LINE)
        self.assertIn("LFI-001", self.rule_ids(r))

    def test_detect_suspicious_ua(self):
        """sqlmap 这种扫描器 UA 要能被识别"""
        r = self.detect_one(SQLI_LINE)
        categories = []
        for f in r["findings"]:
            categories.append(f["category"])
        self.assertIn("可疑User-Agent", categories)

    def test_no_false_positive_on_normal_ua(self):
        """
        回归测试：正常 Chrome 的 UA 里有 120.0.0.0 这种版本号，
        不能因为它长得像内网 IP 就报 SSRF，以前出过这个 bug。
        """
        r = self.detect_one(NORMAL_UA_LINE)
        self.assertNotIn("SSRF-001", self.rule_ids(r))
        # 正常的访问一条严重告警都不该有
        critical_count = 0
        for f in r["findings"]:
            if f["severity"] == "critical":
                critical_count = critical_count + 1
        self.assertEqual(critical_count, 0)

    def test_high_frequency_ip(self):
        """造 400 条同一个 IP 的请求，应该触发高频告警"""
        entries = []
        for i in range(400):
            line = ('45.155.205.19 - - [10/Oct/2026:14:%02d:00 +0800] '
                    '"GET /admin HTTP/1.1" 404 162 "-" "sqlmap/1.7"' % (i % 60))
            e = core.parse_line(line)
            entries.append(e)
        r = core.detect_anomalies(entries, RULES)
        self.assertIn("HF-IP", self.rule_ids(r))

    def test_high_risk_ips_only_ip(self):
        """
        回归测试：高危 IP 榜里只能有 IP，不能混进 UA 字符串，
        以前出过这个 bug。
        """
        entries = []
        for line in [SQLI_LINE, TRAVERSAL_LINE, NORMAL_UA_LINE]:
            e = core.parse_line(line)
            entries.append(e)
        r = core.detect_anomalies(entries, RULES)
        for item in r["high_risk_ips"]:
            self.assertTrue(core.is_valid_ip(item["ip"]),
                            "高危榜里混进了不是 IP 的东西：" + item["ip"])

    def test_rules_count(self):
        """攻击规则不能少于 5 条，任务书要求的"""
        config, compiled = core.load_rules(RULES)
        rules = config["attack_signature"]["rules"]
        self.assertGreaterEqual(len(rules), 5)


# ----------------------------------------------------------------------
# 测试导出
# ----------------------------------------------------------------------

class TestExporter(unittest.TestCase):

    def setUp(self):
        entries = []
        for line in [SQLI_LINE, TRAVERSAL_LINE]:
            e = core.parse_line(line)
            entries.append(e)
        self.result = core.detect_anomalies(entries, RULES)

    def test_export_findings(self):
        text = core.export_csv(self.result, "findings")
        self.assertIn("检测类别", text)
        # 表头加数据，至少两行
        self.assertGreater(len(text.splitlines()), 1)

    def test_export_attacks(self):
        text = core.export_csv(self.result, "attacks")
        self.assertIn("规则ID", text)
        self.assertIn("SQLI-001", text)

    def test_export_all(self):
        text = core.export_csv(self.result, "all")
        self.assertIn("异常发现汇总", text)
        self.assertIn("攻击特征请求明细", text)

    def test_export_bad_kind(self):
        """传个不存在的类型应该报错"""
        try:
            core.export_csv(self.result, "乱写的")
            self.fail("这里应该报错才对")
        except ValueError:
            pass        # 报错了就对了


# ----------------------------------------------------------------------
# 性能测试
# ----------------------------------------------------------------------

class TestPerformance(unittest.TestCase):

    def test_performance_10k(self):
        """一万行日志要在 5 秒内跑完解析加统计加检测"""
        if not os.path.exists(DEMO):
            return

        start = time.time()
        parse_result = core.parse_file(DEMO)
        core.analyze_statistics(parse_result["entries"])
        detection = core.detect_anomalies(parse_result["entries"], RULES)
        cost = time.time() - start

        self.assertGreaterEqual(parse_result["total"], 10000)
        self.assertGreater(detection["summary"]["total"], 0)
        self.assertLess(cost, 5.0)

        print("")
        print("[性能] " + str(parse_result["total"]) + " 行，解析加统计加检测共 " +
              ("%.2f" % cost) + " 秒，发现 " +
              str(detection["summary"]["total"]) + " 项异常")


if __name__ == "__main__":
    unittest.main(verbosity=2)
