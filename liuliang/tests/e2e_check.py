# -*- coding: utf-8 -*-
"""
端到端接口自检

这个脚本用 Flask 自带的测试客户端，把所有接口都请求一遍，
不用先启动服务就能检查有没有问题。

运行：python tests/e2e_check.py
"""

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 测试客户端，用它发请求跟真的浏览器发请求效果一样
c = app.test_client()

print("=" * 60)

# 1. 首页能不能打开
r = c.get("/")
print("[1] GET /                    -> " + str(r.status_code) +
      "，返回 " + str(len(r.data)) + " 字节")
assert r.status_code == 200
assert "网站访问日志可视化分析工具" in r.data.decode("utf-8")

# 2. 加载演示日志
r = c.post("/api/demo")
d = r.get_json()
print("[2] POST /api/demo           -> " + str(r.status_code) +
      "，解析 " + str(d["meta"]["parsed"]) + " 条，成功率 " +
      str(d["meta"]["success_rate"]) + "%")
assert r.status_code == 200 and d["ok"]
session_id = d["session_id"]

# 3. 四种 CSV 导出
for kind in ["findings", "attacks", "ips", "all"]:
    r = c.get("/api/export/" + kind + "?session_id=" + session_id)
    text = r.data.decode("utf-8-sig")
    lines = text.splitlines()
    print("[3] 导出 " + kind.ljust(9) + "        -> " + str(r.status_code) +
          "，" + str(len(lines)) + " 行")
    assert r.status_code == 200 and len(lines) > 1

# 4. 上传文件
log_path = os.path.join(BASE, "data", "sample_access.log")
f = open(log_path, "rb")
file_data = {"file": (io.BytesIO(f.read()), "access.log")}
f.close()
r = c.post("/api/upload", data=file_data, content_type="multipart/form-data")
d = r.get_json()
print("[4] POST /api/upload         -> " + str(r.status_code) +
      "，解析 " + str(d["meta"]["parsed"]) + " 条，格式 " + d["meta"]["format"])
assert r.status_code == 200 and d["ok"]

# 5. 粘贴文本分析
text = ('1.2.3.4 - - [10/Oct/2026:10:00:01 +0800] '
        '"GET /x?a=1 UNION SELECT 1 HTTP/1.1" 500 100 "-" "sqlmap/1.0"\n'
        '5.6.7.8 - - [10/Oct/2026:10:00:02 +0800] '
        '"GET / HTTP/1.1" 200 900 "-" "Mozilla/5.0"\n')
r = c.post("/api/analyze/text", json={"text": text})
d = r.get_json()
print("[5] 粘贴文本分析             -> " + str(r.status_code) +
      "，发现 " + str(d["anomalies"]["summary"]["total"]) + " 项异常")
assert r.status_code == 200

# 6. 规则接口
r = c.get("/api/rules")
d = r.get_json()
rule_count = len(d["rules"]["attack_signature"]["rules"])
print("[6] GET /api/rules           -> " + str(r.status_code) +
      "，攻击规则 " + str(rule_count) + " 条")
assert r.status_code == 200 and rule_count >= 5

# 7. 上传不支持的文件类型，应该被拒绝
r = c.post("/api/upload",
           data={"file": (io.BytesIO(b"hello world\n" * 5), "bad.exe")},
           content_type="multipart/form-data")
print("[7] 上传 .exe                -> " + str(r.status_code) + "（应该是 400 拒绝）")
assert r.status_code == 400

# 8. 用不存在的 session_id 导出，应该报 404
r = c.get("/api/export/findings?session_id=不存在")
print("[8] 无效 session 导出        -> " + str(r.status_code) + "（应该是 404）")
assert r.status_code == 404

print("=" * 60)
print("  全部接口自检通过")
