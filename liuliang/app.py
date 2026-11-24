# -*- coding: utf-8 -*-
"""
网站访问日志可视化分析工具，Flask 后端

这个文件负责接前端的请求，然后调用 core/ 下面的函数去干活。

接口：
    GET  /                   主页面
    POST /api/upload         上传日志文件
    POST /api/analyze/text   分析粘贴的日志文本
    POST /api/demo           加载内置演示日志
    GET  /api/export/<kind>  导出 CSV（findings/attacks/ips/all）
    GET  /api/rules          查看规则
    POST /api/rules/reload   重新加载规则
    GET  /api/session/status 会话状态
    GET  /api/sample/download  下载演示日志

分析结果按 session_id 存在内存里，导出 CSV 的时候不用重新解析一遍。
"""

import json
import os
import time
import uuid

from flask import Flask, request, jsonify, render_template, Response, send_file

import core

# ----------------------------------------------------------------------
# 各种路径
# ----------------------------------------------------------------------

# os.path.abspath(__file__) 是当前这个文件的完整路径
# os.path.dirname 取它所在的目录，也就是项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")       # 上传的文件放这
OUTPUT_DIR = os.path.join(BASE_DIR, "output")        # 导出的 CSV 放这
DEMO_LOG = os.path.join(BASE_DIR, "data", "sample_access.log")
RULES_PATH = os.path.join(BASE_DIR, "config", "rules.json")

# 这两个目录要提前建好，不然第一次上传文件会报错
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 建 Flask 应用，告诉它页面模板和静态文件在哪
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))

# 限制上传文件最大 100MB，防止有人传个几个 G 的文件把服务搞挂
# 1024*1024 是 1MB
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# 允许上传的文件后缀
ALLOWED_EXT = [".log", ".txt", ".text", ".access", ".out"]

# 存分析结果的，key 是 session_id，value 是分析结果
# 用全局变量存是简单做法，缺点是服务重启就没了，这个项目够用了
SESSIONS = {}


# ----------------------------------------------------------------------
# 核心流程
# ----------------------------------------------------------------------

def run_analysis(parse_result, source_name):
    """
    统一的流程：解析完之后，先统计，再检测，最后打包。

    参数 parse_result 是 core.parse_file 或者 core.parse_text 的返回值
    参数 source_name 是日志来源的名字，显示在页面上

    返回一个字典，如果解析出来一条都没有就返回带 error 的字典。
    """
    start_clock = time.time()

    entries = parse_result["entries"]
    if len(entries) == 0:
        return {"ok": False, "error": "没从日志里解析出有效记录，检查一下日志格式对不对"}

    # 第一步：统计
    statistics = core.analyze_statistics(entries)

    # 第二步：异常检测
    detection = core.detect_anomalies(entries, RULES_PATH)

    # 算一下花了多少秒
    cost = round(time.time() - start_clock, 3)

    # 取最早和最晚时间
    start_time, end_time = core.get_time_range(parse_result)

    return {
        "ok": True,
        "meta": {
            "source": source_name,
            "total_lines": parse_result["total"],
            "parsed": len(entries),
            "failed": parse_result["failed"],
            "success_rate": parse_result["success_rate"],
            "format": parse_result["format_detected"],
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else None,
            "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else None,
            "elapsed_seconds": cost,
        },
        "statistics": statistics,
        "anomalies": {
            "findings": detection["findings"],
            "summary": detection["summary"],
            "by_category": detection["by_category"],
            "attack_request_count": len(detection["attack_requests"]),
            # 页面表格只显示前 200 条，全部的话浏览器会卡
            "attack_requests": detection["attack_requests"][:200],
            "high_risk_ips": detection["high_risk_ips"],
        },
        # 下面这个不返回给前端，留在内存里给导出 CSV 用
        "_detection": detection,
    }


def public_payload(data):
    """
    去掉内部字段，只留能转成 JSON 返回给前端的部分。
    """
    return {
        "ok": data.get("ok"),
        "meta": data.get("meta"),
        "statistics": data.get("statistics"),
        "anomalies": data.get("anomalies"),
        "error": data.get("error"),
    }


def new_session(data):
    """
    把分析结果存起来，换一个 session_id 给前端。

    session_id 后面导出 CSV 的时候要带上，服务端才知道要导哪次的结果。
    """
    # uuid4() 生成一串随机不重复的字符串，取前 12 位就够了
    session_id = uuid.uuid4().hex[:12]
    SESSIONS[session_id] = data

    # 最多存 20 个，超了就把最早的删掉，不然一直开着内存会涨
    if len(SESSIONS) > 20:
        oldest = None
        for key in SESSIONS:
            oldest = key
            break
        if oldest is not None:
            del SESSIONS[oldest]

    return session_id


# ----------------------------------------------------------------------
# 页面
# ----------------------------------------------------------------------

@app.route("/")
def index():
    """打开首页"""
    return render_template("index.html")


# ----------------------------------------------------------------------
# 接口：上传文件并分析
# ----------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    接收上传的日志文件，解析分析后返回结果。

    request.files 里装着前端传过来的文件，
    用 "file" 这个 key 取，因为前端 FormData 里就是这么命名的。
    """
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "没收到文件"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"ok": False, "error": "文件名为空"}), 400

    # 检查后缀，os.path.splitext 把 "a.log" 切成 ("a", ".log")
    name, ext = os.path.splitext(f.filename)
    ext = ext.lower()
    if ext != "" and ext not in ALLOWED_EXT:
        return jsonify({
            "ok": False,
            "error": "不支持的文件类型 " + ext + "，只支持 " + "、".join(ALLOWED_EXT)
        }), 400

    # 存到 uploads 目录，文件名前面加一段随机数防止重名覆盖
    save_path = os.path.join(UPLOAD_DIR, uuid.uuid4().hex[:8] + "_" + f.filename)
    f.save(save_path)

    try:
        parse_result = core.parse_file(save_path)
        data = run_analysis(parse_result, f.filename)
        if not data.get("ok"):
            return jsonify({"ok": False, "error": data.get("error")}), 400

        session_id = new_session(data)
        payload = public_payload(data)
        payload["session_id"] = session_id
        return jsonify(payload)
    except Exception as ex:
        # 出错了要告诉前端，不然前端一直转圈
        return jsonify({"ok": False, "error": "解析失败：" + str(ex)}), 500


# ----------------------------------------------------------------------
# 接口：分析粘贴的日志文本
# ----------------------------------------------------------------------

@app.route("/api/analyze/text", methods=["POST"])
def api_analyze_text():
    """
    分析前端直接粘贴过来的日志文本。

    前端用 JSON 传过来，格式是 {"text": "日志内容"}
    request.get_json() 把它转成字典。
    """
    body = request.get_json(silent=True)
    if body is None:
        body = {}

    text = body.get("text", "")
    if text.strip() == "":
        return jsonify({"ok": False, "error": "日志内容是空的"}), 400

    parse_result = core.parse_text(text)
    data = run_analysis(parse_result, "粘贴的日志文本")
    if not data.get("ok"):
        return jsonify({"ok": False, "error": data.get("error")}), 400

    session_id = new_session(data)
    payload = public_payload(data)
    payload["session_id"] = session_id
    return jsonify(payload)


# ----------------------------------------------------------------------
# 接口：加载内置演示日志
# ----------------------------------------------------------------------

@app.route("/api/demo", methods=["GET", "POST"])
def api_demo():
    """一键分析项目自带的演示日志，方便演示和测试"""
    if not os.path.exists(DEMO_LOG):
        return jsonify({"ok": False, "error": "演示日志不存在"}), 404

    parse_result = core.parse_file(DEMO_LOG)
    data = run_analysis(parse_result, os.path.basename(DEMO_LOG))
    if not data.get("ok"):
        return jsonify({"ok": False, "error": data.get("error")}), 400

    session_id = new_session(data)
    payload = public_payload(data)
    payload["session_id"] = session_id
    return jsonify(payload)


# ----------------------------------------------------------------------
# 接口：导出 CSV
# ----------------------------------------------------------------------

@app.route("/api/export/<kind>")
def api_export(kind):
    """
    导出 CSV 文件。

    kind 是导出类型：findings、attacks、ips、all
    session_id 通过网址参数传过来，比如 /api/export/findings?session_id=abc123
    """
    session_id = request.args.get("session_id", "")
    if session_id not in SESSIONS:
        return jsonify({"ok": False, "error": "会话过期了，重新分析一次再导出"}), 404

    data = SESSIONS[session_id]
    detection = data.get("_detection")
    if detection is None:
        return jsonify({"ok": False, "error": "这个会话没有检测结果"}), 400

    if kind not in ("findings", "attacks", "ips", "all"):
        return jsonify({"ok": False, "error": "没有这种导出类型：" + kind}), 400

    try:
        content = core.export_csv(detection, kind)
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500

    # 文件名带上时间
    filename = "anomaly_" + kind + "_" + time.strftime("%Y%m%d_%H%M%S") + ".csv"

    # Response 是手动构造一个响应
    # 前面加 "\ufeff" 是 BOM，让 Excel 打开中文不乱码
    return Response(
        "\ufeff" + content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=" + filename},
    )


# ----------------------------------------------------------------------
# 接口：规则相关
# ----------------------------------------------------------------------

@app.route("/api/rules", methods=["GET"])
def api_rules():
    """把当前的规则文件内容返回给前端看"""
    try:
        f = open(RULES_PATH, "r", encoding="utf-8")
        rules = json.load(f)
        f.close()
        return jsonify({"ok": True, "rules": rules})
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


@app.route("/api/rules/reload", methods=["POST"])
def api_rules_reload():
    """
    重新加载规则。

    其实就是再读一遍规则文件，如果文件写错了（比如正则少了括号）这里会报错，
    相当于一个自检功能。
    """
    try:
        core.load_rules(RULES_PATH)
        return jsonify({"ok": True, "message": "规则文件没问题，重新加载完成"})
    except Exception as ex:
        return jsonify({"ok": False, "error": "规则加载失败：" + str(ex)}), 400


# ----------------------------------------------------------------------
# 接口：状态和样例下载
# ----------------------------------------------------------------------

@app.route("/api/session/status")
def api_session_status():
    """看看服务现在的状态，调试用"""
    return jsonify({
        "ok": True,
        "active_sessions": len(SESSIONS),
        "demo_log_exists": os.path.exists(DEMO_LOG),
        "rules_path": RULES_PATH,
    })


@app.route("/api/sample/download")
def api_sample_download():
    """下载内置演示日志"""
    if not os.path.exists(DEMO_LOG):
        return jsonify({"ok": False, "error": "演示日志不存在"}), 404
    return send_file(DEMO_LOG, as_attachment=True,
                     download_name="sample_access.log")


# ----------------------------------------------------------------------
# 启动
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # argparse 是处理命令行参数的，比如 python app.py --port 8080
    import argparse

    parser = argparse.ArgumentParser(description="网站访问日志可视化分析工具")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print("=" * 56)
    print("  网站访问日志可视化分析工具")
    print("  访问地址： http://" + args.host + ":" + str(args.port))
    print("  演示日志： " + DEMO_LOG)
    print("=" * 56)

    app.run(host=args.host, port=args.port, debug=args.debug)
