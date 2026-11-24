# -*- coding: utf-8 -*-
"""
core 包，放项目核心逻辑，和 Flask 没关系，可以单独拿来测。

四个模块：
    parser      日志解析，把文本变成字典
    statistics  统计分析，算趋势、TopN、分布
    detector    异常检测，按 rules.json 里的规则去查
    exporter    结果导出，生成 CSV
"""

# parser 模块的函数
from .parser import parse_file, parse_text, parse_line
from .parser import normalize_path, is_valid_ip, get_time_range

# statistics 模块的函数，起个别名 statistic_analyze 防止名字撞车
from .statistics import analyze as analyze_statistics

# detector 模块的函数
from .detector import detect as detect_anomalies
from .detector import load_rules

# exporter 模块的函数
from .exporter import export as export_csv
from .exporter import save as save_csv

__version__ = "1.0.0"
