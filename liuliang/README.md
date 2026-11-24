# 网站访问日志可视化分析工具

大二项目。导入 Nginx/Apache 访问日志，自动做解析、统计、异常检测，最后用图表把结果展示出来。

## 能干什么

日志导入：拖文件上去或者点按钮选，也可以直接粘一段日志文本。支持 .log/.txt，最大 100MB，一万行以上也不卡。

日志解析：能认出 combined、common、json 三种格式，把 IP、时间、请求方法、URL、状态码、UA 这些字段拆出来。

统计分析：
- 访问量趋势（跨度小按小时，跨度大按天）
- Top 10 访问 IP
- Top 10 访问 URL
- 状态码分布
- 请求方法分布
- 另外还有 24 小时热度、流量统计、UV/PV

异常检测：
- 单个 IP 访问次数过高
- 单个 IP 短时间内突然爆发
- 4xx/5xx 错误率异常
- 可疑 User-Agent
- 12 条攻击特征规则：路径遍历、SQL 注入、XSS、命令注入、WebShell、Log4Shell、SSRF、编码绕过等
- 异常的 HTTP 方法

结果展示：ECharts 画的趋势折线图、饼图、柱状图，外加异常明细表格。

导出：异常汇总、攻击明细、高危 IP 都能导成 CSV，带 BOM，Excel 打开不乱码。

规则改起来很方便，全在 config/rules.json 里，改完下次分析就生效，不用动代码。

## 怎么跑起来

```bash
cd liuliang

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

python app.py
```

然后浏览器开 http://127.0.0.1:5000 ，点页面上那个"加载演示日志"按钮，就能看到一份 12000 行的样例日志分析结果（里面混了 SQL 注入、路径遍历、Log4Shell、扫描器这些攻击流量）。

想换端口就 `python app.py --port 8080`。

## 目录结构

```
liuliang/
├── app.py                  Flask 主程序，路由和接口都在这
├── requirements.txt
├── .gitignore
├── config/
│   └── rules.json          检测规则，阈值和攻击特征
├── core/                   核心逻辑，和 Web 框架没关系，可以单独测
│   ├── parser.py           日志解析，把一行文本变成字典
│   ├── statistics.py       统计分析，算趋势、Top10、分布
│   ├── detector.py         异常检测，按 rules.json 里的规则去查
│   └── exporter.py         结果导出，生成 CSV
├── templates/
│   └── index.html          页面
├── static/
│   ├── css/style.css
│   └── js/
│       ├── echarts.min.js  本地放了一份，断网也能用
│       ├── charts.js       图表
│       └── main.js         交互
├── data/
│   └── sample_access.log   演示日志 12000 行
├── tools/
│   └── generate_log.py     演示日志生成器
├── tests/
│   ├── test_core.py        单元测试
│   └── e2e_check.py        接口自检
├── uploads/                上传的文件，运行时生成
└── output/                 导出的 CSV，运行时生成
```

## 跑测试

```bash
python tests/test_core.py
python tests/e2e_check.py
```

第一个是单元测试加性能测试，第二个用 Flask 测试客户端把所有接口过一遍，不用先起服务。

## 代码看不懂怎么办

代码是刻意写得很基础的，只用到了字典、列表、循环、函数这些最基础的东西，
每个函数上面都写了注释说明它在干什么。

另外 docs/新手讲解.md 里把每个模块"在干什么、为什么这么干"都讲了一遍，
还整理了老师可能会问的问题和演示流程，答辩前看那份就行。

## 检测规则

详细的在 config/rules.json 里，这里列个大概：

| 规则 ID | 类型 | 等级 |
|---|---|---|
| LFI-001/002 | 路径遍历、敏感文件探测 | critical |
| SQLI-001/002/003 | UNION 注入、盲注、注释绕过 | critical-high |
| XSS-001 | 跨站脚本 | high |
| CMDI-001 | 命令注入 | critical |
| RCE-001 | WebShell、后门 | critical |
| SCAN-001 | 后台入口探测 | medium |
| SSRF-001 | 内网探测、危险协议 | high |
| LOG4J-001 | Log4Shell | critical |
| TRAV-001 | 编码绕过 | high |
| HF-IP / BURST-IP | 高频、突发访问 | high |
| ERR-4XX/5XX/IP | 错误率异常 | medium-high |
| UA-* | 可疑 UA | medium |
| METHOD-* | 异常 HTTP 方法 | medium |

比如想把高频 IP 的阈值从 300 次改成 500 次：

```json
"high_frequency_ip": { "threshold": 500 }
```

存盘，重新分析一次就生效了。

## 接口

方便用 Postman 调：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 页面 |
| POST | `/api/upload` | 上传日志文件 |
| POST | `/api/analyze/text` | 分析粘贴的文本，body 是 `{"text": "..."}` |
| POST | `/api/demo` | 加载内置演示日志 |
| GET | `/api/export/findings` | 异常汇总 CSV，要带 session_id |
| GET | `/api/export/attacks` | 攻击明细 CSV |
| GET | `/api/export/ips` | 高危 IP CSV |
| GET | `/api/rules` | 看当前规则 |
| POST | `/api/rules/reload` | 重新加载规则 |
| GET | `/api/sample/download` | 下载演示日志 |

## 用了什么

后端 Python + Flask，解析统计检测都是用标准库写的，只装了 flask 一个包。前端原生 HTML/CSS/JS 加 ECharts 5。测试用 unittest。
