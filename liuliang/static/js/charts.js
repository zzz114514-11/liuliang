// charts.js  所有 ECharts 图表的配置都在这里
// main.js 只管传数据进来，不单独拼 option

const Charts = (() => {

    /** 主调色板（与 CSS 渐变体系一致） */
    const PALETTE = ['#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#ec4899',
                     '#8b5cf6', '#0ea5e9', '#14b8a6', '#f97316', '#a855f7'];

    /** 危害等级颜色 */
    const SEV_COLOR = { critical: '#e11d48', high: '#ea580c', medium: '#d97706', low: '#0891b2' };

    /** 状态码语义色 */
    const STATUS_COLOR = {
        '2xx 成功': '#10b981', '3xx 重定向': '#0ea5e9',
        '4xx 客户端错误': '#f59e0b', '5xx 服务端错误': '#e11d48', '其它': '#94a3b8'
    };

    const instances = {};

    // 公共样式片段

    /** 统一浮层：白底、圆角、轻阴影 */
    const tooltip = Object.assign({
        backgroundColor: 'rgba(255,255,255,.96)',
        borderColor: 'rgba(148,163,184,.35)', borderWidth: 1,
        padding: [10, 14],
        textStyle: { color: '#0f172a', fontSize: 12.5 },
        extraCssText: 'box-shadow:0 10px 28px -8px rgba(15,23,42,.22);border-radius:10px;'
    });

    /** 统一标题 */
    const title = (text, sub) => ({
        text, subtext: sub || '',
        left: 'center', top: 8,
        itemGap: 4,
        textStyle: { fontSize: 14.5, fontWeight: 700, color: '#0f172a', letterSpacing: .5 },
        subtextStyle: { fontSize: 11.5, color: '#94a3b8' }
    });

    /** 统一网格 */
    const grid = { left: 22, right: 26, top: 56, bottom: 26, containLabel: true };

    /** 统一坐标轴文字 */
    const axisLabel = { color: '#64748b', fontSize: 11 };
    const splitLine = { lineStyle: { color: 'rgba(148,163,184,.16)' } };

    /** 统一入场动画 */
    const ANIM = { animationDuration: 700, animationEasing: 'cubicOut' };

    function get(id) {
        if (!instances[id]) {
            const el = document.getElementById(id);
            if (!el) return null;
            instances[id] = echarts.init(el);
        }
        return instances[id];
    }

    window.addEventListener('resize', () => {
        Object.values(instances).forEach(c => c && c.resize());
    });

    function emptyOption(msg) {
        return {
            title: { text: msg, left: 'center', top: 'middle',
                     textStyle: { color: '#a5b4c4', fontSize: 13.5, fontWeight: 'normal' } }
        };
    }

    /** 面积渐变（图表面积填充用） */
    function areaGrad(color) {
        return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: color.replace('rgb', 'rgba').replace(')', ',0.26)') },
            { offset: 1, color: color.replace('rgb', 'rgba').replace(')', ',0.01)') }
        ]);
    }

    return {
        PALETTE, SEV_COLOR, STATUS_COLOR,

        // 1. 时间趋势（折线+错误叠加）
        trend(id, data) {
            const c = get(id); if (!c) return;
            if (!data || !data.labels || !data.labels.length) { c.setOption(emptyOption('暂无趋势数据'), true); return; }

            const many = data.labels.length > 15;
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, { trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: 'rgba(99,102,241,.4)' } } }),
                legend: { data: ['总访问量', '错误请求 (4xx/5xx)'], top: 34, left: 'center',
                          itemWidth: 14, itemHeight: 8, itemGap: 22,
                          textStyle: { color: '#64748b', fontSize: 12 } },
                grid: Object.assign({}, grid, { top: 72, bottom: many ? 52 : 30 }),
                xAxis: {
                    type: 'category', data: data.labels, boundaryGap: false,
                    axisLabel: Object.assign({}, axisLabel, { rotate: many ? 40 : 0 }),
                    axisLine: { lineStyle: { color: 'rgba(148,163,184,.4)' } },
                    axisTick: { show: false }
                },
                yAxis: {
                    type: 'value', name: '请求数',
                    nameTextStyle: { color: '#94a3b8', fontSize: 11 },
                    splitLine, axisLabel, max: v => Math.ceil(v.max * 1.12)
                },
                dataZoom: data.labels.length > 30
                    ? [{ type: 'inside' }, { type: 'slider', height: 14, bottom: 10,
                        borderColor: 'transparent', backgroundColor: 'rgba(99,102,241,.07)',
                        fillerColor: 'rgba(99,102,241,.16)',
                        handleStyle: { color: '#6366f1', borderColor: '#6366f1' },
                        textStyle: { color: '#94a3b8', fontSize: 10 } }]
                    : [],
                series: [
                    {
                        name: '总访问量', type: 'line', smooth: .42, symbol: 'none',
                        data: data.total,
                        lineStyle: { width: 2.6, color: '#6366f1',
                                     shadowColor: 'rgba(99,102,241,.35)', shadowBlur: 10, shadowOffsetY: 6 },
                        areaStyle: { color: areaGrad('rgb(99,102,241)') },
                        emphasis: { lineStyle: { width: 3.2 } }
                    },
                    {
                        name: '错误请求 (4xx/5xx)', type: 'line', smooth: .42, symbol: 'none',
                        data: data.error,
                        lineStyle: { width: 2, type: 'dashed', color: '#e11d48' },
                        areaStyle: { color: areaGrad('rgb(225,29,72)') }
                    }
                ]
            }, ANIM), true);
        },

        // 2. Top IP（横向渐变柱）
        topIp(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const d = list.slice().reverse();
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, {
                    trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(99,102,241,.06)' } },
                    formatter: p => {
                        const it = d[p[0].dataIndex];
                        return `<b style="font-family:Consolas">${it.ip}</b><br/>` +
                               `请求数　${it.count.toLocaleString()}（${it.percent}%）<br/>` +
                               `错误数　${it.error_count}（错误率 ${it.error_rate}%）<br/>` +
                               `流量　　${(it.bytes / 1024).toFixed(1)} KB`;
                    }
                }),
                title: title('Top 10 访问 IP', '悬停查看错误率与流量'),
                grid: Object.assign({}, grid, { right: 66, top: 62 }),
                xAxis: { type: 'value', splitLine, axisLabel },
                yAxis: {
                    type: 'category', data: d.map(x => x.ip),
                    axisLabel: Object.assign({}, axisLabel, {
                        fontFamily: 'Consolas, monospace', fontSize: 11.5, color: '#334155'
                    }),
                    axisTick: { show: false }
                },
                series: [{
                    type: 'bar', data: d.map(x => x.count), barWidth: '58%',
                    itemStyle: {
                        borderRadius: [0, 6, 6, 0],
                        color: p => {
                            // 高错误率 IP 标红，其余用主渐变
                            if (d[p.dataIndex].error_rate > 50)
                                return new echarts.graphic.LinearGradient(0, 0, 1, 0,
                                    [{ offset: 0, color: '#f43f5e' }, { offset: 1, color: '#e11d48' }]);
                            return new echarts.graphic.LinearGradient(0, 0, 1, 0,
                                [{ offset: 0, color: '#818cf8' }, { offset: 1, color: '#6366f1' }]);
                        }
                    },
                    label: { show: true, position: 'right', fontSize: 10.5,
                             color: '#64748b', fontFamily: 'Consolas' }
                }]
            }, ANIM), true);
        },

        // 3. Top URL
        topUrl(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const d = list.slice().reverse();
            const short = s => s.length > 36 ? s.slice(0, 36) + '…' : s;
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, {
                    trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(6,182,212,.06)' } },
                    formatter: p => {
                        const it = d[p[0].dataIndex];
                        return `<b style="font-family:Consolas;font-size:11px">${it.url}</b><br/>` +
                               `访问　${it.count.toLocaleString()}（${it.percent}%）<br/>错误　${it.error_count}`;
                    }
                }),
                title: title('Top 10 访问 URL', '路径已归一化（数字ID折叠）'),
                grid: Object.assign({}, grid, { right: 60, top: 62 }),
                xAxis: { type: 'value', splitLine, axisLabel },
                yAxis: {
                    type: 'category', data: d.map(x => short(x.url)),
                    axisLabel: Object.assign({}, axisLabel, {
                        fontFamily: 'Consolas, monospace', fontSize: 11, color: '#334155'
                    }),
                    axisTick: { show: false }
                },
                series: [{
                    type: 'bar', data: d.map(x => x.count), barWidth: '58%',
                    itemStyle: {
                        borderRadius: [0, 6, 6, 0],
                        color: new echarts.graphic.LinearGradient(0, 0, 1, 0,
                            [{ offset: 0, color: '#22d3ee' }, { offset: 1, color: '#0891b2' }])
                    },
                    label: { show: true, position: 'right', fontSize: 10.5,
                             color: '#64748b', fontFamily: 'Consolas' }
                }]
            }, ANIM), true);
        },

        // 4. 状态码分布（环形+中心汇总）
        status(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const total = list.reduce((a, b) => a + b.value, 0);
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, { trigger: 'item', formatter: '{b}: {c} ({d}%)' }),
                title: title('状态码分布', '按首位归类'),
                legend: {
                    bottom: 4, itemWidth: 10, itemHeight: 10, itemGap: 14,
                    icon: 'circle',
                    textStyle: { fontSize: 12, color: '#475569' }
                },
                series: [{
                    type: 'pie', radius: ['50%', '70%'], center: ['50%', '52%'],
                    avoidLabelOverlap: true,
                    itemStyle: { borderColor: '#fff', borderWidth: 3 },
                    label: { formatter: '{b}\n{d}%', fontSize: 11.5, color: '#475569', lineHeight: 17 },
                    emphasis: {
                        scale: true, scaleSize: 6,
                        itemStyle: { shadowBlur: 22, shadowColor: 'rgba(15,23,42,.3)' }
                    },
                    data: list.map(x => ({
                        name: x.name, value: x.value,
                        itemStyle: { color: STATUS_COLOR[x.name] || '#94a3b8' }
                    })),
                    // 中心总数标签
                    labelLine: { length: 14, length2: 8, lineStyle: { color: '#cbd5e1' } }
                }, {
                    type: 'pie', radius: ['0%', '0%'], center: ['50%', '52%'],
                    silent: true,
                    label: {
                        position: 'center',
                        formatter: () => `{v|${total.toLocaleString()}}\n{t|总请求}`,
                        rich: {
                            v: { fontSize: 24, fontWeight: 800, color: '#0f172a', lineHeight: 30 },
                            t: { fontSize: 11.5, color: '#94a3b8' }
                        }
                    },
                    data: [{ value: 1 }]
                }]
            }, ANIM), true);
        },

        // 5. 状态码明细（柱状）
        statusDetail(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const colorOf = s => {
                const n = parseInt(s, 10);
                if (n >= 500) return '#e11d48';
                if (n >= 400) return '#f59e0b';
                if (n >= 300) return '#0ea5e9';
                return '#10b981';
            };
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, { trigger: 'axis', axisPointer: { type: 'shadow' } }),
                title: title('状态码明细 Top 10'),
                grid: Object.assign({}, grid, { bottom: 34 }),
                xAxis: {
                    type: 'category', data: list.map(x => x.name),
                    axisLabel: Object.assign({}, axisLabel, {
                        fontFamily: 'Consolas, monospace', fontSize: 11.5, color: '#334155'
                    }),
                    axisTick: { show: false }
                },
                yAxis: { type: 'value', splitLine, axisLabel },
                series: [{
                    type: 'bar', data: list.map(x => x.value), barWidth: '52%',
                    itemStyle: {
                        borderRadius: [7, 7, 0, 0],
                        color: p => new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: colorOf(list[p.dataIndex].name) },
                            { offset: 1, color: colorOf(list[p.dataIndex].name) + '88' }
                        ])
                    },
                    label: { show: true, position: 'top', fontSize: 10.5,
                             color: '#64748b', fontFamily: 'Consolas' }
                }]
            }, ANIM), true);
        },

        // 6. 请求方法（环形玫瑰风）
        method(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const abn = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'OPTIONS'];
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, { trigger: 'item', formatter: '{b}: {c} ({d}%)' }),
                title: title('请求方法分布', '非常规方法标橙警示'),
                legend: {
                    bottom: 4, itemWidth: 10, itemHeight: 10, itemGap: 12,
                    icon: 'circle', type: 'scroll',
                    textStyle: { fontSize: 11.5, color: '#475569' }
                },
                series: [{
                    type: 'pie', radius: ['46%', '68%'], center: ['50%', '50%'],
                    itemStyle: { borderColor: '#fff', borderWidth: 3 },
                    label: { formatter: '{b}\n{d}%', fontSize: 11, color: '#475569', lineHeight: 16 },
                    emphasis: { scale: true, scaleSize: 5 },
                    data: list.map((x, i) => ({
                        name: x.name, value: x.value,
                        itemStyle: {
                            // 非常规方法一律橙色系，一眼识别
                            color: abn.includes(x.name)
                                ? ['#f59e0b', '#f97316', '#ea580c', '#fb923c', '#fbbf24', '#fdba74'][i % 6]
                                : PALETTE[i % PALETTE.length]
                        }
                    }))
                }]
            }, ANIM), true);
        },

        // 7. 24 小时热度
        hour(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无数据'), true); return; }
            const night = h => { const n = parseInt(h, 10); return n >= 0 && n <= 5; };
            const max = Math.max(...list.map(x => x.value)) || 1;
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, {
                    trigger: 'axis', axisPointer: { type: 'shadow' },
                    formatter: p => {
                        const it = list[p[0].dataIndex];
                        return `${it.hour}　<b>${it.value.toLocaleString()}</b> 次请求` +
                               (night(it.hour) ? '<br/><span style="color:#e11d48">深夜时段</span>' : '');
                    }
                }),
                title: title('24 小时访问热度', '深夜 (0-5 时) 访问标红提示'),
                grid: Object.assign({}, grid, { bottom: 34 }),
                xAxis: {
                    type: 'category', data: list.map(x => x.hour),
                    axisLabel: Object.assign({}, axisLabel, { rotate: 45, fontSize: 10 }),
                    axisTick: { show: false }
                },
                yAxis: { type: 'value', splitLine, axisLabel },
                series: [{
                    type: 'bar', data: list.map(x => x.value), barWidth: '60%',
                    itemStyle: {
                        borderRadius: [6, 6, 0, 0],
                        color: p => {
                            if (night(list[p.dataIndex].hour))
                                return new echarts.graphic.LinearGradient(0, 0, 0, 1,
                                    [{ offset: 0, color: '#f43f5e' }, { offset: 1, color: '#f43f5e66' }]);
                            return new echarts.graphic.LinearGradient(0, 0, 0, 1,
                                [{ offset: 0, color: '#818cf8' }, { offset: 1, color: 'rgba(99,102,241,.25)' }]);
                        }
                    },
                    markLine: night(max) ? {} : {
                        silent: true, symbol: 'none',
                        lineStyle: { color: '#c7d2fe', type: 'dashed' },
                        label: { show: false },
                        data: []
                    }
                }]
            }, ANIM), true);
        },

        // 8. 异常类别分布
        category(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('未检测到异常'), true); return; }
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, { trigger: 'item', formatter: '{b}: {c} 条' }),
                title: title('异常类别分布'),
                legend: {
                    type: 'scroll', bottom: 2, itemWidth: 10, itemHeight: 10,
                    icon: 'circle', itemGap: 12,
                    textStyle: { fontSize: 11.5, color: '#475569' }
                },
                series: [{
                    type: 'pie', radius: ['44%', '68%'], center: ['50%', '48%'],
                    itemStyle: { borderColor: '#fff', borderWidth: 3 },
                    label: { formatter: '{c} 条', fontSize: 11.5, color: '#475569' },
                    labelLine: { length: 12, length2: 8, lineStyle: { color: '#cbd5e1' } },
                    emphasis: { scale: true, scaleSize: 5 },
                    data: list.map((x, i) => ({
                        name: x.name, value: x.value,
                        itemStyle: { color: PALETTE[i % PALETTE.length] }
                    }))
                }]
            }, ANIM), true);
        },

        // 9. 高危 IP 排行
        riskIp(id, list) {
            const c = get(id); if (!c) return;
            if (!list || !list.length) { c.setOption(emptyOption('暂无高危 IP'), true); return; }
            const d = list.slice().reverse();
            const hexOf = sev => SEV_COLOR[sev] || '#64748b';
            c.setOption(Object.assign({
                tooltip: Object.assign(tooltip, {
                    trigger: 'axis', axisPointer: { type: 'shadow' },
                    formatter: p => {
                        const it = d[p[0].dataIndex];
                        return `<b style="font-family:Consolas">${it.ip}</b><br/>` +
                               `风险评分　<b>${it.score}</b><br/>` +
                               `命中请求　${it.hits.toLocaleString()}<br/>` +
                               `最高等级　${it.max_severity}<br/>` +
                               `<span style="font-size:11px;color:#64748b">${it.categories.join('、')}</span>`;
                    }
                }),
                title: title('高危 IP 排行', '跨类别加权评分，按最高危害着色'),
                grid: Object.assign({}, grid, { right: 58, top: 62 }),
                xAxis: { type: 'value', splitLine, axisLabel },
                yAxis: {
                    type: 'category', data: d.map(x => x.ip),
                    axisLabel: Object.assign({}, axisLabel, {
                        fontFamily: 'Consolas, monospace', fontSize: 11.5, color: '#334155'
                    }),
                    axisTick: { show: false }
                },
                series: [{
                    type: 'bar', data: d.map(x => x.score), barWidth: '56%',
                    itemStyle: {
                        borderRadius: [0, 6, 6, 0],
                        color: p => new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                            { offset: 0, color: hexOf(d[p.dataIndex].max_severity) + '99' },
                            { offset: 1, color: hexOf(d[p.dataIndex].max_severity) }
                        ])
                    },
                    label: { show: true, position: 'right', fontSize: 10.5,
                             color: '#64748b', fontFamily: 'Consolas' }
                }]
            }, ANIM), true);
        },

        resizeAll() { Object.values(instances).forEach(c => c && c.resize()); }
    };
})();
