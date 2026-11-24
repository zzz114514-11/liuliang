// main.js  页面交互和数据渲染
// 负责：请求接口、渲染卡片和表格、数字滚动和分区入场动画

const App = (() => {

    let sessionId = null;
    let findingsCache = [];

    const $ = id => document.getElementById(id);

    // 工具函数

    function toast(msg, type = '') {
        const el = $('toast');
        el.textContent = msg;
        el.className = 'toast ' + type;
        // 强制重排后再加 show，保证过渡动画生效
        void el.offsetWidth;
        el.classList.add('show');
        clearTimeout(el._t);
        el._t = setTimeout(() => el.classList.remove('show'), 3400);
    }

    function showLoading(v) { $('loading').hidden = !v; }

    function fmt(n) {
        if (n === null || n === undefined) return '-';
        return Number(n).toLocaleString('zh-CN');
    }

    function esc(s) {
        return String(s === null || s === undefined ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function showResult(v) { $('result').hidden = !v; }

    // 数字滚动动画

    function countUp(el, target, duration = 900) {
        const start = performance.now();
        const decimals = String(target).includes('.') ? 2 : 0;
        target = Number(target) || 0;

        function frame(now) {
            const p = Math.min((now - start) / duration, 1);
            // easeOutCubic：先快后慢，观感自然
            const eased = 1 - Math.pow(1 - p, 3);
            const val = target * eased;
            el.textContent = decimals
                ? val.toFixed(decimals)
                : Math.round(val).toLocaleString('zh-CN');
            if (p < 1) requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }

    // 滚动入场动画

    let observer = null;

    function setupReveal() {
        if (!('IntersectionObserver' in window)) {
            document.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
            return;
        }
        observer = new IntersectionObserver(entries => {
            entries.forEach(en => {
                if (en.isIntersecting) {
                    en.target.classList.add('visible');
                    observer.unobserve(en.target);
                }
            });
        }, { threshold: 0.08, rootMargin: '0px 0px -30px 0px' });
        document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
    }

    function retriggerReveal() {
        // 新一次分析：移除 visible 触发重新入场
        document.querySelectorAll('.reveal').forEach(el => {
            el.classList.remove('visible');
            if (observer) observer.observe(el);
        });
    }

    // 概览卡片

    function renderOverview(o) {
        const errRate = o.error_rate || 0;
        const rateCls = errRate > 20 ? 'card-danger' : (errRate > 10 ? 'card-warn' : 'card-ok');

        const ICONS = {
            pv:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
            uv:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
            url:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
            data: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
            e4:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            e5:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
            rate: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
            avg:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>'
        };

        const cards = [
            { label: '总请求数 (PV)',     value: o.total_requests, unit: '',   cls: '',     icon: 'pv',   ic: 'g1' },
            { label: '独立 IP 数 (UV)',   value: o.unique_ips,      unit: '',   cls: '',     icon: 'uv',   ic: 'g2' },
            { label: '不同 URL 数',       value: o.unique_urls,     unit: '',   cls: '',     icon: 'url',  ic: 'g1' },
            { label: '总流量',            value: o.total_mb,        unit: 'MB', cls: '',     icon: 'data', ic: 'g3' },
            { label: '4xx 错误',          value: o.count_4xx,       unit: '',   cls: 'card-warn',   icon: 'e4', ic: 'g4' },
            { label: '5xx 错误',          value: o.count_5xx,       unit: '',   cls: 'card-danger', icon: 'e5', ic: 'g5' },
            { label: '整体错误率',        value: errRate,           unit: '%',  cls: rateCls, icon: 'rate', ic: 'g4' },
            { label: '平均每 IP 请求',    value: o.avg_requests_per_ip, unit: '', cls: '',   icon: 'avg',  ic: 'g6' },
        ];

        $('overviewCards').innerHTML = cards.map(c => `
            <div class="card ${c.cls}">
                <div class="card-icon ${c.ic}">${ICONS[c.icon]}</div>
                <div class="card-body">
                    <div class="card-label">${c.label}</div>
                    <div class="card-value"><span class="num" data-target="${c.value}">0</span>${c.unit ? `<small>${c.unit}</small>` : ''}</div>
                </div>
            </div>`).join('');

        // 数字滚动
        $('overviewCards').querySelectorAll('.num').forEach(el =>
            countUp(el, el.dataset.target));
    }

    // 危害等级卡

    function renderSeverity(summary) {
        const items = [
            { key: 'critical', label: '严重 Critical' },
            { key: 'high',     label: '高危 High' },
            { key: 'medium',   label: '中危 Medium' },
            { key: 'low',      label: '低危 Low' },
        ];
        const total = Math.max(summary.total || 0, 1);
        $('severityCards').innerHTML = items.map((i, idx) => {
            const v = summary[i.key] || 0;
            const pct = Math.round(v / total * 100);
            return `
            <div class="sev-card ${i.key}">
                <div class="sev-num"><span class="num" data-target="${v}">0</span></div>
                <div class="sev-label">${i.label} - 占比 ${pct}%</div>
                <div class="sev-bar" style="animation-delay:${idx * .12}s;width:${pct}%"></div>
            </div>`;
        }).join('');

        $('severityCards').querySelectorAll('.num').forEach(el =>
            countUp(el, el.dataset.target, 700));
    }

    // 表格渲染

    function renderFindings(list) {
        const tbody = $('findingTable').querySelector('tbody');
        if (!list.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:30px">未检测到异常，日志表现正常</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(f => `
            <tr>
                <td><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span></td>
                <td>${esc(f.category)}</td>
                <td class="mono">${esc(f.rule_id)}</td>
                <td class="mono">${esc(f.target)}</td>
                <td><b style="font-variant-numeric:tabular-nums">${fmt(f.count)}</b></td>
                <td style="max-width:440px">${esc(f.detail)}</td>
                <td class="mono" style="font-size:11.5px;color:#94a3b8">${esc(f.first_seen)}<br>${esc(f.last_seen)}</td>
            </tr>`).join('');
    }

    function renderAttacks(list) {
        const tbody = $('attackTable').querySelector('tbody');
        if (!list || !list.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:30px">未检测到攻击特征请求</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(r => `
            <tr>
                <td class="mono">${esc(r.rule_id)}</td>
                <td>${esc(r.type)}</td>
                <td class="mono">${esc(r.ip)}</td>
                <td class="mono" style="font-size:11.5px">${esc(r.time)}</td>
                <td class="mono">${esc(r.method)}</td>
                <td class="url-cell">${esc(r.url)}</td>
                <td class="mono">${esc(r.status)}</td>
                <td style="max-width:200px;font-size:11.5px;color:#94a3b8">${esc(r.user_agent)}</td>
            </tr>`).join('');
    }

    // 主渲染

    function render(data) {
        if (!data.ok) { toast(data.error || '分析失败', 'error'); return; }

        sessionId = data.session_id;
        const m = data.meta, s = data.statistics, a = data.anomalies;

        $('metaTag').textContent =
            `${m.source} - ${fmt(m.parsed)} 条 - 成功率 ${m.success_rate}% - ${m.format} - ${m.elapsed_seconds}s`;

        retriggerReveal();
        renderOverview(s.overview);
        renderSeverity(a.summary);

        findingsCache = a.findings || [];
        renderFindings(findingsCache);
        renderAttacks(a.attack_requests);

        Charts.trend('chartTrend', s.trend);
        Charts.topIp('chartTopIp', s.top_ips);
        Charts.topUrl('chartTopUrl', s.top_urls);
        Charts.status('chartStatus', s.status_distribution);
        Charts.statusDetail('chartStatusDetail', s.status_detail);
        Charts.method('chartMethod', s.method_distribution);
        Charts.hour('chartHour', s.hour_distribution);
        Charts.category('chartCategory', a.by_category);
        Charts.riskIp('chartRiskIp', a.high_risk_ips);

        showResult(true);
        toast(`分析完成：${fmt(m.parsed)} 条记录，发现 ${a.summary.total} 项异常`, 'success');

        setTimeout(() => Charts.resizeAll(), 80);
        $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // 请求封装

    function post(url, body, isForm) {
        showLoading(true);
        const opt = { method: 'POST' };
        if (isForm) opt.body = body;
        else {
            opt.headers = { 'Content-Type': 'application/json' };
            opt.body = JSON.stringify(body);
        }
        return fetch(url, opt)
            .then(r => r.json())
            .then(data => { showLoading(false); render(data); })
            .catch(e => { showLoading(false); toast('请求失败：' + e.message, 'error'); });
    }

    // 事件绑定

    function bind() {
        $('fileInput').addEventListener('change', e => {
            const f = e.target.files[0];
            if (f) uploadFile(f);
            e.target.value = '';   // 允许重复选择同一文件
        });

        const dz = $('dropZone');
        ['dragenter', 'dragover'].forEach(ev =>
            dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('dragover'); }));
        ['dragleave', 'drop'].forEach(ev =>
            dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('dragover'); }));
        dz.addEventListener('drop', e => {
            const f = e.dataTransfer.files[0];
            if (f) uploadFile(f);
        });
        dz.addEventListener('click', e => {
            if (e.target.tagName !== 'BUTTON') $('fileInput').click();
        });

        $('togglePaste').addEventListener('click', () => {
            const b = $('pasteBox');
            b.hidden = !b.hidden;
            $('togglePaste').textContent = b.hidden ? '展开粘贴框' : '收起粘贴框';
        });
        $('btnAnalyzeText').addEventListener('click', () => {
            const t = $('pasteText').value.trim();
            if (!t) { toast('请先粘贴日志内容', 'error'); return; }
            post('/api/analyze/text', { text: t });
        });

        $('btnDemo').addEventListener('click', () => {
            showLoading(true);
            fetch('/api/demo', { method: 'POST' })
                .then(r => r.json())
                .then(d => { showLoading(false); render(d); })
                .catch(e => { showLoading(false); toast('加载失败：' + e.message, 'error'); });
        });

        document.querySelectorAll('[data-export]').forEach(btn => {
            btn.addEventListener('click', () => {
                if (!sessionId) { toast('请先完成一次分析', 'error'); return; }
                window.location.href = `/api/export/${btn.dataset.export}?session_id=${sessionId}`;
                toast('CSV 已开始下载', 'success');
            });
        });

        $('findingFilter').addEventListener('input', e => {
            const kw = e.target.value.trim().toLowerCase();
            if (!kw) { renderFindings(findingsCache); return; }
            renderFindings(findingsCache.filter(f =>
                (f.target || '').toLowerCase().includes(kw) ||
                (f.rule_id || '').toLowerCase().includes(kw) ||
                (f.category || '').toLowerCase().includes(kw) ||
                (f.detail || '').toLowerCase().includes(kw)
            ));
        });
    }

    function uploadFile(f) {
        const fd = new FormData();
        fd.append('file', f);
        post('/api/upload', fd, true);
    }

    // 启动
    document.addEventListener('DOMContentLoaded', () => {
        bind();
        setupReveal();
        // 支持 ?demo=1 打开即自动加载演示日志（演示/联调友好）
        if (new URLSearchParams(location.search).get('demo') === '1') {
            $('btnDemo').click();
        }
    });

    return { toast, render };
})();
