/**
 * DDoS Shield — Frontend App Logic
 * Handles: tabs, drag-and-drop uploads, manual prediction, chart & gauge updates
 */

const API = '';  // same origin; Flask serves both frontend and API

// ─── DOM refs ──────────────────────────────────────────────────────────────
const statusPill = document.getElementById('statusPill');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const resetBtn = document.getElementById('resetBtn');

const statTotalVal = document.getElementById('statTotalVal');
const statDdosVal = document.getElementById('statDdosVal');
const statBenignVal = document.getElementById('statBenignVal');
const statConfVal = document.getElementById('statConfVal');
const statThreatVal = document.getElementById('statThreatVal');

const resultsBody = document.getElementById('resultsBody');
const resultsCount = document.getElementById('resultsCount');
const gaugeFill = document.getElementById('gaugeFill');
const chartDdosPct = document.getElementById('chartDdosPct');
const chartCenter = document.getElementById('chartCenter');

const manualForm = document.getElementById('manualForm');
const manualSubmitBtn = document.getElementById('manualSubmitBtn');
const singleResult = document.getElementById('singleResult');
const resultBadge = document.getElementById('resultBadge');
const resultConf = document.getElementById('resultConf');
const resultDdosProb = document.getElementById('resultDdosProb');

const csvDropzone = document.getElementById('csvDropzone');
const csvFileInput = document.getElementById('csvFileInput');
const csvStatus = document.getElementById('csvStatus');

const pcapDropzone = document.getElementById('pcapDropzone');
const pcapFileInput = document.getElementById('pcapFileInput');
const pcapStatus = document.getElementById('pcapStatus');

// ─── Chart.js Donut ────────────────────────────────────────────────────────
const ctx = document.getElementById('donutChart').getContext('2d');
const donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['DDoS', 'Benign'],
        datasets: [{
            data: [0, 1],
            backgroundColor: ['rgba(255,56,96,0.7)', 'rgba(0,255,136,0.5)'],
            borderColor: ['rgba(255,56,96,0.9)', 'rgba(0,255,136,0.8)'],
            borderWidth: 2,
            hoverOffset: 6,
        }]
    },
    options: {
        cutout: '70%',
        animation: { duration: 600, easing: 'easeInOutQuart' },
        plugins: {
            legend: { display: false }, tooltip: {
                callbacks: {
                    label: (ctx) => ` ${ctx.label}: ${ctx.formattedValue}`
                }
            }
        }
    }
});

// ─── Tabs ───────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`tabContent${capitalise(tab.dataset.tab)}`).classList.add('active');
    });
});
function capitalise(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ─── Health Check ──────────────────────────────────────────────────────────
async function checkHealth() {
    try {
        const res = await fetch(`${API}/health`);
        const data = await res.json();
        if (data.status === 'ok' && data.model_loaded) {
            statusPill.classList.add('online');
            statusPill.classList.remove('offline');
            statusDot.style.background = 'var(--accent)';
            statusText.textContent = 'Model Online';
        } else {
            setOffline('Model not loaded');
        }
    } catch {
        setOffline('API Offline');
    }
}

function setOffline(msg) {
    statusPill.classList.add('offline');
    statusPill.classList.remove('online');
    statusText.textContent = msg;
}

checkHealth();
setInterval(checkHealth, 15000);

// ─── Stats Refresh ──────────────────────────────────────────────────────────
async function refreshStats() {
    try {
        const res = await fetch(`${API}/stats`);
        const data = await res.json();
        applyStats(data);
    } catch { /* silently ignore */ }
}

function applyStats(data) {
    statTotalVal.textContent = data.total ?? 0;
    statDdosVal.textContent = data.ddos ?? 0;
    statBenignVal.textContent = data.benign ?? 0;
    statConfVal.textContent = data.avg_confidence
        ? `${(data.avg_confidence * 100).toFixed(1)}%`
        : '—';

    // Threat pill
    const level = (data.threat_level || 'LOW').toLowerCase();
    statThreatVal.textContent = (data.threat_level || 'LOW');
    statThreatVal.className = `stat-value threat-pill ${level}`;

    // Gauge bar (0-100%)
    const pct = Math.round((data.ddos_ratio ?? 0) * 100);
    gaugeFill.style.width = `${pct}%`;

    // Donut chart
    const d = data.ddos || 0;
    const b = data.benign || 0;
    donutChart.data.datasets[0].data = [d, b || (d === 0 ? 1 : 0)];
    donutChart.update('active');
    chartDdosPct.textContent = `${pct}%`;
}

refreshStats();
setInterval(refreshStats, 5000);

// ─── Reset ──────────────────────────────────────────────────────────────────
resetBtn.addEventListener('click', async () => {
    try {
        await fetch(`${API}/stats/reset`, { method: 'POST' });
        resultsBody.innerHTML = '<tr class="empty-row"><td colspan="5">No results yet — analyze some traffic above</td></tr>';
        resultsCount.textContent = '0 flows';
        singleResult.classList.add('hidden');
        refreshStats();
    } catch { /* ignore */ }
});

// ─── Manual Form ────────────────────────────────────────────────────────────
manualForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    manualSubmitBtn.classList.add('loading');
    manualSubmitBtn.textContent = '⏳ Analyzing…';

    const fd = new FormData(manualForm);
    const body = {};
    fd.forEach((v, k) => { body[k] = isNaN(v) ? v : parseFloat(v); });

    try {
        const res = await fetch(`${API}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Unknown error');

        // Show single result badge
        const isDdos = data.prediction === 'DDoS';
        resultBadge.textContent = isDdos ? '🔴 DDoS' : '🟢 Benign';
        resultBadge.className = `result-badge ${isDdos ? 'ddos' : 'benign'}`;
        resultConf.textContent = `${data.confidence}%`;
        resultDdosProb.textContent = `${data.ddos_prob}%`;
        singleResult.classList.remove('hidden');

        // Append to table
        appendRow({
            flow_id: 'manual',
            source_ip: body.source_ip,
            dest_ip: body.dest_ip,
            prediction: data.prediction,
            confidence: data.confidence,
        });

        refreshStats();
    } catch (err) {
        alert(`Error: ${err.message}`);
    } finally {
        manualSubmitBtn.classList.remove('loading');
        manualSubmitBtn.innerHTML = '<span class="btn-icon">⚡</span> Analyze Flow';
    }
});

// ─── CSV Dropzone ────────────────────────────────────────────────────────────
setupDropzone(csvDropzone, csvFileInput, csvStatus, '/upload-csv', '.csv');

// ─── PCAP Dropzone ───────────────────────────────────────────────────────────
setupDropzone(pcapDropzone, pcapFileInput, pcapStatus, '/upload-pcap', '.pcap,.pcapng');

function setupDropzone(zone, input, statusEl, endpoint, accept) {
    // Click label triggers hidden input
    input.addEventListener('change', () => {
        if (input.files[0]) handleUpload(input.files[0], endpoint, statusEl);
    });

    zone.addEventListener('click', (e) => {
        if (e.target.classList.contains('dz-btn') || e.target.tagName === 'LABEL') return;
        input.click();
    });

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) handleUpload(file, endpoint, statusEl);
    });
}

async function handleUpload(file, endpoint, statusEl) {
    // Client-side size check (10 MB)
    if (file.size > 10 * 1024 * 1024) {
        showStatus(statusEl, 'error', '❌ File too large. Maximum size is 10 MB.');
        return;
    }

    showStatus(statusEl, 'loading', `⏳ Uploading ${file.name} (${formatSize(file.size)})…`);

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(`${API}${endpoint}`, { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Upload failed');

        const count = data.count ?? 0;
        showStatus(statusEl, 'success', `✅ Analyzed ${count} flows from ${file.name}`);
        appendRows(data.results);
        if (data.stats) applyStats(data.stats);

    } catch (err) {
        showStatus(statusEl, 'error', `❌ ${err.message}`);
    }
}

// ─── Table Helpers ───────────────────────────────────────────────────────────
let rowCount = 0;

function appendRows(results = []) {
    results.forEach(r => appendRow(r));
}

function appendRow(r) {
    // Remove empty placeholder
    const empty = resultsBody.querySelector('.empty-row');
    if (empty) empty.remove();

    rowCount++;
    const isDdos = r.prediction === 'DDoS';
    const tr = document.createElement('tr');
    tr.style.animation = 'fadeInUp 0.25s ease';
    tr.innerHTML = `
    <td>${rowCount}</td>
    <td>${r.source_ip || '—'}</td>
    <td>${r.dest_ip || '—'}</td>
    <td><span class="pred-badge ${isDdos ? 'ddos' : 'benign'}">${isDdos ? '🔴 DDoS' : '🟢 Benign'}</span></td>
    <td>${r.confidence ?? '—'}%</td>
  `;
    resultsBody.prepend(tr);
    resultsCount.textContent = `${rowCount} flow${rowCount !== 1 ? 's' : ''}`;
}

// ─── UI Helpers ──────────────────────────────────────────────────────────────
function showStatus(el, type, msg) {
    el.className = `upload-status ${type}`;
    el.textContent = msg;
    el.classList.remove('hidden');
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
