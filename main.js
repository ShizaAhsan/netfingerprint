// NetFingerprint — Frontend Logic
const CHART_COLORS = ['#00e5ff','#00ff88','#ffaa00','#ff3c6e','#a855f7','#f59e0b','#06b6d4','#84cc16'];

let sessionData = { A: null, B: null };
let activeCharts = {};

// ─── TAB SWITCHING ───────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ─── STATUS BAR ──────────────────────────────────────────────────────────────
function setStatus(text, type = 'ready') {
  const dot = document.getElementById('statusDot');
  const label = document.getElementById('statusText');
  label.textContent = text;
  dot.className = 'status-dot';
  if (type === 'active') dot.classList.add('active');
  if (type === 'error') dot.classList.add('error');
}

// ─── CAPTURE (single tab) ────────────────────────────────────────────────────
async function startCapture(slot) {
  const isCompareTab = slot === 'A' && document.getElementById('tab-compare').classList.contains('active')
    || slot === 'B';

  let url, duration, progressContainer, progressFill, progressLabel, progressTimer, resultsEl, btn;

  if (!isCompareTab || (slot === 'A' && document.getElementById('tab-capture').classList.contains('active'))) {
    url = document.getElementById('urlInput').value.trim();
    duration = parseInt(document.getElementById('durationInput').value) || 10;
    progressContainer = document.getElementById('progressContainer');
    progressFill = document.getElementById('progressFill');
    progressLabel = document.getElementById('progressLabel');
    progressTimer = document.getElementById('progressTimer');
    resultsEl = document.getElementById('resultsA');
    btn = document.getElementById('captureBtn');
    slot = 'A';
  } else {
    const suffix = slot;
    url = document.getElementById('url' + suffix).value.trim();
    duration = parseInt(document.getElementById('dur' + suffix).value) || 10;
    progressContainer = document.getElementById('compareProgress');
    progressFill = document.getElementById('compareProgressFill');
    progressLabel = document.getElementById('compareProgressLabel');
    progressTimer = document.getElementById('compareTimer');
    resultsEl = null;
    btn = document.getElementById('captureBtn' + suffix);
  }

  if (!url) { alert('Please enter a URL.'); return; }

  // Disable button
  btn.disabled = true;
  btn.querySelector ? btn.querySelector('.btn-text') && (btn.querySelector('.btn-text').textContent = '⏳ CAPTURING...') : (btn.textContent = '⏳ CAPTURING...');
  setStatus('CAPTURING', 'active');

  // Show progress
  progressContainer.style.display = 'block';
  progressFill.style.width = '0%';

  let elapsed = 0;
  const timer = setInterval(() => {
    elapsed++;
    progressTimer.textContent = elapsed + 's';
    progressFill.style.width = Math.min(95, (elapsed / duration) * 100) + '%';
    progressLabel.textContent = elapsed < 2 ? 'Resolving hostname...' :
      elapsed < 4 ? 'Starting packet capture...' :
      elapsed < duration - 2 ? 'Capturing packets...' : 'Finalizing...';
  }, 1000);

  const sessionId = 'session_' + slot + '_' + Date.now();

  try {
    const res = await fetch('/api/capture', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, duration, session_id: sessionId })
    });
    const data = await res.json();
    clearInterval(timer);
    progressFill.style.width = '100%';
    progressContainer.style.display = 'none';

    if (data.error) {
      setStatus('ERROR', 'error');
      if (resultsEl) {
        resultsEl.style.display = 'block';
        resultsEl.innerHTML = `<div class="error-box">⚠ ${data.error}</div>`;
      }
      const statusEl = document.getElementById('status' + slot);
      if (statusEl) { statusEl.textContent = 'ERROR: ' + data.error; statusEl.className = 'capture-status error-status'; }
    } else {
      setStatus('CAPTURED', 'ready');
      data._sessionId = sessionId;
      sessionData[slot] = data;
      if (resultsEl) {
        resultsEl.style.display = 'block';
        renderResults(data, resultsEl, 'results_' + slot);
      }
      const statusEl = document.getElementById('status' + slot);
      if (statusEl) { statusEl.textContent = '✓ CAPTURED — ' + data.stats.total_packets + ' packets'; statusEl.className = 'capture-status done'; }
      checkCompareReady();
    }
  } catch (err) {
    clearInterval(timer);
    progressContainer.style.display = 'none';
    setStatus('ERROR', 'error');
    if (resultsEl) {
      resultsEl.style.display = 'block';
      resultsEl.innerHTML = `<div class="error-box">⚠ Connection error: ${err.message}</div>`;
    }
  }

  btn.disabled = false;
  const btnText = btn.querySelector ? btn.querySelector('.btn-text') : null;
  if (btnText) btnText.textContent = '▶ CAPTURE TRAFFIC';
  else btn.textContent = slot === 'A' ? '▶ CAPTURE A' : '▶ CAPTURE B';
}

// ─── RENDER RESULTS ──────────────────────────────────────────────────────────
function renderResults(data, container, chartPrefix) {
  const { fingerprint, behavior, stats, charts, url, resolved_ips } = data;

  container.innerHTML = `
    <div class="fingerprint-hero">
      <div>
        <div class="fp-code">${fingerprint}</div>
        <div class="fp-url">${url}</div>
        <div class="ips-line">Resolved IPs: ${resolved_ips.map(ip => `<span>${ip}</span>`).join(', ')}</div>
      </div>
      <div class="behavior-tag">${behavior}</div>
    </div>

    <div class="stats-grid">
      ${statCard('TOTAL PACKETS', stats.total_packets, '')}
      ${statCard('TOTAL BYTES', formatBytes(stats.total_bytes), '')}
      ${statCard('AVG PACKET', stats.avg_packet_size, 'bytes')}
      ${statCard('MAX PACKET', stats.max_packet_size, 'bytes')}
      ${statCard('UNIQUE PORTS', stats.unique_ports, '')}
      ${statCard('PKT/SEC', stats.packets_per_second, '')}
      ${statCard('AVG IAT', stats.avg_inter_arrival_ms, 'ms')}
      ${statCard('DURATION', stats.capture_duration_s, 's')}
    </div>

    <div class="charts-grid">
      <div class="chart-card">
        <div class="chart-title">// PROTOCOL DISTRIBUTION</div>
        <div class="chart-wrap"><canvas id="${chartPrefix}_proto"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">// PACKET SIZE DISTRIBUTION</div>
        <div class="chart-wrap"><canvas id="${chartPrefix}_size"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">// TOP DESTINATION PORTS</div>
        <div class="chart-wrap"><canvas id="${chartPrefix}_ports"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">// TCP FLAGS</div>
        <div class="chart-wrap"><canvas id="${chartPrefix}_flags"></canvas></div>
      </div>
    </div>

    <div class="chart-card" style="margin-bottom:1rem">
      <div class="diff-label">// TOP PORTS DETAIL</div>
      <table class="ports-table">
        <thead><tr><th>PORT</th><th>PACKETS</th><th>SERVICE</th></tr></thead>
        <tbody>
          ${Object.entries(stats.top_ports).slice(0,10).map(([port, count]) =>
            `<tr><td>${port}</td><td>${count}</td><td>${guessService(parseInt(port))}</td></tr>`
          ).join('')}
        </tbody>
      </table>
    </div>
  `;

  // Draw charts
  drawDonut(chartPrefix + '_proto', charts.protocols);
  drawBar(chartPrefix + '_size', charts.size_distribution);
  drawBar(chartPrefix + '_ports', charts.top_ports);
  drawDonut(chartPrefix + '_flags', stats.tcp_flags || {});
}

// ─── CHARTS ──────────────────────────────────────────────────────────────────
function chartDefaults() {
  return {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#4a7a99', font: { family: 'Share Tech Mono', size: 10 }, boxWidth: 12 }
      }
    }
  };
}

function drawDonut(id, obj) {
  const labels = Object.keys(obj);
  const values = Object.values(obj);
  if (!labels.length) return;
  const canvas = document.getElementById(id);
  if (!canvas) return;
  if (activeCharts[id]) activeCharts[id].destroy();
  activeCharts[id] = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: CHART_COLORS, borderColor: '#030a0f', borderWidth: 2 }]
    },
    options: { ...chartDefaults(), cutout: '60%' }
  });
}

function drawBar(id, obj) {
  const labels = Object.keys(obj);
  const values = Object.values(obj);
  if (!labels.length) return;
  const canvas = document.getElementById(id);
  if (!canvas) return;
  if (activeCharts[id]) activeCharts[id].destroy();
  activeCharts[id] = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: CHART_COLORS[0] + '66',
        borderColor: CHART_COLORS[0],
        borderWidth: 1
      }]
    },
    options: {
      ...chartDefaults(),
      scales: {
        x: { ticks: { color: '#4a7a99', font: { family: 'Share Tech Mono', size: 9 } }, grid: { color: '#0d3a5222' } },
        y: { ticks: { color: '#4a7a99', font: { family: 'Share Tech Mono', size: 9 } }, grid: { color: '#0d3a5222' } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// ─── COMPARISON ──────────────────────────────────────────────────────────────
function checkCompareReady() {
  const btn = document.getElementById('compareBtn');
  if (btn) btn.disabled = !(sessionData.A && sessionData.B);
}

async function runComparison() {
  if (!sessionData.A || !sessionData.B) { alert('Capture both websites first!'); return; }
  const btn = document.getElementById('compareBtn');
  btn.disabled = true;
  btn.textContent = '⏳ COMPARING...';
  setStatus('COMPARING', 'active');

  try {
    const res = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_a: sessionData.A._sessionId, session_b: sessionData.B._sessionId })
    });
    const data = await res.json();
    const resultsEl = document.getElementById('compareResults');
    resultsEl.style.display = 'block';

    if (data.error) {
      resultsEl.innerHTML = `<div class="error-box">⚠ ${data.error}</div>`;
    } else {
      renderComparison(data, resultsEl);
    }
    setStatus('COMPARED', 'ready');
  } catch (err) {
    setStatus('ERROR', 'error');
  }

  btn.disabled = false;
  btn.textContent = '⚡ COMPARE FINGERPRINTS';
}

function renderComparison(data, container) {
  const score = data.similarity_score;
  container.innerHTML = `
    <div class="similarity-section">
      <div class="similarity-score">${score}%</div>
      <div class="similarity-label">BEHAVIORAL SIMILARITY SCORE</div>
      <div class="similarity-bar-wrap">
        <div class="similarity-bar" id="simBar" style="width:0%"></div>
      </div>
    </div>

    <div class="compare-fp-grid">
      <div class="compare-fp-card">
        <div class="compare-fp-card-label">SITE A FINGERPRINT</div>
        <div class="compare-fp-hash">${data.fingerprint_a}</div>
        <div class="compare-fp-url">${data.website_a}</div>
        <div class="compare-fp-behavior">${data.behavior_a}</div>
      </div>
      <div class="compare-fp-card">
        <div class="compare-fp-card-label">SITE B FINGERPRINT</div>
        <div class="compare-fp-hash">${data.fingerprint_b}</div>
        <div class="compare-fp-url">${data.website_b}</div>
        <div class="compare-fp-behavior">${data.behavior_b}</div>
      </div>
    </div>

    <div class="chart-card" style="margin-bottom:1rem">
      <div class="diff-label">// STATISTICAL DIFFERENCES</div>
      <table class="diff-table">
        <thead><tr><th>METRIC</th><th>SITE A</th><th>SITE B</th></tr></thead>
        <tbody>
          <tr><td>Total Packets</td><td>${data.differences.total_packets.a}</td><td>${data.differences.total_packets.b}</td></tr>
          <tr><td>Total Bytes</td><td>${formatBytes(data.differences.total_bytes.a)}</td><td>${formatBytes(data.differences.total_bytes.b)}</td></tr>
          <tr><td>Avg Packet Size</td><td>${data.differences.avg_packet_size.a} B</td><td>${data.differences.avg_packet_size.b} B</td></tr>
          <tr><td>Unique Ports</td><td>${data.differences.unique_ports.a}</td><td>${data.differences.unique_ports.b}</td></tr>
        </tbody>
      </table>
    </div>

    <div class="charts-grid">
      <div class="chart-card">
        <div class="chart-title">// PROTOCOLS — SITE A</div>
        <div class="chart-wrap"><canvas id="cmp_proto_a"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">// PROTOCOLS — SITE B</div>
        <div class="chart-wrap"><canvas id="cmp_proto_b"></canvas></div>
      </div>
    </div>
  `;

  setTimeout(() => {
    const bar = document.getElementById('simBar');
    if (bar) bar.style.width = score + '%';
    drawDonut('cmp_proto_a', data.protocols_a);
    drawDonut('cmp_proto_b', data.protocols_b);
  }, 100);
}

// ─── UTILS ───────────────────────────────────────────────────────────────────
function statCard(label, value, unit) {
  return `<div class="stat-card">
    <div class="stat-label">${label}</div>
    <div class="stat-value">${value}<span class="stat-unit">${unit}</span></div>
  </div>`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function guessService(port) {
  const map = {
    80: 'HTTP', 443: 'HTTPS/TLS', 53: 'DNS', 22: 'SSH', 21: 'FTP',
    25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 5432: 'PostgreSQL',
    8080: 'HTTP Alt', 8443: 'HTTPS Alt', 123: 'NTP', 67: 'DHCP', 68: 'DHCP',
    161: 'SNMP', 3389: 'RDP', 5900: 'VNC'
  };
  return map[port] || (port < 1024 ? 'Well-Known' : port < 49152 ? 'Registered' : 'Dynamic');
}

// Allow Enter key on URL inputs
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startCapture('A');
});
