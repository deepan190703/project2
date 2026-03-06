/* ============================================================
   SecureScan – Frontend Application Logic
   ============================================================ */

const API_BASE = '/api';
let currentScanId = null;
let pollTimer = null;

// ---- DOM references ----
const scanForm       = document.getElementById('scanForm');
const domainInput    = document.getElementById('domainInput');
const scanBtn        = document.getElementById('scanBtn');
const formError      = document.getElementById('formError');
const scanFormSection= document.getElementById('scanFormSection');
const scanProgress   = document.getElementById('scanProgress');
const resultsSection = document.getElementById('resultsSection');
const progressDomain = document.getElementById('progressDomain');

const STEPS = ['stepSSL','stepHeaders','stepPorts','stepEndpoints','stepDNS','stepScore'];
let stepIndex = 0;
let stepTimer = null;

// ---- Form submission ----
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) {
    showFormError('Please enter a domain name.');
    return;
  }
  hideFormError();
  await startScan(domain);
});

async function startScan(domain) {
  setScanningState(true);
  scanFormSection.classList.add('hidden');
  scanProgress.classList.remove('hidden');
  resultsSection.classList.add('hidden');
  progressDomain.textContent = domain;
  startProgressAnimation();

  try {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to start scan');
    }
    const scan = await res.json();
    currentScanId = scan.id;
    pollScan(scan.id);
  } catch (err) {
    stopProgressAnimation();
    scanFormSection.classList.remove('hidden');
    scanProgress.classList.add('hidden');
    showFormError(err.message);
    setScanningState(false);
  }
}

function pollScan(scanId) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const res = await fetch(`${API_BASE}/scans/${scanId}`);
      const scan = await res.json();
      if (scan.status === 'completed' || scan.status === 'failed') {
        stopProgressAnimation();
        scanProgress.classList.add('hidden');
        if (scan.status === 'completed') {
          renderResults(scan);
        } else {
          scanFormSection.classList.remove('hidden');
          showFormError(`Scan failed: ${scan.error_message || 'Unknown error'}`);
        }
        setScanningState(false);
        loadHistory();
      } else {
        pollScan(scanId);
      }
    } catch {
      pollScan(scanId);
    }
  }, 2000);
}

// ---- Progress animation ----
function startProgressAnimation() {
  stepIndex = 0;
  STEPS.forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active', 'done');
  });
  document.getElementById(STEPS[0]).classList.add('active');
  stepTimer = setInterval(() => {
    if (stepIndex < STEPS.length - 1) {
      document.getElementById(STEPS[stepIndex]).classList.replace('active','done');
      stepIndex++;
      document.getElementById(STEPS[stepIndex]).classList.add('active');
    }
  }, 8000);
}

function stopProgressAnimation() {
  clearInterval(stepTimer);
  STEPS.forEach(id => {
    document.getElementById(id).classList.remove('active');
    document.getElementById(id).classList.add('done');
  });
}

// ---- Render results ----
function renderResults(scan) {
  resultsSection.classList.remove('hidden');
  scanFormSection.classList.remove('hidden');

  // Risk banner
  const grade   = scan.risk_grade || 'N/A';
  const score   = scan.risk_score !== null ? scan.risk_score.toFixed(1) : 'N/A';
  const gradeEl = document.getElementById('riskGrade');
  gradeEl.textContent = grade;
  gradeEl.className = `risk-grade grade-${grade}`;
  document.getElementById('riskDomain').textContent = scan.domain;
  document.getElementById('riskScore').textContent  = score;

  // Download button
  const dlBtn = document.getElementById('downloadReportBtn');
  dlBtn.onclick = () => window.open(`/api/reports/${scan.id}/pdf`, '_blank');

  document.getElementById('newScanBtn').onclick = () => {
    resultsSection.classList.add('hidden');
    domainInput.value = '';
    currentScanId = null;
  };

  // Severity badges
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (scan.findings || []).forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const badgesEl = document.getElementById('severityBadges');
  badgesEl.innerHTML = Object.entries(counts).map(([sev, cnt]) =>
    `<span class="severity-badge ${sev}">${cnt} ${cap(sev)}</span>`
  ).join('');

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });

  // Render each tab
  renderFindings(scan.findings || []);
  renderSSL(scan.ssl_results);
  renderHeaders(scan.headers_results);
  renderPorts(scan.ports_results);
  renderEndpoints(scan.endpoints_results);
  renderDNS(scan.dns_results);

  // Scroll into view
  resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function renderFindings(findings) {
  const el = document.getElementById('findingsList');
  if (!findings.length) {
    el.innerHTML = '<div class="empty-state"><div class="icon">✅</div><p>No security issues detected!</p></div>';
    return;
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  el.innerHTML = findings.map(f => `
    <div class="finding-card ${f.severity}">
      <div class="finding-header">
        <span class="finding-title">${esc(f.title)}</span>
        <span class="severity-pill ${f.severity}">${f.severity}</span>
      </div>
      <p class="finding-desc">${esc(f.description)}</p>
      <p class="finding-rec"><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>
    </div>
  `).join('');
}

function renderSSL(ssl) {
  const el = document.getElementById('sslDetails');
  if (!ssl) { el.innerHTML = '<p class="loading-text">No SSL data available.</p>'; return; }
  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-title">SSL/TLS Certificate Details</div>
      <table class="detail-table">
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>HTTPS Supported</td><td>${boolTag(ssl.supported)}</td></tr>
        <tr><td>Certificate Valid</td><td>${boolTag(ssl.valid)}</td></tr>
        <tr><td>Subject</td><td>${esc(ssl.subject || 'N/A')}</td></tr>
        <tr><td>Issuer</td><td>${esc(ssl.issuer || 'N/A')}</td></tr>
        <tr><td>Expiry Date</td><td>${esc(ssl.not_after || 'N/A')}</td></tr>
        <tr><td>Days Until Expiry</td><td>${ssl.days_until_expiry !== null ? ssl.days_until_expiry : 'N/A'}</td></tr>
        <tr><td>Protocol Version</td><td>${esc(ssl.protocol_version || 'N/A')}</td></tr>
        <tr><td>Cipher Suite</td><td>${esc(ssl.cipher_suite || 'N/A')}</td></tr>
      </table>
    </div>`;
}

function renderHeaders(hdrs) {
  const el = document.getElementById('headersDetails');
  if (!hdrs) { el.innerHTML = '<p class="loading-text">No headers data available.</p>'; return; }
  const all_headers = [
    'Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
    'X-Content-Type-Options','Referrer-Policy','Permissions-Policy','X-XSS-Protection'
  ];
  const present = new Set((hdrs.present_headers || []).map(h => h.toLowerCase()));
  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-title">Security Header Status</div>
      <table class="detail-table">
        <tr><th>Header</th><th>Status</th></tr>
        ${all_headers.map(h => `<tr><td>${h}</td><td>
          ${present.has(h.toLowerCase())
            ? '<span class="tag present">Present</span>'
            : '<span class="tag missing">Missing</span>'}
        </td></tr>`).join('')}
      </table>
    </div>
    ${hdrs.info_disclosure && hdrs.info_disclosure.length ? `
    <div class="detail-card">
      <div class="detail-title">Information Disclosure Headers</div>
      <table class="detail-table">
        <tr><th>Header</th><th>Value</th></tr>
        ${hdrs.info_disclosure.map(d => `<tr><td>${esc(d.header)}</td><td>${esc(d.value)}</td></tr>`).join('')}
      </table>
    </div>` : ''}`;
}

function renderPorts(ports) {
  const el = document.getElementById('portsDetails');
  if (!ports) { el.innerHTML = '<p class="loading-text">No port scan data available.</p>'; return; }
  const open = ports.open_ports || [];
  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-title">Open Ports (${open.length} found)</div>
      ${open.length ? `
      <table class="detail-table">
        <tr><th>Port</th><th>Service</th><th>Severity</th></tr>
        ${open.map(p => `<tr>
          <td>${p.port}</td>
          <td>${esc(p.service)}</td>
          <td><span class="severity-pill ${p.severity}">${p.severity}</span></td>
        </tr>`).join('')}
      </table>` : '<p class="loading-text">No open ports detected.</p>'}
    </div>`;
}

function renderEndpoints(eps) {
  const el = document.getElementById('endpointsDetails');
  if (!eps) { el.innerHTML = '<p class="loading-text">No endpoint data available.</p>'; return; }
  const found = eps.discovered || [];
  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-title">Discovered Endpoints (${found.length} found)</div>
      ${found.length ? `
      <table class="detail-table">
        <tr><th>Path</th><th>Description</th><th>HTTP Status</th><th>Severity</th></tr>
        ${found.map(e => `<tr>
          <td>${esc(e.path)}</td>
          <td>${esc(e.description)}</td>
          <td>${e.status_code}</td>
          <td><span class="severity-pill ${e.severity}">${e.severity}</span></td>
        </tr>`).join('')}
      </table>` : '<p class="loading-text">No sensitive endpoints discovered.</p>'}
    </div>`;
}

function renderDNS(dns) {
  const el = document.getElementById('dnsDetails');
  if (!dns) { el.innerHTML = '<p class="loading-text">No DNS data available.</p>'; return; }
  el.innerHTML = `
    <div class="detail-card">
      <div class="detail-title">DNS Configuration</div>
      <table class="detail-table">
        <tr><th>Record Type</th><th>Value</th></tr>
        <tr><td>A Records</td><td>${esc((dns.a_records || []).join(', ') || 'None')}</td></tr>
        <tr><td>AAAA Records</td><td>${esc((dns.aaaa_records || []).join(', ') || 'None')}</td></tr>
        <tr><td>MX Records</td><td>${esc((dns.mx_records || []).join(', ') || 'None')}</td></tr>
        <tr><td>NS Records</td><td>${esc((dns.ns_records || []).join(', ') || 'None')}</td></tr>
        <tr><td>SPF Record</td><td>${dns.has_spf ? `<span class="tag good">Present</span> ${esc(dns.spf || '')}` : '<span class="tag missing">Missing</span>'}</td></tr>
        <tr><td>DMARC Record</td><td>${dns.has_dmarc ? `<span class="tag good">Present</span> ${esc(dns.dmarc || '')}` : '<span class="tag missing">Missing</span>'}</td></tr>
        <tr><td>CAA Records</td><td>${dns.has_caa ? '<span class="tag good">Present</span>' : '<span class="tag missing">Missing</span>'}</td></tr>
      </table>
    </div>`;
}

// ---- History ----
async function loadHistory() {
  const el = document.getElementById('historyTable');
  try {
    const res  = await fetch(`${API_BASE}/scans?limit=20`);
    const data = await res.json();
    if (!data.scans || data.scans.length === 0) {
      el.innerHTML = '<p class="loading-text">No scans yet.</p>';
      return;
    }
    el.innerHTML = `
      <table class="history-table">
        <thead><tr><th>#</th><th>Domain</th><th>Status</th><th>Grade</th><th>Risk Score</th><th>Scanned</th><th>Actions</th></tr></thead>
        <tbody>
          ${data.scans.map(s => `
            <tr onclick="viewScan(${s.id})">
              <td>${s.id}</td>
              <td>${esc(s.domain)}</td>
              <td><span class="status-badge ${s.status}">${s.status}</span></td>
              <td>${s.risk_grade || '—'}</td>
              <td>${s.risk_score !== null ? s.risk_score.toFixed(1) : '—'}</td>
              <td>${formatDate(s.created_at)}</td>
              <td>
                ${s.status === 'completed'
                  ? `<a href="/api/reports/${s.id}/pdf" target="_blank" onclick="event.stopPropagation()" class="btn btn-outline" style="padding:.3rem .7rem;font-size:.8rem;">PDF</a>`
                  : ''}
                <button onclick="event.stopPropagation(); deleteScan(${s.id})" class="btn" style="padding:.3rem .7rem;font-size:.8rem;background:#fed7d7;color:#c53030;border:none;">✕</button>
              </td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  } catch {
    el.innerHTML = '<p class="loading-text">Could not load scan history.</p>';
  }
}

async function viewScan(scanId) {
  try {
    const res  = await fetch(`${API_BASE}/scans/${scanId}`);
    const scan = await res.json();
    if (scan.status === 'completed') {
      currentScanId = scan.id;
      renderResults(scan);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  } catch {}
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan?')) return;
  await fetch(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
  if (currentScanId === scanId) {
    resultsSection.classList.add('hidden');
    currentScanId = null;
  }
  loadHistory();
}

// ---- Helpers ----
function setScanningState(loading) {
  scanBtn.disabled = loading;
  document.querySelector('.btn-text').classList.toggle('hidden', loading);
  document.querySelector('.btn-spinner').classList.toggle('hidden', !loading);
}

function showFormError(msg) {
  formError.textContent = msg;
  formError.classList.remove('hidden');
}

function hideFormError() {
  formError.classList.add('hidden');
}

function boolTag(val) {
  return val
    ? '<span class="tag good">Yes</span>'
    : '<span class="tag open">No</span>';
}

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function cap(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch { return iso; }
}

// ---- Init ----
loadHistory();
