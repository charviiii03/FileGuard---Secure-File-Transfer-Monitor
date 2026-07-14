/* FileGuard Dashboard — Client Logic */
'use strict';

// ─── STATE ───────────────────────────────────
const state = {
  events:     [],
  stats:      null,
  baseline:   {},
  charts:     {},
  intervalId: null,
  refreshMs:  8000,
};

// ─── UTILS ───────────────────────────────────
const $  = id => document.getElementById(id);
const fmt = ts => ts ? ts.replace('T',' ').slice(0,19) : '—';
const trunc = (s, n=45) => !s ? '—' : s.length > n ? '…'+s.slice(-(n-1)) : s;

function badge(text, cls) {
  return `<span class="badge badge-${cls}">${text}</span>`;
}
function severityBadge(sev) {
  const m = { INFO:'info', WARNING:'warning', CRITICAL:'critical' };
  return badge(sev||'—', m[sev]||'muted');
}
function hashBadge(s) {
  const m = { MATCH:'match', MISMATCH:'mismatch', NO_BASELINE:'muted', HASH_FAILED:'warning' };
  return badge(s||'—', m[s]||'muted');
}
function senseBadge(v) {
  return (v==='True'||v===true) ? badge('Yes','yes') : badge('No','no');
}
function typeBadge(t) {
  const m = { created:'success', modified:'warning', deleted:'critical', moved:'info' };
  return badge(t||'—', m[t]||'muted');
}
function destBadge(c) {
  if (!c || c==='NORMAL') return badge('Normal','muted');
  return badge(c,'critical');
}

// Relative time
function relTime(ts) {
  if (!ts) return '—';
  const diff = (Date.now() - new Date(ts)) / 1000;
  if (diff < 60)  return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff/60)}m ago`;
  return `${Math.round(diff/3600)}h ago`;
}

// ─── NAVIGATION ──────────────────────────────
function navigate(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const page = $('page-'+pageId);
  if (page) page.classList.add('active');
  document.querySelectorAll('[data-page="'+pageId+'"]').forEach(el => el.classList.add('active'));

  const titles = {
    dashboard: 'Monitoring Dashboard',
    events:    'Transfer Activity',
    alerts:    'Security Alerts',
    integrity: 'File Integrity',
    config:    'Monitoring Rules',
    report:    'Security Report',
  };
  $('page-title').textContent = titles[pageId] || pageId;

  if (pageId==='alerts')    loadAlerts();
  if (pageId==='integrity') loadIntegrity();
  if (pageId==='config')    loadConfig();
}

document.querySelectorAll('[data-page]').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    navigate(el.dataset.page);
    if (window.innerWidth < 769) $('sidebar').classList.remove('open');
  });
});

$('menu-btn').addEventListener('click', () => $('sidebar').classList.toggle('open'));

// ─── CLOCK ───────────────────────────────────
function tick() {
  $('topbar-time').textContent = new Date().toLocaleTimeString('en-GB',{hour12:false});
}
setInterval(tick, 1000); tick();

// ─── CHART HELPERS ───────────────────────────
const CHART_BASE = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      mode: 'index', intersect: false,
      backgroundColor: '#0f1e35',
      borderColor: 'rgba(99,179,237,0.2)',
      borderWidth: 1,
      titleColor: '#94a3b8',
      bodyColor: '#e2e8f0',
      padding: 10,
    }
  }
};
const GRID_OPT = { color: 'rgba(255,255,255,0.04)' };
const TICK_OPT = { color: '#475569', font:{ size:10, family:'JetBrains Mono' } };

function mkChart(id, type, data, opts={}) {
  const ctx = document.getElementById(id)?.getContext('2d');
  if (!ctx) return null;
  if (state.charts[id]) { state.charts[id].destroy(); }
  state.charts[id] = new Chart(ctx, { type, data, options: deepMerge(CHART_BASE, opts) });
  return state.charts[id];
}

function deepMerge(target, src) {
  const out = Object.assign({}, target);
  for (const k in src) {
    if (src[k] && typeof src[k]==='object' && !Array.isArray(src[k])) {
      out[k] = deepMerge(target[k]||{}, src[k]);
    } else { out[k] = src[k]; }
  }
  return out;
}

// ─── BUILD CHARTS ────────────────────────────
function buildCharts(stats) {
  // Timeline — gradient line
  const tl = stats.timeline || {};
  const tlLabels = Object.keys(tl).sort();
  const tlValues = tlLabels.map(k => tl[k]);

  mkChart('chart-timeline', 'line', {
    labels: tlLabels,
    datasets: [{
      data: tlValues,
      borderColor: '#3b82f6',
      backgroundColor: (ctx) => {
        const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 200);
        g.addColorStop(0,   'rgba(59,130,246,0.35)');
        g.addColorStop(0.5, 'rgba(59,130,246,0.1)');
        g.addColorStop(1,   'rgba(59,130,246,0)');
        return g;
      },
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
      pointHoverBackgroundColor: '#60a5fa',
      tension: 0.4,
      fill: true,
    }]
  }, {
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          title: (items) => items[0].label,
          label: (item) => ` ${item.raw} events`
        }
      }
    },
    scales: {
      x: { ticks: { ...TICK_OPT, maxTicksLimit:8 }, grid: GRID_OPT },
      y: { ticks: TICK_OPT, grid: GRID_OPT, beginAtZero: true },
    }
  });

  // Severity donut
  const sc = stats.severity_counts || {};
  mkChart('chart-severity', 'doughnut', {
    labels: ['INFO','WARNING','CRITICAL'],
    datasets: [{
      data: [sc.INFO||0, sc.WARNING||0, sc.CRITICAL||0],
      backgroundColor: ['#3b82f6','#f59e0b','#ef4444'],
      borderWidth: 0,
      hoverOffset: 5,
    }]
  }, {
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: { color:'#64748b', font:{size:10}, padding:10, boxWidth:9 }
      }
    },
    cutout: '68%',
  });

  // Event types bar
  const ec = stats.event_counts || {};
  const etLabels = Object.keys(ec);
  const etColors = etLabels.map(k => ({ created:'#22c55e', modified:'#f59e0b', deleted:'#ef4444', moved:'#3b82f6' }[k]||'#475569'));
  mkChart('chart-events', 'bar', {
    labels: etLabels,
    datasets: [{
      data: etLabels.map(k=>ec[k]),
      backgroundColor: etColors.map(c => c+'99'),
      borderColor:     etColors,
      borderWidth: 1,
      borderRadius: 5,
      borderSkipped: false,
    }]
  }, {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: TICK_OPT, grid: { display: false } },
      y: { ticks: TICK_OPT, grid: GRID_OPT, beginAtZero: true },
    }
  });

  // Destinations horizontal bar
  const dc = stats.dest_counts || {};
  const dcLabels = Object.keys(dc);
  if (dcLabels.length === 0) {
    const ctx = document.getElementById('chart-dest')?.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#475569';
      ctx.font = '12px Inter';
      ctx.textAlign = 'center';
      ctx.fillText('No suspicious transfers', ctx.canvas.width/2, 80);
    }
  } else {
    const dcColors = dcLabels.map(k => ({ USB_DRIVE:'#ef4444', NETWORK_SHARE:'#f59e0b', CLOUD_SYNC:'#14b8a6', UNKNOWN_DESTINATION:'#a78bfa' }[k]||'#475569'));
    mkChart('chart-dest', 'bar', {
      labels: dcLabels,
      datasets: [{
        data: dcLabels.map(k=>dc[k]),
        backgroundColor: dcColors.map(c=>c+'99'),
        borderColor: dcColors,
        borderWidth: 1,
        borderRadius: 5,
        borderSkipped: false,
      }]
    }, {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: TICK_OPT, grid: GRID_OPT, beginAtZero: true },
        y: { ticks: { ...TICK_OPT, font:{size:9.5,family:'Inter'} }, grid: { display: false } },
      }
    });
  }
}

// ─── INTEGRITY RING ──────────────────────────
function drawIntegrityRing(pct) {
  const canvas = $('integrity-ring-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = 60, cy = 60, r = 48, lw = 8;
  const ang = (pct/100) * Math.PI * 2 - Math.PI/2;

  ctx.clearRect(0,0,120,120);

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI*2);
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = lw;
  ctx.stroke();

  // Progress
  const g = ctx.createLinearGradient(0, 0, 120, 120);
  g.addColorStop(0, '#14b8a6');
  g.addColorStop(1, '#3b82f6');
  ctx.beginPath();
  ctx.arc(cx, cy, r, -Math.PI/2, ang);
  ctx.strokeStyle = g;
  ctx.lineWidth = lw;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Glow dot
  const dx = cx + r * Math.cos(ang);
  const dy = cy + r * Math.sin(ang);
  ctx.beginPath();
  ctx.arc(dx, dy, 4, 0, Math.PI*2);
  ctx.fillStyle = '#2dd4bf';
  ctx.shadowColor = '#14b8a6';
  ctx.shadowBlur = 10;
  ctx.fill();
}

// ─── ALERTS PANEL ────────────────────────────
function buildAlertsPanel(events) {
  const container = $('alerts-list');
  if (!container) return;

  const alertEvents = events.filter(r => r.severity === 'CRITICAL' || r.severity === 'WARNING').slice(0, 8);

  if (!alertEvents.length) {
    container.innerHTML = '<div class="alert-empty">✓ No alerts at this time</div>';
    return;
  }

  const iconMap = {
    CRITICAL: `<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.2"/><path d="M6.5 3.5v3M6.5 8.5v.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
    WARNING:  `<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 1.5L1 11h11L6.5 1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M6.5 5v3M6.5 9.5v.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
  };
  const sevClass = { CRITICAL:'high', WARNING:'medium' };

  const typeLabels = {
    created: 'New File Created',
    modified: 'File Modified',
    deleted: 'File Deleted',
    moved: 'File Moved',
  };

  let html = alertEvents.map(r => {
    const sev = r.severity;
    const sc  = sevClass[sev]||'low';
    const label = typeLabels[r.event_type] || r.event_type || 'Unknown Event';
    const path  = r.src_path ? trunc(r.src_path, 28) : '—';

    return `<div class="alert-item">
      <div class="alert-icon ${sc}">${iconMap[sev]||iconMap.WARNING}</div>
      <div class="alert-body">
        <div class="alert-title">${label}</div>
        <div class="alert-path">${path}</div>
      </div>
      <div class="alert-meta">
        <span class="alert-time">${relTime(r.timestamp)}</span>
        <span class="alert-sev ${sc}">${sev}</span>
      </div>
    </div>`;
  }).join('');

  const remaining = alertEvents.length;
  if (remaining >= 8) {
    html += `<div class="more-alerts" data-page="alerts">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="1.5" fill="currentColor"/><circle cx="10" cy="6" r="1.5" fill="currentColor"/><circle cx="2" cy="6" r="1.5" fill="currentColor"/></svg>
      View all alerts
    </div>`;
  }

  container.innerHTML = html;
  container.querySelectorAll('[data-page]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); navigate(el.dataset.page); });
  });
}

// ─── LOAD OVERVIEW ───────────────────────────
async function loadOverview() {
  try {
    const [sr, er] = await Promise.all([fetch('/api/stats'), fetch('/api/events')]);
    const stats  = await sr.json();
    const events = await er.json();
    state.stats  = stats;
    state.events = events;

    // Stat bar
    $('s-total').textContent       = stats.total ?? '—';
    $('s-sensitive').textContent   = stats.sensitive_count ?? '—';
    $('s-warning').textContent     = stats.warning_count ?? '—';
    $('s-critical').textContent    = stats.critical_count ?? '—';
    $('s-integrity').textContent   = stats.integrity_fails ?? '—';
    $('s-unauthorized').textContent= stats.unauthorized ?? '—';

    // Alert nav badge
    const alertCount = (stats.warning_count||0)+(stats.critical_count||0);
    const badge = $('alert-badge');
    if (alertCount > 0) { badge.textContent = alertCount>99?'99+':alertCount; badge.classList.add('show'); }
    else badge.classList.remove('show');

    // Charts
    buildCharts(stats);

    // Integrity ring
    const total  = stats.total || 0;
    const bad    = (stats.integrity_fails||0) + (stats.unauthorized||0);
    const healthy = Math.max(0, total - bad);
    const pct   = total > 0 ? Math.round((healthy/total)*100) : 100;
    drawIntegrityRing(pct);
    const pctEl = $('integrity-pct');
    if (pctEl) pctEl.textContent = pct+'%';
    const hEl = $('healthy-count');    if (hEl) hEl.textContent = healthy;
    const mEl = $('modified-count');   if (mEl) mEl.textContent = stats.warning_count ?? '—';

    // Recent events table
    renderRecentTable(events.slice(0, 8));

    // Alerts panel
    buildAlertsPanel(events);

    // Status
    $('status-dot').className = 'sys-dot online';
    $('status-text').textContent = 'All Systems Online';

    // Refresh event table if visible
    if ($('page-events').classList.contains('active')) renderEventTable(events);

  } catch(err) {
    console.error(err);
    $('status-dot').className = 'sys-dot error';
    $('status-text').textContent = 'API Error';
  }
}

// ─── RECENT TABLE ────────────────────────────
function renderRecentTable(rows) {
  const tbody = $('recent-tbody');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No events recorded yet.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `<tr>
    <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim)">${fmt(r.timestamp)}</td>
    <td>${typeBadge(r.event_type)}</td>
    <td title="${r.src_path}" style="color:var(--text)">${trunc(r.src_path, 40)}</td>
    <td title="${r.src_path}">${r.src_path ? trunc(r.src_path.split('/').slice(0,-1).join('/'), 24)||'/' : '—'}</td>
    <td>${severityBadge(r.severity)}</td>
    <td>${hashBadge(r.hash_status)}</td>
  </tr>`).join('');
}

// ─── FULL EVENT TABLE ─────────────────────────
function renderEventTable(rows) {
  const search  = ($('event-search')?.value||'').toLowerCase();
  const sevFilt = $('event-filter-severity')?.value||'';
  const typeFilt= $('event-filter-type')?.value||'';

  let filtered = rows.filter(r => {
    const ok1 = !search || (r.src_path||'').toLowerCase().includes(search) || (r.dest_path||'').toLowerCase().includes(search) || (r.severity||'').toLowerCase().includes(search) || (r.event_type||'').toLowerCase().includes(search);
    const ok2 = !sevFilt  || r.severity   === sevFilt;
    const ok3 = !typeFilt || r.event_type === typeFilt;
    return ok1 && ok2 && ok3;
  });

  $('event-count-label').textContent = `Showing ${filtered.length} of ${rows.length} events`;
  const tbody = $('event-tbody');

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No events match your filter.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(r => `<tr>
    <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim)">${fmt(r.timestamp)}</td>
    <td>${typeBadge(r.event_type)}</td>
    <td title="${r.src_path}" style="color:var(--text)">${trunc(r.src_path,50)}</td>
    <td title="${r.dest_path}">${r.dest_path ? trunc(r.dest_path,35) : '—'}</td>
    <td>${senseBadge(r.is_sensitive)}</td>
    <td>${destBadge(r.dest_category)}</td>
    <td>${severityBadge(r.severity)}</td>
    <td>${hashBadge(r.hash_status)}</td>
  </tr>`).join('');
}

['event-search','event-filter-severity','event-filter-type'].forEach(id => {
  $( id)?.addEventListener('input',  () => renderEventTable(state.events));
  $(id)?.addEventListener('change', () => renderEventTable(state.events));
});

// ─── ALERTS PAGE ─────────────────────────────
async function loadAlerts() {
  const pre = $('alerts-pre');
  pre.textContent = 'Loading…';
  try {
    const data = await (await fetch('/api/alerts')).json();
    const lines = data.lines || [];
    pre.textContent = lines.length ? lines.join('\n') : 'No alert entries yet.';
    pre.parentElement.scrollTop = pre.parentElement.scrollHeight;
  } catch(e) { pre.textContent = 'Failed: '+e.message; }
}
$('btn-refresh-alerts')?.addEventListener('click', loadAlerts);

// ─── INTEGRITY PAGE ──────────────────────────
async function loadIntegrity() {
  try {
    const [blR, evR] = await Promise.all([fetch('/api/baseline'),fetch('/api/events')]);
    const baseline = await blR.json();
    const events   = await evR.json();

    const blTbody = $('baseline-tbody');
    const entries = Object.entries(baseline);
    blTbody.innerHTML = entries.length
      ? entries.map(([path,hash])=>`<tr>
          <td title="${path}" style="color:var(--text)">${trunc(path,55)}</td>
          <td><code>${hash}</code></td>
          <td><span class="badge badge-match">Stored</span></td>
        </tr>`).join('')
      : '<tr><td colspan="3" class="empty-cell">No baseline hashes stored yet.</td></tr>';

    const mmRows  = events.filter(r=>r.hash_status==='MISMATCH');
    const mmTbody = $('mismatch-tbody');
    mmTbody.innerHTML = mmRows.length
      ? mmRows.map(r=>`<tr>
          <td style="font-family:'JetBrains Mono',monospace;font-size:11px">${fmt(r.timestamp)}</td>
          <td title="${r.src_path}" style="color:var(--text)">${trunc(r.src_path,45)}</td>
          <td><code>${r.stored_hash||'—'}</code></td>
          <td><code style="color:var(--red-lt)">${r.current_hash||'—'}</code></td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="empty-cell">✓ No hash mismatches detected.</td></tr>';
  } catch(e) { console.error(e); }
}

// ─── CONFIG PAGE ─────────────────────────────
async function loadConfig() {
  const grid = $('config-grid');
  grid.innerHTML = '<div class="config-card"><div class="empty-cell">Loading…</div></div>';
  try {
    const cfg = await (await fetch('/api/config')).json();
    grid.innerHTML = `
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M1.5 3.5h10M1.5 6.5h10M1.5 9.5h6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
          Monitored Directories
        </div>
        <ul class="config-list">
          ${(cfg.monitored_directories||[]).map(d=>`<li><span class="config-dot"></span>${d}</li>`).join('')||'<li>None configured</li>'}
        </ul>
      </div>
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="2" y="4.5" width="9" height="7" rx="1" stroke="currentColor" stroke-width="1.1"/><path d="M4.5 4.5V3a2 2 0 0 1 4 0v1.5" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
          Sensitive Paths
        </div>
        <ul class="config-list">
          ${(cfg.sensitive_paths||[]).map(d=>`<li><span class="config-dot" style="background:var(--amber)"></span>${d}</li>`).join('')||'<li>None</li>'}
        </ul>
      </div>
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1.5" y="1.5" width="10" height="10" rx="1.2" stroke="currentColor" stroke-width="1.1"/><path d="M4.5 6.5h4M6.5 4.5v4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
          Sensitive Extensions
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:4px">
          ${(cfg.sensitive_extensions||[]).map(e=>`<span class="badge badge-warning">${e}</span>`).join('')||'—'}
        </div>
      </div>
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.1"/><path d="M6.5 3.5v4l2 2" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Monitor Settings
        </div>
        <div class="config-kv">
          <div class="config-kv-row"><span class="config-key">Hash Algorithm</span><span class="config-val">${cfg.hash_algorithm||'sha256'}</span></div>
          <div class="config-kv-row"><span class="config-key">Recursive</span><span class="config-val">${cfg.monitoring_settings?.recursive?'Yes':'No'}</span></div>
          <div class="config-kv-row"><span class="config-key">Hash on Create</span><span class="config-val">${cfg.monitoring_settings?.hash_on_create?'Yes':'No'}</span></div>
          <div class="config-kv-row"><span class="config-key">Hash on Modify</span><span class="config-val">${cfg.monitoring_settings?.hash_on_modify?'Yes':'No'}</span></div>
          <div class="config-kv-row"><span class="config-key">Hash on Move</span><span class="config-val">${cfg.monitoring_settings?.hash_on_move?'Yes':'No'}</span></div>
        </div>
      </div>
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="6.5" cy="4.5" r="2" stroke="currentColor" stroke-width="1.1"/><path d="M2 11c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
          Allowed Users
        </div>
        <ul class="config-list">
          ${(cfg.allowed_users||[]).map(u=>`<li><span class="config-dot" style="background:var(--teal)"></span>${u}</li>`).join('')||'<li>None specified</li>'}
        </ul>
      </div>
      <div class="config-card">
        <div class="config-card-title">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 6.5h9M8.5 4l3 2.5-3 2.5" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Ignore Patterns
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:4px">
          ${(cfg.monitoring_settings?.ignore_patterns||[]).map(p=>`<span class="badge badge-muted">${p}</span>`).join('')||'—'}
        </div>
      </div>
    `;
  } catch(e) {
    grid.innerHTML = `<div class="config-card"><div class="empty-cell">Failed to load config: ${e.message}</div></div>`;
  }
}

// ─── REPORT PAGE ─────────────────────────────
$('btn-gen-report')?.addEventListener('click', async () => {
  const pre = $('report-pre');
  const btn = $('btn-gen-report');
  btn.textContent = 'Generating…';
  btn.disabled = true;
  pre.textContent = 'Please wait…';
  try {
    const data = await (await fetch('/api/report/generate',{method:'POST'})).json();
    pre.textContent = data.success ? data.report : 'Error: '+data.error;
  } catch(e) {
    pre.textContent = 'Request failed: '+e.message;
  } finally {
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 2v7M4.5 6.5L7 9l2.5-2.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 11h10" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg> Generate Report`;
    btn.disabled = false;
  }
});

// ─── REFRESH ─────────────────────────────────
$('btn-refresh')?.addEventListener('click', () => loadOverview());

// ─── INIT ────────────────────────────────────
(async function init() {
  await loadOverview();
  state.intervalId = setInterval(loadOverview, state.refreshMs);
})();

/* ─────────────────────────────────────────────
   GLOBAL TOP SEARCH
───────────────────────────────────────────── */

(function initialiseGlobalSearch() {
  const globalSearch = document.getElementById('global-search');

  if (!globalSearch) {
    console.error('Global search input was not found.');
    return;
  }

  const pageKeywords = [
    {
      page: 'dashboard',
      words: [
        'dashboard',
        'monitoring dashboard',
        'overview',
        'home'
      ]
    },
    {
      page: 'events',
      words: [
        'transfer activity',
        'activity',
        'events',
        'file events'
      ]
    },
    {
      page: 'alerts',
      words: [
        'security alerts',
        'alerts',
        'warning',
        'critical alerts'
      ]
    },
    {
      page: 'integrity',
      words: [
        'file integrity',
        'integrity',
        'hash',
        'hash mismatch',
        'baseline'
      ]
    },
    {
      page: 'config',
      words: [
        'monitoring rules',
        'rules',
        'configuration',
        'config'
      ]
    },
    {
      page: 'report',
      words: [
        'security report',
        'report',
        'pdf report'
      ]
    }
  ];

  function openPage(pageName) {
    const pageLink = document.querySelector(
      `.nav-item[data-page="${pageName}"]`
    );

    if (!pageLink) {
      return false;
    }

    pageLink.click();
    return true;
  }

  function filterEventRows(query) {
    const eventSearch = document.getElementById('event-search');

    /*
     * Use the existing Transfer Activity search functionality.
     */
    if (eventSearch) {
      eventSearch.value = query;

      eventSearch.dispatchEvent(
        new Event('input', {
          bubbles: true
        })
      );
    }

    /*
     * Fallback filtering in case dashboard.js does not already
     * have an event-search listener.
     */
    const rows = document.querySelectorAll('#event-tbody tr');
    const normalizedQuery = query.toLowerCase();

    rows.forEach(function (row) {
      const rowText = row.textContent.toLowerCase();

      row.style.display =
        !normalizedQuery || rowText.includes(normalizedQuery)
          ? ''
          : 'none';
    });
  }

  function performGlobalSearch() {
    const originalQuery = globalSearch.value.trim();
    const query = originalQuery.toLowerCase();

    if (!query) {
      return;
    }

    /*
     * First check whether the user entered the name
     * of a dashboard section.
     */
    const matchedPage = pageKeywords.find(function (item) {
      return item.words.some(function (word) {
        return query === word;
      });
    });

    if (matchedPage) {
      openPage(matchedPage.page);
      globalSearch.select();
      return;
    }

    /*
     * Otherwise treat the query as an event/file search.
     * Examples:
     * test1.txt
     * modified
     * warning
     * employee_records
     */
    openPage('events');

    window.setTimeout(function () {
      filterEventRows(originalQuery);
    }, 100);
  }

  globalSearch.addEventListener('keydown', function (event) {
    if (event.key === 'Enter') {
      event.preventDefault();
      performGlobalSearch();
    }

    if (event.key === 'Escape') {
      globalSearch.value = '';

      const eventSearch =
        document.getElementById('event-search');

      if (eventSearch) {
        eventSearch.value = '';

        eventSearch.dispatchEvent(
          new Event('input', {
            bubbles: true
          })
        );
      }

      filterEventRows('');
      globalSearch.blur();
    }
  });

  /*
   * Clicking the search icon also performs the search.
   */
  const searchContainer =
    globalSearch.closest('.topbar-search');

  const searchIcon =
    searchContainer?.querySelector('svg');

  if (searchIcon) {
    searchIcon.style.cursor = 'pointer';

    searchIcon.addEventListener('click', function () {
      performGlobalSearch();
    });
  }
})();