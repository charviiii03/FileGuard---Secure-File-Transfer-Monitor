/* dashboard/static/js/dashboard.js
   SentinelShield — all client-side logic
*/

'use strict';

// ──────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────

const state = {
  stats:     null,
  events:    [],
  baseline:  {},
  charts:    {},
  refreshMs: 8000,
  intervalId: null,
};

// ──────────────────────────────────────────────
// UTILS
// ──────────────────────────────────────────────

const $ = id => document.getElementById(id);
const fmt = ts => ts ? ts.replace('T',' ').slice(0,19) : '—';

function severityBadge(sev) {
  const map = { INFO:'badge-info', WARNING:'badge-warning', CRITICAL:'badge-critical' };
  return `<span class="badge ${map[sev]||'badge-muted'}">${sev||'—'}</span>`;
}
function hashBadge(status) {
  const map = { MATCH:'badge-match', MISMATCH:'badge-mismatch', NO_BASELINE:'badge-muted', HASH_FAILED:'badge-warning' };
  return `<span class="badge ${map[status]||'badge-muted'}">${status||'—'}</span>`;
}
function sensitiveBadge(val) {
  return val === 'True' || val === true
    ? '<span class="badge badge-yes">Yes</span>'
    : '<span class="badge badge-no">No</span>';
}
function eventTypeBadge(type) {
  const map = {created:'badge-success', modified:'badge-warning', deleted:'badge-critical', moved:'badge-info'};
  return `<span class="badge ${map[type]||'badge-muted'}">${type||'—'}</span>`;
}
function destBadge(cat) {
  if (!cat || cat === 'NORMAL') return '<span class="badge badge-muted">Normal</span>';
  return `<span class="badge badge-critical">${cat}</span>`;
}

function truncate(str, n=45) {
  if (!str) return '—';
  return str.length > n ? '…' + str.slice(-(n-1)) : str;
}

// ──────────────────────────────────────────────
// NAVIGATION
// ──────────────────────────────────────────────

function navigate(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const page = document.getElementById('page-' + pageId);
  if (page) page.classList.add('active');

  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.dataset.page === pageId) n.classList.add('active');
  });

  const titles = {
    dashboard: 'Overview',
    events:    'Event Log',
    alerts:    'Alerts',
    integrity: 'Integrity Check',
    config:    'Configuration',
    report:    'Audit Report',
  };
  $('page-title').textContent = titles[pageId] || pageId;

  // Lazy-load page data
  if (pageId === 'alerts')    loadAlerts();
  if (pageId === 'integrity') loadIntegrity();
  if (pageId === 'config')    loadConfig();
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    navigate(item.dataset.page);
    if (window.innerWidth < 769) document.getElementById('sidebar').classList.remove('open');
  });
});

// "View all" link in recent events table
document.querySelector('.table-link').addEventListener('click', e => {
  e.preventDefault();
  navigate('events');
});

$('menu-btn').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// ──────────────────────────────────────────────
// CLOCK
// ──────────────────────────────────────────────

function updateClock() {
  const now = new Date();
  $('topbar-time').textContent = now.toLocaleTimeString('en-GB', { hour12:false });
}
setInterval(updateClock, 1000);
updateClock();

// ──────────────────────────────────────────────
// CHART SETUP
// ──────────────────────────────────────────────

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
};
const COLORS = {
  blue:   '#1a73e8',
  red:    '#ef4444',
  amber:  '#f59e0b',
  teal:   '#00b4a6',
  purple: '#a855f7',
  green:  '#22c55e',
  gray:   '#4d6b84',
};

function mkChart(id, type, data, opts={}) {
  const ctx = document.getElementById(id)?.getContext('2d');
  if (!ctx) return null;
  if (state.charts[id]) state.charts[id].destroy();
  state.charts[id] = new Chart(ctx, {
    type,
    data,
    options: { ...CHART_DEFAULTS, ...opts },
  });
  return state.charts[id];
}

function buildCharts(stats) {
  // Timeline
  const tl = stats.timeline || {};
  const tlLabels = Object.keys(tl).sort();
  const tlValues = tlLabels.map(k => tl[k]);

  mkChart('chart-timeline', 'line', {
    labels: tlLabels,
    datasets: [{
      label: 'Events',
      data: tlValues,
      borderColor: COLORS.blue,
      backgroundColor: 'rgba(26,115,232,.12)',
      borderWidth: 1.8,
      pointRadius: 2,
      tension: 0.4,
      fill: true,
    }],
  }, {
    ...CHART_DEFAULTS,
    plugins: {
      ...CHART_DEFAULTS.plugins,
      legend: { display: false },
    },
    scales: {
      x: { ticks: { color: '#4d6b84', font:{size:10}, maxTicksLimit:10 }, grid: { color:'rgba(255,255,255,.04)' } },
      y: { ticks: { color: '#4d6b84', font:{size:10} }, grid: { color:'rgba(255,255,255,.04)' }, beginAtZero:true },
    },
  });

  // Severity donut
  const sc = stats.severity_counts || {};
  mkChart('chart-severity', 'doughnut', {
    labels: ['INFO','WARNING','CRITICAL'],
    datasets: [{
      data: [sc.INFO||0, sc.WARNING||0, sc.CRITICAL||0],
      backgroundColor: [COLORS.blue, COLORS.amber, COLORS.red],
      borderWidth: 0,
      hoverOffset: 6,
    }],
  }, {
    ...CHART_DEFAULTS,
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: { color:'#7a9ab5', font:{size:11}, padding:14, boxWidth:12 },
      },
    },
    cutout: '65%',
  });

  // Event types bar
  const ec = stats.event_counts || {};
  const etLabels = Object.keys(ec);
  const etColors = etLabels.map(k => ({created:COLORS.green, modified:COLORS.amber, deleted:COLORS.red, moved:COLORS.blue}[k]||COLORS.gray));
  mkChart('chart-events', 'bar', {
    labels: etLabels,
    datasets: [{
      label: 'Count',
      data: etLabels.map(k => ec[k]),
      backgroundColor: etColors,
      borderRadius: 4,
      borderSkipped: false,
    }],
  }, {
    ...CHART_DEFAULTS,
    scales: {
      x: { ticks:{color:'#4d6b84',font:{size:11}}, grid:{display:false} },
      y: { ticks:{color:'#4d6b84',font:{size:11}}, grid:{color:'rgba(255,255,255,.04)'}, beginAtZero:true },
    },
  });

  // Destination bar (horizontal)
  const dc = stats.dest_counts || {};
  const dcLabels = Object.keys(dc);
  const dcColors = dcLabels.map(k => ({
    USB_DRIVE: COLORS.red,
    NETWORK_SHARE: COLORS.amber,
    CLOUD_SYNC: COLORS.teal,
    UNKNOWN_DESTINATION: COLORS.purple,
  }[k]||COLORS.gray));

  if (dcLabels.length === 0) {
    // Show placeholder
    const ctx = document.getElementById('chart-dest')?.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#4d6b84';
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No suspicious transfers detected', ctx.canvas.width/2, 90);
    }
  } else {
    mkChart('chart-dest', 'bar', {
      labels: dcLabels,
      datasets: [{
        label: 'Count',
        data: dcLabels.map(k => dc[k]),
        backgroundColor: dcColors,
        borderRadius: 4,
        borderSkipped: false,
      }],
    }, {
      ...CHART_DEFAULTS,
      indexAxis: 'y',
      scales: {
        x: { ticks:{color:'#4d6b84',font:{size:11}}, grid:{color:'rgba(255,255,255,.04)'}, beginAtZero:true },
        y: { ticks:{color:'#7a9ab5',font:{size:11}}, grid:{display:false} },
      },
    });
  }
}

// ──────────────────────────────────────────────
// LOAD OVERVIEW
// ──────────────────────────────────────────────

async function loadOverview() {
  try {
    const [statsRes, eventsRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/events'),
    ]);
    const stats  = await statsRes.json();
    const events = await eventsRes.json();
    state.stats  = stats;
    state.events = events;

    // Stat cards
    $('s-total').textContent       = stats.total ?? '—';
    $('s-sensitive').textContent   = stats.sensitive_count ?? '—';
    $('s-warning').textContent     = stats.warning_count ?? '—';
    $('s-critical').textContent    = stats.critical_count ?? '—';
    $('s-integrity').textContent   = stats.integrity_fails ?? '—';
    $('s-unauthorized').textContent= stats.unauthorized ?? '—';

    // Alert badge on nav
    const alertCount = (stats.warning_count||0) + (stats.critical_count||0);
    const badge = $('alert-badge');
    if (alertCount > 0) {
      badge.textContent = alertCount > 99 ? '99+' : alertCount;
      badge.classList.add('show');
    } else {
      badge.classList.remove('show');
    }

    // Charts
    buildCharts(stats);

    // Recent events (top 10)
    renderRecentTable(events.slice(0, 10));

    // Status
    $('status-dot').className = 'status-dot online';
    $('status-text').textContent = 'Connected';

    // Also refresh event log if visible
    if (document.getElementById('page-events').classList.contains('active')) {
      renderEventTable(events);
    }

  } catch (err) {
    console.error('Overview load error:', err);
    $('status-dot').className = 'status-dot error';
    $('status-text').textContent = 'API error';
  }
}

// ──────────────────────────────────────────────
// RECENT TABLE (overview)
// ──────────────────────────────────────────────

function renderRecentTable(rows) {
  const tbody = $('recent-tbody');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No events recorded yet.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td title="${r.timestamp}">${fmt(r.timestamp)}</td>
      <td>${eventTypeBadge(r.event_type)}</td>
      <td title="${r.src_path}">${truncate(r.src_path, 50)}</td>
      <td>${sensitiveBadge(r.is_sensitive)}</td>
      <td>${severityBadge(r.severity)}</td>
      <td>${hashBadge(r.hash_status)}</td>
    </tr>
  `).join('');
}

// ──────────────────────────────────────────────
// FULL EVENT LOG
// ──────────────────────────────────────────────

function renderEventTable(rows) {
  const search   = ($('event-search')?.value || '').toLowerCase();
  const sevFilt  = $('event-filter-severity')?.value || '';
  const typeFilt = $('event-filter-type')?.value || '';

  let filtered = rows.filter(r => {
    const matchSearch = !search ||
      (r.src_path||'').toLowerCase().includes(search) ||
      (r.dest_path||'').toLowerCase().includes(search) ||
      (r.severity||'').toLowerCase().includes(search) ||
      (r.event_type||'').toLowerCase().includes(search);
    const matchSev  = !sevFilt  || r.severity   === sevFilt;
    const matchType = !typeFilt || r.event_type === typeFilt;
    return matchSearch && matchSev && matchType;
  });

  $('event-count-label').textContent = `Showing ${filtered.length} of ${rows.length} events`;

  const tbody = $('event-tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-row">No events match your filter.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(r => `
    <tr>
      <td title="${r.timestamp}">${fmt(r.timestamp)}</td>
      <td>${eventTypeBadge(r.event_type)}</td>
      <td title="${r.src_path}">${truncate(r.src_path, 55)}</td>
      <td title="${r.dest_path}">${r.dest_path ? truncate(r.dest_path, 40) : '—'}</td>
      <td>${sensitiveBadge(r.is_sensitive)}</td>
      <td>${destBadge(r.dest_category)}</td>
      <td>${severityBadge(r.severity)}</td>
      <td>${hashBadge(r.hash_status)}</td>
    </tr>
  `).join('');
}

// Wire up filters
['event-search','event-filter-severity','event-filter-type'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => renderEventTable(state.events));
  document.getElementById(id)?.addEventListener('change', () => renderEventTable(state.events));
});

// ──────────────────────────────────────────────
// ALERTS LOG
// ──────────────────────────────────────────────

async function loadAlerts() {
  const pre = $('alerts-pre');
  pre.textContent = 'Loading…';
  try {
    const res  = await fetch('/api/alerts');
    const data = await res.json();
    const lines = data.lines || [];
    if (!lines.length) {
      pre.textContent = 'No alert entries yet.';
    } else {
      pre.textContent = lines.join('\n');
      $('alerts-log').scrollTop = $('alerts-log').scrollHeight;
    }
  } catch (e) {
    pre.textContent = 'Failed to load alert log: ' + e.message;
  }
}

$('btn-refresh-alerts').addEventListener('click', loadAlerts);

// ──────────────────────────────────────────────
// INTEGRITY
// ──────────────────────────────────────────────

async function loadIntegrity() {
  try {
    const [blRes, evRes] = await Promise.all([
      fetch('/api/baseline'),
      fetch('/api/events'),
    ]);
    const baseline = await blRes.json();
    const events   = await evRes.json();
    state.baseline = baseline;

    // Baseline table
    const blTbody = $('baseline-tbody');
    const blEntries = Object.entries(baseline);
    if (!blEntries.length) {
      blTbody.innerHTML = '<tr><td colspan="3" class="empty-row">No baseline hashes stored yet.</td></tr>';
    } else {
      blTbody.innerHTML = blEntries.map(([path, hash]) => `
        <tr>
          <td title="${path}">${truncate(path, 60)}</td>
          <td><code style="font-size:11px;color:#7a9ab5">${hash}</code></td>
          <td><span class="badge badge-match">Stored</span></td>
        </tr>
      `).join('');
    }

    // Mismatch table
    const mmRows  = events.filter(r => r.hash_status === 'MISMATCH');
    const mmTbody = $('mismatch-tbody');
    if (!mmRows.length) {
      mmTbody.innerHTML = '<tr><td colspan="4" class="empty-row">✔ No hash mismatches detected.</td></tr>';
    } else {
      mmTbody.innerHTML = mmRows.map(r => `
        <tr>
          <td>${fmt(r.timestamp)}</td>
          <td title="${r.src_path}">${truncate(r.src_path, 55)}</td>
          <td><code style="font-size:11px;color:#7a9ab5">${r.stored_hash||'—'}</code></td>
          <td><code style="font-size:11px;color:#fca5a5">${r.current_hash||'—'}</code></td>
        </tr>
      `).join('');
    }
  } catch (e) {
    console.error('Integrity load error:', e);
  }
}

// ──────────────────────────────────────────────
// CONFIG
// ──────────────────────────────────────────────

async function loadConfig() {
  const grid = $('config-grid');
  grid.innerHTML = '<div class="config-card"><div class="empty-row">Loading…</div></div>';
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();
    grid.innerHTML = `

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><path d="M1 3h13M1 7h13M1 11h13" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          Monitored Directories
        </div>
        <ul class="config-list">
          ${(cfg.monitored_directories||[]).map(d=>`<li><span class="config-dot"></span>${d}</li>`).join('')||'<li>None configured</li>'}
        </ul>
      </div>

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><rect x="2" y="2" width="11" height="11" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M5 7.5h5M7.5 5v5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          Sensitive Paths
        </div>
        <ul class="config-list">
          ${(cfg.sensitive_paths||[]).map(d=>`<li><span class="config-dot" style="background:var(--amber)"></span>${d}</li>`).join('')||'<li>None</li>'}
        </ul>
      </div>

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><path d="M3 3h9v9H3z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M6 6h3v3H6z" fill="currentColor" opacity=".3"/></svg>
          Sensitive Extensions
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
          ${(cfg.sensitive_extensions||[]).map(e=>`<span class="badge badge-warning">${e}</span>`).join('')||'—'}
        </div>
      </div>

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><circle cx="7.5" cy="7.5" r="5.5" stroke="currentColor" stroke-width="1.2"/><path d="M7.5 4.5v4l2 2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Monitor Settings
        </div>
        <div class="config-kv">
          <div class="config-kv-row">
            <span class="config-key">Hash Algorithm</span>
            <span class="config-val">${cfg.hash_algorithm||'sha256'}</span>
          </div>
          <div class="config-kv-row">
            <span class="config-key">Recursive</span>
            <span class="config-val">${cfg.monitoring_settings?.recursive ? 'Yes' : 'No'}</span>
          </div>
          <div class="config-kv-row">
            <span class="config-key">Hash on Create</span>
            <span class="config-val">${cfg.monitoring_settings?.hash_on_create ? 'Yes' : 'No'}</span>
          </div>
          <div class="config-kv-row">
            <span class="config-key">Hash on Modify</span>
            <span class="config-val">${cfg.monitoring_settings?.hash_on_modify ? 'Yes' : 'No'}</span>
          </div>
          <div class="config-kv-row">
            <span class="config-key">Hash on Move</span>
            <span class="config-val">${cfg.monitoring_settings?.hash_on_move ? 'Yes' : 'No'}</span>
          </div>
        </div>
      </div>

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><circle cx="7.5" cy="5" r="2.5" stroke="currentColor" stroke-width="1.2"/><path d="M2 13c0-3.036 2.462-5 5.5-5s5.5 1.964 5.5 5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          Allowed Users
        </div>
        <ul class="config-list">
          ${(cfg.allowed_users||[]).map(u=>`<li><span class="config-dot" style="background:var(--teal)"></span>${u}</li>`).join('')||'<li>None specified</li>'}
        </ul>
      </div>

      <div class="config-card">
        <div class="config-card-title">
          <svg viewBox="0 0 15 15" fill="none"><path d="M2 7.5h11M10 4.5l3 3-3 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Ignore Patterns
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
          ${(cfg.monitoring_settings?.ignore_patterns||[]).map(p=>`<span class="badge badge-muted">${p}</span>`).join('')||'—'}
        </div>
      </div>
    `;
  } catch (e) {
    grid.innerHTML = `<div class="config-card"><div class="empty-row">Failed to load config: ${e.message}</div></div>`;
  }
}

// ──────────────────────────────────────────────
// REPORT
// ──────────────────────────────────────────────

$('btn-gen-report').addEventListener('click', async () => {
  const pre = $('report-pre');
  const btn = $('btn-gen-report');
  btn.textContent = 'Generating…';
  btn.disabled = true;
  pre.textContent = 'Please wait…';
  try {
    const res  = await fetch('/api/report/generate', { method:'POST' });
    const data = await res.json();
    if (data.success) {
      pre.textContent = data.report;
    } else {
      pre.textContent = 'Error: ' + data.error;
    }
  } catch (e) {
    pre.textContent = 'Request failed: ' + e.message;
  } finally {
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2v8M5 7l3 3 3-3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 12h12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg> Generate Report`;
    btn.disabled = false;
  }
});

// ──────────────────────────────────────────────
// REFRESH
// ──────────────────────────────────────────────

$('btn-refresh').addEventListener('click', () => loadOverview());

function startAutoRefresh() {
  state.intervalId = setInterval(loadOverview, state.refreshMs);
}

// ──────────────────────────────────────────────
// INIT
// ──────────────────────────────────────────────

(async function init() {
  await loadOverview();
  startAutoRefresh();
})();