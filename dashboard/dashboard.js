/**
 * NetListener - Dashboard Controller
 * Powers the full-page Network Traffic Inspector and Endpoint Intelligence Suite.
 */

import { filterRequests } from '../core/filters.js';
import { computeEndpointIntelligence } from '../core/endpoint-parser.js';
import { escapeHtml } from '../core/sanitizer.js';

let allRequests = [];
let selectedRequest = null;
let isMonitoring = true;
let currentFilters = {
  search: '',
  method: 'ALL',
  status: 'ALL',
  resourceType: 'ALL',
  origin: 'ALL',
  sortBy: 'newest'
};
let autoScroll = true;
let activeView = 'traffic';
let activeInspectorTab = 'overview';

// DOM Elements - Navigation & Topbar
const statusPulse = document.getElementById('statusPulse');
const toggleMonitoringBtn = document.getElementById('toggleMonitoringBtn');
const toggleMonitoringText = document.getElementById('toggleMonitoringText');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const exportDropdownBtn = document.getElementById('exportDropdownBtn');
const exportMenu = document.getElementById('exportMenu');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const exportCsvBtn = document.getElementById('exportCsvBtn');
const navTabs = document.querySelectorAll('.nav-tab');

// KPI elements
const kpiTotal = document.getElementById('kpiTotal');
const kpiApi = document.getElementById('kpiApi');
const kpiEndpoints = document.getElementById('kpiEndpoints');
const kpiErrors = document.getElementById('kpiErrors');
const kpiRate = document.getElementById('kpiRate');

// Traffic View Elements
const trafficSearchInput = document.getElementById('trafficSearchInput');
const clearTrafficSearchBtn = document.getElementById('clearTrafficSearchBtn');
const filterMethod = document.getElementById('filterMethod');
const filterStatus = document.getElementById('filterStatus');
const filterType = document.getElementById('filterType');
const filterOrigin = document.getElementById('filterOrigin');
const autoScrollToggle = document.getElementById('autoScrollToggle');

const trafficTableBody = document.getElementById('trafficTableBody');
const emptyTrafficState = document.getElementById('emptyTrafficState');
const gridContainer = document.querySelector('.grid-container');

// Inspector Elements
const inspectorEmptyState = document.getElementById('inspectorEmptyState');
const inspectorActiveContent = document.getElementById('inspectorActiveContent');
const inspMethod = document.getElementById('inspMethod');
const inspStatus = document.getElementById('inspStatus');
const inspDuration = document.getElementById('inspDuration');
const inspUrl = document.getElementById('inspUrl');
const copyUrlBtn = document.getElementById('copyUrlBtn');
const copyCurlBtn = document.getElementById('copyCurlBtn');
const inspTabs = document.querySelectorAll('.insp-tab');

// Detail elements
const detailReqId = document.getElementById('detailReqId');
const detailRoute = document.getElementById('detailRoute');
const detailType = document.getElementById('detailType');
const detailLifecycle = document.getElementById('detailLifecycle');
const detailDuration = document.getElementById('detailDuration');
const detailInitiator = document.getElementById('detailInitiator');
const detailCache = document.getElementById('detailCache');
const detailTimestamp = document.getElementById('detailTimestamp');
const detailError = document.getElementById('detailError');
const rowError = document.getElementById('rowError');

const reqHeaderCount = document.getElementById('reqHeaderCount');
const reqHeadersList = document.getElementById('reqHeadersList');
const resHeaderCount = document.getElementById('resHeaderCount');
const resHeadersList = document.getElementById('resHeadersList');
const paramsList = document.getElementById('paramsList');
const redactionSummary = document.getElementById('redactionSummary');
const securityHeadersAudit = document.getElementById('securityHeadersAudit');
const educationalContext = document.getElementById('educationalContext');

// Endpoint Intelligence Elements
const intelTableBody = document.getElementById('intelTableBody');
const intelGroupedCount = document.getElementById('intelGroupedCount');
const methodDistributionBars = document.getElementById('methodDistributionBars');
const interestingApiList = document.getElementById('interestingApiList');
const failedEndpointsList = document.getElementById('failedEndpointsList');

/**
 * Initializes the dashboard application.
 */
async function init() {
  setupEventListeners();

  // Connect port to inform background worker that dashboard is open
  try {
    if (chrome.runtime && chrome.runtime.connect) {
      chrome.runtime.connect({ name: 'netlistener-ui' });
    }
  } catch (err) {}

  await loadState();

  // Listen for live background traffic updates
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'TRAFFIC_BATCH' && Array.isArray(message.events)) {
      for (const ev of message.events) {
        if (ev && ev.request) {
          applyLiveUpdate(ev.request);
        }
      }
      renderAll();
    } else if (message.type === 'TRAFFIC_EVENT') {
      handleLiveTrafficEvent(message.subType, message.request);
    }
  });
}

function applyLiveUpdate(req) {
  if (!req) return;
  const existingIdx = allRequests.findIndex(r => r.id === req.id || r.requestId === req.requestId);
  if (existingIdx !== -1) {
    allRequests[existingIdx] = { ...allRequests[existingIdx], ...req };
    if (selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId)) {
      selectedRequest = allRequests[existingIdx];
      renderInspector();
    }
  } else {
    allRequests.push(req);
    updateOriginFilterOptions();
  }
}

/**
 * Loads current state from the service worker.
 */
async function loadState() {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'GET_STATE' });
    if (res && res.success) {
      allRequests = res.requests || [];
      isMonitoring = res.settings ? res.settings.monitoringEnabled : true;
      const scopeTextEl = document.getElementById('dashboardScopeText');
      if (res.settings && scopeTextEl) {
        const mode = res.settings.scopeMode || 'subnet';
        if (mode === 'subnet') {
          scopeTextEl.innerHTML = 'Scope: <strong>Subnet (192.168.x.x)</strong>';
        } else if (mode === 'local') {
          scopeTextEl.innerHTML = 'Scope: <strong>Localhost Only</strong>';
        } else {
          scopeTextEl.innerHTML = 'Scope: <strong>All Websites</strong>';
        }
      }
      updateMonitoringUI(isMonitoring);
      updateOriginFilterOptions();
      renderAll();
    }
  } catch (err) {
    console.error('Failed to load NetListener dashboard state:', err);
  }
}

/**
 * Handles incoming real-time traffic events.
 */
function handleLiveTrafficEvent(subType, req) {
  if (!req) return;

  const existingIdx = allRequests.findIndex(r => r.id === req.id || r.requestId === req.requestId);
  if (existingIdx !== -1) {
    allRequests[existingIdx] = { ...allRequests[existingIdx], ...req };
    if (selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId)) {
      selectedRequest = allRequests[existingIdx];
      renderInspector();
    }
  } else {
    allRequests.push(req);
    updateOriginFilterOptions();
  }

  renderAll();

  if (autoScroll && activeView === 'traffic' && gridContainer) {
    gridContainer.scrollTop = gridContainer.scrollHeight;
  }
}

/**
 * Updates monitoring UI state in top bar.
 */
function updateMonitoringUI(enabled) {
  isMonitoring = enabled;
  if (enabled) {
    statusPulse.classList.add('active');
    statusPulse.title = 'Monitoring Active (All Websites)';
    toggleMonitoringBtn.classList.add('active');
    toggleMonitoringText.textContent = 'Monitoring: Active';
  } else {
    statusPulse.classList.remove('active');
    statusPulse.title = 'Monitoring Paused';
    toggleMonitoringBtn.classList.remove('active');
    toggleMonitoringText.textContent = 'Monitoring: Paused';
  }
}

/**
 * Populates detected origins into origin filter dropdown.
 */
function updateOriginFilterOptions() {
  const currentVal = filterOrigin.value;
  const origins = new Set();
  allRequests.forEach(r => {
    if (r.origin) origins.add(r.origin);
  });

  const options = ['<option value="ALL">All Local Origins</option>'];
  origins.forEach(origin => {
    options.push(`<option value="${escapeHtml(origin)}">${escapeHtml(origin)}</option>`);
  });

  filterOrigin.innerHTML = options.join('');
  if (origins.has(currentVal)) {
    filterOrigin.value = currentVal;
  }
}

/**
 * Master render function
 */
function renderAll() {
  renderKPIs();

  if (activeView === 'traffic') {
    renderTrafficTable();
  } else if (activeView === 'intelligence') {
    renderEndpointIntelligence();
  }
}

/**
 * Computes and renders KPI strip metrics.
 */
function renderKPIs() {
  const total = allRequests.length;
  const intel = computeEndpointIntelligence(allRequests);

  const apiCount = allRequests.filter(r => r.type === 'xmlhttprequest' || (r.pathname && r.pathname.includes('/api'))).length;

  kpiTotal.textContent = total;
  kpiApi.textContent = apiCount;
  kpiEndpoints.textContent = intel.uniqueEndpointsCount;
  kpiErrors.textContent = intel.failureCount;
  kpiRate.textContent = `${intel.failureRate}%`;
}

/**
 * Renders the main traffic inspector table.
 */
function renderTrafficTable() {
  const filtered = filterRequests(allRequests, currentFilters);

  if (filtered.length === 0) {
    emptyTrafficState.classList.remove('hidden');
    trafficTableBody.innerHTML = '';
    return;
  }

  emptyTrafficState.classList.add('hidden');

  const rows = filtered.map(req => {
    const isSelected = selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId);
    const method = req.method || 'GET';
    const statusText = req.statusCode ? String(req.statusCode) : (req.lifecycle === 'failed' ? 'Failed' : 'Pending');
    const statusClass = getStatusClass(req.statusCode, req.lifecycle);
    const durationText = typeof req.duration === 'number' ? `${req.duration} ms` : '-';
    const timeText = req.timestamp ? new Date(req.timestamp).toLocaleTimeString() : '';

    let displayPath = req.pathname || '/';
    let displaySearch = '';
    try {
      const u = new URL(req.url);
      displayPath = u.pathname;
      displaySearch = u.search;
    } catch {}

    const hasRedactions = req.redactionCount > 0 || (req.redactedKeys && req.redactedKeys.length > 0);

    return `
      <tr class="${isSelected ? 'selected' : ''}" data-id="${escapeHtml(req.id || req.requestId)}">
        <td><span class="method-badge method-${escapeHtml(method)}">${escapeHtml(method)}</span></td>
        <td><span class="status-badge ${statusClass}">${escapeHtml(statusText)}</span></td>
        <td class="path-cell" title="${escapeHtml(req.url)}">
          <span class="path-main">${escapeHtml(displayPath)}</span>
          <span class="path-query">${escapeHtml(displaySearch)}</span>
          ${hasRedactions ? '<span class="redact-pill" title="Sensitive query parameters redacted">redacted</span>' : ''}
        </td>
        <td title="${escapeHtml(req.origin)}">${escapeHtml(req.origin || '')}</td>
        <td><span class="duration-badge">${escapeHtml(req.type || 'other')}</span></td>
        <td><span class="duration-badge">${escapeHtml(durationText)}</span></td>
        <td><span class="duration-badge">${escapeHtml(timeText)}</span></td>
      </tr>
    `;
  }).join('');

  trafficTableBody.innerHTML = rows;

  // Add click listeners to rows
  trafficTableBody.querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', () => {
      const id = tr.getAttribute('data-id');
      selectRequest(id);
    });
  });
}

function getStatusClass(statusCode, lifecycle) {
  if (lifecycle === 'failed') return 'status-failed';
  if (lifecycle === 'pending' || !statusCode) return 'status-pending';
  if (statusCode >= 200 && statusCode < 300) return 'status-2xx';
  if (statusCode >= 300 && statusCode < 400) return 'status-3xx';
  if (statusCode >= 400 && statusCode < 500) return 'status-4xx';
  if (statusCode >= 500) return 'status-5xx';
  return '';
}

/**
 * Selects a request and populates the inspector.
 */
function selectRequest(id) {
  selectedRequest = allRequests.find(r => r.id === id || r.requestId === id) || null;
  if (!selectedRequest) return;

  trafficTableBody.querySelectorAll('tr').forEach(tr => {
    tr.classList.toggle('selected', tr.getAttribute('data-id') === id);
  });

  renderInspector();
}

/**
 * Renders the detailed request inspector pane.
 */
function renderInspector() {
  if (!selectedRequest) {
    inspectorEmptyState.classList.remove('hidden');
    inspectorActiveContent.classList.add('hidden');
    return;
  }

  inspectorEmptyState.classList.add('hidden');
  inspectorActiveContent.classList.remove('hidden');

  const method = selectedRequest.method || 'GET';
  inspMethod.textContent = method;
  inspMethod.className = `method-badge method-${method}`;

  const statusText = selectedRequest.statusCode
    ? `${selectedRequest.statusCode} ${selectedRequest.statusLine || ''}`
    : (selectedRequest.lifecycle === 'failed' ? `Failed: ${selectedRequest.error || 'Network Error'}` : 'Pending');
  inspStatus.textContent = statusText;
  inspStatus.className = `status-badge ${getStatusClass(selectedRequest.statusCode, selectedRequest.lifecycle)}`;

  inspDuration.textContent = typeof selectedRequest.duration === 'number' ? `${selectedRequest.duration} ms` : 'In flight';
  inspUrl.textContent = selectedRequest.url || '';

  // Render active tab pane
  renderInspectorTab();
}

function renderInspectorTab() {
  if (!selectedRequest) return;

  // Overview Tab
  detailReqId.textContent = selectedRequest.id || selectedRequest.requestId;
  detailRoute.textContent = selectedRequest.routePattern || 'N/A';
  detailType.textContent = selectedRequest.type || 'other';
  detailLifecycle.textContent = selectedRequest.lifecycle || 'unknown';
  detailDuration.textContent = typeof selectedRequest.duration === 'number' ? `${selectedRequest.duration} ms` : 'In flight';
  detailInitiator.textContent = selectedRequest.initiator || 'Direct Browser Navigation';
  detailCache.textContent = selectedRequest.fromCache ? 'Yes (Disk / Memory Cache)' : 'No (Network Transmitted)';
  detailTimestamp.textContent = selectedRequest.timestamp ? new Date(selectedRequest.timestamp).toLocaleString() : 'N/A';

  if (selectedRequest.error) {
    rowError.classList.remove('hidden');
    detailError.textContent = selectedRequest.error;
  } else {
    rowError.classList.add('hidden');
  }

  // Headers Tab
  const reqHeaders = selectedRequest.requestHeaders || [];
  const resHeaders = selectedRequest.responseHeaders || [];
  reqHeaderCount.textContent = reqHeaders.length;
  resHeaderCount.textContent = resHeaders.length;

  if (reqHeaders.length === 0) {
    reqHeadersList.innerHTML = '<div style="color:var(--text-muted); padding: 4px;">No request headers captured.</div>';
  } else {
    reqHeadersList.innerHTML = reqHeaders.map(h => `
      <div class="header-entry">
        <span class="h-key">${escapeHtml(h.name)}:</span>
        <span class="h-val ${h.redacted ? 'redacted' : ''}">${escapeHtml(h.value)}</span>
      </div>
    `).join('');
  }

  if (resHeaders.length === 0) {
    resHeadersList.innerHTML = '<div style="color:var(--text-muted); padding: 4px;">No response headers captured.</div>';
  } else {
    resHeadersList.innerHTML = resHeaders.map(h => `
      <div class="header-entry">
        <span class="h-key">${escapeHtml(h.name)}:</span>
        <span class="h-val ${h.redacted ? 'redacted' : ''}">${escapeHtml(h.value)}</span>
      </div>
    `).join('');
  }

  // Params Tab
  let params = [];
  try {
    const u = new URL(selectedRequest.url);
    u.searchParams.forEach((val, key) => {
      params.push({ key, val });
    });
  } catch {}

  if (params.length === 0) {
    paramsList.innerHTML = '<div style="color:var(--text-muted); padding: 6px;">No query parameters in request URL.</div>';
  } else {
    paramsList.innerHTML = params.map(p => `
      <div class="param-entry">
        <span class="p-key">${escapeHtml(p.key)}:</span>
        <span class="p-val ${p.val === '[REDACTED]' ? 'redacted' : ''}">${escapeHtml(p.val)}</span>
      </div>
    `).join('');
  }

  // Security Audit Tab
  renderSecurityAudit();
}

/**
 * Analyzes security aspects of the selected request.
 */
function renderSecurityAudit() {
  if (!selectedRequest) return;

  const redactions = [];

  if (selectedRequest.redactionCount > 0 || (selectedRequest.redactedKeys && selectedRequest.redactedKeys.length > 0)) {
    const keys = selectedRequest.redactedKeys || ['sensitive query key'];
    redactions.push(`Sensitive query parameter(s) redacted: ${keys.join(', ')}`);
  }

  const reqHeaders = selectedRequest.requestHeaders || [];
  reqHeaders.forEach(h => {
    if (h.redacted) {
      redactions.push(`Request header sanitized: "${h.name}"`);
    }
  });

  const resHeaders = selectedRequest.responseHeaders || [];
  resHeaders.forEach(h => {
    if (h.redacted) {
      redactions.push(`Response header sanitized: "${h.name}"`);
    }
  });

  if (redactions.length === 0) {
    redactionSummary.innerHTML = '<div style="color:var(--text-secondary); font-size:11px;">No sensitive credentials or tokens were detected in this request.</div>';
  } else {
    redactionSummary.innerHTML = redactions.map(r => `
      <div class="redaction-item">🔒 ${escapeHtml(r)}</div>
    `).join('');
  }

  // Check observed security headers in response
  const secHeadersFound = [];
  const secHeaderNames = [
    'access-control-allow-origin',
    'access-control-allow-methods',
    'access-control-allow-headers',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'strict-transport-security',
    'cross-origin-opener-policy',
    'x-xss-protection'
  ];

  resHeaders.forEach(h => {
    const lower = h.name.toLowerCase();
    if (secHeaderNames.includes(lower)) {
      secHeadersFound.push({ name: h.name, value: h.value });
    }
  });

  if (secHeadersFound.length === 0) {
    securityHeadersAudit.innerHTML = '<div style="color:#f59e0b; font-size:11.5px; padding: 4px 0;">⚠️ No common security hardening headers (CORS, CSP, HSTS, X-Content-Type-Options) observed in this response.</div>';
  } else {
    securityHeadersAudit.innerHTML = secHeadersFound.map(h => `
      <div class="header-entry" style="margin-bottom: 4px;">
        <span class="h-key" style="color:#38bdf8;">${escapeHtml(h.name)}:</span>
        <span class="h-val">${escapeHtml(h.value)}</span>
      </div>
    `).join('');
  }

  // Educational security context
  let eduNotes = [];
  if (selectedRequest.method === 'OPTIONS') {
    eduNotes.push('<strong>CORS Preflight:</strong> An OPTIONS request was triggered by the browser before the actual cross-origin request to verify server permissions.');
  }
  if (selectedRequest.url.includes('/api/')) {
    eduNotes.push('<strong>API Endpoint:</strong> Identified as a REST/API backend route. Good candidate for mapping endpoint attack surfaces.');
  }
  if (selectedRequest.type === 'script') {
    eduNotes.push('<strong>Script Resource:</strong> Static JavaScript asset. Review for bundled API keys or internal route strings.');
  }
  if (eduNotes.length === 0) {
    eduNotes.push('Standard web resource transaction. Monitored within safe local development scope.');
  }

  educationalContext.innerHTML = eduNotes.map(n => `<div style="margin-bottom: 6px; font-size:11.5px; color:var(--text-secondary);">${n}</div>`).join('');
}

/**
 * Renders Endpoint Intelligence View
 */
function renderEndpointIntelligence() {
  const intel = computeEndpointIntelligence(allRequests);
  intelGroupedCount.textContent = intel.groupedEndpoints.length;

  if (intel.groupedEndpoints.length === 0) {
    intelTableBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 30px; color:var(--text-muted);">No endpoint patterns captured yet.</td></tr>';
    methodDistributionBars.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">No data</div>';
    interestingApiList.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">No API routes detected</div>';
    failedEndpointsList.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">No failures recorded</div>';
    return;
  }

  // 1. Grouped Endpoints Table
  intelTableBody.innerHTML = intel.groupedEndpoints.map(group => {
    const methodsHtml = Object.entries(group.methods).map(([m, cnt]) => `
      <span class="method-badge method-${escapeHtml(m)}">${escapeHtml(m)} (${cnt})</span>
    `).join(' ');

    const statusHtml = Object.entries(group.statusCodes).map(([st, cnt]) => `
      <span class="duration-badge">${escapeHtml(st)}: ${cnt}</span>
    `).join(' ');

    return `
      <tr>
        <td style="font-weight:600; color:#fff;">${escapeHtml(group.routePattern)}</td>
        <td style="color:var(--text-muted);">${escapeHtml(group.origin)}</td>
        <td>${methodsHtml}</td>
        <td style="font-weight:700;">${group.totalCalls}</td>
        <td>${statusHtml}</td>
        <td>${group.avgDuration !== null ? `${group.avgDuration} ms` : '-'}</td>
        <td>${group.failureCount > 0 ? `<span class="text-red font-weight:700;">${group.failureCount}</span>` : '0'}</td>
      </tr>
    `;
  }).join('');

  // 2. HTTP Method Distribution Bars
  const total = intel.totalRequests || 1;
  const methodColors = {
    GET: '#10b981',
    POST: '#3b82f6',
    PUT: '#f59e0b',
    PATCH: '#8b5cf6',
    DELETE: '#ef4444',
    OPTIONS: '#94a3b8'
  };

  methodDistributionBars.innerHTML = Object.entries(intel.methodDistribution).map(([method, count]) => {
    const pct = Math.round((count / total) * 100);
    const color = methodColors[method] || '#60a5fa';
    return `
      <div class="dist-bar-row">
        <span class="dist-method" style="color: ${color};">${escapeHtml(method)}</span>
        <div class="dist-progress">
          <div class="dist-fill" style="width: ${pct}%; background-color: ${color};"></div>
        </div>
        <span class="dist-count">${count}</span>
      </div>
    `;
  }).join('');

  // 3. Interesting API Routes
  if (intel.interestingApiRoutes.length === 0) {
    interestingApiList.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">No API routes detected</div>';
  } else {
    interestingApiList.innerHTML = intel.interestingApiRoutes.slice(0, 8).map(route => `
      <div class="intel-item">
        <span style="color:#60a5fa; font-weight:600;">${escapeHtml(route.routePattern)}</span>
        <span class="badge-count">${route.totalCalls} calls</span>
      </div>
    `).join('');
  }

  // 4. Failed Endpoints Log
  if (intel.failedEndpoints.length === 0) {
    failedEndpointsList.innerHTML = '<div style="color:#10b981; font-size:11px;">✓ Zero failed endpoints in history</div>';
  } else {
    failedEndpointsList.innerHTML = intel.failedEndpoints.slice(0, 8).map(f => `
      <div class="intel-item">
        <span class="text-red">${escapeHtml(f.routePattern)}</span>
        <span class="text-red" style="font-weight:700;">${f.failureCount} errors</span>
      </div>
    `).join('');
  }
}

/**
 * Setup Event Listeners
 */
function setupEventListeners() {
  // Navigation tabs (Traffic / Intelligence / Security Guide)
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      activeView = tab.getAttribute('data-view');

      if (activeView === 'traffic') {
        document.getElementById('trafficView').classList.add('active');
        renderTrafficTable();
      } else if (activeView === 'intelligence') {
        document.getElementById('intelligenceView').classList.add('active');
        renderEndpointIntelligence();
      } else if (activeView === 'security-guide') {
        document.getElementById('securityGuideView').classList.add('active');
      }
    });
  });

  // Toggle monitoring
  toggleMonitoringBtn.addEventListener('click', async () => {
    try {
      const res = await chrome.runtime.sendMessage({
        type: 'TOGGLE_MONITORING',
        enabled: !isMonitoring
      });
      if (res && res.success) {
        updateMonitoringUI(res.monitoringEnabled);
      }
    } catch (e) {
      console.error('Failed to toggle monitoring:', e);
    }
  });

  // Send Log to Firebase from Dashboard
  const dashboardSendLogBtn = document.getElementById('dashboardSendLogBtn');
  const dashSendLogText = document.getElementById('dashSendLogText');
  if (dashboardSendLogBtn) {
    dashboardSendLogBtn.addEventListener('click', async () => {
      if (allRequests.length === 0) {
        alert('No traffic recorded yet to send to Firebase.');
        return;
      }

      dashboardSendLogBtn.style.opacity = '0.7';
      if (dashSendLogText) dashSendLogText.textContent = 'Sending...';

      try {
        const res = await chrome.runtime.sendMessage({
          type: 'SEND_FIREBASE_REPORT',
          metadata: {
            environment: 'Full-Page Intelligence Dashboard',
            trigger: 'User Click Send Log in Dashboard'
          }
        });

        if (res && res.success) {
          alert(`✓ Structured report successfully sent to Firebase!\nReport ID: ${res.reportId}\nCaptured Requests: ${res.reportSummary.totalRequests}`);
        } else {
          alert(`⚠️ Firebase reported: ${res?.error || 'Transmission failed.'}\n\nThe structured report JSON has been copied to your clipboard.`);
          if (res?.rawReport) {
            navigator.clipboard.writeText(JSON.stringify(res.rawReport, null, 2)).catch(() => {});
          }
        }
      } catch (err) {
        alert(`Error transmitting to Firebase: ${err.message}`);
      } finally {
        dashboardSendLogBtn.style.opacity = '1';
        if (dashSendLogText) dashSendLogText.textContent = 'Send log';
      }
    });
  }

  // Clear history
  clearHistoryBtn.addEventListener('click', async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
      if (res && res.success) {
        allRequests = [];
        selectedRequest = null;
        renderAll();
        renderInspector();
      }
    } catch (e) {
      console.error('Failed to clear history:', e);
    }
  });

  // Export dropdown
  exportDropdownBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('hidden');
  });

  document.addEventListener('click', () => {
    exportMenu.classList.add('hidden');
  });

  exportJsonBtn.addEventListener('click', () => triggerExport('json'));
  exportCsvBtn.addEventListener('click', () => triggerExport('csv'));

  async function triggerExport(format) {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'EXPORT_DATA', format });
      if (res && res.success) {
        const blob = new Blob([res.content], { type: res.mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.filename;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      console.error('Export error:', e);
    }
  }

  // Filter inputs
  trafficSearchInput.addEventListener('input', (e) => {
    currentFilters.search = e.target.value;
    clearTrafficSearchBtn.classList.toggle('hidden', !e.target.value);
    renderTrafficTable();
  });

  clearTrafficSearchBtn.addEventListener('click', () => {
    trafficSearchInput.value = '';
    currentFilters.search = '';
    clearTrafficSearchBtn.classList.add('hidden');
    renderTrafficTable();
  });

  filterMethod.addEventListener('change', (e) => {
    currentFilters.method = e.target.value;
    renderTrafficTable();
  });

  filterStatus.addEventListener('change', (e) => {
    currentFilters.status = e.target.value;
    renderTrafficTable();
  });

  filterType.addEventListener('change', (e) => {
    currentFilters.resourceType = e.target.value;
    renderTrafficTable();
  });

  filterOrigin.addEventListener('change', (e) => {
    currentFilters.origin = e.target.value;
    renderTrafficTable();
  });

  autoScrollToggle.addEventListener('change', (e) => {
    autoScroll = e.target.checked;
  });

  // Inspector tabs
  inspTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      inspTabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      activeInspectorTab = tab.getAttribute('data-tab');

      const targetPane = {
        overview: 'paneOverview',
        headers: 'paneHeaders',
        params: 'paneParams',
        security: 'paneSecurity',
        devtools: 'paneDevtools'
      }[activeInspectorTab];

      if (targetPane) {
        document.getElementById(targetPane).classList.add('active');
      }
    });
  });

  // Copy Buttons
  copyUrlBtn.addEventListener('click', () => {
    if (selectedRequest && selectedRequest.url) {
      navigator.clipboard.writeText(selectedRequest.url);
      const prev = copyUrlBtn.textContent;
      copyUrlBtn.textContent = 'Copied!';
      setTimeout(() => { copyUrlBtn.textContent = prev; }, 1200);
    }
  });

  copyCurlBtn.addEventListener('click', () => {
    if (!selectedRequest) return;
    const method = selectedRequest.method || 'GET';
    let curl = `curl -X ${method} "${selectedRequest.url}"`;
    (selectedRequest.requestHeaders || []).forEach(h => {
      curl += ` \\\n  -H "${h.name}: ${h.value}"`;
    });
    navigator.clipboard.writeText(curl);
    const prev = copyCurlBtn.textContent;
    copyCurlBtn.textContent = 'Copied!';
    setTimeout(() => { copyCurlBtn.textContent = prev; }, 1200);
  });
}

document.addEventListener('DOMContentLoaded', init);
