/**
 * NetListener - Popup Controller
 * Manages the compact extension popup view, request filtering, live stream updates,
 * and structured report transmission to Firebase.
 */

import { filterRequests } from '../core/filters.js';
import { escapeHtml } from '../core/sanitizer.js';

let allRequests = [];
let selectedRequest = null;
let currentFilters = {
  search: '',
  method: 'ALL',
  status: 'ALL',
  resourceType: 'ALL',
  sortBy: 'newest'
};
let isMonitoring = true;
let activeDrawerTab = 'headers';
let firebaseConfig = {
  projectId: 'alt-mvgr',
  apiKey: 'AIzaSyCMdcIYi91aWXI9cHz3fFW78rJ8JHV-j9w',
  collection: 'network_reports',
  endpointType: 'firestore',
  customUrl: ''
};

// DOM Elements
const statusPulse = document.getElementById('statusPulse');
const toggleMonitoringBtn = document.getElementById('toggleMonitoringBtn');
const toggleText = document.getElementById('toggleText');
const openDashboardBtn = document.getElementById('openDashboardBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const exportBtn = document.getElementById('exportBtn');

// Send Log & Firebase Elements
const sendLogBtn = document.getElementById('sendLogBtn');
const sendLogBtnText = document.getElementById('sendLogBtnText');
const firebaseSettingsBtn = document.getElementById('firebaseSettingsBtn');
const firebaseModal = document.getElementById('firebaseModal');
const closeFirebaseModalBtn = document.getElementById('closeFirebaseModalBtn');
const saveFirebaseSettingsBtn = document.getElementById('saveFirebaseSettingsBtn');
const fbProjectId = document.getElementById('fbProjectId');
const fbCollection = document.getElementById('fbCollection');
const fbApiKey = document.getElementById('fbApiKey');
const fbEndpointType = document.getElementById('fbEndpointType');
const fbCustomUrl = document.getElementById('fbCustomUrl');
const customUrlGroup = document.getElementById('customUrlGroup');

const toastNotification = document.getElementById('toastNotification');
const toastMessage = document.getElementById('toastMessage');
const toastCloseBtn = document.getElementById('toastCloseBtn');
let toastTimeout = null;

const metricTotal = document.getElementById('metricTotal');
const metricApi = document.getElementById('metricApi');
const metricErrors = document.getElementById('metricErrors');

const searchInput = document.getElementById('searchInput');
const clearSearchBtn = document.getElementById('clearSearchBtn');
const methodPills = document.getElementById('methodPills');

const requestStream = document.getElementById('requestStream');
const requestItems = document.getElementById('requestItems');
const emptyState = document.getElementById('emptyState');

const inspectorDrawer = document.getElementById('inspectorDrawer');
const closeDrawerBtn = document.getElementById('closeDrawerBtn');
const drawerMethod = document.getElementById('drawerMethod');
const drawerStatus = document.getElementById('drawerStatus');
const drawerDuration = document.getElementById('drawerDuration');
const drawerUrl = document.getElementById('drawerUrl');
const drawerContent = document.getElementById('drawerContent');
const drawerOpenDashboardBtn = document.getElementById('drawerOpenDashboardBtn');
const drawerTabs = document.querySelectorAll('.drawer-tab');

/**
 * Initializes the popup view.
 */
async function init() {
  setupEventListeners();

  // Connect dedicated port so service worker tracks active UI and throttles IPC
  try {
    if (chrome.runtime && chrome.runtime.connect) {
      chrome.runtime.connect({ name: 'netlistener-ui' });
    }
  } catch (err) {
    // Non-extension context fallback
  }

  await loadState();

  // Listen for live traffic broadcasts from background service worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'TRAFFIC_BATCH' && Array.isArray(message.events)) {
      for (const ev of message.events) {
        if (ev && ev.request) {
          applyRequestUpdate(ev.request);
        }
      }
      renderUI();
    } else if (message.type === 'TRAFFIC_EVENT') {
      handleLiveTrafficEvent(message.subType, message.request);
    }
  });
}

/**
 * Applies a single request update into allRequests.
 */
function applyRequestUpdate(req) {
  if (!req) return;
  const existingIdx = allRequests.findIndex(r => r.id === req.id || r.requestId === req.requestId);
  if (existingIdx !== -1) {
    allRequests[existingIdx] = { ...allRequests[existingIdx], ...req };
    if (selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId)) {
      selectedRequest = allRequests[existingIdx];
      renderDrawerContent();
    }
  } else {
    allRequests.push(req);
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
      if (res.settings && res.settings.firebaseConfig) {
        firebaseConfig = { ...firebaseConfig, ...res.settings.firebaseConfig };
      }
      if (res.settings && scopeIndicator) {
        const mode = res.settings.scopeMode || 'subnet';
        if (mode === 'subnet') {
          scopeIndicator.textContent = 'Subnet (192.168.x.x)';
          scopeIndicator.title = 'Scope: Local Subnet (192.168.x.x, 10.x.x.x, 172.16-31.x.x, localhost)';
        } else if (mode === 'local') {
          scopeIndicator.textContent = 'Localhost Only';
          scopeIndicator.title = 'Scope: Strict Loopback (localhost, 127.0.0.1)';
        } else {
          scopeIndicator.textContent = 'All Websites';
          scopeIndicator.title = 'Scope: All Websites';
        }
      }
      populateFirebaseModal();
      updateMonitoringUI(isMonitoring);
      renderUI();
    }
  } catch (err) {
    console.error('Failed to load NetListener state:', err);
  }
}

/**
 * Handles real-time traffic events.
 */
function handleLiveTrafficEvent(subType, req) {
  if (!req) return;

  const existingIdx = allRequests.findIndex(r => r.id === req.id || r.requestId === req.requestId);
  if (existingIdx !== -1) {
    allRequests[existingIdx] = { ...allRequests[existingIdx], ...req };
    if (selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId)) {
      selectedRequest = allRequests[existingIdx];
      renderDrawerContent();
    }
  } else {
    allRequests.push(req);
  }

  renderUI();
}

/**
 * Shows temporary toast notification.
 */
function showToast(message, type = 'info', duration = 4500) {
  if (toastTimeout) clearTimeout(toastTimeout);
  toastMessage.textContent = message;
  toastNotification.className = `toast-notification ${type}`;

  toastTimeout = setTimeout(() => {
    toastNotification.classList.add('hidden');
  }, duration);
}

/**
 * Sends structured log report to Firebase.
 */
async function handleSendLog() {
  if (allRequests.length === 0) {
    showToast('No captured traffic to send. Send local requests first!', 'info');
    return;
  }

  sendLogBtn.classList.add('loading');
  sendLogBtnText.textContent = 'Sending...';

  try {
    showToast(`Serializing & transmitting ${allRequests.length} requests to Firebase...`, 'info', 3000);

    const res = await chrome.runtime.sendMessage({
      type: 'SEND_FIREBASE_REPORT',
      config: firebaseConfig,
      metadata: {
        environment: 'Local Chrome Extension Popup',
        trigger: 'User Click Send Log'
      }
    });

    if (res && res.success) {
      showToast(`✓ Log sent to Firebase! Report ID: ${res.reportId}`, 'success', 6000);
    } else {
      const err = res?.error || 'Transmission failed';
      showToast(`⚠️ ${err}. (Report copied to clipboard!)`, 'error', 7000);
      if (res?.rawReport) {
        navigator.clipboard.writeText(JSON.stringify(res.rawReport, null, 2)).catch(() => {});
      }
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    sendLogBtn.classList.remove('loading');
    sendLogBtnText.textContent = 'Send log';
  }
}

/**
 * Updates UI elements based on monitoring state.
 */
function updateMonitoringUI(enabled) {
  isMonitoring = enabled;
  if (enabled) {
    statusPulse.classList.add('active');
    statusPulse.title = 'Monitoring Active (All Websites)';
    toggleMonitoringBtn.classList.add('active');
    toggleText.textContent = 'Active';
  } else {
    statusPulse.classList.remove('active');
    statusPulse.title = 'Monitoring Paused';
    toggleMonitoringBtn.classList.remove('active');
    toggleText.textContent = 'Paused';
  }
}

function populateFirebaseModal() {
  fbProjectId.value = firebaseConfig.projectId || 'alt-mvgr';
  fbCollection.value = firebaseConfig.collection || 'network_reports';
  fbApiKey.value = firebaseConfig.apiKey || '';
  fbEndpointType.value = firebaseConfig.endpointType || 'firestore';
  fbCustomUrl.value = firebaseConfig.customUrl || '';
  customUrlGroup.classList.toggle('hidden', fbEndpointType.value !== 'custom');
}

/**
 * Renders metrics, counts, and filtered request items.
 */
function renderUI() {
  // Update metrics
  const total = allRequests.length;
  const apiCalls = allRequests.filter(r => r.type === 'xmlhttprequest' || (r.pathname && r.pathname.includes('/api'))).length;
  const errors = allRequests.filter(r => r.lifecycle === 'failed' || (typeof r.statusCode === 'number' && r.statusCode >= 400)).length;

  metricTotal.textContent = total;
  metricApi.textContent = apiCalls;
  metricErrors.textContent = errors;

  // Filter requests
  const filtered = filterRequests(allRequests, currentFilters);

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
    requestItems.innerHTML = '';
    return;
  }

  emptyState.classList.add('hidden');
  renderRequestRows(filtered);
}

/**
 * Renders individual request rows.
 */
function renderRequestRows(requests) {
  const html = requests.map(req => {
    const isSelected = selectedRequest && (selectedRequest.id === req.id || selectedRequest.requestId === req.requestId);
    const method = req.method || 'GET';
    const statusText = req.statusCode ? String(req.statusCode) : (req.lifecycle === 'failed' ? 'ERR' : '...');
    const statusClass = getStatusClass(req.statusCode, req.lifecycle);
    const durationText = typeof req.duration === 'number' ? `${req.duration}ms` : '';
    const typeLabel = req.type === 'xmlhttprequest' ? 'xhr' : req.type || 'other';

    let displayPath = req.pathname || '/';
    let displaySearch = '';
    try {
      const u = new URL(req.url);
      displayPath = u.pathname;
      displaySearch = u.search;
    } catch {}

    return `
      <div class="request-row ${isSelected ? 'selected' : ''}" data-id="${escapeHtml(req.id || req.requestId)}">
        <span class="method-tag method-${escapeHtml(method)}">${escapeHtml(method)}</span>
        <span class="status-tag ${statusClass}">${escapeHtml(statusText)}</span>
        <div class="url-col" title="${escapeHtml(req.url)}">
          <span class="url-path">${escapeHtml(displayPath)}</span>
          <span class="url-query">${escapeHtml(displaySearch)}</span>
        </div>
        <div class="meta-col">
          <span class="type-badge">${escapeHtml(typeLabel)}</span>
          <span class="duration-tag">${escapeHtml(durationText)}</span>
        </div>
      </div>
    `;
  }).join('');

  requestItems.innerHTML = html;

  // Row click listeners
  requestItems.querySelectorAll('.request-row').forEach(row => {
    row.addEventListener('click', () => {
      const id = row.getAttribute('data-id');
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
 * Selects a request and opens the inspector drawer.
 */
function selectRequest(id) {
  selectedRequest = allRequests.find(r => r.id === id || r.requestId === id) || null;
  if (!selectedRequest) return;

  // Highlight row
  requestItems.querySelectorAll('.request-row').forEach(r => {
    r.classList.toggle('selected', r.getAttribute('data-id') === id);
  });

  // Populate drawer
  const method = selectedRequest.method || 'GET';
  drawerMethod.textContent = method;
  drawerMethod.className = `method-tag method-${method}`;
  drawerStatus.textContent = selectedRequest.statusCode ? `${selectedRequest.statusCode} ${selectedRequest.statusLine || ''}` : (selectedRequest.lifecycle === 'failed' ? `FAILED (${selectedRequest.error || 'Network Error'})` : 'PENDING');
  drawerStatus.className = `drawer-status ${getStatusClass(selectedRequest.statusCode, selectedRequest.lifecycle)}`;
  drawerDuration.textContent = typeof selectedRequest.duration === 'number' ? `${selectedRequest.duration}ms` : '';
  drawerUrl.textContent = selectedRequest.url || '';

  renderDrawerContent();
  inspectorDrawer.classList.remove('hidden');
}

/**
 * Renders tab content inside the quick drawer.
 */
function renderDrawerContent() {
  if (!selectedRequest) {
    drawerContent.innerHTML = '';
    return;
  }

  if (activeDrawerTab === 'headers') {
    const reqHeaders = selectedRequest.requestHeaders || [];
    const resHeaders = selectedRequest.responseHeaders || [];

    let html = '<div style="margin-bottom: 6px; font-weight:700; color:#1e293b; font-size:10.5px;">REQUEST HEADERS</div>';
    if (reqHeaders.length === 0) {
      html += '<div style="color:#64748b; margin-bottom: 8px;">No request headers captured</div>';
    } else {
      html += '<div class="kv-table" style="margin-bottom: 12px;">' + reqHeaders.map(h => `
        <div class="kv-row">
          <div class="kv-key">${escapeHtml(h.name)}</div>
          <div class="kv-val ${h.redacted ? 'redacted' : ''}">${escapeHtml(h.value)}</div>
        </div>
      `).join('') + '</div>';
    }

    html += '<div style="margin-bottom: 6px; font-weight:700; color:#1e293b; font-size:10.5px;">RESPONSE HEADERS</div>';
    if (resHeaders.length === 0) {
      html += '<div style="color:#64748b;">No response headers captured</div>';
    } else {
      html += '<div class="kv-table">' + resHeaders.map(h => `
        <div class="kv-row">
          <div class="kv-key">${escapeHtml(h.name)}</div>
          <div class="kv-val ${h.redacted ? 'redacted' : ''}">${escapeHtml(h.value)}</div>
        </div>
      `).join('') + '</div>';
    }

    drawerContent.innerHTML = html;
  } else if (activeDrawerTab === 'params') {
    let params = [];
    try {
      const u = new URL(selectedRequest.url);
      u.searchParams.forEach((val, key) => {
        params.push({ key, val });
      });
    } catch {}

    if (params.length === 0) {
      drawerContent.innerHTML = '<div style="color:#64748b; padding-top: 10px;">No query parameters in this request URL.</div>';
    } else {
      drawerContent.innerHTML = '<div class="kv-table">' + params.map(p => `
        <div class="kv-row">
          <div class="kv-key">${escapeHtml(p.key)}</div>
          <div class="kv-val ${p.val === '[REDACTED]' ? 'redacted' : ''}">${escapeHtml(p.val)}</div>
        </div>
      `).join('') + '</div>';
    }
  } else if (activeDrawerTab === 'info') {
    const infoRows = [
      { key: 'Request ID', val: selectedRequest.id || selectedRequest.requestId },
      { key: 'Resource Type', val: selectedRequest.type },
      { key: 'Origin', val: selectedRequest.origin },
      { key: 'Route Pattern', val: selectedRequest.routePattern || 'N/A' },
      { key: 'Lifecycle', val: selectedRequest.lifecycle },
      { key: 'Duration', val: typeof selectedRequest.duration === 'number' ? `${selectedRequest.duration} ms` : 'In flight' },
      { key: 'Initiator', val: selectedRequest.initiator || 'Browser Navigation / Extension' },
      { key: 'From Cache', val: selectedRequest.fromCache ? 'Yes' : 'No' },
      { key: 'Timestamp', val: selectedRequest.timestamp ? new Date(selectedRequest.timestamp).toLocaleString() : 'N/A' }
    ];

    if (selectedRequest.error) {
      infoRows.push({ key: 'Error Details', val: selectedRequest.error });
    }

    drawerContent.innerHTML = '<div class="kv-table">' + infoRows.map(r => `
      <div class="kv-row">
        <div class="kv-key">${escapeHtml(r.key)}</div>
        <div class="kv-val">${escapeHtml(r.val)}</div>
      </div>
    `).join('') + '</div>';
  }
}

/**
 * Event Listeners setup
 */
function setupEventListeners() {
  // Send Log to Firebase
  sendLogBtn.addEventListener('click', handleSendLog);

  // Firebase Settings modal
  firebaseSettingsBtn.addEventListener('click', () => {
    populateFirebaseModal();
    firebaseModal.classList.remove('hidden');
  });

  closeFirebaseModalBtn.addEventListener('click', () => {
    firebaseModal.classList.add('hidden');
  });

  fbEndpointType.addEventListener('change', () => {
    customUrlGroup.classList.toggle('hidden', fbEndpointType.value !== 'custom');
  });

  saveFirebaseSettingsBtn.addEventListener('click', async () => {
    firebaseConfig = {
      projectId: fbProjectId.value.trim() || 'alt-mvgr',
      collection: fbCollection.value.trim() || 'network_reports',
      apiKey: fbApiKey.value.trim(),
      endpointType: fbEndpointType.value,
      customUrl: fbCustomUrl.value.trim()
    };

    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { firebaseConfig }
    });

    firebaseModal.classList.add('hidden');
    showToast('Firebase configuration saved!', 'success');
  });

  toastCloseBtn.addEventListener('click', () => {
    toastNotification.classList.add('hidden');
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

  // Open full dashboard
  openDashboardBtn.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD' });
  });

  drawerOpenDashboardBtn.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD' });
  });

  // Clear history
  clearHistoryBtn.addEventListener('click', async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
      if (res && res.success) {
        allRequests = [];
        selectedRequest = null;
        inspectorDrawer.classList.add('hidden');
        renderUI();
        showToast('Traffic history cleared', 'info');
      }
    } catch (e) {
      console.error('Failed to clear history:', e);
    }
  });

  // Export JSON
  exportBtn.addEventListener('click', async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'EXPORT_DATA', format: 'json' });
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
      console.error('Failed to export:', e);
    }
  });

  // Search input
  searchInput.addEventListener('input', (e) => {
    currentFilters.search = e.target.value;
    clearSearchBtn.classList.toggle('hidden', !e.target.value);
    renderUI();
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    currentFilters.search = '';
    clearSearchBtn.classList.add('hidden');
    renderUI();
  });

  // Method pills
  methodPills.querySelectorAll('.pill').forEach(pill => {
    pill.addEventListener('click', () => {
      methodPills.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilters.method = pill.getAttribute('data-method');
      renderUI();
    });
  });

  // Close drawer
  closeDrawerBtn.addEventListener('click', () => {
    inspectorDrawer.classList.add('hidden');
    selectedRequest = null;
    requestItems.querySelectorAll('.request-row').forEach(r => r.classList.remove('selected'));
  });

  // Drawer tabs
  drawerTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      drawerTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeDrawerTab = tab.getAttribute('data-tab');
      renderDrawerContent();
    });
  });
}

document.addEventListener('DOMContentLoaded', init);
