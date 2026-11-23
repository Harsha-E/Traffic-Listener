/**
 * NetListener - DevTools Panel Controller
 * Leverages chrome.devtools.network for deep HAR inspection and response body analysis.
 */

import { sanitizeUrl, sanitizeHeaders, escapeHtml } from '../core/sanitizer.js';

let devRequests = [];
let selectedDevReq = null;
let activeTab = 'headers';

const devSearch = document.getElementById('devSearch');
const devTableBody = document.getElementById('devTableBody');
const clearDevtoolsBtn = document.getElementById('clearDevtoolsBtn');
const exportDevtoolsBtn = document.getElementById('exportDevtoolsBtn');

const devDetailEmpty = document.getElementById('devDetailEmpty');
const devDetailBody = document.getElementById('devDetailBody');
const devMethodBadge = document.getElementById('devMethodBadge');
const devStatusBadge = document.getElementById('devStatusBadge');
const devUrlDisplay = document.getElementById('devUrlDisplay');
const dTabs = document.querySelectorAll('.d-tab');
const dContentHeaders = document.getElementById('dContentHeaders');
const dContentResponse = document.getElementById('dContentResponse');
const devResponseBody = document.getElementById('devResponseBody');

/**
 * Initializes DevTools network listener.
 */
function init() {
  // Listen to network requests finished in the inspected window
  if (chrome.devtools && chrome.devtools.network) {
    chrome.devtools.network.onRequestFinished.addListener((harEntry) => {
      handleHarRequest(harEntry);
    });
  }

  setupEventListeners();
}

/**
 * Processes a completed HAR entry from chrome.devtools.network.
 */
function handleHarRequest(harEntry) {
  if (!harEntry || !harEntry.request) return;

  const rawUrl = harEntry.request.url || '';
  // Inspect HTTP and HTTPS traffic
  try {
    const urlObj = new URL(rawUrl);
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return;
    }
  } catch {
    return;
  }

  const sanitizedUrlData = sanitizeUrl(rawUrl);
  const method = harEntry.request.method || 'GET';
  const status = harEntry.response ? harEntry.response.status : 0;
  const time = Math.round(harEntry.time || 0);

  const reqItem = {
    id: `dev-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    url: sanitizedUrlData.sanitizedUrl,
    rawUrl: rawUrl,
    method,
    status,
    time,
    requestHeaders: sanitizeHeaders(harEntry.request.headers || []),
    responseHeaders: sanitizeHeaders(harEntry.response?.headers || []),
    harEntry
  };

  devRequests.push(reqItem);
  renderTable();
}

function renderTable() {
  const query = (devSearch.value || '').toLowerCase();
  const filtered = devRequests.filter(r => {
    return !query || r.url.toLowerCase().includes(query) || r.method.toLowerCase().includes(query) || String(r.status).includes(query);
  });

  devTableBody.innerHTML = filtered.map(r => {
    let path = r.url;
    try { path = new URL(r.url).pathname; } catch {}
    const isSel = selectedDevReq && selectedDevReq.id === r.id;

    return `
      <tr class="${isSel ? 'selected' : ''}" data-id="${escapeHtml(r.id)}">
        <td><span class="method-badge method-${escapeHtml(r.method)}">${escapeHtml(r.method)}</span></td>
        <td><span class="status-badge">${escapeHtml(String(r.status))}</span></td>
        <td title="${escapeHtml(r.url)}">${escapeHtml(path)}</td>
        <td>${r.time}ms</td>
      </tr>
    `;
  }).join('');

  devTableBody.querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', () => {
      const id = tr.getAttribute('data-id');
      selectRequest(id);
    });
  });
}

function selectRequest(id) {
  selectedDevReq = devRequests.find(r => r.id === id) || null;
  if (!selectedDevReq) return;

  devDetailEmpty.classList.add('hidden');
  devDetailBody.classList.remove('hidden');

  devMethodBadge.textContent = selectedDevReq.method;
  devMethodBadge.className = `method-badge method-${selectedDevReq.method}`;
  devStatusBadge.textContent = selectedDevReq.status;
  devUrlDisplay.textContent = selectedDevReq.url;

  renderDetailContent();
  renderTable();
}

function renderDetailContent() {
  if (!selectedDevReq) return;

  if (activeTab === 'headers') {
    dContentHeaders.classList.remove('hidden');
    dContentResponse.classList.add('hidden');

    let html = '<div style="margin-bottom:6px; font-weight:700; color:#8ab4f8;">REQUEST HEADERS</div>';
    html += selectedDevReq.requestHeaders.map(h => `
      <div style="margin-bottom:3px;"><span style="color:#8ab4f8;">${escapeHtml(h.name)}:</span> <span style="color:${h.redacted ? '#f28b82' : '#e8eaed'};">${escapeHtml(h.value)}</span></div>
    `).join('') || '<div style="color:#9aa0a6;">None</div>';

    html += '<div style="margin-top:10px; margin-bottom:6px; font-weight:700; color:#8ab4f8;">RESPONSE HEADERS</div>';
    html += selectedDevReq.responseHeaders.map(h => `
      <div style="margin-bottom:3px;"><span style="color:#8ab4f8;">${escapeHtml(h.name)}:</span> <span style="color:${h.redacted ? '#f28b82' : '#e8eaed'};">${escapeHtml(h.value)}</span></div>
    `).join('') || '<div style="color:#9aa0a6;">None</div>';

    dContentHeaders.innerHTML = html;
  } else if (activeTab === 'response') {
    dContentHeaders.classList.add('hidden');
    dContentResponse.classList.remove('hidden');
    devResponseBody.textContent = 'Loading response content...';

    if (selectedDevReq.harEntry && typeof selectedDevReq.harEntry.getContent === 'function') {
      selectedDevReq.harEntry.getContent((body, encoding) => {
        if (!body) {
          devResponseBody.textContent = '(No response body available)';
        } else {
          try {
            // Pretty print if JSON
            const parsed = JSON.parse(body);
            devResponseBody.textContent = JSON.stringify(parsed, null, 2);
          } catch {
            devResponseBody.textContent = body;
          }
        }
      });
    } else {
      devResponseBody.textContent = '(DevTools getContent not supported for this entry)';
    }
  }
}

function setupEventListeners() {
  devSearch.addEventListener('input', renderTable);

  clearDevtoolsBtn.addEventListener('click', () => {
    devRequests = [];
    selectedDevReq = null;
    devDetailEmpty.classList.remove('hidden');
    devDetailBody.classList.add('hidden');
    renderTable();
  });

  exportDevtoolsBtn.addEventListener('click', () => {
    const jsonStr = JSON.stringify(devRequests.map(r => ({
      method: r.method,
      url: r.url,
      status: r.status,
      time: r.time,
      requestHeaders: r.requestHeaders,
      responseHeaders: r.responseHeaders
    })), null, 2);

    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netlistener-devtools-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  dTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      dTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeTab = tab.getAttribute('data-tab');
      renderDetailContent();
    });
  });
}

document.addEventListener('DOMContentLoaded', init);
