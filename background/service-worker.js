/**
 * NetListener - Background Service Worker (Manifest V3)
 * Orchestrates passive network traffic capture, badge indicator state,
 * and inter-context message passing.
 */

import { requestStore } from '../core/request-store.js';
import { requestMonitor } from '../core/request-monitor.js';
import { formatJsonExport, formatCsvExport } from '../core/export.js';
import { buildStructuredReport, sendReportToFirebase } from '../core/firebase-reporter.js';

// URL patterns matching host_permissions (All websites)
const MONITOR_URL_PATTERNS = [
  '<all_urls>'
];

// Active UI ports (Popup, Dashboard, DevTools) to eliminate zero-consumer IPC overhead
const connectedPorts = new Set();

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'netlistener-ui') {
    connectedPorts.add(port);
    requestMonitor.setUiActive(true);

    port.onDisconnect.addListener(() => {
      connectedPorts.delete(port);
      if (connectedPorts.size === 0) {
        requestMonitor.setUiActive(false);
      }
    });
  }
});

let badgeDebounceTimer = null;
function scheduleBadgeUpdate() {
  if (badgeDebounceTimer) clearTimeout(badgeDebounceTimer);
  badgeDebounceTimer = setTimeout(updateBadge, 200);
}

/**
 * Updates the extension badge with traffic count and active status.
 */
async function updateBadge() {
  try {
    const settings = requestStore.getSettings();
    if (!settings.monitoringEnabled) {
      await chrome.action.setBadgeText({ text: 'OFF' });
      await chrome.action.setBadgeBackgroundColor({ color: '#4b5563' });
      return;
    }

    const count = requestStore.getRequests().length;
    const badgeText = count > 999 ? '999+' : count > 0 ? String(count) : '';
    await chrome.action.setBadgeText({ text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ color: '#2563eb' });
  } catch (err) {
    // Service worker action API catch
  }
}

/**
 * Initializes listeners and storage on service worker startup.
 */
async function initServiceWorker() {
  await requestStore.init();
  await updateBadge();

  // Subscribe store changes to keep badge synchronized with debouncing
  requestStore.subscribe(async (event) => {
    if (event.type === 'REQUEST_UPDATED' || event.type === 'HISTORY_CLEARED' || event.type === 'SETTINGS_UPDATED') {
      scheduleBadgeUpdate();
    }
  });

  // Register passive Chrome webRequest listeners
  const filter = { urls: MONITOR_URL_PATTERNS };

  // 1. Before Request (Initiation, URL, Method, Type, Timestamp)
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      requestMonitor.handleBeforeRequest(details);
    },
    filter
  );

  // 2. Send Headers (Request Headers)
  try {
    chrome.webRequest.onSendHeaders.addListener(
      (details) => {
        requestMonitor.handleSendHeaders(details);
      },
      filter,
      ['requestHeaders']
    );
  } catch (e) {
    console.warn('[NetListener] onSendHeaders listener fallback:', e);
  }

  // 3. Headers Received (Status Code, Status Line, Response Headers)
  try {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        requestMonitor.handleHeadersReceived(details);
      },
      filter,
      ['responseHeaders']
    );
  } catch (e) {
    console.warn('[NetListener] onHeadersReceived listener fallback:', e);
  }

  // 4. Completed (Duration, Cache status, Final Status)
  chrome.webRequest.onCompleted.addListener(
    (details) => {
      requestMonitor.handleCompleted(details);
    },
    filter
  );

  // 5. Error Occurred (Network errors, aborts, connection refusals)
  chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
      requestMonitor.handleError(details);
    },
    filter
  );
}

// Start service worker
initServiceWorker();

// Re-sync on install or browser startup
chrome.runtime.onInstalled.addListener(async () => {
  await requestStore.init();
  await updateBadge();
});

chrome.runtime.onStartup.addListener(async () => {
  await requestStore.init();
  await updateBadge();
});

/**
 * Message Dispatcher for Popup, Full-page Dashboard, and DevTools Panel
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  (async () => {
    try {
      switch (message.type) {
        case 'GET_STATE': {
          requestMonitor.setUiActive(true);
          await requestStore.init();
          const settings = requestStore.getSettings();
          const requests = requestStore.getRequests();
          sendResponse({
            success: true,
            settings,
            requests,
            count: requests.length
          });
          break;
        }

        case 'TOGGLE_MONITORING': {
          const currentSettings = requestStore.getSettings();
          const newMonitoringState = message.enabled !== undefined ? message.enabled : !currentSettings.monitoringEnabled;
          await requestStore.updateSettings({ monitoringEnabled: newMonitoringState });
          await updateBadge();
          sendResponse({
            success: true,
            monitoringEnabled: newMonitoringState
          });
          break;
        }

        case 'CLEAR_HISTORY': {
          await requestStore.clearHistory();
          await updateBadge();
          sendResponse({ success: true, count: 0 });
          break;
        }

        case 'UPDATE_SETTINGS': {
          const updated = await requestStore.updateSettings(message.settings || {});
          await updateBadge();
          sendResponse({ success: true, settings: updated });
          break;
        }

        case 'EXPORT_DATA': {
          const requests = requestStore.getRequests();
          const format = message.format || 'json';
          let exportContent = '';
          let mimeType = 'application/json';
          let filename = `netlistener-export-${Date.now()}.json`;

          if (format === 'csv') {
            exportContent = formatCsvExport(requests);
            mimeType = 'text/csv';
            filename = `netlistener-export-${Date.now()}.csv`;
          } else {
            exportContent = formatJsonExport(requests);
          }

          sendResponse({
            success: true,
            format,
            content: exportContent,
            mimeType,
            filename,
            count: requests.length
          });
          break;
        }

        case 'OPEN_DASHBOARD': {
          const dashboardUrl = chrome.runtime.getURL('dashboard/dashboard.html');
          await chrome.tabs.create({ url: dashboardUrl });
          sendResponse({ success: true });
          break;
        }

        case 'SEND_FIREBASE_REPORT': {
          const requests = requestStore.getRequests();
          const settings = requestStore.getSettings();
          const config = message.config || settings.firebaseConfig;
          const report = buildStructuredReport(requests, message.metadata || {});
          const sendResult = await sendReportToFirebase(report, config);
          sendResponse({
            success: sendResult.success,
            reportId: sendResult.reportId,
            status: sendResult.status,
            error: sendResult.error,
            reportSummary: {
              totalRequests: report.summaryMetrics.totalRequestsCaptured,
              generatedAt: report.generatedAt,
              reportId: report.reportId
            },
            rawReport: report
          });
          break;
        }

        default:
          sendResponse({ success: false, error: `Unknown message type: ${message.type}` });
          break;
      }
    } catch (err) {
      console.error('[NetListener ServiceWorker] Message error:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();

  return true; // Keep response channel open for async execution
});
