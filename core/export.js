/**
 * NetListener - Export Module
 * Generates sanitized, audit-compliant JSON and CSV export formats.
 * Guarantees zero leakage of credentials, tokens, cookies, or secrets.
 */

import { sanitizeUrl, sanitizeHeaders } from './sanitizer.js';

/**
 * Prepares a cleaned and strictly sanitized representation of a request for export.
 * 
 * @param {object} req
 * @returns {object}
 */
export function sanitizeRequestForExport(req) {
  // Re-verify URL sanitization
  const urlSanitized = sanitizeUrl(req.url || '');
  
  // Re-verify Header sanitization
  const reqHeadersSanitized = sanitizeHeaders(req.requestHeaders || []);
  const resHeadersSanitized = sanitizeHeaders(req.responseHeaders || []);

  return {
    id: req.id || req.requestId || '',
    timestamp: req.timestamp || Date.now(),
    isoTime: req.timestamp ? new Date(req.timestamp).toISOString() : new Date().toISOString(),
    method: req.method ? req.method.toUpperCase() : 'UNKNOWN',
    url: urlSanitized.sanitizedUrl,
    origin: req.origin || '',
    pathname: req.pathname || '',
    routePattern: req.routePattern || '',
    statusCode: typeof req.statusCode === 'number' ? req.statusCode : null,
    statusLine: req.statusLine || '',
    lifecycle: req.lifecycle || 'unknown',
    durationMs: typeof req.duration === 'number' ? req.duration : null,
    resourceType: req.type || 'other',
    initiator: req.initiator || '',
    fromCache: Boolean(req.fromCache),
    error: req.error || null,
    redactedItemsCount: (urlSanitized.redactionCount || 0) +
      reqHeadersSanitized.filter(h => h.redacted).length +
      resHeadersSanitized.filter(h => h.redacted).length,
    requestHeaders: reqHeadersSanitized.map(h => ({ name: h.name, value: h.value })),
    responseHeaders: resHeadersSanitized.map(h => ({ name: h.name, value: h.value }))
  };
}

/**
 * Generates a formatted JSON string export of the captured requests.
 * 
 * @param {Array<object>} requests
 * @returns {string}
 */
export function formatJsonExport(requests) {
  const sanitizedRequests = (requests || []).map(sanitizeRequestForExport);

  const exportPayload = {
    exportVersion: '1.0',
    tool: 'NetListener — Browser Network Intelligence Extension',
    exportedAt: new Date().toISOString(),
    securityNotice: 'All authentication headers, session cookies, passwords, and sensitive query parameters are strictly redacted.',
    totalRequests: sanitizedRequests.length,
    requests: sanitizedRequests
  };

  return JSON.stringify(exportPayload, null, 2);
}

/**
 * Generates a RFC 4180 compliant CSV export of captured requests.
 * 
 * @param {Array<object>} requests
 * @returns {string}
 */
export function formatCsvExport(requests) {
  const headers = [
    'Request ID',
    'Timestamp (ISO)',
    'Method',
    'Status Code',
    'Lifecycle',
    'Duration (ms)',
    'Resource Type',
    'Origin',
    'Pathname',
    'Route Pattern',
    'Sanitized URL',
    'Redacted Items Count',
    'From Cache',
    'Initiator',
    'Error'
  ];

  const escapeCsv = (val) => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const rows = (requests || []).map(rawReq => {
    const req = sanitizeRequestForExport(rawReq);
    return [
      escapeCsv(req.id),
      escapeCsv(req.isoTime),
      escapeCsv(req.method),
      escapeCsv(req.statusCode !== null ? req.statusCode : 'N/A'),
      escapeCsv(req.lifecycle),
      escapeCsv(req.durationMs !== null ? req.durationMs : 'N/A'),
      escapeCsv(req.resourceType),
      escapeCsv(req.origin),
      escapeCsv(req.pathname),
      escapeCsv(req.routePattern),
      escapeCsv(req.url),
      escapeCsv(req.redactedItemsCount),
      escapeCsv(req.fromCache ? 'true' : 'false'),
      escapeCsv(req.initiator),
      escapeCsv(req.error || '')
    ].join(',');
  });

  return [headers.map(escapeCsv).join(','), ...rows].join('\r\n');
}
