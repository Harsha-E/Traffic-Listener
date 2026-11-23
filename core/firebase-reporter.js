/**
 * NetListener - Firebase Reporter Module
 * Prepares fully structured network audit reports and transmits them
 * to Firebase (Cloud Firestore REST API, Realtime Database, or Custom Webhook).
 */

import { computeEndpointIntelligence } from './endpoint-parser.js';
import { sanitizeRequestForExport } from './export.js';

export const DEFAULT_FIREBASE_CONFIG = {
  projectId: 'alt-mvgr',
  apiKey: 'AIzaSyCMdcIYi91aWXI9cHz3fFW78rJ8JHV-j9w',
  collection: 'network_reports',
  endpointType: 'firestore', // 'firestore' | 'rtdb' | 'custom'
  customUrl: ''
};

/**
 * Converts a standard JavaScript value into Firestore's typed REST format.
 * 
 * @param {any} val
 * @returns {object}
 */
export function toFirestoreValue(val) {
  if (val === null || val === undefined) {
    return { nullValue: null };
  }
  if (typeof val === 'boolean') {
    return { booleanValue: val };
  }
  if (typeof val === 'number') {
    if (Number.isInteger(val)) {
      return { integerValue: String(val) };
    }
    return { doubleValue: val };
  }
  if (typeof val === 'string') {
    return { stringValue: val };
  }
  if (Array.isArray(val)) {
    return { arrayValue: { values: val.map(toFirestoreValue) } };
  }
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) {
      if (v !== undefined) {
        fields[k] = toFirestoreValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

/**
 * Builds a comprehensive, fully structured network intelligence report from captured traffic.
 * Guarantees complete sanitization of all credentials and tokens.
 * 
 * @param {Array<object>} requests
 * @param {object} [metadata]
 * @returns {object}
 */
export function buildStructuredReport(requests = [], metadata = {}) {
  const intel = computeEndpointIntelligence(requests);
  const sanitizedRequests = requests.map(sanitizeRequestForExport);
  const reportId = `nl_rpt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const now = new Date().toISOString();

  const apiCallsCount = requests.filter(r =>
    r.type === 'xmlhttprequest' || (r.pathname && r.pathname.includes('/api'))
  ).length;

  return {
    reportId,
    generatedAt: now,
    tool: {
      name: 'NetListener — Browser Network Intelligence',
      version: '1.0.0',
      platform: 'Chrome Manifest V3',
      environment: metadata.environment || 'Local Development'
    },
    privacyAudit: {
      dataPolicy: 'Strictly sanitized. All tokens, secrets, cookies, and sensitive query parameters redacted before transmission.',
      monitoringScope: 'localhost, 127.0.0.1',
      totalRedactedItems: sanitizedRequests.reduce((acc, r) => acc + (r.redactedItemsCount || 0), 0)
    },
    summaryMetrics: {
      totalRequestsCaptured: requests.length,
      apiCallsCount,
      uniqueOriginsCount: intel.uniqueOriginsCount,
      uniqueEndpointsCount: intel.uniqueEndpointsCount,
      totalFailuresCount: intel.failureCount,
      failureRatePercent: intel.failureRate,
      origins: intel.origins
    },
    trafficDistributions: {
      byMethod: intel.methodDistribution,
      byStatus: intel.statusDistribution,
      byResourceType: intel.typeDistribution
    },
    endpointIntelligence: {
      topFrequentEndpoints: intel.frequentEndpoints.map(g => ({
        routePattern: g.routePattern,
        origin: g.origin,
        totalCalls: g.totalCalls,
        methods: g.methods,
        avgDurationMs: g.avgDuration,
        failureCount: g.failureCount
      })),
      interestingApiRoutes: intel.interestingApiRoutes.map(g => ({
        routePattern: g.routePattern,
        totalCalls: g.totalCalls,
        methods: g.methods
      })),
      failedEndpoints: intel.failedEndpoints.map(g => ({
        routePattern: g.routePattern,
        failureCount: g.failureCount,
        statusCodes: g.statusCodes
      }))
    },
    // Array of strictly sanitized requests
    capturedRequests: sanitizedRequests
  };
}

/**
 * Sends a structured report to Firebase.
 * 
 * @param {object} report
 * @param {object} config
 * @returns {Promise<{ success: boolean, reportId: string, status: number, details?: any, error?: string }>}
 */
export async function sendReportToFirebase(report, config = {}) {
  const mergedConfig = { ...DEFAULT_FIREBASE_CONFIG, ...config };
  const { projectId, apiKey, collection, endpointType, customUrl } = mergedConfig;

  let targetUrl = '';
  let payloadBody = null;

  try {
    if (endpointType === 'custom' && customUrl) {
      targetUrl = customUrl;
      payloadBody = JSON.stringify(report);
    } else if (endpointType === 'rtdb') {
      targetUrl = `https://${projectId}-default-rtdb.firebaseio.com/${collection}/${report.reportId}.json`;
      if (apiKey) targetUrl += `?auth=${apiKey}`;
      payloadBody = JSON.stringify(report);
    } else {
      // Default: Cloud Firestore REST API
      targetUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?documentId=${report.reportId}&key=${apiKey}`;
      const firestoreDoc = {
        fields: toFirestoreValue(report).mapValue.fields
      };
      payloadBody = JSON.stringify(firestoreDoc);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000); // 12s timeout

    const response = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: payloadBody,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const responseData = await response.json().catch(() => ({}));

    if (response.ok) {
      return {
        success: true,
        reportId: report.reportId,
        status: response.status,
        details: responseData
      };
    } else {
      const errMsg = responseData.error?.message || responseData.error || response.statusText;
      return {
        success: false,
        reportId: report.reportId,
        status: response.status,
        error: `Firebase returned HTTP ${response.status}: ${errMsg}`,
        details: responseData
      };
    }
  } catch (err) {
    return {
      success: false,
      reportId: report.reportId,
      status: 0,
      error: `Network/CORS error reaching Firebase: ${err.message}`
    };
  }
}
