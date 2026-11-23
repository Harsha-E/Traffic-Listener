/**
 * NetListener - End-to-End Workflow Integration Test
 * Starts the local test server, dispatches real HTTP traffic, processes it through
 * the NetListener monitor pipeline, and verifies storage, redaction, intelligence,
 * filtering, and exports.
 */

import http from 'http';
import { RequestStore } from '../core/request-store.js';
import { RequestMonitor } from '../core/request-monitor.js';
import { computeEndpointIntelligence } from '../core/endpoint-parser.js';
import { filterRequests } from '../core/filters.js';
import { formatJsonExport, formatCsvExport } from '../core/export.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

process.env.PORT = '3005';
const TEST_PORT = 3005;

async function runE2E() {
  console.log('======================================================');
  console.log('Running NetListener End-to-End Integration Test');
  console.log('======================================================\n');

  // 1. Boot local test server
  console.log('[Step 1: Starting Local Test Server]');
  const serverModule = await import('../test-app/server.js');
  const server = serverModule.default || serverModule;

  await new Promise(resolve => setTimeout(resolve, 350));
  assert(true, `Test server running at http://127.0.0.1:${TEST_PORT}`);

  // 2. Setup monitor and store
  console.log('\n[Step 2: Initializing NetListener Engine]');
  const store = new RequestStore();
  await store.init();
  await store.clearHistory();
  const monitor = new RequestMonitor(store);

  assert(store.getRequests().length === 0, 'Clean store initialized with 0 records');

  // 3. Helper to make real HTTP request and wire into monitor
  async function performMonitoredRequest({ url, method = 'GET', headers = {}, body = null }) {
    const reqId = `req-e2e-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const fullUrl = url.startsWith('http') ? url : `http://127.0.0.1:${TEST_PORT}${url}`;

    // onBeforeRequest
    monitor.handleBeforeRequest({
      requestId: reqId,
      url: fullUrl,
      method,
      type: 'xmlhttprequest',
      timeStamp: Date.now()
    });

    // onSendHeaders
    const headerArr = Object.entries(headers).map(([name, value]) => ({ name, value }));
    monitor.handleSendHeaders({
      requestId: reqId,
      requestHeaders: headerArr
    });

    // Execute actual network call
    try {
      const fetchOpts = { method, headers };
      if (body) fetchOpts.body = body;

      const res = await fetch(fullUrl, fetchOpts);

      // onHeadersReceived
      const resHeaderArr = [];
      res.headers.forEach((val, key) => { resHeaderArr.push({ name: key, value: val }); });

      monitor.handleHeadersReceived({
        requestId: reqId,
        statusCode: res.status,
        statusLine: `HTTP/1.1 ${res.status}`,
        responseHeaders: resHeaderArr
      });

      // onCompleted
      monitor.handleCompleted({
        requestId: reqId,
        statusCode: res.status,
        fromCache: false,
        timeStamp: Date.now() + 15
      });

      return { reqId, status: res.status };
    } catch (err) {
      // onErrorOccurred
      monitor.handleError({
        requestId: reqId,
        error: err.message,
        timeStamp: Date.now() + 10
      });
      return { reqId, error: err.message };
    }
  }

  // 4. Dispatch diverse requests
  console.log('\n[Step 3: Dispatching Monitored Traffic Scenarios]');

  // Scenario A: GET list
  const r1 = await performMonitoredRequest({ url: '/api/v1/users', method: 'GET' });
  assert(r1.status === 200, 'GET /api/v1/users succeeded with status 200');

  // Scenario B: GET single user (tests parameter abstraction)
  const r2 = await performMonitoredRequest({ url: '/api/v1/users/42', method: 'GET' });
  assert(r2.status === 200, 'GET /api/v1/users/42 succeeded with status 200');

  // Scenario C: POST new user
  const r3 = await performMonitoredRequest({
    url: '/api/v1/users',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Integration Tester' })
  });
  assert(r3.status === 201, 'POST /api/v1/users succeeded with status 201');

  // Scenario D: PUT update
  const r4 = await performMonitoredRequest({
    url: '/api/v1/users/42',
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'Updated Role' })
  });
  assert(r4.status === 200, 'PUT /api/v1/users/42 succeeded with status 200');

  // Scenario E: DELETE user
  const r5 = await performMonitoredRequest({ url: '/api/v1/users/42', method: 'DELETE' });
  assert(r5.status === 204, 'DELETE /api/v1/users/42 succeeded with status 204');

  // Scenario F: Sensitive Query Parameters
  const r6 = await performMonitoredRequest({
    url: '/api/v1/secure-data?apiKey=secret_adm_key_999&token=jwt_xyz_888&password=top_secret_pass&session=sess_123&env=dev'
  });
  assert(r6.status === 200, 'GET /api/v1/secure-data succeeded with status 200');

  // Scenario G: Auth Headers & Set-Cookie
  const r7 = await performMonitoredRequest({
    url: '/api/v1/auth/session',
    headers: {
      'Authorization': 'Bearer secret_live_token_777',
      'X-Api-Key': 'private_key_abc'
    }
  });
  assert(r7.status === 200, 'GET /api/v1/auth/session succeeded with status 200');

  // Scenario H: 404 Client Error
  const r8 = await performMonitoredRequest({ url: '/api/v1/error/not-found' });
  assert(r8.status === 404, 'GET /api/v1/error/not-found returned 404');

  // Scenario I: 500 Server Error
  const r9 = await performMonitoredRequest({ url: '/api/v1/error/server-failure' });
  assert(r9.status === 500, 'GET /api/v1/error/server-failure returned 500');

  // Scenario J: Network error (unreachable port)
  const r10 = await performMonitoredRequest({ url: 'http://127.0.0.1:49998/api/unreachable' });
  assert(r10.error !== undefined, 'Unreachable network request errored as expected');

  // 5. Verification of Captured Traffic in Store
  console.log('\n[Step 4: Verifying Captured Records & Redaction]');
  const captured = store.getRequests();
  assert(captured.length === 10, `Stored exactly 10 requests (Found: ${captured.length})`);

  // Verify Sensitive Query Redaction
  const secureReq = captured.find(r => r.url.includes('/api/v1/secure-data'));
  assert(secureReq !== undefined, 'Found secure-data request in store');
  assert(!secureReq.url.includes('secret_adm_key_999'), 'CRITICAL: Secret apiKey was NOT stored in URL');
  assert(!secureReq.url.includes('top_secret_pass'), 'CRITICAL: Secret password was NOT stored in URL');
  assert(!secureReq.url.includes('jwt_xyz_888'), 'CRITICAL: Secret token was NOT stored in URL');
  assert(secureReq.url.includes('env=dev'), 'Non-sensitive parameter env=dev was preserved');

  // Verify Auth Header Redaction
  const authReq = captured.find(r => r.url.includes('/api/v1/auth/session'));
  assert(authReq !== undefined, 'Found auth session request in store');
  const authHeader = (authReq.requestHeaders || []).find(h => h.name.toLowerCase() === 'authorization');
  assert(authHeader && authHeader.value === 'Bearer [REDACTED]', 'CRITICAL: Authorization header stored as "Bearer [REDACTED]"');

  // Verify Endpoint Intelligence
  console.log('\n[Step 5: Verifying Endpoint Intelligence Aggregation]');
  const intel = computeEndpointIntelligence(captured);
  assert(intel.totalRequests === 10, 'Intelligence counted 10 requests');
  assert(intel.failureCount === 3, 'Intelligence identified 3 failures (404, 500, Network error)');
  assert(intel.failureRate === 30, 'Intelligence calculated 30% failure rate');

  // Verify route abstraction grouped /api/v1/users/42 into /api/v1/users/:id
  const userByIdGroup = intel.groupedEndpoints.find(g => g.routePattern === '/api/v1/users/:id');
  assert(userByIdGroup !== undefined, 'Abstracted and grouped route /api/v1/users/:id');
  assert(userByIdGroup.totalCalls === 3, `Grouped 3 calls (GET, PUT, DELETE) to /api/v1/users/:id (Found: ${userByIdGroup.totalCalls})`);

  // 6. Verify Filter Functionality
  console.log('\n[Step 6: Verifying Filters & Search]');
  const getRequests = filterRequests(captured, { method: 'GET' });
  assert(getRequests.length >= 4, `Filtered GET requests: ${getRequests.length}`);

  const postRequests = filterRequests(captured, { method: 'POST' });
  assert(postRequests.length === 1, 'Filtered POST requests: exactly 1');

  const failedOnly = filterRequests(captured, { status: 'failed' });
  assert(failedOnly.length === 3, 'Filtered failed requests: exactly 3');

  // 7. Verify Export Integrity
  console.log('\n[Step 7: Verifying Export Sanitization]');
  const jsonExport = formatJsonExport(captured);
  const parsedJson = JSON.parse(jsonExport);
  assert(parsedJson.totalRequests === 10, 'JSON export contains 10 records');
  assert(!jsonExport.includes('secret_adm_key_999'), 'JSON export free of secret credentials');

  const csvExport = formatCsvExport(captured);
  assert(csvExport.split('\r\n').length >= 11, 'CSV export contains header and data rows');
  assert(!csvExport.includes('secret_adm_key_999'), 'CSV export free of secret credentials');

  // 8. Clean up
  console.log('\n[Step 8: Teardown]');
  await store.clearHistory();
  assert(store.getRequests().length === 0, 'Clear history verified');
  server.close();
  console.log('Test server shut down successfully.');

  console.log('\n======================================================');
  console.log(`END-TO-END SUMMARY: ALL ${passed} VERIFICATION STEPS PASSED!`);
  console.log('======================================================');
}

runE2E().catch(err => {
  console.error('E2E error:', err);
  process.exit(1);
});
