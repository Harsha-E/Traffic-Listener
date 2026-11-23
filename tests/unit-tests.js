/**
 * NetListener Automated Unit & Integration Test Suite
 * Tests sanitization, endpoint parsing, route abstraction, filtering,
 * store FIFO buffer limits, and sanitized export generation.
 */

import { isSensitiveKey, sanitizeUrl, sanitizeHeaders, escapeHtml } from '../core/sanitizer.js';
import { abstractRoutePattern, parseEndpoint, computeEndpointIntelligence, isLikelyApiRoute } from '../core/endpoint-parser.js';
import { filterRequests, sortRequests } from '../core/filters.js';
import { RequestStore } from '../core/request-store.js';
import { formatJsonExport, formatCsvExport, sanitizeRequestForExport } from '../core/export.js';
import { toFirestoreValue, buildStructuredReport } from '../core/firebase-reporter.js';
import { isLocalSubnet, isNoisyResource, shouldCaptureRequest } from '../core/subnet-filter.js';
import { compressJson, decompressJson } from '../core/compression.js';

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

function assertEqual(actual, expected, message) {
  const isMatch = JSON.stringify(actual) === JSON.stringify(expected);
  assert(isMatch, `${message} (Expected: ${JSON.stringify(expected)}, Actual: ${JSON.stringify(actual)})`);
}

console.log('======================================================');
console.log('Running NetListener Automated Test Suite');
console.log('======================================================\n');

// 1. Sanitizer Tests
console.log('[Suite 1: Sanitizer & Credential Redaction]');
{
  assert(isSensitiveKey('apiKey'), 'isSensitiveKey identifies apiKey');
  assert(isSensitiveKey('token'), 'isSensitiveKey identifies token');
  assert(isSensitiveKey('password'), 'isSensitiveKey identifies password');
  assert(isSensitiveKey('session_id'), 'isSensitiveKey identifies session_id');
  assert(isSensitiveKey('my_secret_token'), 'isSensitiveKey identifies custom _token');
  assert(!isSensitiveKey('page'), 'isSensitiveKey ignores page');
  assert(!isSensitiveKey('query'), 'isSensitiveKey ignores query');

  const testUrl = 'http://localhost:3000/api/v1/data?apiKey=secret123&page=2&token=jwt_xyz&format=json';
  const urlRes = sanitizeUrl(testUrl);
  assert(urlRes.redactionCount === 2, 'sanitizeUrl detected exactly 2 sensitive parameters');
  assert(urlRes.sanitizedUrl.includes('apiKey=%5BREDACTED%5D') || urlRes.sanitizedUrl.includes('apiKey=[REDACTED]'), 'apiKey value was redacted');
  assert(urlRes.sanitizedUrl.includes('token=%5BREDACTED%5D') || urlRes.sanitizedUrl.includes('token=[REDACTED]'), 'token value was redacted');
  assert(urlRes.sanitizedUrl.includes('page=2'), 'Non-sensitive page parameter preserved');
  assert(urlRes.sanitizedUrl.includes('format=json'), 'Non-sensitive format parameter preserved');

  // Headers sanitization
  const rawHeaders = [
    { name: 'Host', value: 'localhost:3000' },
    { name: 'Authorization', value: 'Bearer secret_jwt_token_999' },
    { name: 'Cookie', value: 'session_id=sess_secret_123; user_pref=dark' },
    { name: 'X-Api-Key', value: 'super_secret_key' },
    { name: 'Content-Type', value: 'application/json' }
  ];
  const sanitizedHeaders = sanitizeHeaders(rawHeaders);
  const authHeader = sanitizedHeaders.find(h => h.name === 'Authorization');
  const cookieHeader = sanitizedHeaders.find(h => h.name === 'Cookie');
  const apiKeyHeader = sanitizedHeaders.find(h => h.name === 'X-Api-Key');
  const ctHeader = sanitizedHeaders.find(h => h.name === 'Content-Type');

  assertEqual(authHeader.value, 'Bearer [REDACTED]', 'Authorization header redacted with Bearer scheme preserved');
  assert(cookieHeader.value.includes('session_id=[REDACTED]'), 'Cookie values redacted while preserving cookie names');
  assertEqual(apiKeyHeader.value, '[REDACTED]', 'X-Api-Key value redacted');
  assertEqual(ctHeader.value, 'application/json', 'Content-Type header preserved untouched');

  // HTML escaping
  const xssStr = '<script>alert("XSS")</script>&"\'';
  const escaped = escapeHtml(xssStr);
  assert(!escaped.includes('<script>'), 'escapeHtml escapes < and > tags');
  assert(escaped.includes('&lt;script&gt;'), 'escapeHtml correctly encodes HTML entities');
}

// 2. Endpoint Parser & Intelligence Tests
console.log('\n[Suite 2: Route Abstraction & Endpoint Intelligence]');
{
  assertEqual(abstractRoutePattern('/api/v1/users/42'), '/api/v1/users/:id', 'Abstracts numeric ID to :id');
  assertEqual(abstractRoutePattern('/v1/sessions/550e8400-e29b-41d4-a716-446655440000'), '/v1/sessions/:uuid', 'Abstracts UUID to :uuid');
  assertEqual(abstractRoutePattern('/assets/images/logo.png'), '/assets/images/logo.png', 'Preserves static file path');

  const parsed = parseEndpoint('http://localhost:3000/api/v1/users/42?limit=10', 'xmlhttprequest');
  assert(parsed.isValid, 'parseEndpoint parses valid URL');
  assertEqual(parsed.origin, 'http://localhost:3000', 'Extracted origin correctly');
  assertEqual(parsed.routePattern, '/api/v1/users/:id', 'Extracted route pattern correctly');
  assert(parsed.isApiRoute, 'Classified /api route as API endpoint');

  // Endpoint Intelligence Aggregation
  const dummyRequests = [
    { url: 'http://localhost:3000/api/users/1', method: 'GET', statusCode: 200, duration: 15, type: 'xmlhttprequest', timestamp: 1000 },
    { url: 'http://localhost:3000/api/users/2', method: 'GET', statusCode: 200, duration: 25, type: 'xmlhttprequest', timestamp: 1001 },
    { url: 'http://localhost:3000/api/users/3', method: 'DELETE', statusCode: 204, duration: 20, type: 'xmlhttprequest', timestamp: 1002 },
    { url: 'http://localhost:3000/api/users', method: 'POST', statusCode: 500, duration: 40, type: 'xmlhttprequest', timestamp: 1003 },
    { url: 'http://localhost:3000/style.css', method: 'GET', statusCode: 200, duration: 5, type: 'stylesheet', timestamp: 1004 }
  ];

  const intel = computeEndpointIntelligence(dummyRequests);
  assertEqual(intel.totalRequests, 5, 'Intelligence calculated total requests');
  assertEqual(intel.methodDistribution, { GET: 3, DELETE: 1, POST: 1 }, 'Intelligence computed method distribution');
  assertEqual(intel.failureCount, 1, 'Intelligence detected 1 failure (status 500)');
  assertEqual(intel.failureRate, 20, 'Failure rate calculated as 20%');

  // Verify grouping of /api/users/1, /api/users/2, and /api/users/3 into single route /api/users/:id
  const userGroup = intel.groupedEndpoints.find(g => g.routePattern === '/api/users/:id');
  assert(userGroup !== undefined, 'Grouped /api/users/:id route pattern');
  assertEqual(userGroup.totalCalls, 3, 'Grouped 3 calls to /api/users/:id');
  assertEqual(userGroup.methods, { GET: 2, DELETE: 1 }, 'Grouped methods for /api/users/:id');
  assertEqual(userGroup.avgDuration, 20, 'Average duration for /api/users/:id is (15+25+20)/3 = 20ms');
}

// 3. Filters Tests
console.log('\n[Suite 3: Filtering & Search Logic]');
{
  const testSet = [
    { url: 'http://localhost:3000/api/v1/users', method: 'GET', statusCode: 200, type: 'xmlhttprequest', timestamp: 10 },
    { url: 'http://localhost:3000/api/v1/users', method: 'POST', statusCode: 201, type: 'xmlhttprequest', timestamp: 20 },
    { url: 'http://localhost:3000/api/v1/posts', method: 'GET', statusCode: 404, type: 'xmlhttprequest', timestamp: 30 },
    { url: 'http://localhost:3000/app.js', method: 'GET', statusCode: 200, type: 'script', timestamp: 40 }
  ];

  // Method filter
  const postOnly = filterRequests(testSet, { method: 'POST' });
  assertEqual(postOnly.length, 1, 'Filter by method POST returns 1 item');
  assertEqual(postOnly[0].method, 'POST', 'Filter by method POST matches correctly');

  // Status filter
  const errOnly = filterRequests(testSet, { status: '4xx' });
  assertEqual(errOnly.length, 1, 'Filter by status 4xx returns 1 item');
  assertEqual(errOnly[0].statusCode, 404, 'Filter by status 4xx found 404 request');

  // Resource type filter
  const scriptOnly = filterRequests(testSet, { resourceType: 'script' });
  assertEqual(scriptOnly.length, 1, 'Filter by resource type script returns 1 item');

  // Search filter
  const searchUsers = filterRequests(testSet, { search: 'users' });
  assertEqual(searchUsers.length, 2, 'Search query "users" matched 2 requests');

  // Sorting
  const sortedOldest = sortRequests(testSet, 'oldest');
  assertEqual(sortedOldest[0].timestamp, 10, 'Sort oldest places lowest timestamp first');
  const sortedNewest = sortRequests(testSet, 'newest');
  assertEqual(sortedNewest[0].timestamp, 40, 'Sort newest places highest timestamp first');
}

// 4. RequestStore & FIFO Buffer Tests
console.log('\n[Suite 4: RequestStore Persistence & FIFO Buffer Management]');
{
  const store = new RequestStore();
  await store.init();
  await store.updateSettings({ maxHistorySize: 3 });

  store.addOrUpdateRequest({ id: 'r1', url: 'http://localhost:3000/1', timestamp: 1 });
  store.addOrUpdateRequest({ id: 'r2', url: 'http://localhost:3000/2', timestamp: 2 });
  store.addOrUpdateRequest({ id: 'r3', url: 'http://localhost:3000/3', timestamp: 3 });
  assertEqual(store.getRequests().length, 3, 'Store holds 3 requests');

  // Add 4th request -> r1 should be pruned (FIFO)
  store.addOrUpdateRequest({ id: 'r4', url: 'http://localhost:3000/4', timestamp: 4 });
  const reqs = store.getRequests();
  assertEqual(reqs.length, 3, 'Store maintained buffer limit of 3');
  assert(reqs.find(r => r.id === 'r1') === undefined, 'Oldest request r1 was evicted (FIFO)');
  assert(reqs.find(r => r.id === 'r4') !== undefined, 'Newest request r4 was inserted');

  // Update in-place
  store.addOrUpdateRequest({ id: 'r4', statusCode: 200, duration: 18 });
  assertEqual(store.getRequestById('r4').statusCode, 200, 'Existing request r4 updated in-place');
  assertEqual(store.getRequests().length, 3, 'In-place update did not increase buffer count');

  // Clear history
  await store.clearHistory();
  assertEqual(store.getRequests().length, 0, 'clearHistory emptied the store');
}

// 5. Export Tests
console.log('\n[Suite 5: Sanitized JSON and CSV Export]');
{
  const exportSample = [
    {
      id: 'req-01',
      url: 'http://localhost:3000/api/login?token=super_secret_jwt_token',
      method: 'POST',
      statusCode: 200,
      lifecycle: 'completed',
      duration: 18,
      type: 'xmlhttprequest',
      requestHeaders: [
        { name: 'Authorization', value: 'Bearer secret_auth_token_xyz' },
        { name: 'Cookie', value: 'session_id=secret_cookie_val' }
      ],
      responseHeaders: [
        { name: 'Set-Cookie', value: 'auth=secret_auth; HttpOnly' }
      ]
    }
  ];

  const jsonExport = formatJsonExport(exportSample);
  assert(!jsonExport.includes('super_secret_jwt_token'), 'JSON export does NOT contain secret query token');
  assert(!jsonExport.includes('secret_auth_token_xyz'), 'JSON export does NOT contain secret auth token');
  assert(!jsonExport.includes('secret_cookie_val'), 'JSON export does NOT contain secret cookie value');
  assert(jsonExport.includes('[REDACTED]'), 'JSON export contains [REDACTED] indicators');

  const csvExport = formatCsvExport(exportSample);
  assert(!csvExport.includes('super_secret_jwt_token'), 'CSV export does NOT contain secret query token');
  assert(csvExport.includes('Request ID'), 'CSV export includes standard header row');
  assert(csvExport.includes('"req-01"'), 'CSV export includes quoted request record');
}

// 6. Firebase Reporter Tests
console.log('\n[Suite 6: Firebase Structured Report & Firestore Serializer]');
{
  // Test toFirestoreValue primitives
  assertEqual(toFirestoreValue(null), { nullValue: null }, 'toFirestoreValue handles null');
  assertEqual(toFirestoreValue(true), { booleanValue: true }, 'toFirestoreValue handles boolean');
  assertEqual(toFirestoreValue(42), { integerValue: '42' }, 'toFirestoreValue handles integer');
  assertEqual(toFirestoreValue(3.14), { doubleValue: 3.14 }, 'toFirestoreValue handles double');
  assertEqual(toFirestoreValue('hello'), { stringValue: 'hello' }, 'toFirestoreValue handles string');
  assertEqual(toFirestoreValue(['a', 1]), { arrayValue: { values: [{ stringValue: 'a' }, { integerValue: '1' }] } }, 'toFirestoreValue handles array');

  // Test buildStructuredReport
  const testRequests = [
    {
      id: 'r-fb-1',
      url: 'http://localhost:3000/api/v1/auth?token=my_secret_token_123&apiKey=secret_key',
      method: 'POST',
      statusCode: 200,
      duration: 24,
      type: 'xmlhttprequest',
      requestHeaders: [{ name: 'Authorization', value: 'Bearer top_secret_jwt' }]
    },
    {
      id: 'r-fb-2',
      url: 'http://localhost:3000/api/v1/users/99',
      method: 'GET',
      statusCode: 404,
      duration: 10,
      type: 'xmlhttprequest'
    }
  ];

  const report = buildStructuredReport(testRequests, { environment: 'Test Env' });
  assert(report.reportId.startsWith('nl_rpt_'), 'Generated valid report ID');
  assertEqual(report.summaryMetrics.totalRequestsCaptured, 2, 'Summary counts 2 captured requests');
  assertEqual(report.summaryMetrics.totalFailuresCount, 1, 'Summary detected 1 failure');
  assertEqual(report.summaryMetrics.failureRatePercent, 50, 'Failure rate is 50%');

  const reportStr = JSON.stringify(report);
  assert(!reportStr.includes('my_secret_token_123'), 'CRITICAL: Structured report does NOT contain query token');
  assert(!reportStr.includes('top_secret_jwt'), 'CRITICAL: Structured report does NOT contain auth token');
  assert(reportStr.includes('[REDACTED]'), 'Structured report contains [REDACTED] markers');
}

// 7. Subnet & High-Performance Pre-Filtering Tests
console.log('\n[Suite 7: Subnet & Resource Pre-Filtering]');
{
  // 192.168.x.x Subnet
  assert(isLocalSubnet('192.168.1.1'), 'isLocalSubnet identifies 192.168.1.1');
  assert(isLocalSubnet('192.168.0.254'), 'isLocalSubnet identifies 192.168.0.254');
  assert(isLocalSubnet('192.168.100.50'), 'isLocalSubnet identifies 192.168.100.50');

  // 10.x.x.x Subnet
  assert(isLocalSubnet('10.0.0.1'), 'isLocalSubnet identifies 10.0.0.1');
  assert(isLocalSubnet('10.254.1.99'), 'isLocalSubnet identifies 10.254.1.99');

  // 172.16-31.x.x Subnet
  assert(isLocalSubnet('172.16.0.1'), 'isLocalSubnet identifies 172.16.0.1');
  assert(isLocalSubnet('172.24.1.1'), 'isLocalSubnet identifies 172.24.1.1');
  assert(isLocalSubnet('172.31.255.255'), 'isLocalSubnet identifies 172.31.255.255');

  // Local loopbacks and mDNS
  assert(isLocalSubnet('localhost'), 'isLocalSubnet identifies localhost');
  assert(isLocalSubnet('127.0.0.1'), 'isLocalSubnet identifies 127.0.0.1');
  assert(isLocalSubnet('[::1]'), 'isLocalSubnet identifies [::1]');
  assert(isLocalSubnet('my-laptop.local'), 'isLocalSubnet identifies .local mDNS host');
  assert(isLocalSubnet('router.lan'), 'isLocalSubnet identifies .lan host');
  assert(isLocalSubnet('service.internal'), 'isLocalSubnet identifies .internal host');

  // Negative public internet targets (MUST be rejected)
  assert(!isLocalSubnet('8.8.8.8'), 'isLocalSubnet rejects public DNS 8.8.8.8');
  assert(!isLocalSubnet('142.250.190.46'), 'isLocalSubnet rejects public Google IP');
  assert(!isLocalSubnet('google.com'), 'isLocalSubnet rejects google.com');
  assert(!isLocalSubnet('api.github.com'), 'isLocalSubnet rejects api.github.com');
  assert(!isLocalSubnet('172.32.0.1'), 'isLocalSubnet rejects out-of-range 172.32.0.1');

  // Noisy resource type filtering
  assert(isNoisyResource('font', 'http://192.168.1.1/font.woff2'), 'isNoisyResource identifies font');
  assert(isNoisyResource('media', 'http://192.168.1.1/stream.mp4'), 'isNoisyResource identifies media');
  assert(isNoisyResource('ping', 'http://192.168.1.1/track'), 'isNoisyResource identifies ping');
  assert(isNoisyResource('beacon', 'http://192.168.1.1/beacon'), 'isNoisyResource identifies beacon');
  assert(isNoisyResource('other', 'http://192.168.1.1/favicon.ico'), 'isNoisyResource identifies favicon.ico URL');
  assert(!isNoisyResource('xmlhttprequest', 'http://192.168.1.1/api/users'), 'isNoisyResource preserves xmlhttprequest');
  assert(!isNoisyResource('fetch', 'http://192.168.1.1/api/auth'), 'isNoisyResource preserves fetch');
  assert(!isNoisyResource('main_frame', 'http://192.168.1.1/index.html'), 'isNoisyResource preserves document HTML');

  // shouldCaptureRequest end-to-end evaluation
  const settingsSubnet = { monitoringEnabled: true, scopeMode: 'subnet' };
  assert(shouldCaptureRequest({ url: 'http://192.168.1.10:8080/api/status', type: 'xmlhttprequest' }, settingsSubnet), 'Captures local subnet 192.168.x.x request');
  assert(shouldCaptureRequest({ url: 'http://localhost:3000/api/users', type: 'fetch' }, settingsSubnet), 'Captures localhost request');
  assert(!shouldCaptureRequest({ url: 'https://twitter.com/i/api/2/notifications', type: 'xmlhttprequest' }, settingsSubnet), 'Rejects external public web request in subnet mode');
  assert(!shouldCaptureRequest({ url: 'http://192.168.1.10:8080/favicon.ico', type: 'image' }, settingsSubnet), 'Discards noisy favicon.ico on local subnet');
  assert(!shouldCaptureRequest({ url: 'http://192.168.1.10:8080/fonts/glyph.woff2', type: 'font' }, settingsSubnet), 'Discards font resource on local subnet');
}

// 8. Real-time Deflate Compression & Lean Schema Tests
console.log('\n[Suite 8: Real-time Deflate Compression & Lean Schema]');
{
  const mockDataset = [];
  for (let i = 0; i < 50; i++) {
    mockDataset.push({
      id: `req-bench-${i}`,
      url: `http://192.168.1.25:8000/api/v1/devices/${i}/telemetry?period=hourly&filter=all`,
      origin: 'http://192.168.1.25:8000',
      pathname: `/api/v1/devices/${i}/telemetry`,
      routePattern: '/api/v1/devices/:id/telemetry',
      method: i % 2 === 0 ? 'GET' : 'POST',
      type: 'xmlhttprequest',
      timestamp: Date.now() + i * 100,
      statusCode: 200,
      duration: 15 + (i % 30),
      requestHeaders: [
        { name: 'Host', value: '192.168.1.25:8000', redacted: false },
        { name: 'Content-Type', value: 'application/json', redacted: false },
        { name: 'Authorization', value: 'Bearer [REDACTED]', redacted: true }
      ],
      responseHeaders: [
        { name: 'Content-Type', value: 'application/json', redacted: false },
        { name: 'Cache-Control', value: 'no-cache', redacted: false }
      ]
    });
  }

  const rawSize = JSON.stringify(mockDataset).length;
  const compressedResult = await compressJson(mockDataset);

  assert(compressedResult.__compressed === true, 'Payload is marked as compressed');
  assert(compressedResult.algo === 'deflate', 'Compression algorithm is deflate');
  assert(compressedResult.compressedSize < rawSize, `Compressed size (${compressedResult.compressedSize} B) is smaller than raw size (${rawSize} B)`);
  assert(compressedResult.ratio > 80, `Achieved ${compressedResult.ratio}% compression ratio (>80% required)`);

  // Decompress back and verify integrity
  const restored = await decompressJson(compressedResult);
  assertEqual(restored.length, mockDataset.length, 'Restored dataset has exact same item count');
  assertEqual(restored[0].id, mockDataset[0].id, 'Restored first item ID matches');
  assertEqual(restored[49].routePattern, mockDataset[49].routePattern, 'Restored route pattern matches');
  assertEqual(restored[20].requestHeaders, mockDataset[20].requestHeaders, 'Restored sanitized headers match');

  // Verify header stripping of noisy browser internals
  const dirtyHeaders = [
    { name: 'Authorization', value: 'Bearer topsecret' },
    { name: 'sec-ch-ua', value: '"Chromium";v="124"' },
    { name: 'sec-fetch-dest', value: 'empty' },
    { name: 'sec-fetch-mode', value: 'cors' },
    { name: 'priority', value: 'u=1, i' },
    { name: 'Content-Type', value: 'application/json' },
    { name: 'X-Requested-With', value: 'XMLHttpRequest' }
  ];

  const strippedHeaders = sanitizeHeaders(dirtyHeaders, true);
  assertEqual(strippedHeaders.length, 3, 'Stripped 4 low-value sec-ch/sec-fetch/priority headers');
  assertEqual(strippedHeaders.map(h => h.name), ['Authorization', 'Content-Type', 'X-Requested-With'], 'Kept essential API and security headers');
}

console.log('\n======================================================');
console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('======================================================');

if (failed > 0) {
  process.exit(1);
}
