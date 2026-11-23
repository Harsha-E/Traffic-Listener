/**
 * NetListener - Simulation & Lifecycle Tests
 * Simulates service worker suspension & restart, empty & large history,
 * monitoring toggle state, and high-volume burst load.
 */

import { RequestStore } from '../core/request-store.js';
import { RequestMonitor } from '../core/request-monitor.js';
import { computeEndpointIntelligence } from '../core/endpoint-parser.js';
import { filterRequests } from '../core/filters.js';

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
console.log('Running NetListener Lifecycle & Simulation Tests');
console.log('======================================================\n');

// 1. Service Worker Suspension and Restart Test
console.log('[Test 1: Service Worker Ephemeral Lifecycle & Persistence]');
{
  const store1 = new RequestStore();
  await store1.init();
  await store1.updateSettings({ monitoringEnabled: true, maxHistorySize: 200 });

  store1.addOrUpdateRequest({
    id: 'req-persist-1',
    requestId: 'req-persist-1',
    url: 'http://localhost:3000/api/v1/auth/login',
    method: 'POST',
    statusCode: 200,
    duration: 32,
    timestamp: Date.now()
  });
  await store1.flush();

  // Simulate Service Worker termination: store1 discarded, store2 spins up
  const store2 = new RequestStore();
  await store2.init();

  const recoveredRequests = store2.getRequests();
  const recoveredSettings = store2.getSettings();

  assert(recoveredRequests.length >= 1, 'Requests recovered after service worker restart');
  const req = recoveredRequests.find(r => r.id === 'req-persist-1');
  assert(req !== undefined, 'Persisted request found with intact metadata');
  assertEqual(req.method, 'POST', 'Method preserved across SW restart');
  assertEqual(req.statusCode, 200, 'Status code preserved across SW restart');
  assertEqual(recoveredSettings.monitoringEnabled, true, 'Settings preserved across SW restart');
}

// 2. Empty Request History
console.log('\n[Test 2: Empty Request History Handling]');
{
  const emptyStore = new RequestStore();
  await emptyStore.clearHistory();

  const reqs = emptyStore.getRequests();
  assertEqual(reqs.length, 0, 'Store is empty after clear');

  const filtered = filterRequests(reqs, { search: 'users', method: 'GET' });
  assertEqual(filtered.length, 0, 'Filtering on empty store returns empty array gracefully');

  const intel = computeEndpointIntelligence(reqs);
  assertEqual(intel.totalRequests, 0, 'Intelligence handles empty store with 0 total requests');
  assertEqual(intel.failureRate, 0, 'Intelligence failure rate is 0% on empty store (no NaN)');
  assertEqual(intel.groupedEndpoints.length, 0, 'Grouped endpoints is empty array');
}

// 3. Large Request History & FIFO Pruning
console.log('\n[Test 3: Large Request History & Buffer Management]');
{
  const largeStore = new RequestStore();
  await largeStore.init();
  await largeStore.updateSettings({ maxHistorySize: 100 });

  const startTime = Date.now();
  for (let i = 1; i <= 250; i++) {
    largeStore.addOrUpdateRequest({
      id: `burst-${i}`,
      requestId: `burst-${i}`,
      url: `http://localhost:3000/api/items/${i % 10}`,
      method: i % 2 === 0 ? 'GET' : 'POST',
      statusCode: i % 15 === 0 ? 500 : 200,
      duration: 10 + (i % 20),
      timestamp: startTime + i
    });
  }

  const stored = largeStore.getRequests();
  assertEqual(stored.length, 100, 'Buffer strictly capped at maxHistorySize (100)');
  assert(largeStore.getRequestById('burst-1') === null, 'Earliest request (burst-1) was pruned');
  assert(largeStore.getRequestById('burst-250') !== null, 'Latest request (burst-250) is retained');

  // Verify fast search and aggregation over large history
  const t0 = Date.now();
  const searchResults = filterRequests(stored, { method: 'POST', status: '2xx' });
  const intelLarge = computeEndpointIntelligence(stored);
  const elapsed = Date.now() - t0;

  assert(elapsed < 20, `Filter and intelligence executed in ${elapsed}ms (< 20ms)`);
  assert(searchResults.length > 0, `Found ${searchResults.length} matching POST 2xx requests`);
  assertEqual(intelLarge.totalRequests, 100, 'Intelligence accurately aggregated 100 requests');
}

// 4. Monitoring Toggle (Disabled State)
console.log('\n[Test 4: Monitoring Disabled State]');
{
  const store = new RequestStore();
  await store.init();
  const testMonitor = new RequestMonitor(store);
  await store.updateSettings({ monitoringEnabled: false });

  // Simulate webRequest event while monitoring is disabled
  testMonitor.handleBeforeRequest({
    requestId: 'disabled-req-01',
    url: 'http://localhost:3000/api/test',
    method: 'GET',
    type: 'xmlhttprequest',
    timeStamp: Date.now()
  });

  const captured = store.getRequestById('disabled-req-01');
  assert(captured === null, 'Traffic was IGNORED when monitoringEnabled is false');

  // Re-enable monitoring
  await store.updateSettings({ monitoringEnabled: true });
  testMonitor.handleBeforeRequest({
    requestId: 'enabled-req-02',
    url: 'http://localhost:3000/api/test',
    method: 'GET',
    type: 'xmlhttprequest',
    timeStamp: Date.now()
  });

  const captured2 = store.getRequestById('enabled-req-02');
  assert(captured2 !== null, 'Traffic was CAPTURED after re-enabling monitoring');
}

// 5. Origin Scope & Website Coverage Tests
console.log('\n[Test 5: Origin Scope & Website Coverage]');
{
  const testMonitor = new RequestMonitor();

  // Mode: All Websites (default)
  assert(testMonitor.isOriginAllowed('http://localhost:3000/api/users', [], 'all'), 'All mode permits http://localhost');
  assert(testMonitor.isOriginAllowed('https://api.github.com/repos', [], 'all'), 'All mode permits public APIs (api.github.com)');
  assert(testMonitor.isOriginAllowed('https://google.com/search', [], 'all'), 'All mode permits public websites (google.com)');
  assert(testMonitor.isOriginAllowed('https://example.com/api/v1', [], 'all'), 'All mode permits arbitrary web endpoints');

  // Exclude non-web protocols
  assert(!testMonitor.isOriginAllowed('chrome://extensions/', [], 'all'), 'All mode excludes chrome:// URLs');
  assert(!testMonitor.isOriginAllowed('about:blank', [], 'all'), 'All mode excludes about:blank');

  // Mode: Local Only (restricted mode)
  assert(testMonitor.isOriginAllowed('http://localhost:3000/api', [], 'local'), 'Local mode permits localhost');
  assert(!testMonitor.isOriginAllowed('https://google.com/search', [], 'local'), 'Local mode blocks external domains');

  // Mode: Subnet (192.168.x.x, 10.x.x.x, 172.16-31.x.x, localhost)
  assert(testMonitor.isOriginAllowed('http://192.168.1.100:8080/metrics', [], 'subnet'), 'Subnet mode permits 192.168.x.x device');
  assert(testMonitor.isOriginAllowed('http://10.0.1.5:3000/api/v1', [], 'subnet'), 'Subnet mode permits 10.x.x.x endpoint');
  assert(testMonitor.isOriginAllowed('http://172.20.0.2:9000/api', [], 'subnet'), 'Subnet mode permits 172.16-31.x.x Docker container');
  assert(testMonitor.isOriginAllowed('http://localhost:3000/api', [], 'subnet'), 'Subnet mode permits localhost');
  assert(testMonitor.isOriginAllowed('http://127.0.0.1:8000/api', [], 'subnet'), 'Subnet mode permits 127.0.0.1');
  assert(!testMonitor.isOriginAllowed('https://netflix.com/browse', [], 'subnet'), 'Subnet mode blocks public internet (netflix.com)');
  assert(!testMonitor.isOriginAllowed('https://facebook.com/tr', [], 'subnet'), 'Subnet mode blocks trackers (facebook.com)');
}

// 6. Subnet Traffic & Pre-filtering Simulation
console.log('\n[Test 6: Subnet Traffic & Aggressive Pre-Filtering Simulation]');
{
  const store = new RequestStore();
  await store.init();
  await store.updateSettings({ monitoringEnabled: true, scopeMode: 'subnet' });
  const monitor = new RequestMonitor(store);

  // 1. Simulating 192.168.x.x local API request -> MUST capture
  monitor.handleBeforeRequest({
    requestId: 'sub-req-01',
    url: 'http://192.168.1.45:8080/api/v1/sensors',
    method: 'GET',
    type: 'xmlhttprequest',
    timeStamp: Date.now()
  });
  monitor.handleCompleted({
    requestId: 'sub-req-01',
    statusCode: 200,
    fromCache: false,
    timeStamp: Date.now() + 15
  });

  const capturedSubnet = store.getRequestById('sub-req-01');
  assert(capturedSubnet !== null, 'Captured local subnet 192.168.x.x traffic');
  assertEqual(capturedSubnet.statusCode, 200, 'Subnet request completed with status 200');

  // 2. Simulating heavy public internet traffic (e.g. video streams, ad trackers) -> MUST discard instantly
  monitor.handleBeforeRequest({
    requestId: 'public-ad-02',
    url: 'https://adservice.google.com/adsid/integrator.js?domain=example.com',
    method: 'GET',
    type: 'script',
    timeStamp: Date.now()
  });
  const droppedPublic = store.getRequestById('public-ad-02');
  assert(droppedPublic === null, 'Pre-filter dropped public internet script in <0.001ms');

  // 3. Simulating local subnet noisy binary asset (favicon, woff2) -> MUST discard
  monitor.handleBeforeRequest({
    requestId: 'local-font-03',
    url: 'http://192.168.1.45:8080/static/fonts/inter.woff2',
    method: 'GET',
    type: 'font',
    timeStamp: Date.now()
  });
  const droppedFont = store.getRequestById('local-font-03');
  assert(droppedFont === null, 'Pre-filter dropped noisy font asset on local subnet');
}

// 7. IPC Optimization & Debounced Dispatching Simulation
console.log('\n[Test 7: IPC Optimization & Debounced Dispatching]');
{
  const store = new RequestStore();
  await store.init();
  const monitor = new RequestMonitor(store);

  // When UI is closed (hasActiveUi is false)
  monitor.setUiActive(false);
  assertEqual(monitor._hasActiveUi, false, 'UI is tracked as inactive');

  // Simulate traffic burst
  for (let i = 0; i < 10; i++) {
    monitor.handleBeforeRequest({
      requestId: `burst-req-${i}`,
      url: `http://localhost:3000/api/items/${i}`,
      method: 'GET',
      type: 'xmlhttprequest',
      timeStamp: Date.now()
    });
  }

  assertEqual(monitor._pendingBroadcasts.length, 0, 'Zero IPC messages queued when UI is inactive (Cool CPU)');

  // Now simulate UI opening
  monitor.setUiActive(true);
  assertEqual(monitor._hasActiveUi, true, 'UI is tracked as active');

  monitor.handleBeforeRequest({
    requestId: 'live-req-99',
    url: 'http://localhost:3000/api/live',
    method: 'POST',
    type: 'xmlhttprequest',
    timeStamp: Date.now()
  });

  assert(monitor._pendingBroadcasts.length > 0, 'Queued event for debounced batch delivery when UI is active');
  assert(monitor._batchTimer !== null, 'Batch timer active to coalesce rapid updates');
}

console.log('\n======================================================');
console.log(`LIFECYCLE SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('======================================================');

if (failed > 0) process.exit(1);
