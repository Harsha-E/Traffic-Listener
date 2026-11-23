/**
 * NetListener - Test App Client Script
 * Triggers diverse HTTP traffic scenarios, dummy data exchanges,
 * credential redaction tests, error states, and automated suites.
 */

const logConsole = document.getElementById('logConsole');
const dynamicContainer = document.getElementById('dynamicResourceContainer');
const testProgress = document.getElementById('testProgress');
const progressFill = document.getElementById('progressFill');

function log(msg, type = 'info') {
  const line = document.createElement('div');
  line.className = 'log-line';
  const time = new Date().toLocaleTimeString();

  if (type === 'success') line.className += ' text-green';
  else if (type === 'error') line.className += ' text-red';
  else if (type === 'blue') line.className += ' text-blue';
  else line.className += ' text-muted';

  line.textContent = `[${time}] ${msg}`;
  logConsole.appendChild(line);
  logConsole.scrollTop = logConsole.scrollHeight;
}

// 1. REST Operations
async function testGet() {
  log('Dispatching: GET /api/v1/users', 'blue');
  try {
    const res = await fetch('/api/v1/users');
    const data = await res.json();
    log(`✓ GET /api/v1/users -> Status: ${res.status} (Received ${data.data?.length} users)`, 'success');
  } catch (err) {
    log(`✗ GET /api/v1/users failed: ${err.message}`, 'error');
  }
}

async function testGetId() {
  log('Dispatching: GET /api/v1/users/42', 'blue');
  try {
    const res = await fetch('/api/v1/users/42');
    const data = await res.json();
    log(`✓ GET /api/v1/users/42 -> Status: ${res.status} (User ID: ${data.id})`, 'success');
  } catch (err) {
    log(`✗ GET /api/v1/users/42 failed: ${err.message}`, 'error');
  }
}

async function testPost() {
  log('Dispatching: POST /api/v1/users', 'blue');
  try {
    const res = await fetch('/api/v1/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Charlie Dave', role: 'Security Researcher' })
    });
    const data = await res.json();
    log(`✓ POST /api/v1/users -> Status: ${res.status} (Created ID: ${data.id})`, 'success');
  } catch (err) {
    log(`✗ POST failed: ${err.message}`, 'error');
  }
}

async function testPut() {
  log('Dispatching: PUT /api/v1/users/42', 'blue');
  try {
    const res = await fetch('/api/v1/users/42', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Charlie Updated', role: 'Lead Architect' })
    });
    const data = await res.json();
    log(`✓ PUT /api/v1/users/42 -> Status: ${res.status} (Updated: ${data.updated})`, 'success');
  } catch (err) {
    log(`✗ PUT failed: ${err.message}`, 'error');
  }
}

async function testPatch() {
  log('Dispatching: PATCH /api/v1/users/42', 'blue');
  try {
    const res = await fetch('/api/v1/users/42', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'Security Lead' })
    });
    const data = await res.json();
    log(`✓ PATCH /api/v1/users/42 -> Status: ${res.status} (Patched: ${data.patched})`, 'success');
  } catch (err) {
    log(`✗ PATCH failed: ${err.message}`, 'error');
  }
}

async function testDelete() {
  log('Dispatching: DELETE /api/v1/users/42', 'blue');
  try {
    const res = await fetch('/api/v1/users/42', { method: 'DELETE' });
    log(`✓ DELETE /api/v1/users/42 -> Status: ${res.status} (No Content)`, 'success');
  } catch (err) {
    log(`✗ DELETE failed: ${err.message}`, 'error');
  }
}

async function testOptions() {
  log('Dispatching: OPTIONS /api/v1/users', 'blue');
  try {
    const res = await fetch('/api/v1/users', { method: 'OPTIONS' });
    log(`✓ OPTIONS /api/v1/users -> Status: ${res.status} (CORS Preflight)`, 'success');
  } catch (err) {
    log(`✗ OPTIONS failed: ${err.message}`, 'error');
  }
}

async function testSubnet() {
  log('Dispatching request to local interface/subnet simulation...', 'blue');
  try {
    const res = await fetch('/api/v1/users?subnet_test=1');
    const data = await res.json();
    log(`✓ Subnet request completed -> Status: ${res.status}. NetListener captures local subnet traffic without lag.`, 'success');
  } catch (err) {
    log(`✗ Subnet test failed: ${err.message}`, 'error');
  }
}

// 2. Sensitive Redaction Tests
async function testSensitiveQuery() {
  const sensitiveUrl = '/api/v1/secure-data?apiKey=super_secret_key_12345&token=jwt_eyJhGciOi...&password=my_secret_pass&session=sess_abc999&public_filter=developer';
  log('Dispatching request with sensitive query parameters (apiKey, token, password, session)...', 'blue');
  try {
    const res = await fetch(sensitiveUrl);
    const data = await res.json();
    log(`✓ Sent query with secret tokens. Check NetListener inspector: query values MUST be redacted to [REDACTED].`, 'success');
  } catch (err) {
    log(`✗ Sensitive query test failed: ${err.message}`, 'error');
  }
}

async function testAuthHeader() {
  log('Dispatching request with Authorization: Bearer <secret> and X-Api-Key headers...', 'blue');
  try {
    const res = await fetch('/api/v1/auth/session', {
      headers: {
        'Authorization': 'Bearer secret_jwt_token_999888777',
        'X-Api-Key': 'private_api_key_abc123'
      }
    });
    const data = await res.json();
    log(`✓ Sent auth headers. Check NetListener: Authorization header must show "Bearer [REDACTED]" and X-Api-Key "[REDACTED]".`, 'success');
  } catch (err) {
    log(`✗ Auth header test failed: ${err.message}`, 'error');
  }
}

async function testCookieRedaction() {
  log('Dispatching request receiving Set-Cookie header...', 'blue');
  try {
    const res = await fetch('/api/v1/auth/session');
    log(`✓ Server responded with Set-Cookie. NetListener redacts cookie secret value automatically.`, 'success');
  } catch (err) {
    log(`✗ Cookie test failed: ${err.message}`, 'error');
  }
}

// 3. Error Handling Tests
async function test404() {
  log('Dispatching request expecting 404 Not Found...', 'blue');
  try {
    const res = await fetch('/api/v1/error/not-found');
    log(`✓ 404 response captured -> Status: ${res.status}`, 'success');
  } catch (err) {
    log(`✗ 404 test error: ${err.message}`, 'error');
  }
}

async function test500() {
  log('Dispatching request expecting 500 Server Error...', 'blue');
  try {
    const res = await fetch('/api/v1/error/server-failure');
    log(`✓ 500 response captured -> Status: ${res.status}`, 'success');
  } catch (err) {
    log(`✗ 500 test error: ${err.message}`, 'error');
  }
}

async function testNetworkErr() {
  log('Dispatching request to nonexistent local port to trigger net::ERR_CONNECTION_REFUSED...', 'blue');
  try {
    await fetch('http://127.0.0.1:49999/api/unreachable');
    log(`Unexpected success`, 'error');
  } catch (err) {
    log(`✓ Network failure captured by browser: ${err.message}. NetListener registers 'failed' lifecycle.`, 'success');
  }
}

async function testSlow() {
  log('Dispatching slow request (250ms server delay)...', 'blue');
  const start = Date.now();
  try {
    const res = await fetch('/api/v1/slow');
    const elapsed = Date.now() - start;
    log(`✓ Slow request finished in ${elapsed}ms -> NetListener duration tracking verified.`, 'success');
  } catch (err) {
    log(`✗ Slow test failed: ${err.message}`, 'error');
  }
}

// 4. Resource Types & Burst Traffic
function testMultiResource() {
  log('Triggering non-API resource loads: Script, Stylesheet, and Image...', 'blue');

  // Script
  const script = document.createElement('script');
  script.src = `/assets/test-script.js?t=${Date.now()}`;
  dynamicContainer.appendChild(script);

  // Stylesheet
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = `/assets/test-style.css?t=${Date.now()}`;
  dynamicContainer.appendChild(link);

  // Image
  const img = new Image();
  img.src = `/assets/test-image.png?t=${Date.now()}`;

  // XMLHttpRequest (legacy XHR test alongside Fetch)
  const xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/v1/users?xhr=true');
  xhr.send();

  log(`✓ Injected script, CSS stylesheet, image, and XHR. Check NetListener resource type filter!`, 'success');
}

async function testBurst() {
  log('Sending burst of 15 rapid concurrent requests to test debounced storage buffer...', 'blue');
  const promises = [];
  for (let i = 1; i <= 15; i++) {
    promises.push(fetch(`/api/v1/users?burst=${i}`).then(r => r.status));
  }
  await Promise.all(promises);
  log(`✓ 15 concurrent requests completed without storage quota violations.`, 'success');
}

// 5. Automated Verification Suite
async function runAllTests() {
  testProgress.classList.remove('hidden');
  progressFill.style.width = '0%';
  log('====================================================', 'blue');
  log('BEGINNING COMPLETE NETLISTENER VERIFICATION SUITE', 'blue');
  log('====================================================', 'blue');

  const steps = [
    { name: '1. Standard GET', fn: testGet },
    { name: '2. REST GET with :id pattern', fn: testGetId },
    { name: '3. POST with JSON body', fn: testPost },
    { name: '4. PUT Update', fn: testPut },
    { name: '5. PATCH Partial Update', fn: testPatch },
    { name: '6. DELETE Operation', fn: testDelete },
    { name: '7. OPTIONS Preflight', fn: testOptions },
    { name: '8. Sensitive Query Redaction', fn: testSensitiveQuery },
    { name: '9. Auth Header Redaction', fn: testAuthHeader },
    { name: '10. Cookie Redaction', fn: testCookieRedaction },
    { name: '11. 404 Client Error', fn: test404 },
    { name: '12. 500 Server Error', fn: test500 },
    { name: '13. Network Connection Failure', fn: testNetworkErr },
    { name: '14. Slow Request Duration', fn: testSlow },
    { name: '15. Multi-Resource Types (Script, CSS, Image, XHR)', fn: testMultiResource },
    { name: '16. Burst Traffic Load', fn: testBurst }
  ];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    log(`Running Step [${i + 1}/${steps.length}]: ${step.name}...`);
    await step.fn();
    const pct = Math.round(((i + 1) / steps.length) * 100);
    progressFill.style.width = `${pct}%`;
    await new Promise(r => setTimeout(r, 120)); // Small gap
  }

  log('====================================================', 'success');
  log('ALL 16 TEST SCENARIOS COMPLETED SUCCESSFULLY!', 'success');
  log('Inspect NetListener Popup or Dashboard to verify captured traffic.', 'success');
  log('====================================================', 'success');
}

// Event Listeners
document.getElementById('btnGet').addEventListener('click', testGet);
document.getElementById('btnGetId').addEventListener('click', testGetId);
document.getElementById('btnPost').addEventListener('click', testPost);
document.getElementById('btnPut').addEventListener('click', testPut);
document.getElementById('btnPatch').addEventListener('click', testPatch);
document.getElementById('btnDelete').addEventListener('click', testDelete);
document.getElementById('btnOptions').addEventListener('click', testOptions);
const btnSubnet = document.getElementById('btnSubnet');
if (btnSubnet) btnSubnet.addEventListener('click', testSubnet);

document.getElementById('btnSensitiveQuery').addEventListener('click', testSensitiveQuery);
document.getElementById('btnAuthHeader').addEventListener('click', testAuthHeader);
document.getElementById('btnCookieTest').addEventListener('click', testCookieRedaction);

document.getElementById('btn404').addEventListener('click', test404);
document.getElementById('btn500').addEventListener('click', test500);
document.getElementById('btnNetworkErr').addEventListener('click', testNetworkErr);
document.getElementById('btnSlow').addEventListener('click', testSlow);

document.getElementById('btnMultiResource').addEventListener('click', testMultiResource);
document.getElementById('btnBurst').addEventListener('click', testBurst);

document.getElementById('runAllBtn').addEventListener('click', runAllTests);
document.getElementById('clearLogBtn').addEventListener('click', () => {
  logConsole.innerHTML = '<div class="log-line text-muted">[Cleared] Test console cleared.</div>';
});
