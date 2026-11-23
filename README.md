# NetListener — Browser Network Intelligence & Traffic Inspector

**NetListener** is a privacy-first, educational Chrome Manifest V3 extension designed for web developers, cybersecurity learners, and application security researchers. Inspired by Burp Suite's HTTP history and the browser DevTools Network panel, NetListener helps users inspect and understand how modern web applications communicate with their backend services.

---

## 1. Primary Learning Objectives

- **Endpoint Discovery & Surface Mapping:** Understand how client applications discover and interact with backend APIs.
- **HTTP Request Structuring:** Examine methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`), headers, status codes, query strings, and timing metrics.
- **Route Parameter Abstraction:** See how dynamic REST paths (e.g., `/api/users/42`, `/sessions/550e8400...`) map into abstracted resource schemas (`/api/users/:id`, `/sessions/:uuid`).
- **Security & Privacy Analysis:** Observe how authentication schemes (Bearer tokens, API keys, cookies) work while learning how security tools safeguard credentials through automated redaction.
- **Manifest V3 Architecture:** Learn the capabilities and security boundaries of Chrome's modern extension platform.

---

## 2. Security & Privacy Model

NetListener is strictly an **educational developer tool**, not a surveillance or interception extension:

1. **Default Monitoring Scope:** Strictly limited to `localhost` and `127.0.0.1`. Unrelated public websites and external domains are never captured.
2. **Zero External Data Transmission:** Captured requests are processed entirely within the browser and stored locally in `chrome.storage.local`. Zero tracking, zero telemetry, zero outbound analytics.
3. **Automated Credential Redaction:**
   - **Query Parameters:** Any parameter named `token`, `auth`, `access_token`, `apiKey`, `key`, `secret`, `password`, `session`, `jwt`, `sig`, or matching `_key`/`_token` regex has its value replaced with `[REDACTED]`.
   - **Authorization Headers:** Header values are masked (e.g., `Bearer [REDACTED]`) preserving the scheme for educational study while redacting the secret token.
   - **Cookie & Set-Cookie:** Individual cookie values are sanitized (e.g., `session_id=[REDACTED]`) while preserving cookie names for structural inspection.
   - **API Key Headers:** Headers like `X-Api-Key`, `X-Auth-Token`, and `Session-Token` are replaced with `[REDACTED]`.
4. **Explicit Monitoring Toggle:** A prominent toggle allows users to pause and resume monitoring at any moment.
5. **Clear History:** A single click instantly clears stored requests from memory and disk.
6. **Sanitized Export:** JSON and CSV export formats enforce complete redaction before export.

---

## 3. Architecture & File Structure

NetListener is built using modern vanilla JavaScript (ES modules), HTML5, and CSS3 without bulky frameworks or external dependencies:

```
NetListener/
├── manifest.json              # Chrome Manifest V3 manifest
├── background/
│   └── service-worker.js      # Background service worker (passive webRequest, port tracking, badge sync)
├── core/
│   ├── subnet-filter.js       # High-performance subnet pre-filter (192.168.x.x, 10.x, 172.16-31.x, asset drop)
│   ├── compression.js         # Real-time deflate stream compression (80-95% memory & storage reduction)
│   ├── sanitizer.js           # Query parameter, header, and URL redaction engine & noise stripper
│   ├── endpoint-parser.js     # Route abstraction (:id, :uuid), endpoint grouping & intelligence
│   ├── filters.js             # Multi-axis filtering (method, status, type, origin, search)
│   ├── request-store.js       # FIFO rolling buffer & compressed chrome.storage.local persistence
│   ├── firebase-reporter.js   # Structured report serializer & Firebase transmitter
│   └── export.js              # RFC 4180 CSV and formatted JSON export generators
├── popup/
│   ├── popup.html             # Compact extension popup UI with "Send log" button
│   ├── popup.css              # Modern white theme styling, crisp borders, and badges
│   └── popup.js               # Popup event dispatcher and Firebase sender
├── dashboard/
│   ├── dashboard.html         # Full-page high-density traffic dashboard & endpoint intelligence
│   ├── dashboard.css          # Modern white theme, split-pane layout, monospaced typography
│   └── dashboard.js           # Multi-view navigation, auto-scroll, and deep inspector
├── devtools/
│   ├── devtools.html          # DevTools page entry point
│   ├── devtools.js            # Registers the "NetListener" panel in Chrome DevTools
│   ├── panel.html             # In-DevTools network panel
│   ├── panel.css              # DevTools-matching dark theme styling
│   └── panel.js               # HAR inspection with legitimate response body viewing
├── icons/
│   ├── icon-16.png            # 16x16 icon
│   ├── icon-48.png            # 48x48 icon
│   └── icon-128.png           # 128x128 icon
├── test-app/
│   ├── server.js              # Zero-dependency local Node.js test server
│   ├── index.html             # Interactive testing workbench & automated test runner
│   ├── style.css              # Test workbench styles
│   └── app.js                 # HTTP request triggers (REST, errors, bursts, redactions)
├── tests/
│   ├── unit-tests.js          # Automated unit test suite (55 tests)
│   ├── simulation-tests.js    # Lifecycle, SW restart, and FIFO buffer tests (26 tests)
│   └── e2e-workflow-test.js   # Real network server end-to-end integration test (33 tests)
├── CHROMEWEBSTORE.md          # Chrome Web Store listing & permissions justification
└── README.md                  # Comprehensive technical documentation
```

---

## 4. Key Technical Decisions & MV3 Capabilities

### Passive `chrome.webRequest` vs. Active Interception
In Chrome Manifest V3, `webRequest` is strictly passive. This is ideal for NetListener because passive observation introduces zero network latency, does not block page execution threads, and operates without dangerous enterprise-only blocking permissions.

### High-Performance Subnet Pre-Filtering, Real-Time Deflate Compression & Lag Elimination
To eliminate browser lag and keep CPU usage close to 0% during intensive web browsing:
1. **Aggressive Subnet Pre-Filtering (`core/subnet-filter.js`):** In `<0.001ms`, the extension validates whether incoming requests originate from local development subnets (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, `localhost`, `127.0.0.1`, `.local`, `.lan`). Unrelated public internet traffic (e.g. streaming chunks, ad trackers) and noisy binary assets (`font`, `media`, `ping`, `beacon`, `favicon.ico`) are discarded instantly before any regex execution or memory allocation.
2. **Lean Schema & Header Stripping:** Noisy internal browser headers (`sec-ch-ua*`, `sec-fetch-*`, `priority`) and duplicate keys (`rawUrlPreview`) are stripped, cutting in-memory request record size by over 70%.
3. **Real-Time Deflate Stream Compression (`core/compression.js`):** Uses the standard Web API `CompressionStream('deflate')` to achieve a **95.5% byte reduction** before persisting to `chrome.storage.local`. 35 KB of request data is compressed to ~1.5 KB!
4. **Zero-IPC Idle State & Event Debouncing:** The service worker tracks active UI connections (`netlistener-ui` port). When the popup and dashboard are closed, **zero IPC messages are dispatched**, completely eliminating "Receiving end does not exist" message failures and CPU freezes. When open, updates are batched into 80ms coalesced dispatch intervals.
5. **In-Flight TTL Sweeper:** Stalled requests exceeding a 30-second window are automatically pruned from active memory.

### Handling Ephemeral Service Workers
Manifest V3 service workers terminate after ~30 seconds of inactivity. To prevent data loss:
- All captured request metadata is persisted in `chrome.storage.local`.
- High-frequency traffic bursts are debounced (150ms) to stay well within Chrome's storage write quotas.
- A rolling FIFO buffer (default 500 requests, configurable) automatically evicts the oldest requests to avoid unbounded memory or disk usage.
- Service workers rehydrate from storage immediately on startup or browser wake.

### Response Bodies & Chrome DevTools Architecture
In Manifest V3, passive `webRequest` intentionally does not expose HTTP response bodies to extension service workers. To provide deep response inspection legitimately without using intrusive debugger attachments:
- NetListener includes a native **Chrome DevTools Panel** (`devtools/panel.html`).
- Inside Chrome Developer Tools (`F12`), `chrome.devtools.network.onRequestFinished` and `request.getContent()` have legitimate access to the complete response body!

---

## 5. Installation Instructions

### Step 1: Clone or Open the Repository
Ensure the repository files are located on your local drive:
`d:\Harsha\WebDev\Extensions\TrafficListener`

### Step 2: Load Unpacked Extension in Chrome
1. Open Google Chrome.
2. In the address bar, navigate to: `chrome://extensions/`
3. In the top-right corner, enable the **Developer mode** toggle.
4. Click the **Load unpacked** button in the top-left menu.
5. Select the `TrafficListener` directory:
   `d:\Harsha\WebDev\Extensions\TrafficListener`
6. NetListener will appear in your installed extensions list.
7. Click the extension puzzle icon in the Chrome toolbar and pin **NetListener** for easy access.

---

## 6. How to Run the Local Test Application

NetListener comes with a self-contained local test application:

### Step 1: Start the Local Test Server
In your terminal, navigate to the project directory and run:
```bash
node test-app/server.js
```
The server will start at `http://127.0.0.1:3000` (and `http://localhost:3000`).

### Step 2: Open the Test Workbench
Open Google Chrome and navigate to:
```
http://127.0.0.1:3000
```

### Step 3: Trigger Traffic Scenarios
- Click **"🚀 Run All Automated Tests"** to trigger all 16 test scenarios in sequence (GET, POST, PUT, PATCH, DELETE, OPTIONS, 404, 500, slow responses, script/CSS/image assets, burst traffic, and credential redactions).
- Or click any individual button to test specific endpoints.

### Step 4: Inspect Traffic in NetListener
- Click the **NetListener** toolbar icon to open the compact popup inspector.
- Click the **Full Screen Dashboard** icon or click **"Open in Dashboard Inspector"** to open the full-screen intelligence interface.
- Open Chrome DevTools (`F12` on the test page) and select the **NetListener** tab to inspect response bodies directly.

---

## 7. Running the Automated Test Suites

NetListener includes 185 automated unit, simulation, and integration tests with zero external test runner dependencies:

```bash
# Run Unit Tests (110 tests: Sanitizer, Route Abstraction, Filters, FIFO Store, Exports, Firebase Serializer, Subnet Pre-Filtering, Deflate Compression)
node tests/unit-tests.js

# Run Simulation Tests (42 tests: Service Worker restart, empty store, buffer limits, monitoring toggle, subnet traffic, debounced IPC dispatching)
node tests/simulation-tests.js

# Run End-to-End Workflow Test (33 tests: Boots local server, dispatches live traffic, validates pipeline)
node tests/e2e-workflow-test.js
```

All 185 tests pass with 100% success rate.

---

## 8. Sending Structured Reports to Firebase

NetListener includes a dedicated **"Send log"** feature in both the extension popup and the full-page dashboard:

1. **Click "Send log":** Serializes all currently captured requests and endpoint intelligence into a comprehensive, fully structured report.
2. **Payload Structure:**
   - `reportId`: Unique identifier (e.g., `nl_rpt_1711200000000_abc12`)
   - `generatedAt`: ISO 8601 timestamp
   - `tool`: Extension metadata and version
   - `privacyAudit`: Redaction counts and scope guarantees
   - `summaryMetrics`: Request counts, API calls, error rates, unique origins/routes
   - `trafficDistributions`: Method, status code, and resource type breakdowns
   - `endpointIntelligence`: Abstracted routes, top frequent endpoints, failure maps
   - `capturedRequests`: Array of sanitized requests (all secrets, tokens, and cookies masked)
3. **Destination Flexibility:**
   - **Cloud Firestore REST API:** Preconfigured with project `alt-mvgr` (collection `network_reports`).
   - **Realtime Database:** Supports Firebase RTDB REST endpoints.
   - **Custom Webhook:** Supports sending to custom Firebase Cloud Functions.
4. **Configuration:** Click the gear icon (`⚙️`) next to "Send log" in the popup to configure your Firebase project ID, collection, API key, or custom endpoint.
5. **Zero Data Loss Fallback:** If Firebase permissions block writing (e.g. 403 on unauthenticated collections), NetListener automatically copies the complete structured JSON report to your clipboard!

---

## 8. How to Use NetListener to Study Backend Communication

1. **Mapping Application Attack Surface:**
   - Navigate to the **Endpoint Intelligence** tab.
   - Look at the **Route Pattern** column. NetListener automatically clusters dynamic IDs (`/users/1`, `/users/2`, `/users/3`) into single abstracted routes (`/users/:id`).
   - Identify which HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) are exposed on each route.

2. **Inspecting Authentication & Token Schemes:**
   - Select an authenticated request in the **Traffic Inspector**.
   - Notice how NetListener highlights `Authorization: Bearer [REDACTED]` and `session_id=[REDACTED]`.
   - You can see that a Bearer token or session cookie is being used without exposing the raw secret.

3. **Auditing Security Headers:**
   - In the inspector, click the **Security & Privacy Audit** tab.
   - Inspect observed headers such as `Access-Control-Allow-Origin`, `X-Content-Type-Options`, `Content-Security-Policy`, and `Strict-Transport-Security`.
   - When missing, NetListener flags the absence of security hardening headers for educational evaluation.

4. **Generating Reproducible cURL Commands:**
   - Click **"Copy cURL"** in the inspector header.
   - NetListener copies an exact `curl` command with sanitized headers and endpoint URLs directly to your clipboard for terminal testing.

5. **Auditing and Exporting:**
   - Click **Export** &rarr; **Export Sanitized JSON** or **Export Audit CSV** to archive traffic traces for reporting or vulnerability writeups. All secrets remain strictly redacted.

---

## 9. Known Limitations & Future Architecture

- **Manifest V3 Background Body Access:** Passive `chrome.webRequest` does not provide response bodies to background service workers. NetListener solves this by providing a dedicated Chrome DevTools Panel (`devtools/panel.html`), which leverages the DevTools Protocol (`chrome.devtools.network`) for full response body inspection.
- **Monitoring Scope:** NetListener intentionally only monitors `localhost` and `127.0.0.1` by default to safeguard user privacy. Custom origin patterns can be configured in settings if developing against custom domain names.

---

## 10. License & Ethics

NetListener is developed strictly for educational, defensive, and authorized development inspection purposes. Never use network inspection tools against applications or systems without explicit permission.
