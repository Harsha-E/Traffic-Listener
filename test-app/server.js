/**
 * NetListener Local Test Server
 * Zero-dependency Node.js HTTP server for testing network traffic monitoring,
 * HTTP methods, resource types, errors, timing, and credential redaction.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

// Dummy 1x1 PNG for image test
const DUMMY_PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
  0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
  0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
  0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
  0x42, 0x60, 0x82
]);

const server = http.createServer((req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost:' + PORT}`);
  const pathname = urlObj.pathname;
  const method = req.method.toUpperCase();

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key, X-Requested-With');

  // Handle OPTIONS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Static Assets for Test Workbench
  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
    return;
  }

  if (pathname === '/style.css') {
    res.writeHead(200, { 'Content-Type': 'text/css' });
    fs.createReadStream(path.join(__dirname, 'style.css')).pipe(res);
    return;
  }

  if (pathname === '/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    fs.createReadStream(path.join(__dirname, 'app.js')).pipe(res);
    return;
  }

  // Dynamic Static Resource Endpoints (for Resource Type tests)
  if (pathname === '/assets/test-image.png') {
    res.writeHead(200, { 'Content-Type': 'image/png' });
    res.end(DUMMY_PNG);
    return;
  }

  if (pathname === '/assets/test-script.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    res.end('console.log("[Test App] External script resource loaded successfully.");');
    return;
  }

  if (pathname === '/assets/test-style.css') {
    res.writeHead(200, { 'Content-Type': 'text/css' });
    res.end('/* External stylesheet resource */ .test-loaded { color: #60a5fa; }');
    return;
  }

  // API Endpoints for Inspection Testing
  if (pathname === '/api/v1/users') {
    if (method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'success',
        data: [
          { id: 1, name: 'Alice Smith', role: 'Security Analyst' },
          { id: 2, name: 'Bob Jones', role: 'Full Stack Engineer' }
        ]
      }));
      return;
    }

    if (method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'created',
          id: 42,
          message: 'User created successfully'
        }));
      });
      return;
    }
  }

  // Single User REST Pattern (/api/v1/users/:id)
  if (pathname.startsWith('/api/v1/users/')) {
    const id = pathname.split('/')[4];

    if (method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id, name: 'Sample User', role: 'Dev' }));
      return;
    }

    if (method === 'PUT') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id, updated: true, timestamp: Date.now() }));
      return;
    }

    if (method === 'PATCH') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id, patched: true }));
      return;
    }

    if (method === 'DELETE') {
      res.writeHead(204);
      res.end();
      return;
    }
  }

  // Sensitive Query Parameters test endpoint
  if (pathname === '/api/v1/secure-data') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      message: 'Sensitive query parameter test response',
      receivedQueryKeys: Array.from(urlObj.searchParams.keys())
    }));
    return;
  }

  // Auth Header & Cookie test endpoint
  if (pathname === '/api/v1/auth/session') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session_token=secret_sess_abc12345; HttpOnly; SameSite=Lax; Path=/',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(JSON.stringify({
      authenticated: true,
      authHeaderReceived: Boolean(req.headers['authorization'])
    }));
    return;
  }

  // Simulated 404 Endpoint
  if (pathname === '/api/v1/error/not-found') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Resource not found', code: 404 }));
    return;
  }

  // Simulated 500 Endpoint
  if (pathname === '/api/v1/error/server-failure') {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal Server Crash', code: 500 }));
    return;
  }

  // Simulated Slow Endpoint (for duration test)
  if (pathname === '/api/v1/slow') {
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ delayed: true, durationSimulatedMs: 250 }));
    }, 250);
    return;
  }

  // Catch-all
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Endpoint not defined', pathname }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[NetListener Test Server] Running at http://127.0.0.1:${PORT}, http://localhost:${PORT}, and on your local subnet (192.168.x.x:${PORT})`);
});

module.exports = server;
