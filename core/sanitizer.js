/**
 * NetListener - Core Sanitizer Module
 * Ensures privacy and security by strictly redacting sensitive tokens,
 * passwords, API keys, session cookies, and credentials from captured URLs,
 * headers, and exports.
 */

// Known sensitive query parameter keys (lowercased)
const SENSITIVE_QUERY_KEYS = new Set([
  'token',
  'auth',
  'access_token',
  'id_token',
  'refresh_token',
  'auth_token',
  'authtoken',
  'api_key',
  'apikey',
  'key',
  'secret',
  'client_secret',
  'password',
  'pass',
  'passwd',
  'pwd',
  'session',
  'session_id',
  'sessionid',
  'sess',
  'jwt',
  'code',
  'sig',
  'signature',
  'bearer',
  'credential',
  'private_key',
  'oauth_token',
  'csrf_token',
  'xsrf_token',
  'verification_code',
  'otp',
  'pin'
]);

// Sensitive header names (lowercased)
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'api-key',
  'apikey',
  'session-token',
  'private-token',
  'x-csrf-token',
  'x-xsrf-token'
]);

// Low-value browser internal headers that bloat memory without providing security or API value
const LOW_VALUE_HEADERS = new Set([
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-ch-ua-platform-version',
  'sec-ch-prefers-color-scheme',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-fetch-user',
  'priority'
]);

/**
 * Checks if a query parameter key is sensitive
 * @param {string} key
 * @returns {boolean}
 */
export function isSensitiveKey(key) {
  if (!key) return false;
  const lower = key.toLowerCase().trim();
  if (SENSITIVE_QUERY_KEYS.has(lower)) return true;
  return /(_key|_token|_secret|_password|api_key|access_token|auth_token|session)/i.test(lower);
}

/**
 * Sanitizes a URL by redacting sensitive query parameters.
 * Returns both the sanitized URL and a list of redactions performed.
 * 
 * @param {string} rawUrl
 * @returns {{ sanitizedUrl: string, redactionCount: number, redactedKeys: string[] }}
 */
export function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { sanitizedUrl: '', redactionCount: 0, redactedKeys: [] };
  }

  try {
    const urlObj = new URL(rawUrl);
    const redactedKeys = [];

    // Check query parameters
    const params = new URLSearchParams(urlObj.search);
    let modified = false;

    for (const [key, val] of params.entries()) {
      if (isSensitiveKey(key)) {
        redactedKeys.push(key);
        params.set(key, '[REDACTED]');
        modified = true;
      }
    }

    if (modified) {
      urlObj.search = params.toString();
    }

    // Also sanitize userinfo if present in URL (e.g. http://user:pass@localhost)
    if (urlObj.username || urlObj.password) {
      urlObj.username = '[REDACTED]';
      urlObj.password = '[REDACTED]';
      redactedKeys.push('userinfo');
    }

    return {
      sanitizedUrl: urlObj.toString(),
      redactionCount: redactedKeys.length,
      redactedKeys
    };
  } catch (err) {
    // If URL parsing fails, perform regex-based fallback redaction
    const redactedKeys = [];
    const sanitizedUrl = rawUrl.replace(/([?&])([^=&#]+)=([^&#]*)/g, (match, prefix, key, val) => {
      if (isSensitiveKey(key)) {
        redactedKeys.push(key);
        return `${prefix}${key}=[REDACTED]`;
      }
      return match;
    });

    return {
      sanitizedUrl,
      redactionCount: redactedKeys.length,
      redactedKeys
    };
  }
}

/**
 * Sanitizes an array of HTTP headers (as received from Chrome webRequest).
 * 
 * @param {Array<{ name: string, value?: string, binaryValue?: any }>} headers
 * @returns {Array<{ name: string, value: string, redacted: boolean, originalLength?: number }>}
 */
export function sanitizeHeaders(headers, stripLowValue = true) {
  if (!Array.isArray(headers)) return [];

  const result = [];
  for (let i = 0; i < headers.length; i++) {
    const header = headers[i];
    if (!header) continue;

    const name = header.name || '';
    const rawValue = header.value || '';
    const lowerName = name.toLowerCase().trim();

    // Strip noisy browser internal headers if requested to preserve memory & bandwidth
    if (stripLowValue && LOW_VALUE_HEADERS.has(lowerName)) {
      continue;
    }

    // Redact Authorization headers while preserving scheme info (e.g., Bearer, Basic)
    if (lowerName === 'authorization' || lowerName === 'proxy-authorization') {
      const parts = rawValue.trim().split(/\s+/);
      const scheme = parts.length > 1 ? parts[0] : '';
      const sanitizedVal = scheme ? `${scheme} [REDACTED]` : '[REDACTED]';
      result.push({
        name,
        value: sanitizedVal,
        redacted: true,
        originalLength: rawValue.length
      });
      continue;
    }

    // Redact Cookie headers: show cookie names for educational inspection, but redact values
    if (lowerName === 'cookie') {
      const sanitizedCookies = rawValue.split(';').map(cookiePair => {
        const eqIdx = cookiePair.indexOf('=');
        if (eqIdx === -1) return cookiePair.trim();
        const cookieName = cookiePair.substring(0, eqIdx).trim();
        return `${cookieName}=[REDACTED]`;
      }).join('; ');

      result.push({
        name,
        value: sanitizedCookies || '[REDACTED]',
        redacted: true,
        originalLength: rawValue.length
      });
      continue;
    }

    // Redact Set-Cookie headers from responses
    if (lowerName === 'set-cookie') {
      const semiIdx = rawValue.indexOf(';');
      const firstPart = semiIdx !== -1 ? rawValue.substring(0, semiIdx) : rawValue;
      const eqIdx = firstPart.indexOf('=');
      const cookieName = eqIdx !== -1 ? firstPart.substring(0, eqIdx).trim() : 'cookie';
      const attributes = semiIdx !== -1 ? rawValue.substring(semiIdx) : '';
      result.push({
        name,
        value: `${cookieName}=[REDACTED]${attributes}`,
        redacted: true,
        originalLength: rawValue.length
      });
      continue;
    }

    // Redact known token/key headers
    if (SENSITIVE_HEADERS.has(lowerName)) {
      result.push({
        name,
        value: '[REDACTED]',
        redacted: true,
        originalLength: rawValue.length
      });
      continue;
    }

    result.push({
      name,
      value: rawValue,
      redacted: false
    });
  }

  return result;
}

/**
 * Escapes HTML characters to prevent XSS in rendering
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
