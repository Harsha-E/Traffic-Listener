/**
 * NetListener - Subnet & High-Performance Pre-Filtering Module
 * Aggressively discards irrelevant public traffic and noisy non-essential assets
 * in <0.001ms to eliminate CPU load and prevent Chrome lag.
 */

// Local subnet IPv4 regex ranges:
// - 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)
// - 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
// - 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
// - 127.0.0.0 - 127.255.255.255 (Loopback)
// - 169.254.0.0 - 169.254.255.255 (Link-local)
const SUBNET_REGEX = /^(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})$/;

// Local hostnames & domain suffixes (mDNS, internal development)
const LOCAL_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '[::1]',
  '::1'
]);

const LOCAL_DOMAIN_SUFFIXES = [
  '.local',
  '.lan',
  '.internal',
  '.test',
  '.home.arpa',
  '.localhost'
];

// Noisy resource types to discard instantly before any memory allocation or regex parsing
const NOISY_RESOURCE_TYPES = new Set([
  'font',
  'media',
  'ping',
  'beacon',
  'csp_report',
  'other_ignored'
]);

// File extensions for binary noise (icons, web fonts, video/audio chunks)
const NOISY_EXTENSIONS_REGEX = /\.(woff2?|ttf|eot|otf|mp4|webm|mp3|ogg|wav|ico|avi|flv)(\?.*)?$/i;

/**
 * Validates whether a hostname belongs to a local subnet or loopback interface.
 * Fast string and prefix checking for maximum throughput.
 * 
 * @param {string} hostname
 * @returns {boolean}
 */
export function isLocalSubnet(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;

  const host = hostname.toLowerCase().trim();

  // 1. Direct match for loopback & known local names
  if (LOCAL_HOSTNAMES.has(host)) {
    return true;
  }

  // 2. Fast prefix match for 192.168.x.x & 10.x.x.x
  if (host.startsWith('192.168.') || host.startsWith('10.')) {
    return SUBNET_REGEX.test(host);
  }

  // 3. Fast prefix match for 172.16-31.x.x
  if (host.startsWith('172.')) {
    return SUBNET_REGEX.test(host);
  }

  // 4. Local domain suffixes (.local, .lan, .internal, etc.)
  for (let i = 0; i < LOCAL_DOMAIN_SUFFIXES.length; i++) {
    if (host.endsWith(LOCAL_DOMAIN_SUFFIXES[i])) {
      return true;
    }
  }

  // 5. Full regex fallback for any other subnet range
  return SUBNET_REGEX.test(host);
}

/**
 * Checks if a request represents noisy non-actionable background traffic
 * such as fonts, media streams, browser beacons, or favicons.
 * 
 * @param {string} type - Chrome webRequest resource type
 * @param {string} url - Request URL
 * @returns {boolean}
 */
export function isNoisyResource(type, url) {
  if (type && NOISY_RESOURCE_TYPES.has(type.toLowerCase())) {
    return true;
  }

  if (url && typeof url === 'string') {
    // Fast check for favicons and font/media extensions
    if (NOISY_EXTENSIONS_REGEX.test(url)) {
      return true;
    }
  }

  return false;
}

/**
 * Aggressive pre-filter: determines whether a request should be captured.
 * Evaluates in sub-millisecond time.
 * 
 * @param {object} details - Chrome webRequest details object
 * @param {object} settings - NetListener settings
 * @returns {boolean}
 */
export function shouldCaptureRequest(details, settings = {}) {
  if (!details || !details.url) return false;
  if (!settings.monitoringEnabled) return false;

  const url = details.url;

  // 1. Filter out browser protocols (chrome://, chrome-extension://, edge://, about:)
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }

  // 2. Drop noisy resource types immediately
  if (isNoisyResource(details.type, url)) {
    return false;
  }

  let hostname = '';
  try {
    // Fast hostname extraction without full URL parsing when possible
    const slashIdx = url.indexOf('//');
    if (slashIdx !== -1) {
      const rest = url.substring(slashIdx + 2);
      const endIdx = rest.indexOf('/');
      const colonIdx = rest.indexOf(':');
      let hostPart = endIdx !== -1 ? rest.substring(0, endIdx) : rest;
      if (colonIdx !== -1 && (endIdx === -1 || colonIdx < endIdx)) {
        hostPart = hostPart.substring(0, colonIdx);
      }
      hostname = hostPart;
    } else {
      hostname = new URL(url).hostname;
    }
  } catch {
    return false;
  }

  const scopeMode = settings.scopeMode || 'subnet';

  // 3. Subnet filtering mode (default & high-performance)
  if (scopeMode === 'subnet') {
    return isLocalSubnet(hostname);
  }

  // 4. Strict loopback-only mode
  if (scopeMode === 'local') {
    return LOCAL_HOSTNAMES.has(hostname.toLowerCase());
  }

  // 5. 'all' mode: check custom allowed origins if defined, otherwise allow
  if (scopeMode === 'all') {
    if (settings.allowedOrigins && settings.allowedOrigins.length > 0) {
      // If user specified custom patterns, check them
      for (const pattern of settings.allowedOrigins) {
        if (!pattern) continue;
        if (pattern === '<all_urls>' || pattern === '*://*/*') return true;
        if (pattern.includes('*')) {
          const regexStr = '^' + pattern
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*') + '$';
          if (new RegExp(regexStr, 'i').test(url)) return true;
        } else if (url.startsWith(pattern)) {
          return true;
        }
      }
      return false;
    }
    return true;
  }

  return false;
}
