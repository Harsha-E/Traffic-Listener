/**
 * NetListener - Endpoint Parser & Intelligence Module
 * Analyzes request URLs, abstracts route patterns, groups endpoints,
 * and extracts architectural insights for cybersecurity and developer education.
 */

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MONGO_ID_REGEX = /^[0-9a-f]{24}$/i;
const NUMERIC_ID_REGEX = /^\d+$/;
const HEX_HASH_REGEX = /^[0-9a-f]{32,64}$/i;

/**
 * Normalizes a URL path into an abstracted route pattern.
 * e.g., /api/v1/users/42 -> /api/v1/users/:id
 *       /posts/550e8400-e29b-41d4-a716-446655440000 -> /posts/:uuid
 * 
 * @param {string} pathname
 * @returns {string}
 */
export function abstractRoutePattern(pathname) {
  if (!pathname || pathname === '/') return '/';

  const segments = pathname.split('/').filter(Boolean);
  const abstracted = segments.map((seg, idx) => {
    if (NUMERIC_ID_REGEX.test(seg)) {
      return ':id';
    }
    if (UUID_REGEX.test(seg)) {
      return ':uuid';
    }
    if (MONGO_ID_REGEX.test(seg) || HEX_HASH_REGEX.test(seg)) {
      return ':hash';
    }
    return seg;
  });

  return '/' + abstracted.join('/');
}

/**
 * Checks whether an endpoint appears to be an API endpoint.
 * Note: Educational heuristic only; distinguishes typical API paths from static assets.
 * 
 * @param {string} pathname
 * @param {string} resourceType
 * @returns {boolean}
 */
export function isLikelyApiRoute(pathname, resourceType = '') {
  const lowerPath = (pathname || '').toLowerCase();
  const lowerType = (resourceType || '').toLowerCase();

  if (lowerType === 'xmlhttprequest' || lowerType === 'fetch') {
    return true;
  }

  // Common API indicators in URL path
  const apiKeywords = ['/api/', '/api', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/rpc/', '/auth/', '/oauth/', '/webhooks/'];
  return apiKeywords.some(keyword => lowerPath.includes(keyword));
}

/**
 * Parses a request URL into structured components.
 * 
 * @param {string} url
 * @param {string} resourceType
 * @returns {object}
 */
export function parseEndpoint(url, resourceType = '') {
  try {
    const urlObj = new URL(url);
    const origin = urlObj.origin;
    const pathname = urlObj.pathname;
    const routePattern = abstractRoutePattern(pathname);
    const isApi = isLikelyApiRoute(pathname, resourceType);

    // Extract query parameters
    const queryParams = [];
    urlObj.searchParams.forEach((value, key) => {
      queryParams.push({ key, value });
    });

    return {
      isValid: true,
      origin,
      host: urlObj.host,
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
      protocol: urlObj.protocol,
      pathname,
      routePattern,
      search: urlObj.search,
      queryParams,
      isApiRoute: isApi
    };
  } catch (err) {
    return {
      isValid: false,
      origin: 'Unknown',
      host: 'Unknown',
      hostname: 'Unknown',
      port: '',
      protocol: '',
      pathname: url,
      routePattern: url,
      search: '',
      queryParams: [],
      isApiRoute: isLikelyApiRoute(url, resourceType)
    };
  }
}

/**
 * Computes endpoint intelligence and aggregates metrics across a collection of captured requests.
 * 
 * @param {Array<object>} requests
 * @returns {object}
 */
export function computeEndpointIntelligence(requests) {
  if (!Array.isArray(requests) || requests.length === 0) {
    return {
      totalRequests: 0,
      uniqueEndpointsCount: 0,
      uniqueOriginsCount: 0,
      failureCount: 0,
      failureRate: 0,
      methodDistribution: {},
      statusDistribution: {},
      typeDistribution: {},
      groupedEndpoints: [],
      frequentEndpoints: [],
      failedEndpoints: [],
      interestingApiRoutes: [],
      origins: []
    };
  }

  const endpointMap = new Map();
  const methodDist = {};
  const statusDist = {};
  const typeDist = {};
  const originSet = new Set();
  let totalFailures = 0;

  for (const req of requests) {
    // Tally Method
    const method = req.method ? req.method.toUpperCase() : 'UNKNOWN';
    methodDist[method] = (methodDist[method] || 0) + 1;

    // Tally Type
    const type = req.type || 'other';
    typeDist[type] = (typeDist[type] || 0) + 1;

    // Tally Status
    const status = req.statusCode || (req.lifecycle === 'failed' ? 'Failed' : 'Pending');
    statusDist[status] = (statusDist[status] || 0) + 1;

    const isFailure = req.lifecycle === 'failed' || (typeof req.statusCode === 'number' && req.statusCode >= 400);
    if (isFailure) {
      totalFailures++;
    }

    // Grouping Key: origin + routePattern
    const origin = req.origin || (req.url ? parseEndpoint(req.url, req.type).origin : 'Unknown');
    originSet.add(origin);

    const routePattern = req.routePattern || (req.url ? parseEndpoint(req.url, req.type).routePattern : '/');
    const groupKey = `${origin}::${routePattern}`;

    if (!endpointMap.has(groupKey)) {
      endpointMap.set(groupKey, {
        groupKey,
        origin,
        routePattern,
        pathname: req.pathname || routePattern,
        sampleUrl: req.url,
        totalCalls: 0,
        methods: {},
        statusCodes: {},
        failureCount: 0,
        durations: [],
        lastSeen: req.timestamp || Date.now(),
        isApiRoute: isLikelyApiRoute(routePattern, req.type),
        resourceTypes: new Set()
      });
    }

    const group = endpointMap.get(groupKey);
    group.totalCalls++;
    group.methods[method] = (group.methods[method] || 0) + 1;
    group.statusCodes[status] = (group.statusCodes[status] || 0) + 1;
    if (isFailure) {
      group.failureCount++;
    }
    if (typeof req.duration === 'number' && req.duration >= 0) {
      group.durations.push(req.duration);
    }
    if (req.timestamp && req.timestamp > group.lastSeen) {
      group.lastSeen = req.timestamp;
    }
    if (req.type) {
      group.resourceTypes.add(req.type);
    }
  }

  // Format grouped endpoints with computed stats
  const groupedList = Array.from(endpointMap.values()).map(group => {
    const avgDuration = group.durations.length > 0
      ? Math.round(group.durations.reduce((a, b) => a + b, 0) / group.durations.length)
      : null;

    return {
      groupKey: group.groupKey,
      origin: group.origin,
      routePattern: group.routePattern,
      pathname: group.pathname,
      sampleUrl: group.sampleUrl,
      totalCalls: group.totalCalls,
      methods: group.methods,
      statusCodes: group.statusCodes,
      hasFailures: group.failureCount > 0,
      failureCount: group.failureCount,
      avgDuration,
      isApiRoute: group.isApiRoute,
      resourceTypes: Array.from(group.resourceTypes),
      lastSeen: group.lastSeen
    };
  });

  // Sort by most frequent calls
  const frequentEndpoints = [...groupedList].sort((a, b) => b.totalCalls - a.totalCalls);

  // Filter endpoints with failures
  const failedEndpoints = groupedList
    .filter(g => g.hasFailures)
    .sort((a, b) => b.failureCount - a.failureCount);

  // Interesting API routes (unique route patterns matching API indicators)
  const interestingApiRoutes = groupedList
    .filter(g => g.isApiRoute)
    .sort((a, b) => b.totalCalls - a.totalCalls);

  const failureRate = requests.length > 0
    ? Math.round((totalFailures / requests.length) * 100)
    : 0;

  return {
    totalRequests: requests.length,
    uniqueEndpointsCount: groupedList.length,
    uniqueOriginsCount: originSet.size,
    failureCount: totalFailures,
    failureRate,
    methodDistribution: methodDist,
    statusDistribution: statusDist,
    typeDistribution: typeDist,
    groupedEndpoints: frequentEndpoints,
    frequentEndpoints: frequentEndpoints.slice(0, 5),
    failedEndpoints,
    interestingApiRoutes,
    origins: Array.from(originSet)
  };
}
