/**
 * NetListener - Request Filtering & Search Module
 * Provides filtering, searching, and sorting capabilities for captured network traffic.
 */

/**
 * Checks whether a request matches the specified status filter.
 * 
 * @param {object} req
 * @param {string} statusFilter
 * @returns {boolean}
 */
function matchesStatus(req, statusFilter) {
  if (!statusFilter || statusFilter === 'ALL') return true;

  const code = req.statusCode;
  const isFailed = req.lifecycle === 'failed' || (typeof code === 'number' && code >= 400);

  if (statusFilter === 'failed') {
    return isFailed;
  }
  if (statusFilter === 'pending') {
    return req.lifecycle === 'pending' || !req.statusCode;
  }

  if (typeof code !== 'number') return false;

  if (statusFilter === '2xx') return code >= 200 && code < 300;
  if (statusFilter === '3xx') return code >= 300 && code < 400;
  if (statusFilter === '4xx') return code >= 400 && code < 500;
  if (statusFilter === '5xx') return code >= 500 && code < 600;

  // Exact status code match (e.g. "200", "404")
  return String(code) === statusFilter;
}

/**
 * Checks whether a request matches the specified resource type filter.
 * 
 * @param {object} req
 * @param {string} typeFilter
 * @returns {boolean}
 */
function matchesResourceType(req, typeFilter) {
  if (!typeFilter || typeFilter === 'ALL') return true;

  const rawType = (req.type || '').toLowerCase();

  if (typeFilter === 'fetch' || typeFilter === 'xhr' || typeFilter === 'fetch/xhr') {
    return rawType === 'xmlhttprequest' || rawType === 'fetch';
  }
  if (typeFilter === 'document') {
    return rawType === 'main_frame' || rawType === 'sub_frame';
  }
  if (typeFilter === 'script') {
    return rawType === 'script';
  }
  if (typeFilter === 'stylesheet' || typeFilter === 'css') {
    return rawType === 'stylesheet';
  }
  if (typeFilter === 'image' || typeFilter === 'img') {
    return rawType === 'image';
  }
  if (typeFilter === 'other') {
    const common = ['xmlhttprequest', 'fetch', 'script', 'stylesheet', 'image', 'main_frame', 'sub_frame'];
    return !common.includes(rawType);
  }

  return rawType === typeFilter.toLowerCase();
}

/**
 * Filters and searches through an array of captured requests.
 * 
 * @param {Array<object>} requests
 * @param {object} criteria
 * @param {string} [criteria.search]
 * @param {string} [criteria.method]
 * @param {string} [criteria.status]
 * @param {string} [criteria.resourceType]
 * @param {string} [criteria.origin]
 * @param {string} [criteria.sortBy] - 'newest' | 'oldest' | 'duration' | 'status'
 * @returns {Array<object>}
 */
export function filterRequests(requests, criteria = {}) {
  if (!Array.isArray(requests)) return [];

  const {
    search = '',
    method = 'ALL',
    status = 'ALL',
    resourceType = 'ALL',
    origin = 'ALL',
    sortBy = 'newest'
  } = criteria;

  const searchLower = search.trim().toLowerCase();

  const filtered = requests.filter(req => {
    // 1. Search Query (matches url, pathname, routePattern, or method)
    if (searchLower) {
      const matchUrl = (req.url || '').toLowerCase().includes(searchLower);
      const matchPath = (req.pathname || '').toLowerCase().includes(searchLower);
      const matchPattern = (req.routePattern || '').toLowerCase().includes(searchLower);
      const matchMethod = (req.method || '').toLowerCase().includes(searchLower);
      const matchStatus = String(req.statusCode || '').includes(searchLower);

      if (!matchUrl && !matchPath && !matchPattern && !matchMethod && !matchStatus) {
        return false;
      }
    }

    // 2. HTTP Method Filter
    if (method !== 'ALL') {
      if ((req.method || '').toUpperCase() !== method.toUpperCase()) {
        return false;
      }
    }

    // 3. Status Code Filter
    if (!matchesStatus(req, status)) {
      return false;
    }

    // 4. Resource Type Filter
    if (!matchesResourceType(req, resourceType)) {
      return false;
    }

    // 5. Origin Filter
    if (origin !== 'ALL') {
      if (req.origin !== origin) {
        return false;
      }
    }

    return true;
  });

  // Sorting
  return sortRequests(filtered, sortBy);
}

/**
 * Sorts requests by specified strategy.
 * 
 * @param {Array<object>} requests
 * @param {string} sortBy
 * @returns {Array<object>}
 */
export function sortRequests(requests, sortBy = 'newest') {
  const list = [...requests];

  switch (sortBy) {
    case 'oldest':
      return list.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    case 'duration':
      return list.sort((a, b) => (b.duration || 0) - (a.duration || 0));
    case 'status':
      return list.sort((a, b) => (b.statusCode || 0) - (a.statusCode || 0));
    case 'newest':
    default:
      return list.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  }
}
