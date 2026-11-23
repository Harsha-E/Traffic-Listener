/**
 * NetListener - Request Store Module
 * Manages persistence in chrome.storage.local with FIFO buffer limits,
 * debounced writes for high-frequency traffic bursts, and atomic history resets.
 * Uses real-time data compression to minimize storage footprint and memory overhead.
 */

import { compressJson, decompressJson } from './compression.js';

const STORAGE_KEYS = {
  REQUESTS: 'netlistener_requests',
  SETTINGS: 'netlistener_settings'
};

const DEFAULT_SETTINGS = {
  monitoringEnabled: true,
  scopeMode: 'subnet', // 'subnet' (192.168.x.x, 10.x.x.x, 172.16-31.x.x, localhost) | 'local' (127.0.0.1) | 'all'
  maxHistorySize: 500,
  allowedOrigins: [
    'http://localhost:*',
    'https://localhost:*',
    'http://127.0.0.1:*',
    'https://127.0.0.1:*',
    'http://192.168.*:*',
    'https://192.168.*:*'
  ],
  redactSensitiveHeaders: true,
  autoScroll: true,
  firebaseConfig: {
    projectId: 'alt-mvgr',
    apiKey: 'AIzaSyCMdcIYi91aWXI9cHz3fFW78rJ8JHV-j9w',
    collection: 'network_reports',
    endpointType: 'firestore',
    customUrl: ''
  }
};

// Fallback in-memory storage for non-extension test environments
const memoryStorage = new Map();

/**
 * Storage adapter supporting chrome.storage.local with fallback
 */
const storageAdapter = {
  async get(keys) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return await chrome.storage.local.get(keys);
    }
    const result = {};
    if (Array.isArray(keys)) {
      keys.forEach(k => { result[k] = memoryStorage.get(k); });
    } else if (typeof keys === 'string') {
      result[keys] = memoryStorage.get(keys);
    } else if (typeof keys === 'object' && keys !== null) {
      Object.keys(keys).forEach(k => {
        result[k] = memoryStorage.has(k) ? memoryStorage.get(k) : keys[k];
      });
    }
    return result;
  },

  async set(items) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return await chrome.storage.local.set(items);
    }
    for (const [k, v] of Object.entries(items)) {
      memoryStorage.set(k, v);
    }
  },

  async remove(keys) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return await chrome.storage.local.remove(keys);
    }
    const arr = Array.isArray(keys) ? keys : [keys];
    arr.forEach(k => memoryStorage.delete(k));
  }
};

export class RequestStore {
  constructor() {
    this._requests = [];
    this._settings = { ...DEFAULT_SETTINGS };
    this._pendingSaveTimeout = null;
    this._initialized = false;
    this._listeners = new Set();
  }

  /**
   * Initializes the store from storage, handling decompressed payloads transparently.
   */
  async init() {
    try {
      const data = await storageAdapter.get([STORAGE_KEYS.REQUESTS, STORAGE_KEYS.SETTINGS]);
      const storedRequests = data[STORAGE_KEYS.REQUESTS];

      if (storedRequests && storedRequests.__compressed) {
        const decompressed = await decompressJson(storedRequests);
        this._requests = Array.isArray(decompressed) ? decompressed : [];
      } else if (Array.isArray(storedRequests)) {
        this._requests = storedRequests;
      } else {
        this._requests = [];
      }

      if (data[STORAGE_KEYS.SETTINGS]) {
        this._settings = { ...DEFAULT_SETTINGS, ...data[STORAGE_KEYS.SETTINGS] };
      } else {
        this._settings = { ...DEFAULT_SETTINGS };
        await storageAdapter.set({ [STORAGE_KEYS.SETTINGS]: this._settings });
      }

      this._initialized = true;
    } catch (err) {
      console.error('[NetListener Store] Failed to initialize storage:', err);
      this._requests = [];
      this._settings = { ...DEFAULT_SETTINGS };
      this._initialized = true;
    }
    return this;
  }

  /**
   * Returns current settings.
   */
  getSettings() {
    return { ...this._settings };
  }

  /**
   * Updates settings and persists them.
   * @param {Partial<typeof DEFAULT_SETTINGS>} newSettings
   */
  async updateSettings(newSettings) {
    this._settings = { ...this._settings, ...newSettings };
    await storageAdapter.set({ [STORAGE_KEYS.SETTINGS]: this._settings });
    this._notifyListeners({ type: 'SETTINGS_UPDATED', settings: this._settings });
    return this._settings;
  }

  /**
   * Gets all stored requests.
   * @returns {Array<object>}
   */
  getRequests() {
    return [...this._requests];
  }

  /**
   * Gets a single request by its ID.
   * @param {string} id
   * @returns {object|null}
   */
  getRequestById(id) {
    return this._requests.find(r => r.id === id || r.requestId === id) || null;
  }

  /**
   * Adds or updates a request in the store.
   * If the request already exists (same id/requestId), updates it in-place.
   * Otherwise appends it and prunes excess if maxHistorySize is exceeded.
   * 
   * @param {object} req
   */
  addOrUpdateRequest(req) {
    if (!req) return;

    const reqId = req.id || req.requestId;
    const existingIndex = this._requests.findIndex(r => (r.id === reqId || r.requestId === reqId));

    if (existingIndex !== -1) {
      // Merge update with existing record
      const merged = {
        ...this._requests[existingIndex],
        ...req,
        lastUpdated: Date.now()
      };
      if ('rawUrlPreview' in merged) delete merged.rawUrlPreview;
      this._requests[existingIndex] = merged;
    } else {
      // New request entry
      const cleanReq = { ...req };
      if ('rawUrlPreview' in cleanReq) delete cleanReq.rawUrlPreview;
      this._requests.push(cleanReq);

      // Enforce FIFO buffer limit
      const maxSize = this._settings.maxHistorySize || 500;
      if (this._requests.length > maxSize) {
        this._requests.splice(0, this._requests.length - maxSize);
      }
    }

    this._scheduleDebouncedSave();
    this._notifyListeners({ type: 'REQUEST_UPDATED', request: req, count: this._requests.length });
  }

  /**
   * Debounces disk persistence to preserve Chrome storage write quotas during bursts.
   */
  _scheduleDebouncedSave() {
    if (this._pendingSaveTimeout) {
      clearTimeout(this._pendingSaveTimeout);
    }

    this._pendingSaveTimeout = setTimeout(async () => {
      this._pendingSaveTimeout = null;
      await this.flush();
    }, 150);
  }

  /**
   * Immediately flushes stored requests to disk with real-time compression.
   */
  async flush() {
    try {
      const payload = await compressJson(this._requests);
      await storageAdapter.set({ [STORAGE_KEYS.REQUESTS]: payload });
    } catch (err) {
      console.error('[NetListener Store] Error flushing requests to storage:', err);
    }
  }

  /**
   * Clears all request history.
   */
  async clearHistory() {
    if (this._pendingSaveTimeout) {
      clearTimeout(this._pendingSaveTimeout);
      this._pendingSaveTimeout = null;
    }

    this._requests = [];
    await storageAdapter.set({ [STORAGE_KEYS.REQUESTS]: [] });
    this._notifyListeners({ type: 'HISTORY_CLEARED' });
  }

  /**
   * Subscribe to store changes.
   * @param {Function} callback
   * @returns {Function} unsubscribe
   */
  subscribe(callback) {
    this._listeners.add(callback);
    return () => this._listeners.delete(callback);
  }

  _notifyListeners(event) {
    for (const listener of this._listeners) {
      try {
        listener(event);
      } catch (e) {
        console.error('[NetListener Store] Listener error:', e);
      }
    }
  }
}

// Singleton export
export const requestStore = new RequestStore();
