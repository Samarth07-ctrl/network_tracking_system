/**
 * API Service
 * 
 * Centralized API client for communicating with the backend.
 * All HTTP requests to the FastAPI backend go through this service.
 */

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// API methods
export const apiService = {
  // Network endpoints
  getNetworks: () => api.get('/api/networks'),
  getNetwork: (networkId) => api.get(`/api/networks/${networkId}`),
  getNetworkDevices: (networkId, activeOnly = true) => 
    api.get(`/api/networks/${networkId}/devices`, { params: { active_only: activeOnly } }),
  getNetworkMetrics: (networkId, hours = 1) => 
    api.get(`/api/networks/${networkId}/metrics`, { params: { hours } }),
  
  // Packet endpoints
  getPackets: (networkId = null, limit = 100) => 
    api.get('/api/packets', { params: { network_id: networkId, limit } }),
  
  // Protocol and bandwidth endpoints
  getProtocolDistribution: (networkId) => api.get(`/api/protocols/${networkId}`),
  getTopBandwidthConsumers: (networkId, limit = 10) => 
    api.get(`/api/bandwidth/${networkId}`, { params: { limit } }),
  
  // Alert endpoints
  getAlerts: (networkId = null, severity = null, hours = 24, limit = 100) => 
    api.get('/api/alerts', { params: { network_id: networkId, severity, hours, limit } }),
  
  // Prohibited website endpoints
  getProhibitedWebsites: () => api.get('/api/prohibited-websites'),
  addProhibitedWebsite: (domain, category) => 
    api.post('/api/prohibited-websites', { domain, category }),
  deleteProhibitedWebsite: (websiteId) => 
    api.delete(`/api/prohibited-websites/${websiteId}`),
  
  // Overview stats
  getOverviewStats: () => api.get('/api/stats/overview'),

  // Database reset utility — wipe all security alerts
  clearAllAlerts: () => api.delete('/api/alerts/clear-all'),

  /**
   * Upload a .pcap file for forensic analysis / demo mode.
   *
   * @param {File} file - The .pcap or .pcapng File object selected by the user.
   * @param {function(number): void} [onProgress] - Optional callback receiving
   *   upload progress as a percentage (0–100).
   * @returns {Promise} Axios promise resolving to { task_id, message, filename, size_bytes }
   */
  uploadPcap: (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/api/upload-pcap/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      // Override the default 10-second timeout for potentially large files
      timeout: 120000,
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percent);
        }
      },
    });
  },

  /**
   * Download the Campus Network Security Audit PDF report.
   *
   * The response is returned as a Blob so the caller can create an object URL
   * and trigger a browser download.
   *
   * @returns {Promise} Axios promise resolving to a Blob containing the PDF bytes.
   */
  downloadSecurityReport: () =>
    api.get('/api/report/generate-pdf', {
      responseType: 'blob',
      // PDF generation can take up to 10 s on the server; allow 30 s total
      timeout: 30000,
    }),
};

export default apiService;
