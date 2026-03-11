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
};

export default apiService;
