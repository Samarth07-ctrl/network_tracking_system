import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService from '../services/api';

function Dashboard() {
  const [overviewStats, setOverviewStats] = useState(null);
  const [networks, setNetworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, networksRes] = await Promise.all([
        apiService.getOverviewStats(),
        apiService.getNetworks()
      ]);

      setOverviewStats(statsRes.data);
      setNetworks(networksRes.data.networks);
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error('Error fetching data:', err);
      setError('Failed to load data. Make sure the backend is running.');
      setLoading(false);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B/s';
    const k = 1024;
    const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getTrafficLevel = (throughput, capacity) => {
    const capacityBps = capacity * 1024 * 1024 / 8; // Convert Mbps to Bps
    const usage = (throughput / capacityBps) * 100;
    if (usage > 80) return 'HIGH';
    if (usage > 50) return 'MEDIUM';
    return 'LOW';
  };

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  if (error) {
    return <div className="error">{error}</div>;
  }

  return (
    <div className="dashboard">
      <h1>Campus Network Overview</h1>

      {overviewStats && (
        <div className="stats-grid">
          <div className="stat-card" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
            <h3>WiFi Networks</h3>
            <div className="value">{overviewStats.total_networks}</div>
            <div className="label">Active Networks</div>
          </div>

          <div className="stat-card" style={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
            <h3>Connected Devices</h3>
            <div className="value">{overviewStats.total_active_devices}</div>
            <div className="label">Active Devices</div>
          </div>

          <div className="stat-card" style={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
            <h3>Total Throughput</h3>
            <div className="value">{formatBytes(overviewStats.total_throughput_bps)}</div>
            <div className="label">Campus-wide</div>
          </div>

          <div className="stat-card" style={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)' }}>
            <h3>Security Alerts</h3>
            <div className="value">{overviewStats.alerts_24h}</div>
            <div className="label">Last 24 Hours</div>
          </div>
        </div>
      )}

      <div className="card">
        <h2>WiFi Networks</h2>
        <div className="network-grid">
          {networks.map(network => (
            <div
              key={network.id}
              className="network-card"
              onClick={() => navigate(`/network/${network.id}`)}
            >
              <h3>{network.ssid}</h3>
              <div className="location">📍 {network.location}</div>
              <div className="location">🌐 {network.subnet_range}</div>

              <div className="stats">
                <div className="stat">
                  <div className="stat-value">{network.active_devices}</div>
                  <div className="stat-label">Devices</div>
                </div>
                <div className="stat">
                  <div className="stat-value">{formatBytes(network.current_throughput_bps)}</div>
                  <div className="stat-label">Throughput</div>
                </div>
                <div className="stat">
                  <div className="stat-value">
                    {getTrafficLevel(network.current_throughput_bps, network.bandwidth_capacity_mbps)}
                  </div>
                  <div className="stat-label">Load</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
