import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import PcapUploader from './PcapUploader';

function Dashboard() {
  const [overviewStats, setOverviewStats] = useState(null);
  const [networks, setNetworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // --- PDF report download state ---
  /** True while the PDF is being generated / downloaded. */
  const [reportLoading, setReportLoading] = useState(false);
  /** Error message shown when PDF generation fails. */
  const [reportError, setReportError] = useState(null);

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

  /**
   * Trigger a Campus Network Security Audit PDF download.
   * Calls GET /api/report/generate-pdf, receives the PDF as a Blob,
   * and programmatically clicks a temporary <a> element to save the file.
   */
  const handleDownloadReport = async () => {
    setReportLoading(true);
    setReportError(null);

    try {
      const response = await apiService.downloadSecurityReport();

      // Build a temporary object URL from the PDF blob
      const blobUrl = window.URL.createObjectURL(
        new Blob([response.data], { type: 'application/pdf' })
      );

      // Create a hidden <a> element, click it to trigger the download, then clean up
      const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      const link = document.createElement('a');
      link.href = blobUrl;
      link.setAttribute('download', `campus_security_audit_${today}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();

      // Release the object URL to free memory
      window.URL.revokeObjectURL(blobUrl);

    } catch (err) {
      console.error('PDF download failed:', err);
      const detail =
        err.response?.data?.detail ||
        err.message ||
        'Failed to generate report. Please try again.';
      setReportError(detail);
    } finally {
      setReportLoading(false);
    }
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

      {/* ------------------------------------------------------------------ */}
      {/* Feature 3: Download Security Report button                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 style={{ margin: 0 }}>Security Audit Report</h2>
            <p style={{ margin: '0.25rem 0 0', color: '#6b7280', fontSize: '0.875rem' }}>
              Generate a PDF with the top 5 bandwidth consumers and top 5 security alerts from the last 24 hours.
            </p>
          </div>

          <button
            onClick={handleDownloadReport}
            disabled={reportLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.5rem 1.25rem',
              background: reportLoading ? '#9ca3af' : '#1d4ed8',
              color: '#fff',
              border: 'none',
              borderRadius: '0.375rem',
              fontSize: '0.875rem',
              fontWeight: '600',
              cursor: reportLoading ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
            }}
          >
            {reportLoading ? (
              <>
                {/* Spinner */}
                <svg
                  style={{ width: '1rem', height: '1rem', animation: 'spin 1s linear infinite' }}
                  fill="none"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" style={{ opacity: 0.25 }} />
                  <path fill="currentColor" style={{ opacity: 0.75 }} d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Generating…
              </>
            ) : (
              <>
                {/* Download icon */}
                <svg style={{ width: '1rem', height: '1rem' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download Security Report
              </>
            )}
          </button>
        </div>

        {/* Error message */}
        {reportError && (
          <p style={{ marginTop: '0.5rem', color: '#dc2626', fontSize: '0.875rem' }}>
            ✗ {reportError}
          </p>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Feature 1: PCAP Demo Mode uploader                                  */}
      {/* ------------------------------------------------------------------ */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <PcapUploader />
      </div>

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
