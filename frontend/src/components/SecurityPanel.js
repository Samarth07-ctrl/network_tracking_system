import React, { useState, useEffect } from 'react';
import apiService from '../services/api';

function SecurityPanel() {
  const [alerts, setAlerts] = useState([]);
  const [prohibitedWebsites, setProhibitedWebsites] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const [newCategory, setNewCategory] = useState('');
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('');

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchAlerts, 5000); // Refresh alerts every 5 seconds
    return () => clearInterval(interval);
  }, [filterSeverity]);

  const fetchData = async () => {
    await Promise.all([fetchAlerts(), fetchProhibitedWebsites()]);
    setLoading(false);
  };

  const fetchAlerts = async () => {
    try {
      const res = await apiService.getAlerts(null, filterSeverity || null, 24, 100);
      setAlerts(res.data.alerts);
    } catch (err) {
      console.error('Error fetching alerts:', err);
    }
  };

  const fetchProhibitedWebsites = async () => {
    try {
      const res = await apiService.getProhibitedWebsites();
      setProhibitedWebsites(res.data.websites);
    } catch (err) {
      console.error('Error fetching prohibited websites:', err);
    }
  };

  const handleAddWebsite = async (e) => {
    e.preventDefault();
    if (!newDomain || !newCategory) return;

    try {
      await apiService.addProhibitedWebsite(newDomain, newCategory);
      setNewDomain('');
      setNewCategory('');
      fetchProhibitedWebsites();
    } catch (err) {
      console.error('Error adding website:', err);
      alert('Failed to add website');
    }
  };

  const handleDeleteWebsite = async (websiteId) => {
    if (!window.confirm('Are you sure you want to remove this prohibited website?')) return;

    try {
      await apiService.deleteProhibitedWebsite(websiteId);
      fetchProhibitedWebsites();
    } catch (err) {
      console.error('Error deleting website:', err);
      alert('Failed to delete website');
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const getAlertIcon = (alertType) => {
    const icons = {
      'PORT_SCAN': '🔍',
      'DDOS': '⚠️',
      'BRUTE_FORCE': '🔐',
      'PROHIBITED_WEBSITE': '🚫',
      'HIGH_BANDWIDTH': '📊'
    };
    return icons[alertType] || '⚡';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'CRITICAL': '#f44336',
      'HIGH': '#ff9800',
      'MEDIUM': '#ffc107',
      'LOW': '#4caf50'
    };
    return colors[severity] || '#666';
  };

  if (loading) {
    return <div className="loading">Loading security panel...</div>;
  }

  return (
    <div className="security-panel">
      <h1>Security Panel</h1>

      <div className="card">
        <h2>Security Alerts (Last 24 Hours)</h2>

        <div style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
          <div>
            <label>Filter by Severity: </label>
            <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
          <button
            id="clear-dashboard-data-btn"
            onClick={async () => {
              if (!window.confirm(
                'Are you sure you want to delete ALL security alerts?\n\n' +
                'This will truncate the security_alerts table and cannot be undone.'
              )) return;
              try {
                const res = await apiService.clearAllAlerts();
                alert(`Cleared ${res.data.deleted_count} alerts from the database.`);
                fetchAlerts();
              } catch (err) {
                console.error('Error clearing alerts:', err);
                alert('Failed to clear alerts. Check the console for details.');
              }
            }}
            style={{
              backgroundColor: '#d32f2f',
              color: 'white',
              border: 'none',
              padding: '8px 16px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontWeight: 'bold',
              fontSize: '13px',
            }}
          >
            🗑️ Clear Dashboard Data
          </button>
        </div>

        {alerts.length === 0 ? (
          <p>No security alerts found.</p>
        ) : (
          <div>
            {alerts.map((alert, idx) => (
              <div key={idx} className={`alert ${alert.severity}`}>
                <div>
                  <div className="alert-type">
                    {getAlertIcon(alert.alert_type)} {alert.alert_type}
                    <span style={{
                      marginLeft: '10px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      backgroundColor: getSeverityColor(alert.severity),
                      color: 'white'
                    }}>
                      {alert.severity}
                    </span>
                  </div>
                  <div className="alert-details">
                    {alert.source_ip && <span>Source: {alert.source_ip} ({alert.source_mac})</span>}
                    {alert.target_ip && <span> | Target: {alert.target_ip}</span>}
                    {alert.metadata && (
                      <div style={{ marginTop: '5px', fontSize: '13px' }}>
                        {alert.alert_type === 'PORT_SCAN' && (
                          <span>Ports accessed: {alert.metadata.ports_accessed}</span>
                        )}
                        {alert.alert_type === 'DDOS' && (
                          <span>Packet rate: {alert.metadata.packet_rate} pps from {alert.metadata.source_count} sources</span>
                        )}
                        {alert.alert_type === 'BRUTE_FORCE' && (
                          <span>{alert.metadata.attempt_count} attempts on {alert.metadata.port_name} (port {alert.metadata.target_port})</span>
                        )}
                        {alert.alert_type === 'PROHIBITED_WEBSITE' && (
                          <span>Domain: {alert.metadata.domain}</span>
                        )}
                        {alert.alert_type === 'HIGH_BANDWIDTH' && (
                          <span>{alert.metadata.gb_transferred} GB transferred</span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
                <div style={{ fontSize: '12px', color: '#666' }}>
                  {formatTimestamp(alert.timestamp)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h2>Prohibited Websites Management</h2>

        <form onSubmit={handleAddWebsite} style={{ marginBottom: '20px' }}>
          <div className="form-group">
            <label>Domain:</label>
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              required
            />
          </div>
          <div className="form-group">
            <label>Category:</label>
            <select value={newCategory} onChange={(e) => setNewCategory(e.target.value)} required>
              <option value="">Select category</option>
              <option value="gambling">Gambling</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="adult">Adult Content</option>
              <option value="social_media">Social Media</option>
              <option value="other">Other</option>
            </select>
          </div>
          <button type="submit">Add Prohibited Website</button>
        </form>

        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Category</th>
              <th>Added</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {prohibitedWebsites.map((website) => (
              <tr key={website.id}>
                <td>{website.domain}</td>
                <td>{website.category}</td>
                <td>{formatTimestamp(website.added_at)}</td>
                <td>
                  <button
                    onClick={() => handleDeleteWebsite(website.id)}
                    style={{ backgroundColor: '#f44336' }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default SecurityPanel;
