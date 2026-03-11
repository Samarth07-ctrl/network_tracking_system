import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  AreaChart, Area, BarChart, Bar
} from 'recharts';
import {
  Activity, ArrowLeft, Cpu, Global, Server,
  Layers, AlertCircle, TrendingUp, TrendingDown,
  MapPin, Globe, Clock, PlusCircle
} from 'lucide-react';
import apiService from '../services/api';
import './NetworkDetail.css';

function NetworkDetail() {
  const { networkId } = useParams();
  const navigate = useNavigate();
  const [network, setNetwork] = useState(null);
  const [devices, setDevices] = useState([]);
  const [packets, setPackets] = useState([]);
  const [protocolDist, setProtocolDist] = useState(null);
  const [bandwidthConsumers, setBandwidthConsumers] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [networkId]);

  const fetchData = async () => {
    try {
      const [networkRes, devicesRes, packetsRes, protocolRes, bandwidthRes, metricsRes] = await Promise.all([
        apiService.getNetwork(networkId),
        apiService.getNetworkDevices(networkId),
        apiService.getPackets(networkId, 100),
        apiService.getProtocolDistribution(networkId),
        apiService.getTopBandwidthConsumers(networkId, 10),
        apiService.getNetworkMetrics(networkId, 1)
      ]);

      setNetwork(networkRes.data);
      setDevices(devicesRes.data.devices);
      setPackets(packetsRes.data.packets);
      setProtocolDist(protocolRes.data);
      setBandwidthConsumers(bandwidthRes.data.consumers);
      setMetrics(metricsRes.data.metrics);
      setLastUpdated(new Date());
      setLoading(false);
    } catch (err) {
      console.error('Error fetching network details:', err);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getProtocolColor = (protocol) => {
    const protoColors = {
      'TCP': 'badge-primary',
      'UDP': 'badge-info',
      'DNS': 'badge-warning',
      'HTTP': 'badge-success',
      'HTTPS': 'badge-success',
      'ICMP': 'badge-secondary'
    };
    return protoColors[protocol] || 'badge-dark';
  }

  const isSuspiciousPacket = (packet) => {
    // Basic heuristics for visual highlighting 
    if (packet.dest_port === 22 || packet.dest_port === 3389) return true; // SSH/RDP
    if (packet.packet_size > 1500) return true; // Abnormally large packet
    return false;
  }

  const COLORS = ['#4F46E5', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];

  if (loading || !network) {
    return (
      <div className="network-detail page-animate-in">
        <div className="flex gap-2 mb-6">
          <div className="skeleton-box w-32 h-10"></div>
        </div>
        <div className="skeleton-box h-24 mb-6"></div>
        <div className="grid grid-4 gap-4 mb-6">
          <div className="skeleton-box h-32"></div>
          <div className="skeleton-box h-32"></div>
          <div className="skeleton-box h-32"></div>
          <div className="skeleton-box h-32"></div>
        </div>
        <div className="grid grid-2 gap-4">
          <div className="skeleton-box h-80"></div>
          <div className="skeleton-box h-80"></div>
        </div>
      </div>
    );
  }

  const protocolChartData = protocolDist && protocolDist.distribution ?
    Object.entries(protocolDist.distribution).map(([name, value]) => ({ name, value })) : [];

  const metricsChartData = metrics.map(m => ({
    time: formatTimestamp(m.timestamp),
    throughput: m.throughput_bps / 1024, // Convert to KB/s
    packetRate: m.packet_rate
  })).reverse();

  const bandwidthBarData = bandwidthConsumers.slice(0, 5).map(c => ({
    ip: c.ip_address,
    bytes: c.total_bandwidth
  }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="custom-tooltip bg-white p-3 border rounded shadow-lg text-sm">
          <p className="font-semibold mb-1">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.name.includes('Throughput') ?
                formatBytes(entry.value * 1024) + '/s' :
                entry.name.includes('Rate') ? entry.value + ' pps' :
                  entry.name.includes('bytes') ? formatBytes(entry.value) : entry.value
              }
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="network-detail page-animate-in">
      <div className="header-actions">
        <button className="btn btn-ghost" onClick={() => navigate('/')}>
          <ArrowLeft size={18} /> Back to Dashboard
        </button>

        <div className="live-indicator">
          <span className="pulse-dot"></span>
          Live <span className="text-muted ml-2 text-xs">Updated {lastUpdated.toLocaleTimeString()}</span>
        </div>
      </div>

      <div className="network-hero card interactive">
        <div className="hero-icon">
          <Server size={32} color="#4F46E5" />
        </div>
        <div className="hero-content">
          <h1 className="hero-title">{network.ssid}</h1>
          <div className="hero-meta">
            <span className="meta-tag"><MapPin size={14} /> {network.location}</span>
            <span className="meta-tag"><Globe size={14} /> {network.subnet_range}</span>
            <span className="meta-tag"><Cpu size={14} /> {network.capture_interface}</span>
          </div>
        </div>
      </div>

      <div className="top-metrics-row">
        <div className="metric-card">
          <div className="metric-icon bg-indigo-50 text-indigo-500"><Layers size={20} /></div>
          <div className="metric-info">
            <h3>Active Devices</h3>
            <div className="metric-value">{devices.filter(d => d.is_active).length} <span className="metric-sub">/ {devices.length} total</span></div>
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-icon bg-green-50 text-green-500"><Activity size={20} /></div>
          <div className="metric-info">
            <h3>Current Throughput</h3>
            <div className="metric-value">{formatBytes(network.current_stats?.throughput_bps || 0)}/s</div>
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-icon bg-amber-50 text-amber-500"><TrendingUp size={20} /></div>
          <div className="metric-info">
            <h3>Packet Rate</h3>
            <div className="metric-value">{network.current_stats?.packet_rate || 0} <span className="metric-sub">pps</span></div>
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-icon bg-purple-50 text-purple-500"><Layers size={20} /></div>
          <div className="metric-info">
            <h3>Avg Packet Size</h3>
            <div className="metric-value">{network.current_stats?.avg_packet_size || 0} <span className="metric-sub">bytes</span></div>
          </div>
        </div>
      </div>

      <div className="charts-grid mb-6">
        <div className="card h-full">
          <h2 className="section-title">Network Performance</h2>
          {metricsChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={metricsChartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4F46E5" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#4F46E5" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#E5E7EB" />
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#6B7280', fontSize: 12 }} />
                <YAxis yAxisId="left" axisLine={false} tickLine={false} tick={{ fill: '#6B7280', fontSize: 12 }} />
                <YAxis yAxisId="right" orientation="right" axisLine={false} tickLine={false} tick={{ fill: '#6B7280', fontSize: 12 }} />
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
                <Area yAxisId="left" type="monotone" dataKey="throughput" stroke="#4F46E5" strokeWidth={3} fillOpacity={1} fill="url(#colorThroughput)" name="Throughput (KB/s)" animationDuration={500} />
                <Line yAxisId="right" type="monotone" dataKey="packetRate" stroke="#10B981" strokeWidth={2} dot={false} name="Packet Rate" animationDuration={500} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">No performance data available</div>
          )}
        </div>

        <div className="card h-full">
          <h2 className="section-title">Protocol Distribution</h2>
          {protocolChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={protocolChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  animationDuration={800}
                >
                  {protocolChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" layout="vertical" verticalAlign="middle" align="right" wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">No protocol data available</div>
          )}
        </div>
      </div>

      <div className="charts-grid mb-6">
        <div className="card h-full">
          <h2 className="section-title">Top Consumers by IP</h2>
          {bandwidthBarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={bandwidthBarData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#E5E7EB" />
                <XAxis type="number" hide />
                <YAxis dataKey="ip" type="category" axisLine={false} tickLine={false} tick={{ fill: '#4B5563', fontSize: 12 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="bytes" fill="#6366F1" radius={[0, 4, 4, 0]} barSize={20} animationDuration={1000} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">No connection data available</div>
          )}
        </div>
      </div>

      <div className="card no-padding">
        <div className="p-5 border-b border-gray-100 flex justify-between items-center">
          <h2 className="section-title m-0">Live Packet Feed</h2>
          <span className="badge badge-primary animated-pulse">Live</span>
        </div>
        <div className="table-responsive packet-stream">
          <table className="table clean-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Protocol</th>
                <th>Port Flow</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {packets.slice(0, 15).map((packet, idx) => (
                <tr key={idx} className={`packet-row ${isSuspiciousPacket(packet) ? 'suspicious-row' : ''}`}>
                  <td className="text-muted"><Clock size={12} className="inline mr-1" />{formatTimestamp(packet.timestamp)}</td>
                  <td className="font-mono text-sm">{packet.source_ip}</td>
                  <td className="font-mono text-sm">{packet.dest_ip}</td>
                  <td><span className={`badge ${getProtocolColor(packet.protocol)}`}>{packet.protocol}</span></td>
                  <td className="text-sm">
                    {packet.source_port && packet.dest_port ?
                      <span className="flex items-center gap-1">
                        {packet.source_port} <TrendingRight size={14} className="text-gray-400" /> {packet.dest_port}
                      </span> : '-'}
                  </td>
                  <td className="font-semibold">{packet.packet_size} B</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {/* 
      <div className="card">
        <h2>Connected Devices ({devices.length})</h2>
        <table className="table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device, idx) => (
              <tr key={idx}>
                <td>{device.ip_address}</td>
                <td>{device.mac_address}</td>
                <td>{formatTimestamp(device.first_seen)}</td>
                <td>{formatTimestamp(device.last_seen)}</td>
                <td>{device.is_active ? '🟢 Active' : '🔴 Inactive'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div> */}
    </div>
  );
}

// Helper icon component for inline usage in table
const TrendingRight = ({ size, className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <polyline points="9 18 15 12 9 6"></polyline>
  </svg>
)

export default NetworkDetail;
