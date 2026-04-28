/**
 * PcapUploader Component
 *
 * Drag-and-drop PCAP file uploader for Demo Mode / Forensic Analysis.
 * Uses react-dropzone for the drop zone and shows a real-time progress bar.
 *
 * Accepted formats : .pcap, .pcapng
 * Max size         : 500 MB (mirrors backend limit)
 */

import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { apiService } from '../services/api';

const MAX_BYTES = 500 * 1024 * 1024; // 500 MB

/** Human-readable byte formatter */
function fmtBytes(b) {
  if (b >= 1_073_741_824) return `${(b / 1_073_741_824).toFixed(2)} GB`;
  if (b >= 1_048_576)     return `${(b / 1_048_576).toFixed(2)} MB`;
  if (b >= 1_024)         return `${(b / 1_024).toFixed(2)} KB`;
  return `${b} B`;
}

/* ─── tiny inline SVG icons ─────────────────────────────────────────────── */
const IconUpload = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}
       strokeLinecap="round" strokeLinejoin="round" style={{ width: 48, height: 48 }}>
    <path d="M12 16V4m0 0L8 8m4-4 4 4" />
    <path d="M20 16.7A5 5 0 0 0 18 7h-1.26A8 8 0 1 0 4 15.25" />
  </svg>
);

const IconFile = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}
       strokeLinecap="round" strokeLinejoin="round" style={{ width: 20, height: 20 }}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
  </svg>
);

const IconCheck = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
       strokeLinecap="round" strokeLinejoin="round" style={{ width: 20, height: 20 }}>
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const IconX = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
       strokeLinecap="round" strokeLinejoin="round" style={{ width: 20, height: 20 }}>
    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

/* ─── styles (plain objects — no Tailwind dependency) ────────────────────── */
const S = {
  card: {
    background: '#fff',
    borderRadius: 12,
    boxShadow: '0 1px 3px rgba(0,0,0,.1), 0 1px 2px rgba(0,0,0,.06)',
    padding: '1.5rem',
    fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  header: {
    display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4,
  },
  title: { fontSize: 16, fontWeight: 700, color: '#1e3a5f', margin: 0 },
  subtitle: { fontSize: 13, color: '#6b7280', marginBottom: '1.25rem', lineHeight: 1.5 },
  badge: {
    display: 'inline-block', fontSize: 11, fontWeight: 600,
    background: '#dbeafe', color: '#1d4ed8',
    borderRadius: 4, padding: '2px 7px', marginLeft: 6,
  },

  /* drop zone */
  dropBase: {
    border: '2px dashed #cbd5e1',
    borderRadius: 10,
    padding: '2rem 1.5rem',
    textAlign: 'center',
    cursor: 'pointer',
    transition: 'border-color .2s, background .2s',
    background: '#f8fafc',
    outline: 'none',
  },
  dropActive: { borderColor: '#3b82f6', background: '#eff6ff' },
  dropAccepted: { borderColor: '#22c55e', background: '#f0fdf4' },
  dropRejected: { borderColor: '#ef4444', background: '#fef2f2' },

  dropIcon: { color: '#94a3b8', marginBottom: 12 },
  dropTitle: { fontSize: 15, fontWeight: 600, color: '#374151', marginBottom: 4 },
  dropHint: { fontSize: 13, color: '#9ca3af' },

  /* file info row */
  fileRow: {
    display: 'flex', alignItems: 'center', gap: 10,
    background: '#f1f5f9', borderRadius: 8, padding: '10px 14px',
    marginTop: '1rem',
  },
  fileName: { flex: 1, fontSize: 13, fontWeight: 600, color: '#1e293b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  fileSize: { fontSize: 12, color: '#64748b', whiteSpace: 'nowrap' },

  /* progress */
  progressWrap: { marginTop: '1rem' },
  progressLabel: { display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#64748b', marginBottom: 4 },
  progressTrack: { height: 8, background: '#e2e8f0', borderRadius: 99, overflow: 'hidden' },
  progressBar: { height: '100%', background: 'linear-gradient(90deg,#3b82f6,#6366f1)', borderRadius: 99, transition: 'width .2s' },

  /* buttons */
  btnRow: { display: 'flex', gap: 10, marginTop: '1rem' },
  btnPrimary: {
    flex: 1, padding: '9px 0', borderRadius: 8, border: 'none',
    background: 'linear-gradient(135deg,#3b82f6,#6366f1)',
    color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer',
    transition: 'opacity .2s',
  },
  btnPrimaryDisabled: { opacity: 0.45, cursor: 'not-allowed' },
  btnSecondary: {
    padding: '9px 18px', borderRadius: 8, border: '1px solid #e2e8f0',
    background: '#fff', color: '#374151', fontSize: 14, fontWeight: 500,
    cursor: 'pointer',
  },

  /* status banners */
  bannerSuccess: {
    display: 'flex', alignItems: 'flex-start', gap: 10,
    background: '#f0fdf4', border: '1px solid #bbf7d0',
    borderRadius: 8, padding: '10px 14px', marginTop: '1rem',
    fontSize: 13, color: '#166534',
  },
  bannerError: {
    display: 'flex', alignItems: 'flex-start', gap: 10,
    background: '#fef2f2', border: '1px solid #fecaca',
    borderRadius: 8, padding: '10px 14px', marginTop: '1rem',
    fontSize: 13, color: '#991b1b',
  },
};

/* ─── component ──────────────────────────────────────────────────────────── */
export default function PcapUploader() {
  const [file, setFile]       = useState(null);
  const [status, setStatus]   = useState('idle');   // idle | uploading | success | error
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState('');

  /* ── dropzone ── */
  const onDrop = useCallback((accepted, rejected) => {
    if (rejected.length > 0) {
      const reason = rejected[0].errors[0]?.message || 'Invalid file';
      setFile(null);
      setStatus('error');
      setMessage(reason);
      return;
    }
    if (accepted.length > 0) {
      setFile(accepted[0]);
      setStatus('idle');
      setMessage('');
      setProgress(0);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive, isDragAccept, isDragReject } =
    useDropzone({
      onDrop,
      accept: { 'application/octet-stream': ['.pcap', '.pcapng'] },
      maxSize: MAX_BYTES,
      maxFiles: 1,
      disabled: status === 'uploading',
    });

  /* ── upload ── */
  const handleUpload = async () => {
    if (!file) return;
    setStatus('uploading');
    setProgress(0);
    setMessage('');
    try {
      const res = await apiService.uploadPcap(file, pct => setProgress(pct));
      const d = res.data;
      setStatus('success');
      setProgress(100);
      setMessage(
        `"${d.filename}" accepted (task ${d.task_id.slice(0, 8)}…). ` +
        `Alerts will appear in the Security panel shortly.`
      );
      setFile(null);
    } catch (err) {
      setStatus('error');
      setProgress(0);
      setMessage(
        err.response?.data?.detail || err.message || 'Upload failed — please try again.'
      );
    }
  };

  const handleReset = () => {
    setFile(null); setStatus('idle'); setMessage(''); setProgress(0);
  };

  /* ── drop zone style ── */
  const dropStyle = {
    ...S.dropBase,
    ...(isDragActive  ? S.dropActive   : {}),
    ...(isDragAccept  ? S.dropAccepted : {}),
    ...(isDragReject  ? S.dropRejected : {}),
    ...(status === 'uploading' ? { opacity: 0.6, cursor: 'not-allowed' } : {}),
  };

  const canUpload = file !== null && status !== 'uploading';

  return (
    <div style={S.card}>
      {/* ── header ── */}
      <div style={S.header}>
        <svg viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth={2}
             strokeLinecap="round" strokeLinejoin="round" style={{ width: 20, height: 20 }}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
        <h3 style={S.title}>
          PCAP Demo Mode
          <span style={S.badge}>Forensic Analysis</span>
        </h3>
      </div>
      <p style={S.subtitle}>
        Drop a <code>.pcap</code> or <code>.pcapng</code> file to replay captured traffic
        through the live IDS pipeline. Alerts and metrics appear on the dashboard in real time.
      </p>

      {/* ── drop zone ── */}
      <div {...getRootProps({ style: dropStyle })}>
        <input {...getInputProps()} />
        <div style={S.dropIcon}><IconUpload /></div>
        {isDragActive ? (
          <p style={S.dropTitle}>Drop it here…</p>
        ) : (
          <>
            <p style={S.dropTitle}>Drag &amp; drop your PCAP file here</p>
            <p style={S.dropHint}>or click to browse &nbsp;·&nbsp; .pcap / .pcapng &nbsp;·&nbsp; max {fmtBytes(MAX_BYTES)}</p>
          </>
        )}
      </div>

      {/* ── selected file info ── */}
      {file && status !== 'success' && (
        <div style={S.fileRow}>
          <span style={{ color: '#3b82f6' }}><IconFile /></span>
          <span style={S.fileName}>{file.name}</span>
          <span style={S.fileSize}>{fmtBytes(file.size)}</span>
        </div>
      )}

      {/* ── progress bar ── */}
      {status === 'uploading' && (
        <div style={S.progressWrap}>
          <div style={S.progressLabel}>
            <span>Uploading…</span>
            <span>{progress}%</span>
          </div>
          <div style={S.progressTrack}>
            <div style={{ ...S.progressBar, width: `${progress}%` }}
                 role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} />
          </div>
        </div>
      )}

      {/* ── action buttons ── */}
      {file && status !== 'success' && (
        <div style={S.btnRow}>
          <button
            onClick={handleUpload}
            disabled={!canUpload}
            style={{ ...S.btnPrimary, ...(!canUpload ? S.btnPrimaryDisabled : {}) }}
          >
            {status === 'uploading' ? `Uploading… ${progress}%` : '⚡ Analyze PCAP'}
          </button>
          {status !== 'uploading' && (
            <button onClick={handleReset} style={S.btnSecondary}>Clear</button>
          )}
        </div>
      )}

      {/* ── success banner ── */}
      {status === 'success' && (
        <div style={S.bannerSuccess}>
          <span style={{ color: '#16a34a', flexShrink: 0 }}><IconCheck /></span>
          <div>
            <strong>Processing started</strong>
            <p style={{ margin: '2px 0 0', lineHeight: 1.4 }}>{message}</p>
          </div>
          <button onClick={handleReset}
                  style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#16a34a' }}>
            <IconX />
          </button>
        </div>
      )}

      {/* ── error banner ── */}
      {status === 'error' && (
        <div style={S.bannerError}>
          <span style={{ color: '#dc2626', flexShrink: 0 }}><IconX /></span>
          <div>
            <strong>Upload failed</strong>
            <p style={{ margin: '2px 0 0', lineHeight: 1.4 }}>{message}</p>
          </div>
          <button onClick={handleReset}
                  style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626' }}>
            <IconX />
          </button>
        </div>
      )}
    </div>
  );
}
