import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  DollarSign,
  ExternalLink,
  Info,
  Layers,
  LineChart,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react';
import { api, formatCurrency } from '../services/api';
import { ResourceDetail } from '../types';

interface ResourceDrawerProps {
  isOpen: boolean;
  resourceId: string | null;
  onClose: () => void;
  onSelectIncident: (incidentId: string) => void;
}

export const ResourceDrawer: React.FC<ResourceDrawerProps> = ({
  isOpen,
  resourceId,
  onClose,
  onSelectIncident,
}) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<ResourceDetail | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (!isOpen || !resourceId) {
      setDetail(null);
      setError(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    api
      .fetchResourceDetail(resourceId)
      .then(data => {
        if (isMounted) setDetail(data);
      })
      .catch(err => {
        if (isMounted) setError(err.message || 'Failed to fetch resource details');
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, resourceId]);

  const handleCopyId = () => {
    if (!detail?.resource?.id) return;
    navigator.clipboard.writeText(detail.resource.id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  const res = detail?.resource;
  const cost = detail?.cost;
  const util = detail?.utilization;
  const sec = detail?.security;
  const inc = detail?.incidents;

  const isSynthetic = res?.discovered_in_arg === false || res?.provisioningState === 'Unknown';

  return (
    <>
      <div className={`drawer-overlay ${isOpen ? 'active' : ''}`} onClick={onClose} />
      <aside className={`drawer-panel ${isOpen ? 'active' : ''}`}>
        <div className="drawer-header">
          <div>
            <div
              style={{
                fontSize: '0.70rem',
                color: 'var(--accent-sky)',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
              }}
            >
              {res?.type || 'Azure Resource'}
            </div>
            <div
              style={{
                fontSize: '1.15rem',
                fontWeight: 800,
                color: 'var(--text-primary)',
                marginTop: '2px',
                letterSpacing: '-0.02em',
              }}
            >
              {res?.name || 'Resource Inspector'}
            </div>
          </div>
          <button
            className="btn btn-secondary"
            style={{ padding: '6px', borderRadius: '50%' }}
            onClick={onClose}
            title="Close drawer (ESC)"
          >
            <X size={16} />
          </button>
        </div>

        <div className="drawer-body">
          {loading && (
            <div className="empty-state">
              <RefreshCw size={20} className="spin" style={{ display: 'inline-block', marginBottom: '8px', color: 'var(--accent-sky)' }} />
              <div>Querying live Azure APIs (Resource Graph, Monitor, Cost Management)...</div>
            </div>
          )}

          {error && (
            <div
              style={{
                background: 'rgba(252, 129, 129, 0.10)',
                border: '1px solid rgba(252, 129, 129, 0.35)',
                borderRadius: 'var(--radius-sm)',
                padding: '16px',
                color: '#fed7d7',
                fontSize: '0.82rem',
              }}
            >
              <strong>Error querying resource:</strong> {error}
            </div>
          )}

          {!loading && !error && detail && (
            <>
              {/* Synthetic Fixture Notice */}
              {isSynthetic && (
                <div
                  style={{
                    background: 'rgba(246, 173, 85, 0.10)',
                    border: '1px solid rgba(246, 173, 85, 0.30)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 14px',
                    fontSize: '0.76rem',
                    color: '#feebc8',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                  }}
                >
                  <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong>Not Discovered in Azure Resource Graph:</strong> This resource was synthesized from
                    telemetry identifiers and does not exist in the active Azure Resource Graph inventory (simulated test workload, decommissioned resource, or outside current subscription scope).
                  </div>
                </div>
              )}

              {/* 1. Resource Identity */}
              <div className="panel" style={{ padding: '16px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '12px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <Layers size={14} color="var(--accent-sky)" />
                    <span>1. Resource Identity</span>
                  </div>
                  <span className="source-badge arg">Azure Resource Graph</span>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '10px',
                    fontSize: '0.76rem',
                    marginBottom: '12px',
                  }}
                >
                  <div>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.66rem', textTransform: 'uppercase' }}>
                      Name:
                    </span>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{res?.name}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.66rem', textTransform: 'uppercase' }}>
                      Location:
                    </span>
                    <div style={{ color: 'var(--text-secondary)' }}>{res?.location || 'global'}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.66rem', textTransform: 'uppercase' }}>
                      Resource Group:
                    </span>
                    <div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {res?.resourceGroup}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.66rem', textTransform: 'uppercase' }}>
                      Provisioning State:
                    </span>
                    <div style={{ color: 'var(--accent-teal)', fontWeight: 600 }}>
                      {res?.provisioningState || 'Succeeded'}
                    </div>
                  </div>
                </div>

                <div>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: '4px',
                    }}
                  >
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.66rem', textTransform: 'uppercase' }}>
                      Canonical ARM ID:
                    </span>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '2px 8px', fontSize: '0.66rem' }}
                      onClick={handleCopyId}
                    >
                      {copied ? <Check size={11} color="var(--accent-teal)" /> : <Copy size={11} />}
                      <span>{copied ? 'Copied' : 'Copy ID'}</span>
                    </button>
                  </div>
                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.68rem',
                      color: 'var(--text-secondary)',
                      wordBreak: 'break-all',
                      background: 'var(--bg-inset)',
                      padding: '8px 10px',
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    {res?.id}
                  </div>
                </div>
              </div>

              {/* 2. Actual Azure Cost */}
              <div className="panel" style={{ padding: '16px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '12px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <DollarSign size={14} color="#38d9a9" />
                    <span>2. Actual Azure Cost</span>
                  </div>
                  <span className="source-badge cost">Azure Cost Management</span>
                </div>

                {cost?.has_billing_data && cost.total_cost !== null && cost.total_cost !== undefined ? (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px', marginBottom: '10px' }}>
                      <span
                        style={{
                          fontSize: '1.45rem',
                          fontWeight: 800,
                          color: '#38d9a9',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {formatCurrency(cost.total_cost, cost.currency)}
                      </span>
                      <span className="source-badge cost">{cost.cost_category || 'Billed Workload'}</span>
                    </div>

                    {cost.meters && cost.meters.length > 0 && (
                      <div style={{ marginTop: '10px' }}>
                        <div
                          style={{
                            fontSize: '0.66rem',
                            color: 'var(--text-tertiary)',
                            textTransform: 'uppercase',
                            marginBottom: '6px',
                          }}
                        >
                          Meter Breakdown:
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {cost.meters.map((m, idx) => (
                            <div
                              key={idx}
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                fontSize: '0.74rem',
                                padding: '4px 8px',
                                background: 'var(--bg-inset)',
                                borderRadius: 'var(--radius-sm)',
                              }}
                            >
                              <span style={{ fontFamily: 'var(--font-mono)' }}>{m.meter_name}</span>
                              <span style={{ fontFamily: 'var(--font-mono)', color: '#38d9a9', fontWeight: 600 }}>
                                {formatCurrency(m.cost, cost.currency)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {cost.period?.billing_latency_notice && (
                      <div style={{ fontSize: '0.70rem', color: '#f6ad55', marginTop: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Info size={12} />
                        <span>{cost.period.billing_latency_notice}</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-tertiary)', fontSize: '0.76rem' }}>
                    No closed billing data available for selected period (24–48h reconciliation latency).
                  </div>
                )}
              </div>

              {/* 3. Runtime Utilization */}
              <div className="panel" style={{ padding: '16px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '12px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <LineChart size={14} color="#06b6d4" />
                    <span>3. Runtime Utilization</span>
                  </div>
                  <span className="source-badge monitor">Azure Monitor</span>
                </div>

                {util?.supported && util.metrics && Object.keys(util.metrics).length > 0 ? (
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                      gap: '10px',
                    }}
                  >
                    {Object.values(util.metrics).map((m, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-inset)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 12px',
                        }}
                      >
                        <div style={{ fontSize: '0.66rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>
                          {m.display_name || m.name}
                        </div>
                        <div
                          style={{
                            fontSize: '1.1rem',
                            fontWeight: 800,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--accent-sky)',
                            margin: '4px 0',
                          }}
                        >
                          {m.latest_value !== null ? m.latest_value : '—'}{' '}
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-tertiary)' }}>{m.unit}</span>
                        </div>
                        {m.latest_timestamp && (
                          <div
                            style={{
                              fontSize: '0.62rem',
                              color: 'var(--text-tertiary)',
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            {m.latest_timestamp.substring(11, 19)} UTC
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-tertiary)', fontSize: '0.76rem' }}>
                    {util?.message || 'Metrics unavailable for this resource type'}
                  </div>
                )}
              </div>

              {/* 4. Threat Surface Findings */}
              <div className="panel" style={{ padding: '16px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '12px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <ShieldAlert size={14} color="#fc8181" />
                    <span>4. Threat Surface Findings ({sec?.findings_count || 0})</span>
                  </div>
                  <span className="source-badge cloudpulse">CloudPulse Detection Engine</span>
                </div>

                {sec?.findings && sec.findings.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {sec.findings.map(f => (
                      <div
                        key={f.finding_id}
                        style={{
                          background: 'var(--bg-inset)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 12px',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '4px',
                          }}
                        >
                          <span className={`badge-sev ${f.severity}`}>{f.severity}</span>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.70rem',
                              color: 'var(--accent-sky)',
                            }}
                          >
                            {f.finding_id}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {f.finding_type}
                        </div>
                        <div
                          style={{
                            fontSize: '0.66rem',
                            color: 'var(--text-tertiary)',
                            fontFamily: 'var(--font-mono)',
                            marginTop: '2px',
                          }}
                        >
                          {f.timestamp}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--accent-teal)', fontSize: '0.76rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Check size={14} />
                    <span>No active threat surface findings detected on this workload.</span>
                  </div>
                )}
              </div>

              {/* 5. Correlated Incidents */}
              <div className="panel" style={{ padding: '16px' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '12px',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <Layers size={14} color="var(--accent-sky)" />
                    <span>5. Correlated Incidents ({inc?.count || 0})</span>
                  </div>
                  <span className="source-badge postgres">CloudPulse State</span>
                </div>

                {inc?.incidents && inc.incidents.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {inc.incidents.map(i => (
                      <div
                        key={i.incident_id}
                        style={{
                          background: 'var(--bg-inset)',
                          border: '1px solid rgba(252,129,129,0.3)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 12px',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '4px',
                          }}
                        >
                          <span className={`badge-sev ${i.severity}`}>{i.severity}</span>
                          <span className={`badge-status ${i.status}`}>{i.status}</span>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.70rem',
                              color: 'var(--accent-sky)',
                            }}
                          >
                            {i.incident_id}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.80rem', fontWeight: 600, marginBottom: '8px' }}>{i.title}</div>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          onClick={() => {
                            onClose();
                            onSelectIncident(i.incident_id);
                          }}
                        >
                          <ExternalLink size={12} />
                          <span>Open in Incidents Console</span>
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-tertiary)', fontSize: '0.76rem' }}>
                    No correlated security-financial anomaly detected.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
};
