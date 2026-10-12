import React, { useEffect, useMemo, useRef, useState } from 'react';
import gsap from 'gsap';
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  ChevronDown,
  Clock,
  ExternalLink,
  Flame,
  Layers,
  RefreshCw,
  Search,
  Share2,
  Shield,
  ShieldAlert,
  Sparkles,
  User,
  Zap,
} from 'lucide-react';
import { api, formatCurrency, isDemoIncident } from '../services/api';
import {
  FindingDetail,
  Incident,
  IncidentStatus,
  OperatorProfile,
  Severity,
} from '../types';
import { ActionModal } from './ActionModal';
import { ExportBriefModal } from './ExportBriefModal';

interface IncidentsTabProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onIncidentUpdated: (updated: Incident) => void;
  onShowToast: (
    type: 'info' | 'success' | 'warning' | 'error',
    title: string,
    message?: string
  ) => void;
  activeOperator?: OperatorProfile;
}

export const IncidentsTab: React.FC<IncidentsTabProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onIncidentUpdated,
  onShowToast,
  activeOperator,
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sevFilter, setSevFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  const [findings, setFindings] = useState<FindingDetail[]>([]);
  const [loadingFindings, setLoadingFindings] = useState<boolean>(false);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [isMutatingStatus, setIsMutatingStatus] = useState<boolean>(false);
  const [executingActionId, setExecutingActionId] = useState<string | null>(null);

  // Action approval/rejection modal state
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [modalActionId, setModalActionId] = useState<string>('');
  const [modalActionTitle, setModalActionTitle] = useState<string>('');
  const [modalTargetStatus, setModalTargetStatus] = useState<'APPROVED' | 'REJECTED'>('APPROVED');
  const [isSubmittingApproval, setIsSubmittingApproval] = useState<boolean>(false);
  const [exportModalOpen, setExportModalOpen] = useState<boolean>(false);

  const detailPanelRef = useRef<HTMLDivElement>(null);

  const filteredIncidents = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    const sf = sevFilter.toUpperCase();
    const stf = statusFilter.toUpperCase();

    return incidents.filter(inc => {
      if (sf && inc.severity !== sf) return false;
      if (stf && inc.status !== stf) return false;
      if (q) {
        const rName = (inc.resource?.name || '').toLowerCase();
        const title = (inc.title || '').toLowerCase();
        const id = (inc.incident_id || '').toLowerCase();
        if (!rName.includes(q) && !title.includes(q) && !id.includes(q)) return false;
      }
      return true;
    });
  }, [incidents, searchQuery, sevFilter, statusFilter]);

  const selectedIncident = useMemo(() => {
    return incidents.find(i => i.incident_id === selectedIncidentId) || null;
  }, [incidents, selectedIncidentId]);

  // Animate detail view transition when selected incident changes
  useEffect(() => {
    if (detailPanelRef.current && selectedIncident) {
      gsap.fromTo(
        detailPanelRef.current,
        { opacity: 0.7, y: 6 },
        { opacity: 1, y: 0, duration: 0.25, ease: 'power2.out' }
      );
    }
  }, [selectedIncidentId, selectedIncident]);

  // Fetch findings when selected incident changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setFindings([]);
      return;
    }
    let isMounted = true;
    setLoadingFindings(true);
    api
      .fetchIncidentFindings(selectedIncidentId)
      .then(fList => {
        if (isMounted) setFindings(fList);
      })
      .catch(err => {
        console.warn('Could not fetch findings:', err);
        if (isMounted) setFindings([]);
      })
      .finally(() => {
        if (isMounted) setLoadingFindings(false);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedIncidentId]);

  // Handle Status Update
  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!selectedIncident) return;
    setIsMutatingStatus(true);
    try {
      const updated = await api.updateIncidentStatus(selectedIncident.incident_id, newStatus);
      onIncidentUpdated(updated);
      onShowToast('success', 'Incident Status Updated', `Status mutated to ${newStatus}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      onShowToast('error', 'Status Mutation Failed', msg);
    } finally {
      setIsMutatingStatus(false);
    }
  };

  // Handle AI Triage Trigger
  const handleTriggerAITriage = async () => {
    if (!selectedIncident) return;
    setIsAiLoading(true);
    try {
      const updated = await api.triggerAITriage(selectedIncident.incident_id, true);
      onIncidentUpdated(updated);
      onShowToast(
        'success',
        'AI Triage Generated',
        `Synthesis completed via ${updated.ai_analysis?.model_identifier || 'Azure AI'}`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      onShowToast('error', 'AI Triage Failed', msg);
    } finally {
      setIsAiLoading(false);
    }
  };

  // Open Approval/Rejection Modal
  const openActionModal = (
    actionId: string,
    actionTitle: string,
    status: 'APPROVED' | 'REJECTED'
  ) => {
    setModalActionId(actionId);
    setModalActionTitle(actionTitle);
    setModalTargetStatus(status);
    setModalOpen(true);
  };

  // Confirm Approval/Rejection
  const handleConfirmApproval = async (notes: string) => {
    if (!selectedIncident) return;
    setIsSubmittingApproval(true);
    try {
      const updated = await api.submitActionApproval(
        selectedIncident.incident_id,
        modalActionId,
        modalTargetStatus,
        notes,
        activeOperator?.name || 'secops-operator'
      );
      onIncidentUpdated(updated);
      setModalOpen(false);
      onShowToast(
        'success',
        modalTargetStatus === 'APPROVED' ? 'Remediation Authorized' : 'Remediation Rejected',
        `Recorded intent for ${modalActionId}`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      onShowToast('error', 'Approval Intent Failed', msg);
    } finally {
      setIsSubmittingApproval(false);
    }
  };

  // Execute Remediation
  const handleExecuteRemediation = async (actionId: string) => {
    if (!selectedIncident) return;
    setExecutingActionId(actionId);
    try {
      const updated = await api.executeRemediation(selectedIncident.incident_id, actionId);
      onIncidentUpdated(updated);
      onShowToast(
        'success',
        'Remediation Executed & Verified',
        `ARM state verified for ${actionId}`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      onShowToast('error', 'Remediation Execution Failed', msg);
    } finally {
      setExecutingActionId(null);
    }
  };

  const isDemo = isDemoIncident(selectedIncident);
  const costImpact = selectedIncident?.cost_impact;
  const ai = selectedIncident?.ai_analysis;
  const isTriaged = ai && ai.status === 'COMPLETED';
  const isUnavailable =
    ai && (ai.status === 'UNAVAILABLE' || ai.execution_mode === 'UNAVAILABLE');
  const isLive = isTriaged && (ai.execution_mode === 'LIVE' || ai.provider_status === 'LIVE');
  const isFallback = isTriaged && !isLive;

  return (
    <div className="main-workspace">
      {/* Master: Incident List Panel */}
      <aside className="incident-list-panel">
        <div className="panel-header">
          <div className="panel-title">
            <Shield size={16} color="var(--accent-sky)" />
            <span>Incident Feed</span>
            <span className="badge-status OPEN" style={{ marginLeft: '4px' }}>
              {incidents.filter(i => i.status === 'OPEN').length}
            </span>
          </div>
          <span className="source-badge postgres">PostgreSQL</span>
        </div>

        <div
          style={{
            padding: '12px 14px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div className="search-input-wrapper" style={{ width: '100%' }}>
            <Search size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              style={{ width: '100%', minWidth: 'unset' }}
              placeholder="Search resource, title, or ID..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <select
              className="filter-select"
              style={{ fontSize: '0.74rem', padding: '6px 10px' }}
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              className="filter-select"
              style={{ fontSize: '0.74rem', padding: '6px 10px' }}
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="CLOSED">Closed</option>
            </select>
          </div>
        </div>

        <div className="incident-items-scroll">
          {filteredIncidents.length === 0 ? (
            <div className="empty-state">No matching incidents detected.</div>
          ) : (
            filteredIncidents.map(inc => {
              const isActive = inc.incident_id === selectedIncidentId;
              const isIncDemo = isDemoIncident(inc);
              const timeStr = inc.created_at ? inc.created_at.substring(11, 16) + ' UTC' : '';

              return (
                <div
                  key={inc.incident_id}
                  className={`incident-card ${isActive ? 'active' : ''}`}
                  onClick={() => onSelectIncident(inc.incident_id)}
                >
                  <div className="card-top">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className={`badge-sev ${inc.severity}`}>{inc.severity}</span>
                      <span className={`badge-status ${inc.status}`}>{inc.status}</span>
                      {isIncDemo && (
                        <span
                          className="badge-status"
                          style={{
                            background: 'rgba(159, 122, 234, 0.16)',
                            color: '#9f7aea',
                            border: '1px solid rgba(159, 122, 234, 0.35)',
                            fontSize: '0.62rem',
                          }}
                        >
                          SIMULATION
                        </span>
                      )}
                    </div>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.68rem',
                        color: 'var(--text-tertiary)',
                      }}
                    >
                      {inc.incident_id}
                    </span>
                  </div>

                  <div className="card-title">{inc.title}</div>

                  <div className="card-bottom">
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {inc.resource?.name || 'resource'}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {inc.cost_impact && (
                        <span className="finops-tag">
                          +
                          {formatCurrency(
                            inc.cost_impact.deviation_absolute,
                            inc.cost_impact.currency || 'USD'
                          )}
                        </span>
                      )}
                      <span>{timeStr}</span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </aside>

      {/* Detail: Incident Inspector View */}
      <section className="incident-detail-panel" ref={detailPanelRef}>
        {!selectedIncident ? (
          <div className="panel empty-state" style={{ padding: '80px 20px' }}>
            <ShieldAlert size={36} color="var(--text-tertiary)" style={{ marginBottom: '12px' }} />
            <div>Select an incident from the feed to inspect telemetry, FinOps correlation, and AI triage.</div>
          </div>
        ) : (
          <>
            {/* Header Card */}
            <div className="detail-header-card">
              {isDemo && (
                <div
                  style={{
                    background: 'rgba(159, 122, 234, 0.10)',
                    border: '1px solid rgba(159, 122, 234, 0.30)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 14px',
                    marginBottom: '16px',
                    fontSize: '0.78rem',
                    color: '#d6bcfa',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                  }}
                >
                  <Sparkles size={16} color="#9f7aea" style={{ flexShrink: 0 }} />
                  <div>
                    <strong>Seeded Demonstration Fixture:</strong> This incident was generated from simulated test scenario telemetry (workload <code>{selectedIncident.resource.name}</code>, simulated caller <code>{selectedIncident.identity?.caller || 'admin@cloudpulse.io'}</code>). It is intended for testing and operator demonstration.
                  </div>
                </div>
              )}

              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '16px',
                  flexWrap: 'wrap',
                }}
              >
                <div>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      flexWrap: 'wrap',
                      marginBottom: '6px',
                    }}
                  >
                    <span className={`badge-sev ${selectedIncident.severity}`}>
                      {selectedIncident.severity}
                    </span>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.74rem',
                        color: 'var(--text-tertiary)',
                      }}
                    >
                      {selectedIncident.incident_id}
                    </span>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                      Created: {selectedIncident.created_at}
                    </span>
                  </div>
                  <h1 className="detail-heading">{selectedIncident.title}</h1>
                </div>

                {/* Status Mutation & Sharing Actions */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: '0.74rem', padding: '5px 10px', gap: '6px' }}
                    onClick={() => setExportModalOpen(true)}
                    title="Export Incident Brief for leadership or Jira"
                  >
                    <Share2 size={13} color="var(--accent-sky)" />
                    <span>Export Brief</span>
                  </button>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span
                      style={{
                        fontSize: '0.74rem',
                        color: 'var(--text-tertiary)',
                        fontWeight: 600,
                      }}
                    >
                      Status:
                    </span>
                    <select
                      className="filter-select"
                      style={{ fontWeight: 700 }}
                      value={selectedIncident.status}
                      disabled={isMutatingStatus}
                      onChange={e => handleStatusChange(e.target.value as IncidentStatus)}
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Workload Metadata Grid */}
              <div className="meta-grid" style={{ marginTop: '16px' }}>
                <div className="meta-box">
                  <div className="meta-box-label">Target Workload</div>
                  <div className="meta-box-val" style={{ color: 'var(--accent-sky)' }}>
                    {selectedIncident.resource.name}
                  </div>
                </div>
                <div className="meta-box">
                  <div className="meta-box-label">Resource Type</div>
                  <div className="meta-box-val">
                    {selectedIncident.resource.type.split('/').pop() ||
                      selectedIncident.resource.type}
                  </div>
                </div>
                <div className="meta-box">
                  <div className="meta-box-label">Resource Group</div>
                  <div className="meta-box-val">{selectedIncident.resource.resource_group}</div>
                </div>
                <div className="meta-box">
                  <div className="meta-box-label">Initiating Caller</div>
                  <div className="meta-box-val">
                    {selectedIncident.identity?.caller || 'azure-platform'}
                  </div>
                </div>
              </div>
            </div>

            {/* Security ↔ FinOps Concurrence Card */}
            {costImpact && (
              <div className="correlation-card">
                <div className="correlation-header">
                  <div className="correlation-title">
                    <Zap size={16} />
                    <span>Security ↔ FinOps Concurrence</span>
                  </div>
                  <span className="source-badge cloudpulse">
                    {costImpact.correlation_strength} (
                    {(costImpact.correlation_confidence * 100).toFixed(0)}% Conf)
                  </span>
                </div>
                <div className="correlation-stats">
                  <div className="corr-stat">
                    <div className="corr-stat-lbl">Cost Category</div>
                    <div className="corr-stat-val">{costImpact.cost_category}</div>
                  </div>
                  <div className="corr-stat">
                    <div className="corr-stat-lbl">Actual Billed Cost</div>
                    <div className="corr-stat-val">
                      {formatCurrency(costImpact.actual_cost, costImpact.currency)}
                    </div>
                  </div>
                  <div className="corr-stat">
                    <div className="corr-stat-lbl">Historical Baseline</div>
                    <div className="corr-stat-val">
                      {formatCurrency(costImpact.baseline_cost, costImpact.currency)}
                    </div>
                  </div>
                  <div className="corr-stat">
                    <div className="corr-stat-lbl">Financial Surge</div>
                    <div className="corr-stat-val positive">
                      +{costImpact.percentage_increase.toFixed(0)}% (+
                      {formatCurrency(costImpact.deviation_absolute, costImpact.currency)})
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* AI Advisory Triage Card */}
            <div className="ai-card">
              <div className="ai-header">
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    flexWrap: 'wrap',
                  }}
                >
                  <div
                    className={`ai-pill ${
                      isLive ? 'live' : isFallback ? 'fallback' : 'unavailable'
                    }`}
                  >
                    <Bot size={14} />
                    <span>
                      {isLive
                        ? 'Azure OpenAI (Live)'
                        : isFallback
                        ? 'Deterministic Fallback'
                        : 'AI Triage Unavailable'}
                    </span>
                  </div>

                  {isTriaged && (
                    <>
                      <span
                        className="source-badge arg"
                        style={{ fontFamily: 'var(--font-mono)' }}
                      >
                        {ai?.model_identifier}
                      </span>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          color: 'var(--text-tertiary)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {(ai?.confidence || 0) * 100}% Conf
                      </span>
                      {ai?.latency_ms && (
                        <span
                          style={{
                            fontSize: '0.72rem',
                            color: 'var(--text-tertiary)',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {ai.latency_ms}ms
                        </span>
                      )}
                    </>
                  )}
                </div>

                <button
                  className="btn btn-purple"
                  onClick={handleTriggerAITriage}
                  disabled={isAiLoading}
                >
                  {isAiLoading ? <RefreshCw size={13} className="spin" /> : <Sparkles size={13} />}
                  <span>
                    {isAiLoading
                      ? 'Synthesizing...'
                      : isTriaged
                      ? 'Re-Run AI Triage'
                      : 'Generate AI Triage'}
                  </span>
                </button>
              </div>

              {/* Fallback Notice */}
              {isFallback && (
                <div
                  style={{
                    background: 'rgba(246, 173, 85, 0.08)',
                    borderLeft: '3px solid #f6ad55',
                    padding: '10px 14px',
                    borderRadius: '0 4px 4px 0',
                    fontSize: '0.78rem',
                    color: '#feebc8',
                  }}
                >
                  <strong style={{ color: '#f6ad55' }}>Deterministic Offline Synthesis:</strong>{' '}
                  This analysis was synthesized offline by CloudPulse's rule engine using verified
                  telemetry findings. It was not generated by a live Azure OpenAI model.
                </div>
              )}

              {/* Unavailable Notice */}
              {isUnavailable && (
                <div
                  style={{
                    background: 'rgba(252, 129, 129, 0.08)',
                    borderLeft: '3px solid #fc8181',
                    padding: '10px 14px',
                    borderRadius: '0 4px 4px 0',
                    fontSize: '0.80rem',
                    color: '#fed7d7',
                  }}
                >
                  <strong>Inference Service Unavailable:</strong>{' '}
                  {ai?.error_message || 'Inference call failed'}. Deterministic detection severity
                  and correlated cost impact remain authoritative.
                </div>
              )}

              {isTriaged ? (
                <>
                  {/* Executive Summary */}
                  <div>
                    <div className="ai-section-title">Executive Summary</div>
                    <div className="ai-text-box">{ai?.summary}</div>
                  </div>

                  {/* Risk Assessment & Likely Scenario */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '14px',
                    }}
                  >
                    <div>
                      <div className="ai-section-title">Risk Assessment</div>
                      <div className="ai-text-box">{ai?.risk_assessment}</div>
                    </div>
                    <div>
                      <div className="ai-section-title">Likely Scenario</div>
                      <div className="ai-text-box">{ai?.likely_scenario}</div>
                    </div>
                  </div>

                  {/* Tripartition Grid */}
                  <div className="tripartition-grid">
                    <div className="tri-box facts">
                      <div className="ai-section-title" style={{ color: 'var(--accent-sky)' }}>
                        Verified Facts (Telemetry Grounded)
                      </div>
                      <ul className="tri-list">
                        {(ai?.facts || []).map((fact, idx) => (
                          <li key={idx}>{fact}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="tri-box inferences">
                      <div className="ai-section-title" style={{ color: 'var(--accent-amber)' }}>
                        Inferences & Deductions
                      </div>
                      <ul className="tri-list">
                        {(ai?.inferences || []).map((inf, idx) => (
                          <li key={idx}>{inf}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Recommended Operator Actions & Remediation Gate */}
                  <div>
                    <div className="ai-section-title" style={{ color: 'var(--accent-teal)' }}>
                      Recommended Operator Actions & Controlled Remediation Gate
                    </div>
                    <div className="actions-list">
                      {(ai?.recommended_actions || []).map(act => {
                        const remActions = selectedIncident.remediation?.actions || {};
                        const rem =
                          remActions[act.id] ||
                          (selectedIncident.remediation?.action_id === act.id
                            ? selectedIncident.remediation
                            : null);
                        const status = rem?.status || 'PROPOSED';

                        const isVerified = status === 'VERIFIED';
                        const isApproved = status === 'APPROVED';
                        const isExecuting = executingActionId === act.id;
                        const isRejected = status === 'REJECTED';

                        return (
                          <div key={act.id} className="action-item">
                            <div className="action-info">
                              <div className="action-title-row">
                                <span
                                  style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '0.74rem',
                                    color: 'var(--accent-sky)',
                                  }}
                                >
                                  {act.id}
                                </span>
                                <span className="action-name">{act.title}</span>
                                <span className={`badge-status ${status}`}>{status}</span>
                              </div>
                              <div className="action-desc">{act.description}</div>

                              {rem?.approval?.operator && (
                                <div
                                  style={{
                                    fontSize: '0.72rem',
                                    color: 'var(--text-secondary)',
                                    marginTop: '6px',
                                  }}
                                >
                                  Authorized by:{' '}
                                  <strong style={{ color: 'var(--text-primary)' }}>
                                    {rem.approval.operator}
                                  </strong>
                                  {rem.approval.notes ? ` — "${rem.approval.notes}"` : ''}
                                </div>
                              )}

                              {isVerified && rem?.verification && (
                                <div
                                  style={{
                                    fontSize: '0.74rem',
                                    color: 'var(--accent-teal)',
                                    fontWeight: 600,
                                    marginTop: '6px',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '5px',
                                  }}
                                >
                                  <Check size={13} />
                                  <span>Azure State Live-Verified:</span>
                                  <code>{rem.verification.verified_state || 'COMPLIANT'}</code>
                                </div>
                              )}
                            </div>

                            <div className="action-controls">
                              {isVerified ? (
                                <span className="badge-status VERIFIED">VERIFIED</span>
                              ) : isApproved ? (
                                <button
                                  className="btn btn-accent"
                                  onClick={() => handleExecuteRemediation(act.id)}
                                  disabled={isExecuting}
                                >
                                  {isExecuting ? (
                                    <RefreshCw size={12} className="spin" />
                                  ) : (
                                    <Zap size={12} />
                                  )}
                                  <span>
                                    {isExecuting
                                      ? 'Mutating & Verifying...'
                                      : 'Execute Remediation'}
                                  </span>
                                </button>
                              ) : isRejected ? (
                                <span className="badge-status CLOSED">REJECTED</span>
                              ) : (
                                <div style={{ display: 'flex', gap: '6px' }}>
                                  <button
                                    className="btn btn-success"
                                    style={{ padding: '5px 12px', fontSize: '0.74rem' }}
                                    onClick={() =>
                                      openActionModal(act.id, act.title, 'APPROVED')
                                    }
                                  >
                                    Authorize
                                  </button>
                                  <button
                                    className="btn btn-danger"
                                    style={{ padding: '5px 12px', fontSize: '0.74rem' }}
                                    onClick={() =>
                                      openActionModal(act.id, act.title, 'REJECTED')
                                    }
                                  >
                                    Reject
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </>
              ) : (
                <div className="empty-state" style={{ padding: '24px 0' }}>
                  AI triage analysis has not been performed for this incident yet. Click{' '}
                  <strong>Generate AI Triage</strong> above to synthesize telemetry facts,
                  inferences, and controlled actions.
                </div>
              )}
            </div>

            {/* Chronological Evidence Timeline */}
            <div className="timeline-card">
              <div className="panel-title" style={{ marginBottom: '14px' }}>
                <Clock size={16} color="var(--accent-sky)" />
                <span>Chronological Evidence Timeline</span>
              </div>
              <div className="timeline-flow">
                {(selectedIncident.timeline || []).map((entry, idx) => (
                  <div key={idx} className="timeline-node">
                    <div className="node-header">
                      <span className="node-time">{entry.timestamp}</span>
                      <span className="node-tag">{entry.event}</span>
                      {entry.caller && (
                        <span
                          style={{
                            fontSize: '0.70rem',
                            color: 'var(--text-tertiary)',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          Caller: {entry.caller}
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        fontSize: '0.78rem',
                        color: 'var(--text-primary)',
                        marginTop: '2px',
                      }}
                    >
                      {entry.finding_id && (
                        <span
                          style={{
                            color: 'var(--accent-sky)',
                            fontFamily: 'var(--font-mono)',
                            marginRight: '6px',
                          }}
                        >
                          [{entry.finding_id}]
                        </span>
                      )}
                      {entry.operation ||
                        entry.correlation_metadata?.reason ||
                        'Recorded lifecycle event'}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Associated Evidence Records */}
            <div className="panel" style={{ padding: '20px' }}>
              <div className="panel-title" style={{ marginBottom: '14px' }}>
                <Layers size={16} color="var(--accent-sky)" />
                <span>Associated Evidence Records ({findings.length})</span>
              </div>
              {loadingFindings ? (
                <div className="empty-state">Loading evidence records...</div>
              ) : findings.length === 0 ? (
                <div className="empty-state">No associated evidence records.</div>
              ) : (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                    gap: '14px',
                  }}
                >
                  {findings.map(f => (
                    <div
                      key={f.finding_id}
                      style={{
                        background: 'var(--bg-inset)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '12px 14px',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          marginBottom: '6px',
                        }}
                      >
                        <span className={`badge-sev ${f.severity}`}>{f.severity}</span>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.72rem',
                            color: 'var(--accent-sky)',
                          }}
                        >
                          {f.finding_id}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: '0.82rem',
                          fontWeight: 700,
                          color: 'var(--text-primary)',
                          marginBottom: '8px',
                        }}
                      >
                        {f.finding_type}
                      </div>
                      {f.evidence && (
                        <pre
                          style={{
                            background: 'rgba(0,0,0,0.4)',
                            padding: '8px 10px',
                            borderRadius: 'var(--radius-sm)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.68rem',
                            color: 'var(--text-secondary)',
                            overflowX: 'auto',
                            maxHeight: '160px',
                          }}
                        >
                          {JSON.stringify(f.evidence, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </section>

      {/* Action Approval/Rejection Modal */}
      <ActionModal
        isOpen={modalOpen}
        actionId={modalActionId}
        actionTitle={modalActionTitle}
        targetStatus={modalTargetStatus}
        onConfirm={handleConfirmApproval}
        onCancel={() => setModalOpen(false)}
        isLoading={isSubmittingApproval}
      />

      {/* Export Brief Modal */}
      <ExportBriefModal
        isOpen={exportModalOpen}
        incident={selectedIncident}
        onClose={() => setExportModalOpen(false)}
        onShowToast={onShowToast}
      />
    </div>
  );
};
