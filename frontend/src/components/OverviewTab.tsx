import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ArrowRight, Cloud, DollarSign, ShieldAlert, Zap } from 'lucide-react';
import { formatCurrency } from '../services/api';
import { EstateOverview, Incident, Persona, TabType } from '../types';
import { ArchPipeline } from './ArchPipeline';
import { KpiGrid } from './KpiGrid';
import { SegmentedMeter } from './SegmentedMeter';

interface OverviewTabProps {
  estateOverview: EstateOverview | null;
  incidents: Incident[];
  resourceCount: number;
  onNavigateTab: (tab: TabType) => void;
  onSelectIncident: (id: string) => void;
  activePersona?: Persona;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  estateOverview,
  incidents,
  resourceCount,
  onNavigateTab,
  onSelectIncident,
  activePersona = 'secops',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      const panels = containerRef.current.querySelectorAll('.panel, .correlation-card');
      gsap.fromTo(
        panels,
        { opacity: 0, y: 14 },
        {
          opacity: 1,
          y: 0,
          duration: 0.4,
          stagger: 0.08,
          ease: 'power2.out',
        }
      );
    }
  }, []);

  const byType = estateOverview?.resources?.by_type || {};
  const typeKeys = Object.keys(byType);
  const totalRes = estateOverview?.resources?.total || 1;

  const byCat = estateOverview?.costs?.by_category || {};
  const catKeys = Object.keys(byCat);
  const totalCost = estateOverview?.costs?.total_cost || 0;
  const currency = estateOverview?.costs?.currency || 'USD';

  const correlatedIncidents = incidents.filter(i => !!i.cost_impact);
  const topCorr = correlatedIncidents.length > 0 ? correlatedIncidents[0] : null;

  const azureEnabled = estateOverview?.azure_integration?.enabled ?? false;
  const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const isOpen = (i: Incident) => i.status === 'OPEN' || i.status === 'INVESTIGATING';
  const priorityIncidents = [...incidents]
    .sort(
      (a, b) =>
        Number(isOpen(b)) - Number(isOpen(a)) ||
        (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0) ||
        (b.created_at || '').localeCompare(a.created_at || '')
    )
    .slice(0, 6);

  return (
    <div ref={containerRef} className="page-stack">

      <KpiGrid
        estateOverview={estateOverview}
        incidents={incidents}
        resourceCount={resourceCount}
        activePersona={activePersona}
      />

      <div className="overview-columns">
        {/* Main column: what needs attention */}
        <div className="overview-side">
          {topCorr && (
            <div className="correlation-card">
              <div className="correlation-header">
                <div className="correlation-title">
                  <Zap size={16} color="var(--accent-sky)" />
                  <span>Security ↔ FinOps Concurrence</span>
                </div>
                <span className="source-badge cloudpulse">Cross-Vector</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '14px', flexWrap: 'wrap' }}>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.6, flex: '1 1 320px' }}>
                  <strong style={{ color: 'var(--accent-sky)', fontFamily: 'var(--font-mono)' }}>
                    {topCorr.resource?.name}
                  </strong>{' '}
                  has active threat findings alongside a{' '}
                  <strong style={{ color: '#fc8181' }}>
                    +{topCorr.cost_impact?.percentage_increase.toFixed(0)}%
                  </strong>{' '}
                  surge in <strong>{topCorr.cost_impact?.cost_category}</strong> billing (+
                  {formatCurrency(topCorr.cost_impact?.deviation_absolute, topCorr.cost_impact?.currency || currency)}).
                </div>
                <button
                  className="btn btn-accent"
                  onClick={() => {
                    onNavigateTab('incidents');
                    onSelectIncident(topCorr.incident_id);
                  }}
                >
                  <span>Inspect incident</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          )}

          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <ShieldAlert size={16} color="var(--accent-rose)" />
                <span>Priority Incidents</span>
                <span className="tab-badge" style={{ background: 'rgba(252, 129, 129, 0.14)', color: '#fc8181' }}>
                  {incidents.filter(isOpen).length} open
                </span>
              </div>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.72rem', padding: '4px 10px' }}
                onClick={() => onNavigateTab('incidents')}
              >
                <span>All incidents</span>
                <ArrowRight size={12} />
              </button>
            </div>
            {priorityIncidents.length === 0 ? (
              <div className="empty-compact">
                No incidents recorded. Signed-in SecOps operators can use <strong>Seed Demo</strong> to ingest a
                simulated multi-vector scenario.
              </div>
            ) : (
              priorityIncidents.map(inc => (
                <div
                  key={inc.incident_id}
                  className="incident-row"
                  onClick={() => {
                    onNavigateTab('incidents');
                    onSelectIncident(inc.incident_id);
                  }}
                >
                  <span className={`badge-sev ${inc.severity}`}>{inc.severity}</span>
                  <span className="incident-row-title" title={inc.title}>{inc.title}</span>
                  {inc.cost_impact && (
                    <span className="finops-tag">
                      +{formatCurrency(inc.cost_impact.deviation_absolute, inc.cost_impact.currency || 'USD')}
                    </span>
                  )}
                  <span className={`badge-status ${inc.status}`}>{inc.status}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Side column: estate composition */}
        <div className="overview-side">
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <Cloud size={16} color="#38bdf8" />
                <span>Resource Distribution</span>
              </div>
              <button className="topbar-link" onClick={() => onNavigateTab('resources')}>
                Inventory →
              </button>
            </div>
            {typeKeys.length === 0 ? (
              <div className="empty-compact">
                {azureEnabled ? 'No resources discovered via Azure Resource Graph.' : 'Inventory unavailable while Azure is offline.'}
              </div>
            ) : (
              <div style={{ padding: '16px 18px' }}>
                {typeKeys.map(t => {
                  const count = byType[t];
                  const pct = Math.round((count / totalRes) * 100);
                  const shortName = t.split('/').pop() || t;
                  return (
                    <div key={t} style={{ marginBottom: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: '5px', gap: '8px' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {shortName}
                        </span>
                        <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                          {count} ({pct}%)
                        </span>
                      </div>
                      <SegmentedMeter value={pct} totalBlocks={18} colorScheme="sky" showSpark={true} height={6} label={shortName} />
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <DollarSign size={16} color="#38d9a9" />
                <span>Billed Cost by Category</span>
              </div>
              <button className="topbar-link" onClick={() => onNavigateTab('finops')}>
                FinOps →
              </button>
            </div>
            {catKeys.length === 0 || totalCost === 0 ? (
              <div className="empty-compact">
                {azureEnabled ? 'No categorized billing records in the current window.' : 'Billing unavailable while Azure is offline.'}
              </div>
            ) : (
              <div style={{ padding: '16px 18px' }}>
                {catKeys.map(c => {
                  const costVal = byCat[c];
                  const pct = totalCost > 0 ? Math.round((costVal / totalCost) * 100) : 0;
                  return (
                    <div key={c} style={{ marginBottom: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: '5px', gap: '8px' }}>
                        <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{c}</span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: '#38d9a9', fontWeight: 700, whiteSpace: 'nowrap' }}>
                          {formatCurrency(costVal, currency)} ({pct}%)
                        </span>
                      </div>
                      <SegmentedMeter value={pct} totalBlocks={18} colorScheme="multi" showSpark={true} height={6} label={c} />
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      <details className="section-disclosure">
        <summary>
          <Zap size={14} color="var(--accent-sky)" />
          <span>How CloudPulse works: telemetry to controlled remediation</span>
        </summary>
        <ArchPipeline />
      </details>
    </div>
  );
};
