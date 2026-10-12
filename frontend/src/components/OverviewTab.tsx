import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ArrowRight, Cloud, DollarSign, ExternalLink, Zap } from 'lucide-react';
import { formatCurrency } from '../services/api';
import { EstateOverview, Incident, TabType } from '../types';
import { ArchPipeline } from './ArchPipeline';
import { KpiGrid } from './KpiGrid';
import { SegmentedMeter } from './SegmentedMeter';

interface OverviewTabProps {
  estateOverview: EstateOverview | null;
  incidents: Incident[];
  resourceCount: number;
  onNavigateTab: (tab: TabType) => void;
  onSelectIncident: (id: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  estateOverview,
  incidents,
  resourceCount,
  onNavigateTab,
  onSelectIncident,
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

  return (
    <div
      ref={containerRef}
      style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}
    >
      {/* 5 KPI Metric Cards */}
      <KpiGrid
        estateOverview={estateOverview}
        incidents={incidents}
        resourceCount={resourceCount}
      />

      {/* Architectural Telemetry Flow */}
      <ArchPipeline />

      {/* Correlated SecOps ↔ FinOps Concurrence Callout Banner */}
      {topCorr && (
        <div className="correlation-card">
          <div className="correlation-header">
            <div className="correlation-title">
              <Zap size={16} color="var(--accent-sky)" />
              <span>Active Attack Surface Concurrence Spotlight</span>
            </div>
            <span className="source-badge cloudpulse">Cross-Vector Detection</span>
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '16px',
              flexWrap: 'wrap',
            }}
          >
            <div
              style={{
                fontSize: '0.84rem',
                color: 'var(--text-primary)',
                maxWidth: '920px',
                lineHeight: 1.6,
              }}
            >
              Workload{' '}
              <strong style={{ color: 'var(--accent-sky)', fontFamily: 'var(--font-mono)' }}>
                {topCorr.resource?.name}
              </strong>{' '}
              exhibits active threat findings coinciding with a{' '}
              <strong style={{ color: '#fc8181' }}>
                +{topCorr.cost_impact?.percentage_increase.toFixed(0)}%
              </strong>{' '}
              surge in{' '}
              <strong>{topCorr.cost_impact?.cost_category}</strong> billing (+
              {formatCurrency(
                topCorr.cost_impact?.deviation_absolute,
                topCorr.cost_impact?.currency || currency
              )}
              ).
            </div>
            <button
              className="btn btn-accent"
              onClick={() => {
                onNavigateTab('incidents');
                onSelectIncident(topCorr.incident_id);
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <span>Inspect Incident {topCorr.incident_id}</span>
                <ArrowRight size={13} />
              </span>
            </button>
          </div>
        </div>
      )}

      {/* 2-Column Analytics Distribution with Segmented LED Meters */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
          gap: '20px',
        }}
      >
        {/* Left: Resource Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Cloud size={16} color="#38bdf8" />
              <span>Azure Resource Distribution</span>
            </div>
            <span className="source-badge arg">Azure Resource Graph</span>
          </div>
          <div style={{ padding: '20px' }}>
            {typeKeys.length === 0 ? (
              <div className="empty-state">No resources discovered via Azure Resource Graph.</div>
            ) : (
              typeKeys.map(t => {
                const count = byType[t];
                const pct = Math.round((count / totalRes) * 100);
                const shortName = t.split('/').pop() || t;
                return (
                  <div key={t} style={{ marginBottom: '14px' }}>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '0.78rem',
                        marginBottom: '6px',
                      }}
                    >
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-primary)',
                          fontWeight: 600,
                        }}
                      >
                        {shortName}
                      </span>
                      <span
                        style={{
                          color: 'var(--text-secondary)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {count} ({pct}%)
                      </span>
                    </div>
                    <SegmentedMeter
                      value={pct}
                      totalBlocks={18}
                      colorScheme="sky"
                      showSpark={true}
                      height={6}
                      label={shortName}
                    />
                  </div>
                );
              })
            )}
            <div style={{ marginTop: '16px', textAlign: 'right' }}>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.74rem', padding: '5px 12px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                onClick={() => onNavigateTab('resources')}
              >
                <span>View Full Inventory</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>

        {/* Right: Billed Cost by Category */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <DollarSign size={16} color="#38d9a9" />
              <span>Billed Cost by Category</span>
            </div>
            <span className="source-badge cost">Azure Cost Management</span>
          </div>
          <div style={{ padding: '20px' }}>
            {catKeys.length === 0 || totalCost === 0 ? (
              <div className="empty-state">No categorized billing records in current window.</div>
            ) : (
              catKeys.map(c => {
                const costVal = byCat[c];
                const pct = totalCost > 0 ? Math.round((costVal / totalCost) * 100) : 0;
                return (
                  <div key={c} style={{ marginBottom: '14px' }}>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '0.78rem',
                        marginBottom: '6px',
                      }}
                    >
                      <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{c}</span>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          color: '#38d9a9',
                          fontWeight: 700,
                        }}
                      >
                        {formatCurrency(costVal, currency)} ({pct}%)
                      </span>
                    </div>
                    <SegmentedMeter
                      value={pct}
                      totalBlocks={18}
                      colorScheme="multi"
                      showSpark={true}
                      height={6}
                      label={c}
                    />
                  </div>
                );
              })
            )}
            <div style={{ marginTop: '16px', textAlign: 'right' }}>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.74rem', padding: '5px 12px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                onClick={() => onNavigateTab('finops')}
              >
                <span>View FinOps Analysis</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
