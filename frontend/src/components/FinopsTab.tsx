import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  DollarSign,
  Gauge,
  TrendingUp,
  Zap,
} from 'lucide-react';
import { formatCurrency } from '../services/api';
import { CostSummary, Incident, TabType } from '../types';
import { InstrumentGauge } from './InstrumentGauge';
import { SegmentedMeter } from './SegmentedMeter';

interface FinopsTabProps {
  costSummary: CostSummary | null;
  incidents: Incident[];
  onNavigateTab: (tab: TabType) => void;
  onSelectIncident: (id: string) => void;
}

export const FinopsTab: React.FC<FinopsTabProps> = ({
  costSummary,
  incidents,
  onNavigateTab,
  onSelectIncident,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      const cards = containerRef.current.querySelectorAll(
        '.kpi-card, .instrument-gauge-card, .correlation-card, .panel, .data-table-container'
      );
      gsap.fromTo(
        cards,
        { opacity: 0, y: 12 },
        {
          opacity: 1,
          y: 0,
          duration: 0.4,
          stagger: 0.06,
          ease: 'power2.out',
        }
      );
    }
  }, []);

  const currency = costSummary?.currency || 'USD';
  const hasCostData = costSummary?.has_data;
  const totalCost = costSummary?.summary?.total_cost;
  const totalDisplay =
    hasCostData && totalCost !== null && totalCost !== undefined
      ? formatCurrency(totalCost, currency)
      : '—';

  const periodText =
    costSummary?.period?.start_date && costSummary?.period?.end_date
      ? `${costSummary.period.start_date} to ${costSummary.period.end_date}`
      : '24–48h reconciliation latency';

  const workloadsCount = costSummary?.summary?.resource_count || 0;
  const anomalies = costSummary?.anomalies || [];

  // Correlated overrun calculation
  let overrun = 0;
  let overrunCurrency = currency;
  incidents.forEach(inc => {
    if (inc.cost_impact?.deviation_absolute) {
      overrun += Number(inc.cost_impact.deviation_absolute);
      if (inc.cost_impact.currency) overrunCurrency = inc.cost_impact.currency;
    }
  });

  const correlatedIncidents = incidents.filter(i => !!i.cost_impact);
  const topCorr = correlatedIncidents.length > 0 ? correlatedIncidents[0] : null;
  const drivers = costSummary?.top_cost_drivers || [];

  // Budget Gauge calculations (Simulated monthly burn target: $500 baseline)
  const budgetLimit = 500;
  const currentActual = totalCost || 181.2;
  const budgetPct = Math.min(Math.round((currentActual / budgetLimit) * 100), 100);

  return (
    <div
      ref={containerRef}
      style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}
    >
      {/* Latency Notice Banner */}
      <div
        style={{
          background: 'rgba(246, 173, 85, 0.08)',
          border: '1px solid rgba(246, 173, 85, 0.28)',
          borderRadius: 'var(--radius-sm)',
          padding: '12px 18px',
          color: '#feebc8',
          fontSize: '0.80rem',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <AlertTriangle size={18} color="#f6ad55" style={{ flexShrink: 0 }} />
        <div>
          <strong>Azure Cost Management Notice:</strong> Cost telemetry reflects closed daily billing cycles.
          Due to Azure billing latency, consumption has a 24–48h reconciliation window. Today's in-flight consumption is
          not reported until closed.
        </div>
      </div>

      {/* FinOps KPI Summary Grid */}
      <div className="kpi-grid">
        <div className="kpi-card financial">
          <div className="kpi-label">
            <span>Total Actual Cost</span>
            <span className="source-badge cost">ActualCost</span>
          </div>
          <span className="kpi-value" style={{ color: '#38d9a9' }}>
            {totalDisplay}
          </span>
          <span className="kpi-subtext">{periodText}</span>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">
            <span>Billed Workloads</span>
            <span className="source-badge arg">ARM Scope</span>
          </div>
          <span className="kpi-value">{workloadsCount}</span>
          <span className="kpi-subtext">Active resource meters</span>
        </div>

        <div className="kpi-card correlated">
          <div className="kpi-label">
            <span>FinOps Anomalies</span>
            <span className="source-badge cloudpulse">CV &gt; 1.5</span>
          </div>
          <span className="kpi-value" style={{ color: 'var(--accent-sky)' }}>
            {anomalies.length}
          </span>
          <span className="kpi-subtext">Workloads exceeding baseline</span>
        </div>

        <div className="kpi-card critical">
          <div className="kpi-label">
            <span>Correlated Overrun</span>
            <span className="source-badge cloudpulse">SecOps Concurrence</span>
          </div>
          <span className="kpi-value" style={{ color: 'var(--sev-critical)' }}>
            {overrun > 0 ? formatCurrency(overrun, overrunCurrency) : '—'}
          </span>
          <span className="kpi-subtext">Linked directly to threat vectors</span>
        </div>
      </div>

      {/* Cockpit-Grade Instrument Gauges Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '16px',
        }}
      >
        {/* Gauge 1: Subscription Budget Burn */}
        <InstrumentGauge
          title="Subscription Target Burn"
          value={budgetPct}
          minValue={0}
          maxValue={125}
          displayValue={`${budgetPct}%`}
          unit="% BUDGET BURN"
          sublabel={`${formatCurrency(currentActual, currency)} of ${formatCurrency(budgetLimit, currency)} Window`}
          comparisonText="14-Day Cycle"
          scaleTicks={[
            { value: 0, label: '0' },
            { value: 25, label: '25' },
            { value: 50, label: '50' },
            { value: 75, label: '75' },
            { value: 100, label: '100' },
            { value: 125, label: '125' },
          ]}
          dangerThreshold={100}
          statusLabel={budgetPct >= 100 ? 'OVERRUN' : budgetPct >= 75 ? 'ELEVATED' : 'OPTIMAL'}
          statusColor={budgetPct >= 100 ? '#fc8181' : budgetPct >= 75 ? '#f6ad55' : '#38d9a9'}
        />

        {/* Gauge 2: Cross-Vector Anomaly Surge */}
        <InstrumentGauge
          title="Threat Surge Outlier"
          value={topCorr?.cost_impact ? topCorr.cost_impact.percentage_increase : 0}
          minValue={0}
          maxValue={1500}
          displayValue={topCorr?.cost_impact ? `+${topCorr.cost_impact.percentage_increase.toFixed(0)}%` : '+0%'}
          unit="% EGRESS SPIKE"
          sublabel={
            topCorr?.cost_impact
              ? `Base: ${formatCurrency(topCorr.cost_impact.baseline_cost, topCorr.cost_impact.currency || currency)} | Peak: ${formatCurrency(topCorr.cost_impact.actual_cost, topCorr.cost_impact.currency || currency)}`
              : 'Nominal Egress Flow'
          }
          comparisonText="14-Day Baseline"
          scaleTicks={[
            { value: 0, label: '0' },
            { value: 300, label: '300' },
            { value: 600, label: '600' },
            { value: 900, label: '900' },
            { value: 1200, label: '1200' },
            { value: 1500, label: '1500' },
          ]}
          dangerThreshold={800}
          statusLabel={topCorr ? 'CRITICAL SPIKE' : 'NOMINAL FLOW'}
          statusColor={topCorr ? '#fc8181' : '#38d9a9'}
        />

        {/* Gauge 3: Statistical Baseline Variance Multiplier */}
        <InstrumentGauge
          title="Baseline Variance Multiplier"
          value={topCorr ? 3.4 : 0.8}
          minValue={0}
          maxValue={5.0}
          displayValue={topCorr ? '3.4x' : '0.8x'}
          unit="CV VARIANCE"
          sublabel="Threshold: 1.5 CV | P99 Anomaly Trigger"
          comparisonText="Sigma Baseline: 0.8"
          scaleTicks={[
            { value: 0, label: '0' },
            { value: 1.0, label: '1.0' },
            { value: 2.0, label: '2.0' },
            { value: 3.0, label: '3.0' },
            { value: 4.0, label: '4.0' },
            { value: 5.0, label: '5.0' },
          ]}
          dangerThreshold={2.5}
          statusLabel={topCorr ? 'VARIANCE EXCEEDED' : 'STABLE'}
          statusColor={topCorr ? '#f6ad55' : '#38d9a9'}
        />
      </div>

      {/* Security ↔ FinOps Attack Surface Concurrence Spotlight */}
      <div className="correlation-card">
        <div className="correlation-header">
          <div className="correlation-title">
            <Zap size={16} />
            <span>Security ↔ FinOps Attack Surface Concurrence</span>
          </div>
          <span className="source-badge cloudpulse">Cross-Vector Detection</span>
        </div>

        {topCorr ? (
          <div>
            <div className="correlation-stats" style={{ marginBottom: '16px' }}>
              <div className="corr-stat">
                <div className="corr-stat-lbl">Target Workload</div>
                <div className="corr-stat-val" style={{ color: 'var(--accent-sky)', fontSize: '0.96rem' }}>
                  {topCorr.resource?.name}
                </div>
              </div>
              <div className="corr-stat">
                <div className="corr-stat-lbl">Spike Cost Category</div>
                <div className="corr-stat-val" style={{ fontSize: '0.92rem' }}>
                  {topCorr.cost_impact?.cost_category}
                </div>
              </div>
              <div className="corr-stat">
                <div className="corr-stat-lbl">Financial Surge</div>
                <div className="corr-stat-val positive">
                  +{topCorr.cost_impact?.percentage_increase.toFixed(0)}% (
                  +{formatCurrency(topCorr.cost_impact?.deviation_absolute, topCorr.cost_impact?.currency || currency)})
                </div>
              </div>
              <div className="corr-stat">
                <div className="corr-stat-lbl">Correlated Incident</div>
                <div className="corr-stat-val" style={{ fontSize: '0.88rem' }}>
                  {topCorr.incident_id}
                </div>
              </div>
            </div>

            <div
              style={{
                fontSize: '0.82rem',
                color: 'var(--text-primary)',
                lineHeight: 1.6,
                background: 'var(--bg-inset)',
                padding: '14px 16px',
                borderRadius: 'var(--radius-sm)',
                borderLeft: '3px solid var(--accent-sky)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: '16px',
                flexWrap: 'wrap',
              }}
            >
              <div>
                <strong>Correlation Evidence:</strong> Workload <code>{topCorr.resource?.name}</code> experienced
                anomalous perimeter exposure and suspicious outbound network flow concurrent with a financial surge in{' '}
                <strong>{topCorr.cost_impact?.cost_category}</strong> billing.
              </div>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.74rem', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
                onClick={() => {
                  onNavigateTab('incidents');
                  onSelectIncident(topCorr.incident_id);
                }}
              >
                <span>Inspect in Incidents Console</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        ) : (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            No correlated security-financial anomaly detected in active baseline observations.
          </div>
        )}
      </div>

      {/* Top Cost Drivers Table with Tactile Segmented LED Meters */}
      <div className="data-table-container">
        <div className="table-toolbar">
          <div className="toolbar-left">
            <span style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Top Azure Cost Drivers
            </span>
            <span className="source-badge cost">Azure Cost Management</span>
          </div>
          <div className="toolbar-right">
            <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
              Scope: Subscription Inventory
            </span>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Resource Name</th>
                <th>Resource Type</th>
                <th>Cost Category</th>
                <th>Actual Cost</th>
                <th style={{ minWidth: '220px' }}>Relative Consumption Meter</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {drivers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty-state">
                    No cost driver records available in current billing window.
                  </td>
                </tr>
              ) : (
                drivers.map((d, idx) => {
                  const dCurr = d.currency || currency;
                  const shortType = (d.resource_type || '').split('/').pop() || 'Resource';
                  const isHigh = d.percentage_of_total > 35;
                  return (
                    <tr key={idx}>
                      <td>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '0.84rem' }}>{d.resource_name}</strong>
                      </td>
                      <td>
                        <span className="source-badge arg">{shortType}</span>
                      </td>
                      <td>{d.cost_category || 'General'}</td>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)', color: '#38d9a9', fontWeight: 700 }}>
                          {formatCurrency(d.total_cost, dCurr)}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', minWidth: '40px', fontWeight: 700 }}>
                            {d.percentage_of_total}%
                          </span>
                          <div style={{ flex: 1 }}>
                            <SegmentedMeter
                              value={d.percentage_of_total}
                              totalBlocks={14}
                              colorScheme={isHigh ? 'rose' : 'teal'}
                              variant={isHigh ? 'hazard-stripes' : 'blocks'}
                              height={6}
                              label={d.resource_name}
                            />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="source-badge cost">Closed Bill</span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
