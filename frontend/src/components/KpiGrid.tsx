import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import {
  Activity,
  Bot,
  Cloud,
  DollarSign,
  ShieldAlert,
} from 'lucide-react';
import { formatCurrency } from '../services/api';
import { EstateOverview, Incident, Persona } from '../types';

interface KpiGridProps {
  estateOverview: EstateOverview | null;
  incidents: Incident[];
  resourceCount: number;
  activePersona?: Persona;
}

export const KpiGrid: React.FC<KpiGridProps> = ({
  estateOverview,
  incidents,
  resourceCount,
  activePersona = 'secops',
}) => {
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (gridRef.current) {
      const cards = gridRef.current.querySelectorAll('.kpi-card');
      gsap.fromTo(
        cards,
        { opacity: 0, y: 16, scale: 0.98 },
        {
          opacity: 1,
          y: 0,
          scale: 1,
          duration: 0.45,
          stagger: 0.07,
          ease: 'power2.out',
        }
      );
    }
  }, []);

  // 1. Discovered Resources
  const totalResources = resourceCount || estateOverview?.resources?.total || 0;

  // 2. Actual Billed Cost
  const hasCostData = estateOverview?.costs?.has_data;
  const costTotal = estateOverview?.costs?.total_cost;
  const currency = estateOverview?.costs?.currency || 'USD';
  const costDisplay = hasCostData && costTotal !== null && costTotal !== undefined
    ? formatCurrency(costTotal, currency)
    : '—';
  const costPeriodText = estateOverview?.costs?.latest_usage_date
    ? `Closed billing through ${estateOverview.costs.latest_usage_date}`
    : '14-day evaluation window';

  // 3. Active Incidents
  const openIncidents = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING');
  const openCount = openIncidents.length;
  const totalIncidents = incidents.length;
  const critCount = openIncidents.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;

  // 4. Correlated Incidents
  const correlatedCount = openIncidents.filter(i => !!i.cost_impact).length;

  // 5. AI Triaged Workloads1
  const triagedIncidents = incidents.filter(i => i.ai_analysis && i.ai_analysis.status === 'COMPLETED');
  const triagedCount = triagedIncidents.length;
  const liveTriaged = triagedIncidents.filter(
    i => i.ai_analysis?.execution_mode === 'LIVE' || i.ai_analysis?.provider_status === 'LIVE'
  ).length;
  const fallbackTriaged = triagedCount - liveTriaged;

  let aiTagText = 'Deterministic Fallback';
  let aiTagColor = '#eab308';
  let aiTagBg = 'rgba(234, 179, 8, 0.15)';
  let aiSubtext = 'Grounded offline synthesis';

  if (triagedCount === 0) {
    aiTagText = 'Deterministic Fallback';
    aiTagColor = '#c084fc';
    aiTagBg = 'rgba(168, 85, 247, 0.15)';
    aiSubtext = 'Synthesizer ready';
  } else if (liveTriaged > 0 && fallbackTriaged === 0) {
    aiTagText = 'Azure OpenAI (Live)';
    aiTagColor = '#34d399';
    aiTagBg = 'rgba(52, 211, 153, 0.15)';
    aiSubtext = `Live inference via ${
      triagedIncidents.find(i => i.ai_analysis?.model_identifier)?.ai_analysis?.model_identifier || 'Azure OpenAI'
    }`;
  } else if (liveTriaged > 0 && fallbackTriaged > 0) {
    aiTagText = 'Hybrid (Live + Fallback)';
    aiTagColor = '#38bdf8';
    aiTagBg = 'rgba(56, 189, 248, 0.15)';
    aiSubtext = `${liveTriaged} Live / ${fallbackTriaged} Fallback`;
  }

  return (
    <div className="kpi-grid" ref={gridRef}>
      {/* 1. Resources */}
      <div
        className={`kpi-card inventory ${activePersona === 'platform' ? 'persona-highlight' : ''}`}
        style={
          activePersona === 'platform'
            ? { border: '1px solid #38bdf8', boxShadow: '0 0 18px rgba(56, 189, 248, 0.25)' }
            : {}
        }
      >
        <div className="kpi-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <Cloud size={14} color="#38bdf8" />
            <span>Discovered Resources</span>
          </div>
          {activePersona === 'platform' ? (
            <span
              className="kpi-source-tag"
              style={{ background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.5)', fontWeight: 800 }}
            >
              SRE FOCUS
            </span>
          ) : (
            <span className="kpi-source-tag">Resource Graph</span>
          )}
        </div>
        <span className="kpi-value" style={{ color: '#38bdf8' }}>
          {totalResources}
        </span>
        <span className="kpi-subtext">Actual provisioned estate</span>
      </div>

      {/* 2. Cost */}
      <div
        className={`kpi-card financial ${activePersona === 'finops' ? 'persona-highlight' : ''}`}
        style={
          activePersona === 'finops'
            ? { border: '1px solid #34d399', boxShadow: '0 0 18px rgba(52, 211, 153, 0.25)' }
            : {}
        }
      >
        <div className="kpi-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <DollarSign size={14} color="#34d399" />
            <span>Actual Billed Cost</span>
          </div>
          {activePersona === 'finops' ? (
            <span
              className="kpi-source-tag"
              style={{ background: 'rgba(52, 211, 153, 0.2)', color: '#34d399', borderColor: 'rgba(52, 211, 153, 0.5)', fontWeight: 800 }}
            >
              FINOPS FOCUS
            </span>
          ) : (
            <span className="kpi-source-tag">Cost Management</span>
          )}
        </div>
        <span className="kpi-value" style={{ color: '#34d399' }}>
          {costDisplay}
        </span>
        <span className="kpi-subtext">{costPeriodText}</span>
      </div>

      {/* 3. Incidents */}
      <div
        className={`kpi-card critical ${activePersona === 'secops' ? 'persona-highlight' : ''}`}
        style={
          activePersona === 'secops'
            ? { border: '1px solid #fc8181', boxShadow: '0 0 18px rgba(252, 129, 129, 0.25)' }
            : {}
        }
      >
        <div className="kpi-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <ShieldAlert size={14} color="#fc8181" />
            <span>Active Incidents</span>
          </div>
          {activePersona === 'secops' ? (
            <span
              className="kpi-source-tag"
              style={{ background: 'rgba(252, 129, 129, 0.2)', color: '#fc8181', borderColor: 'rgba(252, 129, 129, 0.5)', fontWeight: 800 }}
            >
              SECOPS PRIORITY
            </span>
          ) : (
            <span className="kpi-source-tag">CloudPulse SecOps</span>
          )}
        </div>
        <span className="kpi-value" style={{ color: openCount === 0 ? '#38d9a9' : '#fc8181' }}>
          {openCount}
        </span>
        <span className="kpi-subtext" style={{ color: openCount === 0 ? 'var(--text-secondary)' : '#fb7185' }}>
          {openCount === 0
            ? totalIncidents > 0
              ? `${totalIncidents} Contained / Resolved`
              : 'Perimeter Nominal · 0 Open'
            : `${critCount} Critical/High priority`}
        </span>
      </div>

      {/* 4. Concurrence */}
      <div
        className={`kpi-card correlated ${activePersona === 'executive' ? 'persona-highlight' : ''}`}
        style={
          activePersona === 'executive'
            ? { border: '1px solid #b794f4', boxShadow: '0 0 18px rgba(183, 148, 244, 0.25)' }
            : {}
        }
      >
        <div className="kpi-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <Activity size={14} color="#06b6d4" />
            <span>SecOps ↔ FinOps</span>
          </div>
          {activePersona === 'executive' ? (
            <span
              className="kpi-source-tag"
              style={{ background: 'rgba(183, 148, 244, 0.2)', color: '#b794f4', borderColor: 'rgba(183, 148, 244, 0.5)', fontWeight: 800 }}
            >
              CISO FOCUS
            </span>
          ) : (
            <span className="kpi-source-tag">Cross-Correlation</span>
          )}
        </div>
        <span className="kpi-value" style={{ color: correlatedCount === 0 ? 'var(--text-secondary)' : '#06b6d4' }}>
          {correlatedCount}
        </span>
        <span className="kpi-subtext">
          {correlatedCount === 0 ? 'Zero Cost Deviations' : 'Security & Cost confluence'}
        </span>
      </div>

      {/* 5. AI Triaged */}
      <div className="kpi-card ai">
        <div className="kpi-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <Bot size={14} color="#c084fc" />
            <span>AI Triaged</span>
          </div>
          <span
            className="kpi-source-tag"
            style={{ background: aiTagBg, color: aiTagColor, borderColor: `${aiTagColor}40` }}
          >
            {aiTagText}
          </span>
        </div>
        <span className="kpi-value" style={{ color: '#c084fc' }}>
          {triagedCount}
        </span>
        <span className="kpi-subtext">{aiSubtext}</span>
      </div>
    </div>
  );
};
