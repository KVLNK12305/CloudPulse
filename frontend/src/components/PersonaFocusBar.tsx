import React from 'react';
import { ArrowRight, Cloud, DollarSign, Eye, FileText, Layers, Lock, Shield } from 'lucide-react';
import { getPersonaConfig, PERSONA_CONFIGS } from '../services/personaConfig';
import { Incident, OperatorProfile, Persona, TabType } from '../types';

interface PersonaFocusBarProps {
  activePersona: Persona;
  activeOperator?: OperatorProfile;
  incidents?: Incident[];
  resourceCount?: number;
  costTotal?: number;
  costCurrency?: string;
  onPersonaChange: (p: Persona) => void;
  onNavigateTab: (tab: TabType) => void;
  onOpenExportBrief?: () => void;
  azureEnabled?: boolean;
}

export const PersonaFocusBar: React.FC<PersonaFocusBarProps> = ({
  activePersona,
  activeOperator,
  incidents = [],
  resourceCount = 0,
  costTotal,
  costCurrency,
  onPersonaChange,
  onNavigateTab,
  onOpenExportBrief,
  azureEnabled = false,
}) => {
  const config = getPersonaConfig(activePersona, {
    incidents,
    resourceCount,
    costTotal,
    costCurrency,
    azureEnabled,
  });

  const handleActionClick = () => {
    if (activePersona === 'executive' && onOpenExportBrief) {
      onOpenExportBrief();
    } else {
      onNavigateTab(config.focusHighlights.actionTab);
    }
  };

  const personaIcons: Record<Persona, React.ReactNode> = {
    secops: <Shield size={12} />,
    finops: <DollarSign size={12} />,
    platform: <Cloud size={12} />,
    executive: <Layers size={12} />,
  };

  const statusColor = (status: string) =>
    status === 'critical'
      ? 'var(--sev-critical)'
      : status === 'warning'
      ? 'var(--sev-high)'
      : status === 'optimal'
      ? 'var(--accent-teal)'
      : 'var(--accent-sky)';

  return (
    <div className="context-bar" style={{ borderLeft: `3px solid ${config.color}` }}>
      <div className="context-bar-top">
        <span
          className="context-badge"
          style={{ background: `${config.color}1f`, color: config.color, border: `1px solid ${config.color}45` }}
        >
          {personaIcons[activePersona]}
          <span>{config.badge}</span>
        </span>

        <div className="context-directive">{config.directive}</div>

        <div className="segmented" role="tablist" aria-label="Perspective">
          {(['secops', 'finops', 'platform', 'executive'] as Persona[]).map(p => {
            const pCfg = PERSONA_CONFIGS[p];
            const isCurrent = p === activePersona;
            const isAllowed = !activeOperator || activeOperator.isSuperAdmin || activeOperator.allowedPersonas.includes(p);
            return (
              <button
                key={p}
                role="tab"
                aria-selected={isCurrent}
                className={isCurrent ? 'active' : ''}
                disabled={!isAllowed}
                onClick={() => onPersonaChange(p)}
                style={isCurrent ? { color: pCfg.color } : undefined}
                title={isAllowed ? `Switch view to ${pCfg.label}` : 'This perspective is not assigned to your operator profile.'}
              >
                {personaIcons[p]}
                <span>{pCfg.label.split(' ')[0]}</span>
                {!isAllowed && <Lock size={9} />}
              </button>
            );
          })}
        </div>

        <button
          className="btn"
          onClick={handleActionClick}
          style={{
            background: `${config.color}1a`,
            color: config.color,
            border: `1px solid ${config.color}55`,
            fontSize: '0.72rem',
            padding: '5px 12px',
            fontWeight: 700,
            whiteSpace: 'nowrap',
          }}
        >
          {activePersona === 'executive' ? <FileText size={12} /> : <Eye size={12} />}
          <span>{config.focusHighlights.suggestedAction}</span>
          <ArrowRight size={12} />
        </button>
      </div>

      <div className="context-insights">
        {config.keyInsights.map((ins, idx) => (
          <span key={idx} className="context-chip" title={ins.subtext}>
            <span>{ins.label}</span>
            <b style={{ color: statusColor(ins.status) }}>{ins.value}</b>
          </span>
        ))}
      </div>
    </div>
  );
};
