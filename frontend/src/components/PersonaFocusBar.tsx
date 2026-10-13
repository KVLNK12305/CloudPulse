import React from 'react';
import {
  ArrowRight,
  Cloud,
  DollarSign,
  Eye,
  FileText,
  Layers,
  Lock,
  Shield,
  Sparkles,
} from 'lucide-react';
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
}) => {
  const config = getPersonaConfig(activePersona, {
    incidents,
    resourceCount,
    costTotal,
    costCurrency,
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

  return (
    <div
      className="persona-focus-bar"
      style={{
        background: `linear-gradient(135deg, ${config.accentBg} 0%, rgba(10, 16, 26, 0.95) 100%)`,
        border: `1px solid ${config.accentBorder}`,
        borderRadius: 'var(--radius-sm)',
        padding: '12px 18px',
        marginBottom: '16px',
        boxShadow: `0 4px 20px rgba(0, 0, 0, 0.35), 0 0 1px ${config.color}30`,
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
        transition: 'all 0.3s ease',
      }}
    >
      {/* Top Line: Perspective Selector Chips + Active Operator Mission */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        {/* Left: Role Pill & Mission Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '3px 9px',
              borderRadius: 'var(--radius-xs)',
              background: `${config.color}20`,
              color: config.color,
              border: `1px solid ${config.color}45`,
              fontSize: '0.70rem',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
            }}
          >
            {personaIcons[activePersona]}
            <span>{config.badge}</span>
          </span>

          <span style={{ fontSize: '0.80rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {config.label} POV
          </span>

          <span style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span>
              ({activeOperator ? activeOperator.name : config.operator.name}
              {activeOperator?.isSuperAdmin ? (
                <span style={{ color: '#f6ad55', fontWeight: 700, marginLeft: 4 }}>
                  · Full Access Super-Admin
                </span>
              ) : (
                ` · ${activeOperator ? activeOperator.role : config.operator.organization}`
              )})
            </span>
            {activeOperator?.isSuperAdmin && (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 3,
                  fontSize: '0.58rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color: '#f6ad55',
                  background: 'rgba(246, 173, 85, 0.15)',
                  border: '1px solid rgba(246, 173, 85, 0.35)',
                  padding: '1px 6px',
                  borderRadius: 'var(--radius-xs)',
                }}
              >
                <Sparkles size={10} color="#f6ad55" />
                <span>FULL ACCESS</span>
              </span>
            )}
          </span>
        </div>

        {/* Right: Quick Perspective Switcher Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', marginRight: '2px' }}>
            Switch Role POV:
          </span>
          {(['secops', 'finops', 'platform', 'executive'] as Persona[]).map(p => {
            const pCfg = getPersonaConfig(p, {
              incidents,
              resourceCount,
              costTotal,
              costCurrency,
            });
            const isCurrent = p === activePersona;
            const isAllowed = !activeOperator || activeOperator.isSuperAdmin || activeOperator.allowedPersonas.includes(p);
            return (
              <button
                key={p}
                onClick={() => onPersonaChange(p)}
                style={{
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-xs)',
                  border: isCurrent ? `1px solid ${pCfg.color}` : '1px solid var(--border-subtle)',
                  background: isCurrent ? `${pCfg.color}25` : 'rgba(255, 255, 255, 0.03)',
                  color: isCurrent ? pCfg.color : isAllowed ? 'var(--text-tertiary)' : 'rgba(255, 255, 255, 0.35)',
                  fontSize: '0.68rem',
                  fontWeight: isCurrent ? 700 : 500,
                  cursor: isAllowed ? 'pointer' : 'not-allowed',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  transition: 'all 0.2s ease',
                  opacity: isAllowed ? 1 : 0.45,
                }}
                title={
                  isAllowed
                    ? `Switch view to ${pCfg.label}${activeOperator?.isSuperAdmin ? ' (Full Access)' : ''}`
                    : `Restricted: Only SecOps Commander (K V L N Kushal) has full access to assume this role.`
                }
              >
                {personaIcons[p]}
                <span>{pCfg.label.split(' ')[0]}</span>
                {!isAllowed && <Lock size={9} />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Middle Line: Dynamic Role Directive & Action Spotlight */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '16px',
          flexWrap: 'wrap',
          paddingTop: '4px',
          borderTop: '1px solid rgba(255, 255, 255, 0.05)',
        }}
      >
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', flex: 1, minWidth: '260px' }}>
          <strong style={{ color: config.color }}>Directive: </strong>
          {config.directive}
        </div>

        {/* Action Spotlight Button */}
        <button
          className="btn"
          onClick={handleActionClick}
          style={{
            background: `${config.color}20`,
            color: config.color,
            border: `1px solid ${config.color}60`,
            fontSize: '0.74rem',
            padding: '5px 12px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontWeight: 700,
            whiteSpace: 'nowrap',
            boxShadow: `0 0 12px ${config.color}15`,
            transition: 'all 0.2s ease',
          }}
        >
          {activePersona === 'executive' ? <FileText size={12} /> : <Eye size={12} />}
          <span>{config.focusHighlights.suggestedAction}</span>
          <ArrowRight size={12} />
        </button>
      </div>

      {/* Bottom Line: 3 Role-Specific Telemetry Insights */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '10px',
          paddingTop: '6px',
        }}
      >
        {config.keyInsights.map((ins, idx) => (
          <div
            key={idx}
            style={{
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: 'var(--radius-xs)',
              padding: '6px 10px',
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.66rem', color: 'var(--text-tertiary)', fontWeight: 600 }}>
                {ins.label}
              </span>
              <span
                style={{
                  fontSize: '0.70rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color:
                    ins.status === 'critical'
                      ? 'var(--sev-critical)'
                      : ins.status === 'warning'
                      ? 'var(--sev-high)'
                      : ins.status === 'optimal'
                      ? 'var(--accent-teal)'
                      : 'var(--accent-sky)',
                }}
              >
                {ins.value}
              </span>
            </div>
            <div style={{ fontSize: '0.66rem', color: 'var(--text-secondary)' }}>{ins.subtext}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
