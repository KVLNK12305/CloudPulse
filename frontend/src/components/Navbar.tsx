import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  Building,
  Check,
  ChevronDown,
  Cloud,
  Database,
  DollarSign,
  Key,
  Lock,
  Plus,
  RefreshCw,
  Shield,
  Sparkles,
  Zap,
} from 'lucide-react';
import {
  HealthStatus,
  OperatorProfile,
  Persona,
  TabType,
  TenantScope,
} from '../types';
import { OPERATOR_TEAM, PERSONA_CONFIGS } from '../services/personaConfig';

interface NavbarProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  resourceCount: number;
  openIncidentCount: number;
  health: HealthStatus | null;
  subscriptionId?: string;
  isSeeding: boolean;
  onSeedDemo: () => void;
  isRefreshing: boolean;
  onRefresh: () => void;
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  // Multi-user & Scope props
  activePersona: Persona;
  onPersonaChange: (p: Persona) => void;
  activeTenant: TenantScope;
  availableTenants: TenantScope[];
  onTenantChange: (t: TenantScope) => void;
  onOpenConnectTenant: () => void;
  activeOperator: OperatorProfile;
  availableOperators?: OperatorProfile[];
  onOperatorChange?: (op: OperatorProfile) => void;
  onOpenAuthModal?: () => void;
  onUpdateOperatorName?: (name: string) => void;
}

const PERSONA_LABELS: Record<
  Persona,
  { label: string; short: string; color: string; desc: string; roleTag: string }
> = {
  secops: {
    label: 'SecOps Commander',
    short: 'SECOPS',
    color: '#fc8181',
    desc: 'Threat surface, containment gate',
    roleTag: 'SECOPS',
  },
  finops: {
    label: 'FinOps Economist',
    short: 'FINOPS',
    color: '#38d9a9',
    desc: 'Unit economics, baseline variance',
    roleTag: 'FINOPS',
  },
  platform: {
    label: 'Platform SRE',
    short: 'SRE',
    color: '#63b3ed',
    desc: 'Topology & ARM state readback',
    roleTag: 'SRE',
  },
  executive: {
    label: 'Executive CISO',
    short: 'CISO',
    color: '#9f7aea',
    desc: 'Macro exposure & audit briefs',
    roleTag: 'CISO',
  },
};

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  resourceCount,
  openIncidentCount,
  health,
  isSeeding,
  onSeedDemo,
  isRefreshing,
  onRefresh,
  autoRefresh,
  onToggleAutoRefresh,
  activePersona,
  onPersonaChange,
  activeTenant,
  availableTenants,
  onTenantChange,
  onOpenConnectTenant,
  activeOperator,
  availableOperators = OPERATOR_TEAM,
  onOperatorChange,
  onOpenAuthModal,
}) => {
  const [clock, setClock] = useState<string>('--:--:-- UTC');
  const [tenantDropdownOpen, setTenantDropdownOpen] = useState<boolean>(false);
  const [userMenuOpen, setUserMenuOpen] = useState<boolean>(false);

  const tenantRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setClock(now.toISOString().substring(11, 19) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (tenantRef.current && !tenantRef.current.contains(e.target as Node)) {
        setTenantDropdownOpen(false);
      }
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isDegraded = health?.database?.degraded;
  const isConnected = health?.database?.connected;

  const storageColor = isDegraded ? '#f6ad55' : isConnected ? '#38d9a9' : '#63b3ed';
  const storageLabel = isDegraded
    ? 'Volatile (Degraded)'
    : isConnected
    ? 'PostgreSQL'
    : 'In-Memory Cache';

  const currentPersona = PERSONA_LABELS[activePersona] || PERSONA_LABELS.secops;

  return (
    <header className="topbar">
      {/* ── Zone 1: Brand & Scope (Left) ── */}
      <div className="topbar-zone topbar-zone-left">
        <div
          className="brand"
          onClick={() => onTabChange('overview')}
          role="button"
          tabIndex={0}
          title="CloudPulse Home"
        >
          <div className="brand-icon">
            <Shield size={17} color="#ffffff" strokeWidth={2.5} />
          </div>
          <div>
            <div className="brand-title">CloudPulse</div>
            <div className="brand-subtitle">SecOps · FinOps</div>
          </div>
        </div>

        <div className="topbar-divider" />

        {/* Tenant Scope Selector Dropdown */}
        <div style={{ position: 'relative' }} ref={tenantRef}>
          <button
            className="scope-selector-btn"
            onClick={() => setTenantDropdownOpen(prev => !prev)}
            title="Switch Cloud Tenant or Subscription"
            aria-expanded={tenantDropdownOpen}
          >
            <Building size={12} color="var(--accent-sky)" />
            <span className="scope-name">{activeTenant.name}</span>
            <span
              className="scope-env-tag"
              style={{
                color: activeTenant.isDemo ? 'var(--accent-violet)' : 'var(--accent-teal)',
                background: activeTenant.isDemo ? 'rgba(159, 122, 234, 0.15)' : 'rgba(56, 217, 169, 0.15)',
              }}
            >
              {activeTenant.environment.toUpperCase()}
            </span>
            <ChevronDown size={11} color="var(--text-tertiary)" />
          </button>

          {tenantDropdownOpen && (
            <div className="dropdown-menu scope-dropdown">
              <div className="dropdown-header">Active Cloud Subscriptions</div>
              {availableTenants.map(t => (
                <div
                  key={t.id}
                  className={`dropdown-item ${t.id === activeTenant.id ? 'active' : ''}`}
                  onClick={() => {
                    onTenantChange(t);
                    setTenantDropdownOpen(false);
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.76rem' }}>
                      {t.name}
                    </div>
                    <div style={{ fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)' }}>
                      {t.subscriptionId} · {t.region}
                    </div>
                  </div>
                  {t.id === activeTenant.id && (
                    <Check size={13} color="var(--accent-teal)" />
                  )}
                </div>
              ))}

              <div className="dropdown-divider" />

              <div
                className="dropdown-item connect-action"
                onClick={() => {
                  setTenantDropdownOpen(false);
                  onOpenConnectTenant();
                }}
              >
                <Plus size={13} color="var(--accent-sky)" />
                <span style={{ fontWeight: 700, color: 'var(--accent-sky)', fontSize: '0.74rem' }}>
                  + Connect Cloud Tenant
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Zone 2: Navigation Tabs (Center) ── */}
      <nav className="nav-tabs topbar-zone-center" aria-label="Primary Navigation">
        <button
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => onTabChange('overview')}
        >
          <Activity size={13} />
          <span>Overview</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'resources' ? 'active' : ''}`}
          onClick={() => onTabChange('resources')}
        >
          <Cloud size={13} />
          <span>Resources</span>
          {resourceCount > 0 && (
            <span className="tab-badge" style={{ background: 'rgba(99, 179, 237, 0.16)', color: '#63b3ed' }}>
              {resourceCount}
            </span>
          )}
        </button>

        <button
          className={`nav-tab ${activeTab === 'finops' ? 'active' : ''}`}
          onClick={() => onTabChange('finops')}
        >
          <DollarSign size={13} />
          <span>Cost & FinOps</span>
        </button>

        <button
          className={`nav-tab ${activeTab === 'incidents' ? 'active' : ''}`}
          onClick={() => onTabChange('incidents')}
        >
          <Shield size={13} />
          <span>Incidents</span>
          {openIncidentCount > 0 && (
            <span className="tab-badge" style={{ background: 'rgba(252, 129, 129, 0.16)', color: '#fc8181' }}>
              {openIncidentCount}
            </span>
          )}
        </button>
      </nav>

      {/* ── Zone 3: Operations, Telemetry & Operator (Right) ── */}
      <div className="topbar-zone topbar-zone-right">
        {/* Seed Demo Scenario Action */}
        <button
          className="btn-seed-compact"
          onClick={onSeedDemo}
          disabled={isSeeding}
          title="Simulate breach telemetry & cost anomaly for evaluation"
        >
          {isSeeding ? <RefreshCw size={11} className="spin" /> : <Zap size={11} />}
          <span>{isSeeding ? 'Seeding…' : 'Seed Demo'}</span>
        </button>

        {/* Unified Telemetry Stream Capsule */}
        <div
          className="telemetry-capsule"
          title={`Telemetry Stream: ${autoRefresh ? 'Active (every 15s)' : 'Paused'} | Storage: ${storageLabel}`}
        >
          <button
            className="telemetry-live-btn"
            onClick={onToggleAutoRefresh}
            title={autoRefresh ? 'Telemetry polling active (15s) — Click to pause' : 'Telemetry polling paused — Click to resume'}
          >
            <span
              className={`status-dot ${autoRefresh ? 'pulse' : ''}`}
              style={{
                backgroundColor: autoRefresh ? '#38d9a9' : '#f6ad55',
                boxShadow: autoRefresh ? '0 0 6px #38d9a9' : 'none',
              }}
            />
            <span className="telemetry-state-text">{autoRefresh ? 'LIVE' : 'PAUSED'}</span>
            <span className="telemetry-rate-badge">{autoRefresh ? '15s' : 'OFF'}</span>
          </button>

          <div className="telemetry-capsule-divider" />

          <button
            className="telemetry-refresh-btn"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Instant telemetry reload"
            aria-label="Refresh telemetry data"
          >
            <RefreshCw size={11} className={isRefreshing ? 'spin' : ''} />
          </button>
        </div>

        <div className="topbar-divider" />

        {/* Unified Operator Identity & Perspective Capsule */}
        <div style={{ position: 'relative' }} ref={userRef}>
          <button
            className="operator-pill"
            onClick={() => setUserMenuOpen(prev => !prev)}
            title={`Active Operator: ${activeOperator.name} (${activeOperator.role}) ${activeOperator.isSuperAdmin ? '— Full Access Unlocked' : ''}`}
            aria-expanded={userMenuOpen}
          >
            <div
              className="operator-avatar"
              style={{
                background: activeOperator.isSuperAdmin
                  ? 'linear-gradient(135deg, #f6ad55, #fc8181)'
                  : 'linear-gradient(135deg, #63b3ed, #9f7aea)',
                boxShadow: activeOperator.isSuperAdmin ? '0 0 8px rgba(246, 173, 85, 0.4)' : 'none',
              }}
            >
              {activeOperator.initials}
            </div>
            <div className="operator-pill-meta">
              <span className="operator-name">{activeOperator.name}</span>
              <span
                className="operator-role-tag"
                style={{
                  color: currentPersona.color,
                  backgroundColor: `${currentPersona.color}18`,
                  borderColor: `${currentPersona.color}35`,
                }}
              >
                {currentPersona.short}
              </span>
              {activeOperator.isSuperAdmin && (
                <span
                  style={{
                    fontSize: '0.54rem',
                    fontWeight: 800,
                    fontFamily: 'var(--font-mono)',
                    color: '#f6ad55',
                    background: 'rgba(246, 173, 85, 0.15)',
                    border: '1px solid rgba(246, 173, 85, 0.35)',
                    padding: '0 5px',
                    borderRadius: 'var(--radius-xs)',
                    letterSpacing: '0.04em',
                  }}
                  title="SecOps Super-Admin: Unrestricted access to assume any role"
                >
                  FULL ACCESS
                </span>
              )}
            </div>
            <ChevronDown size={10} color="var(--text-tertiary)" />
          </button>

          {userMenuOpen && (
            <div className="dropdown-menu operator-dropdown" style={{ right: 0, left: 'auto', minWidth: '310px' }}>
              {/* Operator Identity Header */}
              <div className="operator-dropdown-header">
                <div
                  className="operator-avatar"
                  style={{
                    width: 32,
                    height: 32,
                    fontSize: '0.74rem',
                    background: activeOperator.isSuperAdmin
                      ? 'linear-gradient(135deg, #f6ad55, #fc8181)'
                      : 'linear-gradient(135deg, #63b3ed, #9f7aea)',
                    boxShadow: activeOperator.isSuperAdmin ? '0 0 10px rgba(246, 173, 85, 0.35)' : 'none',
                  }}
                >
                  {activeOperator.initials}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 800, fontSize: '0.84rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{activeOperator.name}</span>
                    {activeOperator.isSuperAdmin && (
                      <span
                        style={{
                          fontSize: '0.54rem',
                          fontWeight: 800,
                          fontFamily: 'var(--font-mono)',
                          color: '#f6ad55',
                          background: 'rgba(246, 173, 85, 0.15)',
                          border: '1px solid rgba(246, 173, 85, 0.35)',
                          padding: '1px 5px',
                          borderRadius: 'var(--radius-xs)',
                        }}
                      >
                        FULL ACCESS
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--accent-sky)' }}>
                    {activeOperator.role}
                  </div>
                  <div style={{ fontSize: '0.64rem', color: 'var(--text-tertiary)', marginTop: '1px' }}>
                    {activeOperator.organization}
                  </div>
                </div>
              </div>

              {/* Privilege Elevation Banner */}
              <div
                style={{
                  margin: '6px 6px 4px',
                  padding: '5px 8px',
                  borderRadius: 'var(--radius-xs)',
                  background: activeOperator.isSuperAdmin ? 'rgba(246, 173, 85, 0.08)' : 'rgba(255, 255, 255, 0.03)',
                  border: `1px solid ${activeOperator.isSuperAdmin ? 'rgba(246, 173, 85, 0.25)' : 'var(--border-subtle)'}`,
                  fontSize: '0.64rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  color: activeOperator.isSuperAdmin ? '#f6ad55' : 'var(--text-tertiary)',
                }}
              >
                {activeOperator.isSuperAdmin ? (
                  <>
                    <Sparkles size={11} color="#f6ad55" />
                    <span>SecOps Super-Admin: Unrestricted permission to assume any role.</span>
                  </>
                ) : (
                  <>
                    <Lock size={10} />
                    <span>Role-restricted operator. Cross-domain elevation requires SecOps.</span>
                  </>
                )}
              </div>

              {/* Team Members Switcher */}
              <div className="dropdown-section-title">Team Operators (Switch User)</div>
              {availableOperators.map(op => {
                const isCurrent = op.id === activeOperator.id;
                return (
                  <div
                    key={op.id}
                    className={`dropdown-item ${isCurrent ? 'active' : ''}`}
                    onClick={() => {
                      onOperatorChange?.(op);
                    }}
                    style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px' }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div
                        className="operator-avatar"
                        style={{
                          width: 22,
                          height: 22,
                          fontSize: '0.60rem',
                          background: op.isSuperAdmin
                            ? 'linear-gradient(135deg, #f6ad55, #fc8181)'
                            : 'linear-gradient(135deg, #63b3ed, #9f7aea)',
                        }}
                      >
                        {op.initials}
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '0.74rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span>{op.name}</span>
                          {op.isSuperAdmin && (
                            <span
                              style={{
                                fontSize: '0.52rem',
                                fontFamily: 'var(--font-mono)',
                                color: '#f6ad55',
                                fontWeight: 800,
                              }}
                            >
                              ★ FULL ACCESS
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.62rem', color: 'var(--text-tertiary)' }}>
                          {op.role}
                        </div>
                      </div>
                    </div>
                    {isCurrent && <Check size={12} color="var(--accent-teal)" />}
                  </div>
                );
              })}

              <div className="dropdown-divider" />

              {/* Perspective (POV) Selector */}
              <div className="dropdown-section-title">
                Operational Perspective (POV)
                {activeOperator.isSuperAdmin ? (
                  <span style={{ color: '#f6ad55', fontWeight: 700, fontSize: '0.58rem', marginLeft: 6 }}>
                    (All Roles Unlocked)
                  </span>
                ) : (
                  <span style={{ color: 'var(--text-tertiary)', fontWeight: 500, fontSize: '0.58rem', marginLeft: 6 }}>
                    (SecOps Exclusive)
                  </span>
                )}
              </div>
              {(Object.keys(PERSONA_LABELS) as Persona[]).map(p => {
                const conf = PERSONA_LABELS[p];
                const isSelected = p === activePersona;
                const isAllowed = activeOperator.isSuperAdmin || activeOperator.allowedPersonas.includes(p);
                return (
                  <div
                    key={p}
                    className={`dropdown-item ${isSelected ? 'active' : ''}`}
                    style={{
                      opacity: isAllowed ? 1 : 0.45,
                      cursor: isAllowed ? 'pointer' : 'not-allowed',
                      padding: '6px 10px',
                    }}
                    onClick={() => {
                      if (isAllowed) {
                        onPersonaChange(p);
                        setUserMenuOpen(false);
                      }
                    }}
                    title={
                      isAllowed
                        ? `Switch perspective to ${conf.label}`
                        : `Restricted: Only SecOps Commander (K V L N Kushal) has full-access elevation to switch into all roles.`
                    }
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span
                        style={{
                          width: 7,
                          height: 7,
                          borderRadius: '50%',
                          backgroundColor: conf.color,
                          flexShrink: 0,
                          boxShadow: isSelected ? `0 0 6px ${conf.color}` : 'none',
                        }}
                      />
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '0.74rem', color: conf.color, display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span>{conf.label}</span>
                          {!isAllowed && <Lock size={10} color="var(--text-tertiary)" />}
                        </div>
                        <div style={{ fontSize: '0.62rem', color: 'var(--text-tertiary)' }}>
                          {conf.desc}
                        </div>
                      </div>
                    </div>
                    {isSelected && <Check size={12} color={conf.color} />}
                  </div>
                );
              })}

              <div className="dropdown-divider" />

              {/* Cloud Infrastructure Info */}
              <div className="dropdown-section-title">Cloud Infrastructure</div>
              <div className="dropdown-info-row">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Database size={11} style={{ color: storageColor }} />
                  <span style={{ fontSize: '0.70rem', color: 'var(--text-secondary)' }}>Storage Engine</span>
                </div>
                <span
                  style={{
                    fontSize: '0.66rem',
                    fontFamily: 'var(--font-mono)',
                    color: storageColor,
                    fontWeight: 700,
                  }}
                >
                  {storageLabel}
                </span>
              </div>

              <div className="dropdown-divider" />

              {/* Quick Actions */}
              <div
                className="dropdown-item connect-action"
                onClick={() => {
                  setUserMenuOpen(false);
                  onOpenConnectTenant();
                }}
              >
                <Plus size={12} color="var(--accent-sky)" />
                <span style={{ fontWeight: 700, color: 'var(--accent-sky)', fontSize: '0.74rem' }}>
                  Connect Cloud Tenant…
                </span>
              </div>
              <div
                className="dropdown-item"
                onClick={() => {
                  setUserMenuOpen(false);
                  onOpenAuthModal?.();
                }}
              >
                <Key size={12} color="var(--accent-sky)" />
                <span style={{ fontSize: '0.74rem' }}>Operator Login / Verify OTP…</span>
              </div>
              <div
                className="dropdown-item"
                onClick={() => {
                  setUserMenuOpen(false);
                  onTabChange('incidents');
                }}
              >
                <Shield size={12} color="var(--accent-rose)" />
                <span style={{ fontSize: '0.74rem' }}>Remediation Audit Trail</span>
              </div>
            </div>
          )}
        </div>

        {/* Minimal UTC Monospace Clock */}
        <div className="topbar-clock" title="Coordinated Universal Time (UTC)">
          {clock}
        </div>
      </div>
    </header>
  );
};
