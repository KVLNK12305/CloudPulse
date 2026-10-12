import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  Building,
  Check,
  ChevronDown,
  Cloud,
  Database,
  DollarSign,
  Eye,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Shield,
  User,
  Users,
  Zap,
} from 'lucide-react';
import {
  HealthStatus,
  OperatorProfile,
  Persona,
  TabType,
  TenantScope,
} from '../types';

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
  onUpdateOperatorName?: (name: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  resourceCount,
  openIncidentCount,
  health,
  subscriptionId,
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
}) => {
  const [clock, setClock] = useState<string>('--:--:-- UTC');
  const [tenantDropdownOpen, setTenantDropdownOpen] = useState<boolean>(false);
  const [personaDropdownOpen, setPersonaDropdownOpen] = useState<boolean>(false);
  const [userMenuOpen, setUserMenuOpen] = useState<boolean>(false);

  const tenantRef = useRef<HTMLDivElement>(null);
  const personaRef = useRef<HTMLDivElement>(null);
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
      if (personaRef.current && !personaRef.current.contains(e.target as Node)) {
        setPersonaDropdownOpen(false);
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
    ? 'Volatile'
    : isConnected
    ? 'PostgreSQL'
    : 'In-Memory';

  const personaLabels: Record<Persona, { label: string; color: string; desc: string }> = {
    secops: { label: 'SecOps Commander', color: '#fc8181', desc: 'Threat surface, containment gate' },
    finops: { label: 'FinOps Economist', color: '#38d9a9', desc: 'Unit economics, baseline variance' },
    platform: { label: 'Platform SRE', color: '#63b3ed', desc: 'Topology & ARM state readback' },
    executive: { label: 'Executive CISO', color: '#9f7aea', desc: 'Macro exposure & audit briefs' },
  };

  return (
    <header className="topbar">
      <div className="brand-group">
        <div className="brand" onClick={() => onTabChange('overview')} role="button" tabIndex={0}>
          <div className="brand-icon">
            <Shield size={17} color="#ffffff" strokeWidth={2.5} />
          </div>
          <div>
            <div className="brand-title">CloudPulse</div>
            <div className="brand-subtitle">SecOps · FinOps Platform</div>
          </div>
        </div>

        {/* 1. Tenant & Environment Scope Dropdown */}
        <div style={{ position: 'relative' }} ref={tenantRef}>
          <button
            className="scope-selector-btn"
            onClick={() => setTenantDropdownOpen(prev => !prev)}
            title="Switch Cloud Tenant or Subscription"
          >
            <Building size={12} color="var(--accent-sky)" />
            <span style={{ fontWeight: 700, maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {activeTenant.name}
            </span>
            <span
              style={{
                fontSize: '0.62rem',
                fontFamily: 'var(--font-mono)',
                color: activeTenant.isDemo ? 'var(--accent-violet)' : 'var(--accent-teal)',
                background: activeTenant.isDemo ? 'rgba(159, 122, 234, 0.15)' : 'rgba(56, 217, 169, 0.15)',
                padding: '1px 5px',
                borderRadius: 'var(--radius-xs)',
                fontWeight: 700,
              }}
            >
              {activeTenant.environment.toUpperCase()}
            </span>
            <ChevronDown size={11} color="var(--text-tertiary)" />
          </button>

          {tenantDropdownOpen && (
            <div className="dropdown-menu">
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
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{t.name}</div>
                    <div style={{ fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)' }}>
                      {t.subscriptionId} · {t.region}
                    </div>
                  </div>
                  {t.id === activeTenant.id && (
                    <Check size={13} color="var(--accent-teal)" />
                  )}
                </div>
              ))}

              <div style={{ borderTop: '1px solid var(--border-subtle)', margin: '4px 0' }} />

              <div
                className="dropdown-item connect-action"
                onClick={() => {
                  setTenantDropdownOpen(false);
                  onOpenConnectTenant();
                }}
              >
                <Plus size={13} color="var(--accent-sky)" />
                <span style={{ fontWeight: 700, color: 'var(--accent-sky)' }}>+ Connect Cloud Tenant</span>
              </div>
            </div>
          )}
        </div>

        {/* 2. Primary Navigation Tabs */}
        <nav className="nav-tabs" aria-label="Primary Navigation">
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
      </div>

      <div className="topbar-actions">
        {/* 3. Persona / Role Perspective Selector */}
        <div style={{ position: 'relative' }} ref={personaRef}>
          <button
            className="persona-btn"
            onClick={() => setPersonaDropdownOpen(prev => !prev)}
            title="Switch Operational Persona"
          >
            <Eye size={12} color={personaLabels[activePersona].color} />
            <span style={{ color: personaLabels[activePersona].color }}>
              {personaLabels[activePersona].label}
            </span>
            <ChevronDown size={11} color="var(--text-tertiary)" />
          </button>

          {personaDropdownOpen && (
            <div className="dropdown-menu" style={{ width: '220px' }}>
              <div className="dropdown-header">Operational Persona</div>
              {(Object.keys(personaLabels) as Persona[]).map(p => (
                <div
                  key={p}
                  className={`dropdown-item ${p === activePersona ? 'active' : ''}`}
                  onClick={() => {
                    onPersonaChange(p);
                    setPersonaDropdownOpen(false);
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 700, color: personaLabels[p].color }}>
                      {personaLabels[p].label}
                    </div>
                    <div style={{ fontSize: '0.66rem', color: 'var(--text-tertiary)' }}>
                      {personaLabels[p].desc}
                    </div>
                  </div>
                  {p === activePersona && (
                    <Check size={13} color={personaLabels[p].color} />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 4. Connect Cloud Tenant Button */}
        <button
          className="btn btn-secondary"
          style={{ fontSize: '0.72rem', padding: '5px 10px', gap: '5px' }}
          onClick={onOpenConnectTenant}
          title="Onboard your own Azure or multi-cloud environment"
        >
          <Plus size={12} color="var(--accent-sky)" />
          <span>Connect Cloud</span>
        </button>

        {/* Storage State */}
        <div className="status-pill" title={health?.database?.degradation_reason || storageLabel}>
          <div
            className="status-dot pulse"
            style={{ backgroundColor: storageColor, boxShadow: `0 0 5px ${storageColor}` }}
          />
          <Database size={11} style={{ color: storageColor }} />
          <span>{storageLabel}</span>
        </div>

        {/* Seed Demo Scenario */}
        <button
          className="btn btn-purple"
          onClick={onSeedDemo}
          disabled={isSeeding}
          title="Simulate breach telemetry & cost anomaly"
        >
          {isSeeding ? <RefreshCw size={12} className="spin" /> : <Zap size={12} />}
          <span>{isSeeding ? 'Seeding…' : 'Seed Demo'}</span>
        </button>

        {/* Auto Refresh */}
        <button
          className={`btn ${autoRefresh ? 'btn-accent' : 'btn-secondary'}`}
          onClick={onToggleAutoRefresh}
          title={autoRefresh ? 'Live (15s) — Click to pause' : 'Paused — Click to resume'}
          style={{ minWidth: '70px', padding: '5px 8px' }}
        >
          {autoRefresh ? <Play size={11} /> : <Pause size={11} />}
          <span>{autoRefresh ? 'Live' : 'Paused'}</span>
        </button>

        {/* Manual Refresh */}
        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Reload telemetry"
          style={{ padding: '6px 8px' }}
        >
          <RefreshCw size={12} className={isRefreshing ? 'spin' : ''} />
        </button>

        {/* Active Operator Profile Menu */}
        <div style={{ position: 'relative' }} ref={userRef}>
          <button
            className="operator-pill"
            onClick={() => setUserMenuOpen(prev => !prev)}
            title={`Active Operator: ${activeOperator.name} (${activeOperator.role})`}
          >
            <div className="operator-avatar">
              {activeOperator.name.substring(0, 2).toUpperCase()}
            </div>
            <span style={{ fontWeight: 600, fontSize: '0.72rem' }}>{activeOperator.name}</span>
            <ChevronDown size={10} color="var(--text-tertiary)" />
          </button>

          {userMenuOpen && (
            <div className="dropdown-menu" style={{ right: 0, left: 'auto', width: '210px' }}>
              <div className="dropdown-header">Operator Identity</div>
              <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border-subtle)' }}>
                <div style={{ fontWeight: 800, fontSize: '0.80rem', color: 'var(--text-primary)' }}>
                  {activeOperator.name}
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--accent-sky)' }}>{activeOperator.role}</div>
                <div style={{ fontSize: '0.66rem', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                  {activeOperator.organization}
                </div>
              </div>
              <div
                className="dropdown-item"
                onClick={() => {
                  setUserMenuOpen(false);
                  onOpenConnectTenant();
                }}
              >
                <span>Cloud Settings & Keys</span>
              </div>
              <div
                className="dropdown-item"
                onClick={() => {
                  setUserMenuOpen(false);
                  onTabChange('incidents');
                }}
              >
                <span>Remediation Audit Trail</span>
              </div>
            </div>
          )}
        </div>

        {/* UTC Clock */}
        <div
          style={{
            fontSize: '0.66rem',
            color: 'var(--text-tertiary)',
            fontFamily: 'var(--font-mono)',
            padding: '3px 7px',
            background: 'rgba(0, 0, 0, 0.20)',
            borderRadius: 'var(--radius-xs)',
            border: '1px solid var(--border-subtle)',
            letterSpacing: '0.02em',
          }}
        >
          {clock}
        </div>
      </div>
    </header>
  );
};
