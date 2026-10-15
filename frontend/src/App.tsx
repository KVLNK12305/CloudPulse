import React, { useCallback, useEffect, useState } from 'react';
import { Sparkles, X } from 'lucide-react';
import { AlertsBanner } from './components/AlertsBanner';
import { AuthModal } from './components/AuthModal';
import { ConnectTenantModal } from './components/ConnectTenantModal';
import { ExportBriefModal } from './components/ExportBriefModal';
import { FinopsTab } from './components/FinopsTab';
import { IncidentsTab } from './components/IncidentsTab';
import { Navbar } from './components/Navbar';
import { OverviewTab } from './components/OverviewTab';
import { PersonaFocusBar } from './components/PersonaFocusBar';
import { ResourceDrawer } from './components/ResourceDrawer';
import { ResourcesTab } from './components/ResourcesTab';
import { ToastContainer } from './components/ToastContainer';
import { LandingPage } from './components/landing/LandingPage';
import { GUEST_OPERATOR, PERSONA_CONFIGS } from './services/personaConfig';
import { api } from './services/api';
import {
  CostSummary,
  EstateOverview,
  HealthStatus,
  Incident,
  OperatorProfile,
  Persona,
  ResourceItem,
  TabType,
  TenantScope,
  ToastMessage,
} from './types';

const OFFLINE_TENANT: TenantScope = {
  id: 'tenant-offline',
  name: 'Offline Demo (Azure decommissioned)',
  subscriptionId: 'no live subscription',
  environment: 'offline',
  region: '—',
  isDemo: true,
};

function tenantFromHealth(health: HealthStatus | null): TenantScope {
  const azure = health?.azure_integration;
  if (azure?.enabled && azure.subscription_id) {
    return {
      id: `tenant-${azure.subscription_id}`,
      name: 'CloudPulse Azure Subscription',
      subscriptionId: azure.subscription_id,
      environment: 'production',
      region: '—',
    };
  }
  return OFFLINE_TENANT;
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [resources, setResources] = useState<ResourceItem[]>([]);
  const [estateOverview, setEstateOverview] = useState<EstateOverview | null>(null);
  const [costSummary, setCostSummary] = useState<CostSummary | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [inspectedResourceId, setInspectedResourceId] = useState<string | null>(null);

  const [apiErrors, setApiErrors] = useState<string[]>([]);
  const [dbDegradedWarning, setDbDegradedWarning] = useState<string | null>(null);

  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isSeeding, setIsSeeding] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  // Multi-user & Enterprise scope state
  const [activePersona, setActivePersona] = useState<Persona>('secops');
  const [connectedTenants, setConnectedTenants] = useState<TenantScope[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState<string | null>(null);
  const [connectTenantModalOpen, setConnectTenantModalOpen] = useState<boolean>(false);
  const [showEvaluatorBanner, setShowEvaluatorBanner] = useState<boolean>(true);

  const [activeOperator, setActiveOperator] = useState<OperatorProfile>(GUEST_OPERATOR);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  // Navigation view mode: 'landing' (pitch-ready landing page) vs 'console' (live dashboard)
  const [viewMode, setViewMode] = useState<'landing' | 'console'>(() => {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname;
      const hash = window.location.hash;
      if (path.includes('/dashboard') && !hash.includes('landing')) {
        return 'console';
      }
    }
    return 'landing';
  });

  const handleLaunchConsole = useCallback(() => {
    setViewMode('console');
    if (typeof window !== 'undefined' && window.history && window.history.pushState) {
      window.history.pushState(null, '', '/dashboard');
    }
  }, []);

  const handleNavigateToLanding = useCallback(() => {
    setViewMode('landing');
    if (typeof window !== 'undefined' && window.history && window.history.pushState) {
      window.history.pushState(null, '', '/#landing');
    }
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      if (window.location.pathname.includes('/dashboard')) {
        setViewMode('console');
      } else {
        setViewMode('landing');
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);
  const [cisoExportBriefOpen, setCisoExportBriefOpen] = useState<boolean>(false);

  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const showToast = useCallback(
    (type: 'info' | 'success' | 'warning' | 'error', title: string, message?: string) => {
      const id = Date.now().toString() + Math.random().toString(36).substring(2, 6);
      setToasts(prev => [...prev, { id, type, title, message }]);
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, 5000);
    },
    []
  );

  const handleAuthenticated = useCallback(
    (user: OperatorProfile) => {
      setActiveOperator(user);
      setIsAuthenticated(true);
      setActivePersona(user.primaryPersona);
      showToast(
        'success',
        `Authenticated: ${user.name}`,
        `Signed in as ${user.role}.${user.isSuperAdmin ? ' Full Access Super-Admin privileges unlocked.' : ''}`
      );
    },
    [showToast]
  );

  const handleSignOut = useCallback(async () => {
    const token = localStorage.getItem('cloudpulse_auth_token') || undefined;
    await api.logout(token);
    localStorage.removeItem('cloudpulse_auth_token');
    localStorage.removeItem('cloudpulse_auth_user');
    setActiveOperator(GUEST_OPERATOR);
    setIsAuthenticated(false);
    showToast('info', 'Signed Out', 'Now viewing as a read-only guest.');
  }, [showToast]);

  const handlePersonaChange = useCallback(
    (newPersona: Persona) => {
      if (activeOperator.isSuperAdmin || activeOperator.allowedPersonas.includes(newPersona)) {
        // Switching perspective never changes who is signed in
        setActivePersona(newPersona);
        const cfg = PERSONA_CONFIGS[newPersona];
        showToast(
          'info',
          activeOperator.isSuperAdmin
            ? `${activeOperator.name} (Full Access) assumed ${cfg.label} POV`
            : `${cfg.label} Perspective Active`,
          cfg.directive
        );
      } else {
        showToast(
          'warning',
          'Role Restricted',
          `This perspective is not assigned to ${activeOperator.name} (${activeOperator.role}).`
        );
      }
    },
    [activeOperator, showToast]
  );

  const dismissToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  // Main Data Loader
  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    const errors: string[] = [];

    const [healthRes, incRes, ovRes, resRes, costRes] = await Promise.allSettled([
      api.fetchHealth(),
      api.fetchIncidents(),
      api.fetchEstateOverview(),
      api.fetchResources(),
      api.fetchCostSummary(),
    ]);

    // Health
    if (healthRes.status === 'fulfilled') {
      setHealth(healthRes.value);
      if (healthRes.value.database?.degraded) {
        setDbDegradedWarning(
          healthRes.value.database.degradation_reason ||
            'PostgreSQL connection failed; running in volatile in-memory fallback.'
        );
      } else {
        setDbDegradedWarning(null);
      }
    } else {
      errors.push('Backend health probe unavailable');
    }

    // Incidents
    if (incRes.status === 'fulfilled') {
      setIncidents(incRes.value);
      if (incRes.value.length > 0) {
        setSelectedIncidentId(prev => prev ?? incRes.value[0].incident_id);
      }
    } else {
      errors.push(incRes.reason?.message || 'Incidents API unreachable');
    }

    // Estate Overview
    if (ovRes.status === 'fulfilled') {
      setEstateOverview(ovRes.value);
    } else {
      errors.push(ovRes.reason?.message || 'Estate Overview API unreachable');
    }

    // When Azure integration is intentionally offline, inventory/billing 503s are expected, not errors
    const azureOffline =
      healthRes.status === 'fulfilled' && healthRes.value.azure_integration?.enabled === false;

    // Resources
    if (resRes.status === 'fulfilled') {
      setResources(resRes.value);
    } else {
      setResources([]);
      if (!azureOffline) errors.push(resRes.reason?.message || 'Resource Graph API unreachable');
    }

    // Cost
    if (costRes.status === 'fulfilled') {
      setCostSummary(costRes.value);
    } else {
      setCostSummary(null);
      if (!azureOffline) errors.push(costRes.reason?.message || 'Azure Cost Management API unreachable');
    }

    setApiErrors(errors);
    setIsRefreshing(false);
  }, []);

  // Initial load
  useEffect(() => {
    loadData();
  }, [loadData]);

  // Session restoration (once)
  useEffect(() => {
    const token = localStorage.getItem('cloudpulse_auth_token');
    if (token) {
      api.fetchSession(token).then(res => {
        if (res.authenticated && res.user) {
          setActiveOperator(res.user);
          setIsAuthenticated(true);
          setActivePersona(res.user.primaryPersona);
          showToast(
            'success',
            `Session Active: ${res.user.name}`,
            `Operating as ${res.user.role}${res.user.isSuperAdmin ? ' (✦ Full Access)' : ''}`
          );
        } else {
          localStorage.removeItem('cloudpulse_auth_token');
          localStorage.removeItem('cloudpulse_auth_user');
        }
      }).catch(() => {});
    }
  }, [showToast]);

  // Polling loop
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadData();
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadData]);

  // Seed Demo Handler
  const handleSeedDemo = async () => {
    setIsSeeding(true);
    showToast('info', 'Ingesting Demo Scenario', 'Simulating multi-vector breach telemetry...');
    try {
      const result = await api.seedDemoScenario();
      await loadData();
      setActiveTab('incidents');
      if (result.correlated) {
        showToast('success', 'Demo Scenario Ingested', 'Multi-vector breach and cost anomaly correlated and triaged.');
      } else {
        showToast(
          'warning',
          'Demo Scenario Ingested',
          'Findings were ingested, but the cost anomaly did not correlate with the security incident.'
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown seeding error';
      showToast('error', 'Demo Seeding Failed', msg);
    } finally {
      setIsSeeding(false);
    }
  };

  const handleIncidentUpdated = (updated: Incident) => {
    setIncidents(prev =>
      prev.map(i => (i.incident_id === updated.incident_id ? updated : i))
    );
  };

  const handleTenantConnected = (newTenant: TenantScope) => {
    setConnectedTenants(prev => [newTenant, ...prev]);
    setSelectedTenantId(newTenant.id);
    showToast(
      'success',
      'Tenant Connected',
      `Connected ${newTenant.name} (${newTenant.subscriptionId}). Initializing discovery.`
    );
  };

  const openIncidentCount = incidents.filter(i => i.status === 'OPEN').length;

  const azureEnabled = health?.azure_integration?.enabled ?? false;
  const baseTenant = tenantFromHealth(health);
  const availableTenants = [...connectedTenants, baseTenant];
  const activeTenant = availableTenants.find(t => t.id === selectedTenantId) || baseTenant;
  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  if (viewMode === 'landing') {
    return (
      <>
        <LandingPage
          onLaunchConsole={handleLaunchConsole}
          onOpenAuth={() => setAuthModalOpen(true)}
          isAuthenticated={isAuthenticated}
          operatorName={isAuthenticated ? activeOperator.name : undefined}
        />

        {/* OTP Authentication Modal */}
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          onAuthenticated={handleAuthenticated}
          activeOperator={activeOperator}
        />

        {/* Toast Notifications */}
        <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      </>
    );
  }

  return (
    <>
      <Navbar
        activeTab={activeTab}
        onTabChange={tab => {
          setActiveTab(tab);
          if (tab === 'incidents' && !selectedIncidentId && incidents.length > 0) {
            setSelectedIncidentId(incidents[0].incident_id);
          }
        }}
        resourceCount={resources.length}
        openIncidentCount={openIncidentCount}
        health={health}
        subscriptionId={estateOverview?.subscription_id ?? undefined}
        isSeeding={isSeeding}
        onSeedDemo={handleSeedDemo}
        isRefreshing={isRefreshing}
        onRefresh={loadData}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh(prev => !prev)}
        activePersona={activePersona}
        onPersonaChange={handlePersonaChange}
        activeTenant={activeTenant}
        availableTenants={availableTenants}
        onTenantChange={t => {
          setSelectedTenantId(t.id);
          showToast('info', 'Tenant Scope Switched', `Active scope: ${t.name}`);
        }}
        onOpenConnectTenant={azureEnabled ? () => setConnectTenantModalOpen(true) : undefined}
        activeOperator={activeOperator}
        isAuthenticated={isAuthenticated}
        onSignOut={handleSignOut}
        onOpenAuthModal={() => setAuthModalOpen(true)}
        onNavigateToLanding={handleNavigateToLanding}
      />

      <main className="app-container">
        {/* Role-Based Point-of-View (POV) Focus Directive Bar */}
        <PersonaFocusBar
          activePersona={activePersona}
          activeOperator={activeOperator}
          incidents={incidents}
          resourceCount={resources.length}
          costTotal={estateOverview?.costs?.total_cost ?? undefined}
          costCurrency={estateOverview?.costs?.currency}
          azureEnabled={azureEnabled}
          onPersonaChange={handlePersonaChange}
          onNavigateTab={tab => setActiveTab(tab)}
          onOpenExportBrief={() => {
            if (incidents.length > 0) {
              setCisoExportBriefOpen(true);
            } else {
              showToast(
                'info',
                'Estate Perimeter Nominal',
                'Zero active incidents to export. Generate an incident brief after seeding demo telemetry.'
              );
            }
          }}
        />

        {/* Pitch-Ready Evaluator & Multi-User Welcome Banner */}
        {showEvaluatorBanner && (
          <div
            className="evaluator-banner"
            style={{
              background: 'linear-gradient(90deg, rgba(99, 179, 237, 0.08), rgba(159, 122, 234, 0.08))',
              border: '1px solid rgba(99, 179, 237, 0.25)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px 18px',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '16px',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: '1 1 0', minWidth: 0 }}>
              <Sparkles size={18} color="var(--accent-sky)" style={{ flexShrink: 0 }} />
              <div style={{ fontSize: '0.80rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                <strong>CloudPulse Autonomous SecOps & FinOps Platform:</strong> Built for security commanders,
                cloud economists, and platform teams. Currently inspecting{' '}
                <strong style={{ color: 'var(--accent-sky)' }}>{activeTenant.name}</strong>.{' '}
                {azureEnabled
                  ? <>Switch perspective using the role selector in the top bar, or click <strong>Connect Cloud</strong> to onboard your own Azure tenant.</>
                  : <>The Azure estate has been decommissioned, so inventory, billing and metrics are unavailable and remediation is disabled. Sign in as SecOps and use <strong>Seed Demo</strong> to explore detection, correlation and AI triage offline.</>}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {azureEnabled && (
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: '0.72rem', padding: '4px 10px' }}
                  onClick={() => setConnectTenantModalOpen(true)}
                >
                  + Connect Your Azure Tenant
                </button>
              )}
              <button
                onClick={() => setShowEvaluatorBanner(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-tertiary)',
                  cursor: 'pointer',
                  padding: '4px',
                }}
                title="Dismiss banner"
              >
                <X size={14} />
              </button>
            </div>
          </div>
        )}

        {/* Dynamic Alerts Banner */}
        <AlertsBanner
          dbDegradedWarning={dbDegradedWarning}
          apiErrors={apiErrors}
          onRetry={loadData}
        />

        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <OverviewTab
            estateOverview={estateOverview}
            incidents={incidents}
            resourceCount={resources.length}
            onNavigateTab={tab => setActiveTab(tab)}
            onSelectIncident={id => {
              setSelectedIncidentId(id);
              setActiveTab('incidents');
            }}
            activePersona={activePersona}
          />
        )}

        {/* Tab 2: Resources */}
        {activeTab === 'resources' && (
          <ResourcesTab
            resources={resources}
            onInspectResource={id => setInspectedResourceId(id)}
            activePersona={activePersona}
          />
        )}

        {/* Tab 3: Cost & FinOps */}
        {activeTab === 'finops' && (
          <FinopsTab
            costSummary={costSummary}
            azureEnabled={azureEnabled}
            incidents={incidents}
            onNavigateTab={tab => setActiveTab(tab)}
            onSelectIncident={id => {
              setSelectedIncidentId(id);
              setActiveTab('incidents');
            }}
            activePersona={activePersona}
          />
        )}

        {/* Tab 4: Incidents */}
        {activeTab === 'incidents' && (
          <IncidentsTab
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={id => setSelectedIncidentId(id)}
            onIncidentUpdated={handleIncidentUpdated}
            onShowToast={showToast}
            activeOperator={activeOperator}
            activePersona={activePersona}
            remediationEnabled={health?.azure_integration?.remediation_enabled ?? false}
          />
        )}
      </main>

      {/* Slide-over Deep Resource Drawer */}
      <ResourceDrawer
        isOpen={!!inspectedResourceId}
        resourceId={inspectedResourceId}
        onClose={() => setInspectedResourceId(null)}
        onSelectIncident={id => {
          setSelectedIncidentId(id);
          setActiveTab('incidents');
        }}
      />

      {/* Onboard / Connect Tenant Wizard Modal */}
      <ConnectTenantModal
        isOpen={connectTenantModalOpen}
        onClose={() => setConnectTenantModalOpen(false)}
        onTenantConnected={handleTenantConnected}
      />

      {/* 1-Click Executive CISO Export Brief Modal */}
      {cisoExportBriefOpen && selectedIncident && (
        <ExportBriefModal
          isOpen={cisoExportBriefOpen}
          incident={selectedIncident}
          onClose={() => setCisoExportBriefOpen(false)}
          onShowToast={showToast}
        />
      )}

      {/* OTP Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthenticated={handleAuthenticated}
        activeOperator={activeOperator}
      />

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </>
  );
};

export default App;
