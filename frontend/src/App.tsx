import React, { useCallback, useEffect, useState } from 'react';
import {
  Compass,
  ExternalLink,
  Info,
  Shield,
  Sparkles,
  Users,
  X,
  Zap,
} from 'lucide-react';
import { ActionModal } from './components/ActionModal';
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
import { OPERATOR_TEAM, PERSONA_CONFIGS } from './services/personaConfig';
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

const defaultTenants: TenantScope[] = [
  {
    id: 'tenant-demo',
    name: 'CloudPulse Demo Sandbox',
    subscriptionId: 'sub-6fa109-sandbox',
    environment: 'sandbox',
    region: 'eastus',
    isDemo: true,
  },
  {
    id: 'tenant-prod',
    name: 'Acme Corp Production',
    subscriptionId: 'c9b3e102-45a8-4b71-923f-110022334455',
    environment: 'production',
    region: 'eastus',
  },
  {
    id: 'tenant-staging',
    name: 'Global QA & Staging',
    subscriptionId: '8fa32100-3321-410a-8abc-ff0011223344',
    environment: 'staging',
    region: 'westeurope',
  },
];

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
  const [availableTenants, setAvailableTenants] = useState<TenantScope[]>(defaultTenants);
  const [activeTenant, setActiveTenant] = useState<TenantScope>(defaultTenants[0]);
  const [connectTenantModalOpen, setConnectTenantModalOpen] = useState<boolean>(false);
  const [showEvaluatorBanner, setShowEvaluatorBanner] = useState<boolean>(true);

  const [availableOperators] = useState<OperatorProfile[]>(OPERATOR_TEAM);
  const [activeOperator, setActiveOperator] = useState<OperatorProfile>(OPERATOR_TEAM[0]);
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

  const handleOperatorChange = useCallback(
    (newOp: OperatorProfile) => {
      setActiveOperator(newOp);
      if (newOp.isSuperAdmin) {
        showToast(
          'success',
          `${newOp.name} Active (Full Access)`,
          'SecOps super-admin elevation granted: Unrestricted permissions to audit and assume any role across the estate.'
        );
      } else {
        setActivePersona(newOp.primaryPersona);
        const cfg = PERSONA_CONFIGS[newOp.primaryPersona];
        showToast(
          'info',
          `${newOp.name} Active`,
          `Assigned domain: ${newOp.role}. Switched to ${cfg.label} perspective.`
        );
      }
    },
    [showToast]
  );

  const handlePersonaChange = useCallback(
    (newPersona: Persona) => {
      if (activeOperator.isSuperAdmin || activeOperator.allowedPersonas.includes(newPersona)) {
        setActivePersona(newPersona);
        const cfg = PERSONA_CONFIGS[newPersona];
        if (!activeOperator.isSuperAdmin) {
          setActiveOperator(cfg.operator);
        }
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
          `Only SecOps Commander (K V L N Kushal) has full-access elevation to switch into all roles. Operating as ${activeOperator.name} (${activeOperator.role}).`
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
      if (!selectedIncidentId && incRes.value.length > 0) {
        setSelectedIncidentId(incRes.value[0].incident_id);
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

    // Resources
    if (resRes.status === 'fulfilled') {
      setResources(resRes.value);
    } else {
      errors.push(resRes.reason?.message || 'Resource Graph API unreachable');
    }

    // Cost
    if (costRes.status === 'fulfilled') {
      setCostSummary(costRes.value);
    } else {
      errors.push(costRes.reason?.message || 'Azure Cost Management API unreachable');
    }

    setApiErrors(errors);
    setIsRefreshing(false);
  }, [selectedIncidentId]);

  // Initial load & session restoration
  useEffect(() => {
    loadData();

    // Check for saved auth session
    const token = localStorage.getItem('cloudpulse_auth_token');
    if (token) {
      api.fetchSession(token).then(res => {
        if (res.authenticated && res.user) {
          setActiveOperator(res.user);
          setActivePersona(res.user.primaryPersona);
          showToast(
            'success',
            `Session Active: ${res.user.name}`,
            `Operating as ${res.user.role}${res.user.isSuperAdmin ? ' (✦ Full Access)' : ''}`
          );
        }
      }).catch(() => {});
    }
  }, [loadData, showToast]);

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
      await api.seedDemoScenario();
      await loadData();
      setActiveTab('incidents');
      showToast(
        'success',
        'Demo Scenario Ingested',
        'Multi-vector breach and cost anomaly correlated and triaged.'
      );
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
    setAvailableTenants(prev => [newTenant, ...prev]);
    setActiveTenant(newTenant);
    showToast(
      'success',
      'Tenant Connected',
      `Connected ${newTenant.name} (${newTenant.subscriptionId}). Initializing discovery.`
    );
  };

  const openIncidentCount = incidents.filter(i => i.status === 'OPEN').length;

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
        subscriptionId={estateOverview?.subscription_id}
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
          setActiveTenant(t);
          showToast('info', 'Tenant Scope Switched', `Active scope: ${t.name}`);
        }}
        onOpenConnectTenant={() => setConnectTenantModalOpen(true)}
        activeOperator={activeOperator}
        availableOperators={availableOperators}
        onOperatorChange={handleOperatorChange}
        onOpenAuthModal={() => setAuthModalOpen(true)}
      />

      <main className="app-container">
        {/* Role-Based Point-of-View (POV) Focus Directive Bar */}
        <PersonaFocusBar
          activePersona={activePersona}
          activeOperator={activeOperator}
          onPersonaChange={handlePersonaChange}
          onNavigateTab={tab => setActiveTab(tab)}
          onOpenExportBrief={() => setCisoExportBriefOpen(true)}
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Sparkles size={18} color="var(--accent-sky)" style={{ flexShrink: 0 }} />
              <div style={{ fontSize: '0.80rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                <strong>CloudPulse Autonomous SecOps & FinOps Platform:</strong> Built for security commanders,
                cloud economists, and platform teams. Currently inspecting{' '}
                <strong style={{ color: 'var(--accent-sky)' }}>{activeTenant.name}</strong>. Switch perspective
                using the role selector in the top bar, or click <strong>Connect Cloud</strong> to onboard your own Azure tenant.
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.72rem', padding: '4px 10px' }}
                onClick={() => setConnectTenantModalOpen(true)}
              >
                + Connect Your Azure Tenant
              </button>
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
      {cisoExportBriefOpen && incidents.length > 0 && (
        <ExportBriefModal
          isOpen={cisoExportBriefOpen}
          incident={incidents[0]}
          onClose={() => setCisoExportBriefOpen(false)}
          onShowToast={showToast}
        />
      )}

      {/* OTP Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthenticated={(user) => {
          setActiveOperator(user);
          setActivePersona(user.primaryPersona);
          showToast(
            'success',
            `Authenticated: ${user.name}`,
            `Signed in as ${user.role}. ${user.isSuperAdmin ? 'Full Access Super-Admin privileges unlocked.' : ''}`
          );
        }}
        activeOperator={activeOperator}
      />

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </>
  );
};

export default App;
