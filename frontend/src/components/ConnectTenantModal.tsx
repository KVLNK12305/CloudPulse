import React, { useState } from 'react';
import {
  Check,
  CheckCircle,
  ChevronLeft,
  ChevronRight,
  Cloud,
  Copy,
  ExternalLink,
  Key,
  Layers,
  Lock,
  RefreshCw,
  Shield,
  Terminal,
  X,
} from 'lucide-react';
import { TenantScope } from '../types';

interface ConnectTenantModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTenantConnected: (newTenant: TenantScope) => void;
}

export const ConnectTenantModal: React.FC<ConnectTenantModalProps> = ({
  isOpen,
  onClose,
  onTenantConnected,
}) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [method, setMethod] = useState<'sp' | 'lighthouse' | 'managed-identity'>('sp');
  const [tenantName, setTenantName] = useState<string>('Enterprise Production');
  const [tenantId, setTenantId] = useState<string>('72f988bf-86f1-41af-91ab-2d7cd011db47');
  const [subscriptionId, setSubscriptionId] = useState<string>('c9b3e102-45a8-4b71-923f-110022334455');
  const [clientId, setClientId] = useState<string>('8fa32100-3321-410a-8abc-ff0011223344');
  const [clientSecret, setClientSecret] = useState<string>('••••••••••••••••••••••••••••••••');
  const [region, setRegion] = useState<string>('eastus');
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [copiedCli, setCopiedCli] = useState<boolean>(false);

  if (!isOpen) return null;

  const cliScript = `az ad sp create-for-rbac \\
  --name "CloudPulse-Operator-${tenantName.replace(/\s+/g, '-').toLowerCase()}" \\
  --role "Reader" \\
  --scopes "/subscriptions/${subscriptionId}"`;

  const handleCopyCli = () => {
    navigator.clipboard.writeText(cliScript);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  const handleTestAndConnect = () => {
    setIsVerifying(true);
    setTimeout(() => {
      setIsVerifying(false);
      const newTenant: TenantScope = {
        id: `tenant-${Date.now().toString(36)}`,
        name: tenantName,
        subscriptionId: subscriptionId,
        environment: 'production',
        region: region,
      };
      onTenantConnected(newTenant);
      onClose();
    }, 1200);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-dialog"
        style={{ width: '640px', maxWidth: '95vw' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="panel-header">
          <div className="panel-title">
            <Cloud size={18} color="var(--accent-sky)" />
            <span>Connect Cloud Tenant / Azure Subscription</span>
          </div>
          <button className="btn btn-secondary" style={{ padding: '4px', borderRadius: '50%' }} onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        {/* Wizard Steps Bar */}
        <div
          style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'var(--bg-inset)',
          }}
        >
          {[
            { num: 1, title: 'Auth Method' },
            { num: 2, title: 'Credentials & Scope' },
            { num: 3, title: 'ARM Verification' },
          ].map(s => (
            <div
              key={s.num}
              onClick={() => setStep(s.num as 1 | 2 | 3)}
              style={{
                flex: 1,
                padding: '10px 14px',
                fontSize: '0.74rem',
                fontWeight: 700,
                color: step === s.num ? 'var(--accent-sky)' : 'var(--text-tertiary)',
                borderBottom: step === s.num ? '2px solid var(--accent-sky)' : '2px solid transparent',
                textAlign: 'center',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
              }}
            >
              <span
                style={{
                  width: '18px',
                  height: '18px',
                  borderRadius: '50%',
                  background: step === s.num ? 'var(--accent-sky)' : 'rgba(255,255,255,0.06)',
                  color: step === s.num ? '#06090f' : 'var(--text-tertiary)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.62rem',
                }}
              >
                {s.num}
              </span>
              <span>{s.title}</span>
            </div>
          ))}
        </div>

        <div style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* STEP 1: Integration Method */}
          {step === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ fontSize: '0.80rem', color: 'var(--text-secondary)' }}>
                Select how CloudPulse should connect to your cloud infrastructure to discover topology and telemetry.
              </div>

              {[
                {
                  id: 'sp',
                  title: 'Azure App Registration (Service Principal)',
                  sub: 'Recommended for standalone subscriptions & enterprise tenants',
                  desc: 'Secure authentication via Azure AD Client Credentials or Federated OIDC.',
                  badge: 'Standard',
                },
                {
                  id: 'lighthouse',
                  title: 'Azure Lighthouse Delegated Access',
                  sub: 'Recommended for MSPs, MSSPs & Cross-Tenant Governance',
                  desc: 'Zero credential exchange using Azure Resource Manager projection.',
                  badge: 'Enterprise MSP',
                },
                {
                  id: 'managed-identity',
                  title: 'Azure Managed Identity (In-Cluster)',
                  sub: 'For CloudPulse self-hosted agent deployments in AKS or Azure VMs',
                  desc: 'Passwordless IAM token acquisition via IMDS metadata endpoint.',
                  badge: 'Self-Hosted',
                },
              ].map(opt => (
                <div
                  key={opt.id}
                  onClick={() => setMethod(opt.id as 'sp' | 'lighthouse' | 'managed-identity')}
                  style={{
                    background: method === opt.id ? 'rgba(99, 179, 237, 0.08)' : 'var(--bg-inset)',
                    border: `1px solid ${method === opt.id ? 'var(--accent-sky)' : 'var(--border-subtle)'}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '14px 16px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.84rem', color: 'var(--text-primary)' }}>
                      {opt.title}
                    </span>
                    <span className="source-badge arg" style={{ fontSize: '0.62rem' }}>
                      {opt.badge}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--accent-sky)', marginTop: '2px' }}>
                    {opt.sub}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                    {opt.desc}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* STEP 2: Credentials & Scope */}
          {step === 2 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '4px' }}>
                    Environment / Display Name
                  </label>
                  <input
                    type="text"
                    className="search-input"
                    style={{ width: '100%', minWidth: 'unset' }}
                    value={tenantName}
                    onChange={e => setTenantName(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '4px' }}>
                    Primary Region
                  </label>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={region}
                    onChange={e => setRegion(e.target.value)}
                  >
                    <option value="eastus">East US (Virginia)</option>
                    <option value="westus2">West US 2 (Washington)</option>
                    <option value="westeurope">West Europe (Netherlands)</option>
                    <option value="southeastasia">Southeast Asia (Singapore)</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '4px' }}>
                  Azure Subscription ID
                </label>
                <input
                  type="text"
                  className="search-input"
                  style={{ width: '100%', minWidth: 'unset', fontFamily: 'var(--font-mono)' }}
                  value={subscriptionId}
                  onChange={e => setSubscriptionId(e.target.value)}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '4px' }}>
                    Directory (Tenant) ID
                  </label>
                  <input
                    type="text"
                    className="search-input"
                    style={{ width: '100%', minWidth: 'unset', fontFamily: 'var(--font-mono)' }}
                    value={tenantId}
                    onChange={e => setTenantId(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '4px' }}>
                    Application (Client) ID
                  </label>
                  <input
                    type="text"
                    className="search-input"
                    style={{ width: '100%', minWidth: 'unset', fontFamily: 'var(--font-mono)' }}
                    value={clientId}
                    onChange={e => setClientId(e.target.value)}
                  />
                </div>
              </div>

              {/* 1-Click Azure CLI Helper */}
              <div
                style={{
                  background: 'var(--bg-inset)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.70rem', color: 'var(--text-secondary)' }}>
                    <Terminal size={12} color="var(--accent-sky)" />
                    <span>Run in Azure Cloud Shell to generate credentials automatically:</span>
                  </div>
                  <button className="btn btn-secondary" style={{ padding: '2px 8px', fontSize: '0.66rem' }} onClick={handleCopyCli}>
                    {copiedCli ? <Check size={11} color="var(--accent-teal)" /> : <Copy size={11} />}
                    <span>{copiedCli ? 'Copied' : 'Copy az cli'}</span>
                  </button>
                </div>
                <pre style={{ fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-sky)', overflowX: 'auto', background: 'rgba(0,0,0,0.3)', padding: '6px 8px', borderRadius: '4px' }}>
                  {cliScript}
                </pre>
              </div>
            </div>
          )}

          {/* STEP 3: Permissions Review & Connection Test */}
          {step === 3 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ fontSize: '0.80rem', color: 'var(--text-secondary)' }}>
                CloudPulse verifies least-privilege RBAC assignments across your Azure subscription:
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {[
                  {
                    role: 'Reader',
                    scope: 'Microsoft.ResourceGraph/resources/read',
                    purpose: 'Continuous discovery of provisioned VMs, NSGs, and topologies',
                    status: 'Ready',
                  },
                  {
                    role: 'Cost Management Reader',
                    scope: 'Microsoft.CostManagement/query/action',
                    purpose: 'Daily billed consumption and baseline anomaly calculation',
                    status: 'Ready',
                  },
                  {
                    role: 'Monitoring Reader',
                    scope: 'Microsoft.Insights/metrics/read',
                    purpose: 'Real-time CPU, memory, and network interface throughput',
                    status: 'Ready',
                  },
                  {
                    role: 'Network Contributor (Optional)',
                    scope: 'Microsoft.Network/networkSecurityGroups/write',
                    purpose: 'Remediation containment (Requires human approval gate)',
                    status: 'Approved Gate',
                  },
                ].map((p, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px 12px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                        {p.role} <code style={{ fontSize: '0.68rem', color: 'var(--accent-sky)' }}>({p.scope})</code>
                      </div>
                      <div style={{ fontSize: '0.70rem', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                        {p.purpose}
                      </div>
                    </div>
                    <span
                      className="source-badge monitor"
                      style={{ color: 'var(--accent-teal)', fontSize: '0.66rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Check size={11} strokeWidth={2.5} />
                      <span>{p.status}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Modal Actions */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
            <button
              className="btn btn-secondary"
              onClick={() => {
                if (step > 1) setStep((step - 1) as 1 | 2);
                else onClose();
              }}
            >
              {step === 1 ? (
                'Cancel'
              ) : (
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ChevronLeft size={13} />
                  <span>Back</span>
                </span>
              )}
            </button>

            {step < 3 ? (
              <button className="btn btn-accent" onClick={() => setStep((step + 1) as 2 | 3)}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span>Next Step</span>
                  <ChevronRight size={13} />
                </span>
              </button>
            ) : (
              <button className="btn btn-success" onClick={handleTestAndConnect} disabled={isVerifying}>
                {isVerifying ? <RefreshCw size={13} className="spin" /> : <CheckCircle size={13} />}
                <span>{isVerifying ? 'Testing ARM APIs...' : 'Verify & Connect Estate'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
