import React, { useState, useEffect } from 'react';
import { ShieldCheck, Activity, Terminal, CheckCircle2, AlertTriangle, ArrowRight, Lock, Zap } from 'lucide-react';

interface TelemetryEvent {
  id: string;
  timestamp: string;
  service: string;
  action: string;
  resource: string;
  status: 'intercepted' | 'analyzing' | 'cleared';
  latency: string;
  impact: string;
}

const INITIAL_EVENTS: TelemetryEvent[] = [
  {
    id: 'SIG-8921',
    timestamp: '14:52:10.412',
    service: 'Azure Compute',
    action: 'virtualMachines/create',
    resource: 'vm-bastion-eu-prod',
    status: 'intercepted',
    latency: '1.2s',
    impact: 'Blocked public IP exposure',
  },
  {
    id: 'SIG-8920',
    timestamp: '14:51:48.890',
    service: 'Azure Storage',
    action: 'storageAccounts/blobPublicAccess',
    resource: 'stfinopseast01',
    status: 'intercepted',
    latency: '840ms',
    impact: 'Disabled public container access',
  },
  {
    id: 'SIG-8919',
    timestamp: '14:50:33.104',
    service: 'FinOps Monitor',
    action: 'disks/unattached-premium-ssd',
    resource: 'disk-analytics-vol4',
    status: 'cleared',
    latency: '2.1s',
    impact: 'Auto-reclaimed $184/mo waste',
  },
  {
    id: 'SIG-8918',
    timestamp: '14:49:15.654',
    service: 'Azure Network',
    action: 'securityRules/allow-all-ingress',
    resource: 'nsg-k8s-ingress-prod',
    status: 'intercepted',
    latency: '950ms',
    impact: 'Enforced zero-trust inbound rules',
  },
];

export const TelemetryCanvas: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'stream' | 'pipeline' | 'rollbacks'>('stream');
  const [events, setEvents] = useState<TelemetryEvent[]>(INITIAL_EVENTS);
  const [pulseIndex, setPulseIndex] = useState<number>(0);

  // Periodic event feed simulation
  useEffect(() => {
    const interval = setInterval(() => {
      setPulseIndex(prev => (prev + 1) % 4);
    }, 3500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="telemetry-canvas-container" style={{
      borderRadius: '12px',
      border: '1px solid var(--border-medium, rgba(255, 255, 255, 0.12))',
      backgroundColor: '#070a10',
      overflow: 'hidden',
      boxShadow: '0 24px 60px -12px rgba(0, 0, 0, 0.8)',
    }}>
      {/* Canvas Top Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 18px',
        borderBottom: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.08))',
        backgroundColor: '#0a0e16',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981', boxShadow: '0 0 10px #10b981' }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#94a3b8', letterSpacing: '0.05em' }}>
            ENGINE_STREAM: <strong style={{ color: '#f1f5f9' }}>LIVE_AUTONOMOUS_INTERCEPTION</strong>
          </span>
        </div>

        {/* Tab Switchers */}
        <div style={{ display: 'flex', gap: '4px', backgroundColor: '#05070c', padding: '3px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          {(['stream', 'pipeline', 'rollbacks'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                background: activeTab === tab ? '#172033' : 'transparent',
                color: activeTab === tab ? '#63b3ed' : '#64748b',
                border: 'none',
                padding: '4px 10px',
                borderRadius: '4px',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                textTransform: 'uppercase',
              }}
            >
              {tab === 'stream' ? 'Telemetry Stream' : tab === 'pipeline' ? 'Interception Matrix' : 'Audit Log'}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      <div style={{ padding: '20px' }}>
        {activeTab === 'stream' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {events.map((evt, idx) => {
              const isHighlight = idx === pulseIndex;
              return (
                <div
                  key={evt.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    backgroundColor: isHighlight ? 'rgba(99, 179, 237, 0.08)' : '#0c1018',
                    border: isHighlight ? '1px solid rgba(99, 179, 237, 0.35)' : '1px solid rgba(255, 255, 255, 0.05)',
                    transition: 'all 0.3s ease',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ color: '#64748b', fontSize: '0.72rem' }}>{evt.timestamp}</span>
                    <span style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      backgroundColor: evt.status === 'intercepted' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      color: evt.status === 'intercepted' ? '#fc8181' : '#38d9a9',
                      border: evt.status === 'intercepted' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(16, 185, 129, 0.3)',
                    }}>
                      {evt.status.toUpperCase()}
                    </span>
                    <span style={{ color: '#cbd5e1' }}>{evt.resource}</span>
                    <span style={{ color: '#64748b', fontSize: '0.75rem' }}>({evt.action})</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>{evt.impact}</span>
                    <span style={{
                      color: '#38d9a9',
                      fontSize: '0.72rem',
                      backgroundColor: 'rgba(56, 217, 169, 0.1)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                    }}>
                      {evt.latency}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {activeTab === 'pipeline' && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '12px',
            padding: '10px 0',
          }}>
            {[
              { step: '01', title: 'ARG Ingestion', desc: 'Azure Resource Graph Delta polling under 60s', icon: <Activity size={18} color="#63b3ed" />, stat: '< 850ms' },
              { step: '02', title: 'Threat Correlator', desc: 'Anomaly heuristic signature matrix matching', icon: <AlertTriangle size={18} color="#f6ad55" />, stat: '99.8% Conf' },
              { step: '03', title: 'Cryptographic Gate', desc: 'Supabase HS256 RBAC token verification', icon: <Lock size={18} color="#9f7aea" />, stat: 'Zero Bypass' },
              { step: '04', title: 'Auto Remediation', desc: 'Azure REST API rollback & state correction', icon: <Zap size={18} color="#38d9a9" />, stat: '1.2s MTTR' },
            ].map(col => (
              <div key={col.step} style={{
                backgroundColor: '#0c1018',
                padding: '16px',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#64748b' }}>{col.step}</span>
                  {col.icon}
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.88rem', color: '#f1f5f9' }}>{col.title}</div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>{col.desc}</div>
                <div style={{
                  marginTop: 'auto',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  color: '#63b3ed',
                  backgroundColor: 'rgba(99, 179, 237, 0.08)',
                  padding: '3px 6px',
                  borderRadius: '4px',
                  width: 'fit-content',
                }}>
                  {col.stat}
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'rollbacks' && (
          <div style={{
            backgroundColor: '#05070c',
            borderRadius: '8px',
            padding: '14px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            color: '#cbd5e1',
            lineHeight: 1.6,
            maxHeight: '180px',
            overflowY: 'auto',
            border: '1px solid rgba(255, 255, 255, 0.06)',
          }}>
            <div style={{ color: '#10b981' }}>[SUCCESS] 14:52:10.420 :: Policy enforced on Azure Subscription 90b900ea</div>
            <div style={{ color: '#94a3b8' }}>  └─ Target: Microsoft.Compute/virtualMachines/vm-bastion-eu-prod</div>
            <div style={{ color: '#94a3b8' }}>  └─ Action: Detached public IP configuration ipconfig-primary</div>
            <div style={{ color: '#38d9a9' }}>  └─ Audit Signed: Operator K V L N Kushal (SecOps SuperAdmin)</div>
            <div style={{ color: '#10b981', marginTop: '6px' }}>[SUCCESS] 14:50:33.112 :: FinOps Reclamation Triggered</div>
            <div style={{ color: '#94a3b8' }}>  └─ Target: Microsoft.Compute/disks/disk-analytics-vol4 (Unattached 18 days)</div>
            <div style={{ color: '#94a3b8' }}>  └─ Action: Downscaled disk SKU to Standard_LRS snapshot prior to purge</div>
            <div style={{ color: '#63b3ed' }}>  └─ Net Monthly Savings: +$184.00 USD/month</div>
          </div>
        )}
      </div>

      {/* Canvas Status Bottom Rail */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 18px',
        borderTop: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.06))',
        backgroundColor: '#080c14',
        fontSize: '0.72rem',
        fontFamily: 'var(--font-mono)',
        color: '#64748b',
      }}>
        <div style={{ display: 'flex', gap: '16px' }}>
          <span>LATENCY: <strong style={{ color: '#38d9a9' }}>8.4ms</strong></span>
          <span>INGESTION: <strong style={{ color: '#cbd5e1' }}>1,420 events/min</strong></span>
          <span>INTERCEPT RATE: <strong style={{ color: '#63b3ed' }}>100%</strong></span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
          <CheckCircle2 size={13} />
          <span>ZERO DRIFT DETECTED IN ACTIVE TENANT</span>
        </div>
      </div>
    </div>
  );
};
