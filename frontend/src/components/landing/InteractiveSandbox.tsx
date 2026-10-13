import React, { useState } from 'react';
import { Play, RotateCcw, ShieldAlert, CheckCircle, ArrowRight, Zap, Database, HardDrive, Globe } from 'lucide-react';

interface Scenario {
  id: string;
  title: string;
  category: 'SecOps' | 'FinOps' | 'Compliance';
  icon: React.ReactNode;
  resource: string;
  driftDescription: string;
  riskSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  costImpact: string;
  recommendedAction: string;
  remediationPayload: string;
}

const SCENARIOS: Scenario[] = [
  {
    id: 'scen-1',
    title: 'Rogue Public IP on DB Bastion',
    category: 'SecOps',
    icon: <Globe size={18} color="#fc8181" />,
    resource: 'vm-postgres-core-prod',
    driftDescription: 'Public IP allocation dynamically attached to database subnet bypassing NSG whitelist.',
    riskSeverity: 'CRITICAL',
    costImpact: 'Exposes database port 5432 to 0.0.0.0/0',
    recommendedAction: 'Disassociate NIC Public IP & Lock Ingress Rule',
    remediationPayload: 'az network nic ip-config update --remove publicIpAddress',
  },
  {
    id: 'scen-2',
    title: 'Orphaned 4TB Premium P50 SSD',
    category: 'FinOps',
    icon: <HardDrive size={18} color="#f6ad55" />,
    resource: 'disk-analytics-worker-vol2',
    driftDescription: 'Disk unattached for >14 days after batch job decommissioned with active hourly billing.',
    riskSeverity: 'HIGH',
    costImpact: '$512.00 / month idle waste ($6,144/yr)',
    recommendedAction: 'Create delta snapshot and deallocate volume',
    remediationPayload: 'az disk delete --yes --name disk-analytics-worker-vol2',
  },
  {
    id: 'scen-3',
    title: 'Storage Account Public Blob Drift',
    category: 'Compliance',
    icon: <Database size={18} color="#9f7aea" />,
    resource: 'stfinancialauditprod',
    driftDescription: 'allowBlobPublicAccess flipped to true during CI/CD terraform state apply drift.',
    riskSeverity: 'CRITICAL',
    costImpact: 'Direct GDPR & SOC2 Type II compliance violation',
    recommendedAction: 'Set allowBlobPublicAccess=false & rotate SAS tokens',
    remediationPayload: 'az storage account update --allow-blob-public-access false',
  },
];

export const InteractiveSandbox: React.FC = () => {
  const [selectedId, setSelectedId] = useState<string>('scen-1');
  const [stage, setStage] = useState<'idle' | 'detected' | 'remediating' | 'resolved'>('idle');

  const activeScenario = SCENARIOS.find(s => s.id === selectedId) || SCENARIOS[0];

  const handleSimulate = () => {
    setStage('detected');
  };

  const handleRemediate = () => {
    setStage('remediating');
    setTimeout(() => {
      setStage('resolved');
    }, 900);
  };

  const handleReset = () => {
    setStage('idle');
  };

  return (
    <div style={{
      borderRadius: '14px',
      border: '1px solid var(--border-medium, rgba(255, 255, 255, 0.12))',
      backgroundColor: '#0a0d14',
      padding: '28px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Scenario Selector Tabs */}
      <div style={{
        display: 'flex',
        gap: '12px',
        marginBottom: '24px',
        flexWrap: 'wrap',
      }}>
        {SCENARIOS.map(scen => {
          const isSelected = scen.id === selectedId;
          return (
            <button
              key={scen.id}
              onClick={() => {
                setSelectedId(scen.id);
                setStage('idle');
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 16px',
                borderRadius: '8px',
                border: isSelected ? '1px solid rgba(99, 179, 237, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                backgroundColor: isSelected ? 'rgba(99, 179, 237, 0.1)' : '#070a10',
                color: isSelected ? '#f1f5f9' : '#94a3b8',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                fontSize: '0.85rem',
                fontWeight: 500,
              }}
            >
              {scen.icon}
              <span>{scen.title}</span>
              <span style={{
                fontSize: '0.7rem',
                fontFamily: 'var(--font-mono)',
                padding: '2px 6px',
                borderRadius: '4px',
                backgroundColor: isSelected ? 'rgba(99, 179, 237, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                color: isSelected ? '#63b3ed' : '#64748b',
              }}>
                {scen.category}
              </span>
            </button>
          );
        })}
      </div>

      {/* Interactive Workbench */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1.2fr 0.8fr',
        gap: '24px',
        alignItems: 'stretch',
      }}>
        {/* Left: Drift Inspection & State */}
        <div style={{
          backgroundColor: '#05070c',
          borderRadius: '10px',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.72rem',
                color: '#64748b',
                textTransform: 'uppercase',
              }}>
                Target Resource Scope
              </span>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.95rem',
                color: '#f1f5f9',
                fontWeight: 600,
                marginTop: '2px',
              }}>
                {activeScenario.resource}
              </div>
            </div>

            <span style={{
              fontSize: '0.72rem',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              padding: '3px 8px',
              borderRadius: '4px',
              backgroundColor: activeScenario.riskSeverity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(246, 173, 85, 0.15)',
              color: activeScenario.riskSeverity === 'CRITICAL' ? '#fc8181' : '#f6ad55',
              border: activeScenario.riskSeverity === 'CRITICAL' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(246, 173, 85, 0.3)',
            }}>
              {activeScenario.riskSeverity} RISK
            </span>
          </div>

          <div style={{ fontSize: '0.86rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {activeScenario.driftDescription}
          </div>

          <div style={{
            backgroundColor: '#0a0e18',
            padding: '12px',
            borderRadius: '6px',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            fontSize: '0.8rem',
            color: '#94a3b8',
          }}>
            <strong style={{ color: '#f1f5f9' }}>Impact Vector: </strong> {activeScenario.costImpact}
          </div>

          {/* Action Simulation Controls */}
          <div style={{ marginTop: 'auto', display: 'flex', gap: '10px' }}>
            {stage === 'idle' && (
              <button
                onClick={handleSimulate}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#1d283a',
                  color: '#63b3ed',
                  border: '1px solid rgba(99, 179, 237, 0.35)',
                  padding: '9px 16px',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.82rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <Play size={14} /> Inject Drift Event
              </button>
            )}

            {stage === 'detected' && (
              <button
                onClick={handleRemediate}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#065f46',
                  color: '#a7f3d0',
                  border: '1px solid #10b981',
                  padding: '9px 16px',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.82rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <Zap size={14} /> Authorize Auto-Remediation
              </button>
            )}

            {stage === 'remediating' && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                color: '#63b3ed',
                fontSize: '0.82rem',
                fontFamily: 'var(--font-mono)',
              }}>
                <span className="animate-spin">⟳</span> Dispatching Azure REST API rollback...
              </div>
            )}

            {stage === 'resolved' && (
              <button
                onClick={handleReset}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#111827',
                  color: '#94a3b8',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  padding: '9px 16px',
                  borderRadius: '6px',
                  fontWeight: 500,
                  fontSize: '0.82rem',
                  cursor: 'pointer',
                }}
              >
                <RotateCcw size={14} /> Reset Scenario
              </button>
            )}
          </div>
        </div>

        {/* Right: Real-Time Engine Verdict Output */}
        <div style={{
          backgroundColor: '#05070c',
          borderRadius: '10px',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem',
          gap: '12px',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
            paddingBottom: '10px',
          }}>
            <span style={{ color: '#64748b' }}>ENGINE_STATE</span>
            <span style={{
              color: stage === 'idle' ? '#94a3b8' : stage === 'detected' ? '#fc8181' : stage === 'resolved' ? '#38d9a9' : '#63b3ed',
              fontWeight: 600,
            }}>
              {stage === 'idle' ? 'STANDBY_LISTENING' : stage === 'detected' ? 'ALERT_DRIFT_INTERCEPTED' : stage === 'remediating' ? 'APPLYING_ROLLBACK' : 'POLICY_ENFORCED_OK'}
            </span>
          </div>

          {stage === 'idle' && (
            <div style={{ color: '#64748b', display: 'flex', flexDirection: 'column', gap: '8px', padding: '20px 0' }}>
              <div>[00.00s] Azure Resource Graph listener idle...</div>
              <div>[00.00s] Waiting for drift trigger to execute telemetry test...</div>
              <div style={{ color: '#63b3ed' }}>→ Click "Inject Drift Event" to test detection.</div>
            </div>
          )}

          {stage === 'detected' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div style={{ color: '#fc8181' }}>[ALERT] Threat Signature Matched in 840ms</div>
              <div style={{ color: '#cbd5e1' }}>Rule: RULE-SEC-AZURE-01 (Unauthorized Drift)</div>
              <div style={{ color: '#94a3b8' }}>Remediation: {activeScenario.recommendedAction}</div>
              <div style={{
                marginTop: '10px',
                padding: '10px',
                backgroundColor: '#0e1420',
                borderRadius: '6px',
                color: '#63b3ed',
                fontSize: '0.72rem',
                overflowX: 'auto',
              }}>
                $ {activeScenario.remediationPayload}
              </div>
            </div>
          )}

          {(stage === 'remediating' || stage === 'resolved') && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div style={{ color: '#38d9a9' }}>✓ REST Payload Executed via Azure Management</div>
              <div style={{ color: '#94a3b8' }}>✓ State Hash Verified: No pending drift</div>
              <div style={{ color: '#94a3b8' }}>✓ Cryptographic Audit Record Signed</div>
              <div style={{
                marginTop: '10px',
                padding: '10px',
                backgroundColor: 'rgba(56, 217, 169, 0.08)',
                border: '1px solid rgba(56, 217, 169, 0.25)',
                borderRadius: '6px',
                color: '#a7f3d0',
                fontSize: '0.74rem',
              }}>
                MTTR: 1.14s | Zero Human Downtime | Policy 100% Compliant
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
