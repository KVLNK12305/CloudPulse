import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import {
  Shield,
  Activity,
  Terminal,
  ArrowRight,
  Zap,
  CheckCircle2,
  Lock,
  Cpu,
  BarChart3,
  Layers,
  Copy,
  Check,
  Users,
} from 'lucide-react';
import { LandingNavbar } from './LandingNavbar';
import { SpotlightCard } from './SpotlightCard';
import { DecryptText } from './DecryptText';
import { TelemetryCanvas } from './TelemetryCanvas';
import { InteractiveSandbox } from './InteractiveSandbox';
import './landing.css';

interface LandingPageProps {
  onLaunchConsole: () => void;
  onOpenAuth: () => void;
  isAuthenticated: boolean;
  operatorName?: string;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onLaunchConsole,
  onOpenAuth,
  isAuthenticated,
  operatorName,
}) => {
  const heroRef = useRef<HTMLDivElement>(null);
  const bentoRef = useRef<HTMLDivElement>(null);
  const [copiedCli, setCopiedCli] = useState<boolean>(false);

  // GSAP Entrance Animations
  useEffect(() => {
    const ctx = gsap.context(() => {
      // Hero Timeline
      const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });

      tl.from('.hero-telemetry-badge', {
        opacity: 0,
        y: -15,
        duration: 0.6,
      })
        .from(
          '.hero-headline',
          {
            opacity: 0,
            y: 25,
            duration: 0.8,
          },
          '-=0.3'
        )
        .from(
          '.hero-subhead',
          {
            opacity: 0,
            y: 20,
            duration: 0.7,
          },
          '-=0.4'
        )
        .from(
          '.hero-actions',
          {
            opacity: 0,
            y: 15,
            duration: 0.6,
          },
          '-=0.4'
        )
        .from(
          '.hero-showcase',
          {
            opacity: 0,
            y: 35,
            duration: 0.9,
          },
          '-=0.3'
        );

      // Bento cards staggered entrance on scroll / render
      gsap.from('.bento-item', {
        opacity: 0,
        y: 30,
        stagger: 0.12,
        duration: 0.7,
        ease: 'power2.out',
        delay: 0.4,
      });

      // Stats numbers entrance
      gsap.from('.stat-item', {
        opacity: 0,
        scale: 0.95,
        stagger: 0.08,
        duration: 0.6,
        delay: 0.6,
      });
    }, heroRef);

    return () => ctx.revert();
  }, []);

  const handleCopyCli = () => {
    navigator.clipboard.writeText('curl -sSL https://cloudpulse.io/install.sh | bash');
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2200);
  };

  return (
    <div className="landing-root" ref={heroRef}>
      {/* Precision Dot Grid Canvas */}
      <div className="landing-grid-bg" />

      {/* Top Technical Navbar */}
      <LandingNavbar
        onLaunchConsole={onLaunchConsole}
        onOpenAuth={onOpenAuth}
        isAuthenticated={isAuthenticated}
        operatorName={operatorName}
      />

      <div className="landing-container">
        {/* ── HERO SECTION ── */}
        <section className="hero-section">
          {/* Status Badge */}
          <div className="hero-telemetry-badge">
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#63b3ed', boxShadow: '0 0 8px #63b3ed' }} />
            <span>AZURE AUTONOMOUS DEFENSE & FINOPS ENGINE</span>
            <span style={{ color: '#475569' }}>//</span>
            <span style={{ color: '#38d9a9' }}>v2.4 READY</span>
          </div>

          {/* Cryptographic Decrypt Headline */}
          <h1 className="hero-headline">
            Autonomous Cloud Defense &{' '}
            <span style={{ color: '#63b3ed' }}>
              <DecryptText text="FinOps Intelligence" speed={30} />
            </span>
          </h1>

          <p className="hero-subhead">
            Continuous drift neutralization, real-time Azure Resource Graph telemetry ingestion, and deterministic
            remediation before unapproved workloads impact security boundaries or budget envelopes.
          </p>

          {/* Call to Actions */}
          <div className="hero-actions">
            <button className="btn-primary-console" onClick={onLaunchConsole}>
              <span>Launch Live Console</span>
              <ArrowRight size={16} color="#63b3ed" />
            </button>

            <button
              className="btn-secondary-outline"
              onClick={() => {
                const el = document.getElementById('sandbox');
                el?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              <Zap size={16} color="#f6ad55" />
              <span>Simulate Live Attack</span>
            </button>

            <div className="cli-code-badge" onClick={handleCopyCli}>
              <Terminal size={14} color="#64748b" />
              <span>curl -sSL https://cloudpulse.io/install.sh | bash</span>
              {copiedCli ? <Check size={14} color="#38d9a9" /> : <Copy size={14} color="#64748b" />}
            </div>
          </div>

          {/* Interactive Live Telemetry Canvas Showcase */}
          <div className="hero-showcase" style={{ width: '100%', maxWidth: '1080px', marginTop: '12px' }}>
            <TelemetryCanvas />
          </div>
        </section>

        {/* ── INTERACTIVE SANDBOX: ATTACK & DRIFT SIMULATION ── */}
        <section id="sandbox" style={{ padding: '80px 0 60px 0' }}>
          <div className="section-tag">
            <Zap size={14} />
            <span>Real-Time Incident Lab</span>
          </div>
          <h2 className="section-title">Test the Interception Engine in Real Time</h2>
          <p className="section-desc">
            Trigger simulated security drifts and orphaned FinOps resources to observe how CloudPulse isolates threats,
            computes risk scores, and initiates zero-downtime rollbacks.
          </p>

          <div style={{ marginTop: '32px' }}>
            <InteractiveSandbox />
          </div>
        </section>

        {/* ── BENTO GRID: CORE CAPABILITIES ── */}
        <section id="capabilities" style={{ padding: '70px 0 60px 0' }} ref={bentoRef}>
          <div className="section-tag">
            <Layers size={14} />
            <span>Core Capabilities</span>
          </div>
          <h2 className="section-title">Engineered for Unforgiving Production Clouds</h2>
          <p className="section-desc">
            Built from the ground up to replace fragmented monitoring scripts with deterministic, audit-proven
            autonomous guardrails.
          </p>

          <div className="bento-grid">
            {/* Bento 1: ARG & Monitor Real-Time Ingestion (Col 8) */}
            <div className="bento-col-8 bento-item">
              <SpotlightCard>
                <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <div style={{
                      width: '40px',
                      height: '40px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(99, 179, 237, 0.1)',
                      border: '1px solid rgba(99, 179, 237, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      <Activity size={20} color="#63b3ed" />
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#63b3ed', backgroundColor: 'rgba(99, 179, 237, 0.08)', padding: '3px 8px', borderRadius: '4px' }}>
                      ARG_DELTA_POLL
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                    Sub-60s Azure Resource Graph Telemetry
                  </h3>
                  <p style={{ fontSize: '0.9rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '24px' }}>
                    Continuously syncs Azure estate inventory and changes. Cross-references AzureActivity write events,
                    NSG rule deviations, and disk allocation states without heavy daemon agents or credential exposure.
                  </p>

                  <div style={{
                    marginTop: 'auto',
                    backgroundColor: '#070a10',
                    borderRadius: '8px',
                    padding: '16px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '12px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.78rem',
                  }}>
                    <div>
                      <div style={{ color: '#64748b' }}>AVG_LATENCY</div>
                      <div style={{ color: '#38d9a9', fontWeight: 600, fontSize: '1rem', marginTop: '4px' }}>840ms</div>
                    </div>
                    <div>
                      <div style={{ color: '#64748b' }}>ESTATE_GRAPH</div>
                      <div style={{ color: '#63b3ed', fontWeight: 600, fontSize: '1rem', marginTop: '4px' }}>12,840 Nodes</div>
                    </div>
                    <div>
                      <div style={{ color: '#64748b' }}>POLL_INTERVAL</div>
                      <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '1rem', marginTop: '4px' }}>Every 30s</div>
                    </div>
                  </div>
                </div>
              </SpotlightCard>
            </div>

            {/* Bento 2: FinOps Burn Radar (Col 4) */}
            <div className="bento-col-4 bento-item">
              <SpotlightCard>
                <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <div style={{
                      width: '40px',
                      height: '40px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(246, 173, 85, 0.1)',
                      border: '1px solid rgba(246, 173, 85, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      <BarChart3 size={20} color="#f6ad55" />
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#f6ad55', backgroundColor: 'rgba(246, 173, 85, 0.08)', padding: '3px 8px', borderRadius: '4px' }}>
                      FINOPS_CORRELATION
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                    Continuous Cost Outlier Radar
                  </h3>
                  <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '20px' }}>
                    Calculates workload cost deviations, identifies unattached disks, and prevents runaway cloud burn
                    before monthly invoices close.
                  </p>

                  <div style={{
                    marginTop: 'auto',
                    backgroundColor: '#070a10',
                    padding: '14px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', color: '#64748b', marginBottom: '6px' }}>
                      <span>14-Day Budget Envelope</span>
                      <span style={{ color: '#38d9a9' }}>Optimal (72%)</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', backgroundColor: '#172033', borderRadius: '999px', overflow: 'hidden' }}>
                      <div style={{ width: '72%', height: '100%', backgroundColor: '#38d9a9' }} />
                    </div>
                  </div>
                </div>
              </SpotlightCard>
            </div>

            {/* Bento 3: Multi-Persona Role Lens (Col 4) */}
            <div className="bento-col-4 bento-item">
              <SpotlightCard>
                <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <div style={{
                      width: '40px',
                      height: '40px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(159, 122, 234, 0.1)',
                      border: '1px solid rgba(159, 122, 234, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      <Users size={20} color="#9f7aea" />
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#9f7aea', backgroundColor: 'rgba(159, 122, 234, 0.08)', padding: '3px 8px', borderRadius: '4px' }}>
                      ROLE_BASED_LENS
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                    Tailored Multi-Persona Views
                  </h3>
                  <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6 }}>
                    Instant toggle across SecOps incident isolation, SRE infrastructure health, FinOps unit economics,
                    and CISO board briefs.
                  </p>
                </div>
              </SpotlightCard>
            </div>

            {/* Bento 4: Supabase Zero-Trust Security (Col 8) */}
            <div className="bento-col-8 bento-item">
              <SpotlightCard>
                <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <div style={{
                      width: '40px',
                      height: '40px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(56, 217, 169, 0.1)',
                      border: '1px solid rgba(56, 217, 169, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      <Lock size={20} color="#38d9a9" />
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#38d9a9', backgroundColor: 'rgba(56, 217, 169, 0.08)', padding: '3px 8px', borderRadius: '4px' }}>
                      SUPABASE_AUTHENTICATED
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc', marginBottom: '10px' }}>
                    Cryptographic Zero-Trust RBAC
                  </h3>
                  <p style={{ fontSize: '0.9rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '20px' }}>
                    Mutations, remediations, and tenant switches require Supabase cryptographic HS256 JWT validation.
                    Zero plaintext OTP leaks, strictly enforced operator rosters, and tamper-resistant audit records.
                  </p>

                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '20px',
                    backgroundColor: '#070a10',
                    padding: '14px 18px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    marginTop: 'auto',
                    fontSize: '0.82rem',
                    color: '#cbd5e1',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#38d9a9' }}>
                      <CheckCircle2 size={15} />
                      <span>SEC-01 Cleared</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#38d9a9' }}>
                      <CheckCircle2 size={15} />
                      <span>SEC-02 Enforced</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#38d9a9' }}>
                      <CheckCircle2 size={15} />
                      <span>SEC-03 Locked</span>
                    </div>
                  </div>
                </div>
              </SpotlightCard>
            </div>
          </div>
        </section>

        {/* ── ARCHITECTURE SECTION ── */}
        <section id="architecture" style={{ padding: '70px 0 60px 0' }}>
          <div className="section-tag">
            <Cpu size={14} />
            <span>Architecture & Signal Pipeline</span>
          </div>
          <h2 className="section-title">Deterministic Signal Propagation</h2>
          <p className="section-desc">
            How CloudPulse ingests, evaluates, and mitigates cloud infrastructure drift without requiring intrusive agent
            binaries inside customer virtual machines.
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '16px',
            marginTop: '36px',
          }}>
            {[
              {
                num: '01',
                title: 'Azure Event Ingestion',
                desc: 'Consumes AzureActivity webhook logs and Resource Graph snapshots over TLS 1.3.',
                tag: 'ARG API v2021',
              },
              {
                num: '02',
                title: 'Signature Correlation',
                desc: 'Heuristic detectors cross-check resource tags, subnets, and cost baselines for policy anomalies.',
                tag: 'Rule Engine',
              },
              {
                num: '03',
                title: 'RBAC Authorization',
                desc: 'Requires authenticated SecOps operator token before modifying any infrastructure state.',
                tag: 'Supabase JWT',
              },
              {
                num: '04',
                title: 'REST Rollback & Audit',
                desc: 'Issues idempotent ARM REST calls to rollback unwanted drift and writes immutable audit logs.',
                tag: 'Azure ARM REST',
              },
            ].map(step => (
              <div
                key={step.num}
                style={{
                  backgroundColor: '#080c14',
                  borderRadius: '10px',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  padding: '24px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                  position: 'relative',
                }}
              >
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '1.4rem',
                  fontWeight: 800,
                  color: 'rgba(99, 179, 237, 0.4)',
                }}>
                  {step.num}
                </span>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9' }}>{step.title}</h4>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5 }}>{step.desc}</p>
                <div style={{
                  marginTop: 'auto',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  color: '#63b3ed',
                  backgroundColor: 'rgba(99, 179, 237, 0.08)',
                  padding: '3px 8px',
                  borderRadius: '4px',
                  width: 'fit-content',
                }}>
                  {step.tag}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── VERIFIED METRICS SECTION ── */}
        <section style={{ padding: '60px 0 70px 0' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '16px',
          }}>
            <div className="stat-item">
              <span className="stat-value" style={{ color: '#38d9a9' }}>&lt; 1.2s</span>
              <span className="stat-label">Mean Time to Detection</span>
              <span className="stat-subtext">Immediate alert dispatch upon Azure Activity ingestion.</span>
            </div>

            <div className="stat-item">
              <span className="stat-value" style={{ color: '#63b3ed' }}>100%</span>
              <span className="stat-label">Policy Rollback Precision</span>
              <span className="stat-subtext">Deterministic rollback payloads without side effects.</span>
            </div>

            <div className="stat-item">
              <span className="stat-value" style={{ color: '#f6ad55' }}>$240K+</span>
              <span className="stat-label">Annualized Idle Reclamation</span>
              <span className="stat-subtext">Automated detection of orphaned disks & oversized SKUs.</span>
            </div>

            <div className="stat-item">
              <span className="stat-value" style={{ color: '#f8fafc' }}>299/299</span>
              <span className="stat-label">Automated Test Pass Rate</span>
              <span className="stat-subtext">100% coverage on detection heuristics and auth RBAC.</span>
            </div>
          </div>
        </section>

        {/* ── ENTERPRISE CALL TO ACTION ── */}
        <section style={{
          padding: '60px',
          borderRadius: '16px',
          backgroundColor: '#0a0e18',
          border: '1px solid rgba(99, 179, 237, 0.3)',
          textAlign: 'center',
          position: 'relative',
          overflow: 'hidden',
          marginBottom: '80px',
          boxShadow: '0 20px 60px -15px rgba(0, 0, 0, 0.8)',
        }}>
          <h2 style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', marginBottom: '14px', letterSpacing: '-0.03em' }}>
            Ready to Take Control of Your Azure Estate?
          </h2>
          <p style={{ fontSize: '1rem', color: '#94a3b8', maxWidth: '600px', margin: '0 auto 32px auto', lineHeight: 1.6 }}>
            Connect your production, staging, or sandbox subscriptions in under two minutes with native zero-trust
            access.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <button className="btn-primary-console" onClick={onLaunchConsole} style={{ padding: '14px 34px', fontSize: '1rem' }}>
              <span>Enter CloudPulse Console</span>
              <ArrowRight size={18} color="#63b3ed" />
            </button>
            <button className="btn-secondary-outline" onClick={onOpenAuth} style={{ padding: '14px 26px', fontSize: '1rem' }}>
              <Lock size={16} />
              <span>Sign In with Supabase</span>
            </button>
          </div>
        </section>
      </div>

      {/* ── FOOTER ── */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.08))',
        backgroundColor: '#04060a',
        padding: '36px 0',
      }}>
        <div className="landing-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '24px',
              height: '24px',
              borderRadius: '6px',
              backgroundColor: '#0c121e',
              border: '1px solid rgba(99, 179, 237, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Shield size={13} color="#63b3ed" />
            </div>
            <span style={{ fontWeight: 700, fontSize: '0.9rem', color: '#f1f5f9' }}>CloudPulse</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#64748b' }}>
              © 2026 Enterprise Cyber Defense. All rights reserved.
            </span>
          </div>

          <div style={{ display: 'flex', gap: '20px', fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: '#64748b' }}>
            <span>SHA-256 VERIFIED</span>
            <span>REST API v1</span>
            <span>HUMAN-APPROVED REMEDIATION</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
