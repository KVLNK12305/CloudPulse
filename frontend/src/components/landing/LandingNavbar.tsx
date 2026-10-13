import React from 'react';
import { Shield, Terminal, ArrowRight, Lock, CheckCircle2, Cpu } from 'lucide-react';

interface LandingNavbarProps {
  onLaunchConsole: () => void;
  onOpenAuth: () => void;
  isAuthenticated: boolean;
  operatorName?: string;
}

export const LandingNavbar: React.FC<LandingNavbarProps> = ({
  onLaunchConsole,
  onOpenAuth,
  isAuthenticated,
  operatorName,
}) => {
  return (
    <header style={{
      position: 'sticky',
      top: 0,
      zIndex: 100,
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      backgroundColor: 'rgba(6, 9, 15, 0.85)',
      borderBottom: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.08))',
      padding: '12px 32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
    }}>
      {/* Brand & Monogram */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '28px' }}>
        <div
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
        >
          {/* Crisp Precision Logo Icon */}
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            backgroundColor: '#0c121e',
            border: '1px solid rgba(99, 179, 237, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(99, 179, 237, 0.15)',
          }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#63b3ed" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{
              fontWeight: 800,
              fontSize: '1.05rem',
              letterSpacing: '-0.02em',
              color: '#f8fafc',
            }}>
              CloudPulse
            </span>
            <span style={{
              fontSize: '0.65rem',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.08em',
              color: '#64748b',
              marginTop: '-2px',
            }}>
              AUTONOMOUS DEFENSE
            </span>
          </div>
        </div>

        {/* Section Links */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '20px' }} className="landing-nav-links">
          {[
            { label: 'Capabilities', href: '#capabilities' },
            { label: 'Architecture', href: '#architecture' },
            { label: 'Interactive Sandbox', href: '#sandbox' },
            { label: 'Multi-Persona Lens', href: '#personas' },
            { label: 'Zero-Trust RBAC', href: '#security' },
          ].map(link => (
            <a
              key={link.label}
              href={link.href}
              style={{
                color: '#94a3b8',
                fontSize: '0.82rem',
                textDecoration: 'none',
                fontWeight: 500,
                transition: 'color 0.15s ease',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = '#f1f5f9')}
              onMouseLeave={e => (e.currentTarget.style.color = '#94a3b8')}
            >
              {link.label}
            </a>
          ))}
        </nav>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Telemetry Health Pill */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '5px 10px',
          borderRadius: '999px',
          backgroundColor: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.72rem',
          color: '#38d9a9',
        }}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10b981', boxShadow: '0 0 8px #10b981' }} />
          <span>AZURE TELEMETRY 100% NOMINAL</span>
        </div>

        {/* Supabase Operator Auth */}
        <button
          onClick={onOpenAuth}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '6px 12px',
            borderRadius: '6px',
            backgroundColor: 'transparent',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#cbd5e1',
            fontSize: '0.8rem',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.25)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.backgroundColor = 'transparent';
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)';
          }}
        >
          <Lock size={13} color="#94a3b8" />
          <span>{isAuthenticated ? (operatorName || 'Operator Active') : 'Supabase Sign In'}</span>
        </button>

        {/* Launch Live Console Button */}
        <button
          onClick={onLaunchConsole}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '7px 16px',
            borderRadius: '6px',
            backgroundColor: '#17253d',
            border: '1px solid rgba(99, 179, 237, 0.5)',
            color: '#f8fafc',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            boxShadow: '0 0 16px rgba(99, 179, 237, 0.2)',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.backgroundColor = '#1e3252';
            e.currentTarget.style.boxShadow = '0 0 24px rgba(99, 179, 237, 0.35)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.backgroundColor = '#17253d';
            e.currentTarget.style.boxShadow = '0 0 16px rgba(99, 179, 237, 0.2)';
          }}
        >
          <span>Launch Live Console</span>
          <ArrowRight size={14} color="#63b3ed" />
        </button>
      </div>
    </header>
  );
};
