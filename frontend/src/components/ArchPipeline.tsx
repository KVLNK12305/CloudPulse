import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import {
  Brain,
  CheckCircle,
  Database,
  DollarSign,
  FileText,
  LineChart,
  Shield,
  Zap,
} from 'lucide-react';

const steps = [
  {
    num: '1',
    name: 'Resource Graph',
    sub: 'Live Topological Inventory',
    desc: 'KQL discovery of actual provisioned Azure estate, tags, and topological relationships.',
    color: '#38bdf8',
    icon: Database,
    badge: 'ARG Scope',
  },
  {
    num: '2',
    name: 'Azure Monitor',
    sub: 'Runtime Metrics',
    desc: 'Direct telemetry stream measuring real CPU utilization, memory pressure, and NIC throughput.',
    color: '#38d9a9',
    icon: LineChart,
    badge: 'Live Metrics',
  },
  {
    num: '3',
    name: 'Cost Management',
    sub: 'Metered Consumption',
    desc: 'Actual closed daily billing records and 14-day rolling statistical variance baseline.',
    color: '#f6ad55',
    icon: DollarSign,
    badge: 'ActualCost',
  },
  {
    num: '4',
    name: 'Log Analytics',
    sub: 'Activity & Flow Logs',
    desc: 'AzureActivity audit events, NSG flow logs, and suspicious egress correlation.',
    color: '#06b6d4',
    icon: FileText,
    badge: 'Kusto / KQL',
  },
  {
    num: '5',
    name: 'AI Advisory Triage',
    sub: 'Autonomous Synthesis',
    desc: 'Telemetry-grounded synthesis with tripartition of facts, inferences, and controlled actions.',
    color: '#9f7aea',
    icon: Brain,
    badge: 'Azure OpenAI',
  },
  {
    num: '6',
    name: 'Human Approval Gate',
    sub: 'Controlled Remediation',
    desc: 'Zero unapproved mutations; optimistic concurrency and live ARM readback verification.',
    color: '#fc8181',
    icon: CheckCircle,
    badge: 'Human-in-Loop',
  },
];

export const ArchPipeline: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      const stepEls = containerRef.current.querySelectorAll('.flow-step');
      gsap.fromTo(
        stepEls,
        { opacity: 0, y: 12 },
        {
          opacity: 1,
          y: 0,
          duration: 0.4,
          stagger: 0.06,
          ease: 'power2.out',
        }
      );
    }
  }, []);

  return (
    <div className="arch-flow-card" ref={containerRef}>
      <div className="arch-flow-title">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Zap size={15} color="var(--accent-sky)" />
          <span style={{ fontWeight: 800, letterSpacing: '-0.01em' }}>
            Live Telemetry to Controlled Remediation Pipeline
          </span>
        </div>
        <span className="source-badge arg">Azure Estate Engine</span>
      </div>

      <div className="arch-flow-steps">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isHovered = activeStep === idx;
          return (
            <div
              key={step.num}
              className="flow-step"
              onMouseEnter={() => setActiveStep(idx)}
              onMouseLeave={() => setActiveStep(null)}
              style={{
                borderColor: isHovered ? step.color : undefined,
                boxShadow: isHovered ? `0 0 16px ${step.color}25` : undefined,
                transform: isHovered ? 'translateY(-2px)' : undefined,
                transition: 'all 0.2s cubic-bezier(0.22, 1, 0.36, 1)',
                cursor: 'pointer',
              }}
            >
              <div className="flow-step-num" style={{ color: step.color }}>
                <Icon size={14} color={step.color} />
                <span>
                  {step.num}. {step.name}
                </span>
              </div>
              <div className="flow-step-title">{step.sub}</div>
              <div className="flow-step-desc">{step.desc}</div>
              <div style={{ marginTop: '8px' }}>
                <span
                  style={{
                    fontSize: '0.62rem',
                    fontFamily: 'var(--font-mono)',
                    color: step.color,
                    background: `${step.color}15`,
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-xs)',
                    fontWeight: 600,
                  }}
                >
                  {step.badge}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
