import { OperatorProfile, Persona, TabType } from '../types';

export interface PersonaConfig {
  id: Persona;
  label: string;
  roleTitle: string;
  badge: string;
  color: string;
  accentBg: string;
  accentBorder: string;
  tagline: string;
  directive: string;
  primaryTab: TabType;
  operator: OperatorProfile;
  focusHighlights: {
    heroMetricTitle: string;
    heroMetricReason: string;
    quickFilterLabel: string;
    suggestedAction: string;
    actionTab: TabType;
  };
  lensDescription: string;
  keyInsights: Array<{
    label: string;
    value: string;
    subtext: string;
    status: 'critical' | 'warning' | 'optimal' | 'info';
  }>;
}

export const OPERATOR_TEAM: OperatorProfile[] = [
  {
    id: 'op-kushal',
    name: 'K V L N Kushal',
    initials: 'KK',
    role: 'Lead SecOps Commander & CISO (Full Access)',
    email: 'kvlnkushal@cloudpulse.io',
    organization: 'Enterprise Cyber Defense & Core SecOps',
    primaryPersona: 'secops',
    allowedPersonas: ['secops', 'executive', 'platform', 'finops'],
    isSuperAdmin: true,
  },
  {
    id: 'op-siddardha',
    name: 'K S V siddardha',
    initials: 'KS',
    role: 'Platform SRE Lead',
    email: 'siddardha@cloudpulse.io',
    organization: 'Cloud Platform Engineering & SRE',
    primaryPersona: 'platform',
    allowedPersonas: ['platform'],
    isSuperAdmin: false,
  },
  {
    id: 'op-saketh',
    name: 'R K Saketh',
    initials: 'RS',
    role: 'Principal FinOps Economist',
    email: 'saketh@cloudpulse.io',
    organization: 'Cloud Financial Operations & Economics',
    primaryPersona: 'finops',
    allowedPersonas: ['finops'],
    isSuperAdmin: false,
  },
  {
    id: 'op-rishinath',
    name: 'RishinathKurup',
    initials: 'RK',
    role: 'Chief Information Security Officer (CISO)',
    email: 'rishinath.kurup@cloudpulse.io',
    organization: 'Enterprise Risk & Board Governance',
    primaryPersona: 'executive',
    allowedPersonas: ['executive'],
    isSuperAdmin: false,
  },
];

export const PERSONA_CONFIGS: Record<Persona, PersonaConfig> = {
  secops: {
    id: 'secops',
    label: 'SecOps Commander',
    roleTitle: 'Security Operations & Threat Response',
    badge: 'THREAT VECTOR DEFENSE',
    color: '#fc8181',
    accentBg: 'rgba(252, 129, 129, 0.08)',
    accentBorder: 'rgba(252, 129, 129, 0.28)',
    tagline: 'Zero-Trust Blast Radius & Remediation Gate',
    directive:
      'Active Attack Surface Defense — Prioritizing uncontained breach vectors, unauthorized egress to 198.51.100.77:443, and live ARM isolation gates.',
    primaryTab: 'incidents',
    operator: OPERATOR_TEAM[0],
    focusHighlights: {
      heroMetricTitle: 'Open Security Incidents',
      heroMetricReason: '1 Critical breach vector awaiting remediation gate',
      quickFilterLabel: 'Critical Threats Only',
      suggestedAction: 'Review Containment Gate',
      actionTab: 'incidents',
    },
    lensDescription:
      'Prioritizing vulnerable workloads, external attacker IPs, anomalous data exfiltration, and ARM containment authorization.',
    keyInsights: [
      {
        label: 'Active Attack Vectors',
        value: '1 Uncontained',
        subtext: 'vm-worker-01 (SSH Port 22)',
        status: 'critical',
      },
      {
        label: 'Exfiltration Target',
        value: '198.51.100.77:443',
        subtext: '16.5 GB anomalous outbound transfer',
        status: 'critical',
      },
      {
        label: 'Containment Gate',
        value: 'Human Auth Req',
        subtext: 'Isolate NIC / Revoke NSG Rule',
        status: 'warning',
      },
    ],
  },
  finops: {
    id: 'finops',
    label: 'FinOps Economist',
    roleTitle: 'Cloud Financial Management & Unit Economics',
    badge: 'UNIT ECONOMICS & VARIANCE',
    color: '#38d9a9',
    accentBg: 'rgba(56, 217, 169, 0.08)',
    accentBorder: 'rgba(56, 217, 169, 0.28)',
    tagline: 'Cost Anomaly Correlation & Run-Rate Governance',
    directive:
      'Unit Cost Variance Mitigation — Tracking $181.20 anomaly surge (+1276%), budget burn velocity, and idle cloud waste avoidance.',
    primaryTab: 'finops',
    operator: OPERATOR_TEAM[2],
    focusHighlights: {
      heroMetricTitle: 'Correlated Overrun',
      heroMetricReason: '$181.20 unexpected spike linked directly to threat vector exfiltration',
      quickFilterLabel: 'Sort by Highest Billed Cost',
      suggestedAction: 'Audit Anomaly Multipliers',
      actionTab: 'finops',
    },
    lensDescription:
      'Prioritizing unit cost economics, statistical baseline deviation (CV > 1.5), and projected monthly budget burn velocity.',
    keyInsights: [
      {
        label: 'Unplanned Outlier Surge',
        value: '+$181.20 Egress',
        subtext: '+1276% peak baseline deviation',
        status: 'critical',
      },
      {
        label: 'Containment Run-Rate ROI',
        value: '$4,340 / mo',
        subtext: 'Projected monthly billing avoidance',
        status: 'optimal',
      },
      {
        label: 'Budget Window Trajectory',
        value: '36% Burned',
        subtext: '$181.20 of $500.00 14-day cycle',
        status: 'info',
      },
    ],
  },
  platform: {
    id: 'platform',
    label: 'Platform SRE',
    roleTitle: 'Cloud Reliability & ARM Topology Engineering',
    badge: 'INFRASTRUCTURE & TOPOLOGY',
    color: '#63b3ed',
    accentBg: 'rgba(99, 179, 237, 0.08)',
    accentBorder: 'rgba(99, 179, 237, 0.28)',
    tagline: 'ARM Inventory, Network Isolation & Telemetry Health',
    directive:
      'Infrastructure Resiliency & ARM State Fidelity — Monitoring 3 active workloads, subnet routing, and runtime metric collection health.',
    primaryTab: 'resources',
    operator: OPERATOR_TEAM[1],
    focusHighlights: {
      heroMetricTitle: 'Active Cloud Workloads',
      heroMetricReason: 'Telemetry probes collecting runtime metrics and ARM topology state',
      quickFilterLabel: 'Filter: Monitored Workloads Only',
      suggestedAction: 'Inspect Resource Graph',
      actionTab: 'resources',
    },
    lensDescription:
      'Prioritizing ARM topology mappings, NIC bindings, NSG firewall rules, and Azure Monitor telemetry health.',
    keyInsights: [
      {
        label: 'Discovered ARM Workloads',
        value: '3 Resources',
        subtext: 'VM, Network Interface, NSG',
        status: 'info',
      },
      {
        label: 'Subnet Blast Radius',
        value: 'snet-worker Isolated',
        subtext: 'vnet-cloudpulse database tier protected',
        status: 'optimal',
      },
      {
        label: 'Runtime Metric Probes',
        value: 'Healthy (15s)',
        subtext: 'Azure Monitor metric pipeline live',
        status: 'optimal',
      },
    ],
  },
  executive: {
    id: 'executive',
    label: 'Executive CISO',
    roleTitle: 'Executive Governance, Risk & Board Oversight',
    badge: 'GOVERNANCE & RISK OVERSIGHT',
    color: '#b794f4',
    accentBg: 'rgba(183, 148, 244, 0.08)',
    accentBorder: 'rgba(183, 148, 244, 0.28)',
    tagline: 'Macro Cloud Exposure & Board-Ready Audit Briefs',
    directive:
      'Enterprise Risk Exposure & Audit Readiness — SLA compliance 99.4%, CIS Azure 5.1 readiness, and cross-vector executive brief exports.',
    primaryTab: 'overview',
    operator: OPERATOR_TEAM[3],
    focusHighlights: {
      heroMetricTitle: 'SecOps ↔ FinOps Concurrence',
      heroMetricReason: 'Multi-vector threat-financial concurrence spotlight active',
      quickFilterLabel: 'High-Exposure Assets Only',
      suggestedAction: 'Generate Executive Brief',
      actionTab: 'overview',
    },
    lensDescription:
      'Prioritizing macro risk exposure, regulatory compliance (SOC2/CIS), executive incident briefs, and board audit readiness.',
    keyInsights: [
      {
        label: 'Enterprise Risk Score',
        value: 'High Exposure',
        subtext: '1 Critical correlated incident active',
        status: 'critical',
      },
      {
        label: 'Compliance Scope',
        value: 'SOC 2 & CIS 5.1',
        subtext: 'Unrestricted SSH rule flagged',
        status: 'warning',
      },
      {
        label: 'Board Incident Brief',
        value: 'Export Ready',
        subtext: '1-Click Markdown, Jira, and Slack format',
        status: 'info',
      },
    ],
  },
};
