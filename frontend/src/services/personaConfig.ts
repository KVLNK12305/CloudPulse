import { Incident, OperatorProfile, Persona, TabType } from '../types';

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
    email: 'kls2edmentre@gmail.com',
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
    email: 'siddu28@gmail.com',
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
    email: 'krishnasaketh566@gmail.com',
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
    email: 'rishinathkurup@gmail.com',
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
    badge: 'PERIMETER SECURE',
    color: '#fc8181',
    accentBg: 'rgba(252, 129, 129, 0.08)',
    accentBorder: 'rgba(252, 129, 129, 0.28)',
    tagline: 'Zero-Trust Blast Radius & Remediation Gate',
    directive:
      'Zero-Trust Perimeter Defense — All workloads nominal. 0 open security threats, egress filtering active, zero uncontained breach vectors.',
    primaryTab: 'incidents',
    operator: OPERATOR_TEAM[0],
    focusHighlights: {
      heroMetricTitle: 'Open Security Incidents',
      heroMetricReason: '0 uncontained breach vectors · Perimeter active',
      quickFilterLabel: 'Perimeter Active',
      suggestedAction: 'Audit Perimeter Rules',
      actionTab: 'resources',
    },
    lensDescription:
      'Prioritizing zero-trust workload boundaries, NSG egress filtering, and automated ARM containment readiness.',
    keyInsights: [
      {
        label: 'Active Attack Vectors',
        value: '0 Detected',
        subtext: 'Firewall & NSG boundaries nominal',
        status: 'optimal',
      },
      {
        label: 'Exfiltration Target',
        value: 'None Active',
        subtext: 'Nominal outbound network flow',
        status: 'optimal',
      },
      {
        label: 'Containment Gate',
        value: 'Standby / Armed',
        subtext: 'Zero mutations pending',
        status: 'info',
      },
    ],
  },
  finops: {
    id: 'finops',
    label: 'FinOps Economist',
    roleTitle: 'Cloud Financial Management & Unit Economics',
    badge: 'UNIT ECONOMICS NOMINAL',
    color: '#38d9a9',
    accentBg: 'rgba(56, 217, 169, 0.08)',
    accentBorder: 'rgba(56, 217, 169, 0.28)',
    tagline: 'Cost Anomaly Correlation & Run-Rate Governance',
    directive:
      'Unit Cost Variance Governance — Tracking spend velocity, 14-day statistical baseline, and idle cloud waste avoidance.',
    primaryTab: 'finops',
    operator: OPERATOR_TEAM[2],
    focusHighlights: {
      heroMetricTitle: 'Correlated Overrun',
      heroMetricReason: '+$0.00 anomaly deviation — Workload spend within budget envelope',
      quickFilterLabel: 'Sort by Highest Billed Cost',
      suggestedAction: 'Audit Cost Baseline',
      actionTab: 'finops',
    },
    lensDescription:
      'Prioritizing unit cost economics, statistical baseline deviation (CV < 1.0), and projected monthly budget burn velocity.',
    keyInsights: [
      {
        label: 'Unplanned Outlier Surge',
        value: '+$0.00 Egress',
        subtext: 'Nominal baseline variance (CV < 1.0)',
        status: 'optimal',
      },
      {
        label: 'Budget Variance Multiplier',
        value: '0.8x Stable',
        subtext: 'Standard sigma envelope',
        status: 'optimal',
      },
      {
        label: 'Budget Window Trajectory',
        value: 'Nominal Burn',
        subtext: 'Tracking within $500.00 14-day cycle',
        status: 'optimal',
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
        value: 'Network Isolated',
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
      'Enterprise Risk Exposure & Audit Readiness — SLA compliance 99.8%, CIS Azure 5.1 readiness, zero active high-exposure breach vectors.',
    primaryTab: 'overview',
    operator: OPERATOR_TEAM[3],
    focusHighlights: {
      heroMetricTitle: 'Enterprise Risk Exposure',
      heroMetricReason: '0 active threats · Baseline compliance verified',
      quickFilterLabel: 'All Monitored Assets',
      suggestedAction: 'Export CISO Executive Brief',
      actionTab: 'overview',
    },
    lensDescription:
      'Prioritizing macro risk exposure, regulatory compliance (SOC2/CIS), executive incident briefs, and board audit readiness.',
    keyInsights: [
      {
        label: 'Enterprise Risk Score',
        value: 'Low Exposure',
        subtext: '0 correlated threat incidents',
        status: 'optimal',
      },
      {
        label: 'Compliance Scope',
        value: 'SOC 2 & CIS 5.1',
        subtext: 'Zero high-severity violations',
        status: 'optimal',
      },
      {
        label: 'Board Incident Brief',
        value: 'Audit Ready',
        subtext: '1-Click Markdown, Jira, and Slack format',
        status: 'info',
      },
    ],
  },
};

export interface PersonaTelemetryContext {
  incidents?: Incident[];
  resourceCount?: number;
  costTotal?: number;
  costCurrency?: string;
  topCorrIncident?: Incident | null;
}

export function getPersonaConfig(
  persona: Persona,
  ctx?: PersonaTelemetryContext
): PersonaConfig {
  const base = PERSONA_CONFIGS[persona];
  if (!ctx) return base;

  const incidents = ctx.incidents || [];
  const openIncidents = incidents.filter(
    i => i.status === 'OPEN' || i.status === 'INVESTIGATING'
  );
  const resolvedIncidents = incidents.filter(
    i => i.status === 'RESOLVED' || i.status === 'CLOSED'
  );

  const topCorr =
    ctx.topCorrIncident !== undefined
      ? ctx.topCorrIncident
      : incidents.find(i => !!i.cost_impact) || null;

  const costTotal = ctx.costTotal ?? 0;
  const currency = ctx.costCurrency || 'USD';
  const resourceCount = ctx.resourceCount ?? 0;

  const formatCurr = (val: number, cur = currency) =>
    new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: cur,
      maximumFractionDigits: 2,
    }).format(val);

  const budgetLimit = 500;
  const budgetPct = Math.min(Math.round((costTotal / budgetLimit) * 100), 100);

  // 1. SECOPS
  if (persona === 'secops') {
    if (openIncidents.length === 0 && resolvedIncidents.length === 0) {
      return {
        ...base,
        badge: 'PERIMETER SECURE',
        directive:
          'Zero-Trust Perimeter Defense — All workloads nominal. 0 open security threats, egress filtering active, zero uncontained breach vectors.',
        focusHighlights: {
          heroMetricTitle: 'Open Security Incidents',
          heroMetricReason: '0 uncontained breach vectors · Perimeter active',
          quickFilterLabel: 'Perimeter Active',
          suggestedAction: 'Audit Perimeter Rules',
          actionTab: 'resources',
        },
        lensDescription:
          'Prioritizing zero-trust workload boundaries, NSG egress filtering, and automated ARM containment readiness.',
        keyInsights: [
          {
            label: 'Active Attack Vectors',
            value: '0 Detected',
            subtext: 'Firewall & NSG boundaries nominal',
            status: 'optimal',
          },
          {
            label: 'Exfiltration Target',
            value: 'None Active',
            subtext: 'Nominal outbound network flow',
            status: 'optimal',
          },
          {
            label: 'Containment Gate',
            value: 'Standby / Armed',
            subtext: 'Zero mutations pending',
            status: 'info',
          },
        ],
      };
    }

    if (openIncidents.length === 0 && resolvedIncidents.length > 0) {
      return {
        ...base,
        badge: 'THREAT CONTAINED',
        directive:
          'Perimeter Remediated — All identified breach vectors neutralized and quarantined. Forensic telemetry verified.',
        focusHighlights: {
          heroMetricTitle: 'Remediated Incidents',
          heroMetricReason: 'All threat vectors contained and verified',
          quickFilterLabel: 'Resolved Incidents',
          suggestedAction: 'View Audit Log',
          actionTab: 'incidents',
        },
        lensDescription:
          'Post-incident verification, forensic audit logs, and verified cloud containment assurance.',
        keyInsights: [
          {
            label: 'Active Attack Vectors',
            value: '0 Uncontained',
            subtext: 'All workloads quarantined',
            status: 'optimal',
          },
          {
            label: 'Exfiltration Target',
            value: 'Halted',
            subtext: 'Outbound flow terminated',
            status: 'optimal',
          },
          {
            label: 'Containment Gate',
            value: 'Executed',
            subtext: 'ARM isolation applied',
            status: 'optimal',
          },
        ],
      };
    }

    const topInc = openIncidents[0];
    return {
      ...base,
      badge: 'THREAT VECTOR DEFENSE',
      directive: `Active Attack Surface Defense — Prioritizing ${openIncidents.length} uncontained breach vector${openIncidents.length > 1 ? 's' : ''
        } on ${topInc.resource?.name || 'workload'}, unauthorized egress, and live ARM isolation gates.`,
      focusHighlights: {
        heroMetricTitle: 'Open Security Incidents',
        heroMetricReason: `${openIncidents.length} Critical breach vector${openIncidents.length > 1 ? 's' : ''
          } awaiting remediation gate`,
        quickFilterLabel: 'Critical Threats Only',
        suggestedAction: 'Review Containment Gate',
        actionTab: 'incidents',
      },
      lensDescription:
        'Prioritizing vulnerable workloads, external attacker IPs, anomalous data exfiltration, and ARM containment authorization.',
      keyInsights: [
        {
          label: 'Active Attack Vectors',
          value: `${openIncidents.length} Uncontained`,
          subtext: `${topInc.resource?.name || 'workload'} (${topInc.title})`,
          status: 'critical',
        },
        {
          label: 'Exfiltration Target',
          value: topInc.cost_impact
            ? `+${topInc.cost_impact.percentage_increase.toFixed(0)}% Surge`
            : topInc.identity?.caller_ip || 'Suspicious Egress',
          subtext: topInc.cost_impact
            ? `+${formatCurr(
              topInc.cost_impact.deviation_absolute,
              topInc.cost_impact.currency
            )} deviation`
            : 'Anomalous outbound transfer',
          status: 'critical',
        },
        {
          label: 'Containment Gate',
          value: 'Human Auth Req',
          subtext: 'Isolate NIC / Revoke NSG Rule',
          status: 'warning',
        },
      ],
    };
  }

  // 2. FINOPS
  if (persona === 'finops') {
    const isTopCorrResolved =
      topCorr &&
      (topCorr.status === 'RESOLVED' || topCorr.status === 'CLOSED');

    if (isTopCorrResolved) {
      const devAbs = topCorr?.cost_impact?.deviation_absolute || 181.2;
      return {
        ...base,
        badge: 'OVERRUN ARRESTED',
        directive: `Run-Rate Recovered — Threat-driven egress halted. Overrun of +${formatCurr(
          devAbs,
          topCorr?.cost_impact?.currency || currency
        )} arrested. Monthly avoidance secured.`,
        focusHighlights: {
          heroMetricTitle: 'Arrested Overrun',
          heroMetricReason:
            'Contained threat vector halted runaway monthly egress waste',
          quickFilterLabel: 'Sort by Highest Billed Cost',
          suggestedAction: 'Audit Cost Baseline',
          actionTab: 'finops',
        },
        lensDescription:
          'Post-containment unit economics, verified billing halt, and monthly savings realization.',
        keyInsights: [
          {
            label: 'Unplanned Outlier Surge',
            value: 'Arrested',
            subtext: 'Egress meter halted post-containment',
            status: 'optimal',
          },
          {
            label: 'Containment Run-Rate ROI',
            value: `Avoided ~${formatCurr((devAbs * 30) / 14, currency)}/mo`,
            subtext: 'Runaway billing prevented',
            status: 'optimal',
          },
          {
            label: 'Budget Window Trajectory',
            value: `${budgetPct}% Burned`,
            subtext: `${formatCurr(costTotal, currency)} of $500.00 14-day cycle`,
            status: 'optimal',
          },
        ],
      };
    }

    if (!topCorr || openIncidents.length === 0) {
      return {
        ...base,
        badge: 'UNIT ECONOMICS NOMINAL',
        directive: `Unit Cost Variance Governance — Cloud spend tracking within nominal baseline (${formatCurr(
          costTotal,
          currency
        )} actual). Zero statistical cost outliers or threat overruns.`,
        focusHighlights: {
          heroMetricTitle: 'Correlated Overrun',
          heroMetricReason:
            '+$0.00 anomaly deviation — All workloads within nominal budget',
          quickFilterLabel: 'Sort by Highest Billed Cost',
          suggestedAction: 'Audit Cost Baseline',
          actionTab: 'finops',
        },
        lensDescription:
          'Prioritizing unit cost economics, statistical baseline deviation (CV < 1.0), and projected monthly budget burn velocity.',
        keyInsights: [
          {
            label: 'Unplanned Outlier Surge',
            value: '+$0.00 Egress',
            subtext: 'Nominal baseline variance (CV < 1.0)',
            status: 'optimal',
          },
          {
            label: 'Budget Variance Multiplier',
            value: '0.8x Stable',
            subtext: 'Standard sigma envelope',
            status: 'optimal',
          },
          {
            label: 'Budget Window Trajectory',
            value: `${budgetPct}% Burned`,
            subtext: `${formatCurr(costTotal, currency)} of $500.00 14-day cycle`,
            status: budgetPct > 80 ? 'warning' : 'optimal',
          },
        ],
      };
    }

    const devAbs = topCorr.cost_impact?.deviation_absolute || 181.2;
    const pctInc = topCorr.cost_impact?.percentage_increase || 1276;
    const curr = topCorr.cost_impact?.currency || currency;

    return {
      ...base,
      badge: 'UNIT ECONOMICS & VARIANCE',
      directive: `Unit Cost Variance Mitigation — Tracking +${formatCurr(
        devAbs,
        curr
      )} anomaly surge (+${pctInc.toFixed(
        0
      )}%), budget burn velocity, and idle cloud waste avoidance.`,
      focusHighlights: {
        heroMetricTitle: 'Correlated Overrun',
        heroMetricReason: `+${formatCurr(
          devAbs,
          curr
        )} unexpected spike linked directly to threat vector exfiltration`,
        quickFilterLabel: 'Sort by Highest Billed Cost',
        suggestedAction: 'Audit Anomaly Multipliers',
        actionTab: 'finops',
      },
      lensDescription:
        'Prioritizing unit cost economics, statistical baseline deviation (CV > 1.5), and projected monthly budget burn velocity.',
      keyInsights: [
        {
          label: 'Unplanned Outlier Surge',
          value: `+${formatCurr(devAbs, curr)} Egress`,
          subtext: `+${pctInc.toFixed(0)}% peak baseline deviation`,
          status: 'critical',
        },
        {
          label: 'Containment Run-Rate ROI',
          value: `~${formatCurr((devAbs * 30) / 14, curr)} / mo`,
          subtext: 'Projected monthly billing avoidance',
          status: 'optimal',
        },
        {
          label: 'Budget Window Trajectory',
          value: `${budgetPct}% Burned`,
          subtext: `${formatCurr(costTotal, currency)} of $500.00 14-day cycle`,
          status: 'info',
        },
      ],
    };
  }

  // 3. PLATFORM
  if (persona === 'platform') {
    const isTargeted = openIncidents.length > 0;
    const targetName = openIncidents[0]?.resource?.name || 'Worker';
    return {
      ...base,
      badge: 'INFRASTRUCTURE & TOPOLOGY',
      directive: `Infrastructure Resiliency & ARM State Fidelity — Monitoring ${resourceCount || 3
        } active workloads, subnet routing, and runtime metric collection health.`,
      focusHighlights: {
        heroMetricTitle: 'Active Cloud Workloads',
        heroMetricReason:
          'Telemetry probes collecting runtime metrics and ARM topology state',
        quickFilterLabel: 'Filter: Monitored Workloads Only',
        suggestedAction: 'Inspect Resource Graph',
        actionTab: 'resources',
      },
      lensDescription:
        'Prioritizing ARM topology mappings, NIC bindings, NSG firewall rules, and Azure Monitor telemetry health.',
      keyInsights: [
        {
          label: 'Discovered ARM Workloads',
          value: `${resourceCount || 3} Resources`,
          subtext: 'VM, Network Interface, NSG',
          status: 'info',
        },
        {
          label: 'Subnet Blast Radius',
          value: isTargeted ? `${targetName} Targeted` : 'Network Isolated',
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
    };
  }

  // 4. EXECUTIVE / CISO
  if (persona === 'executive') {
    if (openIncidents.length === 0 && resolvedIncidents.length === 0) {
      return {
        ...base,
        badge: 'GOVERNANCE & RISK OVERSIGHT',
        directive:
          'Enterprise Risk Exposure & Audit Readiness — SLA compliance 99.8%, CIS Azure 5.1 readiness, zero active high-exposure breach vectors.',
        focusHighlights: {
          heroMetricTitle: 'Enterprise Risk Exposure',
          heroMetricReason: '0 active threats · Baseline compliance verified',
          quickFilterLabel: 'All Monitored Assets',
          suggestedAction: 'Export CISO Executive Brief',
          actionTab: 'overview',
        },
        lensDescription:
          'Prioritizing macro risk exposure, regulatory compliance (SOC2/CIS), executive incident briefs, and board audit readiness.',
        keyInsights: [
          {
            label: 'Enterprise Risk Score',
            value: 'Low Exposure',
            subtext: '0 correlated threat incidents',
            status: 'optimal',
          },
          {
            label: 'Compliance Scope',
            value: 'SOC 2 & CIS 5.1',
            subtext: 'Zero high-severity violations',
            status: 'optimal',
          },
          {
            label: 'Board Incident Brief',
            value: 'Audit Ready',
            subtext: '1-Click Markdown, Jira, and Slack format',
            status: 'info',
          },
        ],
      };
    }

    if (openIncidents.length === 0 && resolvedIncidents.length > 0) {
      return {
        ...base,
        badge: 'AUDIT ASSURANCE',
        directive:
          'Enterprise Risk Restored — Breach contained and documented. Post-incident forensic audit ready for board review.',
        focusHighlights: {
          heroMetricTitle: 'Enterprise Risk Exposure',
          heroMetricReason:
            'All incidents remediated · Compliance restored',
          quickFilterLabel: 'Remediated Incidents',
          suggestedAction: 'Export Forensic Brief',
          actionTab: 'overview',
        },
        lensDescription:
          'Post-incident governance, forensic audit verification, and executive stakeholder briefing.',
        keyInsights: [
          {
            label: 'Enterprise Risk Score',
            value: 'Remediated',
            subtext: 'Zero uncontained vectors',
            status: 'optimal',
          },
          {
            label: 'Compliance Scope',
            value: 'SOC 2 & CIS 5.1',
            subtext: 'Remediation actions audited',
            status: 'optimal',
          },
          {
            label: 'Board Incident Brief',
            value: 'Post-Mortem Ready',
            subtext: 'Forensic brief export ready',
            status: 'info',
          },
        ],
      };
    }

    return {
      ...base,
      badge: 'GOVERNANCE & RISK OVERSIGHT',
      directive: `Enterprise Risk Exposure & Audit Readiness — Tracking ${openIncidents.length
        } active critical threat vector${openIncidents.length > 1 ? 's' : ''
        }, SLA compliance 99.4%, and cross-vector executive brief exports.`,
      focusHighlights: {
        heroMetricTitle: 'SecOps ↔ FinOps Concurrence',
        heroMetricReason:
          'Multi-vector threat-financial concurrence spotlight active',
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
          subtext: `${openIncidents.length} Critical correlated incident${openIncidents.length > 1 ? 's' : ''
            } active`,
          status: 'critical',
        },
        {
          label: 'Compliance Scope',
          value: 'SOC 2 & CIS 5.1',
          subtext: 'Unrestricted perimeter rule flagged',
          status: 'warning',
        },
        {
          label: 'Board Incident Brief',
          value: 'Export Ready',
          subtext: '1-Click Markdown, Jira, and Slack format',
          status: 'info',
        },
      ],
    };
  }

  return base;
}
