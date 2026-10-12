export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type RemediationStatus = 'PROPOSED' | 'APPROVED' | 'EXECUTING' | 'VERIFIED' | 'REJECTED' | 'FAILED' | 'PRECONDITION_FAILED' | 'VERIFICATION_FAILED';

export interface IncidentResource {
  id: string;
  name: string;
  type: string;
  resource_group: string;
  location?: string;
}

export interface IncidentIdentity {
  caller?: string;
  caller_ip?: string;
}

export interface TimelineEntry {
  timestamp: string;
  event: string;
  caller?: string;
  finding_id?: string;
  operation?: string;
  correlation_metadata?: {
    reason?: string;
    [key: string]: unknown;
  };
}

export interface CostImpact {
  correlation_strength: string;
  correlation_confidence: number;
  cost_category: string;
  actual_cost: number;
  baseline_cost: number;
  percentage_increase: number;
  deviation_absolute: number;
  currency?: string;
}

export interface RecommendedAction {
  id: string;
  title: string;
  description: string;
}

export interface AIAnalysis {
  status: 'COMPLETED' | 'UNAVAILABLE' | 'PENDING' | 'FAILED';
  execution_mode?: 'LIVE' | 'FALLBACK' | 'UNAVAILABLE';
  provider_status?: 'LIVE' | 'FALLBACK';
  model_identifier: string;
  confidence: number;
  latency_ms?: number;
  summary: string;
  risk_assessment: string;
  likely_scenario: string;
  facts: string[];
  inferences: string[];
  recommended_actions: RecommendedAction[];
  error_message?: string;
  error_category?: string;
}

export interface ActionRemediationState {
  status: RemediationStatus;
  approval?: {
    operator: string;
    notes?: string;
    timestamp?: string;
  };
  verification?: {
    verified_state: string;
    timestamp?: string;
  };
}

export interface IncidentRemediation {
  action_id?: string;
  status?: RemediationStatus;
  actions?: Record<string, ActionRemediationState>;
  approval?: {
    operator: string;
    notes?: string;
  };
  verification?: {
    verified_state: string;
  };
}

export interface Incident {
  incident_id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: IncidentStatus;
  created_at: string;
  resource: IncidentResource;
  identity?: IncidentIdentity;
  findings: string[];
  timeline: TimelineEntry[];
  cost_impact?: CostImpact;
  ai_analysis?: AIAnalysis;
  remediation?: IncidentRemediation;
}

export interface ResourceItem {
  id: string;
  name: string;
  type: string;
  location: string;
  resourceGroup?: string;
  provisioning_state?: string;
  actual_cost?: number | null;
  currency?: string;
  metrics_supported?: boolean;
  findings_count: number;
  max_severity?: Severity;
}

export interface FindingDetail {
  finding_id: string;
  finding_type: string;
  severity: Severity;
  timestamp: string;
  evidence?: Record<string, unknown>;
}

export interface ResourceMetricValue {
  name: string;
  display_name?: string;
  latest_value: number | string | null;
  unit?: string;
  latest_timestamp?: string;
}

export interface ResourceDetail {
  resource: {
    id: string;
    name: string;
    type: string;
    location: string;
    resourceGroup: string;
    provisioningState?: string;
    discovered_in_arg?: boolean;
  };
  cost: {
    has_billing_data: boolean;
    total_cost?: number;
    currency?: string;
    cost_category?: string;
    meters?: Array<{
      meter_name: string;
      cost: number;
    }>;
    period?: {
      billing_latency_notice?: string;
    };
  };
  utilization: {
    supported: boolean;
    message?: string;
    metrics?: Record<string, ResourceMetricValue>;
  };
  security: {
    findings_count: number;
    findings: FindingDetail[];
  };
  finops?: unknown;
  incidents: {
    count: number;
    incidents: Array<{
      incident_id: string;
      title: string;
      severity: Severity;
      status: IncidentStatus;
    }>;
  };
}

export interface CostAnomaly {
  resource_id: string;
  resource_name: string;
  resource_group: string;
  cost_category: string;
  evaluation_date: string;
  current_cost: number;
  baseline_cost: number;
  deviation_absolute: number;
  deviation_ratio: number;
  percentage_increase: number;
  std_dev: number;
  sample_days: number;
  confidence: number;
  currency: string;
}

export interface CostDriver {
  resource_name: string;
  resource_type: string;
  cost_category: string;
  total_cost: number;
  percentage_of_total: number;
  currency?: string;
}

export interface CostSummary {
  currency: string;
  has_data: boolean;
  summary?: {
    total_cost: number;
    resource_count: number;
  };
  period?: {
    start_date: string;
    end_date: string;
    billing_latency_notice?: string;
  };
  anomalies?: CostAnomaly[];
  top_cost_drivers?: CostDriver[];
}

export interface EstateOverview {
  subscription_id?: string;
  resources?: {
    total: number;
    by_type: Record<string, number>;
  };
  costs?: {
    has_data: boolean;
    total_cost: number;
    currency: string;
    latest_usage_date?: string;
    by_category: Record<string, number>;
  };
  security?: {
    total_incidents: number;
    correlated_incidents: number;
    by_severity: Record<string, number>;
  };
}

export interface HealthStatus {
  status: string;
  database?: {
    connected?: boolean;
    degraded?: boolean;
    degradation_reason?: string;
  };
  services?: Record<string, string>;
}

export type TabType = 'overview' | 'resources' | 'finops' | 'incidents';

export interface ToastMessage {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message?: string;
}

export type Persona = 'secops' | 'finops' | 'platform' | 'executive';

export interface TenantScope {
  id: string;
  name: string;
  subscriptionId: string;
  environment: 'production' | 'staging' | 'sandbox';
  region: string;
  isDemo?: boolean;
}

export interface OperatorProfile {
  id: string;
  name: string;
  role: string;
  email: string;
  organization: string;
}
