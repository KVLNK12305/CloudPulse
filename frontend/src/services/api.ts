import {
  CostSummary,
  EstateOverview,
  FindingDetail,
  HealthStatus,
  Incident,
  IncidentStatus,
  OperatorProfile,
  ResourceDetail,
  ResourceItem,
} from '../types';

export function formatCurrency(amount: number | null | undefined, currency: string = 'USD'): string {
  if (amount === null || amount === undefined || isNaN(Number(amount))) return '—';
  const c = (currency || 'USD').toUpperCase();
  const symbol = c === 'USD' ? '$' : (c === 'INR' ? '₹' : (c === 'EUR' ? '€' : (c === 'GBP' ? '£' : c + ' ')));
  return `${symbol}${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

export function isDemoIncident(inc: Incident | null | undefined): boolean {
  if (!inc) return false;
  const rName = (inc.resource?.name || '').toLowerCase();
  const caller = (inc.identity?.caller || '').toLowerCase();
  const incId = (inc.incident_id || '').toLowerCase();
  if (rName === 'vm-worker-01' || caller === 'admin@cloudpulse.io') return true;
  if (incId.includes('demo') || (inc.findings || []).some(f => typeof f === 'string' && f.toLowerCase().includes('demo'))) {
    return true;
  }
  return false;
}

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('cloudpulse_auth_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function postSeed(path: string, body: unknown): Promise<Response> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    if (res.status === 401) throw new Error('Sign in as a SecOps operator to seed demo telemetry.');
    if (res.status === 403) throw new Error('Seeding demo telemetry requires the SecOps role.');
    throw new Error(err.message || err.error || `${path} failed (${res.status})`);
  }
  return res;
}

export const api = {
  async fetchHealth(): Promise<HealthStatus> {
    const res = await fetch('/health');
    if (!res.ok) throw new Error(`Health check failed (${res.status})`);
    return res.json();
  },

  async fetchIncidents(): Promise<Incident[]> {
    const res = await fetch('/api/incidents?limit=100');
    if (!res.ok) throw new Error(`Incidents API failed (${res.status})`);
    const data = await res.json();
    return data.incidents || [];
  },

  async fetchEstateOverview(): Promise<EstateOverview> {
    const res = await fetch('/api/estate/overview');
    if (!res.ok) throw new Error(`Estate overview failed (${res.status})`);
    return res.json();
  },

  async fetchResources(): Promise<ResourceItem[]> {
    const res = await fetch('/api/resources');
    if (!res.ok) throw new Error(`Resource inventory failed (${res.status})`);
    const data = await res.json();
    return data.resources || [];
  },

  async fetchCostSummary(): Promise<CostSummary> {
    const res = await fetch('/api/finops/costs');
    if (!res.ok) {
      if (res.status === 429) {
        throw new Error('Rate limit reached (HTTP 429). Azure Cost Management throttled queries.');
      }
      if (res.status === 503) {
        throw new Error('Service unavailable (HTTP 503). CostManagementClient unconfigured.');
      }
      throw new Error(`Cost Management API failed (HTTP ${res.status})`);
    }
    return res.json();
  },

  async fetchResourceDetail(resourceId: string): Promise<ResourceDetail> {
    const path = resourceId.startsWith('/') ? resourceId : `/${resourceId}`;
    const res = await fetch(`/api/resources${path}`);
    if (!res.ok) throw new Error(`Failed to retrieve resource detail (${res.status})`);
    return res.json();
  },

  async fetchIncidentFindings(incidentId: string): Promise<FindingDetail[]> {
    const res = await fetch(`/api/incidents/${incidentId}/findings`);
    if (!res.ok) throw new Error(`Findings query failed (${res.status})`);
    const data = await res.json();
    return data.findings || [];
  },

  async triggerAITriage(incidentId: string, forceRefresh: boolean = true): Promise<Incident> {
    const res = await fetch(`/api/incidents/${incidentId}/ai-triage`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({ force_refresh: forceRefresh }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || err.error || `AI Triage failed (${res.status})`);
    }
    const data = await res.json();
    return data.incident;
  },

  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<Incident> {
    const res = await fetch(`/api/incidents/${incidentId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || err.message || `Status update failed (${res.status})`);
    }
    return res.json();
  },

  async submitActionApproval(
    incidentId: string,
    actionId: string,
    status: 'APPROVED' | 'REJECTED',
    notes: string,
    operator: string = 'secops-operator'
  ): Promise<Incident> {
    const res = await fetch(`/api/incidents/${incidentId}/actions/${actionId}/approval`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({
        status,
        notes,
        operator,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || err.error || `Action approval failed (${res.status})`);
    }
    const data = await res.json();
    return data.incident;
  },

  async executeRemediation(incidentId: string, actionId: string): Promise<Incident> {
    const res = await fetch(`/api/incidents/${incidentId}/remediation/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({ action_id: actionId }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || data.message || `Remediation execution failed (${res.status})`);
    }
    return data.incident;
  },

  async seedDemoScenario(): Promise<{ correlated: boolean; triaged: boolean }> {
    // Cost anomalies are only evaluated for closed billing days (yesterday or earlier),
    // and the correlator rejects a cost date that precedes the security event. Place the
    // egress event on the same closed day so the pair correlates.
    const evalDate = new Date(Date.now() - 86400000).toISOString().substring(0, 10);
    const soaTime = new Date(`${evalDate}T20:00:00Z`);
    const victimResId = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01";
    
    // 1. Resource Creation
    await postSeed('/detect/resource-creation', {
        events: [{
          TimeGenerated: new Date(Date.now() - 3600000 * 4).toISOString(),
          EventDataId: "evt-rc-demo-01",
          CorrelationId: "corr-demo-01",
          OperationNameValue: "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
          ActivityStatusValue: "Success",
          ActivitySubstatusValue: "Created",
          _ResourceId: victimResId,
          ResourceGroup: "cloudpulse-rg",
          SubscriptionId: "90b900ea-4273-4b40-a343-091aecfe2911",
          Caller: "admin@cloudpulse.io",
          CallerIpAddress: "198.51.100.10",
          Properties_d: JSON.stringify({ statusCode: "Created", activitySubstatusValue: "Created" })
        }]
    });

    // 2. Unexpected Public Exposure
    await postSeed('/detect/unexpected-public-exposure', {
        events: [{
          TimeGenerated: new Date(Date.now() - 3600000 * 3).toISOString(),
          EventDataId: "evt-upe-demo-01",
          OperationNameValue: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
          ActivityStatusValue: "Success",
          _ResourceId: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker",
          ResourceGroup: "cloudpulse-rg",
          SubscriptionId: "90b900ea-4273-4b40-a343-091aecfe2911",
          Caller: "admin@cloudpulse.io",
          Properties_d: JSON.stringify({
            securityRule: {
              access: "Allow",
              direction: "Inbound",
              protocol: "Tcp",
              destinationPortRange: "22",
              sourceAddressPrefix: "*",
              targetResourceId: victimResId
            }
          })
        }],
        topology: {
          public_ips: {
            "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourcegroups/cloudpulse-rg/providers/microsoft.network/publicipaddresses/pip-worker-01": {
              id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/publicIPAddresses/pip-worker-01",
              name: "pip-worker-01",
              ip_address: "20.198.51.10",
              ip_configuration_id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkInterfaces/nic-worker-01/ipConfigurations/ipconfig1",
              resource_group: "cloudpulse-rg",
              subscription_id: "90b900ea-4273-4b40-a343-091aecfe2911"
            }
          },
          nics: {
            "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourcegroups/cloudpulse-rg/providers/microsoft.network/networkinterfaces/nic-worker-01": {
              id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkInterfaces/nic-worker-01",
              name: "nic-worker-01",
              vm_id: victimResId,
              nsg_id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker",
              ip_configurations: [{
                id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkInterfaces/nic-worker-01/ipConfigurations/ipconfig1",
                name: "ipconfig1",
                public_ip_id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/publicIPAddresses/pip-worker-01",
                subnet_id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/virtualNetworks/vnet-cloudpulse/subnets/snet-worker"
              }],
              resource_group: "cloudpulse-rg",
              subscription_id: "90b900ea-4273-4b40-a343-091aecfe2911"
            }
          },
          nsgs: {
            "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourcegroups/cloudpulse-rg/providers/microsoft.network/networksecuritygroups/nsg-worker": {
              id: "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker",
              name: "nsg-worker",
              resource_group: "cloudpulse-rg",
              subscription_id: "90b900ea-4273-4b40-a343-091aecfe2911",
              rules: [{
                name: "Allow-SSH-Internet",
                properties: {
                  access: "Allow",
                  direction: "Inbound",
                  protocol: "Tcp",
                  destinationPortRange: "22",
                  sourceAddressPrefix: "0.0.0.0/0",
                  priority: 100
                }
              }]
            }
          },
          vms: {
            [victimResId.toLowerCase()]: {
              id: victimResId,
              name: "vm-worker-01",
              resourceGroup: "cloudpulse-rg",
              networkInterfaces: ["/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkInterfaces/nic-worker-01"]
            }
          }
        }
    });

    // 3. Suspicious Outbound Egress
    await postSeed('/detect/suspicious-outbound', {
        events: [{
          timestamp: soaTime.toISOString(),
          resource_id: victimResId,
          destination_ip: "198.51.100.77",
          destination_port: 443,
          bytes_sent: 16500000000,
          bytes_received: 24000,
          flow_direction: "O",
          flow_status: "A"
        }],
        baselines: {
          [victimResId]: {
            mean_hourly_bytes: 50000000,
            std_hourly_bytes: 10000000,
            historical_hours: 24,
            flow_count: 100,
            known_destination_ips: ["168.63.129.16"]
          }
        }
    });

    // 4. Cost Anomaly
    await postSeed('/detect/cost-anomaly', {
        evaluation_date: evalDate,
        observations: [{
          resource_id: victimResId,
          resource_name: "vm-worker-01",
          resource_group: "cloudpulse-rg",
          cost_category: "Network/Egress",
          evaluation_date: evalDate,
          current_cost: 195.40,
          baseline_cost: 14.20,
          deviation_absolute: 181.20,
          deviation_ratio: 13.76,
          percentage_increase: 1276.0,
          std_dev: 2.1,
          sample_days: 14,
          confidence: 0.90,
          currency: "USD"
        }]
    });

    // 5. Trigger AI Triage on the incident formed for the seeded workload
    const activeRes = await fetch('/api/incidents?limit=100');
    const activeData = await activeRes.json();
    const seeded: Incident | undefined = (activeData.incidents || []).find(
      (i: Incident) => (i.resource?.id || '').toLowerCase() === victimResId.toLowerCase()
    );
    if (!seeded) return { correlated: false, triaged: false };
    await postSeed(`/api/incidents/${seeded.incident_id}/ai-triage`, { force_refresh: true });
    return { correlated: Boolean(seeded.cost_impact), triaged: true };
  },

  // --- Authentication & OTP API ---
  async requestOtp(email: string): Promise<{
    success: boolean;
    message?: string;
    expires_in_seconds?: number;
    cooldown_seconds?: number;
    dev_mode?: boolean;
    dev_otp?: string;
    delivery_note?: string;
    error?: string;
  }> {
    const res = await fetch('/api/auth/otp/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    return res.json();
  },

  async verifyOtp(email: string, otp: string): Promise<{
    success: boolean;
    token?: string;
    user?: OperatorProfile;
    error?: string;
  }> {
    const res = await fetch('/api/auth/otp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp }),
    });
    return res.json();
  },

  async operatorLogin(email: string): Promise<{
    success: boolean;
    token?: string;
    user?: OperatorProfile;
    error?: string;
    message?: string;
  }> {
    const res = await fetch('/api/auth/operator-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    return res.json();
  },

  async fetchSession(token: string): Promise<{
    authenticated: boolean;
    user: OperatorProfile | null;
  }> {
    const res = await fetch('/api/auth/session', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return { authenticated: false, user: null };
    return res.json();
  },

  async logout(token?: string): Promise<void> {
    if (!token) return;
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => {});
  },

  async configureResendKey(key: string): Promise<{ success: boolean; message?: string; error?: string }> {
    const res = await fetch('/api/auth/configure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ resend_api_key: key }),
    });
    return res.json();
  },

  async fetchAuthStatus(): Promise<{ has_resend_key: boolean; dev_auth_enabled: boolean }> {
    const res = await fetch('/api/auth/status');
    if (!res.ok) return { has_resend_key: false, dev_auth_enabled: false };
    return res.json();
  }
};
