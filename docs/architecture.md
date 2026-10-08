# CloudPulse System Architecture

CloudPulse is an autonomous Azure FinOps and Threat Surface Triage Engine. It correlates security posture telemetry with infrastructure expenditure anomalies, performs advisory AI triage, and provides controlled, human-authorized remediation with live Azure verification.

---

## 1. High-Level Architectural Planes

CloudPulse strictly isolates execution into four decoupled architectural planes:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CLOUDPULSE PLANES                                     │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. DATA & TELEMETRY PLANE                                                               │
│    Azure Monitor Logs · Azure Resource Graph · Azure Cost Management · Network Flows    │
│                                           │                                             │
│                                           ▼                                             │
│ 2. CONTROL & CORRELATION PLANE                                                          │
│    Deterministic Detectors · 5D Concurrence Matrix · PostgreSQL · Orchestrator          │
│                                           │                                             │
│                                           ▼                                             │
│ 3. AI ADVISORY PLANE                                                                    │
│    AISafeIncidentContext · Azure OpenAI / GPT-4o · Advisory Recommendations             │
│                                           │                                             │
│                                           ▼                                             │
│ 4. REMEDIATION & VERIFICATION PLANE                                                     │
│    Human Approval Gate · Precondition Check · ETag Optimistic Concurrency · Verification│
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Plane Definitions & Invariants
1. **Data & Telemetry Plane**: Gathers deterministic signals from Azure control plane APIs without executing mutations.
2. **Control & Correlation Plane**: Evaluates immutable findings, correlates cross-domain anomalies, and manages incident state machines.
3. **AI Advisory Plane**: Produces human-readable narratives, risk assessments, and recommended actions. **AI is strictly read-only and advisory; it never possesses execution privileges.**
4. **Remediation & Verification Plane**: Evaluates preconditions, captures rollback state, mutates Azure resources using typed SDK handlers with ETag concurrency constraints, and verifies effective state.

---

## 2. Infrastructure Architecture & Network Segmentation

All CloudPulse cloud resources reside under resource group `cloudpulse-rg` in region `centralindia`:

```
Virtual Network: cloudpulse-vnet (10.50.0.0/16)
├── Subnet: snet-edge (10.50.1.0/24)
│   └── NSG: sg-edge (Permits port 443 HTTPS inbound from perimeter)
├── Subnet: snet-app (10.50.2.0/24)
│   └── NSG: nsg-app (Application tier)
├── Subnet: snet-worker (10.50.3.0/24)
│   └── NSG: nsg-worker (Worker compute & batch processing tier)
├── Subnet: snet-data (10.50.4.0/24)
│   └── NSG: nsg-data (PostgreSQL Flexible Server private subnet)
└── Subnet: snet-container-apps (10.50.5.0/24)
    └── Dedicated Azure Container Apps environment infrastructure
```

### Supporting Platform Services
* **PostgreSQL Flexible Server**: Dedicated database instance with private networking; stores findings, incidents, audit timelines, and remediation states.
* **Azure Key Vault**: Stores credentials and sensitive configuration.
* **Azure Container Registry (ACR)**: Private container registry hosting detection worker images.
* **Log Analytics Workspace (`cloudpulse-law`)**: Centralized repository for activity logs, diagnostic logs, and network analytics.

---

## 3. Identity & RBAC Boundaries

CloudPulse adheres strictly to the principle of least privilege:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       IDENTITY & ACCESS SEPARATION                          │
├──────────────────────────┬──────────────────────────────────────────────────┤
│ Managed Identity         │ cloudpulse-identity (id-cloudpulse-dev)          │
│ Principal Type           │ User-Assigned Managed Identity                   │
│ Read Scope               │ /subscriptions/.../resourceGroups/cloudpulse-rg  │
│ Telemetry Roles          │ Reader, Cost Management Reader                   │
│ Remediation Role         │ CloudPulse-Remediation-Operator (Custom Role)    │
│ Prohibited Roles         │ Owner, Contributor, User Access Administrator    │
└──────────────────────────┴──────────────────────────────────────────────────┘
```

### Remediation Custom Role Definition
The `CloudPulse-Remediation-Operator` role allows only granular security rule management scoped strictly to `cloudpulse-rg`:
* `Microsoft.Network/networkSecurityGroups/read`
* `Microsoft.Network/networkSecurityGroups/securityRules/read`
* `Microsoft.Network/networkSecurityGroups/securityRules/write`
* `Microsoft.Network/networkSecurityGroups/securityRules/delete`

---

## 4. Detection Pipeline

CloudPulse implements four deterministic detection engines:

| Detector | Telemetry Source | Contract / Logic | Severity |
|---|---|---|---|
| `RESOURCE_CREATION` | Log Analytics (`AzureActivity`) | Monitors creation of unmanaged or high-cost compute/database instances | `LOW` – `HIGH` |
| `UNEXPECTED_PUBLIC_EXPOSURE` | Azure Resource Graph (ARG) | Analyzes effective Public IP → NIC → Subnet → NSG paths for unrestricted Internet ingress (`0.0.0.0/0`) | `HIGH` – `CRITICAL` |
| `SUSPICIOUS_OUTBOUND_ACTIVITY` | Network Flow Telemetry | Detects volumetric spikes, C2 beaconing, port scanning, and anomalous outbound traffic | `MEDIUM` – `CRITICAL` |
| `COST_ANOMALY` | Azure Cost Management API | Statistical evaluation ($z$-score $\ge 2.0$, deviation $> 20\%$) against 14-day rolling baselines | `LOW` – `CRITICAL` |

### Deterministic Finding Schema
Every finding is uniquely identified using deterministic cryptographic hashing:
$$\text{finding\_id} = \text{"F-UPE-"} + \text{SHA256}(\text{resource\_id} + \text{nsg\_rule\_id} + \text{protocol} + \text{destination\_port})[:12].\text{upper()}$$
Findings are immutable records containing full provenance evidence.

---

## 5. Security ↔ FinOps Correlation Engine

The correlation engine identifies multi-stage threat patterns where security compromises lead to cloud financial overruns:

```
[Threat Exposure]                 [Threat Execution]                [Financial Impact]
UNEXPECTED_PUBLIC_EXPOSURE   ──►  SUSPICIOUS_OUTBOUND_ACTIVITY  ──►  COST_ANOMALY
(Port 22/3389 exposed)            (Data exfiltration / scanning)     (Bandwidth overrun)
            │                                │                              │
            └────────────────────────────────┼──────────────────────────────┘
                                             ▼
                               [Correlated Incident]
                               (INC-RC-XXXXXXXXXX)
```

### 5-Dimension Concurrence Matrix
Correlation evaluates:
1. **Resource Alignment**: Identical resource ID or co-located in the same subnet/resource group.
2. **Temporal Proximity**: Events occur within overlapping or contiguous observation windows.
3. **Traffic Concurrence**: Network traffic volume correlates with recorded egress bandwidth costs.
4. **Severity Escalation**: Composite incident severity reflects highest contributing threat vector.
5. **Non-Causal Factuality**: Evidence notes correlation without inventing unproven causal assertions.

---

## 6. AI Incident Triage Engine

CloudPulse integrates Azure OpenAI (GPT-4o) as an advisory layer:

* **Context Isolation**: The `AISafeIncidentContext` extracts only sanitized, factual finding evidence and timeline events. No credentials, tokens, or unrelated infrastructure metadata enter the prompt.
* **Strict JSON Schema**: AI responses are validated against the `AITriageAnalysis` Pydantic model.
* **Structured Output**:
  * `summary`: Executive overview.
  * `risk_assessment`: Threat severity analysis.
  * `security_impact` & `financial_impact`: Distinct impact evaluations.
  * `facts`: Verified evidence items.
  * `inferences`: Identified patterns with explicit caveats.
  * `recommended_actions`: Concrete proposed steps (`requires_human_approval: true`).
  * `limitations`: Explicit acknowledgment of unobserved data.

---

## 7. Controlled Remediation Subsystem

Remediation is governed by strict deterministic state machines:

```
[PROPOSED] ──► [APPROVED] ──► [PRECONDITION_CHECKING] ──► [EXECUTING] ──► [EXECUTED] ──► [VERIFYING] ──► [VERIFIED]
     │              │                     │                                                      │
     ▼              ▼                     ▼                                                      ▼
 [REJECTED]     (Azure Unmutated)   [PRECONDITION_FAILED]                                  [VERIFICATION_FAILED]
```

### Remediation Safety Invariants
1. **Explicit Human Approval**: Remediation never executes autonomously. Every action requires prior operator sign-off.
2. **Finding-Derived Targets**: Resource IDs, NSG names, and rule names are extracted strictly from PostgreSQL finding evidence, never from AI text or user request bodies.
3. **Optimistic Concurrency Control**: All ARM mutations use the Azure SDK `If-Match` header and ETag validation to prevent overwriting concurrent administrator changes.
4. **Snapshot Rollback Preservation**: Pre-mutation rule configuration is serialized into `rollback_state` before issuing mutations.
5. **Post-Mutation Read-Back Verification**: Effective compliance is verified by an independent read query to Azure ARM before transitioning the incident to `RESOLVED`.

---

## 8. Dashboard & Presentation Layer

* **Vanilla Web Architecture**: High-performance dashboard built with semantic HTML5, Vanilla JavaScript, and custom CSS design tokens (no heavy external frontend frameworks).
* **Real-Time SecOps / FinOps View**:
  * Unified metrics: incident counts, severity breakdown, financial overrun totals, and triage status.
  * Interactive incident details with timeline event tracking.
  * One-click operator authorization and controlled remediation execution with live status indicators.
