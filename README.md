# CloudPulse

> **Autonomous Azure FinOps & Threat Surface Triage Engine with Closed-Loop Controlled Remediation.**

---

## 1. Problem: The Disconnect Between Cloud Security and FinOps

In modern cloud environments, security incident management and financial operations (FinOps) operate in isolated silos:
* **SecOps teams** investigate anomalous egress, compromised credentials, and exposed ports without real-time visibility into the financial consequences.
* **FinOps teams** identify anomalous cost spikes and budget overruns days or weeks after an incident occurs, lacking threat intelligence to understand the root cause.
* **Threat actors exploit this gap**: Compromised infrastructure is rapidly leveraged for crypto-mining, proxy networks, and large-scale data exfiltration, creating simultaneous perimeter security breaches and severe financial damage.

---

## 2. Core Idea

CloudPulse bridges this divide through a deterministic, closed-loop pipeline:

$$\textbf{Deterministic Detection} + \textbf{Cross-Domain Correlation} + \textbf{Advisory AI Triage} + \textbf{Human-Approved Controlled Remediation}$$

1. **Deterministic Detection**: Continuous ingestion of telemetry across activity logs, resource graphs, network flows, and cost baselines without probabilistic heuristics.
2. **Security ↔ FinOps Correlation**: High-fidelity correlation linking infrastructure exposure and anomalous network activity directly to cost overruns.
3. **Advisory AI Triage**: Azure OpenAI (GPT-4o) synthesizes executive summaries, risk assessments, and recommended operator actions without possessing execution authority.
4. **Controlled Remediation**: Deterministic, human-authorized Azure SDK mutations protected by optimistic concurrency (ETags), comprehensive preconditions, post-mutation verification, and full rollback capabilities.

---

## 3. Architecture

```
                                  AZURE RESOURCES
         (Virtual Machines · Virtual Networks · Network Security Groups)
                                         │
                                         ▼
                                TELEMETRY INGESTION
          (Azure Monitor Activity Logs · Azure Resource Graph · Azure Cost Management)
                                         │
                                         ▼
                               LOG ANALYTICS WORKSPACE
                                         │
                                         ▼
                              CLOUDPULSE DETECTION ENGINE
             ┌───────────────────────────┴───────────────────────────┐
             ▼                                                       ▼
      SECURITY DETECTORS                                      FINOPS DETECTOR
  • RESOURCE_CREATION                                         • COST_ANOMALY
  • UNEXPECTED_PUBLIC_EXPOSURE
  • SUSPICIOUS_OUTBOUND_ACTIVITY
             │                                                       │
             └───────────────────────────┬───────────────────────────┘
                                         ▼
                        SECURITY ↔ FINOPS CORRELATION ENGINE
                           (5-Dimension Concurrence Matrix)
                                         │
                                         ▼
                             INCIDENT STORAGE (PostgreSQL)
                                         │
                                         ▼
                              AZURE AI ADVISORY TRIAGE
                       (Strictly Read-Only · Operator Guidance)
                                         │
                                         ▼
                               HUMAN APPROVAL GATE
                           (Operator Authorization Required)
                                         │
                                         ▼
                            CONTROLLED REMEDIATION ENGINE
                 (Finding-Derived Targets · ETag Optimistic Concurrency)
                                         │
                                         ▼
                             LIVE AZURE ARM VERIFICATION
                                (Read-Back Validation)
                                         │
                                         ▼
                               OPERATOR DASHBOARD UI
```

---

## 4. Detection Capabilities

CloudPulse implements four deterministic detection engines:

1. **`RESOURCE_CREATION`**:
   * Evaluates `AzureActivity` administrative logs in Log Analytics.
   * Identifies unauthorized workload deployments and unmanaged compute resources.
2. **`UNEXPECTED_PUBLIC_EXPOSURE`**:
   * Analyzes live Azure Resource Graph (ARG) topology graphs spanning Public IPs, NICs, Subnets, and NSGs.
   * Detects permissive inbound rules (`0.0.0.0/0`, `*`, `Internet`) exposing management ports (SSH: 22, RDP: 3389) or database ports (1433, 3306, 5432).
3. **`SUSPICIOUS_OUTBOUND_ACTIVITY`**:
   * Ingests network flow telemetry.
   * Flags volumetric egress spikes, known command-and-control (C2) communication patterns, and scanning behavior.
4. **`COST_ANOMALY`**:
   * Queries Azure Cost Management API and maintains 14-day rolling statistical baselines.
   * Emits findings when daily expenditure exhibits statistically significant deviations ($z$-score $\ge 2.0$, deviation $> 20\%$).

---

## 5. Security ↔ FinOps Correlation

Security ↔ FinOps correlation is CloudPulse's key architectural differentiator:

```
[Unexpected Resource Creation]
             ↓
[Unrestricted Public Exposure]  (Port 22/3389 exposed to Internet)
             ↓
[Suspicious Outbound Activity]  (Egress spike / anomalous destination IPs)
             ↓
[FinOps Cost Anomaly]           (Bandwidth and compute cost overrun)
             ↓
[Correlated Incident Record]    (Unified SecOps/FinOps Incident)
```

* **Deterministic, Non-Causal Coupling**: The correlation engine links observations across resource identities, temporal windows, and metric deviations.
* **Audit Transparency**: Incidents report correlated evidence without fabricating unsupported claims of causality.

---

## 6. Advisory AI Incident Triage

CloudPulse uses Azure OpenAI (GPT-4o) exclusively in an advisory, read-only capacity:

* **Strict Sandboxing**: Prompts are populated solely via `AISafeIncidentContext`, excluding credentials, secrets, or internal connection strings.
* **Guaranteed Schema**: Responses conform strictly to the `AITriageAnalysis` model:
  * Executive Summary & Risk Assessment
  * Independent Security and Financial Impact Statements
  * Verified Facts vs. Inferences
  * Structured Recommended Actions (`requires_human_approval: true`)
  * Analysis Limitations & Confidence Score
* **Zero Execution Authority**: The AI model possesses no Azure credentials, cannot execute shell commands, and cannot initiate infrastructure mutations.

---

## 7. Controlled Remediation Subsystem

CloudPulse implements controlled, reversible infrastructure remediation:

### Supported Actions
* **`DISABLE_PUBLIC_INGRESS`**:
  * Mutates permissive inbound NSG rules from `Allow` to `Deny` while preserving rule names, priorities, and internal traffic routes.
* **`ISOLATE_WORKLOAD`**:
  * Injects a deterministic, high-priority outbound deny rule blocking Internet egress while preserving intra-VNet database and management connectivity.

### Non-Negotiable Safety Invariants
1. **Human Approval Gate**: Remediation requires prior operator authorization (`APPROVED`). Approval alone causes zero mutations.
2. **Finding-Derived Targets**: Remediation targets (NSG ID, rule name, port, protocol) are resolved strictly from verified finding evidence in PostgreSQL, never from user inputs or AI text.
3. **ETag / If-Match Concurrency**: Mutations enforce optimistic concurrency control via HTTP `If-Match` headers. If an administrator alters the rule concurrently, ARM rejects the mutation with HTTP 409/412.
4. **Precondition Checks**: Live rule properties are re-evaluated prior to mutation. If state has drifted, execution aborts safely with `PRECONDITION_FAILED`.
5. **Rollback Snapshot**: Complete pre-mutation rule configuration is captured before execution.
6. **Live ARM Verification**: Effective compliance is confirmed via an independent read-back query to Azure ARM before transitioning the incident to `RESOLVED`.

---

## 8. Proven Live E2E Validation

CloudPulse has been proven end-to-end against live Azure infrastructure under subscription `90b900ea-4273-4b40-a343-091aecfe2911`:

* **Finding ID**: `F-UPE-2D981ABC2B12` (Critical public SSH exposure on `cloudpulse-e2e-vm`)
* **Incident ID**: `INC-RC-95E60E379A`
* **AI Action ID**: `ACT-01` (`title`: "Narrow Source IP Ranges", advisory only)
* **Remediation ID**: `REM-5EC0397F5981` (`action_type`: `DISABLE_PUBLIC_INGRESS`)
* **Live Mutation Flow**:
  1. Initial Rule State: `Allow / Inbound / TCP / 22 / 0.0.0.0/0` (ETag: `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`)
  2. Human Approval recorded: Zero Azure mutations occurred.
  3. Preconditions verified; ETag captured.
  4. ARM Mutation executed using `If-Match`: Rule updated to `Deny / Inbound / TCP / 22 / 0.0.0.0/0` (New ETag: `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`).
  5. Live ARM read-back verified `access=Deny`. Incident status reached `RESOLVED`.
  6. Controlled Rollback restored original `Allow` state with ETag protection (Restored ETag: `W/"15051b17-d981-4e04-9b90-96955c9cafb9"`).
  7. All temporary test resources were completely deleted. Production infrastructure remained untouched.

*Detailed walkthrough available in [docs/demo/live-e2e.md](docs/demo/live-e2e.md).*

---

## 9. Technology Stack

* **Compute & Worker**: Python 3.14, Flask, Gunicorn
* **Persistence**: Azure Database for PostgreSQL Flexible Server (JSONB-backed repositories)
* **Cloud Telemetry**: Azure Monitor Logs (Log Analytics), Azure Resource Graph, Azure Cost Management API
* **Cloud Identity & SDK**: Azure SDK for Python (`azure-mgmt-network`, `azure-identity`, `azure-mgmt-resourcegraph`), DefaultAzureCredential
* **Artificial Intelligence**: Azure OpenAI Service (GPT-4o), Pydantic v2
* **Infrastructure as Code**: Terraform (`azurerm` provider v3)
* **Frontend Dashboard**: HTML5, Vanilla JavaScript, Custom CSS Design System

---

## 10. Security & RBAC Model

* **Least-Privilege Managed Identity**: `cloudpulse-identity` (`id-cloudpulse-dev`).
* **Telemetry Roles**: `Reader` on `cloudpulse-rg`, `Cost Management Reader` on subscription.
* **Remediation Role**: Custom role `CloudPulse-Remediation-Operator` scoped strictly to `cloudpulse-rg`:
  * `Microsoft.Network/networkSecurityGroups/read`
  * `Microsoft.Network/networkSecurityGroups/securityRules/read`
  * `Microsoft.Network/networkSecurityGroups/securityRules/write`
  * `Microsoft.Network/networkSecurityGroups/securityRules/delete`
* **Prohibited Roles**: `Owner`, `Contributor`, `User Access Administrator` are strictly forbidden.

---

## 11. Verification & Test Suite

The test suite covers detection algorithms, correlation logic, API contracts, concurrency control, and remediation state machines:

```bash
PYTHONPATH=services/detection-worker pytest services/detection-worker/tests -v
```

* **Test Results**: **250 passed in 4.8s (100% passing)**
* **Terraform State**: Clean (`terraform/` untouched)
* **Git Status**: Clean working tree
