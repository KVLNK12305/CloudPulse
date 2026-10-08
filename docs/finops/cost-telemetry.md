# CloudPulse FinOps Telemetry Specification — Cost Management & Baseline Contract

## 1. Specification ID & Overview

* **Document ID**: `FINOPS_COST_TELEMETRY_CONTRACT`
* **Target Consumer**: Siddu (Implementation Engineer) & Future `COST_ANOMALY` Detector
* **Target Service**: `services/detection-worker`
* **Status**: Ready for Implementation (Specification Only — No Code/Schema Changes)

### Executive Summary
CloudPulse operates as an Azure-based Autonomous FinOps & Threat Surface Triage Engine. While security detection capabilities (`RESOURCE_CREATION`, `UNEXPECTED_PUBLIC_EXPOSURE`, `SUSPICIOUS_OUTBOUND_ACTIVITY`) identify threat activity across the control and data planes, FinOps telemetry provides the authoritative quantitative basis for financial visibility, baseline modeling, and cost-impact correlation.

This document establishes the formal contract for ingesting, normalizing, deduplicating, and baselining cloud cost telemetry from Microsoft Azure. It defines the exact boundaries, data models, error handling, and interfaces required before the future `COST_ANOMALY` detector can be implemented.

---

## 2. Responsibility Boundaries

To maintain high architectural cohesion and prevent logic bleeding across CloudPulse subsystems, strict boundaries are enforced across all layers:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             CLOUDPULSE ARCHITECTURE                             │
├─────────────────────────┬────────────────────────────────────────────────────────┤
│ Subsystem / Component   │ Explicit Responsibility                                │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Cost Telemetry          │ Retrieves, normalizes, deduplicates, and caches Azure  │
│ (This Specification)    │ Cost Management billing records. Authoritative source  │
│                         │ of actual billed cost.                                 │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Cost Baseline           │ Calculates deterministic expected cost metrics (mean,  │
│ (This Specification)    │ standard deviation, delta, ratio) over historical time  │
│                         │ windows.                                               │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ COST_ANOMALY Detector   │ Evaluates normalized observations against baselines to │
│ (Future Milestone)      │ detect anomalous spikes, threshold breaches, and       │
│                         │ unexpected cost surges. Produces Finding records.      │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Security Detectors      │ Detect security behaviors across control and data      │
│ (RC, UPE, SOA)          │ planes (e.g. public ingress, mining ports, C2 beacons).│
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Security ↔ FinOps       │ Connects security findings with cost evidence on the   │
│ Correlation Orchestrator│ same resource (e.g. data exfiltration → egress spike). │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Azure AI Triage         │ Synthesizes incident timelines, analyzes root causes,  │
│ (Future Milestone)      │ and produces natural-language explanations.            │
├─────────────────────────┼────────────────────────────────────────────────────────┤
│ Remediation Engine      │ Executes human-approved containment and optimization   │
│ (Future Milestone)      │ actions (e.g. deallocating rogue VMs, throttling).    │
└─────────────────────────┴────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Boundary Rule**: The Cost Telemetry layer must **never** determine whether an activity is malicious, nor decide whether a cost increase is an anomaly. It provides verifiable cost facts and statistical baseline context only.

---

## 3. Cost Telemetry Source: Azure Cost Management

### A. Authoritative Source vs. Derived Metrics
CloudPulse enforces a strict separation between actual billed cost and estimated runtime metrics:

* **Real Cost Data (Authoritative)**: Azure Cost Management is the **sole source of truth** for actual financial expenditure. All currency figures consumed by CloudPulse must originate from Azure Cost Management API responses.
* **Derived / Operational Metrics (Evidence Only)**: Metrics such as network flow byte counts (`bytes_sent` from `AzureNetworkAnalytics_CL`), VM execution hours, or storage disk operations provide operational correlation evidence, but must **never** be multiplied by static rates to invent synthetic billing totals.

### B. Selected Azure API: Cost Management Query API
CloudPulse adopts the **Azure Cost Management Query API**:

* **Resource Provider**: `Microsoft.CostManagement`
* **Operation**: `POST`
* **Canonical URI**:
  ```http
  POST https://management.azure.com/{scope}/providers/Microsoft.CostManagement/query?api-version=2023-11-01
  ```
* **Supported Scopes**:
  * **Primary (Subscription Scope)**: `/subscriptions/{subscriptionId}`
  * **Delegated (Resource Group Scope)**: `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}`

#### Why Query API (vs. Cost Details / Exports API)?
| Evaluation Criteria | Cost Management Query API | Cost Details / Exports API | CloudPulse Decision |
|---|---|---|---|
| **Interaction Model** | Synchronous REST query (`POST` with JSON payload) | Asynchronous CSV/Parquet export to Storage Blob | **Query API**: Enables synchronous worker polling without managing intermediate storage containers. |
| **Response Format** | Structured JSON with column descriptors and rows | Massive batch CSV or compressed blob files | **Query API**: Directly serializable into internal Pydantic models. |
| **Data Granularity** | Daily aggregation (`Daily`) or Accumulated total | Line-item invoice level (per-meter event) | **Query API**: Daily grain matches baseline and anomaly detection windows. |
| **Execution Latency** | Low (typically 1–3 seconds per query) | High (queued export jobs can take 15–45 minutes) | **Query API**: Fits inside detection-worker execution cycles. |

### C. Authentication & Managed Identity
* **Identity Mechanism**: Azure User-Assigned Managed Identity (`cloudpulse-identity`), defined in `terraform/identity.tf`.
* **Credential Provider**: `DefaultAzureCredential(managed_identity_client_id=config.AZURE_CLIENT_ID)` via `azure-identity`.
* **OAuth2 Token Audience**: `https://management.azure.com/.default`

### D. RBAC & Least-Privilege Role Recommendation
* **Recommended Role**: **`Cost Management Reader`**
  * **Role Definition ID**: `72fafb9e-0641-4937-9268-a42baaa0c913`
  * **Assigned Scope**: `/subscriptions/{subscriptionId}` (or target Resource Group)
* **Required Actions**:
  * `Microsoft.CostManagement/query/action`
  * `Microsoft.CostManagement/views/read`
* **Explicit Anti-Patterns**:
  * **Do NOT assign `Contributor` or `Owner`**: Violates least privilege.
  * **Do NOT assign `Cost Management Contributor`**: Write access to create budgets or export configurations is unnecessary and presents privilege creep.
  * **What the identity must NOT be allowed to do**: Modify Azure billing properties, create export jobs to external storage, purchase reservations, or alter resource configurations.

### E. Latency, Granularity & Billing Constraints
1. **Billing Ingestion Latency (8 to 24 Hours)**:
   * Azure Cost Management data is **not real-time streaming data**.
   * Microsoft updates usage and rating pipelines every 8 to 24 hours (and up to 48 hours for certain third-party Marketplace items or complex reservation amortizations).
   * **Rule**: Cost records for the *current calendar day* ($T$) are inherently incomplete or unavailable. Telemetry lookbacks must evaluate closed historical daily windows ($T-1$ and earlier).
2. **Supported Granularity**:
   * `Daily`: Daily cost buckets aggregated per resource, meter, and category. This is the official granularity for CloudPulse FinOps baselines.
   * `Accumulated`: Sum over the entire query window (used for high-level sanity checks, but not for day-by-day baselines).
   * *Hourly Note*: Hourly cost queries are not reliably supported across general Azure subscriptions in the Query API without specific Enterprise Agreement or Microsoft Customer Agreement constraints. CloudPulse standardizes on **Daily** buckets.
3. **API Rate Limiting & Throttling**:
   * Azure Cost Management enforces a quota of approximately **30 calls per minute per scope**.
   * HTTP status `429 Too Many Requests` indicates quota exhaustion.
   * Responses include standard `Retry-After` headers.
4. **Pagination**:
   * If a query returns more rows than the page limit (default: 5,000 rows), the response contains a `@nextLink` property with a `$skipToken`.
   * The client implementation must recursively follow `@nextLink` until all rows are retrieved.

---

## 4. Normalized Cost Record Model

### A. Separation of Raw vs. Normalized Data
Azure Cost Management returns a tabular array of row values mapped to a column definitions array:

```json
{
  "properties": {
    "columns": [
      {"name": "PreTaxCost", "type": "Number"},
      {"name": "UsageDate", "type": "Number"},
      {"name": "ResourceId", "type": "String"},
      {"name": "ResourceGroup", "type": "String"},
      {"name": "ServiceName", "type": "String"},
      {"name": "MeterCategory", "type": "String"},
      {"name": "MeterSubCategory", "type": "String"},
      {"name": "MeterName", "type": "String"},
      {"name": "UsageQuantity", "type": "Number"},
      {"name": "UnitOfMeasure", "type": "String"},
      {"name": "Currency", "type": "String"}
    ],
    "rows": [
      [14.285, 20261007, "/subscriptions/.../virtualMachines/vm-worker-01", "cloudpulse-rg", "Virtual Machines", "Virtual Machines", "Virtual Machines BS Series", "B2s", 24.0, "10 Hours", "USD"]
    ]
  }
}
```

CloudPulse isolates this raw wire format and converts it into a typed, validated internal domain model: `CostRecord`.

### B. Normalized CostRecord Contract
The contract specifies the exact fields required for storage, baseline computation, and correlation:

```python
# Specification for Siddu: models/cost_record.py

class CostRecord(BaseModel):
    record_id: str = Field(..., description="Deterministic unique identifier: CR-{SHA256}")
    timestamp: str = Field(..., description="UTC date of the billing bucket: YYYY-MM-DD")
    subscription_id: str = Field(..., description="Azure Subscription GUID")
    resource_id: str = Field(..., description="Canonical Azure Resource ID (lowercase)")
    resource_group: str = Field(..., description="Azure Resource Group name")
    resource_name: str = Field(..., description="Extracted resource name")
    resource_type: str = Field(..., description="Azure Resource Provider namespace, e.g. Microsoft.Compute/virtualMachines")
    service_name: str = Field(..., description="Azure service name as reported by Cost Management")
    cost_category: str = Field(..., description="Deterministic category: Compute, Storage, Network/Egress, Database, Container, Other")
    meter_category: str = Field(..., description="Azure meter category")
    meter_subcategory: Optional[str] = Field(None, description="Azure meter subcategory")
    meter_name: str = Field(..., description="Azure meter name")
    usage_quantity: float = Field(default=0.0, description="Quantitative usage value reported by meter")
    usage_unit: Optional[str] = Field(None, description="Unit of measurement, e.g. Hours, GB, 10k Operations")
    actual_cost: float = Field(..., description="Authoritative billed cost amount")
    currency: str = Field(default="USD", description="ISO 4217 currency code")
    cost_type: str = Field(default="ActualCost", description="Cost type: ActualCost or AmortizedCost")
    is_provisional: bool = Field(default=False, description="True if record is from recent window and subject to reconciliation")
```

### C. Azure-to-CloudPulse Field Mapping

| Azure Cost Management Column | CloudPulse `CostRecord` Field | Transformation / Parsing Rule |
|---|---|---|
| `UsageDate` | `timestamp` | Convert integer `YYYYMMDD` (e.g. `20261007`) to ISO date `2026-10-07`. |
| `ResourceId` | `resource_id` | Trim and convert to canonical lowercase. If null, map to `"unallocated"`. |
| `ResourceId` | `resource_name` | Parsed from last segment of ARM path: `id.split('/')[-1]`. |
| `ResourceId` | `resource_type` | Extracted from ARM provider segments: `providers/{Namespace}/{Type}`. |
| `ResourceGroup` | `resource_group` | Direct string mapping (or parsed from ARM ID if column missing). |
| `PreTaxCost` / `Cost` | `actual_cost` | Float conversion, rounded to 4 decimal places ($0.0001 precision). |
| `Currency` | `currency` | Uppercase 3-letter currency code (e.g. `USD`). |
| `ServiceName` | `service_name` | Raw string name from Azure billing engine. |
| `MeterCategory` | `meter_category` | Direct string mapping. |
| `MeterSubCategory` | `meter_subcategory` | Direct string mapping (nullable). |
| `MeterName` | `meter_name` | Direct string mapping. |
| `UsageQuantity` | `usage_quantity` | Float conversion (default `0.0`). |
| `UnitOfMeasure` | `usage_unit` | String mapping (e.g. `GB`, `Hours`). |
| Deterministic Hash | `record_id` | `generate_cost_record_id(...)` per Section 10. |

---

## 5. Deterministic Cost Categories

To prevent arbitrary classification heuristics, CloudPulse groups disparate Azure meters into six deterministic cost categories based strictly on `resource_type`, `service_name`, and `meter_category`:

```
                                  Azure Meter Dimensions
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
      Compute Workloads             Data & Storage               Networking / Transit
      - Virtual Machines            - Disks & Snapshots          - Egress / Bandwidth
      - App Services                - Storage Accounts (Blob)    - NAT Gateways
      - Cloud Services              - Files & Data Lake          - Public IPs & VPNs
               │                            │                            │
               ▼                            ▼                            ▼
          [ Compute ]                  [ Storage ]               [ Network/Egress ]
```

### Category Classification Matrix

| Category | Azure Match Rules (Case-Insensitive Priority) | Typical Meters & Workloads |
|---|---|---|
| **`Network/Egress`** | `MeterCategory` contains `"Bandwidth"`, `"Data Transfer"`, `"Virtual Network"`, OR `service_name` in (`"Virtual Network"`, `"Bandwidth"`, `"NAT Gateway"`, `"VPN Gateway"`, `"ExpressRoute"`, `"Public IP Addresses"`) | Internet Egress, Inter-region data transfer, NAT Gateway data processed, Public IP hourly. |
| **`Compute`** | `resource_type` starts with `"Microsoft.Compute/virtualMachines"`, `"Microsoft.Web/serverfarms"`, OR `service_name` in (`"Virtual Machines"`, `"Azure App Service"`, `"Cloud Services"`, `"Batch"`) | VM vCPU/RAM cores, Dedicated App Service Plans, Cloud Service compute instances. |
| **`Database`** | `resource_type` starts with `"Microsoft.Sql"`, `"Microsoft.DBforPostgreSQL"`, `"Microsoft.DBforMySQL"`, `"Microsoft.DocumentDB"` OR `service_name` contains `"Database"`, `"Cosmos"`, `"SQL"` | Azure Database for PostgreSQL Flexible Server, Azure SQL DB, Cosmos DB Request Units (RU/s). |
| **`Container`** | `resource_type` starts with `"Microsoft.ContainerService"`, `"Microsoft.App"`, `"Microsoft.ContainerRegistry"` OR `service_name` in (`"Azure Kubernetes Service"`, `"Container Apps"`, `"Container Registry"`) | AKS node pools, Container App active replicas, ACR storage and vulnerability scans. |
| **`Storage`** | `resource_type` starts with `"Microsoft.Storage"` OR `MeterCategory` contains `"Storage"`, `"Disks"` OR `service_name` in (`"Storage"`, `"Managed Disks"`, `"Storage Accounts"`) | Managed Disks (OS/Data SSD), Blob Storage Hot/Cool/Archive, Storage Transactions. |
| **`Other`** | Any record not matched by the above deterministic rules. | Key Vault operations, Log Analytics ingestion, Microsoft Defender for Cloud, Entra ID licenses. |

> [!NOTE]
> **Zero ML Rule**: Category assignment is 100% deterministic code logic. No machine learning, regex fuzzy guesses, or probabilistic clustering may be used for classification.

---

## 6. Historical Lookback Design

### A. Lookback Window Options Analysis
* **7-Day Lookback**:
  * *Pros*: Rapid execution, minimal payload.
  * *Cons*: Highly vulnerable to regular weekday vs. weekend usage cycles (e.g. business applications running at 30% capacity on Saturday/Sunday).
* **30-Day Lookback**:
  * *Pros*: Broad historical context.
  * *Cons*: Frequently exceeds 5,000-row pagination limits; incorporates obsolete architectural states (e.g. workloads decommissioned 3 weeks ago); slow query execution.
* **14-Day Lookback (Recommended Default for CloudPulse MVP)**:
  * *Pros*: Covers **two complete 7-day cyclical periods**, allowing the baseline to absorb natural weekend dips while keeping query payloads compact. Captures recent rightsizing without dragging months of stale data.

### B. Latency and Date Alignment Rules
Because Azure Cost Management data operates on an 8–24 hour processing lag, lookback calculations must adhere to strict temporal boundaries:

$$\text{Lookback Window} = [T - 14\text{ days},\ T - 1\text{ day}]$$

Where $T$ is the current UTC calendar date.

```
                    Historical Baseline Window (14 Days)                     Excluded
  ◄────────────────────────────────────────────────────────────────────────► ◄───────►
  Day T-14    Day T-13   ...   Day T-3        Day T-2         Day T-1         Day T (Today)
  [Closed]    [Closed]         [Closed]       [Closed]        [Latest Closed] [INCOMPLETE]
                                                              (Evaluation)    (Ignored)
```

1. **Exclude Current Day ($T$)**: The current calendar day is strictly excluded from baseline statistics because its billing data is incomplete. Evaluating Day $T$ against a baseline will trigger severe false anomalies due to partial-day billing.
2. **Evaluation Day ($T-1$)**: The most recent completed calendar day ($T-1$) is the target observation evaluated by the future detector.
3. **Timezone Enforcement**: All billing dates are evaluated strictly in **UTC** (`00:00:00Z` to `23:59:59Z`). Azure Cost Management dates are parsed without local timezone shifts.

---

## 7. Baseline Design for Cost Anomaly Detection

### A. Core Mathematical Formulation
For each unique `(resource_id, cost_category)` tuple, the baseline computes statistical parameters over the active days within the 14-day window:

$$\mu_{\text{daily}} = \frac{1}{N} \sum_{i=1}^{N} \text{cost}_i$$

$$\sigma_{\text{daily}} = \sqrt{\frac{1}{N - 1} \sum_{i=1}^{N} (\text{cost}_i - \mu_{\text{daily}})^2} \quad (\text{for } N \ge 2)$$

Where:
* $N$ is the number of active observation days with finalized billing records ($3 \le N \le 14$).
* $\mu_{\text{daily}}$ is the expected daily cost.
* $\sigma_{\text{daily}}$ is the standard deviation.

### B. Deviation Metrics
When comparing the evaluated day's actual cost ($\text{cost}_{\text{eval}}$) against the baseline:

* **Absolute Deviation**:
  $$\Delta_{\text{cost}} = \text{cost}_{\text{eval}} - \mu_{\text{daily}}$$
* **Deviation Ratio ($R_{\text{cost}}$)**:
  $$R_{\text{cost}} = \begin{cases} \frac{\text{cost}_{\text{eval}}}{\mu_{\text{daily}}}, & \mu_{\text{daily}} > 0 \\ 0.0, & \mu_{\text{daily}} = 0 \end{cases}$$
* **Percentage Change**:
  $$\text{PctChange} = (R_{\text{cost}} - 1.0) \times 100\%$$

### C. Edge Cases & Safeguards
1. **Cold-Start Handling ($N < 3$ days)**:
   * If a resource has fewer than 3 days of historical billing data, flag:
     `is_cold_start = True`.
   * For cold-start resources, baseline metrics cannot establish statistical confidence. The baseline reports $\mu_{\text{daily}} = \text{cost}_{\text{eval}}$, $\sigma_{\text{daily}} = 0.0$, and sets `confidence = 0.30`.
   * **Rule**: Cold-start status suppresses percentage-based alerts to avoid alerting simply because a new resource began running.
2. **Zero-Cost Resources ($\mu_{\text{daily}} = 0.0$)**:
   * If a previously idle or free resource begins incurring charges, $R_{\text{cost}}$ would cause division by zero.
   * **Rule**: The baseline sets $R_{\text{cost}} = 0.0$ and flags `zero_baseline = True`. Downstream detectors evaluate absolute delta ($\Delta_{\text{cost}}$) against fixed dollar thresholds rather than ratios.
3. **Missing Days / Intermittent Workloads**:
   * If a resource has no billing record on a specific day, it incurred zero cost on that day.
   * Days where the resource was provably provisioned but generated $0.00$ are recorded as `0.0`. Days prior to the resource's ARM creation timestamp are omitted from $N$.
4. **Naturally Volatile Workloads**:
   * Measure the Coefficient of Variation ($CV$):
     $$CV = \frac{\sigma_{\text{daily}}}{\mu_{\text{daily}}}$$
   * If $CV > 0.50$, the baseline flags `high_volatility = True`, signaling downstream detectors that wider standard deviation bands must be used.

---

## 8. Future COST_ANOMALY Input Contract

The Cost Telemetry subsystem delivers a structured observation bundle to the future `COST_ANOMALY` detector. It packages the evaluated observation alongside its calculated baseline.

```
┌───────────────────────────────────────────────────────────────────────┐
│                 COST TELEMETRY OUTPUT TO DETECTOR                     │
├───────────────────────────────────────────────────────────────────────┤
│  {                                                                    │
│    "resource_id": "/subscriptions/.../virtualMachines/vm-worker-01",  │
│    "resource_name": "vm-worker-01",                                   │
│    "resource_group": "cloudpulse-rg",                                 │
│    "cost_category": "Network/Egress",                                 │
│    "evaluation_date": "2026-10-07",                                   │
│    "current_cost": 48.50,                                             │
│    "baseline_cost": 4.20,                                             │
│    "deviation_absolute": 44.30,                                       │
│    "deviation_ratio": 11.55,                                          │
│    "percentage_increase": 1054.76,                                    │
│    "std_dev": 0.85,                                                   │
│    "currency": "USD",                                                 │
│    "sample_days": 14,                                                 │
│    "is_cold_start": false,                                            │
│    "high_volatility": false,                                          │
│    "confidence": 0.95,                                                │
│    "records": [...]                                                   │
│  }                                                                    │
└───────────────────────────────────────────────────────────────────────┘
```

### Data Contract Schema

```python
# Specification for Siddu: models/cost_anomaly_input.py

class CostObservation(BaseModel):
    resource_id: str = Field(..., description="Canonical Azure Resource ID")
    resource_name: str = Field(..., description="Workload resource name")
    resource_group: str = Field(..., description="Resource group name")
    cost_category: str = Field(..., description="Compute, Storage, Network/Egress, etc.")
    evaluation_date: str = Field(..., description="Target UTC date: YYYY-MM-DD")
    current_cost: float = Field(..., description="Actual cost on evaluation date")
    baseline_cost: float = Field(..., description="Mean daily baseline cost over window")
    deviation_absolute: float = Field(..., description="current_cost - baseline_cost")
    deviation_ratio: float = Field(..., description="current_cost / baseline_cost (0 if baseline is 0)")
    percentage_increase: float = Field(..., description="Percentage change vs baseline")
    std_dev: float = Field(default=0.0, description="Standard deviation over window")
    currency: str = Field(default="USD", description="Billing currency code")
    sample_days: int = Field(..., description="Number of active baseline days evaluated")
    is_cold_start: bool = Field(default=False, description="True if historical samples < 3 days")
    high_volatility: bool = Field(default=False, description="True if standard deviation exceeds 50% of mean")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Data completeness confidence score")
    records: List[CostRecord] = Field(default_factory=list, description="Underlying meter-level records")
```

---

## 9. Security ↔ FinOps Correlation Hooks

A foundational pillar of CloudPulse is correlating threat surface anomalies with tangible financial repercussions:

```
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│        SECURITY FINDING         │           │        FINOPS TELEMETRY         │
│  Type: SUSPICIOUS_OUTBOUND_ACT  │           │  Category: Network/Egress       │
│  Evidence: bytes_sent = 1.5 TB  │           │  Cost: $135.00 (vs $5 baseline) │
│  Resource: vm-worker-01         │           │  Resource: vm-worker-01         │
└────────────────┬────────────────┘           └────────────────┬────────────────┘
                 │                                             │
                 └───────────────────────┬─────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────┐
                 │       UNIFIED CLOUDPULSE INCIDENT           │
                 │       INC-RC-8A1C92EF40                     │
                 ├─────────────────────────────────────────────┤
                 │  Correlated Threat Impact:                  │
                 │  "Data exfiltration of 1.5 TB verified by   │
                 │   Azure billing surge of +$130.00 on Egress"│
                 └─────────────────────────────────────────────┘
```

### Preserved FinOps Evidence for Correlation

To enable cross-subsystem correlation in the Incident Orchestrator, the Cost Telemetry subsystem must preserve specific correlation keys:

1. **Canonical `resource_id`**: The primary universal join key across Security Findings, Activity Logs, Flow Logs, and Cost Records.
2. **`timestamp` / `evaluation_date`**: Temporal boundary ensuring cost surges correspond with the window of observed security anomalies.
3. **`cost_category` & `meter_category`**: Distinguishes whether financial impact was driven by compute abuse (cryptomining) or bandwidth spikes (data exfiltration).
4. **`actual_cost` & `deviation_absolute`**: Directly populates the `cost_impact` field in CloudPulse incidents:
   ```json
   "cost_impact": {
     "currency": "USD",
     "cost_category": "Network/Egress",
     "financial_surge": 130.00,
     "billed_period": "2026-10-07",
     "verified_by_cost_management": true
   }
   ```
5. **Usage Quantity & Meter Dimensions**: Allows verification that billed bandwidth (in GB) quantitatively aligns with raw flow bytes captured by network adapters.

---

## 10. Network Egress vs. FinOps Relationship

### Strict Pricing Policy
> [!CAUTION]
> **Zero Static Pricing Tables**: CloudPulse must **never** hardcode static egress pricing constants (e.g. `AZURE_EGRESS_COST_PER_GB = 0.087`). Static pricing tables become instantly stale, fail to reflect regional pricing tiers, ignore enterprise volume discounts, and misrepresent egress routing configurations (such as Azure Routing Preference or Direct Peering).

### Telemetry Separation of Responsibilities

```
                                  WORKLOAD EGRESS EVENT
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               ▼                                                         ▼
    NETWORK FLOW TELEMETRY                                     AZURE COST MANAGEMENT
    (Source: AzureNetworkAnalytics_CL)                         (Source: Cost Management API)
    ---------------------------------                         -----------------------------
    • bytes_sent: 1,610,612,736,000                            • actual_cost: $135.24
    • destination_ip: 198.51.100.77                            • currency: USD
    • destination_port: 443                                    • usage_quantity: 1500.0
    • protocol: TCP                                            • usage_unit: GB
    • source_subnet: snet-worker                               • service_name: Bandwidth
    • timestamp: 2026-10-07T14:15:00Z                          • meter_name: Data Transfer Out - Internet
```

### Correlation Methodology
The correlation layer links these two independent datasets using a deterministic matching pipeline:
1. **Workload Attribution**: Filter both flow telemetry and cost records to matching `resource_id`.
2. **Date Reconciliation**: Aggregate total flow telemetry `bytes_sent` for date $T-1$, converted to gigabytes ($GB = \text{bytes} / 1024^3$).
3. **Meter Concurrence**: Verify that the billed `usage_quantity` under meter `Data Transfer Out` or category `Network/Egress` mirrors the magnitude of observed network telemetry.
4. **Financial Truth**: Attribute the actual dollar impact directly from `actual_cost` reported by Cost Management.

---

## 11. Polling & Refresh Strategy

### Recommended Strategy for CloudPulse MVP: Daily Batch with Reconciliation
Because Azure Cost Management updates at 8 to 24-hour cadences, high-frequency polling (e.g. every minute) is wasteful and triggers API rate limits.

```
       00:00 UTC                 06:00 UTC                       06:30 UTC
           │                         │                               │
   Day T-1 Finishes          Azure Daily Pipeline           CloudPulse FinOps
   Billing Ingestion         Aggregates Records              Batch Execution
   Period Concludes          (8-12h latency)                 (Daily Run)
```

1. **Daily Scheduled Batch**:
   * **Execution Time**: Daily at **06:00 UTC** (or 12:00 UTC), allowing sufficient buffer for Azure’s billing engine to finalize the previous day's metrics.
   * **Primary Query Window**: Looks back across $[T-14, T-1]$.
2. **Reconciliation Window ($T-3$ to $T-1$)**:
   * CloudPulse re-queries the previous 3 days during each daily execution.
   * *Rationale*: Azure occasionally applies late-arriving usage adjustments or reservation discounts retroactively within a 72-hour window. Re-querying $T-3$ to $T-1$ automatically reconciles provisional data.
3. **Historical Backfill (Bootstrap Mode)**:
   * Upon initial deployment to a new subscription, CloudPulse executes a one-time historical query for the preceding 14 days ($[T-14, T-1]$) to instantly establish valid workload baselines.
4. **On-Demand Inspection Endpoint**:
   * Provide a manual trigger endpoint `POST /finops/refresh` allowing operators to force an ad-hoc ingestion for testing and incident verification.

---

## 12. Idempotency & Deduplication Design

### A. Deterministic Cost Record Identifier
To guarantee that repeated queries or scheduled re-runs never insert duplicate billing records, every `CostRecord` is assigned a deterministic hash identifier derived from its canonical billing dimensions:

$$\text{seed} = \text{sub\_id} + \text{":"} + \text{res\_id} + \text{":"} + \text{meter\_name} + \text{":"} + \text{timestamp} + \text{":"} + \text{cost\_type}$$

$$\text{record\_id} = \text{"CR-"} + \text{SHA256}(\text{seed})[:16].\text{upper()}$$

```python
# Specification for Siddu: helpers/cost_identity.py

def generate_cost_record_id(
    subscription_id: str,
    resource_id: str,
    meter_name: str,
    usage_date: str,
    cost_type: str = "ActualCost"
) -> str:
    cleaned_sub = subscription_id.strip().lower()
    cleaned_res = resource_id.strip().lower()
    cleaned_meter = meter_name.strip().lower()
    cleaned_date = usage_date.strip()
    cleaned_type = cost_type.strip().lower()
    
    seed = f"{cleaned_sub}:{cleaned_res}:{cleaned_meter}:{cleaned_date}:{cleaned_type}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    return f"CR-{digest}"
```

### B. Upsert / Reconciliation Strategy
When persisting records to PostgreSQL or an in-memory repository:

* If `record_id` does not exist: Insert the record.
* If `record_id` already exists: Perform an `UPDATE` on `actual_cost`, `usage_quantity`, and `updated_at`.
* This ensures that retroactive billing adjustments from Azure update existing records cleanly rather than duplicating rows or skewing statistical calculations.

---

## 13. Error Handling & Resilience

### A. Retryable vs. Non-Retryable Error Classification

| Error Condition | HTTP Code / Exception | Category | Handling Procedure |
|---|---|---|---|
| **Rate Throttling** | `429 Too Many Requests` | **Retryable** | Parse `Retry-After` header. Apply exponential backoff with jitter (initial delay 5s, max delay 60s, 4 retries). |
| **Azure Transient Fault** | `500`, `502`, `503`, `504` | **Retryable** | Retry up to 3 times with exponential backoff (2s, 4s, 8s). |
| **Network Timeout** | Connection / Read Timeout | **Retryable** | Retry twice with a 5s delay. |
| **Missing RBAC Role** | `403 Forbidden` | **Non-Retryable** | Log critical alert: `"Managed Identity lacks Cost Management Reader on scope"`. Terminate run immediately without retrying. |
| **Authentication Expired** | `401 Unauthorized` | **Non-Retryable** | Refresh token via `DefaultAzureCredential`. If token refresh fails, abort run. |
| **Invalid Scope / Syntax** | `400 Bad Request` | **Non-Retryable** | Log error with query payload details for developer debugging. Abort run. |
| **Scope Not Found** | `404 Not Found` | **Non-Retryable** | Log error: `"Subscription or Resource Group does not exist"`. Abort run. |

### B. Data-Level Anomaly Handling
1. **Missing Resource ID**:
   * Certain platform-level Azure costs (such as shared subscription reservation fees or orphaned IP reservations) lack a specific resource ID in billing data.
   * *Resolution*: Map `resource_id = "/subscriptions/{sub_id}/resourceGroups/unallocated"`, set `resource_name = "unallocated"`, and category = `"Other"`. Do not drop the row.
2. **Null or Negative Costs**:
   * Azure occasionally emits negative cost records for billing credits, refunds, or reservation offsets.
   * *Resolution*: Record the exact numerical value reported by Azure. In baseline computations, clamp negative values to `0.0` to prevent skewing variance calculations.
3. **Multi-Currency Workloads**:
   * CloudPulse preserves the currency reported by Azure (e.g. `USD`, `EUR`, `INR`).
   * *Rule*: Baselines and deviations must **only compare like-with-like currencies**. Do not implement dynamic foreign exchange (Forex) conversions in the telemetry layer.

---

## 14. Implementation Contract for Siddu

Siddu must follow this sequential roadmap when implementing the FinOps Cost Management integration:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SIDDU IMPLEMENTATION CHECKLIST                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ ] 1. Create Telemetry Client: telemetry/cost_management.py              │
│         - Uses DefaultAzureCredential(managed_identity_client_id=...)       │
│         - Executes POST queries against Cost Management Query API           │
│         - Implements @nextLink pagination traversal                         │
│                                                                             │
│  [ ] 2. Create Domain Models: models/cost_record.py                         │
│         - CostRecord model with validation and deterministic categories     │
│         - Deterministic generate_cost_record_id helper                      │
│                                                                             │
│  [ ] 3. Create Baseline Engine: telemetry/cost_baseline.py                  │
│         - CostBaselineStore interface with InMemoryCostBaselineStore        │
│         - 14-day mean, standard deviation, and ratio calculation            │
│         - Cold-start and zero-baseline guardrails                           │
│                                                                             │
│  [ ] 4. Update Configuration: config.py                                     │
│         - Add COST_LOOKBACK_DAYS (default: 14)                              │
│         - Add COST_QUERY_API_VERSION (default: "2023-11-01")                │
│                                                                             │
│  [ ] 5. Implement Resilience & Retry Logic                                  │
│         - Exponential backoff with jitter on HTTP 429 and 503               │
│         - Non-retryable termination on 401/403/400                          │
│                                                                             │
│  [ ] 6. Create Unit Tests & Fixtures: tests/test_cost_telemetry.py          │
│         - Test query parsing and normalization                              │
│         - Test deterministic categorization rules                           │
│         - Test baseline calculations (mean, std dev, cold start, zero cost) │
│         - Test deduplication & idempotent record IDs                        │
│         - Test rate-limit backoff handling                                  │
│                                                                             │
│  [ ] 7. Expose Inspection Route: app.py                                     │
│         - Add POST /finops/cost-query (with mock replay and live mode)      │
│         - Follow same pattern as /detect/suspicious-outbound                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 15. Non-Goals

To maintain focus and avoid scope creep, the following items are explicitly **excluded** from this specification and must **NOT** be implemented as part of this milestone:

* ❌ **No `COST_ANOMALY` Detector Implementation**: Developing alert rules, severity thresholds, or detector classes is deferred to the detector milestone.
* ❌ **No Security Detector Modifications**: Existing detectors (`RESOURCE_CREATION`, `UNEXPECTED_PUBLIC_EXPOSURE`, `SUSPICIOUS_OUTBOUND_ACTIVITY`) must not be refactored.
* ❌ **No AI / LLM Triage Implementation**: Generative AI incident summarization belongs strictly to the AI integration layer.
* ❌ **No Automated Remediation**: No automated deallocation, budget resizing, or network isolation code.
* ❌ **No UI / Dashboard Components**: Visual presentation of FinOps charts belongs to the frontend layer.
* ❌ **No Terraform / Infrastructure Changes**: Managed identity role assignments in Azure will be provisioned in a separate infrastructure milestone.
* ❌ **No Database Schema Migrations**: PostgreSQL migrations for storing long-term cost records will be executed separately; the initial worker implementation must rely on the existing schema and in-memory caches.
* ❌ **No Hardcoded Azure Pricing Tables**: Zero static rates per GB or hour.
* ❌ **No Machine Learning Forecasting**: No ARIMA, Prophet, or deep learning predictive models. Simple, robust, deterministic statistics only.
