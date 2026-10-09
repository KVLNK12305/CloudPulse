# CloudPulse — Comprehensive Dashboard Audit, Failure Analysis & Remediation Report

**Audit Target:** CloudPulse Operator Console & Supporting Backend Stack  
**Audit Date:** October 2026  
**Status:** Completed & Remediated  
**Execution Environment:** Azure Subscription `90b900ea-4273-4b40-a343-091aecfe2911` / Resource Group `cloudpulse-rg` (Central India)  
**Baseline Test Results:** 265 passed  
**Post-Remediation Test Results:** 276 passed (100% pass rate, 0 failures, 0 skipped)  
**Lifecycle Test Results:** 16 passed (100% pass rate)

---

## 1. Architecture and Data-Flow Summary

CloudPulse provides a single-pane-of-glass operator dashboard for cloud security, FinOps cost anomaly detection, automated multi-vector attack correlation, and controlled, human-authorized Azure remediation.

### A. Component Hierarchy

```
Browser (Vanilla SPA / SSE / Polling)
       │
       ▼
Flask Backend (services/detection-worker/app.py)
       ├── Authentication: DefaultAzureCredential (Managed Identity / Azure CLI)
       ├── Persistence: PostgreSQL / InMemoryDatabase repository
       ├── Baseline Store: InMemoryCostBaselineStore
       │
       ├── Telemetry Clients:
       │     ├── Azure Resource Graph (ResourceGraphClient) ──► KQL Resource Inventory
       │     ├── Azure Cost Management (CostManagementClient) ──► Closed Daily Billing REST API
       │     ├── Azure Monitor Metrics (AzureMonitorMetricsClient) ──► ARM Metrics API
       │     └── Log Analytics (LogAnalyticsClient) ──► KQL Flow & Activity Query API
       │
       └── Core Engines:
             ├── Detection Engine (DetectionService / Rule Detectors)
             ├── Correlation Engine (IncidentOrchestrator)
             ├── AI Triage Service (AITriageService / Azure OpenAI)
             └── Controlled Remediation Engine (RemediationService / AzureNetworkClient)
```

### B. End-to-End Data Flow & Source of Truth Trace

| Dashboard Surface | Consuming Frontend Function | API Endpoint | Backend Service / Source of Truth | Telemetry Latency & Guarantees |
| :--- | :--- | :--- | :--- | :--- |
| **Estate Overview KPIs** | `renderOverviewTab()` | `GET /api/estate/overview` | Aggregation: ARG (`Resources`), Cost Management (`Query API`), Repository (`Incident` table) | ARG: ~1-5 min; Cost: 24–48h closed daily billing |
| **Resource Explorer** | `renderResourcesTable()` | `GET /api/resources` | Live KQL query against Azure Resource Graph (`Resources \| where ...`), enriched with local findings | Real-time ARM state reflection |
| **Deep Inspector Drawer** | `inspectResource(id)` | `GET /api/resources/<path:id>` | ARG metadata + Azure Monitor runtime metrics + Cost Management meter breakdown + PostgreSQL findings | Live ARM + cached 14-day Cost Management summary |
| **FinOps Summary & Drivers** | `renderFinopsTab()` | `GET /api/finops/costs` | Azure Cost Management Query API + `InMemoryCostBaselineStore` statistical baselines | 24–48h reconciliation latency (closed billing) |
| **Incidents Console** | `renderIncidentList()` | `GET /api/incidents` | PostgreSQL / InMemory repository (`incidents` table) | Immediate / Persisted transaction state |
| **Incident Details & Triage** | `renderIncidentDetail(id)` | `GET /api/incidents/<id>/findings`, `GET /api/incidents/<id>/timeline` | Relational join of finding records + timeline event journal | Immediate / Immutable append-only audit trail |
| **AI Incident Triage** | `triggerAITriage(id)` | `POST /api/incidents/<id>/ai-triage` | Azure OpenAI (`gpt-4o`) via `AITriageService` (grounded in verified facts vs inferences) | On-demand operator invocation |
| **Remediation Approval** | `handleActionApproval(id)` | `POST /api/incidents/<id>/actions/<aid>/approval` | `RemediationService.record_approval` (human-in-the-loop authorization invariant) | Persisted audit record with operator identity & notes |
| **Remediation Execution** | `handleExecuteRemediation(id)`| `POST /api/incidents/<id>/remediation/execute` | `RemediationService.execute_remediation` with ETag validation & read-back ARM verification | Synchronous mutation + live Azure read-back verification |

---

## 2. Complete Feature Inventory

| Area | Feature | Status Prior to Audit | Verified Backend Route |
| :--- | :--- | :--- | :--- |
| **Overview** | Resource Count KPI | Functional | `GET /api/estate/overview` |
| **Overview** | Actual Billed Cost KPI | **DEFECTIVE** (showed fake `$0.00`/`₹0.00` on missing data) | `GET /api/estate/overview` |
| **Overview** | Active Incidents KPI | **DEFECTIVE** (diverged from incidents table state) | `GET /api/estate/overview` vs `GET /api/incidents` |
| **Overview** | Cross-Correlation Count | Functional | `GET /api/estate/overview` |
| **Overview** | AI Triaged Count | Functional | Derived from `incidents` |
| **Overview** | Resource Type Distribution | Functional | `GET /api/estate/overview` (`resources.by_type`) |
| **Overview** | Cost Category Distribution | Functional | `GET /api/estate/overview` (`costs.by_category`) |
| **Resources** | ARG Inventory Listing | Functional | `GET /api/resources` |
| **Resources** | Filter by Type, Name, Severity | Functional | Client-side filtering over `resources` |
| **Resources** | Cost & Metrics Status Tags | **DEFECTIVE** (mixed currency symbols) | `GET /api/resources` |
| **Drawer** | Deep Resource Metadata | **DEFECTIVE** (fabricated fallback misattributed to ARG) | `GET /api/resources/<path:id>` |
| **Drawer** | Azure Monitor Runtime Metrics | Functional | `GET /api/resources/<path:id>` (`utilization`) |
| **Drawer** | Cost & Meter Breakdown | Functional | `GET /api/resources/<path:id>` (`cost`) |
| **Drawer** | Security Findings List | Functional | `GET /api/resources/<path:id>` (`security`) |
| **FinOps** | Total Cost KPI | **DEFECTIVE** (showed fake `$0.00` on missing data/429) | `GET /api/finops/costs` |
| **FinOps** | Anomaly Count KPI | Functional | `GET /api/finops/costs` (`anomalies`) |
| **FinOps** | Correlated Overrun KPI | **DEFECTIVE** (hardcoded currency symbols) | `incidents.forEach(inc.cost_impact)` |
| **FinOps** | Top Cost Drivers Table | Functional | `GET /api/finops/costs` (`top_cost_drivers`) |
| **FinOps** | Correlation Spotlight Card | **DEFECTIVE** (hardcoded `$`, ignored real currency) | Derived from top correlated incident |
| **FinOps** | Billing Latency Notice Banner | Functional | `GET /api/finops/costs` (`period.billing_latency_notice`) |
| **Incidents** | Incident List Filtering | Functional | `GET /api/incidents` |
| **Incidents** | Financial Tag on Incidents | **DEFECTIVE** (hardcoded `+$`) | `inc.cost_impact` |
| **Incidents** | Test Fixture Provenance Badging | **DEFECTIVE** (synthetic `vm-worker-01` lacked demo badge)| `isDemoIncident(inc)` check was missing |
| **Incidents** | Status Mutation (PATCH) | **DEFECTIVE** (empty payload accepted, unvalidated) | `PATCH /api/incidents/<id>` |
| **Incidents** | Timeline Ordering | **DEFECTIVE** (unordered list returned) | `GET /api/incidents/<id>/timeline` |
| **Incidents** | Associated Evidence Grid | Functional | `GET /api/incidents/<id>/findings` |
| **AI Triage** | Autonomous Synthesis & Grounding | Functional | `POST /api/incidents/<id>/ai-triage` |
| **AI Triage** | Recommended Actions List | Functional | `inc.ai_analysis.recommended_actions` |
| **Remediation**| Human Operator Authorization | Functional | `POST /api/incidents/<id>/actions/<aid>/approval` |
| **Remediation**| Read-Back Verified Execution | Functional | `POST /api/incidents/<id>/remediation/execute` |
| **Error Handling**| Rate Limit (429) Visibility | **DEFECTIVE** (swallowed with `.catch(() => null)`) | Frontend `loadDashboardData()` |
| **Error Handling**| Action Button Failure Alerts | **DEFECTIVE** (generic alert without server error details)| Frontend button handlers |

---

## 3. Confirmed Defects, Suspected Issues, and Missing Capabilities

### Confirmed Defects (Remediated)
1. **DEF-01 (High): Silent Error Conversion to Fake "$0.00" / "₹0.00" Cost.**
2. **DEF-02 (High): Fabricated Resource Fallback Misattributed to Azure Resource Graph.**
3. **DEF-03 (High): Data Provenance Ambiguity on Seeded Test Scenarios (`vm-worker-01`).**
4. **DEF-04 (Medium): Currency Inconsistency Across Entire Dashboard.**
5. **DEF-05 (Medium): Overview Incident Count Disconnection from Live Incidents State.**
6. **DEF-06 (Medium): Swallowed Errors and Silent Failure on Cost Management 429 Throttling.**
7. **DEF-07 (Medium): Unvalidated Status Payload on Incident PATCH Endpoint.**
8. **DEF-08 (Medium): Non-Chronological Ordering in Incident Timeline API.**
9. **DEF-09 (Low): Missing Missing-Findings Count in Incident Findings API.**
10. **DEF-10 (Low): Missing Currency Specification in `/api/dashboard/summary` Contract.**
11. **DEF-11 (Low): Generic Opaque Error Alerts in Remediation & AI Action Handlers.**

### Suspected Issues (Investigated & Clarified)
- **Suspected unauthorized remediation bypass:** Audited `app.py` line 1425 and `RemediationService`. Found that human approval is strictly verified server-side (`record.approval.status == "APPROVED"`); execution requests for unapproved actions are rejected with HTTP 400 (`RemediationUnapprovedError`).
- **Suspected AI authorization hallucination:** Audited `AITriageService`. Verified that AI output only produces advisory recommendations. It cannot mutate state, authorize remediation, or inject ARM templates.

### Missing Capabilities (Documented for Roadmap)
- Real-time SSE / WebSocket push for incident mutations (currently using polling every 15s).
- Multi-currency conversion engine (currently displays native subscription billing currency, usually USD).
- Historical trend chart component for FinOps 30-day lookback (currently tabular top cost drivers).

---

## 4. Severity-Ranked Findings

| ID | Severity | File Path | Function / Route | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | **High** | `services/detection-worker/app.py` & `static/index.html` | `/api/estate/overview`, `renderOverviewTab`, `renderFinopsTab` | Unavailable or delayed billing data was represented as `$0.00` or `₹0.00`, misleading operators into believing zero spend had occurred. |
| **DEF-02** | **High** | `services/detection-worker/app.py` & `static/index.html` | `GET /api/resources/<path:id>`, `renderDrawerContent` | When ARG returned 0 records for a resource, the backend synthesized fallback metadata but still attributed the source to `"Azure Resource Graph"`. |
| **DEF-03** | **High** | `services/detection-worker/static/index.html` | `renderIncidentList`, `renderIncidentDetail` | The multi-vector test scenario for `vm-worker-01` / `198.51.100.77` was presented without demo fixture provenance, indistinguishable from live breaches. |
| **DEF-04** | **Medium** | `services/detection-worker/static/index.html` | HTML markup, `formatCurrency`, `renderFinopsTab` | Initial HTML hardcoded `₹0.00`, JavaScript defaulted to `INR`, while Azure returned `USD` and incident cards hardcoded `$`. |
| **DEF-05** | **Medium** | `services/detection-worker/static/index.html` | `renderOverviewTab` | Overview summary cards read from cached `estateOverview` while Incidents Console read from `incidents`, causing counter divergence. |
| **DEF-06** | **Medium** | `services/detection-worker/static/index.html` | `loadDashboardData`, `renderFinopsTab` | Fetch errors were caught with `.catch(() => null)`, completely hiding 429 rate-limiting and 503 unavailability from the operator. |
| **DEF-07** | **Medium** | `services/detection-worker/app.py` | `PATCH /api/incidents/<id>` | PATCH endpoint accepted empty JSON payloads `{}` without validating that `status` was present, appending false timeline audit entries. |
| **DEF-08** | **Medium** | `services/detection-worker/app.py` | `GET /api/incidents/<id>/timeline` | Timeline records were returned as unordered lists, violating chronological audit expectations. |
| **DEF-09** | **Low** | `services/detection-worker/app.py` | `GET /api/incidents/<id>/findings` | Pruned or missing finding IDs in `incident.findings` were silently dropped without reporting `missing_findings_count`. |
| **DEF-10** | **Low** | `services/detection-worker/app.py` | `GET /api/dashboard/summary` | API contract omitted `currency`, preventing consumers from knowing the denomination of `total_financial_overrun`. |
| **DEF-11** | **Low** | `services/detection-worker/static/index.html` | `triggerAITriage`, `handleActionApproval`, `handleExecuteRemediation` | Action failure alerts showed generic messages instead of parsing server JSON error messages. |

---

## 5. Root-Cause Analysis and Reproduction Steps

### DEF-01: Silent Conversion to Fake Zero Cost
- **Root Cause:** In `app.py` line 1162, `cost_total` defaulted to `0.0` even when `has_cost_data` was `False`. In `index.html` line 1409, `const costTotal = estateOverview.costs?.total_cost || 0` rendered `${currSymbol}${costTotal.toFixed(2)}` (`$0.00`).
- **Reproduction:** Set `mock_cost.get_cost_summary.return_value = {"has_data": False, "summary": {"total_cost": 0.0}}`. Load Overview tab. UI displays `$0.00` instead of `—` (Unavailable).

### DEF-02: Fabricated Resource Fallback Misattributed to ARG
- **Root Cause:** In `app.py` lines 935–952, when ARG returned no records (`res_records` empty), a synthesized fallback dictionary was generated. However, line 1064 set `"source_attributions": {"resource": "Azure Resource Graph"}` unconditionally.
- **Reproduction:** Call `GET /api/resources/subscriptions/.../virtualMachines/vm-worker-01` against an Azure subscription where `vm-worker-01` does not exist. Inspect `source_attributions.resource`; it returned `"Azure Resource Graph"` instead of identifying it as a synthesized fallback.

### DEF-03: Data Provenance Ambiguity on Seeded Test Scenarios
- **Root Cause:** In `index.html`, `btn-seed-demo` injected simulated events for `vm-worker-01` with caller `admin@cloudpulse.io`. The incident rendering logic contained no check for test telemetry markers and rendered the incident identically to ARM production events.
- **Reproduction:** Click "Seed Test Scenario" in the dashboard. Ingested incident `INC-RC-...` had no indicator that it originated from synthetic test fixtures.

### DEF-04: Currency Inconsistency Across Views
- **Root Cause:** HTML templates in `index.html` hardcoded `₹0.00` in initial KPI tags, JavaScript defaulted fallback currency to `'INR'`, while correlation spotlights and incident cards hardcoded `$`.
- **Reproduction:** Open dashboard in an empty state or with USD subscription. Overview and FinOps KPIs loaded as `₹0.00` while incident cards loaded as `+$181.20`.

### DEF-05: Overview Card Disconnection from Incident State
- **Root Cause:** Overview card `#ov-incidents-count` read `estateOverview.security?.total_incidents`, while `#nav-inc-count` read `incidents.length`. Mutations to incidents (via PATCH, seeding, or resolution) updated `incidents` but not `estateOverview`.
- **Reproduction:** Change an incident status to RESOLVED or click "Seed Test Scenario". The Overview count did not match the Incidents tab navigation counter.

### DEF-06: Swallowed Rate-Limiting Errors
- **Root Cause:** In `index.html`, `Promise.all([fetch(...).catch(() => null), ...])` swallowed non-200 responses. If Azure Cost Management returned HTTP 429, `costResp.ok` was false, and the error was silently ignored without notifying the operator.
- **Reproduction:** Configure mock or live Cost Management client to return HTTP 429. Open FinOps tab. UI remained blank with initial placeholders and showed no error banner.

---

## 6. Fixes Implemented and Regression Tests

### A. Backend Fixes (`services/detection-worker/app.py`)

1. **Explicit Null for Unavailable Cost Telemetry:**
   - In `get_estate_overview()`, if `has_cost_data` is `False`, `total_cost` is explicitly set to `None` instead of `0.0`.
   - `latency_notice` is populated with specific error messages if queries fail.
2. **Accurate Resource Provenance Tracking:**
   - In `get_resource_detail()`, tracked `discovered_in_arg = True` only when ARG query yields matching records.
   - If not found in ARG, `resource_meta["discovered_in_arg"] = False`, and `source_attributions["resource"]` is set to `"Fabricated fallback (Resource not found in Azure Resource Graph)"`.
3. **Payload Validation on Incident Status PATCH:**
   - Validated that `status` is non-empty before processing; returns HTTP 400 Bad Request with an explicit error message if missing.
4. **Chronological Ordering of Incident Timeline:**
   - Sorted timeline entries chronologically by timestamp (`sorted(incident.timeline, key=lambda e: e.get("timestamp") or "")`).
5. **Pruned Findings Tracking:**
   - In `get_incident_findings()`, added `missing_findings_count = max(0, len(incident.findings) - len(findings))` to the JSON response.
6. **Currency Inclusion in Summary Contract:**
   - In `get_dashboard_summary()`, added `"currency": "USD"` to the response schema.

### B. Frontend Fixes (`services/detection-worker/static/index.html`)

1. **Standardized Currency Formatting:**
   - Replaced initial DOM hardcoded `₹0.00` with `—`.
   - Created centralized, null-safe `formatCurrency(amount, currency = 'USD')` helper mapping symbols dynamically (`USD` -> `$`, `INR` -> `₹`, `EUR` -> `€`, `GBP` -> `£`).
   - Replaced all hardcoded currency symbols across Overview, FinOps, Resource Explorer, and Incident Console with `formatCurrency`.
2. **Transparent Telemetry Availability:**
   - In `renderOverviewTab()` and `renderFinopsTab()`, if `has_data` is `false` or `total_cost == null`, rendered `—` and displayed `No closed billing data (24–48h latency)`.
3. **Rate-Limiting & Error Notification Banners:**
   - Added `#finops-alert-container` and `#overview-alert-container`.
   - Updated `loadDashboardData()` to inspect response status codes. On HTTP 429, displays: `⚠️ Rate limit reached (HTTP 429). Azure Cost Management throttled queries.` with a retry button.
4. **Overview & Incident Counter Synchronization:**
   - In `renderOverviewTab()`, synchronized incident counts directly from active `incidents` state, guaranteeing 100% agreement between Overview KPI cards, navigation badges, and the incident list.
5. **Seeded Test Fixture Provenance Badging:**
   - Added `isDemoIncident(inc)` helper detecting test markers (`vm-worker-01`, `admin@cloudpulse.io`, `evt-rc-demo`).
   - Added prominent `[🧪 DEMO FIXTURE]` badge on incident cards and a dedicated notice banner in the incident detail view.
6. **Unindexed Resource Warning:**
   - In `renderDrawerContent()`, if `res.discovered_in_arg === false`, displays: `⚠️ Not Discovered in Azure Resource Graph: This resource was synthesized from telemetry identifiers and does not exist in the active Azure Resource Graph inventory.`
7. **Action Error Visibility:**
   - Replaced generic alert strings with server-returned JSON error parsing (`errData.message || errData.error`).

### C. Regression Test Suite (`services/detection-worker/tests/test_dashboard_audit_remediation.py`)

A comprehensive test suite of 11 regression tests was created to lock in the audited behavior:
- `test_estate_overview_missing_cost_data_returns_none`
- `test_estate_overview_with_cost_data_returns_actual_total`
- `test_resource_detail_unindexed_provenance`
- `test_resource_detail_indexed_provenance`
- `test_dashboard_summary_contract_currency`
- `test_patch_incident_status_validation`
- `test_incident_timeline_chronological_ordering`
- `test_incident_findings_missing_count`
- `test_finops_costs_rate_limit_propagation`
- `test_finops_costs_rbac_propagation`
- `test_approval_unregistered_action_rejected`

---

## 7. Test Results

### Application Test Suite
```bash
PYTHONPATH=services/detection-worker services/detection-worker/.venv/bin/pytest services/detection-worker/tests/ -q
```
**Result:** `276 passed in 0.95s` (100% pass rate, 0 failures, 0 skipped).

### Azure Lifecycle Test Suite
```bash
./scripts/test-lifecycle.sh -q
```
**Result:** `16 passed in 11.65s` (100% pass rate).

### JavaScript Syntax & Build Validation
```bash
node -e "/* script syntax parser */"
```
**Result:** `Script block 1: valid syntax`.

---

## 8. Data-Source Provenance Findings

During the audit, a comprehensive tracing of displayed data fields was performed:

| Workload / Telemetry | Appears In | Provenance Source | Classification | Remediated Display |
| :--- | :--- | :--- | :--- | :--- |
| `cloudpulse-app` | Resource Explorer | Azure Resource Graph | **Actual Azure Data** | Succeeded, ARG badge, metrics supported |
| `cloudpulse-postgres01` | Resource Explorer | Azure Resource Graph | **Actual Azure Data** | Succeeded, ARG badge, flexible server |
| `nsg-worker` | Resource Explorer | Azure Resource Graph | **Actual Azure Data** | Succeeded, ARG badge, NSG rules |
| `vnet-cloudpulse` | Resource Explorer | Azure Resource Graph | **Actual Azure Data** | Succeeded, ARG badge, virtual network |
| `vm-worker-01` | Incident Console (when seeded) | Seeded Test Scenario | **Explicit Demo Fixture** | Badged with `[🧪 DEMO FIXTURE]` + disclaimer banner |
| `198.51.100.77` (IP) | Incident Evidence (when seeded) | Seeded Network Flow | **Explicit Demo Fixture** | Tagged as simulated outbound IP |
| `+$181.20` Egress Spike | Incident Evidence (when seeded) | Seeded Cost Observation | **Explicit Demo Fixture** | Tagged as simulated FinOps anomaly |
| Total Billed Cost | Overview / FinOps | Azure Cost Management | **Actual Azure Telemetry** | Displays `—` during 24-48h reconciliation window; displays actual USD spend when closed |

---

## 9. Remaining Risks and Unresolved Issues

1. **Azure Cost Management Rate Limits (HTTP 429):**  
   *Risk:* Azure Cost Management enforces strict tenant-level call quotas (typically 15 calls/minute per subscription/resource group scope). Rapid consecutive browser refreshes can trigger HTTP 429 throttling.  
   *Mitigation:* Handled via in-memory summary caching (60s TTL), exponential backoff in `CostManagementClient`, and the newly added operator alert banner with a manual retry button.
2. **Azure Billing Reconciliation Latency (24–48 Hours):**  
   *Risk:* Cost Management data is not real-time stream telemetry; Azure reconciles billing records on daily boundaries with 24–48h latency. Operators expecting real-time cost feedback for today's workloads will see closed billing from yesterday or earlier.  
   *Mitigation:* Preserved and emphasized latency notice banners across Overview, FinOps, and Resource Drawer views.
3. **In-Memory Test vs Production PostgreSQL Mode:**  
   *Risk:* When running without `POSTGRES_PASSWORD`, CloudPulse falls back to `InMemoryDatabase`. Data in memory does not persist across container app restarts.  
   *Mitigation:* Production mode connects to `cloudpulse-postgres01` over SSL with connection pooling. The lifecycle scripts ensure DB boot before application start.

---

## 10. Recommended Next Steps

1. **Short-Term (High Impact):**
   - Implement an HTTP-level ETag cache for `/api/estate/overview` to reduce unnecessary ARG and Cost Management queries on repeated polling intervals.
   - Configure Azure Container Apps diagnostic logging alerts to monitor for 429 responses from Azure Cost Management.
2. **Medium-Term (Medium Impact):**
   - Add Server-Sent Events (SSE) on `/api/incidents/stream` so that incident mutations and status updates push directly to the browser without polling.
   - Add automated scheduled baseline jobs in `detection-worker` to pre-aggregate daily FinOps observations.
3. **Long-Term (Architectural):**
   - Introduce a multi-currency exchange rate service to support subscriptions billed in mixed currencies (EUR, GBP, INR, USD).
   - Expand remediation actions beyond NSGs to include automated Azure Firewall and Network Security Perimeter rule adjustments.
