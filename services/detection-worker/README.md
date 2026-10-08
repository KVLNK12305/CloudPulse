# CloudPulse Detection Worker

The **Detection Worker** is the autonomous ingestion and deterministic detection engine of the CloudPulse platform. It ingests Azure telemetry from Log Analytics, executes deterministic detection rules, normalizes events into structured CloudPulse Findings, persists state in PostgreSQL, and creates unified Incidents for triage.

---

## Architecture: Vertical Slice (MVP Milestone 1)

```
 Azure Activity Log (Subscription Diagnostic Setting)
          │
          ▼
 Azure Log Analytics Workspace (cloudpulse-law / AzureActivity)
          │
          ▼  [query_workspace via Managed Identity / KQL]
 Detection Worker (services/detection-worker)
    ├── Telemetry Layer (telemetry/log_analytics.py)
    ├── Detector Engine (detectors/resource_creation.py)
    │     └── RESOURCE_CREATION rule (Conservative creation filter)
    ├── Domain Models (models/finding.py, models/incident.py)
    ├── Incident Orchestrator (services/incident_orchestrator.py)
    └── Persistence (database/postgres.py)
          │
          ▼
 Azure Database for PostgreSQL (Flexible Server)
    ├── findings (deduplicated by deterministic finding_id)
    ├── incidents (unified incident state)
    └── incident_findings (correlation links)
```

---

## Detection Contract: `RESOURCE_CREATION`

The detection worker strictly adheres to the detection specification defined in [`docs/detection/resource-creation.md`](../../docs/detection/resource-creation.md).

### Supported Resource Categories (MVP)

1. **Virtual Machines**: `Microsoft.Compute/virtualMachines`
2. **Public IP Addresses**: `Microsoft.Network/publicIPAddresses`
3. **Storage Accounts**: `Microsoft.Storage/storageAccounts`
4. **Network Security Groups**: `Microsoft.Network/networkSecurityGroups`
5. **Role Assignments**: `Microsoft.Authorization/roleAssignments`
6. **Container Apps**: `Microsoft.App/containerApps`

### Conservative Creation Filtering

Azure Activity Log operations use `/WRITE` verbs for both create and update actions (e.g. `MICROSOFT.APP/CONTAINERAPPS/WRITE`).
To avoid false positives, the detector enforces conservative filtering:
* Verifies `ActivityStatusValue` is `Success` or `Succeeded`.
* Verifies creation signals such as `ActivitySubstatusValue` of `Created` or `201`, or inner JSON properties with `statusCode: "Created"`.
* Operations returning generic `OK` or `200` without creation markers are treated as resource modifications and ignored.

### Severity & Confidence Scoring

* **HIGH Severity**: Security-sensitive boundary changes (`Role Assignments`, `Public IP addresses`).
* **MEDIUM Severity**: Workload and data resource creations (`Virtual Machines`, `Container Apps`, `Storage Accounts`, `Network Security Groups`).
* **Confidence**: Guaranteed within $[0.0, 1.0]$. Base confidence is $0.85$–$0.90$, boosted up to $0.95$ when both substatus and inner properties confirm creation.

---

## Database Schema & Migrations

PostgreSQL schemas are managed via SQL migration scripts in `database/migrations/`:

* `001_initial_schema.sql`:
  * `findings`: Stores normalized findings with deterministic `finding_id` primary/unique keys, resource metadata, identity, and full raw evidence JSONB.
  * `incidents`: Unified incident representations with deterministic `incident_id`, lifecycle status (`OPEN`), severity, and evidence timeline.
  * `incident_findings`: Foreign-key correlation mapping between incidents and findings.

Migrations run automatically on worker startup via `PostgresDatabase.initialize_schema()`.

---

## API Endpoints

### 1. Health Probe
* **Endpoint**: `GET /health`
* **Response**:
```json
{
  "service": "cloudpulse-detection-worker",
  "status": "healthy",
  "environment": "production",
  "detector": "RESOURCE_CREATION"
}
```

### 2. Trigger Detection Pipeline
* **Endpoint**: `POST /detect/resource-creation`
* **Request Body** (optional):
```json
{
  "lookback_minutes": 60,
  "events": []
}
```
> *Note: If `events` is omitted, the worker queries live Log Analytics using KQL.*

* **Response**:
```json
{
  "status": "success",
  "events_analyzed": 12,
  "findings_detected": 2,
  "new_findings_persisted": 2,
  "incidents_created_or_updated": 2,
  "findings": [...],
  "incidents": [...]
}
```

### 3. Query Findings
* **`GET /findings?limit=50`**: List recent normalized findings.
* **`GET /findings/<finding_id>`**: Retrieve a specific finding by deterministic ID.

### 4. Query Incidents
* **`GET /incidents?limit=50`**: List tracked security incidents.
* **`GET /incidents/<incident_id>`**: Retrieve a specific incident by deterministic ID.

---

## Environment Variables & Configuration

| Variable | Description | Default |
|---|---|---|
| `LOG_ANALYTICS_WORKSPACE_ID` | Customer ID (GUID) of the Log Analytics workspace | `f4fcc158-554b-497e-8231-4cc47c66b194` |
| `POSTGRES_HOST` | Azure PostgreSQL server hostname | `cloudpulse-postgres01.postgres.database.azure.com` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_DB` | PostgreSQL database name | `postgres` |
| `POSTGRES_USER` | PostgreSQL admin username | `cloudpulseadmin` |
| `POSTGRES_PASSWORD` | PostgreSQL admin password (injected via secret) | *None* |
| `POSTGRES_SSLMODE` | SSL connection mode | `require` |
| `ENVIRONMENT` | Runtime environment (`production`, `development`, `test`) | `production` |
| `LOOKBACK_MINUTES` | Default telemetry query window in minutes | `60` |

---

## Azure Identity & Permissions (Least Privilege)

The detection worker utilizes **Managed Identity** (`DefaultAzureCredential`):
* In Azure Container Apps: Uses User-Assigned Managed Identity `cloudpulse-identity`.
* In Local Development: Falls back seamlessly to authenticated Azure CLI credentials (`az login`).

### Required Azure Roles
* **`Log Analytics Reader`** or **`Reader`**: Assigned to `cloudpulse-identity` on workspace `cloudpulse-law` to execute KQL queries on `AzureActivity`.
* **`Key Vault Secrets User`**: Assigned on `cloudpulse-kv01` for secret retrieval.
* **`AcrPull`**: Assigned on Container Registry `cloudpulseacr01`.

*Note: The worker does NOT require nor receive write permissions to Azure resources.*

---

## Local Development & Testing

### Running Tests
The automated test suite runs with pytest without requiring live Azure credentials:

```bash
cd services/detection-worker
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests -v
```

### Running Locally
```bash
export ENVIRONMENT=development
python app.py
```

---

## Known Limitations & MVP Assumptions

1. **Activity Log Ingestion Latency**: Azure Activity Log events exported to Log Analytics typically exhibit a 1-to-5 minute ingestion delay from event generation. Lookback windows account for this latency.
2. **PostgreSQL Network Access**: In production, PostgreSQL Flexible Server has public network access disabled and resides inside delegated subnet `snet-data`. To communicate with PostgreSQL from Azure Container Apps, the container environment connects via private networking. For offline/isolated testing, the worker automatically provides an in-memory repository fallback.
3. **Interpretive AI & Remediation**: AI analysis (`ai_analysis`) and remediation (`remediation`) fields are preserved in the Incident data model as explicit nulls/placeholders, ensuring full forward compatibility without premature implementation.
