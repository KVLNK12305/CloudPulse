# CloudPulse Specification — Controlled Remediation & Verification Contract

## 1. Document Overview & Architectural Identity

* **Document ID**: `REMEDIATION_CONTROLLED_VERIFICATION_CONTRACT`
* **Target Consumer**: CloudPulse Remediation Engine (`services.remediation_service`), API Layer (`app.py`), Dashboard Application
* **Target Service**: `services/detection-worker`
* **Subsystems**:
  * Azure Network Client (`services/azure_network_client.py`)
  * Remediation Service (`services/remediation_service.py`)
  * Incident & Finding Storage (`database/postgres.py`)
* **Status**: Authoritative Architectural Contract for CloudPulse Controlled Remediation

---

## 2. Core Architectural Principles & Security Invariants

CloudPulse establishes a strict, non-negotiable boundary between AI-generated triage and infrastructure mutation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RESPONSIBILITY SEPARATION                         │
├──────────────────────────┬──────────────────────────────────────────────────┤
│ Detection Layer          │ Evaluates telemetry and emits immutable Findings │
│ Correlation Layer        │ Evaluates 5-dimension concurrence matrix        │
│ Incident Orchestration   │ Binds findings into resource incidents          │
│ AI Triage Layer          │ Produces advisory narrative & recommendations    │
│ Human Approval Layer     │ Captures explicit operator authorization         │
│ Remediation Layer        │ Executes deterministic, typed Azure SDK mutations│
│ Verification Layer       │ Reads live Azure state to prove remediation      │
└──────────────────────────┴──────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Fundamental Security Principle: AI is Advisory.**
> 1. The AI model **MUST NEVER** generate executable CLI, PowerShell, Bash, or ARM template scripts.
> 2. The AI model **MUST NEVER** directly initiate or trigger Azure mutations.
> 3. The AI model **MUST NEVER** choose target Azure resource IDs or parameters.
> 4. All target resource, NSG, rule, port, and IP parameters are resolved **strictly from verified Finding evidence stored in PostgreSQL**.
> 5. Remediation executes **only** predefined, hardcoded, deterministic Python handler routines.
> 6. Every remediation action strictly requires prior human operator authorization (`status == APPROVED`).

---

## 3. Supported Remediation Actions

Initial scope supports exactly two deterministic, tightly bounded network actions:

### Action 1: `DISABLE_PUBLIC_INGRESS`
* **Trigger Finding Type**: `UNEXPECTED_PUBLIC_EXPOSURE`
* **Objective**: Remove the dangerous public inbound access path identified by detection.
* **Evidence Source**: `finding.evidence` containing `nsg_id`, `nsg_rule_name`, `destination_port`, `protocol`, `source_address_prefix`.
* **Execution Boundary**:
  * Reads the live NSG security rule.
  * Mutates **only** the identified rule by changing `access` to `Deny`.
  * Preserves priority, port ranges, and rule name.
  * Captures the full original rule schema in `rollback_state` before mutation.
* **Prohibited Actions**:
  * Must NOT delete the NSG, NIC, Subnet, VNet, or VM.
  * Must NOT modify or reorder unrelated security rules.
  * Must NOT replace or flush the NSG.

### Action 2: `ISOLATE_WORKLOAD`
* **Trigger Finding Type**: `SUSPICIOUS_OUTBOUND_ACTIVITY`
* **Objective**: Block external egress from an affected workload to eliminate C2 communication and data exfiltration while maintaining intra-VNet database and management connectivity.
* **Evidence Source**: `finding.resource.id`, `finding.evidence.source_ip`.
* **Execution Boundary**:
  * Inspects the workload's associated subnet/NIC NSG.
  * Identifies an unused priority in the high-priority range (e.g. 100–150).
  * Injects a deterministic deny rule:
    * `name`: `CloudPulse-Isolate-Outbound-{workload_name}`
    * `direction`: `Outbound`
    * `access`: `Deny`
    * `protocol`: `*`
    * `source_address_prefix`: `{workload_private_ip}/32`
    * `destination_address_prefix`: `Internet`
    * `destination_port_range`: `*`
  * Preserves intra-VNet communication (does not block local subnets).
* **Prohibited Actions**:
  * Must NOT detach the NIC from the VM.
  * Must NOT deallocate or restart the VM.
  * Must NOT block RFC1918 internal traffic.

---

## 4. Remediation State Machine

Remediation follows a deterministic state machine strictly decoupled from overall `IncidentStatus`:

```
       [PROPOSED] (AI Recommendation Attached)
           │
           ├──────────────────────────────┐
           ▼ (Operator Rejects)           ▼ (Operator Approves)
      [REJECTED]                     [APPROVED]
                                          │
                                          ▼ (Execution Invoked)
                                [PRECONDITION_CHECKING]
                                          │
                     ┌────────────────────┴────────────────────┐
                     ▼ (Mismatch / Stale)                      ▼ (Verified Vulnerable)
           [PRECONDITION_FAILED]                           [EXECUTING]
                     │                                         │
                     ▼ (Safe Exit)                ┌────────────┴────────────┐
               [NEEDS_REVIEW]                     ▼ (Azure SDK Error)       ▼ (ARM Mutation Success)
                                               [FAILED]                 [EXECUTED]
                                                  │                         │
                                                  ▼                         ▼
                                            [NEEDS_REVIEW]             [VERIFYING]
                                                                            │
                                                           ┌────────────────┴────────────────┐
                                                           ▼ (Exposure Cleared)              ▼ (Exposure Persists)
                                                       [VERIFIED]                  [VERIFICATION_FAILED]
                                                           │                                 │
                                                           ▼ (Terminal Success)              ▼
                                                   (Incident Resolved)                 [NEEDS_REVIEW]
```

### State Definitions
1. `PROPOSED`: Triage recommended an action; awaiting human evaluation.
2. `APPROVED`: Operator explicitly submitted authorization intent (`status: APPROVED`).
3. `REJECTED`: Operator explicitly declined the action.
4. `PRECONDITION_CHECKING`: Worker is inspecting live Azure state to confirm the vulnerability exists.
5. `PRECONDITION_FAILED`: Live Azure state does not match the finding evidence (e.g. rule already removed, port changed, resource deleted). Aborts without mutation.
6. `EXECUTING`: Live Azure ARM mutation is in-flight via Azure SDK.
7. `EXECUTED`: Azure ARM mutation completed successfully.
8. `VERIFYING`: Read-back query in-flight to verify effective state in Azure.
9. `VERIFIED`: Live read-back confirms the dangerous condition is eliminated. Terminal success.
10. `VERIFICATION_FAILED`: Azure accepted mutation, but read-back confirms exposure persists.
11. `FAILED`: Azure API returned an error (403, 404, 409, 500).
12. `NEEDS_REVIEW`: Action terminated abnormally; operator investigation required.

### Incident Status Decoupling
* `incident.status` (`OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED`) remains independent of remediation status.
* When execution starts, `incident.status` moves to `INVESTIGATING`.
* **Only after** `remediation.status == VERIFIED` may the incident transition to `RESOLVED`.

---

## 5. Precondition, Mutation, and Verification Model

Every remediation follows three non-negotiable phases:

### Phase 1: Precondition
Before sending any mutation to Azure:
1. Re-read the live target NSG and rules using `DefaultAzureCredential`.
2. Confirm the target resource exists.
3. Confirm the specific rule matches finding evidence:
   - Name matches `nsg_rule_name`
   - Direction matches `Inbound`
   - Access matches `Allow`
   - Destination port matches `destination_port`
   - Source prefix matches permissive pattern (`*`, `0.0.0.0/0`, `Internet`)
4. **Idempotent Already-Remediated Check**:
   - If the rule already exists with `access == Deny`, or if the isolation rule already exists with required properties, record `status = VERIFIED` and return without issuing redundant mutations.
5. If live state differs unexpectedly, abort with `PRECONDITION_FAILED`.

### Phase 2: Mutation
1. Capture complete original rule schema for rollback.
2. Invoke `NetworkManagementClient` (`begin_create_or_update` or `begin_delete`).
3. Await long-running operation completion with timeout protection.
4. If ARM returns 409 (`Conflict`), execute bounded exponential backoff retry (up to 3 attempts).
5. If unrecoverable failure occurs, mark `FAILED`, capture error, and do not claim resolution.

### Phase 3: Post-Remediation Verification
1. Issue an independent, cache-busting read request to Azure ARM.
2. Re-evaluate the effective security posture:
   - For `DISABLE_PUBLIC_INGRESS`: Verify the rule has `access == Deny` (or no longer permits public ingress).
   - For `ISOLATE_WORKLOAD`: Verify the isolation rule exists with `access == Deny` covering the workload IP.
3. If condition passes: mark `VERIFIED`.
4. If condition fails: mark `VERIFICATION_FAILED`.

---

## 6. Idempotency & Concurrency

### Deterministic Remediation Identifier
Every remediation execution is uniquely keyed:
$$\text{remediation\_id} = \text{"REM-"} + \text{SHA256}(\text{incident\_id} + \text{action\_type} + \text{target\_resource} + \text{target\_rule})[:12].\text{upper()}$$

### Concurrency Rules
1. **Duplicate Execution**: If a remediation request arrives for an action that is already `VERIFIED`, return the verified record without calling Azure APIs.
2. **Concurrent Approvals**: The first valid approval transitions state to `APPROVED`. Subsequent approvals append operator notes without resetting in-progress execution.
3. **ARM Resource Conflicts (409)**: Caught and retried with exponential jitter up to 3 times before declaring `FAILED`.
4. **Target Deleted**: Precondition catches 404 and transitions cleanly to `PRECONDITION_FAILED` with reason `"Target resource not found"`.

---

## 7. Rollback & Original-State Preservation

Before any mutation:
* The exact existing configuration of the target rule is serialized into `rollback_state`:
  ```json
  {
    "name": "Allow-SSH-Internet",
    "priority": 100,
    "direction": "Inbound",
    "access": "Allow",
    "protocol": "Tcp",
    "source_port_range": "*",
    "destination_port_range": "22",
    "source_address_prefix": "*",
    "destination_address_prefix": "*",
    "description": "Original rule before CloudPulse remediation"
  }
  ```
* Rollback is preserved for future operator recovery; CloudPulse **never** performs automatic rollback on successful operations.

---

## 8. Audit Timeline Integration

The incident timeline records each step in chronological order:

| Event Name | Trigger | Content |
|---|---|---|
| `REMEDIATION_PROPOSED` | AI generates recommendation | `action_id`, `action_type`, `risk`, `target` |
| `REMEDIATION_APPROVED` | Operator authorizes action | `action_id`, `operator`, `notes` |
| `REMEDIATION_REJECTED` | Operator declines action | `action_id`, `operator`, `notes` |
| `REMEDIATION_STARTED` | Precondition check begins | `remediation_id`, `action_type`, `target_resource` |
| `REMEDIATION_PRECONDITION_FAILED` | Target state mismatch | `remediation_id`, `reason`, `live_state` |
| `REMEDIATION_EXECUTED` | ARM mutation succeeds | `remediation_id`, `operation`, `duration_ms` |
| `REMEDIATION_VERIFICATION_STARTED` | Verification query begins | `remediation_id`, `verification_target` |
| `REMEDIATION_VERIFIED` | Post-read confirms compliance | `remediation_id`, `verified_state` |
| `REMEDIATION_FAILED` | ARM or verification failure | `remediation_id`, `error_code`, `error_message` |

---

## 9. Database & Storage Architecture

* **Zero Schema Migrations**: The existing PostgreSQL `incidents.remediation` `JSONB` column stores the remediation domain model directly.
* **Multi-Action Structure**:
  ```json
  {
    "actions": {
      "ACT-01": {
        "remediation_id": "REM-4A1B2C3D4E5F",
        "action_id": "ACT-01",
        "action_type": "DISABLE_PUBLIC_INGRESS",
        "status": "VERIFIED",
        "target_resource_id": "/subscriptions/.../virtualMachines/vm-worker-01",
        "target_nsg_id": "/subscriptions/.../networkSecurityGroups/nsg-worker",
        "target_rule_name": "Allow-SSH-Internet",
        "approval": {
          "status": "APPROVED",
          "operator": "secops-operator",
          "timestamp": "2026-10-09T01:00:00Z",
          "notes": "Approved ssh ingress disable"
        },
        "execution": {
          "executed_at": "2026-10-09T01:00:05Z",
          "operation": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
          "status": "SUCCESS"
        },
        "verification": {
          "verified_at": "2026-10-09T01:00:08Z",
          "verified_state": "ACCESS_DENY",
          "is_compliant": true
        },
        "rollback_state": { ... },
        "created_at": "2026-10-09T01:00:00Z",
        "updated_at": "2026-10-09T01:00:08Z"
      }
    }
  }
  ```
* **Backward Compatibility**: Legacy single-dictionary records without `"actions"` remain fully readable.

---

## 10. RBAC & Identity Requirements

The remediation client authenticates using the existing User-Assigned Managed Identity `cloudpulse-identity`.

### Least-Privilege Role Definition (Target)
```json
{
  "Name": "CloudPulseRemediationOperator",
  "IsCustom": true,
  "Description": "Grants CloudPulse Managed Identity least-privilege permissions to read, modify, and delete NSG security rules for controlled remediation.",
  "Actions": [
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg"
  ]
}
```

* **Standard Built-in Fallback**: `Network Contributor` scoped **strictly** to `cloudpulse-rg`.
* **Prohibited Roles**: `Owner`, `Contributor`, `User Access Administrator` are strictly forbidden.

---

## 11. API Surface

| Endpoint | Method | Precondition | Behavior |
|---|---|---|---|
| `/api/incidents/<id>/actions/<action_id>/approval` | `POST` | Incident exists | Records operator intent (`APPROVED` / `REJECTED`). Does **NOT** execute remediation. |
| `/api/incidents/<id>/remediation/execute` | `POST` | Incident exists, action approved | Executes deterministic precondition check, ARM mutation, verification, and updates incident. |
| `/api/incidents/<id>/remediation/verify` | `GET` | Incident exists | Read-only verification query against live Azure state. Zero mutation. |

---

## 12. Live E2E Verification & Operational Proof

The complete controlled remediation lifecycle has been proven end-to-end against live Azure infrastructure under subscription `90b900ea-4273-4b40-a343-091aecfe2911` and resource group `cloudpulse-rg`:

```
Azure Security Exposure (NSG: cloudpulse-e2e-nsg, Rule: Allow-SSH-Internet)
    ↓
Azure Resource Graph Telemetry & Network Topology Ingestion
    ↓
Unexpected Public Exposure Detector (F-UPE-2D981ABC2B12)
    ↓
Incident Orchestrator (INC-RC-95E60E379A)
    ↓
Azure AI Advisory Triage (ACT-01: Narrow Source IP Ranges)
    ↓
Human Operator Approval (/api/incidents/.../actions/ACT-01/approval)
    ↓
Controlled Remediation (REM-5EC0397F5981)
    ↓
Precondition Read & ETag Capture (W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf")
    ↓
ARM Concurrency Mutation via If-Match (Allow → Deny)
    ↓
Live Verification Read-Back (access=Deny, ETag: W/"88d48d2e-79c0-45c2-a465-bf09c1afde83")
    ↓
Remediation VERIFIED → Incident RESOLVED
    ↓
Controlled Rollback via ETag (Deny → Allow, ETag: W/"15051b17-d981-4e04-9b90-96955c9cafb9")
    ↓
Live Rollback Verification & Disposable Topology Deletion
```

### Verified Live Identifiers
* **Finding ID**: `F-UPE-2D981ABC2B12` (Severity: `CRITICAL`)
* **Incident ID**: `INC-RC-95E60E379A`
* **AI Action ID**: `ACT-01` (`title`: "Narrow Source IP Ranges", advisory only)
* **Remediation ID**: `REM-5EC0397F5981` (`action_type`: `DISABLE_PUBLIC_INGRESS`)

### Concurrency Protection & State Transitions
1. **Initial Pre-Remediation State**:
   * NSG: `cloudpulse-e2e-nsg`, Rule: `Allow-SSH-Internet`
   * Direction: `Inbound`, Access: `Allow`, Port: `22`, Protocol: `Tcp`, Source: `0.0.0.0/0`
   * Captured ETag: `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`
2. **Approval Verification**:
   * Unknown action IDs rejected with `400 Bad Request`.
   * Operator approval (`rishi@cloudpulse.io`) recorded without modifying Azure state (confirmed zero mutation during approval).
3. **Execution & ETag Protection**:
   * Preconditions evaluated and passed.
   * ARM `PUT` executed with `If-Match: W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`.
   * Rule mutated from `Allow` to `Deny`. All other properties preserved.
   * New ETag: `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`.
4. **Post-Mutation Verification**:
   * Independent ARM read-back confirmed `access=Deny`.
   * Remediation transitioned to `VERIFIED`. Incident transitioned to `RESOLVED`.
5. **Controlled Rollback**:
   * Live rule fetched with current ETag `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`.
   * Mutation restored original `Allow` state with ETag concurrency protection.
   * Restored rule confirmed `access=Allow` (ETag: `W/"15051b17-d981-4e04-9b90-96955c9cafb9"`).
6. **Integrity & Clean State**:
   * All 4 disposable test resources deleted.
   * Existing infrastructure (`sg-edge`, `cloudpulse-vnet`, `snet-*`, etc.) untouched.
   * Test suite: **250/250 tests passing (100%)**.
