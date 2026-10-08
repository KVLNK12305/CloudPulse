# CloudPulse Live Remediation E2E Demonstration

This walkthrough documents the verified live end-to-end execution of CloudPulse's autonomous threat surface detection and controlled remediation pipeline against live Azure infrastructure.

---

## 1. Executive Summary & Objective

* **Objective**: Prove the complete closed-loop CloudPulse lifecycle against real Azure resources:
  ```
  Permissive Exposure → Detection → Incident → Advisory AI Triage → Human Approval → Controlled Remediation (ETag) → Live Verification → Rollback → Resource Cleanup
  ```
* **Subscription Scope**: `/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911`
* **Resource Group**: `cloudpulse-rg` (Region: `centralindia`)
* **Test Outcome**: **PASSED (100% compliance across all safety invariants)**

---

## 2. Initial Azure Topology & Vulnerable State

A temporary, isolated test topology was provisioned in `cloudpulse-rg` strictly for pipeline validation:

* **Target Workload**: `cloudpulse-e2e-vm` (`Standard_B2as_v2`)
* **Network Interface**: `cloudpulse-e2e-nic` (Attached to `snet-worker`, Private IP: `10.50.3.4`)
* **Public IP**: `cloudpulse-e2e-pip` (`20.219.4.13`)
* **Network Security Group**: `cloudpulse-e2e-nsg`
* **Vulnerable Inbound Rule**:
  * **Rule Name**: `Allow-SSH-Internet`
  * **Priority**: `100`
  * **Direction**: `Inbound`
  * **Access**: `Allow`
  * **Protocol**: `Tcp`
  * **Destination Port**: `22` (Management Port)
  * **Source CIDR**: `0.0.0.0/0` (Permissive public Internet)
  * **Initial ETag**: `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`

---

## 3. Step 1: Telemetry Ingestion & Deterministic Detection

The `UnexpectedPublicExposureDetector` queried live network topology via Azure Resource Graph (ARG):
1. ARG synthesized relationships across Public IP (`20.219.4.13`), NIC (`cloudpulse-e2e-nic`), Subnet (`snet-worker`), and NSG (`cloudpulse-e2e-nsg`).
2. The detector evaluated effective security rules against port classification rules.
3. Inbound port 22 exposed to `0.0.0.0/0` triggered critical severity classification `MANAGEMENT_PORT`.
4. The detector synthesized a deterministic finding.

### Verified Finding
* **Finding ID**: `F-UPE-2D981ABC2B12`
* **Finding Type**: `UNEXPECTED_PUBLIC_EXPOSURE`
* **Severity**: `CRITICAL`
* **Resource**: `/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/cloudpulse-e2e-vm`
* **Evidence**:
  * NSG: `/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/cloudpulse-e2e-nsg`
  * Rule: `Allow-SSH-Internet`
  * Destination Port: `22`
  * Protocol: `TCP`
  * Source Prefix: `0.0.0.0/0`
  * Public IP: `20.219.4.13`

---

## 4. Step 2: Incident Orchestration & PostgreSQL Persistence

The deterministic finding was processed by the `IncidentOrchestrator`:
* Correlated findings and bound them to the target resource workload.
* Created incident `INC-RC-95E60E379A`.
* Persisted finding and incident records into the PostgreSQL repository.
* Initial Incident Status: `OPEN`.

---

## 5. Step 3: Advisory AI Triage

CloudPulse invoked the AI triage service (`AITriageService`):
* Context was strictly isolated using `AISafeIncidentContext` (no credentials, tokens, or irrelevant resource metadata).
* AI generated structured, advisory incident analysis:
  * **Confidence**: `0.88`
  * **Status**: `COMPLETED`
  * **Summary**: Identified unexpected public SSH exposure on `cloudpulse-e2e-vm`.
  * **Recommended Action**:
    * **Action ID**: `ACT-01`
    * **Title**: `Narrow Source IP Ranges`
    * **Category**: `CONTAINMENT`
    * **Risk**: `LOW`
    * **Requires Human Approval**: `true`
* **Security Verification**:
  * AI executed zero Azure commands.
  * AI produced no executable shell scripts.
  * AI did not mutate infrastructure.

---

## 6. Step 4: Human Approval Gate & Mutation Invariance

Remediation requires explicit operator authorization via API:

1. **Rejection of Unknown Actions**:
   * A request to approve unregistered action `UNKNOWN-ACT-999` was rejected immediately with `400 Bad Request`.
2. **Pre-Approval Live State Check**:
   * Azure ARM read confirmed rule `Allow-SSH-Internet` was still `Inbound / Allow / TCP / 22 / 0.0.0.0/0` with ETag `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`.
3. **Approval Execution**:
   * Operator `rishi@cloudpulse.io` approved action `ACT-01` via `POST /api/incidents/INC-RC-95E60E379A/actions/ACT-01/approval`.
   * Action state transitioned to `APPROVED`.
4. **Zero-Mutation Verification**:
   * Azure ARM rule was read immediately post-approval.
   * Rule was confirmed **100% UNCHANGED** (`access=Allow`, ETag unchanged). Approval alone caused zero Azure mutation.

---

## 7. Step 5: Controlled Remediation Execution (`DISABLE_PUBLIC_INGRESS`)

The remediation engine was invoked with only `action_id=ACT-01`:

1. **Parameter Resolution**:
   * Target NSG (`cloudpulse-e2e-nsg`) and Rule (`Allow-SSH-Internet`) were resolved strictly from finding evidence, not user payload.
2. **Precondition Validation**:
   * Live ARM rule was fetched and verified: Direction = `Inbound`, Access = `Allow`, Port = `22`, Protocol = `Tcp`, Source = `0.0.0.0/0`.
   * Full rollback snapshot captured.
   * Initial ETag captured: `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`.
3. **ARM Mutation with Optimistic Concurrency**:
   * CloudPulse submitted ARM `PUT` with `If-Match: W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`.
   * Mutated `access` from `Allow` to `Deny`. All other rule properties (name, priority, port, source) preserved.
   * Azure accepted mutation: HTTP `200 OK`.
   * New ETag assigned by Azure: `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`.

---

## 8. Step 6: Post-Remediation Verification & Incident Resolution

1. **Live State Verification**:
   * CloudPulse performed an independent read-back query to ARM.
   * Confirmed live rule configuration:
     * `access`: `Deny`
     * `direction`: `Inbound`
     * `destination_port_range`: `22`
     * `protocol`: `Tcp`
     * `source_address_prefix`: `0.0.0.0/0`
     * `etag`: `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`
2. **State Machine Progression**:
   * Remediation: `PROPOSED` → `APPROVED` → `PRECONDITION_CHECKING` → `EXECUTING` → `EXECUTED` → `VERIFYING` → `VERIFIED`.
   * Incident Status: transitioned to `RESOLVED` automatically only upon `VERIFIED`.
3. **Audit Timeline**:
   * Chronological audit sequence persisted in PostgreSQL:
     1. `UNEXPECTED_PUBLIC_EXPOSURE_DETECTED`
     2. `AI_TRIAGE_PERFORMED`
     3. `ACTION_APPROVED`
     4. `REMEDIATION_APPROVED`
     5. `REMEDIATION_STARTED`
     6. `REMEDIATION_EXECUTED`
     7. `REMEDIATION_VERIFICATION_STARTED`
     8. `REMEDIATION_VERIFIED`

---

## 9. Step 7: Controlled Rollback Verification

To ensure safe operational recovery:
1. CloudPulse fetched current live rule and captured ETag `W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`.
2. Applied rollback payload restoring original `Allow` state using `If-Match: W/"88d48d2e-79c0-45c2-a465-bf09c1afde83"`.
3. Live read-back verified restored state: `access=Allow` (ETag: `W/"15051b17-d981-4e04-9b90-96955c9cafb9"`).

---

## 10. Step 8: Complete Cleanup & Infrastructure Invariance

1. **Deleted Disposable Resources**:
   * `cloudpulse-e2e-vm` (Deleted)
   * `cloudpulse-e2e-nic` (Deleted)
   * `cloudpulse-e2e-pip` (Deleted)
   * `cloudpulse-e2e-nsg` (Deleted)
   * `cloudpulse-e2e-vm_OsDisk_*` (Deleted)
   * Azure CLI query confirmed zero `cloudpulse-e2e` resources remain.
2. **Untouched Production Infrastructure**:
   * `cloudpulse-vnet` (Intact)
   * Subnets (`snet-edge`, `snet-worker`, `snet-app`, `snet-data`, `snet-container-apps`) (Intact)
   * NSGs (`sg-edge`, `nsg-worker`, `nsg-app`, `nsg-data`) (Intact)
   * Perimeter rule `sg-edge` `Allow-HTTPS-Inbound` (Intact)
   * PostgreSQL Flexible Server, Azure Key Vault, ACR, Log Analytics (Intact)

---

## 11. Verification Summary Table

| Phase | Expected Behavior | Observed Result | Status |
|---|---|---|---|
| 1. Detection | Synthesize finding from live ARG topology | Finding `F-UPE-2D981ABC2B12` generated | **PASSED** |
| 2. AI Triage | Produce advisory recommended action | Action `ACT-01` recommended; 0 mutations | **PASSED** |
| 3. Approval | Record operator approval without mutating | `status=APPROVED`; ARM state untouched | **PASSED** |
| 4. Concurrency | Use ETag / If-Match constraint on mutation | `If-Match` matched and accepted by ARM | **PASSED** |
| 5. Mutation | Mutate Allow → Deny preserving parameters | Rule updated to `access=Deny` | **PASSED** |
| 6. Verification | Live read-back confirms `Deny` | Read-back confirmed; status `VERIFIED` | **PASSED** |
| 7. Resolution | Incident resolves only upon verification | `incident.status` updated to `RESOLVED` | **PASSED** |
| 8. Rollback | Restore original `Allow` state with ETag | Rule restored to `Allow` and verified | **PASSED** |
| 9. Cleanup | Delete only disposable test topology | All test resources deleted; prod intact | **PASSED** |
| 10. Tests | Full unit and integration test suite | **250/250 tests passed** | **PASSED** |
