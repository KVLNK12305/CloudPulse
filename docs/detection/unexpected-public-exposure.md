# CloudPulse Detection Specification — Unexpected Public Exposure

## 1. Detection ID

`UNEXPECTED_PUBLIC_EXPOSURE`

---

## 2. Objective

The `UNEXPECTED_PUBLIC_EXPOSURE` detector identifies Azure workloads, network interfaces, and subnets that are directly accessible from the untrusted public Internet without an authorized perimeter protection architecture.

### Distinguishing Exposure from Resource Existence
A resource existing in Azure (such as a Virtual Machine, Container App, Storage Account, or Network Security Group) does **not** inherently constitute public exposure. 

A resource is considered **publicly exposed** only when a verifiable inbound network path exists from the public Internet to the workload. This requires **both** of the following conditions to be true:
1. **Public Ingress Route**: The resource has a directly associated Public IP address (via NIC or front-end IP configuration) or is routed via an external public endpoint.
2. **Permissive Network Access**: An Inbound Network Security Group (NSG) rule (applied at the NIC or Subnet level) permits traffic from public source prefixes (`*`, `Internet`, or `0.0.0.0/0`) to the resource's listening ports.

---

## 3. Threat Model

Unrestricted public network exposure represents one of the most critical cloud attack vectors, enabling direct external enumeration and exploitation. This detector addresses the following threat scenarios:

* **Unintended Internet Exposure**: Internal backend workloads (application servers, build runners, data pipelines) deployed into public-facing subnets or erroneously assigned Public IPs.
* **Exposed Management Interfaces**: Administrative protocols exposed to the Internet—specifically SSH (TCP 22), RDP (TCP 3389), and WinRM (TCP 5985/5986)—inviting automated brute-force attacks, credential stuffing, and remote code execution vulnerabilities.
* **Overly Permissive Inbound NSG Rules**: Security rules with wildcard source addresses (`*`, `0.0.0.0/0`, `Internet`) and broad destination port ranges (e.g., `1-65535` or `0-1024`).
* **Accidental Database Exposure**: Direct public routing permitted to database engines (PostgreSQL 5432, MySQL 3306, MSSQL 1433, MongoDB 27017, Redis 6379), bypassing private VNet endpoints and bastion architectures.
* **Bypassing Perimeter Security**: Workloads exposed directly rather than behind approved edge controls (such as Azure Application Gateway, Azure Front Door, or Web Application Firewalls).

> **Important**: A Public IP alone is not automatically malicious. Legitimate public endpoints exist (e.g., edge load balancers, API gateways). Detection must deterministically evaluate the *nature of the exposure* (e.g., port criticality, source breadth, and workload sensitivity).

---

## 4. Telemetry and Data Sources

To accurately identify public exposure, CloudPulse evaluates event signals and resource state.

### A. Azure Activity Log (`AzureActivity` in Log Analytics)
* **Status**: **Currently Ingested** by CloudPulse detection worker via Log Analytics (`cloudpulse-law`).
* **Evidence Provided**:
  * Event timestamp, subscription ID, correlation ID, and initiating identity (`Caller`, `principal_id`).
  * Operations:
    * `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE`
    * `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE`
    * `MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE`
    * `MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE`
  * Rule parameters in request/response payloads (`direction`, `access`, `sourceAddressPrefix`, `destinationPortRange`).
* **Limitation**: AzureActivity represents point-in-time change events. It cannot determine if an NSG is actively attached to a running NIC or whether a detached public IP is receiving traffic.

### B. Azure Resource Graph (ARG)
* **Status**: **Implementation Dependency for Siddu** (Requires integrating ARG query client).
* **Evidence Provided**:
  * Live topological inventory of network state.
  * Joins between `Microsoft.Network/publicIPAddresses`, `Microsoft.Network/networkInterfaces`, `Microsoft.Network/networkSecurityGroups`, and `Microsoft.Compute/virtualMachines`.
  * Verifies effective association: confirms whether a public IP is attached to a NIC that has an active inbound allow rule.
* **Required SDK / Permissions**: `azure-mgmt-resourcegraph` (or ARM REST API) using Managed Identity (`cloudpulse-identity`) with `Reader` role on the subscription.

---

## 5. Detection Conditions

The detector evaluates telemetry against deterministic rules. An event or configuration is flagged as `UNEXPECTED_PUBLIC_EXPOSURE` when all of the following conditions are met:

### Condition 1: Public Reachability Exists
* The target resource has an allocated Public IP address (`ipConfiguration` is non-null).
* **OR** the operation explicitly associates a Public IP with a network interface.

### Condition 2: Inbound NSG Rule Permits Public Traffic
* `direction` = `Inbound`
* `access` = `Allow`
* `sourceAddressPrefix` or `sourceAddressPrefixes` contains:
  * `*`
  * `0.0.0.0/0`
  * `Internet`
  * CIDR blocks broader than `/8`

### Condition 3: Dangerous Port or Sensitive Service Exposed
Exposure is categorized into three criticality tiers:
1. **Administrative / Management Ports**:
   * SSH: `22`
   * RDP: `3389`
   * WinRM: `5985`, `5986`
   * Telnet: `23`
2. **Database & Cache Ports**:
   * PostgreSQL: `5432`
   * MySQL: `3306`
   * MSSQL: `1433`
   * MongoDB: `27017`
   * Redis: `6379`
   * Elasticsearch: `9200`, `9300`
3. **Broad Port Ranges**:
   * Any destination port range containing wildcard `*` or spanning $> 100$ ports without an edge proxy profile.

---

## 6. Severity Model

Severity is assigned deterministically based on port criticality, workload sensitivity, and source restrictions:

| Severity | Deterministic Criteria | Example Scenario |
|---|---|---|
| **CRITICAL** | Direct Internet exposure (`*`, `0.0.0.0/0`, `Internet`) on **Management Ports** (22, 3389, 5985, 5986) OR **Database Ports** (5432, 3306, 1433, 27017, 6379). | Inbound NSG rule allows `0.0.0.0/0` to port 22 on a VM with a Public IP. |
| **HIGH** | Internet exposure (`*`, `0.0.0.0/0`) on **Wildcard/Broad Port Ranges** (`*` or range $> 100$ ports), OR Public IP directly attached to an internal subnet workload (`snet-app`, `snet-data`, `snet-worker`). | NSG rule opening ports `1-65535` to `Internet`. |
| **MEDIUM** | Inbound Internet access permitted to non-standard application ports (e.g. 8080, 8443, 5000) on an unmanaged compute instance without a verified Web Application Firewall. | Inbound allow rule on port 8080 directly on a VM without Application Gateway. |
| **LOW** | A Public IP is allocated but currently unassociated with an active NIC, OR an inbound rule has wide source restrictions (e.g. broad CIDR like `/16` that is not global `0.0.0.0/0`). | Standalone Public IP created but not yet bound to a NIC. |

---

## 7. Confidence Model

Confidence scores are calculated deterministically on a scale of $0.0$ to $1.0$ (no AI):

| Confidence Score | Evaluation Criteria |
|---|---|
| **0.95** | **Fully Correlated State**: Verified via Azure Resource Graph that the Public IP is actively bound to a running workload NIC **and** an effective Inbound NSG rule allows public access. |
| **0.85** | **Verified Activity Log Event**: Azure Activity Log explicitly records successful creation of an Inbound Allow NSG rule for `Internet`/`0.0.0.0/0` on an NSG already associated with a public interface. |
| **0.75** | **Delta Signal Only**: Azure Activity Log records an NSG rule allowing Internet traffic, but NIC binding status has not yet been verified against live topology. |
| **0.60** | **Partial Network Signal**: A Public IP creation event is observed with uncertain inbound firewall rules. |

---

## 8. Required Evidence

Each normalized `Finding` must contain structured evidence adhering to the CloudPulse schema:

### Mandatory Fields
* **Resource Metadata**:
  * `resource.id`: Full Azure Resource ID of the exposed resource (VM, NIC, or NSG).
  * `resource.type`: Resource type (e.g., `Microsoft.Compute/virtualMachines`, `Microsoft.Network/networkSecurityGroups`).
  * `resource.name`: Resource name.
  * `resource.resource_group`: Resource group name.
* **Network Evidence (inside `evidence`)**:
  * `operation`: Azure operation name (e.g., `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE`).
  * `activity_log_event_id`: Unique Azure EventDataId or state assessment ID.
  * `protocol`: `TCP`, `UDP`, or `*`.
  * `source_address_prefix`: Source CIDR or service tag (e.g., `0.0.0.0/0`, `Internet`, `*`).
  * `destination_port`: Target port or port range (e.g., `22`, `3389`, `1-1024`).
  * `exposure_type`: Category identifier (`MANAGEMENT_PORT`, `DATABASE_PORT`, `WILDCARD_PORTS`, `UNPROTECTED_SERVICE`).
* **Context**:
  * `timestamp`: ISO-8601 timestamp of event detection.
  * `subscription_id`: Azure subscription ID.

### Optional Fields (Included when available)
* `evidence.public_ip`: Public IPv4/IPv6 address string.
* `evidence.public_ip_resource_id`: Resource ID of the Public IP.
* `evidence.nsg_id`: Resource ID of the associated NSG.
* `evidence.nsg_rule_name`: Name of the security rule granting access.
* `evidence.nic_id`: Resource ID of the bound network interface.
* `evidence.subnet_id`: Associated VNet subnet ID.
* `identity.caller`: UPN, email, or SPN that authored the change.
* `identity.principal_id`: Object ID of the initiating principal.
* `evidence.correlation_id`: Azure Correlation ID.

---

## 9. Finding Schema

Normalized JSON finding adhering to the CloudPulse Finding contract:

```json
{
  "finding_id": "F-UPE-7A39B21C4D10",
  "finding_type": "UNEXPECTED_PUBLIC_EXPOSURE",
  "severity": "CRITICAL",
  "timestamp": "2026-10-08T12:30:00Z",
  "resource": {
    "id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-backend-01",
    "type": "Microsoft.Compute/virtualMachines",
    "name": "vm-backend-01",
    "resource_group": "cloudpulse-rg"
  },
  "identity": {
    "principal_id": "2a42dc24-83cc-437c-804b-967bb1808c91",
    "principal_type": "User",
    "caller": "admin@cloudpulse.io"
  },
  "evidence": {
    "operation": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "activity_log_event_id": "9b12a345-6789-4bcd-ef01-23456789abcd",
    "correlation_id": "corr-nsg-rule-999",
    "subscription_id": "90b900ea-4273-4b40-a343-091aecfe2911",
    "public_ip": "20.198.110.45",
    "public_ip_resource_id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/publicIPAddresses/pip-vm-backend",
    "nsg_id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker",
    "nsg_rule_name": "Allow-SSH-All",
    "protocol": "TCP",
    "source_address_prefix": "0.0.0.0/0",
    "destination_port": "22",
    "exposure_type": "MANAGEMENT_PORT"
  },
  "confidence": 0.95
}
```

---

## 10. Deduplication and Finding Identity

To prevent alert fatigue and redundant database records across periodic detection runs:

### Deterministic Finding ID Formulation
The finding ID must be generated by hashing the canonical tuple of **target resource**, **NSG rule / exposure vector**, and **exposed port/protocol**:

$$\text{seed} = \text{resource\_id} + \text{":"} + \text{nsg\_rule\_id} + \text{":"} + \text{protocol} + \text{":"} + \text{destination\_port}$$

$$\text{finding\_id} = \text{"F-UPE-"} + \text{SHA256}(\text{seed})[:12].\text{upper()}$$

### Deduplication Semantics:
* **Repeated Sweeps**: If a subsequent detection sweep evaluates the same exposed port on the same resource under the same rule, it yields the identical `finding_id`. PostgreSQL's `ON CONFLICT (finding_id) DO NOTHING` prevents duplicate inserts.
* **Port or Protocol Modifications**: If an existing exposed resource has an additional port opened (e.g. port 3389 added alongside port 22), a new distinct finding ID is generated and linked to the existing resource incident.

---

## 11. False Positives and Exclusions

Not all public exposure is unauthorized. The detector must accommodate legitimate public architectures:

### Legitimate Exposure Scenarios:
1. **Managed Edge Ingress**: Azure Application Gateway, Azure Front Door, or API Management deployed in designated perimeter subnets (`snet-edge`).
2. **Approved Public Services**: Public HTTPS (port 443) services explicitly architected for external users.
3. **Restricted Administrative Access**: Inbound NSG rules restricted to verified corporate IP ranges (e.g. corporate VPN egress CIDRs), rather than `0.0.0.0/0` or `Internet`.

### Future Allowlist Extension (Specification):
* A future milestone will support resource tagging (e.g., `cloudpulse-public-exposure: approved`) or a static configuration list of approved public endpoints.
* *Note: Do not implement allowlists or tag evaluators in the initial detector implementation.*

---

## 12. Detection vs. Incident Distinction

CloudPulse strictly separates detection from triage orchestration:

```
┌─────────────────────────────────┐
│  UNEXPECTED_PUBLIC_EXPOSURE     │
│  Detector                       │
└────────────────┬────────────────┘
                 │ Generates normalized Finding
                 ▼
┌─────────────────────────────────┐
│  Database Repository            │
│  (PostgreSQL: findings)         │
└────────────────┬────────────────┘
                 │ Passes Finding to Orchestrator
                 ▼
┌─────────────────────────────────┐
│  Incident Orchestrator          │
│  - Correlates by resource_id    │
│  - Creates/updates Incident     │
│  - Promotes severity            │
│  - Updates evidence timeline    │
└─────────────────────────────────┘
```

* **Detector Responsibility**: Pure evaluation of telemetry. Extracts network evidence, validates conditions, calculates confidence, and returns `Finding`.
* **Incident Orchestrator Responsibility**: Checks if an active incident already exists for `resource_id`. Links the finding to the incident, updates timeline with the exposure event, and escalates incident severity (e.g., upgrading from `MEDIUM` to `CRITICAL` if SSH exposure is added).

---

## 13. KQL and Query Feasibility Analysis

### What CAN Be Detected via KQL in `AzureActivity`:
Log Analytics can detect when NSG security rules or Public IP write operations occur:
```kql
AzureActivity
| where TimeGenerated >= ago(60m)
| where ActivityStatusValue in~ ("Success", "Succeeded") or ActivityStatus in~ ("Success", "Succeeded")
| where OperationNameValue has_any (
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
    "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE"
)
| project TimeGenerated, EventDataId, CorrelationId, OperationNameValue, 
          ActivityStatusValue, _ResourceId, ResourceGroup, Caller, Properties_d
```
* The `Properties_d` payload contains rule properties (e.g., `access: "Allow"`, `direction: "Inbound"`, `sourceAddressPrefix: "0.0.0.0/0"`, `destinationPortRange: "22"`).

### What CANNOT Be Detected via KQL Alone:
* `AzureActivity` **cannot** verify current effective network state.
* It cannot tell if an NSG is attached to a subnet or NIC.
* It cannot tell if a VM has an active public IP if the public IP was attached in an earlier session.

### Implementation Requirement for Siddu:
To achieve high-confidence detection without false positives:
1. **MVP Phase 2A (Event-Driven Trigger)**: Use KQL on `AzureActivity` to detect inbound allow rule creation on NSGs and Public IP bindings.
2. **MVP Phase 2B (State Verification)**: When an event is detected, query Azure Resource Graph (or Azure ARM API) to verify that the target resource currently has a Public IP and that the NSG is actively bound.

---

## 14. Implementation Notes for Siddu

### Checklist for Siddu:

1. **Telemetry & Client**:
   * Create `telemetry/resource_graph.py` (or extend `telemetry/log_analytics.py`) to query network exposure.
   * Add `azure-mgmt-resourcegraph>=8.0.0` to `requirements.txt` if using ARG SDK, or execute queries via ARM REST API with `DefaultAzureCredential`.
2. **Detector Module**:
   * Implement `detectors/unexpected_public_exposure.py` inheriting from `BaseDetector` interface.
   * Export `UnexpectedPublicExposureDetector` in `detectors/__init__.py`.
   * Detection ID constant: `UNEXPECTED_PUBLIC_EXPOSURE`.
3. **Model Compatibility**:
   * In [models/finding.py](../../services/detection-worker/models/finding.py), update the `validate_finding_type` field validator to accept both `"RESOURCE_CREATION"` and `"UNEXPECTED_PUBLIC_EXPOSURE"`.
   * Add `exposure_type`, `protocol`, `source_address_prefix`, `destination_port`, and `public_ip` fields to `EvidenceInfo` (all optional or default-null for backward compatibility with `RESOURCE_CREATION`).
4. **Deduplication**:
   * Implement deterministic finding ID helper:
     `generate_exposure_finding_id(resource_id, nsg_rule_id, protocol, destination_port)`.
5. **Incident Orchestrator**:
   * Ensure `IncidentOrchestrator.process_finding()` receives the finding and maps it cleanly to the canonical incident by `resource_id`.
6. **Automated Unit Tests**:
   * In `tests/test_unexpected_public_exposure.py`, test:
     1. Inbound allow on port 22 with `0.0.0.0/0` $\rightarrow$ `CRITICAL` finding.
     2. Inbound allow on port 3389 with `Internet` $\rightarrow$ `CRITICAL` finding.
     3. Inbound allow with private/restricted source CIDR $\rightarrow$ Ignored or `LOW`.
     4. Inbound deny rule $\rightarrow$ Ignored.
     5. Outbound rule with `0.0.0.0/0` $\rightarrow$ Ignored.
     6. Duplicate event execution $\rightarrow$ Deduplicated.
7. **Constraints**:
   * **No AI**: Severity and confidence must be 100% deterministic code rules.
   * **No Autonomous Remediation**: Do not modify Azure NSG rules.
   * **No Terraform Modifications**: Use existing infrastructure.
