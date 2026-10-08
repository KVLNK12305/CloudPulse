# CloudPulse Detection Specification — Suspicious Outbound Activity

## 1. Detection ID

`SUSPICIOUS_OUTBOUND_ACTIVITY`

---

## 2. Objective

The `SUSPICIOUS_OUTBOUND_ACTIVITY` detector identifies anomalous, high-risk, or unauthorized outbound network communication originating from Azure workloads.

### Purpose and Scope
Modern cloud workloads must communicate externally to function properly (e.g., retrieving OS updates, pulling container images, interacting with third-party APIs, and communicating with Azure platform services). **Outbound Internet connectivity is not inherently suspicious.**

This detector identifies **deviations from normal behavior**, **abnormal egress volumes**, and **communication with high-risk destinations or ports**, rather than general Internet access.

### Critical Distinction: Suspicious Signal vs. Confirmed Compromise
* **Suspicious Outbound Signal**: A statistically anomalous egress spike, connection to an uncommon port, or novel external communication from an internal workload. This warrants automated triage and security investigation.
* **Confirmed Compromise**: A verified intrusion requiring corroborating evidence (e.g., malicious process execution, lateral movement, or verified threat intelligence indicators). 

CloudPulse produces deterministic findings that serve as evidentiary building blocks for incident reconstruction, avoiding premature or unsubstantiated claims of compromise.

---

## 3. Threat Model

This detector addresses the primary outbound attack stages in cloud workload compromises:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Workload Compromise Lifecycle                          │
├───────────────────┬──────────────────────────────────┬──────────────────────────┤
│ Attack Phase      │ Observable Network Behavior      │ Telemetry Required       │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Command & Control │ Low-volume periodic beaconing,   │ Flow timestamps, dest IP,│
│ (C2)              │ non-standard ports (4444, 8888)  │ dest port, byte count    │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Staging / Payload │ Immediate outbound HTTP/raw TCP  │ Event timestamps, dest IP│
│ Retrieval         │ to unclassified external IP      │ correlated with workload │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Data Exfiltration │ Massive egress byte spike, high  │ Total bytes sent, session│
│                   │ transfer rate to novel external IP│ duration, flow volume    │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Cryptomining &    │ Persistent TCP connections to    │ Destination port, session│
│ Resource Abuse    │ Stratum mining ports (3333, 8333)│ persistence, flow count  │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Outbound Network  │ High destination IP diversity,   │ Unique dest IP count,    │
│ Scanning          │ high SYN packet / zero-byte response syn packet ratio       │
├───────────────────┼──────────────────────────────────┼──────────────────────────┤
│ Subnet Boundary   │ Workload in private/data subnet  │ Source subnet, dest IP,  │
│ Violation         │ initiating direct Internet egress│ flow direction           │
└───────────────────┴──────────────────────────────────┴──────────────────────────┘
```

---

## 4. Telemetry and Data Sources

To detect outbound anomalies, CloudPulse evaluates network flow records and resource state.

### A. Existing vs. Required Telemetry Matrix

| Telemetry Source | Azure Service / Table | Currently Ingested? | Network Flow Data Provided? | Status for CloudPulse |
|---|---|:---:|:---:|---|
| **Azure Activity Log** | `AzureActivity` in Log Analytics | **YES** | **NO** (Control-plane only: `write`/`delete`) | Available for lifecycle context, insufficient for flow detection. |
| **Azure Resource Graph** | `ResourceGraphClient` | **YES** | **NO** (Resource state & topology) | Available for subnet, NIC, and workload attribution. |
| **VNet / NSG Flow Logs (Traffic Analytics)** | `AzureNetworkAnalytics_CL` or storage | **NO** | **YES** (Flow-level tuples, bytes, packets) | **IMPLEMENTATION DEPENDENCY** (Required for real flow data). |
| **Azure Monitor Host Metrics** | `AzureMetrics` / VM Metrics | **NO** | **PARTIAL** (Aggregate bytes out, no dest IP/port) | Supplementary volume indicator only. |
| **Azure Firewall Logs** | `AZFWNetworkRule` | **NO** | **YES** (FQDN, IP, port, rule decision) | Optional (only applicable if Azure Firewall is deployed). |

### B. Feasibility Analysis of Azure Flow Telemetry
1. **Azure Activity Log alone cannot detect outbound flows**:
   `AzureActivity` only captures ARM control-plane operations (e.g. creating an NSG rule). It **never** captures runtime TCP/UDP connections.
2. **True Network Flow Telemetry Requires VNet / NSG Flow Logs**:
   * Azure Network Watcher supports NSG Flow Logs (v2) and VNet Flow Logs.
   * When exported to Log Analytics with **Traffic Analytics**, data is parsed into `AzureNetworkAnalytics_CL` with structured fields:
     * `SourceIP_s`, `DestIP_s`, `DestPort_d`, `L4Protocol_s`
     * `BytesSent_d`, `BytesReceived_d`, `PacketsSent_d`, `PacketsReceived_d`
     * `FlowDirection_s` (`O` for Outbound, `I` for Inbound)
     * `FlowStatus_s` (`A` for Allowed, `D` for Denied)
     * `TimeGenerated`, `VM_s`, `SrcSubnet_s`
3. **Implementation Requirement for Siddu**:
   * For production, Flow Logs must be enabled on `cloudpulse-vnet` subnets (`snet-worker`, `snet-data`, `snet-app`) exporting to `cloudpulse-law`.
   * For the detection worker, Siddu must implement a telemetry adapter that ingests normalized network flow records (either queried from `AzureNetworkAnalytics_CL` via KQL or supplied via test fixtures).

---

## 5. Detection Conditions

The detector evaluates outbound flows against deterministic rules organized into five categories:

### A. Destination Anomalies
* **Novel External Destination**: Outbound communication to an external public IPv4/IPv6 address that has not been observed for this resource or subnet during the baseline window ($\ge 7$ days).
* **Destination Diversity Spike**: An individual workload connects to $> 50$ distinct external IP addresses within a 15-minute window (where baseline is $\le 5$).
* **Periodic Beaconing**: Repeated outbound connections ($\ge 20$ sessions) to the same external IP at regular intervals ($\le 10\%$ timing variance) with low payload size ($< 5$ KB per flow).

### B. Port and Protocol Anomalies
* **Cryptomining & Abuse Ports**: Outbound connections to common mining pool ports:
  * `3333`, `4444`, `5555`, `6666`, `8333`, `14444`
* **Unusual External Management Egress**: Workload initiating outbound connections to remote management ports over the Internet:
  * SSH (`22`), RDP (`3389`), WinRM (`5985`, `5986`), Telnet (`23`)
* **Unencrypted Database Egress**: Outbound connections to public IPs on standard database ports:
  * PostgreSQL (`5432`), MySQL (`3306`), MSSQL (`1433`), MongoDB (`27017`), Redis (`6379`)

### C. Volume Anomalies
* **Egress Volume Spike**: Total outbound bytes transferred by a resource in the observation window (1 hour) exceeds the historical baseline by a factor of $5.0$ ($R_{\text{volume}} \ge 5.0$) AND total transferred bytes exceed $500\text{ MB}$.
* **Connection Count Spike**: Total outbound session count in the observation window exceeds the baseline by a factor of $10.0$ ($R_{\text{flows}} \ge 10.0$).

### D. Behavioral and Topology Anomalies
* **Subnet Role Violation**: Direct external Internet egress originating from a resource residing in a designated internal tier (e.g., `snet-data` or `snet-worker`) that should only communicate via private VNet endpoints or NAT gateways.
* **Asymmetric Scanning Pattern**: Workload generates $> 100$ outbound SYN packets with near-zero response bytes received, indicating external port scanning.

### E. Security-Context Signals
The detector inspects recent findings in PostgreSQL for the same `resource_id`:
* **Corroborating Context 1**: Resource was provisioned within the last 24 hours (`RESOURCE_CREATION`).
* **Corroborating Context 2**: Resource currently has an active public exposure finding (`UNEXPECTED_PUBLIC_EXPOSURE`).
* When present, security context boosts the confidence score and escalates severity.

---

## 6. Baseline and Anomaly Model (Deterministic MVP)

To identify anomalies without non-deterministic ML/AI, CloudPulse utilizes a statistical baseline window:

```
┌──────────────────────────────────────────────┐ ┌──────────────────────┐
│        Baseline Window: Rolling 7 Days       │ │ Observation: 1 Hour  │
│  - μ_bytes, σ_bytes (hourly egress)          │ │ - Observed Bytes     │
│  - Known Destination IP Set: D_known         │ │ - Observed Flows     │
│  - Distinct destination count distribution   │ │ - Current Dest IPs   │
└──────────────────────────────────────────────┘ └──────────────────────┘
```

### Mathematical Formulation
1. **Volume Ratio**:
   $$R_{\text{volume}} = \frac{\text{Observed\_Bytes}}{\max(\mu_{\text{baseline\_hourly\_bytes}}, 10\,\text{MB})}$$
2. **Deviation Trigger**:
   * If $R_{\text{volume}} \ge 5.0$ and $\text{Observed\_Bytes} \ge 500\text{ MB}$ $\longrightarrow$ **Volume Anomaly**
3. **Destination Novelty Trigger**:
   * If $\text{DestIP} \notin \mathcal{D}_{\text{known}}$ and $\text{DestIP}$ is a public non-Azure IP $\longrightarrow$ **Destination Anomaly**

### Cold-Start Behavior (Resource Age $< 24$ Hours or $< 10$ Historical Hours)
* **Volume Anomalies**: Quantitative volume ratio checks are suppressed to avoid false positives during initial application setup or software deployment.
* **Port & Subnet Violations**: Structural checks (mining ports, management ports, `snet-data` egress) **remain 100% active immediately**.
* **Confidence Capping**: Confidence is capped at a maximum of $0.70$ during cold-start periods.

---

## 7. Severity Model

Severity is assigned deterministically based on verified evidence:

| Severity | Deterministic Criteria | Example Scenario |
|---|---|---|
| **CRITICAL** | Outbound traffic to **Cryptomining Ports** (3333, 8333, etc.), **OR** massive exfiltration ($R_{\text{volume}} \ge 10.0$ and egress $> 5\text{ GB}$) to an unknown public destination, **OR** outbound anomaly from a resource with an active `UNEXPECTED_PUBLIC_EXPOSURE` finding. | VM exposed to the Internet suddenly begins egressing 10 GB to an unknown external IP over port 4444. |
| **HIGH** | Significant volume spike ($R_{\text{volume}} \ge 5.0$ and egress $> 1\text{ GB}$) to a novel external IP, **OR** direct Internet egress originating from a resource in `snet-data`, **OR** external scanning pattern ($> 50$ distinct IPs in 15 mins). | Database flexible server or worker in `snet-data` communicating directly with a public IP. |
| **MEDIUM** | Moderate volume deviation ($3.0 \le R_{\text{volume}} < 5.0$ with egress $> 250\text{ MB}$), **OR** outbound communication to remote management ports (22, 3389) over the Internet, **OR** previously unseen destination with repeated connections. | Worker VM opening an outbound SSH session to an external IP. |
| **LOW** | Minor volume deviation ($1.5 \le R_{\text{volume}} < 3.0$), **OR** isolated connection to an uncommon high port ($> 10000$) with minimal byte transfer ($< 1\text{ MB}$). | Workload communicating once with a new external IP over port 8443. |

---

## 8. Confidence Model

Confidence scores are calculated deterministically on a scale of $0.0$ to $1.0$ (no AI):

| Component | Condition | Confidence Weight |
|---|---|:---:|
| **Telemetry Fidelity** | Full bidirectional flow logs (`BytesSent` + `BytesReceived` + `DestPort`) | $+0.40$ |
| | Aggregate metrics only (no flow-level port/IP) | $+0.20$ |
| **Destination Evidence** | Destination IP verified novel against $\ge 7$-day baseline | $+0.20$ |
| **Port Risk** | Destination port matches known mining (3333, 8333) or C2 (4444) | $+0.20$ |
| **Corroborating Findings** | Resource has active `UNEXPECTED_PUBLIC_EXPOSURE` finding | $+0.15$ |
| | Resource has active `RESOURCE_CREATION` finding ($< 24\text{ h}$) | $+0.10$ |
| **Cold-Start Penalty** | Baseline history $< 24$ hours | $-0.20$ |

$$\text{Confidence} = \min(1.0, \max(0.1, \sum \text{Weights}))$$

---

## 9. Required Evidence

Each normalized finding must contain structured evidence adhering to the CloudPulse schema:

### Mandatory Fields
* **Resource Metadata**:
  * `resource.id`: Full Azure Resource ID of the initiating workload (e.g. VM or Container App).
  * `resource.type`: Azure resource type (e.g., `Microsoft.Compute/virtualMachines`).
  * `resource.name`: Workload resource name.
  * `resource.resource_group`: Resource group name.
* **Network Evidence (inside `evidence`)**:
  * `operation`: Identifier (e.g., `NETWORK_FLOW_TELEMETRY` or `TRAFFIC_ANALYTICS_EGRESS`).
  * `destination_ip`: Target external IP address.
  * `destination_port`: Destination port string or integer.
  * `protocol`: `TCP` or `UDP`.
  * `bytes_sent`: Total outbound bytes in observation window.
  * `bytes_received`: Total inbound bytes in observation window.
  * `flow_count`: Number of flow sessions observed.
  * `anomaly_type`: Specific trigger (`VOLUME_SPIKE`, `MINING_PORT`, `C2_BEACON`, `SCANNING`, `SUBNET_VIOLATION`).
* **Context**:
  * `timestamp`: ISO-8601 timestamp of observation.
  * `subscription_id`: Azure subscription ID.

### Optional Fields (Included when available)
* `evidence.source_ip`: Source private IP address.
* `evidence.nic_id`: Associated Network Interface ARM ID.
* `evidence.subnet_id`: Associated VNet subnet ID.
* `evidence.baseline_bytes`: Expected baseline hourly bytes.
* `evidence.deviation_ratio`: Calculated $R_{\text{volume}}$ ratio.
* `evidence.dest_ip_count`: Count of unique destination IPs (for scanning detection).
* `evidence.related_finding_ids`: List of supporting CloudPulse finding IDs (e.g. `["F-UPE-...", "F-RC-..."]`).

---

## 10. Finding Schema

Normalized JSON finding adhering to the CloudPulse Finding contract:

```json
{
  "finding_id": "F-SOA-8C21EA4F9B10",
  "finding_type": "SUSPICIOUS_OUTBOUND_ACTIVITY",
  "severity": "CRITICAL",
  "timestamp": "2026-10-08T14:15:00Z",
  "resource": {
    "id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    "type": "Microsoft.Compute/virtualMachines",
    "name": "vm-worker-01",
    "resource_group": "cloudpulse-rg"
  },
  "identity": {
    "principal_id": null,
    "principal_type": null,
    "caller": null
  },
  "evidence": {
    "operation": "NETWORK_FLOW_TELEMETRY",
    "activity_log_event_id": "flow-20261008-141500-vm-worker-01",
    "correlation_id": "corr-flow-9912",
    "subscription_id": "90b900ea-4273-4b40-a343-091aecfe2911",
    "source_ip": "10.50.3.4",
    "subnet_id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/virtualNetworks/cloudpulse-vnet/subnets/snet-worker",
    "destination_ip": "198.51.100.77",
    "destination_port": "3333",
    "protocol": "TCP",
    "bytes_sent": 1548291000,
    "bytes_received": 14200,
    "flow_count": 84,
    "anomaly_type": "MINING_PORT",
    "baseline_bytes": 12500000,
    "deviation_ratio": 123.86,
    "related_finding_ids": [
      "F-UPE-7A39B21C4D10"
    ]
  },
  "confidence": 0.95
}
```

---

## 11. Deduplication and Finding Identity

To prevent repeated detection runs from spawning unbounded finding records for ongoing long-lived connections:

### Deterministic Finding ID Formulation
The finding ID is generated by hashing the canonical tuple of **target resource**, **destination IP**, **destination port**, **anomaly type**, and a **time bucket** (e.g., 4-hour epoch window):

$$\text{time\_bucket} = \lfloor \text{epoch\_timestamp} / 14400 \rfloor$$

$$\text{seed} = \text{resource\_id} + \text{":"} + \text{destination\_ip} + \text{":"} + \text{destination\_port} + \text{":"} + \text{anomaly\_type} + \text{":"} + \text{time\_bucket}$$

$$\text{finding\_id} = \text{"F-SOA-"} + \text{SHA256}(\text{seed})[:12].\text{upper()}$$

### Deduplication Rules:
1. **Ongoing Session / Sweep**: Re-evaluating the same destination IP and port within the active 4-hour window yields the identical `finding_id`. PostgreSQL's `ON CONFLICT (finding_id) DO NOTHING` prevents redundant rows.
2. **Distinct Anomalies**: If the workload simultaneously connects to a new C2 IP or begins port scanning, a separate finding ID is generated.

---

## 12. False Positives and Exclusions

Legitimate cloud services generate significant outbound traffic that must not be flagged:

### Standard Approved Destinations:
* **Azure Platform & Management Services**:
  * Azure Storage endpoints (`*.blob.core.windows.net`)
  * Entra ID authentication (`login.microsoftonline.com`)
  * Azure Monitor / Log Analytics ingestion endpoints (`*.ods.opinsights.azure.com`)
  * Azure Container Registry (`*.azurecr.io`)
* **Package Repositories & Distributions**:
  * Ubuntu / Debian mirrors (`archive.ubuntu.com`, `security.ubuntu.com`)
  * Python Package Index (`pypi.org`, `files.pythonhosted.org`)
  * Node Package Manager (`registry.npmjs.org`)
* **Core Internet Infrastructure**:
  * Standard DNS servers (`168.63.129.16`, `1.1.1.1`, `8.8.8.8` on UDP port 53)
  * NTP synchronization (`pool.ntp.org` on UDP port 123)

### Future Allowlist Specification (Design Only):
* A future configuration mechanism (`approved_egress_destinations`) will support defining approved CIDRs, FQDNs, and ports per subnet. *(Do not implement in the initial detector).*

---

## 13. Detection vs. Incident Correlation Architecture

CloudPulse strictly isolates detector responsibilities from incident triage:

```
┌─────────────────────────────────┐
│  SUSPICIOUS_OUTBOUND_ACTIVITY   │
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
│  - Attaches to Incident INC-RC- │
│  - Escalates Incident Severity  │
│  - Appends to Timeline          │
└─────────────────────────────────┘
```

* **Detector**: Pure anomaly calculation and telemetry normalization. Produces `Finding`.
* **Incident Orchestrator**: Attaches the finding to the canonical incident for `resource_id`, updates the incident status, and elevates severity if an attack sequence is unfolding.

---

## 14. Security Kill-Chain Correlation (Multi-Detector Hooks)

The primary power of CloudPulse is correlating independent detectors into a unified incident timeline:

```
  [RESOURCE_CREATION]             [UNEXPECTED_PUBLIC_EXPOSURE]          [SUSPICIOUS_OUTBOUND_ACTIVITY]
   New VM created in                Inbound rule 0.0.0.0/0                Workload connects to
   snet-worker (MEDIUM)             allows port 22 (HIGH)                 mining pool port 3333 (CRITICAL)
          │                                      │                                      │
          └──────────────────────────────────────┼──────────────────────────────────────┘
                                                 │
                                                 ▼
                           ┌───────────────────────────────────────────┐
                           │      Unified CloudPulse Incident          │
                           │      INC-RC-7A1B2C3D4E (CRITICAL)         │
                           ├───────────────────────────────────────────┤
                           │ Timeline:                                 │
                           │ 1. 10:00 - RESOURCE_CREATION              │
                           │ 2. 10:15 - UNEXPECTED_PUBLIC_EXPOSURE     │
                           │ 3. 10:45 - SUSPICIOUS_OUTBOUND_ACTIVITY   │
                           └───────────────────────────────────────────┘
```

### Correlation Hooks:
The finding includes `related_finding_ids` linking to prior findings for the same `resource_id`, allowing the Incident Orchestrator to reconstruct the exact attack progression.

---

## 15. FinOps Correlation: Security-Driven Financial Impact

A fundamental core differentiator of CloudPulse is bridging **Threat Surface Triage** with **Cloud FinOps**:

### The Problem
Data exfiltration and unauthorized compute abuse (such as cryptomining or DDoS participation) directly drive cloud infrastructure costs:
* **Azure Network Egress Charges**: Outbound data transfer to the public Internet incurs per-GB bandwidth billing.
* A security breach exfiltrating 10 TB of database records generates hundreds of dollars in unexpected egress costs on the Azure invoice.

### Preserved FinOps Evidence
The detector preserves quantitative egress telemetry in `EvidenceInfo`:
* `bytes_sent`: Exact raw byte volume.
* `egress_gb`: Calculated as $\text{bytes\_sent} / (1024^3)$.
* `time_window`: Duration of anomalous egress.
* `destination_ip`: External routing target.

### Future FinOps Engine Integration (Specification Hook):
In later milestones, the FinOps Correlation engine will compute:
$$\text{Estimated Financial Impact (\$) } = \text{egress\_gb} \times \text{Azure\_Egress\_Rate\_Per\_GB}$$
This populates the `cost_impact` field in `Incident`, allowing security and FinOps teams to triage both the security threat and the financial loss simultaneously.

---

## 16. KQL and Query Feasibility Analysis

### A. What Can Be Queried Today in Log Analytics (`cloudpulse-law`)
* **Control-plane events in `AzureActivity`**: Can identify when network security rules or route tables are modified, but **cannot** query data-plane outbound packets.

### B. What Requires NSG / VNet Flow Logs with Traffic Analytics
* If NSG Flow Logs (v2) or VNet Flow Logs are enabled on `cloudpulse-vnet` and sent to Log Analytics, the `AzureNetworkAnalytics_CL` table provides:
```kql
AzureNetworkAnalytics_CL
| where FlowDirection_s == "O" and FlowStatus_s == "A"
| where TimeGenerated >= ago(1h)
| where DestPublicIPs_s != "" and DestPublicIPs_s != "-"
| project
    TimeGenerated,
    VM_s,
    SrcSubnet_s,
    SourceIP_s,
    DestIP_s = DestPublicIPs_s,
    DestPort_d,
    L4Protocol_s,
    BytesSent_d,
    BytesReceived_d,
    PacketsSent_d
| summarize
    TotalBytesSent = sum(BytesSent_d),
    TotalBytesReceived = sum(BytesReceived_d),
    FlowCount = count()
    by VM_s, SrcSubnet_s, DestIP_s, DestPort_d, L4Protocol_s
| order by TotalBytesSent desc
```

### C. Implementation Reality for Siddu
* Siddu **must not fabricate KQL against tables that do not exist** in `cloudpulse-law`.
* Until VNet Flow Logs are deployed to Azure in a future infrastructure phase, Siddu's implementation should support:
  1. A `NetworkFlowEvent` ingestion schema.
  2. Integration with `AzureNetworkAnalytics_CL` when configured.
  3. A robust mock/replay fixture for testing outbound flow anomalies without requiring live flow log infrastructure.

---

## 17. Implementation Notes for Siddu

### Step-by-Step Checklist for Siddu:

1. **Model Extension in [models/finding.py](../../services/detection-worker/models/finding.py)**:
   * Update `validate_finding_type` field validator to accept `"SUSPICIOUS_OUTBOUND_ACTIVITY"`.
   * Add network flow fields to `EvidenceInfo` (optional/default-null):
     * `destination_ip: Optional[str]`
     * `destination_port: Optional[str]`
     * `bytes_sent: Optional[int]`
     * `bytes_received: Optional[int]`
     * `flow_count: Optional[int]`
     * `anomaly_type: Optional[str]`
     * `baseline_bytes: Optional[int]`
     * `deviation_ratio: Optional[float]`
     * `related_finding_ids: Optional[List[str]]`
   * Implement deterministic finding ID helper:
     `generate_outbound_finding_id(resource_id, dest_ip, dest_port, anomaly_type, time_bucket)`.

2. **Detector Module**:
   * Implement `detectors/suspicious_outbound_activity.py`.
   * Export `SuspiciousOutboundActivityDetector` in `detectors/__init__.py`.
   * Detection ID constant: `SUSPICIOUS_OUTBOUND_ACTIVITY`.

3. **Baseline Store / Mock Interface**:
   * Create an in-memory or database baseline cache interface to look up historical average bytes per workload.

4. **Incident Orchestrator Integration**:
   * In [services/incident_orchestrator.py](../../services/detection-worker/services/incident_orchestrator.py), add timeline event label:
     `"SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED"`.
   * Ensure correlation by canonical `resource_id` attaches the finding to the existing resource incident and escalates incident severity to `CRITICAL` when paired with an existing `UNEXPECTED_PUBLIC_EXPOSURE` finding.

5. **API & Service Integration**:
   * In [services/detection_service.py](../../services/detection-worker/services/detection_service.py), add endpoint or pipeline handler:
     `POST /detect/suspicious-outbound`.

6. **Automated Unit Tests**:
   * Create `tests/test_suspicious_outbound_activity.py` testing:
     1. Outbound connection to cryptomining port 3333 $\longrightarrow$ `CRITICAL`.
     2. Significant egress spike ($R_{\text{volume}} \ge 5.0$) to novel destination $\longrightarrow$ `HIGH`.
     3. Destination IP diversity spike ($> 50$ distinct IPs) $\longrightarrow$ `HIGH`.
     4. Cold-start suppression (new workload with $< 10$ records suppresses false volume spikes).
     5. Duplicate finding within same 4-hour window $\longrightarrow$ Deduplicated.
     6. Multi-detector incident escalation: combining with existing UPE finding promotes Incident to `CRITICAL`.

7. **Strict Implementation Constraints**:
   * **No ML/AI**: All anomaly ratios and confidence scores must use deterministic code rules.
   * **No Remediation**: Do not modify Azure firewall or NSG rules.
   * **No Terraform Modifications**: Use existing infrastructure.
