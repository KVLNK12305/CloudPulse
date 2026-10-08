# CloudPulse: Real-Life Data Reference & Demo Presentation Playbook

This guide contains everything needed to deliver a world-class, 3-to-5 minute live demonstration of **CloudPulse**, complete with real-life data scenarios, the operational narrative, click-by-click instructions, and executive talking points.

---

## 1. Real-Life Datasets in CloudPulse

CloudPulse includes two complementary, high-fidelity datasets:

### Scenario A: The Multi-Stage Breach & FinOps Surge (`vm-worker-01`)
*Available directly in the local running application at `http://127.0.0.1:8080/dashboard`.*

This scenario models an actual modern cloud breach pattern: an attacker gains initial access, opens an administrative ingress backdoor, stages and exfiltrates proprietary data, and leaves behind an immediate bandwidth billing overrun.

| Dimension | Telemetry Source | Real-Life Data Point | CloudPulse Finding |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Azure Activity Log | Operation: `MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE`<br>Target: `vm-worker-01`<br>Caller: `admin@cloudpulse.io`<br>IP: `198.51.100.10` | `F-RC-EE4021A53016`<br>*(Resource Creation)* |
| **Perimeter Exposure** | Azure Resource Graph & NSG Rules | Rule: `Allow-SSH-Internet`<br>Port: `22` (TCP)<br>Access: `Allow`<br>Source: `0.0.0.0/0`<br>Public IP: `20.198.51.10` | `F-UPE-B8490C119B30`<br>*(Unexpected Public Exposure: MANAGEMENT_PORT)* |
| **Data Exfiltration** | Azure VNet Flow Logs | Destination: `198.51.100.77:443`<br>Egress Volume: **16.5 GB** (Baseline: 50 MB/hr)<br>Flow Status: Active/Outbound | `F-SOA-EA4F7E149F66` (Volume Spike)<br>`F-SOA-75C2DD26F109` (Novel IP) |
| **FinOps Spike** | Azure Cost Management API | Category: `Network/Egress`<br>Current: **$195.40** (Baseline: $14.20)<br>Deviation: **+$181.20 (+1276%)** | `F-COST-00110E703BAC`<br>*(Cost Anomaly)* |
| **Correlated Incident** | 5-Dimension Correlation Matrix | Incident: `INC-RC-E348322B23`<br>Severity: **CRITICAL**<br>Timeline: 5 synchronized lifecycle events | Unified Incident Card |

---

### Scenario B: Live Azure E2E Controlled Remediation Proof (`cloudpulse-e2e-vm`)
*Documented proof of live Azure ARM execution in [`docs/demo/live-e2e.md`](live-e2e.md).*

This dataset proves that CloudPulse does not just simulate remediation—it executed live against Microsoft Azure infrastructure under strict least-privilege RBAC:
* **Subscription**: `/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911` (`cloudpulse-rg`, `centralindia`)
* **Real Public IP**: `20.219.4.13`
* **Real Target NSG**: `cloudpulse-e2e-nsg`, rule `Allow-SSH-Internet` (Port 22, `0.0.0.0/0`)
* **Finding ID**: `F-UPE-2D981ABC2B12`
* **Incident ID**: `INC-RC-95E60E379A`
* **AI Action**: `ACT-01` (*"Narrow Source IP Ranges"*, Risk: Low)
* **Remediation**: `REM-5EC0397F5981` (`DISABLE_PUBLIC_INGRESS`)
* **Live Concurrency**: ETag `W/"c7263ae2-36e4-49ca-ab56-2ac91f3f1ccf"`
* **Live Azure Mutation**: `Allow` → `Deny` with HTTP `If-Match` headers verified against ARM.
* **Live Rollback**: `Deny` → `Allow` verified, followed by complete resource cleanup.

---

## 2. Quick Setup & How to Reset/Seed Data

### Option 1: One-Click in Web Dashboard (Recommended for Live Demos)
1. Ensure the application is running:
   ```bash
   PYTHONPATH=services/detection-worker services/detection-worker/.venv/bin/python services/detection-worker/app.py
   ```
2. Open **`http://127.0.0.1:8080/dashboard`** in your browser.
3. Click the **⚡ Seed Test Scenario** button in the top navigation bar.
4. The system ingests all 4 kill-chain stages, triggers AI triage, and displays the incident.

### Option 2: CLI Seeder Script
In your terminal, simply execute:
```bash
python scripts/seed_demo_scenario.py
```
This script validates server health, ingests the 4 stages with realistic timestamps, invokes AI triage, and prints a formatted summary of the findings and recommended actions.

---

## 3. The 3-to-5 Minute Demo Script (What to Say & Do)

### ACT 1: The Problem Hook (45 Seconds)
> *"In modern cloud environments, security teams and finance teams live in complete silos. When an attacker compromises a cloud VM and starts exfiltrating terabytes of customer data, SecOps sees an alert about an open port, while FinOps doesn't discover the resulting bandwidth bill until 30 days later when the invoice arrives.*
>
> *CloudPulse solves this by unifying **SecOps threat surface detection** with **FinOps cost anomaly correlation**, pairing deterministic detection with **safe, advisory AI triage** and **human-approved controlled remediation**."*

**Action**: Open `http://127.0.0.1:8080/dashboard` on screen.

---

### ACT 2: Telemetry Ingestion & Real-Time Correlation (60 Seconds)
> *"Let's look at an active incident. We'll simulate a multi-vector attack fixture where a developer or compromised credential spins up a worker VM in Azure."*

**Action**: Click the **⚡ Seed Test Scenario** button (or show the existing card `INC-RC-E348322B23`).
**What to point to**:
1. Point to **`INC-RC-E348322B23`** in the incident list.
2. Note the **CRITICAL** severity badge and target resource: `vm-worker-01`.
3. Highlight the **Correlated Findings**:
   * **Resource Creation**: VM created by `admin@cloudpulse.io`.
   * **Unexpected Public Exposure**: Port 22 SSH exposed to `0.0.0.0/0` via rule `Allow-SSH-Internet`.
   * **Suspicious Outbound Activity**: 16.5 GB of egress data transferred to untrusted IP `198.51.100.77:443`.
   * **FinOps Cost Overrun**: An immediate **+$181.20 (+1276%)** network egress surge.
4. Emphasize:
   > *"Notice that CloudPulse didn't create four separate noisy tickets. Our concurrence engine correlated these disparate signals into a single actionable incident."*

---

### ACT 3: Advisory AI Triage & The Safety Boundary (45 Seconds)
**Action**: Click the **AI Triage** tab or scroll to the AI analysis panel.
**What to point to**:
1. Point to the **AI Summary**:
   > *"Multi-stage workload compromise pattern on vm-worker-01: Internet exposure coincided with high-volume outbound data transfer and an unexpected Azure billing surge."*
2. Point to the **Advisory Actions**:
   * `[ACT-01] Restrict Inbound NSG Exposure` (Category: `CONTAINMENT`, Risk: `MEDIUM`, Approval: `Required`)
   * `[ACT-02] Block Malicious Destination Egress` (Category: `CONTAINMENT`, Risk: `LOW`, Approval: `Required`)
   * `[ACT-03] Inspect Workload Sockets and Processes` (Category: `INVESTIGATION`, Risk: `NONE`, Approval: `Required`)
3. Emphasize the **Architectural Guardrail**:
   > *"Crucially, CloudPulse treats LLMs as **strictly advisory**. The AI cannot execute arbitrary shell scripts, cannot mutate Azure directly, and cannot bypass approval gates. It outputs strict JSON according to a typed Pydantic schema."*

---

### ACT 4: Human-in-the-Loop Approval & Controlled Remediation (60 Seconds)
**Action**: Point to the **Approve Action** button or show the approval state in the timeline.
**What to point to**:
1. Show the **Approval Invariant**:
   * Operator clicks "Approve" for `ACT-01`.
   * Explain:
     > *"Even after approval, CloudPulse does NOT automatically mutate the network. Approval records intent. Remediation execution remains an explicit, auditable step."*
2. Explain the **Azure ARM Remediation Engine**:
   * CloudPulse operates under **least-privilege RBAC** (Custom role `CloudPulse-Remediation-Operator`—it cannot delete VMs or read databases).
   * It enforces **Optimistic Concurrency via HTTP If-Match ETags**:
     > *"If an engineer is modifying the firewall rule in the Azure Portal at the same second CloudPulse attempts remediation, CloudPulse detects the ETag conflict (HTTP 412/409) and safely aborts rather than blindly overwriting manual work."*
3. Point to the verified live Azure test:
   * Refer to [`docs/demo/live-e2e.md`](live-e2e.md), where CloudPulse mutated `cloudpulse-e2e-nsg` from `Allow` to `Deny`, performed a live read-back verification, and verified complete rollback.

---

### ACT 5: Summary & Key Takeaways (30 Seconds)
> *"To summarize what you've seen today:*
> 1. *Deterministic detection of public cloud exposure across NSGs, NICs, and Public IPs.*
> 2. *Automated cross-domain correlation between cyber threats and FinOps billing spikes.*
> 3. *Advisory AI triage that contextualizes the kill-chain without safety risks.*
> 4. *ETag-protected, least-privilege remediation with full human governance.*
> *250 out of 250 unit, integration, and E2E tests are passing."*

---

## 4. Anticipated Questions & Answers (Q&A Defense)

| Question | Strongest Answer |
| :--- | :--- |
| **"What if the AI hallucinates a non-existent remediation?"** | The AI has zero authority to execute changes. Its output is parsed strictly into advisory actions. The remediation service only executes registered deterministic handlers (`DISABLE_PUBLIC_INGRESS`) mapped against validated Azure resources. |
| **"How do you prevent breaking production during remediation?"** | Every ARM write includes an `If-Match: <etag>` header. If the rule changed since triage, the operation aborts with a 412 Precondition Failed. Furthermore, remediation requires explicit human approval and automatically records pre-change rollback state. |
| **"What Azure permissions does CloudPulse need?"** | Only least privilege. We tested and verified with `CloudPulse-Remediation-Operator`, which only grants read/write on NSG security rules within the target resource group. It has zero Contributor, Owner, or Compute permissions. |
| **"How fast does the correlation run?"** | The correlation engine runs in-memory using an optimized 5-dimension concurrence matrix; our test suite of 250 tests completes in approximately 3 seconds. |
