# CloudPulse AI Specification — Autonomous Incident Triage Contract

## 1. Specification ID & Overview

* **Document ID**: `AI_INCIDENT_TRIAGE_CONTRACT`
* **Target Consumers**: AI Triage Service (`services.ai_triage_service`), API Layer (`app.py`), Dashboard Application
* **Target Service**: `services/detection-worker`
* **Status**: Authoritative Architectural Contract for the CloudPulse AI Layer

---

## 2. Core Architectural Principles & Invariants

CloudPulse maintains a strict separation across three intelligence layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CLOUDPULSE THREE-TIER INTELLIGENCE                     │
├──────────────────────────┬──────────────────────────────────────────────────┤
│ Layer                    │ Architectural Purpose                            │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ 1. Detection Layer       │ "What happened?"                                 │
│    (Deterministic)       │ Emits immutable, mathematically proven Findings. │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ 2. Correlation Layer     │ "Are these findings related?"                    │
│    (Deterministic)       │ Evaluates 5-dimension matrix, escalates severity.│
├──────────────────────────┼──────────────────────────────────────────────────┤
│ 3. AI Triage Layer       │ "What does this mean & what should an operator   │
│    (Interpretive Only)   │  consider doing?" Synthesizes narrative & triage.│
└──────────────────────────┴──────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Fundamental Invariant: AI is Interpretive, NOT the Source of Truth.**
> AI must **never** become the source of truth for detection or telemetry.
> The following elements are strictly deterministic and immutable:
> - Finding existence, finding types, and finding IDs
> - Underlying telemetry records and raw event evidence
> - Deterministic detector confidence and severity ratings
> - Financial figures from Azure Cost Management
> - Resource identity, ARM IDs, and caller identity
> - Chronological timeline events

### Categorical Tripartition: Facts vs Inference vs Recommendation
To eliminate hallucination risk and prevent alert degradation, the AI layer strictly enforces three non-overlapping categories:

1. **FACTS**: Directly verifiable from the supplied telemetry, findings, and correlation records (e.g., *"workload transferred 15.2 GB to destination IP 198.51.100.77 on port 443"*).
2. **INFERENCES**: Contextual deduction and reasonable interpretation of those facts (e.g., *"the high volume of egress coinciding with port 443 could indicate data staging or potential exfiltration"*). Inferences must explicitly state what is known and what remains unverified.
3. **RECOMMENDATIONS**: Reversible, controlled actions an operator or incident responder should consider evaluating (e.g., *"inspect process-level network connections on VM-01 to identify the PID initiating connections to 198.51.100.77"*).

---

## 3. Input Contract: AI-Safe Incident Context

The AI engine accepts an `AISafeIncidentContext` object. Internal database state, raw tokens, connection strings, and unrelated system configurations are explicitly pruned before reaching the AI model.

### Input Schema Definition

```json
{
  "incident_id": "INC-RC-3B91C80F2A",
  "title": "Correlated Incident: vm-worker-01 - Outbound Traffic Spike with Azure Network Egress Surge",
  "severity": "CRITICAL",
  "status": "OPEN",
  "created_at": "2026-10-07T14:20:00Z",
  "updated_at": "2026-10-08T02:00:00Z",
  "resource": {
    "id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    "type": "Microsoft.Compute/virtualMachines",
    "name": "vm-worker-01",
    "resource_group": "cloudpulse-rg",
    "subscription_id": "90b900ea-4273-4b40-a343-091aecfe2911"
  },
  "identity": {
    "caller": "admin@cloudpulse.io",
    "principal_id": "usr-001",
    "principal_type": "User"
  },
  "cost_impact": {
    "correlation_strength": "VERY_STRONG",
    "correlation_confidence": 0.90,
    "correlation_type": "EGRESS_SPIKE_COST_SURGE",
    "cost_category": "Network/Egress",
    "actual_cost": 185.50,
    "baseline_cost": 12.00,
    "deviation_absolute": 173.50,
    "percentage_increase": 1445.83,
    "currency": "USD",
    "evaluation_date": "2026-10-07"
  },
  "findings": [
    {
      "finding_id": "F-SOA-9B3E12D4FA01",
      "finding_type": "SUSPICIOUS_OUTBOUND_ACTIVITY",
      "severity": "HIGH",
      "confidence": 0.95,
      "timestamp": "2026-10-07T14:15:00Z",
      "key_evidence": {
        "destination_ip": "198.51.100.77",
        "destination_port": "443",
        "bytes_sent": 15200000000,
        "anomaly_type": "VOLUME_SPIKE",
        "deviation_ratio": 12.4
      }
    },
    {
      "finding_id": "F-COST-4A82F109C4B2",
      "finding_type": "COST_ANOMALY",
      "severity": "HIGH",
      "confidence": 0.90,
      "timestamp": "2026-10-08T01:30:00Z",
      "key_evidence": {
        "cost_category": "Network/Egress",
        "actual_cost": 185.50,
        "baseline_cost": 12.00,
        "deviation_absolute": 173.50,
        "percentage_increase": 1445.83,
        "evaluation_date": "2026-10-07"
      }
    }
  ],
  "timeline": [
    {
      "timestamp": "2026-10-07T14:15:00Z",
      "event": "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED",
      "finding_id": "F-SOA-9B3E12D4FA01"
    },
    {
      "timestamp": "2026-10-08T01:30:00Z",
      "event": "COST_ANOMALY_DETECTED",
      "finding_id": "F-COST-4A82F109C4B2"
    },
    {
      "timestamp": "2026-10-08T02:00:00Z",
      "event": "SECURITY_FINOPS_CORRELATED",
      "reason": "Egress volume spike of 15.2 GB coincided with Azure billing network egress surge of +$173.50."
    }
  ]
}
```

---

## 4. Output Contract: Structured AI Analysis

The AI response must strictly conform to the following JSON schema. No freeform non-JSON commentary is accepted.

### Output JSON Schema

```json
{
  "summary": "Executive overview of the incident synthesizing security observations and financial concurrence.",
  "risk_assessment": "Operational risk classification and immediate threat posture.",
  "likely_scenario": "Inference of probable workload activity based strictly on available evidence.",
  "security_impact": "Analysis of the control-plane and data-plane security posture.",
  "financial_impact": "Quantitative analysis of billed overrun and projected cost trajectory.",
  "facts": [
    "List of verified factual assertions directly supported by telemetry."
  ],
  "inferences": [
    "List of reasonable interpretations explaining the facts, noting uncertainties."
  ],
  "key_evidence": [
    {
      "source": "SUSPICIOUS_OUTBOUND_ACTIVITY",
      "finding_id": "F-SOA-9B3E12D4FA01",
      "observation": "15.2 GB transferred to 198.51.100.77 on TCP 443"
    },
    {
      "source": "COST_ANOMALY",
      "finding_id": "F-COST-4A82F109C4B2",
      "observation": "+$173.50 billed overrun (+1446% vs $12.00 baseline) on Network/Egress"
    }
  ],
  "recommended_actions": [
    {
      "id": "ACT-01",
      "title": "Inspect Workload Network Sockets",
      "description": "Examine active processes on vm-worker-01 connected to remote IP 198.51.100.77.",
      "category": "INVESTIGATION",
      "risk": "NONE",
      "requires_human_approval": true
    },
    {
      "id": "ACT-02",
      "title": "Apply NSG Egress Restriction",
      "description": "Block outbound traffic to 198.51.100.77 on NSG nsg-worker pending verification.",
      "category": "CONTAINMENT",
      "risk": "MEDIUM",
      "requires_human_approval": true
    }
  ],
  "confidence": 0.88,
  "limitations": [
    "Payload contents of outbound traffic were not captured in flow telemetry; data classification cannot be confirmed.",
    "Process-level command line and executable attribution require host-level Agent diagnostics."
  ],
  "triage_timestamp": "2026-10-08T02:05:00Z",
  "model_identifier": "gpt-4.1-mini"
}
```

---

## 5. Security & Safety Constraints

1. **Zero Write Permissions**: The AI service principal has `Cognitive Services OpenAI User` role scoped specifically to the Azure OpenAI account and **zero** resource write/modify permissions.
2. **Untrusted Interpreter Model**: All AI output is treated by the system as untrusted advisory text.
3. **No Direct Execution**: Model recommendations **never** become executable shell or Azure CLI commands automatically.
4. **Human-in-the-Loop Gateway**: Any proposed containment action requires explicit human review and authorization before being handed to future remediation workers.
5. **No Hallucinated Telemetry**: The AI must explicitly declare missing information in the `limitations` section rather than speculating.
6. **Data Processing & Region Residency (GlobalStandard SKU)**: The `cloudpulse-triage` deployment utilizes the `GlobalStandard` SKU with `gpt-4.1-mini`. Prompts may be routed and processed dynamically across any Azure data center region based on global capacity. Strictly sanitized context (`AISafeIncidentContext`) is transmitted; raw secrets, customer network payload contents, and credentials are never sent to the model.

---

## 6. Graceful Degradation & Failure Handling

If the Azure AI service is unavailable (HTTP 401, 429, 500, timeout, or invalid JSON schema):
- The underlying `Incident` remains completely functional and valid.
- The `incident.ai_analysis` status is recorded as `UNAVAILABLE` or `ERROR` with a descriptive message.
- The UI renders an informative fallback badge: `"AI Triage Unavailable — Deterministic Telemetry Unaffected"`.
- Incident retrieval, finding queries, and correlation status never fail due to AI service disruption.
