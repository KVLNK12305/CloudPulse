import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator

from .finding import Finding, SeverityLevel
from .incident import Incident, IncidentStatus


class AISafeResourceContext(BaseModel):
    id: str
    type: str
    name: str
    resource_group: str
    subscription_id: Optional[str] = None


class AISafeIdentityContext(BaseModel):
    caller: Optional[str] = None
    principal_id: Optional[str] = None
    principal_type: Optional[str] = None


class AISafeCostImpact(BaseModel):
    correlation_strength: str
    correlation_confidence: float
    correlation_type: str
    cost_category: str
    actual_cost: float
    baseline_cost: float
    deviation_absolute: float
    percentage_increase: float
    currency: str = "USD"
    evaluation_date: Optional[str] = None


class AISafeFindingContext(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    confidence: float
    timestamp: str
    key_evidence: Dict[str, Any] = Field(default_factory=dict)


class AISafeTimelineEntry(BaseModel):
    timestamp: str
    event: str
    finding_id: Optional[str] = None
    operation: Optional[str] = None
    caller: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AISafeIncidentContext(BaseModel):
    """
    Sanitized, normalized incident context object for AI evaluation.
    Prunes internal connection strings, credentials, and raw database identifiers.
    """
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: str
    updated_at: str
    resource: AISafeResourceContext
    identity: Optional[AISafeIdentityContext] = None
    cost_impact: Optional[AISafeCostImpact] = None
    findings: List[AISafeFindingContext] = Field(default_factory=list)
    timeline: List[AISafeTimelineEntry] = Field(default_factory=list)

    @classmethod
    def from_incident(
        cls,
        incident: Incident,
        findings_map: Optional[Dict[str, Finding]] = None,
    ) -> "AISafeIncidentContext":
        # Extract subscription from resource id if available
        sub_id = None
        sub_match = re.search(r"/subscriptions/([^/]+)", incident.resource.id, re.IGNORECASE)
        if sub_match:
            sub_id = sub_match.group(1)

        res_ctx = AISafeResourceContext(
            id=incident.resource.id,
            type=incident.resource.type,
            name=incident.resource.name,
            resource_group=incident.resource.resource_group,
            subscription_id=sub_id,
        )

        id_ctx = None
        if incident.identity:
            id_ctx = AISafeIdentityContext(
                caller=incident.identity.caller,
                principal_id=incident.identity.principal_id,
                principal_type=incident.identity.principal_type,
            )

        cost_impact_ctx = None
        if incident.cost_impact and isinstance(incident.cost_impact, dict):
            cost_impact_ctx = AISafeCostImpact(
                correlation_strength=str(incident.cost_impact.get("correlation_strength", "NONE")),
                correlation_confidence=float(incident.cost_impact.get("correlation_confidence", 0.0)),
                correlation_type=str(incident.cost_impact.get("correlation_type", "UNKNOWN")),
                cost_category=str(incident.cost_impact.get("cost_category", "Unknown")),
                actual_cost=float(incident.cost_impact.get("actual_cost", 0.0)),
                baseline_cost=float(incident.cost_impact.get("baseline_cost", 0.0)),
                deviation_absolute=float(incident.cost_impact.get("deviation_absolute", 0.0)),
                percentage_increase=float(incident.cost_impact.get("percentage_increase", 0.0)),
                currency=str(incident.cost_impact.get("currency", "USD")),
                evaluation_date=incident.cost_impact.get("evaluation_date"),
            )

        safe_findings: List[AISafeFindingContext] = []
        if findings_map:
            for fid in incident.findings:
                finding = findings_map.get(fid)
                if not finding:
                    continue

                # Filter safe evidence fields per finding type
                ev = finding.evidence
                clean_evidence: Dict[str, Any] = {}
                if finding.finding_type == "RESOURCE_CREATION":
                    clean_evidence = {
                        "operation": ev.operation,
                        "activity_log_event_id": ev.activity_log_event_id,
                        "caller_ip": ev.caller_ip,
                    }
                elif finding.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
                    clean_evidence = {
                        "exposure_type": ev.exposure_type,
                        "destination_port": ev.destination_port,
                        "protocol": ev.protocol,
                        "source_address_prefix": ev.source_address_prefix,
                        "public_ip": ev.public_ip,
                        "nsg_rule_name": ev.nsg_rule_name,
                    }
                elif finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
                    clean_evidence = {
                        "destination_ip": ev.destination_ip,
                        "destination_port": ev.destination_port,
                        "bytes_sent": ev.bytes_sent,
                        "bytes_received": ev.bytes_received,
                        "anomaly_type": ev.anomaly_type,
                        "deviation_ratio": ev.deviation_ratio,
                        "flow_count": ev.flow_count,
                    }
                elif finding.finding_type == "COST_ANOMALY":
                    clean_evidence = {
                        "actual_cost": ev.actual_cost,
                        "baseline_cost": ev.baseline_cost,
                        "deviation_absolute": ev.deviation_absolute,
                        "percentage_increase": ev.percentage_increase,
                        "cost_category": ev.cost_category,
                        "evaluation_date": ev.evaluation_date,
                        "sample_days": ev.sample_days,
                        "is_cold_start": ev.is_cold_start,
                    }

                # Strip None values
                clean_evidence = {k: v for k, v in clean_evidence.items() if v is not None}

                safe_findings.append(
                    AISafeFindingContext(
                        finding_id=finding.finding_id,
                        finding_type=finding.finding_type,
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        timestamp=finding.timestamp,
                        key_evidence=clean_evidence,
                    )
                )

        safe_timeline: List[AISafeTimelineEntry] = []
        for entry in incident.timeline:
            safe_timeline.append(
                AISafeTimelineEntry(
                    timestamp=str(entry.get("timestamp", "")),
                    event=str(entry.get("event", "")),
                    finding_id=entry.get("finding_id"),
                    operation=entry.get("operation"),
                    caller=entry.get("caller"),
                    details=entry.get("correlation_metadata"),
                )
            )

        return cls(
            incident_id=incident.incident_id,
            title=incident.title,
            severity=incident.severity.value,
            status=incident.status.value,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            resource=res_ctx,
            identity=id_ctx,
            cost_impact=cost_impact_ctx,
            findings=safe_findings,
            timeline=safe_timeline,
        )


class ActionCategory(str, Enum):
    INVESTIGATION = "INVESTIGATION"
    CONTAINMENT = "CONTAINMENT"
    MONITORING = "MONITORING"
    OPTIMIZATION = "OPTIMIZATION"


class ActionRiskLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AIRecommendedAction(BaseModel):
    id: str = Field(..., description="Action identifier, e.g. ACT-01")
    title: str = Field(..., description="Concise action title")
    description: str = Field(..., description="Detailed reversible action guidance")
    category: ActionCategory = Field(default=ActionCategory.INVESTIGATION)
    risk: ActionRiskLevel = Field(default=ActionRiskLevel.LOW)
    requires_human_approval: bool = Field(default=True, description="Strict human-in-the-loop requirement")


class AIKeyEvidenceItem(BaseModel):
    source: str = Field(..., description="Finding type or telemetry source")
    finding_id: Optional[str] = Field(None, description="Correlated Finding ID if applicable")
    observation: str = Field(..., description="Direct factual observation")


class AITriageAnalysis(BaseModel):
    """
    Structured domain model for the validated CloudPulse AI triage response.
    Enforces the contract defined in docs/ai/incident-triage.md.
    """
    summary: str = Field(..., description="Executive overview synthesizing security and FinOps observations")
    risk_assessment: str = Field(..., description="Operational risk posture and criticality justification")
    likely_scenario: str = Field(..., description="Inference of probable workload activity based on facts")
    security_impact: str = Field(..., description="Analysis of control-plane and data-plane security posture")
    financial_impact: str = Field(..., description="Quantitative analysis of cost deviation and trajectory")
    facts: List[str] = Field(default_factory=list, description="Verified factual assertions supported directly by telemetry")
    inferences: List[str] = Field(default_factory=list, description="Reasonable interpretations with noted uncertainties")
    key_evidence: List[AIKeyEvidenceItem] = Field(default_factory=list, description="Key evidence items")
    recommended_actions: List[AIRecommendedAction] = Field(default_factory=list, description="Proposed operator actions")
    confidence: float = Field(..., ge=0.0, le=1.0, description="AI confidence score in analysis")
    limitations: List[str] = Field(default_factory=list, description="Explicit declarations of missing or unverified data")
    triage_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of AI triage execution",
    )
    model_identifier: str = Field(default="azure-openai/gpt-4o", description="Model/deployment name used")
    status: str = Field(default="COMPLETED", description="Triage status: COMPLETED, UNAVAILABLE, or ERROR")
    error_message: Optional[str] = Field(None, description="Error detail if triage degraded or failed")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence score must be between 0.0 and 1.0, got {v}")
        return round(v, 2)


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class HumanApprovalIntent(BaseModel):
    """
    Represents an operator's explicit authorization intent on a recommended action.
    No remediation is executed; state transition is captured only.
    """
    action_id: str
    incident_id: str
    action_title: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    operator: str = "security-operator"
    notes: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
