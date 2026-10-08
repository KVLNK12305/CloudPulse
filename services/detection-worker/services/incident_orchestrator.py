import logging
from datetime import datetime, timezone
from typing import Optional, List

from database.postgres import DatabaseRepository
from models.finding import Finding, SeverityLevel
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from services.correlation_service import (
    SecurityFinopsCorrelator,
    CorrelationStrength,
    CorrelationResult,
)

logger = logging.getLogger("cloudpulse.services.incident_orchestrator")


class IncidentOrchestrator:
    """
    Orchestrates promotion of CloudPulse Findings into unified Incidents.
    Ensures stable deterministic incident IDs, evidence preservation, and deduplication.
    """

    def __init__(
        self,
        db_repo: DatabaseRepository,
        correlator: Optional[SecurityFinopsCorrelator] = None,
    ):
        self._db = db_repo
        self._correlator = correlator or SecurityFinopsCorrelator()


    def process_finding(self, finding: Finding) -> Incident:
        """
        Process a detected finding.
        If an incident for this resource/caller already exists, attach the finding.
        Otherwise, create a new incident.
        """
        incident_id = generate_deterministic_incident_id(
            resource_id=finding.resource.id,
            caller=finding.identity.caller,
        )

        # Ensure finding is persisted in repository so subsequent correlation can retrieve it
        self._db.save_finding(finding)

        existing_incident = self._db.get_incident(incident_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        if finding.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
            timeline_event = "UNEXPECTED_PUBLIC_EXPOSURE_DETECTED"
        elif finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
            timeline_event = "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED"
        elif finding.finding_type == "COST_ANOMALY":
            timeline_event = "COST_ANOMALY_DETECTED"
        else:
            timeline_event = "RESOURCE_CREATION_DETECTED"

        timeline_entry = {
            "timestamp": finding.timestamp,
            "event": timeline_event,
            "finding_id": finding.finding_id,
            "operation": finding.evidence.operation,
            "activity_log_event_id": finding.evidence.activity_log_event_id,
            "caller": finding.identity.caller,
        }

        if existing_incident:
            logger.info(
                "Attaching finding %s to existing incident %s",
                finding.finding_id,
                existing_incident.incident_id,
            )
            if finding.finding_id not in existing_incident.findings:
                existing_incident.findings.append(finding.finding_id)
                existing_incident.timeline.append(timeline_entry)

            # Multi-detector escalation per contract (Section 17.4):
            # Pairing UNEXPECTED_PUBLIC_EXPOSURE with SUSPICIOUS_OUTBOUND_ACTIVITY escalates to CRITICAL
            has_upe = any("PUBLIC_EXPOSURE" in e.get("event", "") for e in existing_incident.timeline)
            has_soa = (finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY") or any(
                "OUTBOUND_ACTIVITY" in e.get("event", "") for e in existing_incident.timeline
            )
            if has_upe and has_soa:
                existing_incident.severity = SeverityLevel.CRITICAL
            elif self._severity_rank(finding.severity.value) > self._severity_rank(existing_incident.severity.value):
                existing_incident.severity = finding.severity

            # Security ↔ FinOps Correlation
            incident_findings: List[Finding] = []
            for fid in existing_incident.findings:
                if fid == finding.finding_id:
                    incident_findings.append(finding)
                else:
                    f = self._db.get_finding(fid)
                    if f:
                        incident_findings.append(f)

            corr_result = self._correlator.correlate_incident_findings(incident_findings)
            if corr_result and corr_result.strength in (
                CorrelationStrength.MODERATE,
                CorrelationStrength.STRONG,
                CorrelationStrength.VERY_STRONG,
            ):
                self._apply_correlation(existing_incident, corr_result, now_iso)

            existing_incident.updated_at = now_iso
            self._db.save_incident(existing_incident)
            self._db.link_incident_finding(incident_id, finding.finding_id)
            return existing_incident

        # Create new Incident
        if finding.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
            exp_label = finding.evidence.exposure_type or "Public Exposure"
            title = f"Unexpected Public Exposure: {finding.resource.name} ({exp_label})"
        elif finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
            soa_label = finding.evidence.anomaly_type or "Outbound Egress"
            title = f"Suspicious Outbound Activity: {finding.resource.name} ({soa_label})"
        elif finding.finding_type == "COST_ANOMALY":
            cat_label = finding.evidence.cost_category or "FinOps"
            delta = finding.evidence.deviation_absolute or 0.0
            pct = finding.evidence.percentage_increase or 0.0
            title = f"Cost Anomaly: {finding.resource.name} ({cat_label}) - +${delta:.2f} (+{pct:.0f}%)"
        else:
            title = f"New Resource Created: {finding.resource.name} ({finding.resource.type.split('/')[-1]})"
        logger.info(
            "Creating new incident %s for resource %s",
            incident_id,
            finding.resource.id,
        )

        new_incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=finding.severity,
            status=IncidentStatus.OPEN,
            created_at=now_iso,
            updated_at=now_iso,
            resource=finding.resource,
            identity=finding.identity,
            findings=[finding.finding_id],
            timeline=[timeline_entry],
            cost_impact=None,   # MVP boundary
            ai_analysis=None,   # MVP boundary
            remediation=None,   # MVP boundary
        )

        self._db.save_incident(new_incident)
        self._db.link_incident_finding(incident_id, finding.finding_id)
        return new_incident

    def _apply_correlation(
        self,
        incident: Incident,
        result: CorrelationResult,
        now_iso: str,
    ) -> None:
        """
        Populate cost_impact, update title, escalate severity, and record
        SECURITY_FINOPS_CORRELATED timeline entry per docs/correlation/security-finops.md.
        """
        # 1. Populate cost_impact
        incident.cost_impact = {
            "correlated_finding_id": result.finops_finding_id,
            "cost_category": result.cost_category,
            "actual_cost": result.actual_cost,
            "baseline_cost": result.baseline_cost,
            "deviation_absolute": result.deviation_absolute,
            "percentage_increase": result.percentage_increase,
            "currency": result.currency,
            "evaluation_date": result.evaluation_date,
            "correlation_strength": result.strength.value,
            "correlation_confidence": result.confidence,
            "correlation_type": result.correlation_type,
            "correlated_security_finding_id": result.security_finding_id,
        }

        # 2. Update title if correlated title generated
        if result.correlated_title:
            incident.title = result.correlated_title

        # 3. Escalate severity if higher
        if result.escalate_severity:
            if self._severity_rank(result.escalate_severity.value) > self._severity_rank(incident.severity.value):
                incident.severity = result.escalate_severity

        # 4. Append or update SECURITY_FINOPS_CORRELATED timeline entry
        res_name = incident.resource.name
        eval_date = (result.evaluation_date or "").replace("-", "")
        corr_timeline_entry = {
            "timestamp": now_iso,
            "event": "SECURITY_FINOPS_CORRELATED",
            "finding_id": result.finops_finding_id,
            "operation": "CORRELATION_ENGINE_EVALUATION",
            "activity_log_event_id": f"corr-ev-{res_name}-{eval_date}",
            "caller": "cloudpulse-correlation-engine",
            "correlation_metadata": {
                "security_finding_id": result.security_finding_id,
                "finops_finding_id": result.finops_finding_id,
                "correlation_strength": result.strength.value,
                "correlation_confidence": result.confidence,
                "correlation_type": result.correlation_type,
                "affected_resource": incident.resource.id,
                "financial_delta": result.deviation_absolute,
                "currency": result.currency,
                "reason": result.reason,
            },
        }

        # Deduplication: check if correlation entry for this finding pair already exists
        found_idx = None
        for idx, entry in enumerate(incident.timeline):
            if entry.get("event") == "SECURITY_FINOPS_CORRELATED":
                meta = entry.get("correlation_metadata", {})
                if (
                    meta.get("security_finding_id") == result.security_finding_id
                    and meta.get("finops_finding_id") == result.finops_finding_id
                ):
                    found_idx = idx
                    break

        if found_idx is not None:
            incident.timeline[found_idx] = corr_timeline_entry
        else:
            incident.timeline.append(corr_timeline_entry)

    @staticmethod
    def _severity_rank(sev: str) -> int:
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(sev.upper(), 1)

