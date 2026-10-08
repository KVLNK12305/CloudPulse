import logging
from datetime import datetime, timezone
from typing import Optional

from database.postgres import DatabaseRepository
from models.finding import Finding, SeverityLevel
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id

logger = logging.getLogger("cloudpulse.services.incident_orchestrator")


class IncidentOrchestrator:
    """
    Orchestrates promotion of CloudPulse Findings into unified Incidents.
    Ensures stable deterministic incident IDs, evidence preservation, and deduplication.
    """

    def __init__(self, db_repo: DatabaseRepository):
        self._db = db_repo

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

        existing_incident = self._db.get_incident(incident_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        if finding.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
            timeline_event = "UNEXPECTED_PUBLIC_EXPOSURE_DETECTED"
        elif finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
            timeline_event = "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED"
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

    @staticmethod
    def _severity_rank(sev: str) -> int:
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(sev.upper(), 1)
