import logging
from datetime import timedelta
from typing import Optional, List, Dict, Any

from config import config
from database.postgres import DatabaseRepository
from detectors.resource_creation import ResourceCreationDetector
from models.finding import Finding
from models.incident import Incident
from services.incident_orchestrator import IncidentOrchestrator
from telemetry.log_analytics import LogAnalyticsClient

logger = logging.getLogger("cloudpulse.services.detection_service")


class DetectionService:
    """
    Main detection pipeline coordinator.
    Ingests telemetry from Azure Log Analytics -> Evaluates RESOURCE_CREATION rules ->
    Normalizes Findings -> Persists to PostgreSQL -> Creates/Updates Incidents.
    """

    def __init__(
        self,
        db_repo: DatabaseRepository,
        log_client: Optional[LogAnalyticsClient] = None,
        detector: Optional[ResourceCreationDetector] = None,
        orchestrator: Optional[IncidentOrchestrator] = None,
    ):
        self._db = db_repo
        self._log_client = log_client
        self._detector = detector or ResourceCreationDetector()
        self._orchestrator = orchestrator or IncidentOrchestrator(db_repo)

    def run_detection(
        self,
        lookback_minutes: Optional[int] = None,
        raw_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the RESOURCE_CREATION detection cycle.

        Args:
            lookback_minutes: Time window in minutes for telemetry query (defaults to config).
            raw_events: Optional list of raw AzureActivity events for replay/testing.
                        If None, live Log Analytics query will be executed.

        Returns:
            Structured summary containing statistics and generated findings & incidents.
        """
        lookback = lookback_minutes or config.LOOKBACK_MINUTES

        # 1. Telemetry Ingestion
        events: List[Dict[str, Any]] = []
        if raw_events is not None:
            logger.info("Using %d provided/mocked AzureActivity events", len(raw_events))
            events = raw_events
        else:
            if not self._log_client:
                raise ValueError("LogAnalyticsClient is required when raw_events is not supplied")

            kql = self._detector.get_kql_query(lookback_minutes=lookback)
            logger.info("Executing Log Analytics query on workspace %s", config.WORKSPACE_ID)
            events = self._log_client.query_workspace(
                workspace_id=config.WORKSPACE_ID,
                kql=kql,
                timespan=timedelta(minutes=lookback),
            )

        logger.info("Ingested %d AzureActivity events for evaluation", len(events))

        # 2. Deterministic Detection
        findings = self._detector.detect(events)
        det_name = getattr(self._detector, "DETECTION_ID", "DETECTOR")
        logger.info("%s detector generated %d findings", det_name, len(findings))

        # 3. Persistence & Incident Promotion
        persisted_findings_count = 0
        incidents_map: Dict[str, Incident] = {}

        for finding in findings:
            # 3a. Persist Finding (deduplication built-in)
            is_new = self._db.save_finding(finding)
            if is_new:
                persisted_findings_count += 1

            # 3b. Promote / attach to Incident
            incident = self._orchestrator.process_finding(finding)
            incidents_map[incident.incident_id] = incident

        incidents_list = list(incidents_map.values())

        return {
            "status": "success",
            "events_analyzed": len(events),
            "findings_detected": len(findings),
            "new_findings_persisted": persisted_findings_count,
            "incidents_created_or_updated": len(incidents_list),
            "findings": [f.model_dump() for f in findings],
            "incidents": [inc.model_dump() for inc in incidents_list],
        }
