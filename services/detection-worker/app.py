import logging
from typing import Optional
from flask import Flask, jsonify, request

from config import config
from database.postgres import PostgresDatabase, InMemoryDatabase, DatabaseRepository
from detectors.resource_creation import ResourceCreationDetector
from services.detection_service import DetectionService
from telemetry.log_analytics import LogAnalyticsClient, LogAnalyticsQueryError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudpulse.detection_worker")


def create_app(
    db_repo: Optional[DatabaseRepository] = None,
    log_client: Optional[LogAnalyticsClient] = None,
) -> Flask:
    """
    Application factory for the CloudPulse Detection Worker.
    Supports injecting database repositories and telemetry clients for testing.
    """
    app = Flask(__name__)

    # Initialize persistence
    if db_repo is not None:
        repository = db_repo
    else:
        if config.ENVIRONMENT == "test" or not config.POSTGRES_PASSWORD:
            logger.info("Using InMemoryDatabase repository (test environment or no PG password provided).")
            repository = InMemoryDatabase()
        else:
            try:
                repository = PostgresDatabase(
                    host=config.POSTGRES_HOST,
                    port=config.POSTGRES_PORT,
                    database=config.POSTGRES_DB,
                    user=config.POSTGRES_USER,
                    password=config.POSTGRES_PASSWORD,
                    sslmode=config.POSTGRES_SSLMODE,
                )
                repository.initialize_schema()
            except Exception as e:
                logger.warning(
                    "Could not connect to PostgreSQL Flexible Server (%s). Falling back to InMemoryDatabase: %s",
                    config.POSTGRES_HOST,
                    str(e),
                )
                repository = InMemoryDatabase()

    # Initialize Log Analytics client
    if log_client is not None:
        telemetry_client = log_client
    else:
        try:
            telemetry_client = LogAnalyticsClient()
        except Exception as e:
            logger.warning("Default LogAnalyticsClient initialization deferred: %s", str(e))
            telemetry_client = None

    detection_service = DetectionService(
        db_repo=repository,
        log_client=telemetry_client,
        detector=ResourceCreationDetector(),
    )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "service": "cloudpulse-detection-worker",
            "status": "healthy",
            "environment": config.ENVIRONMENT,
            "detector": ResourceCreationDetector.DETECTION_ID,
            "storage": "postgres" if isinstance(repository, PostgresDatabase) else "in_memory",
        })

    @app.route("/", methods=["GET"])
    def home():
        return jsonify({
            "service": "cloudpulse-detection-worker",
            "message": "CloudPulse detection worker is running",
            "detection_contract": ResourceCreationDetector.DETECTION_ID,
        })

    @app.route("/detect/resource-creation", methods=["POST"])
    def detect_resource_creation():
        """
        Trigger the RESOURCE_CREATION detection pipeline.
        Accepts optional JSON body with:
          - lookback_minutes: int (default: 60)
          - events: list of raw AzureActivity events (for testing/mock replay)
        """
        data = request.get_json(silent=True) or {}
        lookback_minutes = data.get("lookback_minutes")
        raw_events = data.get("events")

        try:
            result = detection_service.run_detection(
                lookback_minutes=lookback_minutes,
                raw_events=raw_events,
            )
            return jsonify(result), 200
        except LogAnalyticsQueryError as lqe:
            logger.error("Log Analytics query failed: %s", str(lqe))
            return jsonify({"status": "error", "message": str(lqe)}), 502
        except Exception as ex:
            logger.exception("Unexpected error during detection execution: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500

    @app.route("/findings", methods=["GET"])
    def get_findings():
        limit = int(request.args.get("limit", 50))
        findings = repository.list_findings(limit=limit)
        return jsonify({
            "count": len(findings),
            "findings": [f.model_dump() for f in findings],
        }), 200

    @app.route("/findings/<finding_id>", methods=["GET"])
    def get_finding_by_id(finding_id: str):
        finding = repository.get_finding(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found", "finding_id": finding_id}), 404
        return jsonify(finding.model_dump()), 200

    @app.route("/incidents", methods=["GET"])
    def get_incidents():
        limit = int(request.args.get("limit", 50))
        incidents = repository.list_incidents(limit=limit)
        return jsonify({
            "count": len(incidents),
            "incidents": [inc.model_dump() for inc in incidents],
        }), 200

    @app.route("/incidents/<incident_id>", methods=["GET"])
    def get_incident_by_id(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        return jsonify(incident.model_dump()), 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)