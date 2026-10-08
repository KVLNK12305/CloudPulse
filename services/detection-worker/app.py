import logging
from typing import Optional
from flask import Flask, jsonify, request

from config import config
from database.postgres import PostgresDatabase, InMemoryDatabase, DatabaseRepository
from detectors.resource_creation import ResourceCreationDetector
from detectors.unexpected_public_exposure import UnexpectedPublicExposureDetector
from detectors.suspicious_outbound_activity import SuspiciousOutboundActivityDetector
from detectors.cost_anomaly import CostAnomalyDetector
from models.cost_record import CostRecord, CostObservation
from models.network_flow import WorkloadBaseline
from services.detection_service import DetectionService
from services.incident_orchestrator import IncidentOrchestrator
from telemetry.cost_baseline import CostBaselineStore, InMemoryCostBaselineStore
from telemetry.cost_management import (
    CostManagementClient,
    CostManagementQueryError,
    CostManagementAuthenticationError,
    CostManagementRbacError,
    CostManagementRateLimitError,
    CostManagementBadRequestError,
    CostManagementNotFoundError,
)
from telemetry.log_analytics import LogAnalyticsClient, LogAnalyticsQueryError
from telemetry.network_flow import NetworkFlowAdapter, InMemoryBaselineStore
from telemetry.resource_graph import ResourceGraphClient, ResourceGraphQueryError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudpulse.detection_worker")


def create_app(
    db_repo: Optional[DatabaseRepository] = None,
    log_client: Optional[LogAnalyticsClient] = None,
    arg_client: Optional[ResourceGraphClient] = None,
    cost_client: Optional[CostManagementClient] = None,
    cost_store: Optional[CostBaselineStore] = None,
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

    # Initialize Resource Graph client
    if arg_client is not None:
        graph_client = arg_client
    else:
        try:
            graph_client = ResourceGraphClient()
        except Exception as e:
            logger.warning("Default ResourceGraphClient initialization deferred: %s", str(e))
            graph_client = None

    # Initialize Cost Management client
    if cost_client is not None:
        cost_telemetry_client = cost_client
    else:
        try:
            cost_telemetry_client = CostManagementClient()
        except Exception as e:
            logger.warning("Default CostManagementClient initialization deferred: %s", str(e))
            cost_telemetry_client = None

    # Initialize Cost Baseline Store
    finops_baseline_store = cost_store if cost_store is not None else InMemoryCostBaselineStore()

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
            "detectors": [
                ResourceCreationDetector.DETECTION_ID,
                UnexpectedPublicExposureDetector.DETECTION_ID,
                SuspiciousOutboundActivityDetector.DETECTION_ID,
                CostAnomalyDetector.DETECTION_ID,
            ],
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

    @app.route("/detect/unexpected-public-exposure", methods=["POST"])
    def detect_unexpected_public_exposure():
        """
        Trigger the UNEXPECTED_PUBLIC_EXPOSURE detection pipeline.
        Accepts optional JSON body with:
          - lookback_minutes: int (default: 60)
          - events: list of raw AzureActivity events (for testing/mock replay)
          - topology: optional mock/injected topology dictionary
        """
        data = request.get_json(silent=True) or {}
        lookback_minutes = data.get("lookback_minutes")
        raw_events = data.get("events")
        injected_topology = data.get("topology")

        try:
            detector_inst = UnexpectedPublicExposureDetector(
                arg_client=graph_client,
                topology=injected_topology,
            )
            exposure_service = DetectionService(
                db_repo=repository,
                log_client=telemetry_client,
                detector=detector_inst,
            )
            result = exposure_service.run_detection(
                lookback_minutes=lookback_minutes,
                raw_events=raw_events,
            )
            return jsonify(result), 200
        except LogAnalyticsQueryError as lqe:
            logger.error("Log Analytics query failed: %s", str(lqe))
            return jsonify({"status": "error", "message": str(lqe)}), 502
        except ResourceGraphQueryError as rge:
            logger.error("Resource Graph query failed: %s", str(rge))
            return jsonify({"status": "error", "message": str(rge)}), 502
        except Exception as ex:
            logger.exception("Unexpected error during UNEXPECTED_PUBLIC_EXPOSURE execution: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500

    @app.route("/detect/suspicious-outbound", methods=["POST"])
    def detect_suspicious_outbound():
        """
        Trigger the SUSPICIOUS_OUTBOUND_ACTIVITY detection pipeline.
        Accepts optional JSON body with:
          - lookback_minutes: int (default: 60)
          - events: list of raw flow records / dicts (for testing/mock replay)
          - baselines: optional dict mapping resource_id -> baseline metrics
        """
        data = request.get_json(silent=True) or {}
        lookback_minutes = data.get("lookback_minutes")
        raw_events = data.get("events")
        raw_baselines = data.get("baselines")

        # Parse injected baselines if provided
        baseline_store = InMemoryBaselineStore()
        if raw_baselines and isinstance(raw_baselines, dict):
            for res_id, bl_data in raw_baselines.items():
                if isinstance(bl_data, dict):
                    known_ips = set(bl_data.get("known_destination_ips", []))
                    baseline_store.set_baseline(
                        res_id,
                        WorkloadBaseline(
                            resource_id=res_id,
                            mean_hourly_bytes=float(bl_data.get("mean_hourly_bytes", 0.0)),
                            std_hourly_bytes=float(bl_data.get("std_hourly_bytes", 0.0)),
                            known_destination_ips=known_ips,
                            historical_hours=int(bl_data.get("historical_hours", 0)),
                            flow_count=int(bl_data.get("flow_count", 0)),
                            is_cold_start=bool(bl_data.get("is_cold_start", False)),
                        ),
                    )

        flow_adapter = NetworkFlowAdapter(log_client=telemetry_client)

        # If live telemetry query is requested (events is None)
        if raw_events is None:
            if not telemetry_client:
                return jsonify({"status": "error", "message": "LogAnalyticsClient is not configured"}), 503

            # Verify table availability before attempting query
            if not flow_adapter.check_table_exists(config.WORKSPACE_ID):
                return jsonify({
                    "status": "error",
                    "message": "AzureNetworkAnalytics_CL table is not configured in Log Analytics workspace. Network flow telemetry (NSG/VNet Flow Logs with Traffic Analytics) must first be enabled.",
                    "dependency": "AzureNetworkAnalytics_CL",
                }), 503

        try:
            detector_inst = SuspiciousOutboundActivityDetector(
                db_repo=repository,
                baseline_store=baseline_store,
            )
            outbound_service = DetectionService(
                db_repo=repository,
                log_client=telemetry_client,
                detector=detector_inst,
            )
            result = outbound_service.run_detection(
                lookback_minutes=lookback_minutes,
                raw_events=raw_events,
            )
            return jsonify(result), 200
        except LogAnalyticsQueryError as lqe:
            logger.error("Log Analytics query failed: %s", str(lqe))
            return jsonify({"status": "error", "message": str(lqe)}), 502
        except Exception as ex:
            logger.exception("Unexpected error during SUSPICIOUS_OUTBOUND_ACTIVITY execution: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500


    @app.route("/topology", methods=["GET"])
    def get_topology():
        """
        Query and return the live network topology from Azure Resource Graph.
        Used for verification and diagnosing ARG permissions.
        """
        if not graph_client:
            return jsonify({"status": "error", "message": "ResourceGraphClient is not configured"}), 503

        try:
            topo = graph_client.get_network_topology()
            return jsonify({
                "status": "success",
                "counts": {
                    "public_ips": len(topo.get("public_ips", {})),
                    "nics": len(topo.get("nics", {})),
                    "nsgs": len(topo.get("nsgs", {})),
                    "vms": len(topo.get("vms", {})),
                    "subnets": len(topo.get("subnets", {})),
                },
                "topology": topo,
            }), 200
        except Exception as ex:
            logger.exception("Error querying live topology from ARG: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500

    @app.route("/finops/cost-query", methods=["POST"])
    def query_finops_costs():
        """
        Query and normalize Azure Cost Management telemetry, compute baselines,
        and generate CostObservations.
        Accepts optional JSON body with:
          - scope: str (e.g. /subscriptions/{id} or /subscriptions/{id}/resourceGroups/{rg})
          - lookback_days: int (default: 14)
          - evaluation_date: str (YYYY-MM-DD)
          - raw_response: dict (mock/replay Azure Cost Management Query API response)
          - records: list of dicts (pre-normalized CostRecord inputs for testing)
        """
        data = request.get_json(silent=True) or {}
        scope = data.get("scope") or f"/subscriptions/{config.AZURE_SUBSCRIPTION_ID}"
        lookback_days = int(data.get("lookback_days") or config.COST_LOOKBACK_DAYS)
        evaluation_date = data.get("evaluation_date")
        raw_response = data.get("raw_response")
        pre_formed_records = data.get("records")

        try:
            ingested_records: List[CostRecord] = []

            if pre_formed_records is not None:
                for rec_data in pre_formed_records:
                    if isinstance(rec_data, dict):
                        ingested_records.append(CostRecord(**rec_data))
                    elif isinstance(rec_data, CostRecord):
                        ingested_records.append(rec_data)

            elif raw_response is not None:
                client = cost_telemetry_client or CostManagementClient()
                ingested_records = client.normalize_query_response(
                    raw_response=raw_response,
                    default_sub_id=config.AZURE_SUBSCRIPTION_ID,
                )

            else:
                if not cost_telemetry_client:
                    return jsonify({
                        "status": "error",
                        "message": "CostManagementClient is not configured",
                    }), 503

                ingested_records = cost_telemetry_client.get_historical_cost(
                    scope=scope,
                    lookback_days=lookback_days,
                    default_sub_id=config.AZURE_SUBSCRIPTION_ID,
                )

            # Idempotently record costs into baseline store
            finops_baseline_store.record_costs(ingested_records)

            # Compute observations
            observations = finops_baseline_store.list_observations(evaluation_date=evaluation_date)
            unique_workloads = {r.resource_id for r in ingested_records}

            return jsonify({
                "status": "success",
                "scope": scope,
                "records_ingested": len(ingested_records),
                "unique_workloads": len(unique_workloads),
                "observations_generated": len(observations),
                "observations": [obs.model_dump() for obs in observations],
                "records": [r.model_dump() for r in ingested_records[:50]],
            }), 200

        except CostManagementRbacError as rbe:
            logger.error("Cost Management RBAC error on scope %s: %s", scope, str(rbe))
            return jsonify({
                "status": "error",
                "error_type": "RBAC_FORBIDDEN",
                "message": str(rbe),
            }), 403

        except CostManagementRateLimitError as rle:
            logger.error("Cost Management rate limit exceeded on scope %s: %s", scope, str(rle))
            return jsonify({
                "status": "error",
                "error_type": "RATE_LIMIT_EXCEEDED",
                "message": str(rle),
            }), 429

        except CostManagementBadRequestError as bre:
            logger.error("Cost Management bad request on scope %s: %s", scope, str(bre))
            return jsonify({
                "status": "error",
                "error_type": "BAD_REQUEST",
                "message": str(bre),
            }), 400

        except CostManagementNotFoundError as nfe:
            logger.error("Cost Management scope not found: %s: %s", scope, str(nfe))
            return jsonify({
                "status": "error",
                "error_type": "NOT_FOUND",
                "message": str(nfe),
            }), 404

        except CostManagementAuthenticationError as cae:
            logger.error("Cost Management authentication failure: %s", str(cae))
            return jsonify({
                "status": "error",
                "error_type": "AUTHENTICATION_FAILED",
                "message": str(cae),
            }), 401

        except CostManagementQueryError as cqe:
            logger.error("Cost Management query failed: %s", str(cqe))
            return jsonify({
                "status": "error",
                "message": str(cqe),
            }), 502

        except Exception as ex:
            logger.exception("Unexpected error in /finops/cost-query: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500

    @app.route("/finops/baseline", methods=["GET"])
    def get_finops_baseline():
        """
        Query current FinOps baseline observations from the baseline store.
        """
        evaluation_date = request.args.get("evaluation_date")
        resource_id = request.args.get("resource_id")
        cost_category = request.args.get("cost_category")

        if resource_id and cost_category:
            obs = finops_baseline_store.get_observation(
                resource_id=resource_id,
                cost_category=cost_category,
                evaluation_date=evaluation_date,
            )
            if not obs:
                return jsonify({"error": "Observation not found for specified resource and category"}), 404
            return jsonify(obs.model_dump()), 200

        observations = finops_baseline_store.list_observations(evaluation_date=evaluation_date)
        return jsonify({
            "count": len(observations),
            "observations": [o.model_dump() for o in observations],
        }), 200

    @app.route("/finops/rbac-check", methods=["GET"])
    def check_finops_rbac():
        """
        Validate Cost Management Reader RBAC permissions on the specified scope.
        """
        scope = request.args.get("scope") or f"/subscriptions/{config.AZURE_SUBSCRIPTION_ID}"
        if not cost_telemetry_client:
            return jsonify({"status": "error", "message": "CostManagementClient is not configured"}), 503

        is_valid = cost_telemetry_client.validate_rbac(scope=scope)
        return jsonify({
            "scope": scope,
            "rbac_valid": is_valid,
            "required_role": "Cost Management Reader",
            "role_definition_id": "72fafb9e-0641-4937-9268-a42baaa0c913",
        }), 200 if is_valid else 403

    @app.route("/detect/cost-anomaly", methods=["POST"])
    def detect_cost_anomaly():
        """
        Trigger the COST_ANOMALY detection pipeline.
        Accepts optional JSON body with:
          - observations: list of CostObservation dicts (for testing/mock replay)
          - records: list of CostRecord dicts
          - raw_response: mock Cost Management Query API response
          - evaluation_date: str (YYYY-MM-DD)
          - scope: str
          - lookback_days: int
        """
        data = request.get_json(silent=True) or {}
        injected_observations = data.get("observations")
        injected_records = data.get("records") or data.get("raw_records")
        raw_response = data.get("raw_response")
        evaluation_date = data.get("evaluation_date")
        scope = data.get("scope") or f"/subscriptions/{config.AZURE_SUBSCRIPTION_ID}"
        lookback_days = int(data.get("lookback_days") or config.COST_LOOKBACK_DAYS)

        try:
            obs_to_evaluate: List[CostObservation] = []

            if injected_observations is not None:
                for item in injected_observations:
                    if isinstance(item, CostObservation):
                        obs_to_evaluate.append(item)
                    elif isinstance(item, dict):
                        obs_to_evaluate.append(CostObservation(**item))

            elif injected_records is not None or raw_response is not None:
                records: List[CostRecord] = []
                if injected_records is not None:
                    for rec in injected_records:
                        if isinstance(rec, CostRecord):
                            records.append(rec)
                        elif isinstance(rec, dict):
                            records.append(CostRecord(**rec))
                elif raw_response is not None:
                    client = cost_telemetry_client or CostManagementClient()
                    records = client.normalize_query_response(
                        raw_response=raw_response,
                        default_sub_id=config.AZURE_SUBSCRIPTION_ID,
                    )

                finops_baseline_store.record_costs(records)
                obs_to_evaluate = finops_baseline_store.list_observations(evaluation_date=evaluation_date)

            else:
                # Live execution: pull historical cost from Cost Management if available
                if cost_telemetry_client:
                    live_records = cost_telemetry_client.get_historical_cost(
                        scope=scope,
                        lookback_days=lookback_days,
                        default_sub_id=config.AZURE_SUBSCRIPTION_ID,
                    )
                    finops_baseline_store.record_costs(live_records)

                obs_to_evaluate = finops_baseline_store.list_observations(evaluation_date=evaluation_date)

            detector_inst = CostAnomalyDetector(baseline_store=finops_baseline_store)
            findings = detector_inst.detect(observations=obs_to_evaluate, evaluation_date=evaluation_date)

            # Persist Findings and correlate into Incidents
            orchestrator = IncidentOrchestrator(repository)
            persisted_count = 0
            incidents_map = {}

            for finding in findings:
                is_new = repository.save_finding(finding)
                if is_new:
                    persisted_count += 1

                incident = orchestrator.process_finding(finding)
                incidents_map[incident.incident_id] = incident

            incidents_list = list(incidents_map.values())

            return jsonify({
                "status": "success",
                "observations_evaluated": len(obs_to_evaluate),
                "findings_detected": len(findings),
                "new_findings_persisted": persisted_count,
                "incidents_created_or_updated": len(incidents_list),
                "findings": [f.model_dump() for f in findings],
                "incidents": [inc.model_dump() for inc in incidents_list],
            }), 200

        except Exception as ex:
            logger.exception("Unexpected error during COST_ANOMALY execution: %s", str(ex))
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