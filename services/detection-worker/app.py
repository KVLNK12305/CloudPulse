import logging
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from flask import Flask, jsonify, request, send_from_directory

from config import config
from database.postgres import PostgresDatabase, InMemoryDatabase, DatabaseRepository
from detectors.resource_creation import ResourceCreationDetector
from detectors.unexpected_public_exposure import UnexpectedPublicExposureDetector
from detectors.suspicious_outbound_activity import SuspiciousOutboundActivityDetector
from detectors.cost_anomaly import CostAnomalyDetector
from models.cost_record import CostRecord, CostObservation
from models.network_flow import WorkloadBaseline
from models.incident import Incident, IncidentStatus
from models.ai_context import (
    AISafeIncidentContext,
    AITriageAnalysis,
    HumanApprovalIntent,
    ApprovalStatus,
)
from models.remediation import (
    RemediationActionType,
    RemediationStatus,
    RemediationRecord,
    RemediationContainer,
)
from services.ai_triage_service import AITriageService
from services.azure_ai_client import AzureAIClient
from services.azure_network_client import AzureNetworkClient
from services.remediation_service import (
    RemediationService,
    RemediationError,
    RemediationUnapprovedError,
    RemediationPreconditionError,
    RemediationVerificationError,
)
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
from telemetry.monitor_metrics import (
    AzureMonitorMetricsClient,
    AzureMonitorMetricsError,
    AzureMonitorMetricsAuthenticationError,
    AzureMonitorMetricsPermissionError,
    AzureMonitorMetricsNotFoundError,
    AzureMonitorMetricsBadRequestError,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudpulse.detection_worker")


_DEFAULT_CLIENT = object()


def create_app(
    db_repo: Optional[DatabaseRepository] = None,
    log_client: Any = _DEFAULT_CLIENT,
    arg_client: Any = _DEFAULT_CLIENT,
    cost_client: Any = _DEFAULT_CLIENT,
    cost_store: Optional[CostBaselineStore] = None,
    ai_client: Optional[AzureAIClient] = None,
    remediation_svc: Optional[RemediationService] = None,
    metrics_client: Any = _DEFAULT_CLIENT,
) -> Flask:
    """
    Application factory for the CloudPulse Detection Worker.
    Supports injecting database repositories and telemetry clients for testing.
    """
    app = Flask(__name__)

    def _is_postgres_repo(repo: Any) -> bool:
        return type(repo).__name__ == "PostgresDatabase"

    # Initialize persistence with explicit degradation observability
    db_degraded = False
    db_degraded_reason = None
    if db_repo is not None:
        repository = db_repo
        storage_mode = "persistent" if _is_postgres_repo(repository) else "in_memory"
    else:
        if config.ENVIRONMENT == "test" or not config.POSTGRES_PASSWORD:
            logger.info("Using InMemoryDatabase repository (test environment or no PG password provided).")
            repository = InMemoryDatabase()
            storage_mode = "in_memory"
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
                storage_mode = "persistent"
            except Exception as e:
                db_degraded = True
                db_degraded_reason = f"PostgreSQL connection to {config.POSTGRES_HOST} failed: {str(e)}"
                logger.warning(
                    "Could not connect to PostgreSQL Flexible Server (%s). Falling back to InMemoryDatabase: %s",
                    config.POSTGRES_HOST,
                    str(e),
                )
                repository = InMemoryDatabase()
                storage_mode = "in_memory"

    app.db_degraded = db_degraded
    app.db_degraded_reason = db_degraded_reason
    app.storage_mode = storage_mode
    app.is_persistent = (storage_mode == "persistent")

    # Initialize Log Analytics client
    if log_client is not _DEFAULT_CLIENT:
        telemetry_client = log_client
    else:
        try:
            telemetry_client = LogAnalyticsClient()
        except Exception as e:
            logger.warning("Default LogAnalyticsClient initialization deferred: %s", str(e))
            telemetry_client = None

    # Initialize Resource Graph client
    if arg_client is not _DEFAULT_CLIENT:
        graph_client = arg_client
    else:
        try:
            graph_client = ResourceGraphClient()
        except Exception as e:
            logger.warning("Default ResourceGraphClient initialization deferred: %s", str(e))
            graph_client = None

    # Initialize Cost Management client
    if cost_client is not _DEFAULT_CLIENT:
        cost_telemetry_client = cost_client
    else:
        try:
            cost_telemetry_client = CostManagementClient()
        except Exception as e:
            logger.warning("Default CostManagementClient initialization deferred: %s", str(e))
            cost_telemetry_client = None

    # Initialize Azure Monitor Metrics client
    if metrics_client is not _DEFAULT_CLIENT:
        monitor_metrics = metrics_client
    else:
        try:
            monitor_metrics = AzureMonitorMetricsClient()
        except Exception as e:
            logger.warning("Default AzureMonitorMetricsClient initialization deferred: %s", str(e))
            monitor_metrics = None

    # Initialize Cost Baseline Store
    finops_baseline_store = cost_store if cost_store is not None else InMemoryCostBaselineStore()

    detection_service = DetectionService(
        db_repo=repository,
        log_client=telemetry_client,
        detector=ResourceCreationDetector(),
    )

    ai_triage_service = AITriageService(
        db_repo=repository,
        ai_client=ai_client,
    )

    remediation_service = remediation_svc or RemediationService(
        db_repo=repository,
    )

    @app.route("/health", methods=["GET"])
    def health():
        is_postgres = _is_postgres_repo(repository)
        # Reflect database disconnection in overall status if degraded from failed Postgres connection
        overall_status = "degraded" if getattr(app, "db_degraded", False) else "healthy"

        actual_ai_client = ai_triage_service._client
        ai_cfg = actual_ai_client.get_configuration_status() if hasattr(actual_ai_client, "get_configuration_status") else {}

        return jsonify({
            "service": "cloudpulse-detection-worker",
            "status": overall_status,
            "environment": config.ENVIRONMENT,
            "detector": ResourceCreationDetector.DETECTION_ID,
            "detectors": [
                ResourceCreationDetector.DETECTION_ID,
                UnexpectedPublicExposureDetector.DETECTION_ID,
                SuspiciousOutboundActivityDetector.DETECTION_ID,
                CostAnomalyDetector.DETECTION_ID,
            ],
            "storage": "postgres" if is_postgres else "in_memory",
            "database": {
                "connected": is_postgres,
                "readiness": "ready" if is_postgres else ("unhealthy" if getattr(app, "db_degraded", False) else "in_memory"),
                "storage_mode": "persistent" if is_postgres else "in_memory",
                "durable": is_postgres,
                "host": config.POSTGRES_HOST if (is_postgres or getattr(app, "db_degraded", False)) else None,
                "degraded": getattr(app, "db_degraded", False),
                "degradation_reason": getattr(app, "db_degraded_reason", None),
            },
            "ai_provider": {
                "provider": ai_cfg.get("provider", "deterministic-synthesizer"),
                "execution_mode": ai_cfg.get("execution_mode", "FALLBACK"),
                "status": ai_cfg.get("status", "FALLBACK"),
                "endpoint_configured": ai_cfg.get("endpoint_configured", False),
                "mock_mode": ai_cfg.get("mock_mode", False),
                "deployment_name": ai_cfg.get("deployment_name"),
                "model_identifier": ai_cfg.get("model_identifier", "gpt-4.1-mini"),
                "last_successful_request_timestamp": ai_cfg.get("last_successful_request_timestamp"),
                "error_category": ai_cfg.get("error_category"),
            },
        })

    @app.route("/api/ai/status", methods=["GET"])
    def get_ai_status():
        actual_ai_client = ai_triage_service._client
        ai_cfg = actual_ai_client.get_configuration_status() if hasattr(actual_ai_client, "get_configuration_status") else {}
        return jsonify({
            "service": "cloudpulse-ai-triage",
            "status": "success",
            "provider": ai_cfg.get("provider", "deterministic-synthesizer"),
            "deployment_name": ai_cfg.get("deployment_name"),
            "model_identifier": ai_cfg.get("model_identifier", "gpt-4.1-mini"),
            "execution_mode": ai_cfg.get("execution_mode", "FALLBACK"),
            "last_successful_request_timestamp": ai_cfg.get("last_successful_request_timestamp"),
            "error_category": ai_cfg.get("error_category"),
            "ai_configuration": ai_cfg,
        }), 200

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

    # --- Azure Estate, Resource Inventory & FinOps APIs ---
    @app.route("/api/resources", methods=["GET"])
    def get_resources_inventory():
        """
        Query Azure Resource Graph for live inventory of all provisioned cloud resources.
        Enriches each resource with:
          - findings_count & max_severity (from CloudPulse repository)
          - known cost from Cost Management
          - metrics indicator (from Azure Monitor client)
        """
        if not graph_client:
            return jsonify({
                "status": "error",
                "message": "ResourceGraphClient is not configured",
                "resources": [],
            }), 503

        search_q = (request.args.get("search") or "").strip().lower()
        type_filter = (request.args.get("type") or "").strip()
        rg_filter = request.args.get("resource_group")
        sub_filter = request.args.get("subscription_id") or config.AZURE_SUBSCRIPTION_ID

        try:
            raw_resources = graph_client.get_resource_inventory(
                subscription_id=sub_filter,
                resource_group=rg_filter,
                resource_type=type_filter,
            )

            # Get cost summary if available to enrich resource cost
            cost_by_res = {}
            currency = "USD"
            if cost_telemetry_client:
                try:
                    c_sum = cost_telemetry_client.get_cost_summary(
                        scope=f"/subscriptions/{sub_filter}",
                        lookback_days=14,
                        default_sub_id=sub_filter,
                    )
                    if isinstance(c_sum, dict):
                        curr_val = c_sum.get("currency")
                        if isinstance(curr_val, str):
                            currency = curr_val
                        by_res = c_sum.get("by_resource")
                        if isinstance(by_res, list):
                            for r_cost in by_res:
                                if isinstance(r_cost, dict):
                                    cid = (r_cost.get("resource_id") or "")
                                    if isinstance(cid, str):
                                        cost_by_res[cid.lower()] = r_cost
                except Exception as c_err:
                    logger.debug("Non-fatal: could not enrich resource cost: %s", str(c_err))

            enriched_list = []
            for r in raw_resources:
                rid = r.get("id") or ""
                canon_id = rid.lower()
                rname = r.get("name") or ""
                rtype = (r.get("type") or "").lower()

                if search_q and search_q not in rname.lower() and search_q not in canon_id and search_q not in rtype:
                    continue

                # Query CloudPulse repository for security findings on this resource
                findings = repository.get_findings_by_resource_id(rid)
                if not findings and canon_id != rid:
                    findings = repository.get_findings_by_resource_id(canon_id)

                max_sev = None
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                for f in findings:
                    f_val = f.severity.value.upper()
                    if max_sev is None or sev_order.get(f_val, 0) > sev_order.get(max_sev, 0):
                        max_sev = f_val

                # Cost enrichment
                cost_info = cost_by_res.get(canon_id)
                actual_cost = None
                res_currency = currency
                cost_cat = None
                if isinstance(cost_info, dict):
                    raw_cost = cost_info.get("total_cost")
                    if isinstance(raw_cost, (int, float)):
                        actual_cost = float(raw_cost)
                    raw_curr = cost_info.get("currency")
                    if isinstance(raw_curr, str):
                        res_currency = raw_curr
                    raw_cat = cost_info.get("cost_category")
                    if isinstance(raw_cat, str):
                        cost_cat = raw_cat

                # Metrics support indicator
                metrics_supported = False
                if monitor_metrics and hasattr(monitor_metrics, "get_supported_metrics"):
                    try:
                        supp = monitor_metrics.get_supported_metrics(rtype)
                        metrics_supported = bool(supp)
                    except Exception:
                        metrics_supported = False

                enriched_list.append({
                    "id": rid,
                    "name": rname,
                    "type": r.get("type"),
                    "location": r.get("location"),
                    "resource_group": r.get("resourceGroup"),
                    "subscription_id": r.get("subscriptionId"),
                    "provisioning_state": r.get("provisioningState") or "Succeeded",
                    "sku": r.get("sku") if isinstance(r.get("sku"), (dict, str, int, float, list)) else None,
                    "tags": r.get("tags") if isinstance(r.get("tags"), (dict, list)) else None,
                    "actual_cost": actual_cost,
                    "currency": res_currency,
                    "cost_category": cost_cat,
                    "findings_count": len(findings),
                    "max_severity": max_sev,
                    "finding_ids": [f.finding_id for f in findings],
                    "metrics_supported": metrics_supported,
                    "source": "Azure Resource Graph",
                })

            return jsonify({
                "status": "success",
                "count": len(enriched_list),
                "source": "Azure Resource Graph",
                "subscription_id": sub_filter,
                "resources": enriched_list,
            }), 200

        except ResourceGraphQueryError as rge:
            logger.error("Resource Graph query error: %s", str(rge))
            return jsonify({
                "status": "error",
                "message": str(rge),
                "resources": [],
            }), 502
        except Exception as ex:
            logger.exception("Unexpected error in /api/resources: %s", str(ex))
            return jsonify({
                "status": "error",
                "message": str(ex),
                "resources": [],
            }), 500

    @app.route("/api/resources/<path:resource_id>/metrics", methods=["GET"])
    def get_resource_metrics_endpoint(resource_id: str):
        """
        Query Azure Monitor runtime metrics for a specific resource.
        Accepts optional query param: timespan (default: 'PT1H').
        Read-only endpoint.
        """
        clean_id = resource_id.strip()
        if not clean_id.startswith("/"):
            clean_id = "/" + clean_id

        if not monitor_metrics:
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": "AzureMonitorMetricsClient is not configured",
                "metrics": {},
                "source": "Azure Monitor",
            }), 503

        timespan = request.args.get("timespan", "PT1H")

        try:
            metrics_result = monitor_metrics.get_resource_metrics(
                resource_id=clean_id,
                timespan=timespan,
            )
            return jsonify(metrics_result), 200
        except AzureMonitorMetricsAuthenticationError as ae:
            logger.error("Azure Monitor auth failed: %s", str(ae))
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": str(ae),
                "metrics": {},
                "source": "Azure Monitor",
            }), 401
        except AzureMonitorMetricsPermissionError as pe:
            logger.error("Azure Monitor permissions denied: %s", str(pe))
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": str(pe),
                "metrics": {},
                "source": "Azure Monitor",
            }), 403
        except AzureMonitorMetricsNotFoundError as ne:
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": str(ne),
                "metrics": {},
                "source": "Azure Monitor",
            }), 404
        except Exception as ex:
            logger.exception("Unexpected error querying metrics for %s: %s", clean_id, str(ex))
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": str(ex),
                "metrics": {},
                "source": "Azure Monitor",
            }), 500

    @app.route("/api/resources/<path:resource_id>/cost", methods=["GET"])
    def get_resource_cost_endpoint(resource_id: str):
        """
        Retrieve cost telemetry and baseline observations for a specific resource.
        """
        clean_id = resource_id.strip()
        if not clean_id.startswith("/"):
            clean_id = "/" + clean_id

        sub_id = config.AZURE_SUBSCRIPTION_ID
        if not cost_telemetry_client:
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": "CostManagementClient is not configured",
            }), 503

        try:
            summary = cost_telemetry_client.get_cost_summary(
                scope=f"/subscriptions/{sub_id}",
                lookback_days=int(request.args.get("lookback_days", 14)),
                default_sub_id=sub_id,
            )
            matching = [
                r for r in summary.get("by_resource", [])
                if (r.get("resource_id") or "").lower() == clean_id.lower()
            ]

            obs_list = finops_baseline_store.list_observations()
            matching_obs = [
                o for o in obs_list
                if (o.resource_id or "").lower() == clean_id.lower()
            ]

            if not matching:
                return jsonify({
                    "status": "success",
                    "resource_id": clean_id,
                    "has_billing_data": False,
                    "message": "No billing data available for selected period",
                    "total_cost": None,
                    "currency": summary.get("currency", "USD"),
                    "period": summary.get("period"),
                    "meters": [],
                    "observations": [o.model_dump() for o in matching_obs],
                    "source": "Azure Cost Management",
                }), 200

            res_cost = matching[0]
            return jsonify({
                "status": "success",
                "resource_id": clean_id,
                "has_billing_data": True,
                "total_cost": res_cost.get("total_cost", 0.0),
                "currency": res_cost.get("currency", "USD"),
                "cost_category": res_cost.get("cost_category"),
                "period": summary.get("period"),
                "meters": res_cost.get("meters", []),
                "observations": [o.model_dump() for o in matching_obs],
                "source": "Azure Cost Management",
            }), 200
        except Exception as ex:
            logger.exception("Error querying cost for resource %s: %s", clean_id, str(ex))
            return jsonify({
                "status": "error",
                "resource_id": clean_id,
                "message": str(ex),
            }), 500

    @app.route("/api/resources/<path:resource_id>", methods=["GET"])
    def get_resource_detail(resource_id: str):
        """
        Deep resource detail aggregator combining:
          - Resource inventory metadata (Azure Resource Graph)
          - Runtime metrics (Azure Monitor)
          - Actual billing data & meters (Azure Cost Management)
          - Security findings (CloudPulse Detection Engine)
          - FinOps baseline observations (CloudPulse FinOps Engine)
          - Associated incidents (CloudPulse PostgreSQL state)
        """
        clean_id = resource_id.strip()
        if not clean_id.startswith("/"):
            clean_id = "/" + clean_id

        if not AzureMonitorMetricsClient.validate_resource_id(clean_id):
            return jsonify({
                "status": "error",
                "message": f"Invalid Azure Resource ID format: '{clean_id}'",
            }), 400

        sub_id = config.AZURE_SUBSCRIPTION_ID

        # 1. Fetch resource metadata from ARG
        resource_meta = None
        discovered_in_arg = False
        if graph_client:
            try:
                escaped_id = clean_id.replace("'", "")
                kql = f"Resources | where id =~ '{escaped_id}' | project id, name, type, location, resourceGroup, subscriptionId, sku, tags, provisioningState=properties.provisioningState, kind"
                res_records = graph_client.query(kql)
                if res_records:
                    resource_meta = res_records[0]
                    discovered_in_arg = True
            except Exception as e:
                logger.warning("Could not fetch resource metadata from ARG for %s: %s", clean_id, str(e))

        if not resource_meta:
            res_type = AzureMonitorMetricsClient.extract_resource_type(clean_id) or "unknown"
            rname = clean_id.split("/")[-1]
            rg_part = ""
            if "/resourcegroups/" in clean_id.lower():
                rg_part = clean_id.lower().split("/resourcegroups/")[1].split("/")[0]
            resource_meta = {
                "id": clean_id,
                "name": rname,
                "type": res_type,
                "location": "unknown",
                "resourceGroup": rg_part,
                "subscriptionId": sub_id,
                "provisioningState": "Unknown",
                "sku": None,
                "tags": {},
                "discovered_in_arg": False,
            }
        else:
            resource_meta["discovered_in_arg"] = True

        # 2. Fetch metrics
        metrics_data = {
            "supported": False,
            "metrics_available": False,
            "message": "Azure Monitor client not configured",
            "metrics": {},
            "source": "Azure Monitor",
        }
        if monitor_metrics:
            try:
                metrics_data = monitor_metrics.get_resource_metrics(clean_id)
            except Exception as e:
                metrics_data = {
                    "supported": False,
                    "metrics_available": False,
                    "message": f"Metrics query failed: {str(e)}",
                    "metrics": {},
                    "source": "Azure Monitor",
                }

        # 3. Fetch cost data
        cost_data = {
            "has_billing_data": False,
            "total_cost": None,
            "currency": "USD",
            "cost_category": None,
            "meters": [],
            "message": "No billing data available for selected period",
            "source": "Azure Cost Management",
        }
        if cost_telemetry_client:
            try:
                c_sum = cost_telemetry_client.get_cost_summary(
                    scope=f"/subscriptions/{sub_id}",
                    lookback_days=14,
                    default_sub_id=sub_id,
                )
                matching = [
                    r for r in c_sum.get("by_resource", [])
                    if (r.get("resource_id") or "").lower() == clean_id.lower()
                ]
                if matching:
                    res_cost = matching[0]
                    cost_data = {
                        "has_billing_data": True,
                        "total_cost": res_cost.get("total_cost", 0.0),
                        "currency": res_cost.get("currency", "USD"),
                        "cost_category": res_cost.get("cost_category"),
                        "meters": res_cost.get("meters", []),
                        "period": c_sum.get("period"),
                        "message": None,
                        "source": "Azure Cost Management",
                    }
                else:
                    cost_data["period"] = c_sum.get("period")
            except Exception as e:
                logger.warning("Cost lookup error for %s: %s", clean_id, str(e))

        # 4. Fetch security findings from repository
        findings = repository.get_findings_by_resource_id(clean_id)
        if not findings and clean_id.lower() != clean_id:
            findings = repository.get_findings_by_resource_id(clean_id.lower())

        max_sev = None
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for f in findings:
            f_val = f.severity.value.upper()
            if max_sev is None or sev_order.get(f_val, 0) > sev_order.get(max_sev, 0):
                max_sev = f_val

        # 5. Fetch FinOps baseline observations
        obs_list = finops_baseline_store.list_observations()
        res_obs = [
            o.model_dump() for o in obs_list
            if (o.resource_id or "").lower() == clean_id.lower()
        ]
        is_anomalous = any(
            (o.get("deviation_ratio") or 0.0) >= 1.5 or (o.get("percentage_increase") or 0.0) >= 50.0
            for o in res_obs
        )

        # 6. Fetch linked incidents
        all_incidents = repository.list_incidents(limit=200)
        linked_incidents = [
            inc.model_dump() for inc in all_incidents
            if (inc.resource.id or "").lower() == clean_id.lower()
        ]

        return jsonify({
            "status": "success",
            "resource_id": clean_id,
            "resource": resource_meta,
            "cost": cost_data,
            "utilization": metrics_data,
            "security": {
                "findings_count": len(findings),
                "max_severity": max_sev,
                "findings": [f.model_dump() for f in findings],
                "source": "CloudPulse Detection Engine",
            },
            "finops": {
                "is_anomalous": is_anomalous,
                "observations": res_obs,
                "source": "CloudPulse FinOps Engine",
            },
            "incidents": {
                "count": len(linked_incidents),
                "incidents": linked_incidents,
                "source": "CloudPulse PostgreSQL state",
            },
            "source_attributions": {
                "resource": "Azure Resource Graph" if discovered_in_arg else "Fabricated fallback (Resource not found in Azure Resource Graph)",
                "cost": "Azure Cost Management",
                "utilization": "Azure Monitor",
                "security": "CloudPulse Detection Engine",
                "finops": "CloudPulse FinOps Engine",
                "incidents": "CloudPulse PostgreSQL state",
            },
        }), 200

    @app.route("/api/finops/costs", methods=["GET"])
    def get_finops_costs_summary():
        """
        Dashboard API for Azure Cost Management data.
        Returns total cost, cost by resource, cost by category, top drivers,
        and billing latency notice.
        """
        scope = request.args.get("scope") or f"/subscriptions/{config.AZURE_SUBSCRIPTION_ID}"
        lookback_days = int(request.args.get("lookback_days", 14))

        if not cost_telemetry_client:
            return jsonify({
                "status": "error",
                "message": "CostManagementClient is not configured",
            }), 503

        try:
            summary = cost_telemetry_client.get_cost_summary(
                scope=scope,
                lookback_days=lookback_days,
                default_sub_id=config.AZURE_SUBSCRIPTION_ID,
            )

            observations = finops_baseline_store.list_observations()
            anomalies = [
                obs.model_dump() for obs in observations
                if (obs.deviation_ratio or 0.0) >= 1.5 or (obs.percentage_increase or 0.0) >= 50.0
            ]

            summary["anomalies"] = anomalies
            summary["source"] = "Azure Cost Management"
            return jsonify(summary), 200

        except CostManagementRbacError as rbe:
            return jsonify({
                "status": "error",
                "error_type": "RBAC_FORBIDDEN",
                "message": str(rbe),
            }), 403
        except CostManagementRateLimitError as rle:
            return jsonify({
                "status": "error",
                "error_type": "RATE_LIMIT_EXCEEDED",
                "message": str(rle),
            }), 429
        except Exception as ex:
            logger.exception("Error in /api/finops/costs: %s", str(ex))
            return jsonify({
                "status": "error",
                "message": str(ex),
            }), 500

    @app.route("/api/estate/overview", methods=["GET"])
    def get_estate_overview():
        """
        High-level executive overview of the Azure estate combining
        real Azure Resource Graph inventory, Cost Management totals,
        and CloudPulse SecOps & FinOps telemetry.
        """
        sub_id = config.AZURE_SUBSCRIPTION_ID
        rg = "cloudpulse-rg"

        # 1. Resource counts via ARG
        res_count = 0
        by_type_counts = {}
        if graph_client:
            try:
                inv = graph_client.get_resource_inventory(subscription_id=sub_id, resource_group=rg)
                res_count = len(inv)
                for r in inv:
                    t = r.get("type", "unknown")
                    by_type_counts[t] = by_type_counts.get(t, 0) + 1
            except Exception as e:
                logger.warning("Could not query ARG for estate overview: %s", str(e))

        # 2. Cost summary via Cost Management
        cost_total = None
        currency = "USD"
        by_category = {}
        latency_notice = "Cost data unavailable"
        latest_usage_date = None
        has_cost_data = False
        if cost_telemetry_client:
            try:
                c_sum = cost_telemetry_client.get_cost_summary(
                    scope=f"/subscriptions/{sub_id}",
                    lookback_days=14,
                    default_sub_id=sub_id,
                )
                has_cost_data = c_sum.get("has_data", False)
                if has_cost_data:
                    cost_total = c_sum.get("summary", {}).get("total_cost", 0.0)
                else:
                    cost_total = None
                currency = c_sum.get("currency", "USD")
                by_category = c_sum.get("by_category", {})
                latency_notice = c_sum.get("period", {}).get("billing_latency_notice")
                latest_usage_date = c_sum.get("period", {}).get("latest_usage_date")
            except Exception as e:
                logger.warning("Could not query Cost Management for estate overview: %s", str(e))
                latency_notice = f"Cost query unavailable: {str(e)}"

        # 3. Incident & Security state via Database
        incidents = repository.list_incidents(limit=200)
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        correlated_count = 0
        for inc in incidents:
            s_val = inc.severity.value.upper()
            by_sev[s_val] = by_sev.get(s_val, 0) + 1
            if inc.cost_impact:
                correlated_count += 1

        observations = finops_baseline_store.list_observations()
        anomalies_count = len([
            obs for obs in observations
            if (obs.deviation_ratio or 0.0) >= 1.5 or (obs.percentage_increase or 0.0) >= 50.0
        ])

        return jsonify({
            "status": "success",
            "subscription_id": sub_id,
            "resource_group": rg,
            "environment": config.ENVIRONMENT,
            "resources": {
                "total": res_count,
                "by_type": by_type_counts,
                "source": "Azure Resource Graph",
            },
            "costs": {
                "has_data": has_cost_data,
                "total_cost": cost_total,
                "currency": currency,
                "by_category": by_category,
                "latest_usage_date": latest_usage_date,
                "billing_latency_notice": latency_notice,
                "source": "Azure Cost Management",
            },
            "security": {
                "total_incidents": len(incidents),
                "by_severity": by_sev,
                "correlated_incidents": correlated_count,
                "cost_anomalies_count": anomalies_count,
                "source": "CloudPulse PostgreSQL state",
            },
            "source_attributions": {
                "inventory": "Azure Resource Graph",
                "costs": "Azure Cost Management",
                "metrics": "Azure Monitor",
                "security_findings": "CloudPulse Detection Engine",
                "incidents": "CloudPulse PostgreSQL state",
            },
        }), 200

    # --- Dashboard UI Serving ---
    @app.route("/dashboard", methods=["GET"])
    def serve_dashboard():
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        return send_from_directory(static_dir, "index.html")

    @app.route("/static/<path:filename>", methods=["GET"])
    def serve_static(filename):
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        return send_from_directory(static_dir, filename)

    # --- Incident APIs ---
    @app.route("/incidents", methods=["GET"])
    @app.route("/api/incidents", methods=["GET"])
    def get_incidents():
        limit = int(request.args.get("limit", 50))
        severity_filter = request.args.get("severity")
        status_filter = request.args.get("status")
        incidents = repository.list_incidents(limit=limit)
        if severity_filter:
            incidents = [i for i in incidents if i.severity.value.upper() == severity_filter.upper()]
        if status_filter:
            incidents = [i for i in incidents if i.status.value.upper() == status_filter.upper()]
        return jsonify({
            "count": len(incidents),
            "incidents": [inc.model_dump() for inc in incidents],
        }), 200

    @app.route("/incidents/<incident_id>", methods=["GET"])
    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def get_incident_by_id(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        return jsonify(incident.model_dump()), 200

    @app.route("/incidents/<incident_id>", methods=["PATCH"])
    @app.route("/api/incidents/<incident_id>", methods=["PATCH"])
    def patch_incident(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        data = request.get_json(silent=True) or {}
        new_status = data.get("status")
        if not new_status:
            return jsonify({"error": "Field 'status' is required for incident status update"}), 400
        try:
            incident.status = IncidentStatus(new_status.upper())
        except ValueError:
            valid = [s.value for s in IncidentStatus]
            return jsonify({"error": f"Invalid status '{new_status}'. Valid statuses: {valid}"}), 400
        now_iso = datetime.now(timezone.utc).isoformat()
        incident.updated_at = now_iso
        incident.timeline.append({
            "timestamp": now_iso,
            "event": "STATUS_UPDATED",
            "operation": "OPERATOR_STATUS_MUTATION",
            "caller": data.get("caller", "operator"),
            "correlation_metadata": {"new_status": incident.status.value},
        })
        repository.save_incident(incident)
        return jsonify(incident.model_dump()), 200

    @app.route("/api/incidents/<incident_id>/findings", methods=["GET"])
    def get_incident_findings(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        findings = []
        for fid in incident.findings:
            f = repository.get_finding(fid)
            if f:
                findings.append(f)
        missing_count = max(0, len(incident.findings) - len(findings))
        return jsonify({
            "incident_id": incident_id,
            "count": len(findings),
            "missing_findings_count": missing_count,
            "findings": [f.model_dump() for f in findings],
        }), 200

    @app.route("/api/incidents/<incident_id>/timeline", methods=["GET"])
    def get_incident_timeline(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        sorted_timeline = sorted(incident.timeline, key=lambda e: e.get("timestamp") or "")
        return jsonify({
            "incident_id": incident_id,
            "count": len(sorted_timeline),
            "timeline": sorted_timeline,
        }), 200

    @app.route("/api/incidents/<incident_id>/ai-analysis", methods=["GET"])
    def get_incident_ai_analysis(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        if not incident.ai_analysis:
            return jsonify({"incident_id": incident_id, "status": "NOT_TRIAGED"}), 404
        return jsonify(incident.ai_analysis), 200

    @app.route("/api/incidents/<incident_id>/ai-triage", methods=["POST"])
    def trigger_ai_triage(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        data = request.get_json(silent=True) or {}
        force_refresh = bool(data.get("force_refresh", False))
        analysis = ai_triage_service.triage_incident(incident=incident, force_refresh=force_refresh)
        refreshed_incident = repository.get_incident(incident_id) or incident
        is_durable = _is_postgres_repo(repository)
        response_data = {
            "status": "success",
            "incident_id": incident_id,
            "ai_analysis": analysis.model_dump(),
            "incident": refreshed_incident.model_dump(),
            "storage_mode": "persistent" if is_durable else "in_memory",
            "durable": is_durable,
        }
        if not is_durable:
            response_data["storage_warning"] = (
                "Operating on volatile in-memory storage. State will NOT persist across container restarts."
            )
        return jsonify(response_data), 200

    @app.route("/api/incidents/<incident_id>/actions/<action_id>/approval", methods=["POST"])
    def approve_action(incident_id: str, action_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        data = request.get_json(silent=True) or {}
        decision = (data.get("status") or "APPROVED").upper()
        if decision not in ("APPROVED", "REJECTED"):
            return jsonify({"error": "Invalid approval status. Must be 'APPROVED' or 'REJECTED'"}), 400
        operator = data.get("operator", "security-operator")
        notes = data.get("notes")
        now_iso = datetime.now(timezone.utc).isoformat()

        # If the action_id is not yet registered in the remediation container,
        # check whether it corresponds to a valid AI triage recommended action.
        # If so, register it as PROPOSED before forwarding to record_approval.
        # This keeps the service layer strict (rejects unknown action IDs)
        # while preserving the AI triage → approval workflow.
        container = RemediationContainer.from_incident_remediation(incident.remediation)
        if action_id not in container.actions:
            # Verify the action_id exists in AI triage recommended_actions
            ai_action_valid = False
            if incident.ai_analysis and isinstance(incident.ai_analysis, dict):
                for act in incident.ai_analysis.get("recommended_actions", []):
                    if act.get("id") == action_id:
                        ai_action_valid = True
                        break

            if not ai_action_valid:
                return jsonify({
                    "status": "error",
                    "message": f"Action '{action_id}' is not registered on incident '{incident_id}' "
                               f"and does not correspond to any AI triage recommendation."
                }), 400

            # Auto-register as PROPOSED from validated AI recommendation
            act_type = RemediationActionType.DISABLE_PUBLIC_INGRESS
            if any(
                repository.get_finding(fid) and repository.get_finding(fid).finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY"
                for fid in incident.findings
            ):
                act_type = RemediationActionType.ISOLATE_WORKLOAD

            remediation_service.propose_action_from_recommendation(
                incident=incident,
                action_id=action_id,
                action_type=act_type,
            )

        try:
            record = remediation_service.record_approval(
                incident_id=incident_id,
                action_id=action_id,
                decision=decision,
                operator=operator,
                notes=notes,
            )
            refreshed = repository.get_incident(incident_id) or incident
            approval_resp = {
                "action_id": action_id,
                "status": decision,
                "operator": operator,
                "notes": notes,
                "timestamp": now_iso,
                "remediation_executed": False,
                "remediation_id": record.remediation_id,
            }
            return jsonify({
                "status": "success",
                "incident_id": incident_id,
                "approval": approval_resp,
                "incident": refreshed.model_dump(),
            }), 200
        except RemediationError as re:
            return jsonify({"status": "error", "message": str(re)}), 400
        except Exception as e:
            logger.exception("Error recording approval for incident %s: %s", incident_id, str(e))
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/incidents/<incident_id>/remediation/execute", methods=["POST"])
    def execute_remediation_endpoint(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404

        data = request.get_json(silent=True) or {}
        action_id = data.get("action_id")

        if not action_id:
            container = RemediationContainer.from_incident_remediation(incident.remediation)
            for aid, rec in container.actions.items():
                if rec.status == RemediationStatus.APPROVED:
                    action_id = aid
                    break

        if not action_id:
            return jsonify({
                "status": "error",
                "message": "No action_id specified and no action currently in APPROVED status on this incident."
            }), 400

        try:
            record = remediation_service.execute_remediation(
                incident_id=incident_id,
                action_id=action_id,
            )
            refreshed = repository.get_incident(incident_id) or incident
            http_status = 200
            if record.status == RemediationStatus.PRECONDITION_FAILED:
                http_status = 400
            elif record.status in (RemediationStatus.VERIFICATION_FAILED, RemediationStatus.FAILED):
                http_status = 500

            return jsonify({
                "status": "success" if record.status == RemediationStatus.VERIFIED else "failed",
                "incident_id": incident_id,
                "remediation": record.model_dump(),
                "incident": refreshed.model_dump(),
            }), http_status

        except RemediationUnapprovedError as ue:
            return jsonify({"status": "error", "error_type": "UNAPPROVED_ACTION", "message": str(ue)}), 400
        except RemediationPreconditionError as pe:
            return jsonify({"status": "error", "error_type": "PRECONDITION_FAILED", "message": str(pe)}), 400
        except RemediationError as re:
            return jsonify({"status": "error", "error_type": "REMEDIATION_ERROR", "message": str(re)}), 400
        except Exception as ex:
            logger.exception("Unexpected error executing remediation: %s", str(ex))
            return jsonify({"status": "error", "message": str(ex)}), 500

    @app.route("/api/incidents/<incident_id>/remediation", methods=["GET"])
    def get_incident_remediation(incident_id: str):
        incident = repository.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found", "incident_id": incident_id}), 404
        container = RemediationContainer.from_incident_remediation(incident.remediation)
        return jsonify({
            "incident_id": incident_id,
            "actions": {aid: r.model_dump() for aid, r in container.actions.items()},
        }), 200

    @app.route("/api/dashboard/summary", methods=["GET"])
    def get_dashboard_summary():
        incidents = repository.list_incidents(limit=200)
        total = len(incidents)
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_stat = {"OPEN": 0, "INVESTIGATING": 0, "RESOLVED": 0, "CLOSED": 0}
        correlated_count = 0
        total_overrun = 0.0
        triaged_count = 0
        triaged_live_count = 0
        triaged_fallback_count = 0

        for inc in incidents:
            s_val = inc.severity.value.upper()
            by_sev[s_val] = by_sev.get(s_val, 0) + 1
            st_val = inc.status.value.upper()
            by_stat[st_val] = by_stat.get(st_val, 0) + 1
            if inc.cost_impact:
                correlated_count += 1
                total_overrun += float(inc.cost_impact.get("deviation_absolute", 0.0))
            if inc.ai_analysis and inc.ai_analysis.get("status") == "COMPLETED":
                triaged_count += 1
                if inc.ai_analysis.get("execution_mode") == "LIVE":
                    triaged_live_count += 1
                else:
                    triaged_fallback_count += 1

        is_postgres = _is_postgres_repo(repository)
        actual_ai_client = ai_triage_service._client
        ai_cfg = actual_ai_client.get_configuration_status() if hasattr(actual_ai_client, "get_configuration_status") else {}

        return jsonify({
            "total_incidents": total,
            "by_severity": by_sev,
            "by_status": by_stat,
            "correlated_incidents": correlated_count,
            "total_financial_overrun": round(total_overrun, 2),
            "currency": "USD",
            "triaged_count": triaged_count,
            "triaged_live_count": triaged_live_count,
            "triaged_fallback_count": triaged_fallback_count,
            "storage_mode": "persistent" if is_postgres else "in_memory",
            "durable": is_postgres,
            "database_degraded": getattr(app, "db_degraded", False),
            "ai_provider_status": ai_cfg,
        }), 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)