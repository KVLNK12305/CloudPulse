import json
import pytest
from unittest.mock import MagicMock, patch

from app import create_app
from database.postgres import InMemoryDatabase
from models.finding import Finding, ResourceInfo, IdentityInfo, EvidenceInfo, SeverityLevel
from models.incident import Incident, IncidentStatus
from telemetry.cost_baseline import InMemoryCostBaselineStore
from telemetry.cost_management import (
    CostManagementClient,
    CostManagementQueryError,
    CostManagementRbacError,
    CostManagementRateLimitError,
)
from telemetry.monitor_metrics import (
    AzureMonitorMetricsClient,
    AzureMonitorMetricsError,
    AzureMonitorMetricsAuthenticationError,
    AzureMonitorMetricsPermissionError,
    AzureMonitorMetricsNotFoundError,
)
from telemetry.resource_graph import ResourceGraphClient, ResourceGraphQueryError


@pytest.fixture
def mock_clients():
    db = InMemoryDatabase()
    cost_store = InMemoryCostBaselineStore()
    mock_arg = MagicMock(spec=ResourceGraphClient)
    mock_cost = MagicMock(spec=CostManagementClient)
    mock_metrics = MagicMock(spec=AzureMonitorMetricsClient)

    app = create_app(
        db_repo=db,
        arg_client=mock_arg,
        cost_client=mock_cost,
        cost_store=cost_store,
        metrics_client=mock_metrics,
    )
    client = app.test_client()

    return {
        "db": db,
        "cost_store": cost_store,
        "arg_client": mock_arg,
        "cost_client": mock_cost,
        "metrics_client": mock_metrics,
        "app": app,
        "client": client,
    }


# ---------------------------------------------------------------------------
# 1. Resource Graph Inventory API Tests (Phase 2)
# ---------------------------------------------------------------------------

def test_resource_inventory_api_success(mock_clients):
    c = mock_clients["client"]
    arg = mock_clients["arg_client"]
    cost = mock_clients["cost_client"]
    db = mock_clients["db"]

    # Mock ARG inventory response
    sample_res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"
    arg.get_resource_inventory.return_value = [
        {
            "id": sample_res_id,
            "name": "cloudpulse-postgres01",
            "type": "microsoft.dbforpostgresql/flexibleservers",
            "location": "centralindia",
            "resourceGroup": "cloudpulse-rg",
            "subscriptionId": "90b900ea-4273-4b40-a343-091aecfe2911",
            "provisioningState": "Succeeded",
            "sku": {"name": "Standard_B1ms"},
            "tags": {},
        }
    ]

    # Mock cost summary enrichment
    cost.get_cost_summary.return_value = {
        "has_data": True,
        "currency": "INR",
        "by_resource": [
            {
                "resource_id": sample_res_id,
                "total_cost": 42.50,
                "currency": "INR",
                "cost_category": "Database",
            }
        ],
    }

    # Add a finding in DB to test enrichment
    finding = Finding(
        finding_id="F-TEST-01",
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-08T12:00:00Z",
        resource=ResourceInfo(
            id=sample_res_id,
            name="cloudpulse-postgres01",
            type="microsoft.dbforpostgresql/flexibleservers",
            resource_group="cloudpulse-rg",
        ),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(operation="write", activity_log_event_id="evt-01"),
        confidence=0.95,
    )
    db.save_finding(finding)

    resp = c.get("/api/resources")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["count"] == 1
    assert data["source"] == "Azure Resource Graph"

    res = data["resources"][0]
    assert res["name"] == "cloudpulse-postgres01"
    assert res["actual_cost"] == 42.50
    assert res["currency"] == "INR"
    assert res["cost_category"] == "Database"
    assert res["findings_count"] == 1
    assert res["max_severity"] == "HIGH"
    assert "F-TEST-01" in res["finding_ids"]


def test_resource_inventory_filters(mock_clients):
    c = mock_clients["client"]
    arg = mock_clients["arg_client"]

    arg.get_resource_inventory.return_value = [
        {
            "id": "/subscriptions/sub-1/resourceGroups/cloudpulse-rg/providers/Microsoft.App/containerApps/app-1",
            "name": "app-1",
            "type": "microsoft.app/containerapps",
            "location": "centralindia",
            "resourceGroup": "cloudpulse-rg",
            "subscriptionId": "sub-1",
        },
        {
            "id": "/subscriptions/sub-1/resourceGroups/cloudpulse-rg/providers/Microsoft.Storage/storageAccounts/st-1",
            "name": "st-1",
            "type": "microsoft.storage/storageaccounts",
            "location": "centralindia",
            "resourceGroup": "cloudpulse-rg",
            "subscriptionId": "sub-1",
        },
    ]

    # Search filter matching only app-1
    resp = c.get("/api/resources?search=app")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 1
    assert data["resources"][0]["name"] == "app-1"


def test_resource_inventory_api_error_handling(mock_clients):
    c = mock_clients["client"]
    arg = mock_clients["arg_client"]

    arg.get_resource_inventory.side_effect = ResourceGraphQueryError("ARG service unavailable")
    resp = c.get("/api/resources")
    assert resp.status_code == 502
    data = resp.get_json()
    assert data["status"] == "error"
    assert "ARG service unavailable" in data["message"]


def test_resource_inventory_client_none():
    app = create_app(db_repo=InMemoryDatabase(), arg_client=None)
    # Monkeypatch graph_client to None
    client = app.test_client()
    resp = client.get("/api/resources")
    assert resp.status_code == 503
    data = resp.get_json()
    assert "ResourceGraphClient is not configured" in data["message"]


# ---------------------------------------------------------------------------
# 2. Cost Aggregation & FinOps API Tests (Phase 3)
# ---------------------------------------------------------------------------

def test_finops_cost_summary_api_success(mock_clients):
    c = mock_clients["client"]
    cost = mock_clients["cost_client"]

    cost.get_cost_summary.return_value = {
        "has_data": True,
        "scope": "/subscriptions/sub-1",
        "currency": "INR",
        "period": {
            "start_date": "2026-09-24",
            "end_date": "2026-10-07",
            "latest_usage_date": "2026-10-07",
            "billing_latency_notice": "Subject to 24-48h reconciliation latency.",
        },
        "summary": {
            "total_cost": 21.43,
            "total_records": 10,
            "resource_count": 4,
        },
        "by_resource": [],
        "by_category": {"Container": 7.37, "Storage": 0.05},
        "by_service": {"Container Apps": 7.37},
        "top_cost_drivers": [
            {
                "resource_name": "app-1",
                "total_cost": 7.37,
                "currency": "INR",
                "percentage_of_total": 34.4,
            }
        ],
    }

    resp = c.get("/api/finops/costs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["has_data"] is True
    assert data["currency"] == "INR"
    assert data["summary"]["total_cost"] == 21.43
    assert data["source"] == "Azure Cost Management"
    assert len(data["top_cost_drivers"]) == 1


def test_finops_cost_summary_missing_billing_data(mock_clients):
    c = mock_clients["client"]
    cost = mock_clients["cost_client"]

    cost.get_cost_summary.return_value = {
        "has_data": False,
        "scope": "/subscriptions/sub-1",
        "currency": "USD",
        "period": {
            "start_date": "2026-09-24",
            "end_date": "2026-10-07",
            "latest_usage_date": None,
            "billing_latency_notice": "No billing records found.",
        },
        "summary": {"total_cost": 0.0, "total_records": 0, "resource_count": 0},
        "by_resource": [],
        "by_category": {},
        "by_service": {},
        "top_cost_drivers": [],
        "message": "No billing data available for selected period",
    }

    resp = c.get("/api/finops/costs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["has_data"] is False
    assert data["message"] == "No billing data available for selected period"


def test_finops_cost_rbac_forbidden(mock_clients):
    c = mock_clients["client"]
    cost = mock_clients["cost_client"]

    cost.get_cost_summary.side_effect = CostManagementRbacError("403 Forbidden: Cost Management Reader required")
    resp = c.get("/api/finops/costs")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["error_type"] == "RBAC_FORBIDDEN"


def test_finops_cost_rate_limit_exceeded(mock_clients):
    c = mock_clients["client"]
    cost = mock_clients["cost_client"]

    cost.get_cost_summary.side_effect = CostManagementRateLimitError("429 Too Many Requests")
    resp = c.get("/api/finops/costs")
    assert resp.status_code == 429
    data = resp.get_json()
    assert data["error_type"] == "RATE_LIMIT_EXCEEDED"


# ---------------------------------------------------------------------------
# 3. Azure Monitor Metrics API Tests (Phase 4)
# ---------------------------------------------------------------------------

def test_monitor_metrics_resource_id_validation():
    client = AzureMonitorMetricsClient(credential=MagicMock())

    valid_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"
    assert client.validate_resource_id(valid_id) is True

    invalid_ids = [
        "",
        "not-a-resource-id",
        "/subscriptions/sub1/no-resource-group",
        "https://portal.azure.com/resource/123",
        None,
    ]
    for bad in invalid_ids:
        assert client.validate_resource_id(bad) is False


def test_monitor_metrics_supported_resource():
    client = AzureMonitorMetricsClient(credential=MagicMock())

    res_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"
    raw_arm_response = {
        "value": [
            {
                "name": {"value": "cpu_percent", "localizedValue": "CPU percent"},
                "unit": "Percent",
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2026-10-08T12:00:00Z", "average": 7.5},
                            {"timeStamp": "2026-10-08T12:01:00Z", "average": 8.2},
                        ]
                    }
                ],
            },
            {
                "name": {"value": "active_connections", "localizedValue": "Active Connections"},
                "unit": "Count",
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2026-10-08T12:01:00Z", "average": 8.0}
                        ]
                    }
                ],
            },
        ]
    }

    with patch.object(client, "_get_access_token", return_value="fake-token"):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(raw_arm_response).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = client.get_resource_metrics(res_id)

    assert result["supported"] is True
    assert result["metrics_available"] is True
    assert result["source"] == "Azure Monitor"

    metrics = result["metrics"]
    assert "cpu_percent" in metrics
    assert metrics["cpu_percent"]["latest_value"] == 8.2
    assert metrics["cpu_percent"]["unit"] == "Percent"
    assert len(metrics["cpu_percent"]["history"]) == 2

    assert "active_connections" in metrics
    assert metrics["active_connections"]["latest_value"] == 8.0


def test_monitor_metrics_unsupported_resource_type():
    client = AzureMonitorMetricsClient(credential=MagicMock())
    dns_res_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/private.postgres.database.azure.com"

    result = client.get_resource_metrics(dns_res_id)
    assert result["supported"] is False
    assert result["metrics_available"] is False
    assert result["message"] == "Metrics unavailable for this resource type"


def test_monitor_metrics_endpoint_success(mock_clients):
    c = mock_clients["client"]
    metrics_client = mock_clients["metrics_client"]

    res_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"
    metrics_client.get_resource_metrics.return_value = {
        "resource_id": res_id,
        "supported": True,
        "metrics_available": True,
        "source": "Azure Monitor",
        "metrics": {
            "cpu_percent": {"latest_value": 7.8, "unit": "Percent"},
        },
    }

    resp = c.get(f"/api/resources{res_id}/metrics")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["supported"] is True
    assert data["metrics"]["cpu_percent"]["latest_value"] == 7.8


def test_monitor_metrics_endpoint_auth_failure(mock_clients):
    c = mock_clients["client"]
    metrics_client = mock_clients["metrics_client"]

    res_id = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"
    metrics_client.get_resource_metrics.side_effect = AzureMonitorMetricsAuthenticationError("Auth failed")

    resp = c.get(f"/api/resources{res_id}/metrics")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["status"] == "error"


# ---------------------------------------------------------------------------
# 4. Resource Detail Aggregation Tests (Phase 5)
# ---------------------------------------------------------------------------

def test_resource_detail_aggregation(mock_clients):
    c = mock_clients["client"]
    arg = mock_clients["arg_client"]
    cost = mock_clients["cost_client"]
    metrics = mock_clients["metrics_client"]
    db = mock_clients["db"]

    res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/cloudpulse-postgres01"

    # Mock ARG metadata
    arg.query.return_value = [
        {
            "id": res_id,
            "name": "cloudpulse-postgres01",
            "type": "microsoft.dbforpostgresql/flexibleservers",
            "location": "centralindia",
            "resourceGroup": "cloudpulse-rg",
            "subscriptionId": "90b900ea-4273-4b40-a343-091aecfe2911",
            "provisioningState": "Succeeded",
        }
    ]

    # Mock Cost Management
    cost.get_cost_summary.return_value = {
        "has_data": True,
        "currency": "INR",
        "by_resource": [
            {
                "resource_id": res_id,
                "total_cost": 15.00,
                "currency": "INR",
                "cost_category": "Database",
                "meters": [{"meter_name": "Flexible Server vCPU", "cost": 15.00}],
            }
        ],
    }

    # Mock Metrics
    metrics.get_resource_metrics.return_value = {
        "supported": True,
        "metrics_available": True,
        "source": "Azure Monitor",
        "metrics": {"cpu_percent": {"latest_value": 7.8, "unit": "Percent"}},
    }

    # Add security finding and incident
    finding = Finding(
        finding_id="F-TEST-DET-01",
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(
            id=res_id,
            name="cloudpulse-postgres01",
            type="microsoft.dbforpostgresql/flexibleservers",
            resource_group="cloudpulse-rg",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(operation="write", activity_log_event_id="evt-02"),
        confidence=0.90,
    )
    db.save_finding(finding)

    incident = Incident(
        incident_id="INC-TEST-01",
        title="PostgreSQL Operational Event",
        severity=SeverityLevel.MEDIUM,
        status=IncidentStatus.OPEN,
        resource=ResourceInfo(
            id=res_id,
            name="cloudpulse-postgres01",
            type="microsoft.dbforpostgresql/flexibleservers",
            resource_group="cloudpulse-rg",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        findings=["F-TEST-DET-01"],
        timeline=[],
        created_at="2026-10-08T10:00:00Z",
        updated_at="2026-10-08T10:00:00Z",
    )
    db.save_incident(incident)

    resp = c.get(f"/api/resources{res_id}")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["status"] == "success"
    assert data["resource"]["name"] == "cloudpulse-postgres01"
    assert data["cost"]["has_billing_data"] is True
    assert data["cost"]["total_cost"] == 15.00
    assert data["utilization"]["supported"] is True
    assert data["security"]["findings_count"] == 1
    assert data["incidents"]["count"] == 1

    # Source Attributions check (Phase 8 requirement)
    sources = data["source_attributions"]
    assert sources["resource"] == "Azure Resource Graph"
    assert sources["cost"] == "Azure Cost Management"
    assert sources["utilization"] == "Azure Monitor"
    assert sources["security"] == "CloudPulse Detection Engine"
    assert sources["incidents"] == "CloudPulse PostgreSQL state"


# ---------------------------------------------------------------------------
# 5. Estate Overview API Tests (Phase 6)
# ---------------------------------------------------------------------------

def test_estate_overview_api(mock_clients):
    c = mock_clients["client"]
    arg = mock_clients["arg_client"]
    cost = mock_clients["cost_client"]

    arg.get_resource_inventory.return_value = [
        {"type": "microsoft.app/containerapps"},
        {"type": "microsoft.dbforpostgresql/flexibleservers"},
    ]

    cost.get_cost_summary.return_value = {
        "has_data": True,
        "summary": {"total_cost": 50.0},
        "currency": "INR",
        "by_category": {"Container": 30.0, "Database": 20.0},
        "period": {
            "billing_latency_notice": "Latency 24-48h",
            "latest_usage_date": "2026-10-07",
        },
    }

    resp = c.get("/api/estate/overview")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["resources"]["total"] == 2
    assert data["costs"]["total_cost"] == 50.0
    assert data["costs"]["currency"] == "INR"
    assert data["source_attributions"]["inventory"] == "Azure Resource Graph"
    assert data["source_attributions"]["costs"] == "Azure Cost Management"
