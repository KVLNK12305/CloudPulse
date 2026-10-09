"""
Regression Test Suite for CloudPulse Dashboard Audit & Remediation.

Validates:
1. Estate overview representation of missing/delayed cost data (None vs fake 0.0).
2. Estate overview representation of live cost telemetry.
3. Resource detail provenance attribution (discovered_in_arg True vs False).
4. Fabricated fallback attribution in source_attributions dictionary.
5. Dashboard summary contract currency inclusion.
6. Incident status PATCH payload validation (missing/invalid status rejected with 400).
7. Incident timeline strict chronological ordering.
8. Incident findings resolution with missing_findings_count.
9. FinOps cost error status propagation (HTTP 429 for rate-limiting, HTTP 403 for RBAC).
10. Server-side remediation approval rejection for unrecommended/unregistered actions.
"""

import json
import pytest
from unittest.mock import MagicMock

from app import create_app
from database.postgres import InMemoryDatabase
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
)
from models.incident import Incident, IncidentStatus
from telemetry.cost_baseline import InMemoryCostBaselineStore
from telemetry.cost_management import (
    CostManagementClient,
    CostManagementRateLimitError,
    CostManagementRbacError,
)
from telemetry.monitor_metrics import AzureMonitorMetricsClient
from telemetry.resource_graph import ResourceGraphClient


@pytest.fixture
def audit_app_context():
    db = InMemoryDatabase()
    cost_store = InMemoryCostBaselineStore()
    mock_arg = MagicMock(spec=ResourceGraphClient)
    mock_cost = MagicMock(spec=CostManagementClient)
    mock_metrics = MagicMock(spec=AzureMonitorMetricsClient)
    mock_metrics.get_resource_metrics.return_value = {
        "supported": False,
        "metrics_available": False,
        "metrics": {},
        "message": "Metrics not supported",
        "source": "Azure Monitor",
    }

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
# 1. Estate Overview: Accurate Missing Cost Representation
# ---------------------------------------------------------------------------

def test_estate_overview_missing_cost_data_returns_none(audit_app_context):
    """When Cost Management has no data (24-48h latency), total_cost must be None, not fake 0.0."""
    c = audit_app_context["client"]
    cost = audit_app_context["cost_client"]
    arg = audit_app_context["arg_client"]

    arg.get_resource_inventory.return_value = [{"type": "microsoft.compute/virtualmachines"}]
    cost.get_cost_summary.return_value = {
        "has_data": False,
        "summary": {"total_cost": 0.0},
        "currency": "USD",
        "period": {"billing_latency_notice": "No closed billing data (24-48h delay)"},
    }

    resp = c.get("/api/estate/overview")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["costs"]["has_data"] is False
    assert data["costs"]["total_cost"] is None, "Missing cost data must not be represented as 0.0"


def test_estate_overview_with_cost_data_returns_actual_total(audit_app_context):
    """When Cost Management has closed billing data, total_cost reflects actual spend."""
    c = audit_app_context["client"]
    cost = audit_app_context["cost_client"]
    arg = audit_app_context["arg_client"]

    arg.get_resource_inventory.return_value = [{"type": "microsoft.compute/virtualmachines"}]
    cost.get_cost_summary.return_value = {
        "has_data": True,
        "summary": {"total_cost": 142.50},
        "currency": "USD",
        "period": {"latest_usage_date": "2026-10-08"},
    }

    resp = c.get("/api/estate/overview")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["costs"]["has_data"] is True
    assert data["costs"]["total_cost"] == 142.50
    assert data["costs"]["currency"] == "USD"


# ---------------------------------------------------------------------------
# 2. Resource Detail: Provenance & Fabricated Fallback Attribution
# ---------------------------------------------------------------------------

def test_resource_detail_unindexed_provenance(audit_app_context):
    """Resources not discovered in ARG must be attributed to fabricated fallback."""
    c = audit_app_context["client"]
    arg = audit_app_context["arg_client"]
    cost = audit_app_context["cost_client"]

    # ARG query returns empty list
    arg.query.return_value = []
    cost.get_cost_summary.return_value = {"has_data": False, "by_resource": []}

    res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
    resp = c.get(f"/api/resources{res_id}")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["resource"]["discovered_in_arg"] is False
    assert data["source_attributions"]["resource"] == "Fabricated fallback (Resource not found in Azure Resource Graph)"


def test_resource_detail_indexed_provenance(audit_app_context):
    """Resources discovered in ARG must be accurately attributed to Azure Resource Graph."""
    c = audit_app_context["client"]
    arg = audit_app_context["arg_client"]
    cost = audit_app_context["cost_client"]

    res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker"
    arg.query.return_value = [{
        "id": res_id,
        "name": "nsg-worker",
        "type": "microsoft.network/networksecuritygroups",
        "location": "centralindia",
        "resourceGroup": "cloudpulse-rg",
        "subscriptionId": "90b900ea-4273-4b40-a343-091aecfe2911",
        "provisioningState": "Succeeded",
    }]
    cost.get_cost_summary.return_value = {"has_data": False, "by_resource": []}

    resp = c.get(f"/api/resources{res_id}")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["resource"]["discovered_in_arg"] is True
    assert data["source_attributions"]["resource"] == "Azure Resource Graph"


# ---------------------------------------------------------------------------
# 3. Dashboard Summary API Contract
# ---------------------------------------------------------------------------

def test_dashboard_summary_contract_currency(audit_app_context):
    """GET /api/dashboard/summary must include currency unit."""
    c = audit_app_context["client"]
    resp = c.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "currency" in data
    assert data["currency"] == "USD"
    assert "total_financial_overrun" in data
    assert "total_incidents" in data


# ---------------------------------------------------------------------------
# 4. Incident Status Mutation Validation
# ---------------------------------------------------------------------------

def test_patch_incident_status_validation(audit_app_context):
    """PATCH /api/incidents/<id> validates payload strictly."""
    c = audit_app_context["client"]
    db = audit_app_context["db"]

    inc = Incident(
        incident_id="INC-AUDIT-01",
        title="Audit Test Incident",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        resource=ResourceInfo(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        findings=[],
        timeline=[],
    )
    db.save_incident(inc)

    # 1. Missing status field -> 400
    resp_empty = c.patch(f"/api/incidents/{inc.incident_id}", json={})
    assert resp_empty.status_code == 400
    assert "status' is required" in resp_empty.get_json()["error"]

    # 2. Invalid status value -> 400
    resp_invalid = c.patch(f"/api/incidents/{inc.incident_id}", json={"status": "INVALID_STATE"})
    assert resp_invalid.status_code == 400
    assert "Invalid status" in resp_invalid.get_json()["error"]

    # 3. Valid status -> 200 and audit timeline appended
    resp_valid = c.patch(f"/api/incidents/{inc.incident_id}", json={"status": "INVESTIGATING", "caller": "secops"})
    assert resp_valid.status_code == 200
    updated = resp_valid.get_json()
    assert updated["status"] == "INVESTIGATING"
    assert len(updated["timeline"]) == 1
    assert updated["timeline"][0]["event"] == "STATUS_UPDATED"


# ---------------------------------------------------------------------------
# 5. Incident Timeline Chronological Ordering
# ---------------------------------------------------------------------------

def test_incident_timeline_chronological_ordering(audit_app_context):
    """GET /api/incidents/<id>/timeline must return entries sorted chronologically."""
    c = audit_app_context["client"]
    db = audit_app_context["db"]

    inc = Incident(
        incident_id="INC-TIMELINE-01",
        title="Chronology Test Incident",
        severity=SeverityLevel.MEDIUM,
        status=IncidentStatus.OPEN,
        resource=ResourceInfo(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        findings=[],
        timeline=[
            {"timestamp": "2026-10-08T15:00:00Z", "event": "LATER_EVENT"},
            {"timestamp": "2026-10-08T10:00:00Z", "event": "EARLIER_EVENT"},
            {"timestamp": "2026-10-08T12:00:00Z", "event": "MIDDLE_EVENT"},
        ],
    )
    db.save_incident(inc)

    resp = c.get(f"/api/incidents/{inc.incident_id}/timeline")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 3
    timestamps = [e["timestamp"] for e in data["timeline"]]
    assert timestamps == [
        "2026-10-08T10:00:00Z",
        "2026-10-08T12:00:00Z",
        "2026-10-08T15:00:00Z",
    ], "Timeline events must be ordered chronologically"


# ---------------------------------------------------------------------------
# 6. Incident Findings & Missing Count Tracking
# ---------------------------------------------------------------------------

def test_incident_findings_missing_count(audit_app_context):
    """GET /api/incidents/<id>/findings tracks missing findings if purged."""
    c = audit_app_context["client"]
    db = audit_app_context["db"]

    finding = Finding(
        finding_id="F-EXIST-01",
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.LOW,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(operation="write", activity_log_event_id="evt-01"),
        confidence=0.9,
    )
    db.save_finding(finding)

    inc = Incident(
        incident_id="INC-FINDINGS-01",
        title="Findings Resolution Test",
        severity=SeverityLevel.LOW,
        status=IncidentStatus.OPEN,
        resource=ResourceInfo(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        findings=["F-EXIST-01", "F-PURGED-99"],  # One exists, one is missing
        timeline=[],
    )
    db.save_incident(inc)

    resp = c.get(f"/api/incidents/{inc.incident_id}/findings")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 1
    assert data["missing_findings_count"] == 1
    assert data["findings"][0]["finding_id"] == "F-EXIST-01"


# ---------------------------------------------------------------------------
# 7. FinOps Costs API Error Propagation (Rate Limit & RBAC)
# ---------------------------------------------------------------------------

def test_finops_costs_rate_limit_propagation(audit_app_context):
    """When Cost Management hits rate limits (429), API returns HTTP 429."""
    c = audit_app_context["client"]
    cost = audit_app_context["cost_client"]

    cost.get_cost_summary.side_effect = CostManagementRateLimitError("Too Many Requests: Rate limit exceeded")

    resp = c.get("/api/finops/costs")
    assert resp.status_code == 429
    data = resp.get_json()
    assert data["error_type"] == "RATE_LIMIT_EXCEEDED"


def test_finops_costs_rbac_propagation(audit_app_context):
    """When Cost Management returns RBAC forbidden (403), API returns HTTP 403."""
    c = audit_app_context["client"]
    cost = audit_app_context["cost_client"]

    cost.get_cost_summary.side_effect = CostManagementRbacError("Principal lacks Cost Management Reader role")

    resp = c.get("/api/finops/costs")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["error_type"] == "RBAC_FORBIDDEN"


# ---------------------------------------------------------------------------
# 8. Server-Side Remediation Authorization Guard
# ---------------------------------------------------------------------------

def test_approval_unregistered_action_rejected(audit_app_context):
    """Approving an unrecommended/unregistered action ID is rejected server-side."""
    c = audit_app_context["client"]
    db = audit_app_context["db"]

    inc = Incident(
        incident_id="INC-AUTH-01",
        title="Unauthorized Approval Test",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        resource=ResourceInfo(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        findings=[],
        timeline=[],
        ai_analysis=None,
    )
    db.save_incident(inc)

    # Attempt to approve bogus action ID
    resp = c.post(f"/api/incidents/{inc.incident_id}/actions/bogus-action-id/approval", json={
        "status": "APPROVED",
        "operator": "attacker",
    })
    assert resp.status_code == 400
    data = resp.get_json()
    assert "not registered" in data["message"]
