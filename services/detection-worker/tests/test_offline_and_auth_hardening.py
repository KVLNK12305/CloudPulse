"""
Regression tests for the post-decommission hardening:
  - dev-only auth shortcuts are off by default
  - unknown emails never gain elevated personas
  - AI recommendations map to remediation types by their own intent
  - remediation refuses to execute when Azure integration is disabled
"""

from unittest.mock import patch, MagicMock

import pytest

from app import create_app
from database.postgres import InMemoryDatabase
from models.remediation import RemediationActionType
from services.auth_service import AuthService
from services.remediation_service import (
    RemediationService,
    RemediationUnavailableError,
    RemediationAdvisoryError,
)


# --- Auth ---

def test_dev_passcode_rejected_when_dev_auth_disabled():
    svc = AuthService()
    with patch("services.auth_service.config") as cfg:
        cfg.DEV_AUTH_ENABLED = False
        res = svc.verify_otp("someone@example.com", "123456")
    assert res["success"] is False
    assert "token" not in res


def test_dev_passcode_accepted_only_when_enabled():
    svc = AuthService()
    with patch("services.auth_service.config") as cfg:
        cfg.DEV_AUTH_ENABLED = True
        cfg.SUPABASE_JWT_SECRET = ""
        cfg.SUPABASE_URL = ""
        res = svc.verify_otp("someone@example.com", "123456")
    assert res["success"] is True


@pytest.mark.parametrize("email", ["kushal.attacker@evil.com", "random@example.com"])
def test_unknown_email_gets_read_only_observer(email):
    user = AuthService()._resolve_user_profile(email)
    assert user["isSuperAdmin"] is False
    assert user["allowedPersonas"] == ["executive"]
    assert "secops" not in user["allowedPersonas"]


def test_operator_login_disabled_by_default():
    app = create_app(db_repo=InMemoryDatabase())
    with patch("app.config") as cfg:
        cfg.DEV_AUTH_ENABLED = False
        res = app.test_client().post("/api/auth/operator-login", json={"email": "x@example.com"})
    assert res.status_code == 403


def test_auth_status_does_not_expose_roster():
    app = create_app(db_repo=InMemoryDatabase())
    data = app.test_client().get("/api/auth/status").get_json()
    assert "roster" not in data


# --- Recommendation → remediation mapping ---

@pytest.mark.parametrize(
    "action, findings, expected",
    [
        ({"category": "MONITORING", "title": "Acknowledge and Monitor Workload"},
         {"SUSPICIOUS_OUTBOUND_ACTIVITY"}, RemediationActionType.ADVISORY),
        ({"category": "INVESTIGATION", "title": "Inspect Workload Sockets and Processes"},
         {"SUSPICIOUS_OUTBOUND_ACTIVITY"}, RemediationActionType.ADVISORY),
        ({"category": "CONTAINMENT", "title": "Block Malicious Destination Egress"},
         {"SUSPICIOUS_OUTBOUND_ACTIVITY"}, RemediationActionType.ISOLATE_WORKLOAD),
        ({"category": "CONTAINMENT", "title": "Restrict Inbound NSG Exposure"},
         {"UNEXPECTED_PUBLIC_EXPOSURE", "SUSPICIOUS_OUTBOUND_ACTIVITY"}, RemediationActionType.DISABLE_PUBLIC_INGRESS),
        # Containment intent without matching evidence must not mutate anything
        ({"category": "CONTAINMENT", "title": "Restrict Inbound NSG Exposure"},
         {"SUSPICIOUS_OUTBOUND_ACTIVITY"}, RemediationActionType.ADVISORY),
    ],
)
def test_classify_recommended_action(action, findings, expected):
    assert RemediationService.classify_recommended_action(action, findings) == expected


# --- Offline remediation ---

def _approved_incident(db, action_type):
    from models.incident import Incident, IncidentStatus
    from models.finding import SeverityLevel
    from models.remediation import RemediationContainer, RemediationRecord, RemediationStatus, ApprovalDetails

    record = RemediationRecord(
        remediation_id="REM-1",
        incident_id="INC-OFF-1",
        action_id="ACT-01",
        action_type=action_type,
        status=RemediationStatus.APPROVED,
        target_resource_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
        approval=ApprovalDetails(status="APPROVED", operator="op@example.com", timestamp="2026-01-01T00:00:00Z"),
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    container = RemediationContainer(actions={"ACT-01": record})
    inc = Incident(
        incident_id="INC-OFF-1",
        title="t",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        resource={"id": record.target_resource_id, "name": "vm", "type": "Microsoft.Compute/virtualMachines",
                  "resource_group": "rg", "subscription_id": "s"},
        identity={"caller": "op@example.com"},
        findings=[],
        remediation=container.to_dict(),
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    db.save_incident(inc)
    return inc


def test_execute_refused_when_azure_disabled():
    db = InMemoryDatabase()
    _approved_incident(db, RemediationActionType.ISOLATE_WORKLOAD)
    svc = RemediationService(db_repo=db, azure_enabled=False)
    with pytest.raises(RemediationUnavailableError):
        svc.execute_remediation("INC-OFF-1", "ACT-01")
    # Nothing was attempted, so the incident is untouched
    assert db.get_incident("INC-OFF-1").status.value == "OPEN"


def test_execute_refused_for_advisory_action():
    db = InMemoryDatabase()
    _approved_incident(db, RemediationActionType.ADVISORY)
    svc = RemediationService(db_repo=db, network_client=MagicMock())
    with pytest.raises(RemediationAdvisoryError):
        svc.execute_remediation("INC-OFF-1", "ACT-01")


def test_execute_endpoint_returns_503_offline():
    db = InMemoryDatabase()
    _approved_incident(db, RemediationActionType.ISOLATE_WORKLOAD)
    app = create_app(db_repo=db, remediation_svc=RemediationService(db_repo=db, azure_enabled=False))
    res = app.test_client().post("/api/incidents/INC-OFF-1/remediation/execute", json={"action_id": "ACT-01"})
    assert res.status_code == 503
    assert res.get_json()["error_type"] == "AZURE_INTEGRATION_DISABLED"
