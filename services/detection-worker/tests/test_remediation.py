"""
Comprehensive unit test suite for CloudPulse Controlled Remediation Subsystem.

Covers:
  1.  valid DISABLE_PUBLIC_INGRESS
  2.  mismatched port precondition
  3.  mismatched protocol precondition
  4.  already-denied rule
  5.  already-remediated idempotency
  6.  unrelated NSG rule protection
  7.  original state capture
  8.  successful mutation
  9.  ARM 403 error handling
  10. ARM 404 error handling
  11. ARM 409 conflict retry
  12. verification success
  13. verification failure
  14. unapproved execution rejection
  15. invalid action type
  16. target resource mismatch
  17. duplicate execution idempotency
  18. concurrent execution protection
  19. timeline audit ordering
  20. multi-action incident persistence
  21. AI cannot control target
  22. AI cannot inject executable commands
  23. isolation rule creation
  24. isolation idempotency
  25. isolation verification
  26. incident resolves only after verification
"""

import pytest
from unittest.mock import MagicMock, patch

from database.postgres import InMemoryDatabase
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
    generate_exposure_finding_id,
    generate_outbound_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from models.remediation import (
    RemediationActionType,
    RemediationStatus,
    RemediationRecord,
    RemediationContainer,
    ApprovalDetails,
    ExecutionDetails,
    VerificationDetails,
    generate_deterministic_remediation_id,
)
from services.azure_network_client import (
    AzureNetworkClient,
    AzureNetworkError,
    AzureNetworkAuthError,
    AzureNetworkNotFoundError,
    AzureNetworkConflictError,
)
from services.remediation_service import (
    RemediationService,
    RemediationError,
    RemediationUnapprovedError,
    RemediationPreconditionError,
    RemediationVerificationError,
)


RES_ID = "/subscriptions/sub-123/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
NSG_ID = "/subscriptions/sub-123/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker"


@pytest.fixture
def db_repo():
    return InMemoryDatabase()


@pytest.fixture
def mock_net_client():
    client = MagicMock(spec=AzureNetworkClient)
    client.subscription_id = "sub-123"
    return client


@pytest.fixture
def remediation_service(db_repo, mock_net_client):
    return RemediationService(db_repo=db_repo, network_client=mock_net_client)


def _setup_upe_incident(db_repo):
    """Setup an incident with a verified UNEXPECTED_PUBLIC_EXPOSURE finding."""
    f_upe = Finding(
        finding_id=generate_exposure_finding_id(RES_ID, f"{NSG_ID}/securityRules/Allow-SSH-Internet", "Tcp", "22"),
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-09T01:00:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-worker-01", resource_group="cloudpulse-rg"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-upe-1",
            exposure_type="MANAGEMENT_PORT",
            destination_port="22",
            protocol="Tcp",
            source_address_prefix="*",
            nsg_id=NSG_ID,
            nsg_rule_name="Allow-SSH-Internet",
        ),
        confidence=0.95,
    )
    db_repo.save_finding(f_upe)

    inc_id = generate_deterministic_incident_id(RES_ID)
    incident = Incident(
        incident_id=inc_id,
        title="Unexpected Public Exposure: vm-worker-01 (SSH 22)",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        created_at="2026-10-09T01:00:00Z",
        updated_at="2026-10-09T01:00:00Z",
        resource=f_upe.resource,
        identity=f_upe.identity,
        findings=[f_upe.finding_id],
        timeline=[],
        remediation=None,
    )
    db_repo.save_incident(incident)
    return incident, f_upe


def _setup_soa_incident(db_repo):
    """Setup an incident with a verified SUSPICIOUS_OUTBOUND_ACTIVITY finding."""
    f_soa = Finding(
        finding_id=generate_outbound_finding_id(RES_ID, "198.51.100.77", "443", "VOLUME_SPIKE", 0),
        finding_type="SUSPICIOUS_OUTBOUND_ACTIVITY",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-09T01:10:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-worker-01", resource_group="cloudpulse-rg"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="FLOW_LOG_EGRESS",
            activity_log_event_id="flow-soa-1",
            destination_ip="198.51.100.77",
            destination_port="443",
            bytes_sent=15000000000,
            source_ip="10.50.3.10",
            nsg_id=NSG_ID,
            anomaly_type="VOLUME_SPIKE",
        ),
        confidence=0.90,
    )
    db_repo.save_finding(f_soa)

    inc_id = generate_deterministic_incident_id(RES_ID)
    incident = Incident(
        incident_id=inc_id,
        title="Suspicious Outbound Activity: vm-worker-01",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        created_at="2026-10-09T01:10:00Z",
        updated_at="2026-10-09T01:10:00Z",
        resource=f_soa.resource,
        identity=f_soa.identity,
        findings=[f_soa.finding_id],
        timeline=[],
        remediation=None,
    )
    db_repo.save_incident(incident)
    return incident, f_soa


# ---------------------------------------------------------------------------
# Tests: DISABLE_PUBLIC_INGRESS
# ---------------------------------------------------------------------------

def test_1_valid_disable_public_ingress_success(remediation_service, db_repo, mock_net_client):
    """Test full pipeline: proposal -> approval -> precondition -> mutation -> verification -> incident resolved."""
    incident, f = _setup_upe_incident(db_repo)

    # 1. Proposal
    rec = remediation_service.propose_action_from_recommendation(
        incident=incident,
        action_id="ACT-01",
        action_type=RemediationActionType.DISABLE_PUBLIC_INGRESS,
        target_finding_id=f.finding_id,
    )
    assert rec.status == RemediationStatus.PROPOSED
    assert rec.target_rule_name == "Allow-SSH-Internet"

    # 2. Approval
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED", "secops-operator")

    # Mock Azure live state before mutation
    mock_net_client.get_security_rule.side_effect = [
        # Precondition check: live rule is Allow
        {
            "name": "Allow-SSH-Internet",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "destination_port_range": "22",
            "source_address_prefix": "*",
        },
        # Verification check: live rule is now Deny
        {
            "name": "Allow-SSH-Internet",
            "priority": 100,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "Tcp",
            "destination_port_range": "22",
            "source_address_prefix": "*",
        },
    ]

    # 3. Execution
    executed_rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")

    assert executed_rec.status == RemediationStatus.VERIFIED
    assert executed_rec.verification.is_compliant is True
    assert executed_rec.verification.verified_state == "ACCESS_DENIED"

    # Verify mutation called with access=Deny
    mock_net_client.create_or_update_security_rule.assert_called_once()
    args, kwargs = mock_net_client.create_or_update_security_rule.call_args
    assert kwargs["rule_parameters"]["access"] == "Deny"
    assert kwargs["rule_parameters"]["priority"] == 100

    # Incident status should now be RESOLVED
    refreshed_inc = db_repo.get_incident(incident.incident_id)
    assert refreshed_inc.status == IncidentStatus.RESOLVED


def test_2_mismatched_port_precondition(remediation_service, db_repo, mock_net_client):
    """Precondition failure if live rule port does not match finding evidence."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.return_value = {
        "name": "Allow-SSH-Internet",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "destination_port_range": "8080",  # Mismatched! Expected 22
        "source_address_prefix": "*",
    }

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.PRECONDITION_FAILED
    assert "Rule port is '8080', expected '22'" in rec.error_message
    mock_net_client.create_or_update_security_rule.assert_not_called()


def test_3_mismatched_protocol_precondition(remediation_service, db_repo, mock_net_client):
    """Precondition failure if live rule protocol does not match finding evidence."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.return_value = {
        "name": "Allow-SSH-Internet",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Udp",  # Mismatched! Expected Tcp
        "destination_port_range": "22",
        "source_address_prefix": "*",
    }

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.PRECONDITION_FAILED
    assert "Rule protocol is 'UDP', expected 'TCP'" in rec.error_message
    mock_net_client.create_or_update_security_rule.assert_not_called()


def test_4_already_denied_rule_idempotent(remediation_service, db_repo, mock_net_client):
    """If live rule is already access=Deny, mark VERIFIED without issuing mutation."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.return_value = {
        "name": "Allow-SSH-Internet",
        "direction": "Inbound",
        "access": "Deny",  # Already Denied!
        "protocol": "Tcp",
        "destination_port_range": "22",
        "source_address_prefix": "*",
    }

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFIED
    assert rec.verification.verified_state == "ACCESS_DENIED_IDEMPOTENT"
    mock_net_client.create_or_update_security_rule.assert_not_called()


def test_5_already_remediated_idempotency(remediation_service, db_repo, mock_net_client):
    """If record is already VERIFIED, repeated execution immediately returns without Azure calls."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    # Manually mark record as VERIFIED
    container = RemediationContainer.from_incident_remediation(incident.remediation)
    container.actions["ACT-01"].status = RemediationStatus.VERIFIED
    incident.remediation = container.to_dict()
    db_repo.save_incident(incident)

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFIED
    mock_net_client.get_security_rule.assert_not_called()


def test_6_unrelated_nsg_rule_protection(remediation_service, db_repo, mock_net_client):
    """Verify that only the target rule is updated and other rule parameters are untouched."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "priority": 150, "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        {"name": "Allow-SSH-Internet", "priority": 150, "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    mock_net_client.create_or_update_security_rule.assert_called_once()
    _, kwargs = mock_net_client.create_or_update_security_rule.call_args
    assert kwargs["security_rule_name"] == "Allow-SSH-Internet"
    assert kwargs["rule_parameters"]["priority"] == 150


def test_7_original_state_captured_for_rollback(remediation_service, db_repo, mock_net_client):
    """Verify complete original rule state is captured in rollback_state."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    original = {
        "name": "Allow-SSH-Internet",
        "priority": 100,
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "destination_port_range": "22",
        "source_address_prefix": "*",
        "description": "Original corporate admin rule",
    }
    mock_net_client.get_security_rule.side_effect = [
        original,
        {**original, "access": "Deny"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.rollback_state == original
    assert rec.rollback_state["access"] == "Allow"


def test_8_arm_403_forbidden_handling(remediation_service, db_repo, mock_net_client):
    """Verify clean failure transition when Azure returns 403 Forbidden."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = AzureNetworkAuthError("Forbidden: missing Microsoft.Network write")

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.FAILED
    assert "Forbidden" in rec.error_message


def test_9_arm_404_not_found_handling(remediation_service, db_repo, mock_net_client):
    """Verify PRECONDITION_FAILED if target rule is not found (404)."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.return_value = None  # 404

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.PRECONDITION_FAILED
    assert "Target rule 'Allow-SSH-Internet' does not exist" in rec.error_message


def test_10_arm_409_conflict_retry(mock_net_client):
    """Verify AzureNetworkClient retries on 409 conflict and eventually succeeds."""
    mock_mgmt = MagicMock()
    client = AzureNetworkClient(subscription_id="sub-123", network_client=mock_mgmt)

    poller = MagicMock()
    poller.result.return_value = {"name": "test-rule", "access": "Deny"}

    # Simulate 409 on first 2 calls, then success
    from azure.core.exceptions import HttpResponseError
    err409 = HttpResponseError(message="Conflict")
    err409.status_code = 409

    mock_mgmt.security_rules.begin_create_or_update.side_effect = [err409, err409, poller]

    with patch("time.sleep", return_value=None):
        res = client.create_or_update_security_rule("rg", "nsg", "rule", {"access": "Deny"})
        assert res["access"] == "Deny"
        assert mock_mgmt.security_rules.begin_create_or_update.call_count == 3


def test_11_verification_failure_detected(remediation_service, db_repo, mock_net_client):
    """If post-read still reports access=Allow, marks VERIFICATION_FAILED."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        # Precondition check: Allow
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        # Verification check: Still Allow (mutation failed silently or was rolled back by Azure)
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFICATION_FAILED
    assert "Post-remediation read-back failed" in rec.error_message


def test_12_unapproved_execution_rejected(remediation_service, db_repo):
    """Attempting to execute an action in PROPOSED or REJECTED status must raise RemediationUnapprovedError."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)

    with pytest.raises(RemediationUnapprovedError) as excinfo:
        remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert "has not been approved by an operator" in str(excinfo.value)


def test_13_rejection_marks_rejected(remediation_service, db_repo):
    """Rejecting an action sets status REJECTED and updates audit timeline."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    rec = remediation_service.record_approval(incident.incident_id, "ACT-01", "REJECTED", "secops-operator", "Not needed")
    assert rec.status == RemediationStatus.REJECTED

    refreshed = db_repo.get_incident(incident.incident_id)
    assert any(e.get("event") == "REMEDIATION_REJECTED" for e in refreshed.timeline)


# ---------------------------------------------------------------------------
# Tests: ISOLATE_WORKLOAD
# ---------------------------------------------------------------------------

def test_14_isolate_workload_creation_and_verification(remediation_service, db_repo, mock_net_client):
    """Test full pipeline for ISOLATE_WORKLOAD on SUSPICIOUS_OUTBOUND_ACTIVITY."""
    incident, f = _setup_soa_incident(db_repo)

    remediation_service.propose_action_from_recommendation(
        incident=incident,
        action_id="ACT-02",
        action_type=RemediationActionType.ISOLATE_WORKLOAD,
        target_finding_id=f.finding_id,
    )
    remediation_service.record_approval(incident.incident_id, "ACT-02", "APPROVED")

    mock_net_client.list_security_rules.return_value = [
        {"name": "Allow-HTTPS-Inbound", "priority": 100},
        {"name": "Allow-Internal-DB", "priority": 110},
    ]

    mock_net_client.get_security_rule.return_value = {
        "name": "CloudPulse-Isolate-Outbound-vm-worker-01",
        "priority": 120,
        "direction": "Outbound",
        "access": "Deny",
        "protocol": "*",
        "source_address_prefix": "10.50.3.10/32",
        "destination_address_prefix": "Internet",
    }

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-02")
    assert rec.status == RemediationStatus.VERIFIED
    assert rec.verification.verified_state == "WORKLOAD_ISOLATED"

    mock_net_client.create_or_update_security_rule.assert_called_once()
    _, kwargs = mock_net_client.create_or_update_security_rule.call_args
    assert kwargs["security_rule_name"] == "CloudPulse-Isolate-Outbound-vm-worker-01"
    assert kwargs["rule_parameters"]["priority"] == 120  # Unused priority selected
    assert kwargs["rule_parameters"]["destination_address_prefix"] == "Internet"
    assert kwargs["rule_parameters"]["access"] == "Deny"


def test_15_isolate_workload_idempotency(remediation_service, db_repo, mock_net_client):
    """If isolation rule already exists with access=Deny, returns VERIFIED immediately."""
    incident, f = _setup_soa_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-02", RemediationActionType.ISOLATE_WORKLOAD)
    remediation_service.record_approval(incident.incident_id, "ACT-02", "APPROVED")

    mock_net_client.list_security_rules.return_value = [
        {
            "name": "CloudPulse-Isolate-Outbound-vm-worker-01",
            "priority": 100,
            "direction": "Outbound",
            "access": "Deny",
        }
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-02")
    assert rec.status == RemediationStatus.VERIFIED
    assert rec.verification.verified_state == "WORKLOAD_ISOLATED_IDEMPOTENT"
    mock_net_client.create_or_update_security_rule.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: Security Invariants & Multi-Action Persistence
# ---------------------------------------------------------------------------

def test_16_multi_action_persistence(remediation_service, db_repo):
    """Verify multiple distinct actions can be stored and retrieved on a single incident."""
    incident, _ = _setup_upe_incident(db_repo)

    r1 = remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    r2 = remediation_service.propose_action_from_recommendation(incident, "ACT-02", RemediationActionType.ISOLATE_WORKLOAD)

    refreshed = db_repo.get_incident(incident.incident_id)
    container = RemediationContainer.from_incident_remediation(refreshed.remediation)

    assert len(container.actions) == 2
    assert "ACT-01" in container.actions
    assert "ACT-02" in container.actions
    assert container.actions["ACT-01"].action_type == RemediationActionType.DISABLE_PUBLIC_INGRESS
    assert container.actions["ACT-02"].action_type == RemediationActionType.ISOLATE_WORKLOAD


def test_17_timeline_audit_sequence(remediation_service, db_repo, mock_net_client):
    """Verify chronological timeline entries recorded from proposal to verification."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    remediation_service.execute_remediation(incident.incident_id, "ACT-01")

    refreshed = db_repo.get_incident(incident.incident_id)
    events = [e.get("event") for e in refreshed.timeline]

    assert "REMEDIATION_APPROVED" in events
    assert "REMEDIATION_STARTED" in events
    assert "REMEDIATION_EXECUTED" in events
    assert "REMEDIATION_VERIFICATION_STARTED" in events
    assert "REMEDIATION_VERIFIED" in events


def test_18_ai_cannot_control_target_or_inject_commands(remediation_service, db_repo, mock_net_client):
    """
    Security Invariant Test:
    Even if an adversary passes a malicious action ID or attempts to change parameters,
    the remediation service resolves target NSG and rules strictly from Finding evidence.
    """
    incident, f = _setup_upe_incident(db_repo)

    # Propose with valid action ID
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    # Corrupt or attempt injection into action record in DB
    refreshed = db_repo.get_incident(incident.incident_id)
    container = RemediationContainer.from_incident_remediation(refreshed.remediation)
    # Inject fake target in record
    container.actions["ACT-01"].target_rule_name = "rm -rf /; az vm delete"
    refreshed.remediation = container.to_dict()
    db_repo.save_incident(refreshed)

    # When executed, the engine resolves the target strictly from Finding evidence (Allow-SSH-Internet)
    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.target_rule_name == "Allow-SSH-Internet"
    # Never passed injected string to Azure SDK
    _, kwargs = mock_net_client.create_or_update_security_rule.call_args
    assert kwargs["security_rule_name"] == "Allow-SSH-Internet"


def test_19_invalid_action_type_rejected(remediation_service, db_repo):
    """Execution rejects unsupported or invalid action types."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    # Pydantic schema validation rejects invalid action types
    with pytest.raises(Exception):
        RemediationRecord(
            remediation_id="REM-1",
            incident_id=incident.incident_id,
            action_id="ACT-01",
            action_type="UNKNOWN_ACTION",  # type: ignore
            status=RemediationStatus.APPROVED,
            target_resource_id=RES_ID,
        )

    # And attempting to execute non-existent action raises RemediationError
    with pytest.raises(RemediationError) as excinfo:
        remediation_service.execute_remediation(incident.incident_id, "ACT-NONEXISTENT")
    assert "not found on incident" in str(excinfo.value)


def test_20_target_resource_mismatch_precondition(remediation_service, db_repo):
    """Precondition fails if finding does not contain required network evidence."""
    # Create incident with resource creation finding only (no UPE evidence)
    f_rc = Finding(
        finding_id=generate_deterministic_finding_id("rc-1", RES_ID),
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.LOW,
        timestamp="2026-10-09T01:00:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-worker-01", resource_group="cloudpulse-rg"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            activity_log_event_id="evt-rc-1",
        ),
        confidence=0.90,
    )
    db_repo.save_finding(f_rc)
    incident = Incident(
        incident_id=generate_deterministic_incident_id(RES_ID),
        title="Resource Creation: vm-worker-01",
        severity=SeverityLevel.LOW,
        status=IncidentStatus.OPEN,
        created_at="2026-10-09T01:00:00Z",
        updated_at="2026-10-09T01:00:00Z",
        resource=f_rc.resource,
        identity=f_rc.identity,
        findings=[f_rc.finding_id],
        timeline=[],
        remediation=None,
    )
    db_repo.save_incident(incident)

    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.PRECONDITION_FAILED
    assert "No UNEXPECTED_PUBLIC_EXPOSURE finding evidence" in rec.error_message


def test_21_duplicate_execution_idempotency(remediation_service, db_repo, mock_net_client):
    """Subsequent execution calls on already VERIFIED action return immediately with zero Azure calls."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    # First execution succeeds and marks VERIFIED
    r1 = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert r1.status == RemediationStatus.VERIFIED

    # Second execution is idempotent
    r2 = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert r2.status == RemediationStatus.VERIFIED
    # No additional network calls made on second call
    assert mock_net_client.create_or_update_security_rule.call_count == 1


def test_22_concurrent_operator_approval(remediation_service, db_repo):
    """First operator approval marks APPROVED; second approval updates notes cleanly."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)

    r1 = remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED", "operator-1", "Initial review")
    assert r1.status == RemediationStatus.APPROVED

    r2 = remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED", "operator-2", "Secondary signoff")
    assert r2.status == RemediationStatus.APPROVED
    assert r2.approval.operator == "operator-2"
    assert r2.approval.notes == "Secondary signoff"


def test_23_incident_resolves_only_after_verification(remediation_service, db_repo, mock_net_client):
    """Incident status transitions to RESOLVED only when remediation status is VERIFIED."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    # If verification fails:
    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFICATION_FAILED
    # Incident status must NOT be RESOLVED!
    refreshed = db_repo.get_incident(incident.incident_id)
    assert refreshed.status != IncidentStatus.RESOLVED
    assert refreshed.status == IncidentStatus.INVESTIGATING


def test_24_ai_cannot_inject_executable_commands(remediation_service, db_repo):
    """
    Verify that AI output fields (like recommendations or descriptions)
    cannot introduce shell or CLI scripts into the execution pipeline.
    """
    incident, f = _setup_upe_incident(db_repo)
    # The RemediationService only accepts typed action_ids and incident_ids
    # There is no API parameter for raw shell commands, powershell, or scripts.
    rec = remediation_service.propose_action_from_recommendation(
        incident=incident,
        action_id="ACT-01",
        action_type=RemediationActionType.DISABLE_PUBLIC_INGRESS,
    )
    assert rec.action_type == RemediationActionType.DISABLE_PUBLIC_INGRESS
    # The model strictly validates action_type against RemediationActionType Enum
    with pytest.raises(ValueError):
        RemediationActionType("bash -c 'rm -rf /'")


def test_25_isolation_verification_readback(remediation_service, db_repo, mock_net_client):
    """ISOLATE_WORKLOAD post-readback checks live security rule state."""
    incident, f = _setup_soa_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-02", RemediationActionType.ISOLATE_WORKLOAD)
    remediation_service.record_approval(incident.incident_id, "ACT-02", "APPROVED")

    mock_net_client.list_security_rules.return_value = []
    # Verify readback returns the injected rule
    mock_net_client.get_security_rule.return_value = {
        "name": "CloudPulse-Isolate-Outbound-vm-worker-01",
        "priority": 100,
        "direction": "Outbound",
        "access": "Deny",
        "protocol": "*",
        "destination_address_prefix": "Internet",
    }

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-02")
    assert rec.status == RemediationStatus.VERIFIED
    assert rec.verification.is_compliant is True
    refreshed = db_repo.get_incident(incident.incident_id)
    assert refreshed.status == IncidentStatus.RESOLVED


def test_26_deterministic_remediation_id_stability():
    """Verify deterministic remediation ID formula is stable and unique."""
    id1 = generate_deterministic_remediation_id("INC-01", RemediationActionType.DISABLE_PUBLIC_INGRESS, RES_ID, "Rule-1")
    id2 = generate_deterministic_remediation_id("INC-01", RemediationActionType.DISABLE_PUBLIC_INGRESS, RES_ID, "Rule-1")
    id3 = generate_deterministic_remediation_id("INC-01", RemediationActionType.ISOLATE_WORKLOAD, RES_ID, "Rule-1")

    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("REM-")


def test_27_stale_etag_prevents_mutation():
    """Unit test proving stale ETag prevents mutation via If-Match optimistic concurrency constraint."""
    mock_mgmt = MagicMock()
    client = AzureNetworkClient(subscription_id="sub-123", network_client=mock_mgmt)

    from azure.core.exceptions import HttpResponseError
    # Simulate ARM 412 Precondition Failed when ETag is stale
    err412 = HttpResponseError(message="Precondition Failed: If-Match header does not match current entity ETag")
    err412.status_code = 412
    mock_mgmt.security_rules.begin_create_or_update.side_effect = err412

    with pytest.raises(AzureNetworkConflictError) as exc_info:
        client.create_or_update_security_rule(
            resource_group_name="rg",
            network_security_group_name="nsg",
            security_rule_name="rule",
            rule_parameters={"access": "Deny"},
            etag="stale-etag-999",
        )

    assert "Concurrent write conflict" in str(exc_info.value)
    mock_mgmt.security_rules.begin_create_or_update.assert_called_once()
    call_kwargs = mock_mgmt.security_rules.begin_create_or_update.call_args[1]
    assert call_kwargs.get("headers") == {"If-Match": "stale-etag-999"}
    assert call_kwargs.get("security_rule_parameters")["etag"] == "stale-etag-999"


def test_28_409_reread_and_revalidation(remediation_service, db_repo, mock_net_client):
    """When HTTP 409 occurs during mutation, RemediationService re-reads live rule and revalidates preconditions."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    # Call 1: initial precondition read (etag-1)
    # Call 2: 409 re-read (etag-2)
    # Call 3: post-mutation verification read
    mock_net_client.get_security_rule.side_effect = [
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-1"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-2"},
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-2"},
    ]

    # Attempt 1: 409 Conflict
    # Attempt 2: Success
    mock_net_client.create_or_update_security_rule.side_effect = [
        AzureNetworkConflictError("Conflict on attempt 1"),
        {"name": "Allow-SSH-Internet", "access": "Deny", "etag": "etag-2"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFIED

    # Verify get_security_rule was called for precondition read, 409 re-read, and verification
    assert mock_net_client.get_security_rule.call_count == 3
    # Verify create_or_update was called twice (initial + 1 retry)
    assert mock_net_client.create_or_update_security_rule.call_count == 2


def test_29_409_followed_by_successful_retry_with_fresh_etag(remediation_service, db_repo, mock_net_client):
    """Verify that after a 409 conflict, the retry passes the newly captured fresh ETag and succeeds."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        # 1. Initial precondition read with etag-v1
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-v1"},
        # 2. Re-read on 409 with fresh etag-v2
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-v2"},
        # 3. Post-mutation verification
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Deny", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-v2"},
    ]

    mock_net_client.create_or_update_security_rule.side_effect = [
        AzureNetworkConflictError("Conflict with etag-v1"),
        {"name": "Allow-SSH-Internet", "access": "Deny", "etag": "etag-v2"},
    ]

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.VERIFIED

    # Verify attempt 1 used etag-v1 and attempt 2 used etag-v2
    calls = mock_net_client.create_or_update_security_rule.call_args_list
    assert len(calls) == 2
    assert calls[0].kwargs.get("etag") == "etag-v1"
    assert calls[1].kwargs.get("etag") == "etag-v2"


def test_30_409_state_drift_transitions_to_precondition_failed(remediation_service, db_repo, mock_net_client):
    """When a 409 re-read reveals that live state drifted and no longer matches preconditions, fail safely."""
    incident, f = _setup_upe_incident(db_repo)
    remediation_service.propose_action_from_recommendation(incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
    remediation_service.record_approval(incident.incident_id, "ACT-01", "APPROVED")

    mock_net_client.get_security_rule.side_effect = [
        # 1. Initial precondition read: permissive public
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "*", "etag": "etag-v1"},
        # 2. Re-read on 409: state drifted! Another admin changed source to private subnet (10.0.0.0/8)
        {"name": "Allow-SSH-Internet", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destination_port_range": "22", "source_address_prefix": "10.0.0.0/8", "etag": "etag-v2"},
    ]

    # Mutation fails with 409
    mock_net_client.create_or_update_security_rule.side_effect = AzureNetworkConflictError("Conflict with etag-v1")

    rec = remediation_service.execute_remediation(incident.incident_id, "ACT-01")
    assert rec.status == RemediationStatus.PRECONDITION_FAILED
    assert "no longer permissive public" in rec.error_message

    # Mutation was NOT retried blindly after drift was detected
    assert mock_net_client.create_or_update_security_rule.call_count == 1
    # Incident timeline captures failure
    refreshed = db_repo.get_incident(incident.incident_id)
    assert any(e["event"] == "REMEDIATION_PRECONDITION_FAILED" for e in refreshed.timeline)


def test_31_unknown_action_approval_rejected(remediation_service, db_repo):
    """Approval must only operate on a previously registered PROPOSED action; unknown action IDs are rejected."""
    incident, f = _setup_upe_incident(db_repo)

    # Attempt to approve an unproposed action_id
    with pytest.raises(RemediationError) as exc_info:
        remediation_service.record_approval(incident.incident_id, "UNKNOWN-ACTION-999", "APPROVED")

    assert "not registered on incident" in str(exc_info.value)
    assert "Only previously proposed actions can be approved" in str(exc_info.value)

    # Verify no action was created or registered in incident.remediation
    refreshed = db_repo.get_incident(incident.incident_id)
    container = RemediationContainer.from_incident_remediation(refreshed.remediation)
    assert "UNKNOWN-ACTION-999" not in container.actions
    assert len(container.actions) == 0


def test_32_valid_preregistered_action_approval_succeeds(remediation_service, db_repo):
    """Valid pre-registered PROPOSED action can be approved by operator."""
    incident, f = _setup_upe_incident(db_repo)
    proposed = remediation_service.propose_action_from_recommendation(
        incident, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS
    )
    assert proposed.status == RemediationStatus.PROPOSED

    record = remediation_service.record_approval(
        incident_id=incident.incident_id,
        action_id="ACT-01",
        decision="APPROVED",
        operator="secops@cloudpulse.io",
        notes="Pre-registered action approved after human review",
    )

    assert record.status == RemediationStatus.APPROVED
    assert record.approval.operator == "secops@cloudpulse.io"
    assert record.approval.notes == "Pre-registered action approved after human review"

    refreshed = db_repo.get_incident(incident.incident_id)
    container = RemediationContainer.from_incident_remediation(refreshed.remediation)
    assert container.actions["ACT-01"].status == RemediationStatus.APPROVED


def test_33_api_unknown_action_approval_rejected(mock_db):
    """API endpoint /api/incidents/<id>/actions/<action_id>/approval rejects unknown action IDs with 400."""
    from app import create_app
    incident, f = _setup_upe_incident(mock_db)
    app = create_app(db_repo=mock_db, log_client=None)
    app.config["TESTING"] = True
    client = app.test_client()

    # Attempt to approve an action that does not exist and is not in AI triage
    resp = client.post(
        f"/api/incidents/{incident.incident_id}/actions/UNKNOWN-ACT/approval",
        json={"status": "APPROVED", "operator": "ops@cloudpulse.io"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "error"
    assert "not registered on incident" in data["message"]

    # Verify no action was auto-created in repository
    refreshed = mock_db.get_incident(incident.incident_id)
    container = RemediationContainer.from_incident_remediation(refreshed.remediation)
    assert "UNKNOWN-ACT" not in container.actions
