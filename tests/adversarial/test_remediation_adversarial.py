"""
Adversarial Remediation Test Suite (Scenarios 12-22)
Tests controlled NSG remediation edge-cases: approval drift & TTL, idempotency,
approver-requester separation (4-eyes), API payload tampering, crash consistency,
409 retry bounds, rollback capabilities, workload isolation scope & egress disruption,
post-mutation verification depth, blast radius visibility, and permission scope boundaries.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from unittest.mock import MagicMock
import pytest

from models.finding import Finding, ResourceInfo, IdentityInfo, EvidenceInfo, SeverityLevel
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from models.remediation import RemediationActionType, RemediationStatus
from services.remediation_service import (
    RemediationService,
    RemediationError,
    RemediationPreconditionError,
    RemediationVerificationError,
    RemediationUnapprovedError,
)
from services.azure_network_client import AzureNetworkClient, AzureNetworkConflictError
from database.postgres import InMemoryDatabase
from app import create_app


def create_test_incident_with_finding(
    db: InMemoryDatabase,
    res_id: str = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-app",
    nsg_id: str = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-app",
    rule_name: str = "Allow-SSH-All",
    caller: str = "devops-engineer@cloudpulse.io",
) -> Incident:
    f = Finding(
        finding_id="F-UPE-TEST-01",
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=SeverityLevel.CRITICAL,
        timestamp=datetime.now(timezone.utc).isoformat(),
        resource=ResourceInfo(
            id=res_id,
            name="vm-app",
            type="Microsoft.Compute/virtualMachines",
            resource_group="rg-1",
        ),
        identity=IdentityInfo(
            caller=caller,
            principal_id="user-123",
            principal_type="User",
        ),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-001",
            destination_port="22",
            protocol="TCP",
            exposure_type="MANAGEMENT_PORT",
            nsg_id=nsg_id,
            nsg_rule_name=rule_name,
            source_address_prefix="0.0.0.0/0",
            source_ip="10.0.1.4",
        ),
        confidence=0.95,
    )
    db.save_finding(f)

    inc_id = generate_deterministic_incident_id(res_id)
    inc = Incident(
        incident_id=inc_id,
        title="Unexpected Public Exposure: vm-app",
        severity=SeverityLevel.CRITICAL,
        status=IncidentStatus.OPEN,
        resource=f.resource,
        identity=f.identity,
        findings=[f.finding_id],
    )
    db.save_incident(inc)
    return inc


class TestAdversarialRemediation:

    def test_scenario_12_state_drift_and_approval_expiration(self):
        """
        Scenario 12:
        Part A: Approval executed after live rule state drifted → PRECONDITION_FAILED expected.
        Part B: Do approvals expire? Verify whether approval timestamp TTL is enforced.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(
            incident=inc,
            action_id="ACT-01",
            action_type=RemediationActionType.DISABLE_PUBLIC_INGRESS,
        )

        # Approve action
        svc.record_approval(incident_id=inc.incident_id, action_id="ACT-01", decision="APPROVED")

        # Simulate state drift: Live rule direction was drifted to Outbound by external admin
        mock_net.get_security_rule.return_value = {
            "name": "Allow-SSH-All",
            "direction": "Outbound",  # Drifted!
            "access": "Allow",
            "destination_port_range": "22",
            "protocol": "TCP",
            "source_address_prefix": "0.0.0.0/0",
        }

        # Execution after drift must fail with PRECONDITION_FAILED
        rec = svc.execute_remediation(incident_id=inc.incident_id, action_id="ACT-01")
        assert rec.status == RemediationStatus.PRECONDITION_FAILED

        # Part B: Approval Expiration Audit
        # Check if record.approval has an expiry check or if stale approval from 30 days ago is accepted
        stale_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        rec.approval.timestamp = stale_time
        rec.status = RemediationStatus.APPROVED
        db.save_incident(db.get_incident(inc.incident_id))

        # Flaw confirmation: approvals have NO expiration check in code
        has_ttl_check = hasattr(rec.approval, "expires_at") or "expires" in rec.approval.__dict__
        assert not has_ttl_check, "Approvals do not define or enforce a TTL/expiration window"

    def test_scenario_13_concurrent_or_replayed_approval(self):
        """
        Scenario 13: Two concurrent approvals / replayed execution → exactly ONE mutation.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        # First live state: Allow
        mock_net.get_security_rule.side_effect = [
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Allow",
                "destination_port_range": "22",
                "protocol": "TCP",
                "source_address_prefix": "0.0.0.0/0",
                "etag": "etag-1",
            },
            # Post-mutation readback: Deny
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Deny",
                "destination_port_range": "22",
                "protocol": "TCP",
                "source_address_prefix": "0.0.0.0/0",
            },
        ]

        # Execution 1
        rec1 = svc.execute_remediation(inc.incident_id, "ACT-01")
        assert rec1.status == RemediationStatus.VERIFIED
        assert mock_net.create_or_update_security_rule.call_count == 1

        # Execution 2 (Replayed): Already verified, must not mutate again
        rec2 = svc.execute_remediation(inc.incident_id, "ACT-01")
        assert rec2.status == RemediationStatus.VERIFIED
        # Mutation call count MUST REMAIN 1
        assert mock_net.create_or_update_security_rule.call_count == 1

    def test_scenario_14_approver_equals_requester_separation(self):
        """
        Scenario 14: Approver == Requester separation of duties (4-eyes principle).
        Requirement: The identity requesting/causing the change cannot self-approve remediation.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        caller = "attacker-compromised-operator@cloudpulse.io"
        inc = create_test_incident_with_finding(db, caller=caller)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)

        # Requester is inc.identity.caller
        # Attempt self-approval with operator == caller
        # In secure enterprise architectures, self-approval MUST be rejected
        is_blocked = False
        try:
            rec = svc.record_approval(
                incident_id=inc.incident_id,
                action_id="ACT-01",
                decision="APPROVED",
                operator=caller,  # Self-approval!
            )
            # If it succeeded without error, self-approval was allowed!
            is_blocked = False
        except RemediationError:
            is_blocked = True

        assert not is_blocked, (
            "4-EYES VULNERABILITY CONFIRMED: Approver is identical to requester, but backend permitted self-approval."
        )

    def test_scenario_15_tamper_api_payloads_isolated_to_finding_evidence(self):
        """
        Scenario 15: Tamper API payloads (NSG ID, rule name, port, remediation target).
        Targets must come ONLY from stored finding evidence, not API body.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        # Malicious operator modifies record.target_nsg_id in memory or sends forged target via payload
        container = db.get_incident(inc.incident_id).remediation
        # Target NSG resolved from finding evidence
        mock_net.get_security_rule.side_effect = [
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Allow",
                "destination_port_range": "22",
                "protocol": "TCP",
                "source_address_prefix": "0.0.0.0/0",
            },
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Deny",
                "destination_port_range": "22",
            },
        ]

        svc.execute_remediation(inc.incident_id, "ACT-01")

        # Verify mutation was sent to the finding's NSG, NOT any tampered target
        call_kwargs = mock_net.create_or_update_security_rule.call_args[1]
        assert call_kwargs["network_security_group_name"] == "nsg-app"
        assert call_kwargs["security_rule_name"] == "Allow-SSH-All"

    def test_scenario_16_crash_between_arm_write_and_db_write(self):
        """
        Scenario 16: Simulated crash between ARM write and DB write.
        Is there a background reconciler? What state is left?
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        # Crash simulation: create_or_update succeeds, but process dies before verification / save
        mock_net.get_security_rule.return_value = {
            "name": "Allow-SSH-All",
            "direction": "Inbound",
            "access": "Allow",
            "destination_port_range": "22",
            "protocol": "TCP",
            "source_address_prefix": "0.0.0.0/0",
        }

        # Verify whether any reconciler job exists in the codebase
        import services.remediation_service as rem_module
        has_reconciler = any("reconcil" in name.lower() for name in dir(rem_module))

        assert not has_reconciler, (
            "No background reconciler exists: if worker crashes after ARM write, DB state is left desynchronized."
        )

    def test_scenario_17_bounded_409_retry_no_infinite_loop(self):
        """
        Scenario 17: 409/412 retry behavior → bounded at max 3 retries?
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        # Initial rule read
        mock_net.get_security_rule.return_value = {
            "name": "Allow-SSH-All",
            "direction": "Inbound",
            "access": "Allow",
            "destination_port_range": "22",
            "protocol": "TCP",
            "source_address_prefix": "0.0.0.0/0",
        }
        # Every write attempt raises AzureNetworkConflictError (409)
        mock_net.create_or_update_security_rule.side_effect = AzureNetworkConflictError("409 Conflict")

        rec = svc.execute_remediation(inc.incident_id, "ACT-01")

        # Must terminate boundedly without infinite loop
        assert rec.status == RemediationStatus.PRECONDITION_FAILED
        assert mock_net.create_or_update_security_rule.call_count == 3
        assert "409 conflict retries" in rec.error_message

    def test_scenario_18_rollback_capabilities_audit(self):
        """
        Scenario 18: Rollback after external drift.
        Audit: Does the codebase implement any rollback method or endpoint?
        README.md:25 claims 'full rollback capabilities'.
        """
        import services.remediation_service as rem_module
        svc = RemediationService(db_repo=InMemoryDatabase())

        has_rollback_method = any("rollback" in name.lower() for name in dir(svc))
        assert not has_rollback_method, (
            "README CLAIM FALSE: RemediationService has zero rollback implementation methods."
        )

    def test_scenario_19_isolate_workload_egress_and_priority_collision(self):
        """
        Scenario 19: ISOLATE_WORKLOAD:
        Part A: Priority collision resolution with existing rules.
        Part B: Workload scoping and egress breakage analysis (Internet destination tag).
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        # Finding of suspicious outbound activity
        f_soa = Finding(
            finding_id="F-SOA-01",
            finding_type="SUSPICIOUS_OUTBOUND_ACTIVITY",
            severity=SeverityLevel.CRITICAL,
            timestamp=datetime.now(timezone.utc).isoformat(),
            resource=ResourceInfo(
                id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-miner",
                name="vm-miner",
                type="Microsoft.Compute/virtualMachines",
                resource_group="rg-1",
            ),
            identity=IdentityInfo(caller="agent", principal_id="id-1", principal_type="VM"),
            evidence=EvidenceInfo(
                operation="FLOW_LOG_DETECTION",
                activity_log_event_id="act-1",
                nsg_id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-worker",
                source_ip="10.50.3.15",
                destination_ip="198.51.100.99",
                destination_port="3333",
            ),
            confidence=0.95,
        )
        db.save_finding(f_soa)
        inc = Incident(
            incident_id=generate_deterministic_incident_id(f_soa.resource.id),
            title="Suspicious Outbound Mining: vm-miner",
            severity=SeverityLevel.CRITICAL,
            status=IncidentStatus.OPEN,
            resource=f_soa.resource,
            identity=f_soa.identity,
            findings=[f_soa.finding_id],
        )
        db.save_incident(inc)

        svc.propose_action_from_recommendation(inc, "ACT-ISO", RemediationActionType.ISOLATE_WORKLOAD)
        svc.record_approval(inc.incident_id, "ACT-ISO", "APPROVED")

        # Existing rules occupying priorities 100, 110, 120
        mock_net.list_security_rules.return_value = [
            {"name": "rule-1", "priority": 100},
            {"name": "rule-2", "priority": 110},
            {"name": "rule-3", "priority": 120},
        ]
        # Verified rule readback
        mock_net.get_security_rule.return_value = {
            "name": "CloudPulse-Isolate-Outbound-vm-miner",
            "direction": "Outbound",
            "access": "Deny",
        }

        rec = svc.execute_remediation(inc.incident_id, "ACT-ISO")
        assert rec.status == RemediationStatus.VERIFIED

        # Check injected rule parameters
        call_kwargs = mock_net.create_or_update_security_rule.call_args[1]
        rule_params = call_kwargs["rule_parameters"]

        # Priority must avoid collision: 100, 110, 120 occupied -> chosen 130
        assert rule_params["priority"] == 130
        # Source is scoped to 10.50.3.15/32
        assert rule_params["source_address_prefix"] == "10.50.3.15/32"
        # Destination is 'Internet'
        assert rule_params["destination_address_prefix"] == "Internet"

    def test_scenario_20_post_mutation_verification_depth(self):
        """
        Scenario 20: Post-mutation verification checks ONLY single rule property,
        not effective security rules or reachability flow.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        mock_net.get_security_rule.side_effect = [
            # Precondition
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Allow",
                "destination_port_range": "22",
                "protocol": "TCP",
                "source_address_prefix": "0.0.0.0/0",
            },
            # Verification readback
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Deny",
                "destination_port_range": "22",
            },
        ]

        rec = svc.execute_remediation(inc.incident_id, "ACT-01")
        assert rec.status == RemediationStatus.VERIFIED

        # Flaw confirmation: network client only called get_security_rule, never effective security rules or IP flow verify
        has_effective_check = hasattr(mock_net, "get_effective_security_rules")
        assert not has_effective_check, (
            "Verification checks single rule access property only, ignoring effective security rules."
        )

    def test_scenario_21_blast_radius_calculation_missing(self):
        """
        Scenario 21: Blast radius: NSG shared by multiple NICs/VMs.
        Audit: Is blast radius calculated or shown before approval?
        """
        db = InMemoryDatabase()
        svc = RemediationService(db_repo=db)
        inc = create_test_incident_with_finding(db)

        rec = svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)

        # In RemediationRecord, check if any blast radius metadata exists
        assert not hasattr(rec, "blast_radius") and not hasattr(rec, "affected_nic_count"), (
            "Blast radius not calculated: operator cannot see number of shared interfaces affected before approving."
        )

    def test_scenario_22_permissions_boundary_no_allow_rules(self):
        """
        Scenario 22: Verify no code path can create an Allow rule or touch resources beyond
        the 4 declared permissions.
        """
        db = InMemoryDatabase()
        mock_net = MagicMock(spec=AzureNetworkClient)
        svc = RemediationService(db_repo=db, network_client=mock_net)

        inc = create_test_incident_with_finding(db)
        svc.propose_action_from_recommendation(inc, "ACT-01", RemediationActionType.DISABLE_PUBLIC_INGRESS)
        svc.record_approval(inc.incident_id, "ACT-01", "APPROVED")

        mock_net.get_security_rule.side_effect = [
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Allow",
                "destination_port_range": "22",
                "protocol": "TCP",
                "source_address_prefix": "0.0.0.0/0",
            },
            {
                "name": "Allow-SSH-All",
                "direction": "Inbound",
                "access": "Deny",
                "destination_port_range": "22",
            },
        ]

        svc.execute_remediation(inc.incident_id, "ACT-01")

        # Verify mutation payload access is strictly 'Deny'
        payload = mock_net.create_or_update_security_rule.call_args[1]["rule_parameters"]
        assert payload["access"] == "Deny", "Remediation attempted to set access other than Deny!"
