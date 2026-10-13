"""
Adversarial Correlation Test Suite (Scenarios 8-11)
Tests cross-resource correlation isolation, idempotent event deduplication,
rule flapping deduplication, and cross-subscription/tenant data leakage.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from models.finding import Finding, ResourceInfo, IdentityInfo, EvidenceInfo, SeverityLevel
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from services.correlation_service import SecurityFinopsCorrelator, CorrelationStrength
from services.incident_orchestrator import IncidentOrchestrator
from database.postgres import InMemoryDatabase
from app import create_app


def make_security_finding(res_id: str, rg: str, fid: str, timestamp: str = "2026-10-13T10:00:00Z") -> Finding:
    return Finding(
        finding_id=fid,
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=SeverityLevel.HIGH,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=res_id,
            name=res_id.split("/")[-1],
            type="Microsoft.Compute/virtualMachines",
            resource_group=rg,
        ),
        identity=IdentityInfo(
            caller="operator@cloudpulse.io",
            principal_id="user-123",
            principal_type="User",
        ),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-sec-01",
            destination_port="22",
            exposure_type="MANAGEMENT_PORT",
            nsg_id=f"{res_id}-nsg",
            nsg_rule_name="Allow-SSH",
        ),
        confidence=0.90,
    )


def make_cost_finding(res_id: str, rg: str, fid: str, timestamp: str = "2026-10-13T10:15:00Z") -> Finding:
    return Finding(
        finding_id=fid,
        finding_type="COST_ANOMALY",
        severity=SeverityLevel.HIGH,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=res_id,
            name=res_id.split("/")[-1],
            type="Microsoft.Compute/virtualMachines",
            resource_group=rg,
        ),
        identity=IdentityInfo(
            caller="billing-engine",
            principal_id="sub-123",
            principal_type="ServicePrincipal",
        ),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COSTMANAGEMENT/QUERY",
            activity_log_event_id="evt-cost-01",
            cost_category="Compute",
            actual_cost=250.0,
            baseline_cost=50.0,
            deviation_absolute=200.0,
            percentage_increase=400.0,
            currency="USD",
            evaluation_date=timestamp[:10],
        ),
        confidence=0.95,
    )


class TestAdversarialCorrelation:

    def test_scenario_8_unrelated_events_must_not_correlate(self):
        """
        Scenario 8: Two unrelated events in the same temporal window on different resources
        must NOT correlate into an escalated incident.
        """
        correlator = SecurityFinopsCorrelator()

        # Different resources, different resource groups
        f_sec = make_security_finding(
            res_id="/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.Compute/virtualMachines/vm-sec",
            rg="rg-sec",
            fid="F-SEC-01",
        )
        f_cost = make_cost_finding(
            res_id="/subscriptions/sub-1/resourceGroups/rg-finops/providers/Microsoft.Compute/virtualMachines/vm-finops",
            rg="rg-finops",
            fid="F-COST-01",
        )

        res = correlator.correlate(f_sec, f_cost)

        assert res.strength == CorrelationStrength.NONE
        assert res.confidence == 0.0
        assert res.escalate_severity is None
        assert res.correlation_type == "UNRELATED_RESOURCES"

    def test_scenario_9_out_of_order_and_replay_idempotency(self):
        """
        Scenario 9: Out-of-order arrival, duplicate events, and replayed Activity Log events
        must resolve idempotently to exactly ONE incident.
        """
        db = InMemoryDatabase()
        orchestrator = IncidentOrchestrator(db_repo=db)

        res_id = "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-prod"
        rg = "rg-app"

        # Event 1: Arrived at 10:30 UTC
        f1 = make_security_finding(res_id=res_id, rg=rg, fid="F-EVT-01", timestamp="2026-10-13T10:30:00Z")
        inc1 = orchestrator.process_finding(f1)

        # Event 2 (Out of order): Occurred earlier at 10:10 UTC but arrived later
        f2 = make_security_finding(res_id=res_id, rg=rg, fid="F-EVT-02", timestamp="2026-10-13T10:10:00Z")
        inc2 = orchestrator.process_finding(f2)

        # Event 3 (Replayed duplicate): Same event replayed
        inc3 = orchestrator.process_finding(f1)

        incidents = db.list_incidents()

        assert len(incidents) == 1, f"Expected 1 deduplicated incident, found {len(incidents)}"
        assert inc1.incident_id == inc2.incident_id == inc3.incident_id
        # Timeline should record both distinct finding detections without creating extra incidents
        assert len(inc3.findings) == 2

    def test_scenario_10_rule_flapping_50x_hour(self):
        """
        Scenario 10: Rule flapping 50x/hour on same resource must attach to ONE incident.
        """
        db = InMemoryDatabase()
        orchestrator = IncidentOrchestrator(db_repo=db)

        res_id = "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-flap"
        rg = "rg-app"

        for i in range(50):
            t_str = f"2026-10-13T10:{i:02d}:00Z"
            f = make_security_finding(res_id=res_id, rg=rg, fid=f"F-FLAP-{i:03d}", timestamp=t_str)
            orchestrator.process_finding(f)

        incidents = db.list_incidents()
        assert len(incidents) == 1, f"Flapping created {len(incidents)} incidents instead of 1."
        assert len(incidents[0].findings) == 50

    def test_scenario_11_cross_subscription_and_tenant_leakage(self):
        """
        Scenario 11: Cross-subscription/tenant data isolation.
        Querying incidents must NOT return incidents from other subscriptions or tenants.
        Flaw: The DB schema and GET /api/incidents query have no tenant/subscription filtering.
        """
        db = InMemoryDatabase()
        orchestrator = IncidentOrchestrator(db_repo=db)

        # Tenant/Sub A incident
        f_sub_a = make_security_finding(
            res_id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-a",
            rg="rg-a",
            fid="F-SUB-A",
        )
        orchestrator.process_finding(f_sub_a)

        # Tenant/Sub B incident
        f_sub_b = make_security_finding(
            res_id="/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-b/providers/Microsoft.Compute/virtualMachines/vm-b",
            rg="rg-b",
            fid="F-SUB-B",
        )
        orchestrator.process_finding(f_sub_b)

        app = create_app(db_repo=db)
        client = app.test_client()

        # Query API for subscription A only
        resp = client.get("/api/incidents?subscription_id=11111111-1111-1111-1111-111111111111")
        data = resp.get_json()
        incidents = data.get("incidents", [])

        # If data returns both incidents, multi-tenant isolation failed
        sub_b_leaked = any("22222222-2222-2222-2222-222222222222" in inc["resource"]["id"] for inc in incidents)

        assert not sub_b_leaked, (
            "CROSS-SUBSCRIPTION DATA LEAKAGE CONFIRMED: GET /api/incidents returned incidents from Subscription B "
            "when queried with subscription_id filter because backend ignores multi-tenancy."
        )
