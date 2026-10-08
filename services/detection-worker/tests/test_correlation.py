import math
import pytest
from datetime import datetime, timezone
from typing import Dict, Any

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
    generate_cost_anomaly_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from services.incident_orchestrator import IncidentOrchestrator
from services.correlation_service import (
    SecurityFinopsCorrelator,
    CorrelationStrength,
    CorrelationResult,
)


# ---------------------------------------------------------------------------
# Fixture Helpers
# ---------------------------------------------------------------------------

def create_rc_finding(
    resource_id: str = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    name: str = "vm-worker-01",
    timestamp: str = "2026-10-07T10:00:00Z",
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    confidence: float = 0.85,
) -> Finding:
    fid = generate_deterministic_finding_id("evt-rc-1", resource_id)
    return Finding(
        finding_id=fid,
        finding_type="RESOURCE_CREATION",
        severity=severity,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=resource_id,
            type="Microsoft.Compute/virtualMachines",
            name=name,
            resource_group="rg-prod",
        ),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            activity_log_event_id="evt-rc-1",
            subscription_id="sub-123",
        ),
        confidence=confidence,
    )


def create_soa_finding(
    resource_id: str = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    name: str = "vm-worker-01",
    timestamp: str = "2026-10-07T14:15:00Z",
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = 0.95,
    bytes_sent: int = 15000000000,  # 15 GB
    anomaly_type: str = "VOLUME_SPIKE",
) -> Finding:
    fid = generate_outbound_finding_id(resource_id, "198.51.100.77", "443", anomaly_type)
    return Finding(
        finding_id=fid,
        finding_type="SUSPICIOUS_OUTBOUND_ACTIVITY",
        severity=severity,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=resource_id,
            type="Microsoft.Compute/virtualMachines",
            name=name,
            resource_group="rg-prod",
        ),
        identity=IdentityInfo(caller="azure-network-analytics"),
        evidence=EvidenceInfo(
            operation="NETWORK_FLOW_TELEMETRY",
            activity_log_event_id="flow-1",
            subscription_id="sub-123",
            destination_ip="198.51.100.77",
            destination_port="443",
            bytes_sent=bytes_sent,
            anomaly_type=anomaly_type,
        ),
        confidence=confidence,
    )


def create_upe_finding(
    resource_id: str = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    name: str = "vm-worker-01",
    timestamp: str = "2026-10-07T09:00:00Z",
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = 0.95,
) -> Finding:
    fid = generate_exposure_finding_id(resource_id, "rule-allow-ssh", "TCP", "22")
    return Finding(
        finding_id=fid,
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=severity,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=resource_id,
            type="Microsoft.Compute/virtualMachines",
            name=name,
            resource_group="rg-prod",
        ),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-upe-1",
            subscription_id="sub-123",
            destination_port="22",
            exposure_type="MANAGEMENT_PORT",
        ),
        confidence=confidence,
    )


def create_cost_finding(
    resource_id: str = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    name: str = "vm-worker-01",
    cost_category: str = "Network/Egress",
    evaluation_date: str = "2026-10-07",
    timestamp: str = "2026-10-08T06:00:00Z",
    actual_cost: float = 135.24,
    baseline_cost: float = 4.20,
    deviation_absolute: float = 131.04,
    percentage_increase: float = 3120.0,
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = 0.92,
    sample_days: int = 14,
    is_cold_start: bool = False,
    high_volatility: bool = False,
) -> Finding:
    fid = generate_cost_anomaly_finding_id(resource_id, cost_category, evaluation_date)
    return Finding(
        finding_id=fid,
        finding_type="COST_ANOMALY",
        severity=severity,
        timestamp=timestamp,
        resource=ResourceInfo(
            id=resource_id,
            type="Microsoft.Compute/virtualMachines",
            name=name,
            resource_group="rg-prod",
        ),
        identity=IdentityInfo(caller="azure-cost-management"),
        evidence=EvidenceInfo(
            operation="COST_ANOMALY_EVALUATION",
            activity_log_event_id=f"cost-obs-{name}-{evaluation_date}",
            subscription_id="sub-123",
            actual_cost=actual_cost,
            baseline_cost=baseline_cost,
            deviation_absolute=deviation_absolute,
            percentage_increase=percentage_increase,
            currency="USD",
            cost_category=cost_category,
            service_name="Bandwidth" if cost_category == "Network/Egress" else "Virtual Machines",
            meter_name="Data Transfer Out" if cost_category == "Network/Egress" else "Compute Hours",
            evaluation_date=evaluation_date,
            sample_days=sample_days,
            is_cold_start=is_cold_start,
            high_volatility=high_volatility,
        ),
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# 1. Basic Correlation & Dimension Tests (Sections 2, 3)
# ---------------------------------------------------------------------------

def test_correlation_same_resource_compatible_findings():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding()
    cost = create_cost_finding(cost_category="Network/Egress")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.VERY_STRONG
    assert result.confidence >= 0.90
    assert result.correlation_type == "SECURITY_FINOPS_EGRESS_CONCURRENCE"
    assert result.affected_resource == soa.resource.id
    assert result.escalate_severity == SeverityLevel.CRITICAL


def test_correlation_different_resources():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
    )
    cost = create_cost_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/vm-dev-02"
    )
    cost.resource.resource_group = "rg-dev"

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.NONE
    assert result.confidence == 0.0
    assert result.escalate_severity is None


def test_correlation_same_resource_group_only():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
        name="vm-worker-01",
    )
    cost = create_cost_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stgdiag01",
        name="stgdiag01",
        cost_category="Storage",
    )

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.WEAK
    assert result.confidence <= 0.40
    assert result.correlation_type == "RESOURCE_GROUP_CO_LOCATION"
    assert "Different resources" in result.reason
    assert result.escalate_severity is None


def test_correlation_same_subscription_only():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-a",
        name="vm-a",
    )
    cost = create_cost_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-b/providers/Microsoft.Compute/virtualMachines/vm-b",
        name="vm-b",
    )
    # Set different resource groups
    soa.resource.resource_group = "rg-a"
    cost.resource.resource_group = "rg-b"

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.NONE
    assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# 2. Detector Pairs Matrix Tests (Section 4)
# ---------------------------------------------------------------------------

def test_correlation_rc_and_cost_anomaly():
    correlator = SecurityFinopsCorrelator()
    rc = create_rc_finding(timestamp="2026-10-05T10:00:00Z")  # 2 days prior
    cost = create_cost_finding(
        cost_category="Compute",
        evaluation_date="2026-10-07",
        deviation_absolute=185.00,
        severity=SeverityLevel.HIGH,
    )

    result = correlator.correlate(rc, cost)

    assert result.strength == CorrelationStrength.STRONG
    assert result.confidence >= 0.80
    assert result.correlation_type == "SECURITY_FINOPS_PROVISIONING_COST_SURGE"
    assert result.escalate_severity == SeverityLevel.HIGH


def test_correlation_soa_and_cost_anomaly_mining():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(anomaly_type="MINING_PORT")
    cost = create_cost_finding(
        cost_category="Compute",
        evaluation_date="2026-10-07",
        severity=SeverityLevel.HIGH,
    )

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.STRONG
    assert result.confidence >= 0.85
    assert result.correlation_type == "SECURITY_FINOPS_COMPUTE_CONCURRENCE"
    assert result.escalate_severity == SeverityLevel.CRITICAL


def test_correlation_upe_and_cost_anomaly():
    correlator = SecurityFinopsCorrelator()
    upe = create_upe_finding(timestamp="2026-10-06T10:00:00Z")
    cost = create_cost_finding(
        cost_category="Network/Egress",
        evaluation_date="2026-10-07",
        severity=SeverityLevel.MEDIUM,
    )

    result = correlator.correlate(upe, cost)

    assert result.strength == CorrelationStrength.MODERATE
    assert result.confidence >= 0.70
    assert result.correlation_type == "SECURITY_FINOPS_EXPOSURE_COST_INCREASE"


def test_correlation_categorical_mismatch():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding()
    cost = create_cost_finding(cost_category="Storage")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.WEAK
    assert result.correlation_type == "SECURITY_FINOPS_CATEGORICAL_MISMATCH"
    assert "categorical mismatch" in result.reason.lower()


# ---------------------------------------------------------------------------
# 3. Temporal Alignment Tests (Sections 3.D, 7)
# ---------------------------------------------------------------------------

def test_temporal_same_calendar_day():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(timestamp="2026-10-07T14:15:00Z")
    cost = create_cost_finding(evaluation_date="2026-10-07")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.VERY_STRONG


def test_temporal_preceding_calendar_day():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(timestamp="2026-10-06T23:50:00Z")  # 1 day prior
    cost = create_cost_finding(evaluation_date="2026-10-07")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.VERY_STRONG


def test_temporal_outside_correlation_window():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(timestamp="2026-09-20T10:00:00Z")  # 17 days prior
    cost = create_cost_finding(evaluation_date="2026-10-07")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.NONE
    assert result.confidence == 0.0
    assert "Temporal divergence" in result.reason


def test_temporal_event_in_future_rejected():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(timestamp="2026-10-09T10:00:00Z")  # Future event vs past billing date
    cost = create_cost_finding(evaluation_date="2026-10-07")

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.NONE
    assert result.confidence == 0.0


def test_event_time_vs_ingestion_time_distinction():
    """
    Simulates late-arriving FinOps telemetry:
    Security flow event occurred on 2026-10-07 (T).
    FinOps Cost Management ingested on 2026-10-08 (T+1), with evaluation_date="2026-10-07".
    Correlation must evaluate 2026-10-07 against 2026-10-07, NOT 2026-10-08.
    """
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(timestamp="2026-10-07T14:15:00Z")
    cost = create_cost_finding(
        timestamp="2026-10-08T06:00:00Z",  # Ingested next day
        evaluation_date="2026-10-07",      # Evaluated calendar day
    )

    result = correlator.correlate(soa, cost)

    assert result.strength == CorrelationStrength.VERY_STRONG
    assert result.evaluation_date == "2026-10-07"


# ---------------------------------------------------------------------------
# 4. Strength and Confidence Scoring Tests (Sections 5, 6)
# ---------------------------------------------------------------------------

def test_confidence_scoring_additive_formula():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(confidence=0.95)
    cost = create_cost_finding(
        confidence=0.92,
        sample_days=14,
        is_cold_start=False,
        high_volatility=False,
    )

    result = correlator.correlate(soa, cost)

    base = math.sqrt(0.95 * 0.92)
    expected = min(1.0, base + 0.15 + 0.15 + 0.10 + 0.05)
    assert result.confidence == round(expected, 2)
    assert result.confidence >= 0.94


def test_confidence_penalties_cold_start_and_volatility():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding()
    cost = create_cost_finding(
        is_cold_start=True,
        high_volatility=True,
    )

    result = correlator.correlate(soa, cost)

    # Should have stability penalty of -0.15
    assert result.confidence < 0.90


def test_non_security_pairs_rejected():
    correlator = SecurityFinopsCorrelator()
    soa1 = create_soa_finding()
    soa2 = create_soa_finding()

    result = correlator.correlate(soa1, soa2)

    assert result.strength == CorrelationStrength.NONE
    assert result.correlation_type == "UNSUPPORTED_FINDING_PAIR"


# ---------------------------------------------------------------------------
# 5. Deterministic Severity Escalation Tests (Section 10)
# ---------------------------------------------------------------------------

def test_severity_escalation_soa_and_cost_to_critical():
    correlator = SecurityFinopsCorrelator()
    soa = create_soa_finding(severity=SeverityLevel.HIGH)
    cost = create_cost_finding(
        cost_category="Network/Egress",
        severity=SeverityLevel.HIGH,
    )

    result = correlator.correlate(soa, cost)

    assert result.escalate_severity == SeverityLevel.CRITICAL


def test_severity_escalation_multi_stage_to_critical():
    correlator = SecurityFinopsCorrelator()
    upe = create_upe_finding(severity=SeverityLevel.HIGH)
    soa = create_soa_finding(severity=SeverityLevel.HIGH)
    cost = create_cost_finding(severity=SeverityLevel.MEDIUM)

    # When all 3 findings exist on workload
    all_types = {upe.finding_type, soa.finding_type}
    result = correlator.correlate(soa, cost, all_security_types=all_types)

    assert result.escalate_severity == SeverityLevel.CRITICAL
    assert "Critical Multi-Stage Incident" in result.correlated_title


def test_severity_rc_low_cost_medium_stays_medium():
    correlator = SecurityFinopsCorrelator()
    rc = create_rc_finding(severity=SeverityLevel.LOW)
    cost = create_cost_finding(
        cost_category="Compute",
        deviation_absolute=45.00,
        severity=SeverityLevel.MEDIUM,
    )

    result = correlator.correlate(rc, cost)

    # RC LOW + COST MEDIUM (Delta < $100) must stay MEDIUM, NOT become HIGH
    assert result.escalate_severity == SeverityLevel.MEDIUM


def test_severity_rc_medium_cost_critical_catastrophic():
    correlator = SecurityFinopsCorrelator()
    rc = create_rc_finding(severity=SeverityLevel.MEDIUM)
    cost = create_cost_finding(
        cost_category="Compute",
        deviation_absolute=1250.00,  # >= $1000.00
        severity=SeverityLevel.CRITICAL,
    )

    result = correlator.correlate(rc, cost)

    assert result.escalate_severity == SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# 6. Incident Orchestrator Integration & Deduplication (Sections 9, 12, 13, 16)
# ---------------------------------------------------------------------------

def test_orchestrator_correlates_security_and_finops(mock_db):
    orchestrator = IncidentOrchestrator(db_repo=mock_db)

    # 1. First event: SUSPICIOUS_OUTBOUND_ACTIVITY on Day T
    soa = create_soa_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-victim-01",
        name="vm-victim-01",
        timestamp="2026-10-07T14:15:00Z",
        severity=SeverityLevel.HIGH,
    )
    inc1 = orchestrator.process_finding(soa)

    assert inc1.severity == SeverityLevel.HIGH
    assert inc1.cost_impact is None
    assert len(inc1.timeline) == 1
    assert inc1.timeline[0]["event"] == "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED"

    # 2. Second event: COST_ANOMALY arrives on Day T+1 for Day T
    cost = create_cost_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-victim-01",
        name="vm-victim-01",
        cost_category="Network/Egress",
        evaluation_date="2026-10-07",
        timestamp="2026-10-08T06:00:00Z",
        severity=SeverityLevel.HIGH,
    )
    inc2 = orchestrator.process_finding(cost)

    # Verify correlated incident properties
    assert inc2.incident_id == inc1.incident_id
    assert inc2.severity == SeverityLevel.CRITICAL  # Escalated
    assert inc2.cost_impact is not None
    assert inc2.cost_impact["correlation_strength"] == "VERY_STRONG"
    assert inc2.cost_impact["actual_cost"] == 135.24
    assert inc2.cost_impact["cost_category"] == "Network/Egress"
    assert "Correlated Security & FinOps" in inc2.title

    # Verify timeline: original events preserved + correlation event added
    timeline_events = [e["event"] for e in inc2.timeline]
    assert "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED" in timeline_events
    assert "COST_ANOMALY_DETECTED" in timeline_events
    assert "SECURITY_FINOPS_CORRELATED" in timeline_events
    assert len(inc2.timeline) == 3


def test_orchestrator_deduplication_repeated_correlation_runs(mock_db):
    orchestrator = IncidentOrchestrator(db_repo=mock_db)

    soa = create_soa_finding()
    cost = create_cost_finding()

    orchestrator.process_finding(soa)
    inc_first = orchestrator.process_finding(cost)
    timeline_len_before = len(inc_first.timeline)

    # Reprocess the exact same cost finding (e.g. daily cron re-run)
    inc_repeated = orchestrator.process_finding(cost)

    assert inc_repeated.incident_id == inc_first.incident_id
    # Timeline should NOT duplicate the SECURITY_FINOPS_CORRELATED entry
    assert len(inc_repeated.timeline) == timeline_len_before


def test_standalone_cost_anomaly_remains_uncorrelated(mock_db):
    orchestrator = IncidentOrchestrator(db_repo=mock_db)
    cost = create_cost_finding(
        resource_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-solo-cost",
        name="vm-solo-cost",
        cost_category="Compute",
    )

    inc = orchestrator.process_finding(cost)

    assert inc.cost_impact is None
    assert inc.title.startswith("Cost Anomaly:")
    assert len(inc.timeline) == 1
    assert inc.timeline[0]["event"] == "COST_ANOMALY_DETECTED"
