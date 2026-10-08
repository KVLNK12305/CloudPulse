import pytest
from pydantic import ValidationError

from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id


def test_valid_finding_creation():
    finding_id = generate_deterministic_finding_id("evt-123", "/sub/rg/vm/vm1")
    finding = Finding(
        finding_id=finding_id,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(
            id="/sub/rg/vm/vm1",
            type="Microsoft.Compute/virtualMachines",
            name="vm1",
            resource_group="rg",
        ),
        identity=IdentityInfo(
            principal_id="p-1",
            principal_type="User",
            caller="user@cloudpulse.io",
        ),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            activity_log_event_id="evt-123",
            correlation_id="corr-1",
        ),
        confidence=0.85,
    )
    assert finding.finding_id == finding_id
    assert finding.confidence == 0.85
    assert finding.severity == SeverityLevel.MEDIUM


def test_confidence_validation():
    finding_id = generate_deterministic_finding_id("evt-123", "/sub/rg/vm/vm1")
    resource = ResourceInfo(id="/sub/rg/vm/vm1", type="Microsoft.Compute/virtualMachines", name="vm1", resource_group="rg")
    identity = IdentityInfo(caller="user@cloudpulse.io")
    evidence = EvidenceInfo(operation="OP", activity_log_event_id="evt-123")

    # Invalid: > 1.0
    with pytest.raises(ValidationError):
        Finding(
            finding_id=finding_id,
            finding_type="RESOURCE_CREATION",
            severity=SeverityLevel.LOW,
            timestamp="2026-10-08T10:00:00Z",
            resource=resource,
            identity=identity,
            evidence=evidence,
            confidence=1.5,
        )

    # Invalid: < 0.0
    with pytest.raises(ValidationError):
        Finding(
            finding_id=finding_id,
            finding_type="RESOURCE_CREATION",
            severity=SeverityLevel.LOW,
            timestamp="2026-10-08T10:00:00Z",
            resource=resource,
            identity=identity,
            evidence=evidence,
            confidence=-0.1,
        )


def test_deterministic_finding_id_stability():
    id1 = generate_deterministic_finding_id("EVENT-ABC", "/subscriptions/1/vm/test")
    id2 = generate_deterministic_finding_id("event-abc", "/subscriptions/1/vm/test")
    id3 = generate_deterministic_finding_id("EVENT-XYZ", "/subscriptions/1/vm/test")

    assert id1.startswith("F-RC-")
    assert id1 == id2  # Case-insensitive / stable
    assert id1 != id3


def test_deterministic_incident_id_stability():
    inc1 = generate_deterministic_incident_id("/subscriptions/1/vm/test", "caller@cloudpulse.io")
    inc2 = generate_deterministic_incident_id("/subscriptions/1/vm/test", None)
    inc3 = generate_deterministic_incident_id("/subscriptions/1/vm/different", "caller@cloudpulse.io")

    assert inc1.startswith("INC-RC-")
    assert inc1 == inc2  # Deduplicates to the same incident regardless of caller presentation
    assert inc1 != inc3


def test_incident_model_defaults():
    inc = Incident(
        incident_id="INC-001",
        title="Test Incident",
        severity=SeverityLevel.HIGH,
        resource=ResourceInfo(id="/res", type="Microsoft.Network/publicIPAddresses", name="pip", resource_group="rg"),
        identity=IdentityInfo(caller="secops@cloudpulse.io"),
        findings=["F-RC-123"],
    )
    assert inc.status == IncidentStatus.OPEN
    assert inc.cost_impact is None
    assert inc.ai_analysis is None
    assert inc.remediation is None
    assert len(inc.findings) == 1
