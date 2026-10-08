import pytest
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
)
from models.incident import IncidentStatus
from services.incident_orchestrator import IncidentOrchestrator


def test_orchestrator_creates_incident_from_finding(mock_db):
    orchestrator = IncidentOrchestrator(db_repo=mock_db)
    fid = generate_deterministic_finding_id("evt-orch-1", "/sub/vm-new")
    finding = Finding(
        finding_id=fid,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(id="/sub/vm-new", type="Microsoft.Compute/virtualMachines", name="vm-new", resource_group="rg-prod"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", activity_log_event_id="evt-orch-1"),
        confidence=0.85,
    )

    incident = orchestrator.process_finding(finding)

    assert incident is not None
    assert incident.incident_id.startswith("INC-")
    assert incident.title == "New Resource Created: vm-new (virtualMachines)"
    assert incident.status == IncidentStatus.OPEN
    assert incident.severity == SeverityLevel.MEDIUM
    assert fid in incident.findings
    assert len(incident.timeline) == 1
    assert incident.timeline[0]["event"] == "RESOURCE_CREATION_DETECTED"
    assert incident.cost_impact is None
    assert incident.ai_analysis is None
    assert incident.remediation is None


def test_orchestrator_correlates_subsequent_findings_and_upgrades_severity(mock_db):
    orchestrator = IncidentOrchestrator(db_repo=mock_db)
    
    # First finding: Medium
    fid1 = generate_deterministic_finding_id("evt-1", "/sub/shared-res")
    finding1 = Finding(
        finding_id=fid1,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(id="/sub/shared-res", type="Microsoft.Compute/virtualMachines", name="shared-res", resource_group="rg-prod"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(operation="WRITE", activity_log_event_id="evt-1"),
        confidence=0.85,
    )
    inc1 = orchestrator.process_finding(finding1)
    assert inc1.severity == SeverityLevel.MEDIUM

    # Second finding for same resource/caller: High
    fid2 = generate_deterministic_finding_id("evt-2", "/sub/shared-res")
    finding2 = Finding(
        finding_id=fid2,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-08T10:05:00Z",
        resource=ResourceInfo(id="/sub/shared-res", type="Microsoft.Compute/virtualMachines", name="shared-res", resource_group="rg-prod"),
        identity=IdentityInfo(caller="operator@cloudpulse.io"),
        evidence=EvidenceInfo(operation="WRITE", activity_log_event_id="evt-2"),
        confidence=0.90,
    )
    inc2 = orchestrator.process_finding(finding2)

    assert inc2.incident_id == inc1.incident_id
    assert inc2.severity == SeverityLevel.HIGH  # Upgraded
    assert fid1 in inc2.findings
    assert fid2 in inc2.findings
    assert len(inc2.timeline) == 2
