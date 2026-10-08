import os
import pytest
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id


def test_migration_sql_exists_and_valid():
    migration_path = os.path.join(
        os.path.dirname(__file__), "..", "database", "migrations", "001_initial_schema.sql"
    )
    assert os.path.exists(migration_path)
    with open(migration_path, "r", encoding="utf-8") as f:
        sql = f.read()
    assert "CREATE TABLE IF NOT EXISTS findings" in sql
    assert "CREATE TABLE IF NOT EXISTS incidents" in sql
    assert "idx_findings_finding_type" in sql
    assert "idx_incidents_severity" in sql
    assert "idx_incident_findings_finding_id" in sql


def test_save_and_retrieve_finding(mock_db):
    fid = generate_deterministic_finding_id("evt-db-1", "/sub/vm1")
    finding = Finding(
        finding_id=fid,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(id="/sub/vm1", type="Microsoft.Compute/virtualMachines", name="vm1", resource_group="rg"),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(operation="WRITE", activity_log_event_id="evt-db-1"),
        confidence=0.85,
    )

    inserted = mock_db.save_finding(finding)
    assert inserted is True

    fetched = mock_db.get_finding(fid)
    assert fetched is not None
    assert fetched.finding_id == fid
    assert fetched.resource.name == "vm1"


def test_duplicate_finding_handling(mock_db):
    fid = generate_deterministic_finding_id("evt-db-dup", "/sub/vm2")
    finding = Finding(
        finding_id=fid,
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.MEDIUM,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(id="/sub/vm2", type="Microsoft.Compute/virtualMachines", name="vm2", resource_group="rg"),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(operation="WRITE", activity_log_event_id="evt-db-dup"),
        confidence=0.85,
    )

    # First insert succeeds
    assert mock_db.save_finding(finding) is True
    # Duplicate insert is rejected cleanly
    assert mock_db.save_finding(finding) is False

    findings_list = mock_db.list_findings()
    assert len([f for f in findings_list if f.finding_id == fid]) == 1


def test_save_and_update_incident(mock_db):
    iid = generate_deterministic_incident_id("/sub/vm1", "admin@cloudpulse.io")
    incident = Incident(
        incident_id=iid,
        title="New Resource Created: vm1 (virtualMachines)",
        severity=SeverityLevel.MEDIUM,
        resource=ResourceInfo(id="/sub/vm1", type="Microsoft.Compute/virtualMachines", name="vm1", resource_group="rg"),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        findings=["F-1"],
    )

    # First save
    assert mock_db.save_incident(incident) is True

    # Update with additional finding
    incident.findings.append("F-2")
    assert mock_db.save_incident(incident) is False  # False indicates existing updated

    fetched = mock_db.get_incident(iid)
    assert fetched is not None
    assert "F-1" in fetched.findings
    assert "F-2" in fetched.findings
