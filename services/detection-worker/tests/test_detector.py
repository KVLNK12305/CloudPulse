import pytest
from models.finding import SeverityLevel


def test_detect_virtual_machine_creation(detector, vm_creation_event):
    findings = detector.detect([vm_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "RESOURCE_CREATION"
    assert f.resource.type == "Microsoft.Compute/virtualMachines"
    assert f.resource.name == "vm-app-01"
    assert f.severity == SeverityLevel.MEDIUM
    assert 0.85 <= f.confidence <= 1.0
    assert f.evidence.activity_log_event_id == "vm-evt-001"
    assert f.identity.caller == "admin@cloudpulse.io"


def test_detect_public_ip_creation(detector, public_ip_creation_event):
    findings = detector.detect([public_ip_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.resource.type == "Microsoft.Network/publicIPAddresses"
    assert f.severity == SeverityLevel.HIGH  # High risk due to external exposure
    assert f.confidence >= 0.90


def test_detect_storage_account_creation(detector, storage_account_creation_event):
    findings = detector.detect([storage_account_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.resource.type == "Microsoft.Storage/storageAccounts"
    assert f.severity == SeverityLevel.MEDIUM


def test_detect_nsg_creation(detector, nsg_creation_event):
    findings = detector.detect([nsg_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.resource.type == "Microsoft.Network/networkSecurityGroups"
    assert f.severity == SeverityLevel.MEDIUM


def test_detect_role_assignment_creation(detector, role_assignment_creation_event):
    findings = detector.detect([role_assignment_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.resource.type == "Microsoft.Authorization/roleAssignments"
    assert f.severity == SeverityLevel.HIGH  # High risk due to IAM permissions


def test_detect_container_app_creation(detector, container_app_creation_event):
    findings = detector.detect([container_app_creation_event])
    assert len(findings) == 1
    f = findings[0]
    assert f.resource.type == "Microsoft.App/containerApps"
    assert f.severity == SeverityLevel.MEDIUM


def test_successful_write_without_creation_ignored(detector, write_update_only_event):
    """Ensure conservative detection: /WRITE events without creation signal are ignored."""
    findings = detector.detect([write_update_only_event])
    assert len(findings) == 0


def test_irrelevant_resource_type_ignored(detector, irrelevant_resource_event):
    """Ensure resources outside the 6 MVP categories are ignored."""
    findings = detector.detect([irrelevant_resource_event])
    assert len(findings) == 0


def test_missing_optional_identity_handled_safely(detector, vm_creation_event):
    """Ensure missing caller or claims does not cause failure."""
    vm_creation_event["Caller"] = None
    vm_creation_event["Claims_d"] = None
    vm_creation_event["Authorization_d"] = None

    findings = detector.detect([vm_creation_event])
    assert len(findings) == 1
    assert findings[0].identity.caller is None
    assert findings[0].identity.principal_id is None


def test_malformed_event_handled_safely(detector):
    """Ensure corrupted or incomplete events are skipped gracefully."""
    malformed_events = [
        {},
        {"OperationNameValue": "INVALID"},
        {"OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE"},  # Missing status & resource
        {"OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "ActivityStatusValue": "Failed"},
        {"Properties_d": "NOT_JSON_AT_ALL{{{"},
    ]
    findings = detector.detect(malformed_events)
    assert len(findings) == 0


def test_kql_query_generation(detector):
    query = detector.get_kql_query(lookback_minutes=30)
    assert "AzureActivity" in query
    assert "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" in query
    assert "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" in query
    assert "ago(30m)" in query
