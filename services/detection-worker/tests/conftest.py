import pytest
from typing import Dict, Any

from database.postgres import InMemoryDatabase
from detectors.resource_creation import ResourceCreationDetector
from services.incident_orchestrator import IncidentOrchestrator
from services.detection_service import DetectionService
from app import create_app


@pytest.fixture
def mock_db():
    return InMemoryDatabase()


@pytest.fixture
def detector():
    return ResourceCreationDetector()


@pytest.fixture
def orchestrator(mock_db):
    return IncidentOrchestrator(db_repo=mock_db)


@pytest.fixture
def detection_service(mock_db, detector, orchestrator):
    return DetectionService(
        db_repo=mock_db,
        log_client=None,
        detector=detector,
        orchestrator=orchestrator,
    )


@pytest.fixture
def app(mock_db):
    app = create_app(db_repo=mock_db, log_client=None)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# --- Sample Telemetry Fixtures ---

@pytest.fixture
def vm_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:00:00Z",
        "EventDataId": "vm-evt-001",
        "CorrelationId": "corr-vm-001",
        "OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-app-01",
        "ResourceGroup": "rg-prod",
        "SubscriptionId": "sub-123",
        "Caller": "admin@cloudpulse.io",
        "CallerIpAddress": "198.51.100.10",
        "Properties_d": "{\"statusCode\": \"Created\", \"activitySubstatusValue\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"usr-001\", \"principalType\": \"User\"}}",
        "Claims_d": "{\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn\": \"admin@cloudpulse.io\"}",
    }


@pytest.fixture
def public_ip_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:05:00Z",
        "EventDataId": "pip-evt-002",
        "CorrelationId": "corr-pip-002",
        "OperationNameValue": "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/pip-external",
        "ResourceGroup": "rg-prod",
        "SubscriptionId": "sub-123",
        "Caller": "secops@cloudpulse.io",
        "CallerIpAddress": "203.0.113.4",
        "Properties_d": "{\"statusCode\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"usr-002\", \"principalType\": \"User\"}}",
    }


@pytest.fixture
def storage_account_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:10:00Z",
        "EventDataId": "stg-evt-003",
        "CorrelationId": "corr-stg-003",
        "OperationNameValue": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/cloudpulseshare01",
        "ResourceGroup": "rg-data",
        "SubscriptionId": "sub-123",
        "Caller": "dataeng@cloudpulse.io",
        "CallerIpAddress": "198.51.100.22",
        "Properties_d": "{\"statusCode\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"usr-003\", \"principalType\": \"User\"}}",
    }


@pytest.fixture
def nsg_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:15:00Z",
        "EventDataId": "nsg-evt-004",
        "CorrelationId": "corr-nsg-004",
        "OperationNameValue": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-dmz",
        "ResourceGroup": "rg-network",
        "SubscriptionId": "sub-123",
        "Caller": "neteng@cloudpulse.io",
        "CallerIpAddress": "198.51.100.5",
        "Properties_d": "{\"statusCode\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"usr-004\", \"principalType\": \"User\"}}",
    }


@pytest.fixture
def role_assignment_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:20:00Z",
        "EventDataId": "rbac-evt-005",
        "CorrelationId": "corr-rbac-005",
        "OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/role-perm-999",
        "ResourceGroup": "",
        "SubscriptionId": "sub-123",
        "Caller": "iam-admin@cloudpulse.io",
        "CallerIpAddress": "198.51.100.8",
        "Properties_d": "{\"roleAssignmentId\": \"role-perm-999\", \"statusCode\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"admin-oid-77\", \"principalType\": \"User\", \"roleAssignmentId\": \"role-perm-999\"}}",
    }


@pytest.fixture
def container_app_creation_event() -> Dict[str, Any]:
    return {
        "TimeGenerated": "2026-10-08T10:25:00Z",
        "EventDataId": "aca-evt-006",
        "CorrelationId": "corr-aca-006",
        "OperationNameValue": "MICROSOFT.APP/CONTAINERAPPS/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-apps/providers/Microsoft.App/containerApps/cloudpulse-api",
        "ResourceGroup": "rg-apps",
        "SubscriptionId": "sub-123",
        "Caller": "devops@cloudpulse.io",
        "CallerIpAddress": "198.51.100.12",
        "Properties_d": "{\"statusCode\": \"Created\", \"activitySubstatusValue\": \"Created\"}",
        "Authorization_d": "{\"evidence\": {\"principalId\": \"spn-deployer\", \"principalType\": \"ServicePrincipal\"}}",
    }


@pytest.fixture
def write_update_only_event() -> Dict[str, Any]:
    """A write event that is merely an update (OK / 200, no Created signal)."""
    return {
        "TimeGenerated": "2026-10-08T10:30:00Z",
        "EventDataId": "vm-update-001",
        "CorrelationId": "corr-vm-upd",
        "OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "OK",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-app-01",
        "ResourceGroup": "rg-prod",
        "SubscriptionId": "sub-123",
        "Caller": "admin@cloudpulse.io",
        "Properties_d": "{\"statusCode\": \"OK\"}",
    }


@pytest.fixture
def irrelevant_resource_event() -> Dict[str, Any]:
    """An event for a resource type outside our 6 MVP categories (e.g. DNS Zone)."""
    return {
        "TimeGenerated": "2026-10-08T10:35:00Z",
        "EventDataId": "dns-evt-001",
        "CorrelationId": "corr-dns",
        "OperationNameValue": "MICROSOFT.NETWORK/DNSZONES/WRITE",
        "ActivityStatusValue": "Success",
        "ActivitySubstatusValue": "Created",
        "_ResourceId": "/subscriptions/sub-123/resourceGroups/rg-dns/providers/Microsoft.Network/dnsZones/example.com",
        "ResourceGroup": "rg-dns",
        "Caller": "admin@cloudpulse.io",
    }
