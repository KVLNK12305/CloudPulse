import pytest
import hashlib
from datetime import datetime, timezone

from detectors.unexpected_public_exposure import UnexpectedPublicExposureDetector
from models.finding import (
    Finding,
    SeverityLevel,
    generate_exposure_finding_id,
)
from models.incident import Incident, generate_deterministic_incident_id
from services.incident_orchestrator import IncidentOrchestrator
from database.postgres import InMemoryDatabase


def build_test_topology(
    pip_associated: bool = True,
    nic_nsg_attached: bool = True,
    subnet_nsg_attached: bool = False,
    rules: list = None,
    subnet_name: str = "snet-backend",
    has_vm: bool = True,
    public_ip_addr: str = "20.198.110.45",
):
    """Helper to construct deterministic Azure network topologies for testing."""
    sub_id = "90b900ea-4273-4b40-a343-091aecfe2911"
    rg = "cloudpulse-rg"
    pip_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/publicIPAddresses/pip-test"
    ip_cfg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/nic-test/ipConfigurations/ipconfig1"
    nic_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/nic-test"
    vm_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/vm-test"
    nsg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/nsg-test"
    subnet_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/{subnet_name}"

    default_rules = [
        {
            "name": "Allow-SSH",
            "id": f"{nsg_id}/securityRules/Allow-SSH",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "0.0.0.0/0",
                "destinationPortRange": "22",
                "priority": 100,
            },
        }
    ]

    actual_rules = rules if rules is not None else default_rules

    topology = {
        "public_ips": {
            pip_id.lower(): {
                "id": pip_id,
                "name": "pip-test",
                "ip_address": public_ip_addr,
                "ip_configuration_id": ip_cfg_id if pip_associated else None,
                "resource_group": rg,
                "subscription_id": sub_id,
            }
        },
        "nics": {
            nic_id.lower(): {
                "id": nic_id,
                "name": "nic-test",
                "vm_id": vm_id if has_vm else None,
                "nsg_id": nsg_id if nic_nsg_attached else None,
                "ip_configurations": [
                    {
                        "id": ip_cfg_id,
                        "name": "ipconfig1",
                        "public_ip_id": pip_id,
                        "subnet_id": subnet_id,
                    }
                ],
                "resource_group": rg,
                "subscription_id": sub_id,
            }
        },
        "nsgs": {
            nsg_id.lower(): {
                "id": nsg_id,
                "name": "nsg-test",
                "rules": actual_rules,
                "resource_group": rg,
                "subscription_id": sub_id,
            }
        },
        "vms": (
            {
                vm_id.lower(): {
                    "id": vm_id,
                    "name": "vm-test",
                    "nic_ids": [nic_id],
                    "resource_group": rg,
                    "subscription_id": sub_id,
                }
            }
            if has_vm
            else {}
        ),
        "subnets": {
            subnet_id.lower(): {
                "id": subnet_id,
                "name": subnet_name,
                "nsg_id": nsg_id if subnet_nsg_attached else None,
            }
        },
    }
    return topology


# 1. Internet -> TCP/22 -> CRITICAL
def test_internet_ssh_port_22_critical():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Allow-SSH",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-SSH",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "22",
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.evidence.exposure_type == "MANAGEMENT_PORT"
    assert f.evidence.destination_port == "22"
    assert f.evidence.protocol == "TCP"
    assert f.confidence == 0.95


# 2. Internet -> TCP/3389 -> CRITICAL
def test_internet_rdp_port_3389_critical():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Allow-RDP",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-RDP",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "3389",
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.CRITICAL
    assert f.evidence.exposure_type == "MANAGEMENT_PORT"
    assert f.evidence.destination_port == "3389"


# 3. Internet -> database port -> CRITICAL
@pytest.mark.parametrize("db_port,db_name", [
    ("5432", "PostgreSQL"),
    ("3306", "MySQL"),
    ("1433", "MSSQL"),
    ("27017", "MongoDB"),
    ("6379", "Redis"),
    ("9200", "Elasticsearch"),
])
def test_internet_database_ports_critical(db_port, db_name):
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": f"Allow-{db_name}",
                "id": f"/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-{db_name}",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": db_port,
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.CRITICAL
    assert f.evidence.exposure_type == "DATABASE_PORT"
    assert f.evidence.destination_port == db_port


# 4. broad port range -> HIGH
@pytest.mark.parametrize("broad_range", ["1-65535", "0-1024", "*"])
def test_broad_port_range_high(broad_range):
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Allow-Broad",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-Broad",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": broad_range,
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    # If range spans management ports (like 1-65535 covering 22), it flags MANAGEMENT_PORT or WILDCARD_PORTS
    if broad_range == "*":
        assert f.severity == SeverityLevel.HIGH
        assert f.evidence.exposure_type == "WILDCARD_PORTS"


# 5. application port such as 8080 -> MEDIUM
@pytest.mark.parametrize("app_port", ["8080", "8443", "5000", "8000"])
def test_application_port_medium(app_port):
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": f"Allow-App-{app_port}",
                "id": f"/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-App-{app_port}",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": app_port,
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.MEDIUM
    assert f.evidence.exposure_type == "UNPROTECTED_SERVICE"
    assert f.evidence.destination_port == app_port


# 6. restricted/private source -> not a critical public exposure
@pytest.mark.parametrize("private_cidr", [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.1.0/24",
    "10.50.4.0/24",
    "VirtualNetwork",
    "AzureLoadBalancer",
])
def test_restricted_private_source_ignored(private_cidr):
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Allow-Internal-SSH",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-Internal-SSH",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": private_cidr,
                    "destinationPortRange": "22",
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 7. Deny rule -> ignored
def test_deny_rule_ignored():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Deny-SSH",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Deny-SSH",
                "properties": {
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 8. outbound rule -> ignored
def test_outbound_rule_ignored():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        rules=[
            {
                "name": "Allow-Outbound-Internet",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-Outbound",
                "properties": {
                    "direction": "Outbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
            }
        ]
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 9. Public IP without actual association -> no exposure finding
def test_unassociated_public_ip_no_finding():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        pip_associated=False,  # Unattached Public IP
        rules=[
            {
                "name": "Allow-SSH",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-SSH",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "22",
                },
            }
        ],
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 10. NSG not actually associated with target -> no exposure finding
def test_unassociated_nsg_no_finding():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        pip_associated=True,
        nic_nsg_attached=False,      # NSG not attached to NIC
        subnet_nsg_attached=False,   # NSG not attached to Subnet
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 11. legitimate edge HTTPS -> not incorrectly classified as CRITICAL
def test_legitimate_edge_https_not_critical():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology(
        subnet_name="snet-edge",
        rules=[
            {
                "name": "Allow-HTTPS-Public",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/Allow-HTTPS",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "443",
                },
            }
        ],
    )
    findings = detector.detect(topology=topology)
    assert len(findings) == 0


# 12. deterministic finding ID verification
def test_deterministic_finding_id_formula():
    res_id = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-backend-01"
    rule_id = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg-worker/securityRules/Allow-SSH-All"
    protocol = "TCP"
    dest_port = "22"

    seed = f"{res_id}:{rule_id}:{protocol}:{dest_port}"
    expected_digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
    expected_id = f"F-UPE-{expected_digest}"

    calculated_id = generate_exposure_finding_id(res_id, rule_id, protocol, dest_port)
    assert calculated_id == expected_id
    assert calculated_id.startswith("F-UPE-")
    assert len(calculated_id) == 18  # "F-UPE-" (6) + 12 chars = 18


# 13. repeated evaluation -> same finding ID / database deduplication
def test_repeated_evaluation_deduplication():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology()

    # Evaluation 1
    findings_1 = detector.detect(topology=topology)
    assert len(findings_1) == 1
    fid_1 = findings_1[0].finding_id

    # Evaluation 2
    findings_2 = detector.detect(topology=topology)
    assert len(findings_2) == 1
    fid_2 = findings_2[0].finding_id

    # Same finding ID generated deterministically
    assert fid_1 == fid_2

    # Database repository deduplication
    db = InMemoryDatabase()
    is_new_1 = db.save_finding(findings_1[0])
    assert is_new_1 is True

    is_new_2 = db.save_finding(findings_2[0])
    assert is_new_2 is False  # Deduplicated by finding_id

    assert len(db.list_findings()) == 1

    # Incident Orchestrator correlation
    orchestrator = IncidentOrchestrator(db)
    inc1 = orchestrator.process_finding(findings_1[0])
    assert inc1.severity == SeverityLevel.CRITICAL
    assert len(inc1.findings) == 1

    # Process duplicate finding
    inc2 = orchestrator.process_finding(findings_2[0])
    assert inc2.incident_id == inc1.incident_id
    assert len(inc2.findings) == 1  # No duplicate finding attached


# 14. AzureActivity candidate event trigger verification
def test_candidate_event_trigger_with_topology():
    detector = UnexpectedPublicExposureDetector()
    topology = build_test_topology()

    nsg_rule_write_event = {
        "TimeGenerated": "2026-10-08T12:00:00Z",
        "EventDataId": "evt-candidate-001",
        "CorrelationId": "corr-candidate-001",
        "OperationNameValue": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "ActivityStatusValue": "Success",
        "_ResourceId": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-test/securityRules/Allow-SSH",
        "Caller": "secops@cloudpulse.io",
        "CallerIpAddress": "203.0.113.1",
        "Properties_d": {
            "direction": "Inbound",
            "access": "Allow",
            "sourceAddressPrefix": "0.0.0.0/0",
            "destinationPortRange": "22",
        },
    }

    findings = detector.detect(raw_events=[nsg_rule_write_event], topology=topology)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE"
    assert f.identity.caller == "secops@cloudpulse.io"
    assert f.evidence.operation == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
    assert f.evidence.activity_log_event_id == "evt-candidate-001"
