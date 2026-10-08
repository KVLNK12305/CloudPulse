"""
Deterministic network flow telemetry fixtures for testing SUSPICIOUS_OUTBOUND_ACTIVITY.
Provides replay data modeled after AzureNetworkAnalytics_CL schema.
"""

from typing import List, Dict, Any

# Primary test workload
WORKLOAD_VM_01 = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
WORKLOAD_VM_DATA = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-db-data-01"
WORKLOAD_VM_NEW = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-new-workload-01"

SUBNET_WORKER = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/virtualNetworks/cloudpulse-vnet/subnets/snet-worker"
SUBNET_DATA = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/virtualNetworks/cloudpulse-vnet/subnets/snet-data"


def make_flow_record(
    vm: str = WORKLOAD_VM_01,
    subnet: str = SUBNET_WORKER,
    src_ip: str = "10.50.3.4",
    dest_ip: str = "93.184.216.34",
    dest_port: int = 443,
    protocol: str = "TCP",
    bytes_sent: int = 25000,
    bytes_received: int = 150000,
    packets_sent: int = 45,
    packets_received: int = 120,
    flow_direction: str = "O",
    flow_status: str = "A",
    flow_count: int = 1,
    timestamp: str = "2026-10-08T14:15:00Z",
) -> Dict[str, Any]:
    """Helper to generate an AzureNetworkAnalytics_CL shaped dictionary."""
    return {
        "TimeGenerated": timestamp,
        "VM_s": vm,
        "SrcSubnet_s": subnet,
        "SourceIP_s": src_ip,
        "DestPublicIPs_s": dest_ip,
        "DestPort_d": float(dest_port),
        "L4Protocol_s": protocol,
        "TotalBytesSent": bytes_sent,
        "TotalBytesReceived": bytes_received,
        "TotalPacketsSent": packets_sent,
        "TotalPacketsReceived": packets_received,
        "FlowCount": flow_count,
        "FlowDirection_s": flow_direction,
        "FlowStatus_s": flow_status,
        "SubscriptionId": "90b900ea-4273-4b40-a343-091aecfe2911",
        "ResourceGroup": "cloudpulse-rg",
    }


def mining_flow_fixture() -> Dict[str, Any]:
    """Outbound connection to Stratum mining pool port 3333."""
    return make_flow_record(
        dest_ip="198.51.100.77",
        dest_port=3333,
        protocol="TCP",
        bytes_sent=15482910,
        bytes_received=14200,
        flow_count=84,
    )


def volume_spike_fixture(bytes_sent: int = 1500 * 1024 * 1024) -> Dict[str, Any]:
    """Significant outbound egress spike (default 1.5 GB)."""
    return make_flow_record(
        dest_ip="198.51.100.99",
        dest_port=443,
        protocol="TCP",
        bytes_sent=bytes_sent,
        bytes_received=50000,
        flow_count=250,
    )


def massive_exfiltration_fixture() -> Dict[str, Any]:
    """Massive outbound egress (> 5 GB)."""
    return make_flow_record(
        dest_ip="203.0.113.88",
        dest_port=443,
        protocol="TCP",
        bytes_sent=6 * 1024 * 1024 * 1024,  # 6 GB
        bytes_received=12000,
        flow_count=500,
    )


def management_port_ssh_fixture() -> Dict[str, Any]:
    """Outbound SSH (port 22) to external public IP."""
    return make_flow_record(
        dest_ip="203.0.113.50",
        dest_port=22,
        protocol="TCP",
        bytes_sent=45000,
        bytes_received=82000,
        flow_count=3,
    )


def management_port_rdp_fixture() -> Dict[str, Any]:
    """Outbound RDP (port 3389) to external public IP."""
    return make_flow_record(
        dest_ip="203.0.113.51",
        dest_port=3389,
        protocol="TCP",
        bytes_sent=120000,
        bytes_received=340000,
        flow_count=1,
    )


def scanning_sweep_fixtures(num_targets: int = 60) -> List[Dict[str, Any]]:
    """Burst scanning: workload connecting to > 50 distinct public IPs."""
    records = []
    for i in range(num_targets):
        records.append(
            make_flow_record(
                dest_ip=f"198.51.100.{i + 1}",
                dest_port=80,
                protocol="TCP",
                bytes_sent=64,
                bytes_received=0,
                packets_sent=3,
                packets_received=0,
                flow_count=1,
            )
        )
    return records


def subnet_violation_fixture() -> Dict[str, Any]:
    """Database workload in snet-data attempting direct Internet egress."""
    return make_flow_record(
        vm=WORKLOAD_VM_DATA,
        subnet=SUBNET_DATA,
        src_ip="10.50.4.15",
        dest_ip="198.51.100.22",
        dest_port=443,
        protocol="TCP",
        bytes_sent=500000,
        bytes_received=250000,
        flow_count=5,
    )


def internal_traffic_fixture() -> Dict[str, Any]:
    """Internal RFC 1918 traffic between virtual network subnets."""
    return make_flow_record(
        src_ip="10.50.3.4",
        dest_ip="10.50.4.10",
        dest_port=5432,
        protocol="TCP",
        bytes_sent=1000 * 1024 * 1024,  # 1 GB internal transfer
        bytes_received=500 * 1024 * 1024,
        flow_count=100,
    )


def standard_approved_dns_fixture() -> Dict[str, Any]:
    """Standard recursive DNS to Azure Wire Server (168.63.129.16 UDP 53)."""
    return make_flow_record(
        dest_ip="168.63.129.16",
        dest_port=53,
        protocol="UDP",
        bytes_sent=1500,
        bytes_received=4500,
        flow_count=30,
    )


def standard_approved_cloudflare_dns_fixture() -> Dict[str, Any]:
    """Standard DNS to Cloudflare resolver (1.1.1.1 UDP 53)."""
    return make_flow_record(
        dest_ip="1.1.1.1",
        dest_port=53,
        protocol="UDP",
        bytes_sent=1200,
        bytes_received=3800,
        flow_count=25,
    )


def normal_known_traffic_fixture() -> Dict[str, Any]:
    """Normal traffic to a known destination IP."""
    return make_flow_record(
        dest_ip="93.184.216.34",  # In known baseline
        dest_port=443,
        protocol="TCP",
        bytes_sent=1500000,  # 1.5 MB, normal volume
        bytes_received=8500000,
        flow_count=12,
    )
