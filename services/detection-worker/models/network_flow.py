from typing import Optional, Set
from pydantic import BaseModel, Field


class NetworkFlowEvent(BaseModel):
    """
    Clean internal representation of an Azure network flow event.
    Normalized from AzureNetworkAnalytics_CL or replay telemetry.
    """
    timestamp: str = Field(..., description="Timestamp of the network flow event in ISO 8601 format")
    resource_id: str = Field(..., description="Full Azure Resource ID of the initiating workload")
    destination_ip: str = Field(..., description="Destination IP address (public or private)")
    destination_port: int = Field(..., description="Destination L4 port")
    protocol: str = Field(default="TCP", description="L4 protocol (TCP, UDP)")
    source_ip: Optional[str] = Field(None, description="Source IP address of the workload")
    bytes_sent: int = Field(default=0, description="Total outbound bytes transmitted")
    bytes_received: int = Field(default=0, description="Total inbound bytes received")
    packets_sent: int = Field(default=0, description="Total outbound packets transmitted")
    packets_received: int = Field(default=0, description="Total inbound packets received")
    flow_direction: str = Field(default="O", description="Flow direction: 'O' for outbound, 'I' for inbound")
    flow_status: str = Field(default="A", description="Flow status: 'A' for allowed, 'D' for denied")
    flow_count: int = Field(default=1, description="Number of aggregated flow sessions")
    subnet_id: Optional[str] = Field(None, description="Source subnet name or full ARM resource ID")
    resource_group: Optional[str] = Field(None, description="Resource group name")
    subscription_id: Optional[str] = Field(None, description="Azure subscription ID")


class WorkloadBaseline(BaseModel):
    """
    Deterministic baseline statistics for a workload over historical baseline window (7 days).
    """
    resource_id: str = Field(..., description="Full Azure Resource ID")
    mean_hourly_bytes: float = Field(default=0.0, description="Mean hourly outbound bytes over baseline window")
    std_hourly_bytes: float = Field(default=0.0, description="Standard deviation of hourly outbound bytes")
    known_destination_ips: Set[str] = Field(default_factory=set, description="Set of known external destination IPs")
    historical_hours: int = Field(default=0, description="Total historical observation hours available")
    flow_count: int = Field(default=0, description="Total historical flow records observed")
    is_cold_start: bool = Field(default=False, description="True if baseline history is insufficient (< 10 hours)")
