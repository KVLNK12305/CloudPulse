import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Set, Union

from models.network_flow import NetworkFlowEvent, WorkloadBaseline
from telemetry.log_analytics import LogAnalyticsClient, LogAnalyticsQueryError

logger = logging.getLogger("cloudpulse.telemetry.network_flow")


class BaselineStore(ABC):
    """Abstract interface for retrieving workload network baselines."""

    @abstractmethod
    def get_baseline(self, resource_id: str) -> WorkloadBaseline:
        """Retrieve historical baseline for the specified resource ID."""
        pass


class InMemoryBaselineStore(BaselineStore):
    """
    In-memory baseline store for testing, offline replay, and local caching.
    """

    def __init__(self, baselines: Optional[Dict[str, WorkloadBaseline]] = None):
        self._baselines: Dict[str, WorkloadBaseline] = baselines or {}

    def get_baseline(self, resource_id: str) -> WorkloadBaseline:
        clean_id = resource_id.strip()
        if clean_id in self._baselines:
            return self._baselines[clean_id]
        # Case-insensitive fallback
        for k, v in self._baselines.items():
            if k.lower() == clean_id.lower():
                return v

        # Default cold-start baseline when no history exists
        return WorkloadBaseline(
            resource_id=resource_id,
            mean_hourly_bytes=0.0,
            std_hourly_bytes=0.0,
            known_destination_ips=set(),
            historical_hours=0,
            flow_count=0,
            is_cold_start=True,
        )

    def set_baseline(self, resource_id: str, baseline: WorkloadBaseline) -> None:
        self._baselines[resource_id.strip()] = baseline

    @classmethod
    def from_historical_flows(cls, flows: List[NetworkFlowEvent]) -> "InMemoryBaselineStore":
        """
        Compute deterministic baselines from historical flow events.
        Groups events by resource_id and hourly buckets to calculate mean hourly egress and known destination IPs.
        """
        resource_hourly_bytes: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        resource_dest_ips: Dict[str, Set[str]] = defaultdict(set)
        resource_flow_counts: Dict[str, int] = defaultdict(int)

        for flow in flows:
            res_id = flow.resource_id
            resource_dest_ips[res_id].add(flow.destination_ip)
            resource_flow_counts[res_id] += flow.flow_count

            # Extract hour bucket from timestamp
            try:
                dt = datetime.fromisoformat(flow.timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%Y-%m-%d-%H")
            except Exception:
                hour_key = "default-hour"

            resource_hourly_bytes[res_id][hour_key] += flow.bytes_sent

        baselines: Dict[str, WorkloadBaseline] = {}
        for res_id, hourly_map in resource_hourly_bytes.items():
            hours_count = len(hourly_map)
            total_bytes = sum(hourly_map.values())
            mean_bytes = (total_bytes / hours_count) if hours_count > 0 else 0.0

            # Compute standard deviation if multiple hours
            if hours_count > 1:
                variance = sum((b - mean_bytes) ** 2 for b in hourly_map.values()) / (hours_count - 1)
                std_bytes = variance ** 0.5
            else:
                std_bytes = 0.0

            # Resource is in cold-start if history < 10 hours or flow count < 10
            is_cold = hours_count < 10 or resource_flow_counts[res_id] < 10

            baselines[res_id] = WorkloadBaseline(
                resource_id=res_id,
                mean_hourly_bytes=mean_bytes,
                std_hourly_bytes=std_bytes,
                known_destination_ips=resource_dest_ips[res_id],
                historical_hours=hours_count,
                flow_count=resource_flow_counts[res_id],
                is_cold_start=is_cold,
            )

        return cls(baselines)


class NetworkFlowAdapter:
    """
    Telemetry adapter for Azure network flow records (AzureNetworkAnalytics_CL).
    Normalizes raw Log Analytics or replay telemetry into strongly-typed NetworkFlowEvents.
    """

    def __init__(self, log_client: Optional[LogAnalyticsClient] = None):
        self._client = log_client

    @classmethod
    def build_outbound_flows_kql(cls, lookback_minutes: int = 60) -> str:
        """
        Build the deterministic KQL query for outbound network flows from AzureNetworkAnalytics_CL.
        """
        return f"""
AzureNetworkAnalytics_CL
| where FlowDirection_s == "O" and FlowStatus_s == "A"
| where TimeGenerated >= ago({lookback_minutes}m)
| where DestPublicIPs_s != "" and DestPublicIPs_s != "-"
| project
    TimeGenerated,
    VM_s,
    SrcSubnet_s,
    SourceIP_s,
    DestIP_s = DestPublicIPs_s,
    DestPort_d,
    L4Protocol_s,
    BytesSent_d,
    BytesReceived_d,
    PacketsSent_d,
    PacketsReceived_d
| summarize
    TotalBytesSent = sum(BytesSent_d),
    TotalBytesReceived = sum(BytesReceived_d),
    TotalPacketsSent = sum(PacketsSent_d),
    TotalPacketsReceived = sum(PacketsReceived_d),
    FlowCount = count()
    by VM_s, SrcSubnet_s, SourceIP_s, DestIP_s, DestPort_d, L4Protocol_s
| order by TotalBytesSent desc
""".strip()

    @classmethod
    def build_baseline_kql(cls, lookback_days: int = 7) -> str:
        """
        Build the deterministic KQL query to compute historical 7-day baselines in Log Analytics.
        """
        return f"""
AzureNetworkAnalytics_CL
| where FlowDirection_s == "O" and FlowStatus_s == "A"
| where TimeGenerated between (ago({lookback_days}d) .. ago(1h))
| where DestPublicIPs_s != "" and DestPublicIPs_s != "-"
| summarize
    HourlyBytes = sum(BytesSent_d),
    DistinctDestIPs = dcount(DestPublicIPs_s)
    by VM_s, bin(TimeGenerated, 1h)
| summarize
    MeanHourlyBytes = avg(HourlyBytes),
    HistoricalHours = count()
    by VM_s
""".strip()

    def check_table_exists(self, workspace_id: str) -> bool:
        """
        Determines whether AzureNetworkAnalytics_CL exists in the target Log Analytics workspace.
        Executes a safe read-only query.
        """
        if not self._client:
            return False

        try:
            # Safe read-only probe
            test_kql = "AzureNetworkAnalytics_CL | take 1"
            self._client.query_workspace(
                workspace_id=workspace_id,
                kql=test_kql,
                timespan=timedelta(minutes=5),
            )
            return True
        except LogAnalyticsQueryError as ex:
            error_msg = str(ex).lower()
            if "not exist" in error_msg or "could not be resolved" in error_msg or "failed to resolve" in error_msg or "semantic" in error_msg:
                logger.info("AzureNetworkAnalytics_CL does not exist in workspace %s: %s", workspace_id, str(ex))
                return False
            logger.warning("Query error while checking table existence: %s", str(ex))
            return False
        except Exception as ex:
            logger.warning("Unexpected error checking AzureNetworkAnalytics_CL existence: %s", str(ex))
            return False

    def query_outbound_flows(
        self,
        workspace_id: str,
        lookback_minutes: int = 60,
    ) -> List[NetworkFlowEvent]:
        """
        Queries Log Analytics for outbound network flows and returns normalized NetworkFlowEvents.
        """
        if not self._client:
            raise ValueError("LogAnalyticsClient is required to query live flows")

        kql = self.build_outbound_flows_kql(lookback_minutes=lookback_minutes)
        raw_records = self._client.query_workspace(
            workspace_id=workspace_id,
            kql=kql,
            timespan=timedelta(minutes=lookback_minutes),
        )
        return self.normalize_records(raw_records)

    def normalize_records(self, raw_records: List[Dict[str, Any]]) -> List[NetworkFlowEvent]:
        """
        Normalizes a list of raw Azure Log Analytics records or mock dicts into NetworkFlowEvents.
        Handles missing fields, schema variations, and delimiter parsing safely.
        """
        events: List[NetworkFlowEvent] = []
        for record in raw_records:
            try:
                norm_events = self.normalize_record(record)
                events.extend(norm_events)
            except Exception as e:
                logger.warning("Error normalizing flow record: %s (record: %s)", str(e), record)
                continue
        return events

    def normalize_record(self, record: Dict[str, Any]) -> List[NetworkFlowEvent]:
        """
        Normalizes a single record. If multiple destination IPs are aggregated in DestIP_s / DestPublicIPs_s,
        unpacks into individual events with distributed volume or emits primary records.
        """
        # Timestamp
        raw_ts = record.get("TimeGenerated") or record.get("timestamp") or record.get("timeGenerated")
        if not raw_ts:
            timestamp = datetime.now(timezone.utc).isoformat()
        elif hasattr(raw_ts, "isoformat"):
            timestamp = raw_ts.isoformat()
        else:
            timestamp = str(raw_ts)

        # Workload / Resource ID
        resource_id = str(
            record.get("resource_id")
            or record.get("VM_s")
            or record.get("_ResourceId")
            or record.get("ResourceId")
            or ""
        ).strip()

        # If only a VM name was provided (e.g., 'vm-worker-01') and not a full ARM ID,
        # preserve it or format canonical ID if subscription / RG are available
        subscription_id = record.get("SubscriptionId") or record.get("Subscription_g") or record.get("subscription_id")
        resource_group = record.get("ResourceGroup") or record.get("resource_group")

        if resource_id and not resource_id.startswith("/subscriptions/"):
            if subscription_id and resource_group:
                resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{resource_id}"
            else:
                # Default canonical pattern for standard CloudPulse workload
                resource_id = f"/subscriptions/unknown/resourceGroups/unknown/providers/Microsoft.Compute/virtualMachines/{resource_id}"

        # Source IP and Subnet
        source_ip = record.get("SourceIP_s") or record.get("source_ip") or record.get("SrcIP_s")
        subnet_id = record.get("SrcSubnet_s") or record.get("subnet_id") or record.get("Subnet_s")

        # Destination Port
        raw_port = record.get("DestPort_d") or record.get("DestPort") or record.get("destination_port") or 0
        try:
            destination_port = int(float(raw_port))
        except (ValueError, TypeError):
            destination_port = 0

        # Protocol
        raw_proto = str(record.get("L4Protocol_s") or record.get("protocol") or "TCP").strip().upper()
        if raw_proto in ("T", "TCP"):
            protocol = "TCP"
        elif raw_proto in ("U", "UDP"):
            protocol = "UDP"
        else:
            protocol = raw_proto

        # Quantitative Metrics
        bytes_sent = int(float(record.get("TotalBytesSent") or record.get("BytesSent_d") or record.get("bytes_sent") or 0))
        bytes_received = int(float(record.get("TotalBytesReceived") or record.get("BytesReceived_d") or record.get("bytes_received") or 0))
        packets_sent = int(float(record.get("TotalPacketsSent") or record.get("PacketsSent_d") or record.get("packets_sent") or 0))
        packets_received = int(float(record.get("TotalPacketsReceived") or record.get("PacketsReceived_d") or record.get("packets_received") or 0))
        flow_count = int(float(record.get("FlowCount") or record.get("flow_count") or 1))

        # Flow Direction & Status
        raw_direction = str(record.get("FlowDirection_s") or record.get("flow_direction") or "O").strip().upper()
        flow_direction = "O" if raw_direction.startswith("O") else "I"

        raw_status = str(record.get("FlowStatus_s") or record.get("flow_status") or "A").strip().upper()
        flow_status = "A" if raw_status.startswith("A") else "D"

        # Destination IP (Traffic Analytics DestPublicIPs_s may contain pipe or comma-separated lists)
        raw_dest = str(record.get("DestIP_s") or record.get("DestPublicIPs_s") or record.get("destination_ip") or "").strip()
        dest_ips: List[str] = []
        if "|" in raw_dest:
            dest_ips = [ip.strip() for ip in raw_dest.split("|") if ip.strip() and ip.strip() != "-"]
        elif "," in raw_dest:
            dest_ips = [ip.strip() for ip in raw_dest.split(",") if ip.strip() and ip.strip() != "-"]
        elif raw_dest and raw_dest != "-":
            dest_ips = [raw_dest]

        if not dest_ips:
            return []

        # If single destination IP, return single event
        if len(dest_ips) == 1:
            return [
                NetworkFlowEvent(
                    timestamp=timestamp,
                    resource_id=resource_id,
                    source_ip=str(source_ip) if source_ip else None,
                    destination_ip=dest_ips[0],
                    destination_port=destination_port,
                    protocol=protocol,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    packets_sent=packets_sent,
                    packets_received=packets_received,
                    flow_direction=flow_direction,
                    flow_status=flow_status,
                    flow_count=flow_count,
                    subnet_id=str(subnet_id) if subnet_id else None,
                    resource_group=str(resource_group) if resource_group else None,
                    subscription_id=str(subscription_id) if subscription_id else None,
                )
            ]

        # If multiple destination IPs were concatenated, partition across events
        split_bytes_sent = bytes_sent // len(dest_ips)
        split_bytes_received = bytes_received // len(dest_ips)
        split_packets_sent = packets_sent // len(dest_ips)
        split_packets_received = packets_received // len(dest_ips)
        split_flow_count = max(1, flow_count // len(dest_ips))

        events = []
        for dst in dest_ips:
            events.append(
                NetworkFlowEvent(
                    timestamp=timestamp,
                    resource_id=resource_id,
                    source_ip=str(source_ip) if source_ip else None,
                    destination_ip=dst,
                    destination_port=destination_port,
                    protocol=protocol,
                    bytes_sent=split_bytes_sent,
                    bytes_received=split_bytes_received,
                    packets_sent=split_packets_sent,
                    packets_received=split_packets_received,
                    flow_direction=flow_direction,
                    flow_status=flow_status,
                    flow_count=split_flow_count,
                    subnet_id=str(subnet_id) if subnet_id else None,
                    resource_group=str(resource_group) if resource_group else None,
                    subscription_id=str(subscription_id) if subscription_id else None,
                )
            )
        return events
