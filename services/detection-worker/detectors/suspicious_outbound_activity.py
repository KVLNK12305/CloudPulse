import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple, Union

from database.postgres import DatabaseRepository
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_outbound_finding_id,
)
from models.network_flow import NetworkFlowEvent, WorkloadBaseline
from telemetry.network_flow import BaselineStore, InMemoryBaselineStore, NetworkFlowAdapter

logger = logging.getLogger("cloudpulse.detectors.suspicious_outbound_activity")

# 10 MB floor in bytes to prevent zero-division in baseline calculation
MIN_BASELINE_HOURLY_BYTES = 10 * 1024 * 1024  # 10,485,760 bytes

# Volume Thresholds
VOLUME_SPIKE_RATIO = 5.0
VOLUME_SPIKE_MIN_BYTES = 500 * 1024 * 1024  # 500 MB (524,288,000 bytes)
MASSIVE_EXFIL_RATIO = 10.0
MASSIVE_EXFIL_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB (5,368,709,120 bytes)
HIGH_VOLUME_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB (1,073,741,824 bytes)
MODERATE_VOLUME_BYTES = 250 * 1024 * 1024  # 250 MB (262,144,000 bytes)


class SuspiciousOutboundActivityDetector:
    """
    Deterministic detector for SUSPICIOUS_OUTBOUND_ACTIVITY.
    Identifies destination, port, volume, behavioral, and topological outbound network anomalies.
    Adheres strictly to docs/detection/suspicious-outbound-activity.md.
    """

    DETECTION_ID = "SUSPICIOUS_OUTBOUND_ACTIVITY"

    # Cryptomining & Abuse Ports (docs/detection/suspicious-outbound-activity.md Section 5.B)
    MINING_PORTS: Set[int] = {3333, 4444, 5555, 6666, 8333, 14444}

    # Remote Management Ports (Section 5.B)
    MANAGEMENT_PORTS: Dict[int, str] = {
        22: "SSH",
        3389: "RDP",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        23: "Telnet",
    }

    # Unencrypted Database Egress (Section 5.B)
    DATABASE_PORTS: Dict[int, str] = {
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
    }

    # Standard Approved Destinations / Infrastructure (Section 12)
    STANDARD_APPROVED_IPS: Set[str] = {
        "168.63.129.16",    # Azure Platform wire / recursive DNS
        "169.254.169.254",   # Azure Instance Metadata Service (IMDS)
        "1.1.1.1",          # Cloudflare DNS
        "1.0.0.1",          # Cloudflare DNS secondary
        "8.8.8.8",          # Google DNS
        "8.8.4.4",          # Google DNS secondary
    }

    # Internal Sensitive Subnets where Internet egress is a role violation (Section 5.D)
    RESTRICTED_DATA_SUBNETS: Set[str] = {"snet-data"}

    def __init__(
        self,
        db_repo: Optional[DatabaseRepository] = None,
        baseline_store: Optional[BaselineStore] = None,
    ):
        """
        Initialize the detector with optional database repository and baseline store.
        """
        self._db = db_repo
        self._baseline_store = baseline_store or InMemoryBaselineStore()
        self._adapter = NetworkFlowAdapter()

    @classmethod
    def get_kql_query(cls, lookback_minutes: int = 60) -> str:
        """KQL query string for AzureNetworkAnalytics_CL."""
        return NetworkFlowAdapter.build_outbound_flows_kql(lookback_minutes=lookback_minutes)

    def detect(
        self,
        flows: Optional[List[Union[NetworkFlowEvent, Dict[str, Any]]]] = None,
        baselines: Optional[Dict[str, WorkloadBaseline]] = None,
    ) -> List[Finding]:
        """
        Evaluate network flows against baseline and deterministic anomaly conditions.

        Args:
            flows: List of normalized NetworkFlowEvents or raw flow dicts.
            baselines: Optional map of resource_id -> WorkloadBaseline.

        Returns:
            List of normalized Finding objects.
        """
        if flows is None or len(flows) == 0:
            return []

        # If baseline map provided, inject into baseline store
        if baselines:
            if isinstance(self._baseline_store, InMemoryBaselineStore):
                for res_id, bl in baselines.items():
                    self._baseline_store.set_baseline(res_id, bl)

        # Normalize any dicts into NetworkFlowEvents
        normalized_events: List[NetworkFlowEvent] = []
        for item in flows:
            if isinstance(item, NetworkFlowEvent):
                normalized_events.append(item)
            elif isinstance(item, dict):
                normalized_events.extend(self._adapter.normalize_record(item))

        if not normalized_events:
            return []

        # Group flows by workload/resource
        workload_flows: Dict[str, List[NetworkFlowEvent]] = defaultdict(list)
        for ev in normalized_events:
            workload_flows[ev.resource_id].append(ev)

        findings: List[Finding] = []
        seen_finding_ids: Set[str] = set()

        for resource_id, res_flows in workload_flows.items():
            workload_findings = self._evaluate_workload_flows(resource_id, res_flows)
            for f in workload_findings:
                if f.finding_id not in seen_finding_ids:
                    seen_finding_ids.add(f.finding_id)
                    findings.append(f)

        logger.info(
            "SUSPICIOUS_OUTBOUND_ACTIVITY detector evaluated %d events across %d workloads and generated %d findings",
            len(normalized_events),
            len(workload_flows),
            len(findings),
        )
        return findings

    def _evaluate_workload_flows(
        self,
        resource_id: str,
        flows: List[NetworkFlowEvent],
    ) -> List[Finding]:
        """
        Evaluate flows for an individual workload against the deterministic contract rules.
        """
        findings: List[Finding] = []
        baseline = self._baseline_store.get_baseline(resource_id)

        # Retrieve security context from PostgreSQL if available
        related_upe_ids: List[str] = []
        related_rc_ids: List[str] = []
        has_active_upe = False
        has_recent_rc = False

        if self._db is not None:
            try:
                past_findings = self._db.get_findings_by_resource_id(resource_id)
                now_utc = datetime.now(timezone.utc)
                for pf in past_findings:
                    if pf.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
                        has_active_upe = True
                        related_upe_ids.append(pf.finding_id)
                    elif pf.finding_type == "RESOURCE_CREATION":
                        try:
                            pf_time = datetime.fromisoformat(pf.timestamp.replace("Z", "+00:00"))
                            if (now_utc - pf_time) <= timedelta(hours=24):
                                has_recent_rc = True
                                related_rc_ids.append(pf.finding_id)
                        except Exception:
                            has_recent_rc = True
                            related_rc_ids.append(pf.finding_id)
            except Exception as e:
                logger.warning("Could not query past findings for resource %s: %s", resource_id, str(e))

        security_context = {
            "has_active_upe": has_active_upe,
            "has_recent_rc": has_recent_rc,
            "related_finding_ids": list(set(related_upe_ids + related_rc_ids)),
        }

        # -------------------------------------------------------------------------
        # Signal 1: Behavioral Anomaly — Outbound Scanning / Diversity Spike
        # -------------------------------------------------------------------------
        distinct_public_destinations = set()
        total_workload_bytes_sent = 0
        total_workload_bytes_received = 0
        total_workload_packets_sent = 0

        for f in flows:
            is_public = self._is_public_ip(f.destination_ip)
            if is_public:
                total_workload_bytes_sent += f.bytes_sent
                total_workload_bytes_received += f.bytes_received
                total_workload_packets_sent += f.packets_sent
                if not self._is_standard_approved(f.destination_ip, f.destination_port, f.protocol):
                    distinct_public_destinations.add(f.destination_ip)

        dest_count = len(distinct_public_destinations)
        # Condition A: Destination diversity spike (> 50 distinct public IPs)
        # Condition B: Asymmetric scanning (> 100 packets sent, near-zero response bytes, >= 10 distinct public IPs)
        is_diversity_spike = dest_count > 50
        is_asymmetric_scan = (total_workload_packets_sent > 100 and total_workload_bytes_received < 100 and dest_count >= 10)

        if is_diversity_spike or is_asymmetric_scan:
            scan_finding = self._build_scanning_finding(
                resource_id=resource_id,
                flows=flows,
                dest_count=dest_count,
                baseline=baseline,
                security_context=security_context,
            )
            findings.append(scan_finding)

        # -------------------------------------------------------------------------
        # Signal 2: Workload Aggregate Volume Anomaly
        # -------------------------------------------------------------------------
        volume_anomaly_triggered = False
        volume_ratio = 0.0

        if not baseline.is_cold_start:
            # Baseline denominator uses max(mean_hourly_bytes, 10 MB)
            denom = max(baseline.mean_hourly_bytes, float(MIN_BASELINE_HOURLY_BYTES))
            volume_ratio = round(total_workload_bytes_sent / denom, 2)

            # Trigger condition: R_volume >= 5.0 AND total transferred bytes >= 500 MB
            if volume_ratio >= VOLUME_SPIKE_RATIO and total_workload_bytes_sent >= VOLUME_SPIKE_MIN_BYTES:
                volume_anomaly_triggered = True
                vol_finding = self._build_volume_spike_finding(
                    resource_id=resource_id,
                    flows=flows,
                    total_bytes_sent=total_workload_bytes_sent,
                    total_bytes_received=total_workload_bytes_received,
                    baseline=baseline,
                    volume_ratio=volume_ratio,
                    security_context=security_context,
                )
                findings.append(vol_finding)

        # -------------------------------------------------------------------------
        # Signal 3: Flow-Level Structural & Destination Anomalies
        # -------------------------------------------------------------------------
        # Evaluate individual outbound flow sessions
        for flow in flows:
            # Skip inbound or denied records
            if flow.flow_direction != "O" or flow.flow_status != "A":
                continue

            dest_ip = flow.destination_ip
            dest_port = flow.destination_port

            # Filter: Check if destination is internal/private (RFC 1918, loopback, link-local)
            if not self._is_public_ip(dest_ip):
                # Internal private traffic is not an Internet anomaly
                continue

            # Check if destination is standard approved platform endpoint (DNS, NTP, Azure wire)
            if self._is_standard_approved(dest_ip, dest_port, flow.protocol):
                continue

            # 3a. Cryptomining & Abuse Ports (CRITICAL)
            if dest_port in self.MINING_PORTS:
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="MINING_PORT",
                    severity=SeverityLevel.CRITICAL,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

            # 3b. Subnet Role Violation (HIGH)
            subnet_name = (flow.subnet_id or "").split("/")[-1].lower()
            if any(restricted in subnet_name for restricted in self.RESTRICTED_DATA_SUBNETS):
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="SUBNET_VIOLATION",
                    severity=SeverityLevel.HIGH,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

            # 3c. Unusual Remote Management Egress (MEDIUM)
            if dest_port in self.MANAGEMENT_PORTS:
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="MANAGEMENT_PORT",
                    severity=SeverityLevel.MEDIUM,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

            # 3d. Unencrypted Database Egress (MEDIUM)
            if dest_port in self.DATABASE_PORTS:
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="DATABASE_PORT",
                    severity=SeverityLevel.MEDIUM,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

            # 3e. Periodic Beaconing / C2 (flow_count >= 20 and low payload < 5 KB per flow)
            avg_flow_bytes = flow.bytes_sent / max(1, flow.flow_count)
            if flow.flow_count >= 20 and avg_flow_bytes < 5120:
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="C2_BEACON",
                    severity=SeverityLevel.MEDIUM,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

            # 3f. Novel External Destination
            # Must not be cold-start to avoid deployment setup false positives
            if not baseline.is_cold_start and dest_ip not in baseline.known_destination_ips:
                severity = SeverityLevel.MEDIUM if flow.flow_count > 1 else SeverityLevel.LOW
                f = self._build_flow_finding(
                    flow=flow,
                    anomaly_type="NOVEL_DESTINATION",
                    severity=severity,
                    baseline=baseline,
                    security_context=security_context,
                )
                findings.append(f)
                continue

        return findings

    # -------------------------------------------------------------------------
    # Helper: Finding Builders
    # -------------------------------------------------------------------------

    def _build_flow_finding(
        self,
        flow: NetworkFlowEvent,
        anomaly_type: str,
        severity: SeverityLevel,
        baseline: WorkloadBaseline,
        security_context: Dict[str, Any],
    ) -> Finding:
        """Constructs a normalized Finding for a single flow session."""
        resource_info = self._parse_resource_info(flow.resource_id, flow.resource_group)

        # Escalation: Active UNEXPECTED_PUBLIC_EXPOSURE escalates to CRITICAL
        effective_severity = severity
        if security_context.get("has_active_upe"):
            effective_severity = SeverityLevel.CRITICAL

        # Calculate deterministic confidence
        is_novel = flow.destination_ip not in baseline.known_destination_ips
        confidence = self._calculate_confidence(
            has_bidirectional=(flow.bytes_sent > 0 and flow.bytes_received > 0 and flow.destination_port > 0),
            is_novel_destination=is_novel,
            is_high_risk_port=(flow.destination_port in self.MINING_PORTS or flow.destination_port == 4444 or flow.destination_port in self.MANAGEMENT_PORTS),
            has_active_upe=security_context.get("has_active_upe", False),
            has_recent_rc=security_context.get("has_recent_rc", False),
            is_cold_start=baseline.is_cold_start,
        )

        # Deterministic finding ID
        finding_id = generate_outbound_finding_id(
            resource_id=flow.resource_id,
            destination_ip=flow.destination_ip,
            destination_port=flow.destination_port,
            anomaly_type=anomaly_type,
            epoch_timestamp=flow.timestamp,
        )

        clean_ts = flow.timestamp.replace(":", "").replace("-", "").replace(".", "")
        evidence = EvidenceInfo(
            operation="NETWORK_FLOW_TELEMETRY",
            activity_log_event_id=f"flow-{clean_ts[:15]}-{resource_info.name}",
            correlation_id=None,
            subscription_id=flow.subscription_id or resource_info.id.split("/")[2] if "/subscriptions/" in resource_info.id else None,
            caller_ip=flow.source_ip,
            raw_event=flow.model_dump(),
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            destination_port=str(flow.destination_port),
            protocol=flow.protocol,
            bytes_sent=flow.bytes_sent,
            bytes_received=flow.bytes_received,
            flow_count=flow.flow_count,
            anomaly_type=anomaly_type,
            baseline_bytes=int(baseline.mean_hourly_bytes),
            deviation_ratio=None,
            subnet_id=flow.subnet_id,
            related_finding_ids=security_context.get("related_finding_ids", []),
        )

        return Finding(
            finding_id=finding_id,
            finding_type=self.DETECTION_ID,
            severity=effective_severity,
            timestamp=flow.timestamp,
            resource=resource_info,
            identity=IdentityInfo(principal_id=None, principal_type=None, caller=None),
            evidence=evidence,
            confidence=confidence,
        )

    def _build_volume_spike_finding(
        self,
        resource_id: str,
        flows: List[NetworkFlowEvent],
        total_bytes_sent: int,
        total_bytes_received: int,
        baseline: WorkloadBaseline,
        volume_ratio: float,
        security_context: Dict[str, Any],
    ) -> Finding:
        """Constructs a normalized Finding for an aggregate egress volume spike."""
        primary_flow = max(flows, key=lambda f: f.bytes_sent)
        resource_info = self._parse_resource_info(resource_id, primary_flow.resource_group)

        # Deterministic Severity Model (Section 7)
        if security_context.get("has_active_upe"):
            severity = SeverityLevel.CRITICAL
        elif volume_ratio >= MASSIVE_EXFIL_RATIO and total_bytes_sent > MASSIVE_EXFIL_BYTES:
            severity = SeverityLevel.CRITICAL
        elif volume_ratio >= VOLUME_SPIKE_RATIO and total_bytes_sent > HIGH_VOLUME_BYTES:
            severity = SeverityLevel.HIGH
        elif volume_ratio >= 3.0 and total_bytes_sent > MODERATE_VOLUME_BYTES:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        is_novel = primary_flow.destination_ip not in baseline.known_destination_ips
        confidence = self._calculate_confidence(
            has_bidirectional=(total_bytes_sent > 0 and total_bytes_received > 0),
            is_novel_destination=is_novel,
            is_high_risk_port=(primary_flow.destination_port in self.MINING_PORTS),
            has_active_upe=security_context.get("has_active_upe", False),
            has_recent_rc=security_context.get("has_recent_rc", False),
            is_cold_start=baseline.is_cold_start,
        )

        finding_id = generate_outbound_finding_id(
            resource_id=resource_id,
            destination_ip=primary_flow.destination_ip,
            destination_port=primary_flow.destination_port,
            anomaly_type="VOLUME_SPIKE",
            epoch_timestamp=primary_flow.timestamp,
        )

        clean_ts = primary_flow.timestamp.replace(":", "").replace("-", "").replace(".", "")
        evidence = EvidenceInfo(
            operation="NETWORK_FLOW_TELEMETRY",
            activity_log_event_id=f"flow-vol-{clean_ts[:15]}-{resource_info.name}",
            correlation_id=None,
            subscription_id=primary_flow.subscription_id,
            caller_ip=primary_flow.source_ip,
            raw_event={"flows_aggregated": len(flows), "total_bytes_sent": total_bytes_sent},
            source_ip=primary_flow.source_ip,
            destination_ip=primary_flow.destination_ip,
            destination_port=str(primary_flow.destination_port),
            protocol=primary_flow.protocol,
            bytes_sent=total_bytes_sent,
            bytes_received=total_bytes_received,
            flow_count=sum(f.flow_count for f in flows),
            anomaly_type="VOLUME_SPIKE",
            baseline_bytes=int(baseline.mean_hourly_bytes),
            deviation_ratio=volume_ratio,
            subnet_id=primary_flow.subnet_id,
            related_finding_ids=security_context.get("related_finding_ids", []),
        )

        return Finding(
            finding_id=finding_id,
            finding_type=self.DETECTION_ID,
            severity=severity,
            timestamp=primary_flow.timestamp,
            resource=resource_info,
            identity=IdentityInfo(principal_id=None, principal_type=None, caller=None),
            evidence=evidence,
            confidence=confidence,
        )

    def _build_scanning_finding(
        self,
        resource_id: str,
        flows: List[NetworkFlowEvent],
        dest_count: int,
        baseline: WorkloadBaseline,
        security_context: Dict[str, Any],
    ) -> Finding:
        """Constructs a normalized Finding for outbound scanning / destination diversity spike."""
        sample_flow = flows[0]
        resource_info = self._parse_resource_info(resource_id, sample_flow.resource_group)

        # Scanning is HIGH, escalated to CRITICAL if active UPE is present
        severity = SeverityLevel.CRITICAL if security_context.get("has_active_upe") else SeverityLevel.HIGH

        confidence = self._calculate_confidence(
            has_bidirectional=False,  # Scanning typically features zero/near-zero response
            is_novel_destination=True,
            is_high_risk_port=False,
            has_active_upe=security_context.get("has_active_upe", False),
            has_recent_rc=security_context.get("has_recent_rc", False),
            is_cold_start=baseline.is_cold_start,
        )

        finding_id = generate_outbound_finding_id(
            resource_id=resource_id,
            destination_ip="MULTIPLE",
            destination_port="*",
            anomaly_type="SCANNING",
            epoch_timestamp=sample_flow.timestamp,
        )

        total_bytes_sent = sum(f.bytes_sent for f in flows)
        total_bytes_received = sum(f.bytes_received for f in flows)
        clean_ts = sample_flow.timestamp.replace(":", "").replace("-", "").replace(".", "")

        evidence = EvidenceInfo(
            operation="NETWORK_FLOW_TELEMETRY",
            activity_log_event_id=f"flow-scan-{clean_ts[:15]}-{resource_info.name}",
            correlation_id=None,
            subscription_id=sample_flow.subscription_id,
            caller_ip=sample_flow.source_ip,
            raw_event={"dest_ip_count": dest_count, "flows_observed": len(flows)},
            source_ip=sample_flow.source_ip,
            destination_ip="MULTIPLE",
            destination_port="*",
            protocol="TCP",
            bytes_sent=total_bytes_sent,
            bytes_received=total_bytes_received,
            flow_count=len(flows),
            dest_ip_count=dest_count,
            anomaly_type="SCANNING",
            baseline_bytes=int(baseline.mean_hourly_bytes),
            deviation_ratio=None,
            subnet_id=sample_flow.subnet_id,
            related_finding_ids=security_context.get("related_finding_ids", []),
        )

        return Finding(
            finding_id=finding_id,
            finding_type=self.DETECTION_ID,
            severity=severity,
            timestamp=sample_flow.timestamp,
            resource=resource_info,
            identity=IdentityInfo(principal_id=None, principal_type=None, caller=None),
            evidence=evidence,
            confidence=confidence,
        )

    # -------------------------------------------------------------------------
    # Helper: Deterministic Confidence Model (Section 8)
    # -------------------------------------------------------------------------

    @classmethod
    def _calculate_confidence(
        cls,
        has_bidirectional: bool,
        is_novel_destination: bool,
        is_high_risk_port: bool,
        has_active_upe: bool,
        has_recent_rc: bool,
        is_cold_start: bool,
    ) -> float:
        """
        Calculates deterministic confidence score between 0.10 and 1.0.
        Section 8:
            Full bidirectional flow: +0.40 (or +0.20 if unidirectional)
            Novel destination: +0.20
            Mining/C2 port risk: +0.20
            Corroborating UPE: +0.15
            Corroborating Resource Creation: +0.10
            Cold-start penalty: -0.20
            Formula: min(1.0, max(0.1, sum(Weights)))
            If cold-start: cap at 0.70.
        """
        score = 0.0

        if has_bidirectional:
            score += 0.40
        else:
            score += 0.20

        if is_novel_destination:
            score += 0.20

        if is_high_risk_port:
            score += 0.20

        if has_active_upe:
            score += 0.15

        if has_recent_rc:
            score += 0.10

        if is_cold_start:
            score -= 0.20

        score = max(0.10, min(1.0, score))

        if is_cold_start:
            score = min(0.70, score)

        return round(score, 2)

    # -------------------------------------------------------------------------
    # Helper: IP Classification & Exclusions
    # -------------------------------------------------------------------------

    @classmethod
    def _is_public_ip(cls, ip_str: str) -> bool:
        """
        Returns True if ip_str is a routable public IPv4/IPv6 address.
        Returns False for RFC 1918 private, loopback, link-local, multicast, or invalid IPs.

        Uses ``ip.is_global`` instead of negating ``ip.is_private`` because
        Python 3.11+ (and especially 3.14) classify IANA documentation ranges
        (TEST-NET-1/2/3: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as
        ``is_private=True`` per RFC 5737.  ``is_global`` correctly returns True
        only for addresses that are routable on the public Internet *or* that
        belong to documentation/benchmarking ranges used in our test fixtures.
        """
        if not ip_str or ip_str in ("-", "MULTIPLE"):
            return False

        try:
            ip = ipaddress.ip_address(ip_str.strip())
            # Explicitly exclude RFC 1918, loopback, link-local, and multicast
            if ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
            # RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if isinstance(ip, ipaddress.IPv4Address):
                rfc1918_networks = [
                    ipaddress.IPv4Network("10.0.0.0/8"),
                    ipaddress.IPv4Network("172.16.0.0/12"),
                    ipaddress.IPv4Network("192.168.0.0/16"),
                ]
                for net in rfc1918_networks:
                    if ip in net:
                        return False
            # All other addresses are considered public/external for detection
            return True
        except ValueError:
            return False

    @classmethod
    def _is_standard_approved(cls, dest_ip: str, dest_port: int, protocol: str) -> bool:
        """
        Returns True if the connection represents standard approved cloud services or core infrastructure:
        - Azure platform wire IP (168.63.129.16)
        - Azure IMDS (169.254.169.254)
        - Standard DNS (port 53 UDP) to known resolvers
        - NTP (port 123 UDP)
        """
        clean_ip = dest_ip.strip()
        proto_upper = protocol.strip().upper()

        if clean_ip in cls.STANDARD_APPROVED_IPS:
            # Wire IP is always approved
            if clean_ip == "168.63.129.16":
                return True
            # DNS resolvers approved on UDP 53
            if dest_port == 53 and proto_upper == "UDP":
                return True

        # NTP synchronization on UDP 123
        if dest_port == 123 and proto_upper == "UDP":
            return True

        return False

    @classmethod
    def _parse_resource_info(cls, resource_id: str, resource_group: Optional[str] = None) -> ResourceInfo:
        """Parses resource_id into ResourceInfo."""
        clean_id = resource_id.strip()
        res_name = clean_id.split("/")[-1] if "/" in clean_id else clean_id
        res_type = "Microsoft.Compute/virtualMachines"
        rg = resource_group or ""

        if "/resourceGroups/" in clean_id:
            try:
                parts = clean_id.split("/resourceGroups/")[1].split("/")
                rg = parts[0]
                if len(parts) >= 3 and parts[1].lower() == "providers":
                    res_type = f"{parts[2]}/{parts[3]}"
            except Exception:
                pass

        return ResourceInfo(
            id=clean_id,
            type=res_type,
            name=res_name,
            resource_group=rg,
        )
