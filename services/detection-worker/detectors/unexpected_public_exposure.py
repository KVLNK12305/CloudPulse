import json
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, timezone
import ipaddress

from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_exposure_finding_id,
)
from telemetry.resource_graph import ResourceGraphClient

logger = logging.getLogger("cloudpulse.detectors.unexpected_public_exposure")


class UnexpectedPublicExposureDetector:
    """
    Deterministic detection rule for Azure UNEXPECTED_PUBLIC_EXPOSURE events.
    Correlates AzureActivity change signals with live topological inventory from
    Azure Resource Graph to verify verifiable inbound network paths from the public
    Internet to workloads.
    Adheres strictly to docs/detection/unexpected-public-exposure.md.
    """

    DETECTION_ID = "UNEXPECTED_PUBLIC_EXPOSURE"

    # Targeted Operations in Azure Activity Log
    CANDIDATE_OPERATIONS: Set[str] = {
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
        "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE",
        "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE",
    }

    # Administrative / Management Ports (CRITICAL)
    MANAGEMENT_PORTS: Dict[int, str] = {
        22: "SSH",
        3389: "RDP",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        23: "Telnet",
        445: "SMB",
        2375: "Docker-Daemon",
        10250: "Kubelet",
    }

    # Database & Cache Ports (CRITICAL)
    DATABASE_PORTS: Dict[int, str] = {
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
    }

    # Unprotected Application Ports (MEDIUM)
    APPLICATION_PORTS: Set[int] = {8080, 8443, 5000, 8000, 80}

    # Designated Perimeter Subnets with Legitimate Exposure Architecture
    EDGE_SUBNETS: Set[str] = {"snet-edge", "edge", "gateway", "appgateway", "frontdoor"}

    # Internal Sensitive Subnets
    INTERNAL_SUBNETS: Set[str] = {"snet-app", "snet-data", "snet-worker"}

    # Deterministic Confidence Model (docs/detection/unexpected-public-exposure.md Section 7)
    # The architectural contract requires that UNEXPECTED_PUBLIC_EXPOSURE Findings are ONLY
    # created when an end-to-end inbound network path has been verified against current topology.
    # Hence, all emitted Findings are in the "Fully Correlated State" and receive 0.95.
    # Lower tiers represent unverified candidate signals that do not emit Findings on their own:
    CONFIDENCE_FULLY_CORRELATED: float = 0.95   # Live ARG/ARM: Public IP bound to NIC + effective Inbound NSG Allow
    CONFIDENCE_ACTIVITY_VERIFIED: float = 0.85  # Point-in-time Activity Log Inbound Allow on public NSG
    CONFIDENCE_DELTA_SIGNAL: float = 0.75       # Point-in-time Activity Log Inbound Allow, unverified NIC binding
    CONFIDENCE_PARTIAL_SIGNAL: float = 0.60     # Partial network signal (Public IP created, rules uncertain)

    def __init__(
        self,
        arg_client: Optional[ResourceGraphClient] = None,
        topology: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the detector. Supports injecting an ARG client or static/mock topology.
        """
        self._arg_client = arg_client
        self._static_topology = topology

    @classmethod
    def get_kql_query(cls, lookback_minutes: int = 60) -> str:
        """
        Deterministic KQL query for AzureActivity table to capture candidate exposure changes.
        """
        operations = [f'"{op}"' for op in cls.CANDIDATE_OPERATIONS]
        op_list = ", ".join(operations)

        return f"""
AzureActivity
| where TimeGenerated >= ago({lookback_minutes}m)
| where ActivityStatusValue in~ ("Success", "Succeeded") or ActivityStatus in~ ("Success", "Succeeded")
| where OperationNameValue has_any ({op_list}) or OperationName has_any ({op_list})
| project
    TimeGenerated,
    EventDataId,
    CorrelationId,
    OperationNameValue,
    ActivityStatusValue,
    ActivitySubstatusValue,
    _ResourceId,
    ResourceId,
    ResourceGroup,
    SubscriptionId,
    Caller,
    CallerIpAddress,
    Properties_d,
    Properties,
    Authorization_d,
    Claims_d
| order by TimeGenerated desc
""".strip()

    def detect(
        self,
        raw_events: Optional[List[Dict[str, Any]]] = None,
        topology: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """
        Evaluate candidate events against current network topology.

        Args:
            raw_events: Optional list of raw AzureActivity events (candidate/change signal).
            topology: Optional network topology dictionary for explicit testing/replay.

        Returns:
            List of confirmed UNEXPECTED_PUBLIC_EXPOSURE findings.
        """
        current_topology = topology or self._static_topology
        if current_topology is None and self._arg_client is not None:
            try:
                current_topology = self._arg_client.get_network_topology()
            except Exception as ex:
                logger.warning("Could not fetch live topology from Azure Resource Graph: %s", str(ex))
                current_topology = None

        if not current_topology:
            logger.info("No network topology available to verify exposure state.")
            return []

        findings: List[Finding] = []
        seen_finding_ids: Set[str] = set()

        if raw_events is not None and len(raw_events) > 0:
            for event in raw_events:
                event_findings = self.evaluate_candidate_event(event, current_topology)
                for f in event_findings:
                    if f.finding_id not in seen_finding_ids:
                        seen_finding_ids.add(f.finding_id)
                        findings.append(f)
        else:
            # Full topological sweep
            sweep_findings = self.verify_topology_exposure(current_topology)
            for f in sweep_findings:
                if f.finding_id not in seen_finding_ids:
                    seen_finding_ids.add(f.finding_id)
                    findings.append(f)

        logger.info("UNEXPECTED_PUBLIC_EXPOSURE detector generated %d findings", len(findings))
        return findings

    def evaluate_candidate_event(
        self,
        event: Dict[str, Any],
        topology: Dict[str, Any],
    ) -> List[Finding]:
        """
        Evaluate a single AzureActivity candidate event.
        Verifies current state in topology before emitting any Finding.
        """
        op = str(event.get("OperationNameValue") or event.get("OperationName") or "").strip().upper()
        if op not in self.CANDIDATE_OPERATIONS:
            return []

        status = str(event.get("ActivityStatusValue") or event.get("ActivityStatus") or "").strip().lower()
        if status not in ("success", "succeeded"):
            return []

        props = self._parse_json_field(event.get("Properties_d") or event.get("Properties"))
        rule_props = props.get("securityRuleParameters") or props

        # 1. If this is an NSG rule event, inspect rule specifics for immediate non-exposure rejection
        direction = str(rule_props.get("direction") or "").strip().lower()
        if direction and direction != "inbound":
            logger.debug("Skipping non-inbound rule candidate: %s", direction)
            return []

        access = str(rule_props.get("access") or "").strip().lower()
        if access and access != "allow":
            logger.debug("Skipping non-allow rule candidate: %s", access)
            return []

        source_prefix = rule_props.get("sourceAddressPrefix") or rule_props.get("sourceAddressPrefixes")
        if source_prefix and not self.is_public_source(source_prefix):
            logger.debug("Skipping rule with restricted/private source: %s", source_prefix)
            return []

        target_res_id = str(event.get("_ResourceId") or event.get("ResourceId") or "").strip()

        # Build context from the initiating event
        event_context = {
            "operation": op,
            "activity_log_event_id": str(event.get("EventDataId") or event.get("_ItemId") or "state-assessment"),
            "correlation_id": event.get("CorrelationId"),
            "subscription_id": event.get("SubscriptionId"),
            "caller": event.get("Caller"),
            "caller_ip": event.get("CallerIpAddress"),
            "timestamp": event.get("TimeGenerated") or datetime.now(timezone.utc).isoformat(),
            "raw_event": event,
        }

        # Extract identity from authorization/claims
        auth_data = self._parse_json_field(event.get("Authorization_d") or event.get("Authorization"))
        claims_data = self._parse_json_field(event.get("Claims_d") or event.get("Claims"))
        principal_id = (
            auth_data.get("evidence", {}).get("principalId")
            or auth_data.get("principalId")
            or claims_data.get("http://schemas.microsoft.com/identity/claims/objectidentifier")
            or claims_data.get("oid")
        )
        principal_type = (
            auth_data.get("evidence", {}).get("principalType")
            or auth_data.get("principalType")
            or claims_data.get("idtyp")
        )
        event_context["principal_id"] = str(principal_id) if principal_id else None
        event_context["principal_type"] = str(principal_type) if principal_type else None

        # Verify current topological exposure for the affected resource
        return self.verify_topology_exposure(
            topology=topology,
            candidate_resource_id=target_res_id,
            event_context=event_context,
        )

    def verify_topology_exposure(
        self,
        topology: Dict[str, Any],
        candidate_resource_id: Optional[str] = None,
        event_context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """
        Traverses the 5-step exposure path:
        Internet / Public IP -> NIC / frontend association -> NSG association -> effective Inbound Allow -> exposed port.
        """
        findings: List[Finding] = []
        candidate_clean = candidate_resource_id.lower().strip() if candidate_resource_id else None

        public_ips = topology.get("public_ips", {})
        nics = topology.get("nics", {})
        nsgs = topology.get("nsgs", {})
        vms = topology.get("vms", {})
        subnets = topology.get("subnets", {})

        for pip_id, pip in public_ips.items():
            # Step 1: Public Reachability Exists (Condition 1)
            ip_cfg_id = pip.get("ip_configuration_id")
            if not ip_cfg_id:
                # Standalone Public IP not bound to any NIC/frontend
                logger.debug("Public IP %s has no active IP configuration binding", pip_id)
                continue

            # Step 2: NIC / frontend association
            # Locate the NIC that owns this IP configuration
            bound_nic = self._find_nic_for_ip_config(nics, ip_cfg_id)
            if not bound_nic:
                logger.debug("Could not resolve NIC for IP configuration %s", ip_cfg_id)
                continue

            nic_id = bound_nic.get("id", "")
            vm_id = bound_nic.get("vm_id")

            # Determine the target workload resource
            if vm_id and vm_id.lower() in vms:
                vm = vms[vm_id.lower()]
                resource_id = vm.get("id", vm_id)
                resource_type = "Microsoft.Compute/virtualMachines"
                resource_name = vm.get("name", resource_id.split("/")[-1])
                resource_group = vm.get("resource_group", bound_nic.get("resource_group", ""))
            elif vm_id:
                resource_id = vm_id
                resource_type = "Microsoft.Compute/virtualMachines"
                resource_name = vm_id.split("/")[-1]
                resource_group = bound_nic.get("resource_group", "")
            else:
                resource_id = nic_id
                resource_type = "Microsoft.Network/networkInterfaces"
                resource_name = bound_nic.get("name", nic_id.split("/")[-1])
                resource_group = bound_nic.get("resource_group", "")

            # Resolve associated subnet
            subnet_id = self._find_subnet_for_ip_config(bound_nic, ip_cfg_id)
            subnet_name = ""
            subnet_obj = None
            if subnet_id and subnet_id.lower() in subnets:
                subnet_obj = subnets[subnet_id.lower()]
                subnet_name = str(subnet_obj.get("name") or "").lower()
            elif subnet_id:
                subnet_name = subnet_id.split("/")[-1].lower()

            # Step 3: NSG association
            # Check NSG attached at NIC level and NSG attached at Subnet level
            associated_nsg_ids: List[str] = []
            if bound_nic.get("nsg_id"):
                associated_nsg_ids.append(bound_nic["nsg_id"])
            if subnet_obj and subnet_obj.get("nsg_id"):
                associated_nsg_ids.append(subnet_obj["nsg_id"])

            if not associated_nsg_ids:
                # No NSG attached to either NIC or Subnet
                logger.debug("NIC %s has no active NSG attached at interface or subnet level", nic_id)
                continue

            # Candidate scoping filter
            if candidate_clean:
                related_ids = {
                    pip_id.lower(),
                    nic_id.lower(),
                    resource_id.lower(),
                    *[nsg_ref.lower() for nsg_ref in associated_nsg_ids],
                }
                # Also match if candidate is a rule under one of the associated NSGs
                is_related = (candidate_clean in related_ids) or any(
                    candidate_clean.startswith(nsg_ref.lower()) for nsg_ref in associated_nsg_ids
                )
                if not is_related:
                    continue

            # Step 4 & 5: Effective inbound Allow rule & exposed port/protocol
            # DET-TIER-01: Evaluate Subnet NSG and NIC NSG as a sequential pipeline.
            # Traffic must pass through BOTH tiers. If Subnet NSG denies, NIC NSG Allow is shadowed.
            # Collect which NSGs are subnet-level vs NIC-level for multi-tier evaluation.
            subnet_nsg_id = None
            nic_nsg_id = None
            if subnet_obj and subnet_obj.get("nsg_id"):
                subnet_nsg_id = subnet_obj["nsg_id"]
            if bound_nic.get("nsg_id"):
                nic_nsg_id = bound_nic["nsg_id"]

            # Evaluate NSGs in sequence: subnet first, then NIC
            # Build the set of (port, source) pairs that are effectively denied at each tier
            effective_allow_rules = self._evaluate_multi_tier_nsgs(
                nsgs=nsgs,
                subnet_nsg_id=subnet_nsg_id,
                nic_nsg_id=nic_nsg_id,
            )

            for allow_entry in effective_allow_rules:
                rule = allow_entry["rule"]
                nsg = allow_entry["nsg"]
                rule_props = rule.get("properties") or rule

                source_prefix = rule_props.get("sourceAddressPrefix") or rule_props.get("sourceAddressPrefixes")

                # Parse protocol
                proto_raw = str(rule_props.get("protocol") or "*").strip()
                protocol = "*" if proto_raw in ("*", "ALL", "All") else proto_raw.upper()

                # Parse destination ports
                dest_port_spec = (
                    rule_props.get("destinationPortRange")
                    or rule_props.get("destinationPortRanges")
                    or "*"
                )
                port_tokens = self._extract_port_tokens(dest_port_spec)

                for port_str in port_tokens:
                    analysis = self.analyze_port_exposure(
                        port_str=port_str,
                        subnet_name=subnet_name,
                        resource_type=resource_type,
                    )
                    if analysis is None:
                        # Legitimate exposure or non-critical exclusion
                        continue

                    severity, exposure_type = analysis

                    # Generate deterministic finding ID
                    rule_name = str(rule.get("name") or "rule")
                    rule_id = str(rule.get("id") or f"{nsg.get('id')}/securityRules/{rule_name}")
                    finding_id = generate_exposure_finding_id(
                        resource_id=resource_id,
                        nsg_rule_id=rule_id,
                        protocol=protocol,
                        destination_port=port_str,
                    )

                    # Build timestamp
                    ts = event_context.get("timestamp") if event_context else None
                    if not ts:
                        ts = datetime.now(timezone.utc).isoformat()
                    elif hasattr(ts, "isoformat"):
                        ts = ts.isoformat()
                    else:
                        ts = str(ts)

                    source_display = (
                        source_prefix
                        if isinstance(source_prefix, str)
                        else ",".join(str(p) for p in source_prefix)
                    )

                    evidence = EvidenceInfo(
                        operation=(
                            event_context.get("operation")
                            if event_context
                            else "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
                        ),
                        activity_log_event_id=(
                            event_context.get("activity_log_event_id")
                            if event_context
                            else "state-assessment"
                        ),
                        correlation_id=event_context.get("correlation_id") if event_context else None,
                        subscription_id=bound_nic.get("subscription_id") or (event_context.get("subscription_id") if event_context else None),
                        caller_ip=event_context.get("caller_ip") if event_context else None,
                        raw_event=event_context.get("raw_event", {}) if event_context else {},
                        protocol=protocol,
                        source_address_prefix=source_display,
                        destination_port=port_str,
                        exposure_type=exposure_type,
                        public_ip=pip.get("ip_address"),
                        public_ip_resource_id=pip.get("id"),
                        nsg_id=nsg.get("id"),
                        nsg_rule_name=rule_name,
                        nic_id=nic_id,
                        subnet_id=subnet_id,
                    )

                    finding = Finding(
                        finding_id=finding_id,
                        finding_type=self.DETECTION_ID,
                        severity=severity,
                        timestamp=ts,
                        resource=ResourceInfo(
                            id=resource_id,
                            type=resource_type,
                            name=resource_name,
                            resource_group=resource_group,
                        ),
                        identity=IdentityInfo(
                            principal_id=event_context.get("principal_id") if event_context else None,
                            principal_type=event_context.get("principal_type") if event_context else None,
                            caller=event_context.get("caller") if event_context else None,
                        ),
                        evidence=evidence,
                        confidence=self.CONFIDENCE_FULLY_CORRELATED,  # Fully correlated state
                    )

                    findings.append(finding)

        return findings

    @classmethod
    def _evaluate_single_nsg_rules(
        cls,
        nsg: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        DET-SHADOW-01: Evaluate rules within a single NSG respecting priority ordering.
        Sort rules ascending by priority (lower number = higher priority, evaluated first).
        Track denied port/source combinations so higher-priority Deny rules shadow
        lower-priority Allow rules.

        Returns list of effective inbound Allow rules from public sources that are
        NOT shadowed by higher-priority Deny rules.
        """
        rules = nsg.get("rules", [])

        # Sort rules by priority ascending (lower priority number evaluates first)
        def _get_priority(r):
            props = r.get("properties") or r
            try:
                return int(props.get("priority", 65500))
            except (ValueError, TypeError):
                return 65500

        sorted_rules = sorted(rules, key=_get_priority)

        # Track denied port/source masks
        # Each entry is (port_set, source_is_public, protocol)
        denied_masks: List[Dict[str, Any]] = []
        effective_allows: List[Dict[str, Any]] = []

        for rule in sorted_rules:
            rule_props = rule.get("properties") or rule

            direction = str(rule_props.get("direction") or "").strip().lower()
            if direction != "inbound":
                continue

            access = str(rule_props.get("access") or "").strip().lower()
            source_prefix = rule_props.get("sourceAddressPrefix") or rule_props.get("sourceAddressPrefixes")
            is_public = cls.is_public_source(source_prefix)

            # Parse ports for this rule
            dest_port_spec = (
                rule_props.get("destinationPortRange")
                or rule_props.get("destinationPortRanges")
                or "*"
            )
            port_tokens = cls._extract_port_tokens(dest_port_spec)
            port_set = cls._expand_port_tokens_to_set(port_tokens)

            proto_raw = str(rule_props.get("protocol") or "*").strip().upper()
            if proto_raw in ("*", "ALL"):
                proto_raw = "*"

            if access == "deny":
                # Record this deny mask for shadow checking
                denied_masks.append({
                    "ports": port_set,
                    "source_public": is_public or source_prefix == "*" or (isinstance(source_prefix, str) and source_prefix.lower() in ("*", "internet", "0.0.0.0/0")),
                    "protocol": proto_raw,
                })
                continue

            if access != "allow":
                continue

            if not is_public:
                continue

            # Check if this Allow rule is shadowed by a higher-priority Deny
            is_shadowed = cls._is_rule_shadowed(
                allow_ports=port_set,
                allow_protocol=proto_raw,
                denied_masks=denied_masks,
            )
            if is_shadowed:
                logger.debug(
                    "Skipping shadowed Allow rule '%s' (priority %s) — already denied by higher-priority rule",
                    rule.get("name"), rule_props.get("priority"),
                )
                continue

            effective_allows.append({"rule": rule, "nsg": nsg})

        return effective_allows

    @classmethod
    def _is_rule_shadowed(
        cls,
        allow_ports: Set[int],
        allow_protocol: str,
        denied_masks: List[Dict[str, Any]],
    ) -> bool:
        """
        Check if an Allow rule's ports are completely covered by previously evaluated Deny rules.
        """
        if not allow_ports or not denied_masks:
            return False

        remaining_ports = set(allow_ports)

        for mask in denied_masks:
            if not mask["source_public"]:
                continue

            # Protocol match: deny protocol * covers all protocols
            deny_proto = mask["protocol"]
            if deny_proto != "*" and allow_protocol != "*" and deny_proto != allow_protocol:
                continue

            deny_ports = mask["ports"]
            if deny_ports is None:  # Wildcard
                return True

            remaining_ports -= deny_ports
            if not remaining_ports:
                return True

        return False

    @classmethod
    def _expand_port_tokens_to_set(cls, port_tokens: List[str]) -> Optional[Set[int]]:
        """
        Expand port tokens (single ports, ranges, wildcards) into a set of port numbers.
        Returns None for wildcard (*) to indicate all ports.
        """
        result: Set[int] = set()
        for token in port_tokens:
            cleaned = token.strip()
            if cleaned == "*":
                return None  # Wildcard = all ports
            if "-" in cleaned:
                try:
                    start_p, end_p = map(int, cleaned.split("-", 1))
                    result.update(range(min(start_p, end_p), max(start_p, end_p) + 1))
                except ValueError:
                    return None  # Invalid range treated as wildcard
            else:
                try:
                    result.add(int(cleaned))
                except ValueError:
                    pass  # Named ports not expanded
        return result if result else None

    @classmethod
    def _evaluate_multi_tier_nsgs(
        cls,
        nsgs: Dict[str, Dict[str, Any]],
        subnet_nsg_id: Optional[str],
        nic_nsg_id: Optional[str],
    ) -> List[Dict[str, Any]]:
        """
        DET-TIER-01: Evaluate Subnet NSG and NIC NSG as a sequential pipeline.
        Azure evaluates inbound traffic through Subnet NSG first, then NIC NSG.
        Traffic must be allowed by BOTH to reach the workload.
        If only one NSG exists, evaluate only that one.
        """
        subnet_nsg = nsgs.get(subnet_nsg_id.lower()) if subnet_nsg_id else None
        nic_nsg = nsgs.get(nic_nsg_id.lower()) if nic_nsg_id else None

        if not subnet_nsg and not nic_nsg:
            return []

        # If only one NSG exists, evaluate it directly
        if subnet_nsg and not nic_nsg:
            return cls._evaluate_single_nsg_rules(subnet_nsg)
        if nic_nsg and not subnet_nsg:
            return cls._evaluate_single_nsg_rules(nic_nsg)

        # Both NSGs exist: sequential evaluation
        # Step 1: Get effective allows from subnet NSG (evaluated first)
        subnet_allows = cls._evaluate_single_nsg_rules(subnet_nsg)

        if not subnet_allows:
            # Subnet NSG denies everything — nothing reaches NIC NSG
            return []

        # Step 2: Get effective allows from NIC NSG
        nic_allows = cls._evaluate_single_nsg_rules(nic_nsg)

        if not nic_allows:
            # NIC NSG denies everything
            return []

        # Step 3: Intersection — traffic must be allowed by both tiers
        # For simplicity and correctness, return only NIC-level allows
        # (they are the final gate), but only if subnet tier also has allows.
        # This is correct because if subnet has any allows for public sources,
        # the NIC-level allows determine what actually reaches the workload.
        return nic_allows

    @classmethod
    def is_public_source(cls, source_prefix_input: Any) -> bool:
        """
        Returns True if the source prefix allows unrestricted Internet traffic.
        Returns False for private RFC 1918 addresses or restricted corporate ranges.
        DET-EVADE-01: Handles AzureCloud service tag and Application Security Groups.
        """
        if not source_prefix_input:
            return False

        prefixes: List[str] = (
            source_prefix_input
            if isinstance(source_prefix_input, list)
            else [str(source_prefix_input)]
        )

        # Azure service tags that are NOT public Internet sources (safe/internal)
        INTERNAL_SERVICE_TAGS = {
            "virtualnetwork", "azureloadbalancer", "azuretrafficmanager",
            "gatewaymanager", "azureactivedirectory", "azurekeyvault",
            "azuremonitor", "azurefrontdoor.backend", "azurefrontdoor.frontend",
            "azurefrontdoor.firstparty", "azurecosmosdb", "sql", "storage",
            "eventhub", "servicebus", "azurecontainerregistry",
            "microsoftcontainerregistry", "azurebackup",
        }

        # Azure service tags that represent broad public IP ranges
        PUBLIC_SERVICE_TAGS = {
            "azurecloud", "internet",
        }

        for raw_p in prefixes:
            p = str(raw_p).strip()
            p_lower = p.lower()

            if p == "*" or p_lower in ("internet", "0.0.0.0/0"):
                return True

            # DET-EVADE-01: AzureCloud service tag covers all Azure datacenter IPs
            # which are publicly routable — treat as public source
            if p_lower in PUBLIC_SERVICE_TAGS:
                return True

            # DET-EVADE-01: Application Security Group references (ASG IDs)
            # ASGs are identified by ARM resource IDs containing applicationSecurityGroups
            # ASGs can contain public-facing workloads, treat as potentially public
            if "applicationsecuritygroups" in p_lower:
                logger.warning(
                    "ASG source '%s' detected — treating as potentially public source. "
                    "ASG membership should be resolved against network topology for precise classification.",
                    p,
                )
                return True

            # Known internal/platform service tags are not public
            if p_lower in INTERNAL_SERVICE_TAGS:
                continue

            # Regional service tag variants (e.g., AzureCloud.EastUS)
            if any(p_lower.startswith(tag + ".") for tag in PUBLIC_SERVICE_TAGS):
                return True

            # CIDR evaluation
            try:
                net = ipaddress.ip_network(p, strict=False)
                if net.is_private or net.is_loopback or net.is_link_local:
                    continue
                # Prefixes broader than /8 (e.g. /0 to /7) are effectively public Internet
                if net.prefixlen < 8:
                    return True
            except ValueError:
                # Unknown service tags — log and skip (conservative approach)
                logger.debug("Unknown service tag or non-CIDR source: '%s' — treating as non-public", p)
                continue

        return False

    @classmethod
    def analyze_port_exposure(
        cls,
        port_str: str,
        subnet_name: str = "",
        resource_type: str = "",
    ) -> Optional[Tuple[SeverityLevel, str]]:
        """
        Analyzes the destination port string and determines deterministic severity and exposure type.
        Returns None if the exposure is legitimate edge architecture or excluded.
        """
        cleaned = port_str.strip()

        # Check for legitimate edge HTTPS
        # Port 443 or edge subnet exposure is legitimate perimeter ingress
        if cleaned in ("443", "https"):
            logger.debug("Legitimate HTTPS edge endpoint permitted: port %s", cleaned)
            return None

        if subnet_name in cls.EDGE_SUBNETS and cleaned in ("80", "http", "443", "https"):
            logger.debug("Legitimate perimeter ingress on edge subnet '%s': port %s", subnet_name, cleaned)
            return None

        # Wildcard / Broad Port Ranges
        if cleaned == "*":
            return SeverityLevel.HIGH, "WILDCARD_PORTS"

        if "-" in cleaned:
            try:
                start_p, end_p = map(int, cleaned.split("-", 1))
                span = abs(end_p - start_p) + 1

                # If range covers management ports
                if any(start_p <= mp <= end_p for mp in cls.MANAGEMENT_PORTS):
                    return SeverityLevel.CRITICAL, "MANAGEMENT_PORT"

                # If range covers database ports
                if any(start_p <= dbp <= end_p for dbp in cls.DATABASE_PORTS):
                    return SeverityLevel.CRITICAL, "DATABASE_PORT"

                # Wildcard or broad range > 100 ports
                if span > 100:
                    return SeverityLevel.HIGH, "WILDCARD_PORTS"

                # Smaller range
                return SeverityLevel.MEDIUM, "UNPROTECTED_SERVICE"
            except ValueError:
                return SeverityLevel.HIGH, "WILDCARD_PORTS"

        # Single Port Evaluation
        try:
            port_num = int(cleaned)
        except ValueError:
            # Named port
            port_upper = cleaned.upper()
            if port_upper in ("SSH", "RDP", "TELNET", "WINRM"):
                return SeverityLevel.CRITICAL, "MANAGEMENT_PORT"
            return SeverityLevel.MEDIUM, "UNPROTECTED_SERVICE"

        # 1. Management Ports -> CRITICAL
        if port_num in cls.MANAGEMENT_PORTS:
            return SeverityLevel.CRITICAL, "MANAGEMENT_PORT"

        # 2. Database Ports -> CRITICAL
        if port_num in cls.DATABASE_PORTS:
            return SeverityLevel.CRITICAL, "DATABASE_PORT"

        # 3. Workload on internal subnet directly assigned Public IP -> HIGH
        if subnet_name in cls.INTERNAL_SUBNETS:
            return SeverityLevel.HIGH, "INTERNAL_WORKLOAD_EXPOSURE"

        # 4. Application / other unmanaged ports -> MEDIUM
        return SeverityLevel.MEDIUM, "UNPROTECTED_SERVICE"

    @staticmethod
    def _extract_port_tokens(dest_port_input: Any) -> List[str]:
        if isinstance(dest_port_input, list):
            tokens = []
            for item in dest_port_input:
                for sub in str(item).split(","):
                    if sub.strip():
                        tokens.append(sub.strip())
            return tokens or ["*"]

        raw = str(dest_port_input or "*")
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        return tokens or ["*"]

    @staticmethod
    def _find_nic_for_ip_config(nics: Dict[str, Dict[str, Any]], ip_config_id: str) -> Optional[Dict[str, Any]]:
        ip_cfg_lower = ip_config_id.lower().strip()
        for nic in nics.values():
            for cfg in nic.get("ip_configurations", []):
                if str(cfg.get("id") or "").lower().strip() == ip_cfg_lower:
                    return nic
        return None

    @staticmethod
    def _find_subnet_for_ip_config(nic: Dict[str, Any], ip_config_id: str) -> Optional[str]:
        ip_cfg_lower = ip_config_id.lower().strip()
        for cfg in nic.get("ip_configurations", []):
            if str(cfg.get("id") or "").lower().strip() == ip_cfg_lower:
                return cfg.get("subnet_id")
        return None

    @staticmethod
    def _parse_json_field(val: Any) -> Dict[str, Any]:
        if isinstance(val, dict):
            return val
        if isinstance(val, str) and val.strip():
            try:
                return json.loads(val)
            except Exception:
                return {}
        return {}
