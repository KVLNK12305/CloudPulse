import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
)

logger = logging.getLogger("cloudpulse.detectors.resource_creation")

# The 6 security-relevant resource types targeted for the CloudPulse MVP
RESOURCE_TYPE_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE": {
        "resource_type": "Microsoft.Compute/virtualMachines",
        "category": "Virtual Machines",
        "default_severity": SeverityLevel.MEDIUM,
        "base_confidence": 0.85,
    },
    "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE": {
        "resource_type": "Microsoft.Network/publicIPAddresses",
        "category": "Public IP addresses",
        "default_severity": SeverityLevel.HIGH,  # High severity due to direct public exposure risk
        "base_confidence": 0.90,
    },
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE": {
        "resource_type": "Microsoft.Storage/storageAccounts",
        "category": "Storage Accounts",
        "default_severity": SeverityLevel.MEDIUM,
        "base_confidence": 0.85,
    },
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE": {
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "category": "Network Security Groups",
        "default_severity": SeverityLevel.MEDIUM,
        "base_confidence": 0.85,
    },
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE": {
        "resource_type": "Microsoft.Authorization/roleAssignments",
        "category": "Role Assignments",
        "default_severity": SeverityLevel.HIGH,  # High severity due to IAM privilege delegation
        "base_confidence": 0.90,
    },
    "MICROSOFT.APP/CONTAINERAPPS/WRITE": {
        "resource_type": "Microsoft.App/containerApps",
        "category": "Container Apps",
        "default_severity": SeverityLevel.MEDIUM,
        "base_confidence": 0.85,
    },
}


class ResourceCreationDetector:
    """
    Deterministic detection rule for Azure RESOURCE_CREATION events.
    Analyzes AzureActivity telemetry, enforces conservative creation filtering,
    and produces normalized CloudPulse Findings adhering to docs/detection/resource-creation.md.
    """

    DETECTION_ID = "RESOURCE_CREATION"

    @classmethod
    def get_kql_query(cls, lookback_minutes: int = 60) -> str:
        """
        Build the deterministic KQL query for AzureActivity table.
        Filtering for the 6 target resource operations where status is Success/Succeeded.
        """
        operations = [f'"{op}"' for op in RESOURCE_TYPE_MAPPINGS.keys()]
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

    def detect(self, raw_events: List[Dict[str, Any]]) -> List[Finding]:
        """
        Process a list of raw AzureActivity events and return detected findings.
        """
        findings: List[Finding] = []

        for event in raw_events:
            try:
                finding = self.evaluate_event(event)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(
                    "Error evaluating AzureActivity event (EventDataId: %s): %s",
                    event.get("EventDataId", "unknown"),
                    str(e),
                )
                continue

        return findings

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[Finding]:
        """
        Evaluate a single AzureActivity event.
        Returns a normalized Finding if the event is a confirmed creation of a target resource,
        or None if it is irrelevant or an update.
        """
        # 1. Operation check
        op_raw = str(event.get("OperationNameValue") or event.get("OperationName") or "").strip().upper()
        if op_raw not in RESOURCE_TYPE_MAPPINGS:
            return None

        # 2. Activity status check (must be successful)
        status = str(event.get("ActivityStatusValue") or event.get("ActivityStatus") or "").strip().lower()
        if status not in ("success", "succeeded"):
            return None

        # 3. Conservative Creation vs Update verification
        # An AzureActivity /WRITE event can be a CREATE or UPDATE.
        # We verify that creation signals are present.
        if not self._is_creation_event(event):
            logger.debug("Skipping /WRITE event without creation signal: %s", event.get("EventDataId"))
            return None

        mapping = RESOURCE_TYPE_MAPPINGS[op_raw]

        # 4. Extract Resource details
        resource_id = str(event.get("_ResourceId") or event.get("ResourceId") or "").strip()
        if not resource_id:
            # Try extracting from properties if _ResourceId is empty
            props = self._parse_json_field(event.get("Properties_d") or event.get("Properties"))
            resource_id = props.get("entity") or props.get("resource") or ""

        if not resource_id:
            logger.debug("Skipping event with missing resource ID: %s", event.get("EventDataId"))
            return None

        # Parse resource name from ID
        resource_name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
        resource_group = str(event.get("ResourceGroup") or "").strip()
        if not resource_group and "/resourceGroups/" in resource_id:
            parts = resource_id.split("/resourceGroups/")
            resource_group = parts[1].split("/")[0]

        resource_info = ResourceInfo(
            id=resource_id,
            type=mapping["resource_type"],
            name=resource_name,
            resource_group=resource_group,
        )

        # 5. Extract Identity details
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
        caller = event.get("Caller") or claims_data.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")

        identity_info = IdentityInfo(
            principal_id=str(principal_id) if principal_id else None,
            principal_type=str(principal_type) if principal_type else None,
            caller=str(caller) if caller else None,
        )

        # 6. Extract Evidence details
        event_id = str(event.get("EventDataId") or event.get("_ItemId") or "").strip()
        if not event_id:
            # Fallback if EventDataId is missing
            event_id = str(event.get("CorrelationId") or "")

        evidence_info = EvidenceInfo(
            operation=op_raw,
            activity_log_event_id=event_id,
            correlation_id=event.get("CorrelationId"),
            subscription_id=event.get("SubscriptionId"),
            caller_ip=event.get("CallerIpAddress"),
            raw_event=event,
        )

        # 7. Severity and confidence evaluation
        severity = mapping["default_severity"]
        confidence = mapping["base_confidence"]

        # Boost confidence to 0.95 if both ActivitySubstatusValue and Properties explicitly indicate 'Created' or HTTP 201
        substatus = str(event.get("ActivitySubstatusValue") or event.get("ActivitySubstatus") or "").strip().lower()
        if substatus in ("created", "201"):
            confidence = min(1.0, confidence + 0.05)

        # Determine timestamp
        timestamp = event.get("TimeGenerated") or event.get("EventSubmissionTimestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
        elif hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        else:
            timestamp = str(timestamp)

        # Generate deterministic finding ID
        finding_id = generate_deterministic_finding_id(event_id, resource_id)

        return Finding(
            finding_id=finding_id,
            finding_type=self.DETECTION_ID,
            severity=severity,
            timestamp=timestamp,
            resource=resource_info,
            identity=identity_info,
            evidence=evidence_info,
            confidence=confidence,
        )

    def _is_creation_event(self, event: Dict[str, Any]) -> bool:
        """
        Distinguishes resource creation from resource updates.
        Checks ActivitySubstatusValue and Properties status signals.
        """
        substatus = str(event.get("ActivitySubstatusValue") or event.get("ActivitySubstatus") or "").strip().lower()
        if substatus in ("created", "201"):
            return True

        props = self._parse_json_field(event.get("Properties_d") or event.get("Properties"))
        if not props:
            # If no detailed properties and substatus is not 'created', default to conservative rejection
            return False

        # Check for status codes or substatus in properties payload
        status_code = str(props.get("statusCode") or "").strip().lower()
        if status_code in ("created", "201"):
            return True

        prop_substatus = str(props.get("subStatus") or props.get("activitySubstatusValue") or "").strip().lower()
        if prop_substatus in ("created", "201"):
            return True

        # Special case: Role Assignment write events created via Azure Resource Manager
        # often return status code 201 or contain action 'Microsoft.Authorization/roleAssignments/write'
        # with roleAssignmentId generated.
        op_raw = str(event.get("OperationNameValue") or "").strip().upper()
        if op_raw == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE":
            auth = self._parse_json_field(event.get("Authorization_d") or event.get("Authorization"))
            if auth.get("evidence", {}).get("roleAssignmentId") or props.get("roleAssignmentId"):
                return True

        return False

    @staticmethod
    def _parse_json_field(val: Any) -> Dict[str, Any]:
        """Helper to parse JSON string fields into dictionaries safely."""
        if isinstance(val, dict):
            return val
        if isinstance(val, str) and val.strip():
            try:
                return json.loads(val)
            except Exception:
                return {}
        return {}
