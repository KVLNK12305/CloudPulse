import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field


class RemediationActionType(str, Enum):
    """
    Deterministic typed remediation action categories.
    AI recommendations are strictly mapped to these predefined types.
    """
    DISABLE_PUBLIC_INGRESS = "DISABLE_PUBLIC_INGRESS"
    ISOLATE_WORKLOAD = "ISOLATE_WORKLOAD"


class RemediationStatus(str, Enum):
    """
    State machine states for controlled remediation lifecycle.
    Decoupled from overall IncidentStatus.
    """
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PRECONDITION_CHECKING = "PRECONDITION_CHECKING"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


def generate_deterministic_remediation_id(
    incident_id: str,
    action_type: Union[RemediationActionType, str],
    target_resource: str,
    target_rule: Optional[str] = None,
) -> str:
    """
    Generate a deterministic remediation identifier.
    Guarantees idempotent tracking and prevents duplicate mutations.
    """
    act_str = action_type.value if isinstance(action_type, RemediationActionType) else str(action_type)
    seed = f"{incident_id}:{act_str}:{target_resource.strip().lower()}:{str(target_rule or '').strip().lower()}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"REM-{digest}"


class ApprovalDetails(BaseModel):
    status: str = Field(..., description="APPROVED or REJECTED")
    operator: str = Field(default="security-operator")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: Optional[str] = None


class ExecutionDetails(BaseModel):
    executed_at: Optional[str] = None
    operation: Optional[str] = None
    status: Optional[str] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None


class VerificationDetails(BaseModel):
    verified_at: Optional[str] = None
    verified_state: Optional[str] = None
    is_compliant: bool = False
    details: Optional[Dict[str, Any]] = None


class RemediationRecord(BaseModel):
    """
    Domain model for a single controlled remediation action.
    Stored inside incident.remediation JSONB under the actions map.
    """
    remediation_id: str
    incident_id: str
    action_id: str
    action_type: RemediationActionType
    status: RemediationStatus = RemediationStatus.PROPOSED
    target_resource_id: str
    target_finding_id: Optional[str] = None
    target_nsg_id: Optional[str] = None
    target_rule_name: Optional[str] = None
    approval: Optional[ApprovalDetails] = None
    execution: Optional[ExecutionDetails] = None
    verification: Optional[VerificationDetails] = None
    rollback_state: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RemediationContainer(BaseModel):
    """
    Container supporting multiple remediation actions inside incident.remediation.
    Compatible with existing single-dictionary structures.
    """
    actions: Dict[str, RemediationRecord] = Field(default_factory=dict)

    @classmethod
    def from_incident_remediation(cls, raw: Optional[Dict[str, Any]]) -> "RemediationContainer":
        if not raw:
            return cls(actions={})
        if "actions" in raw and isinstance(raw["actions"], dict):
            actions_map = {}
            for aid, rec_data in raw["actions"].items():
                if isinstance(rec_data, dict):
                    try:
                        actions_map[aid] = RemediationRecord(**rec_data)
                    except Exception:
                        pass
                elif isinstance(rec_data, RemediationRecord):
                    actions_map[aid] = rec_data
            return cls(actions=actions_map)
        # Legacy flat structure migration (e.g. { "action_id": "ACT-01", "status": "APPROVED", ... })
        action_id = raw.get("action_id", "ACT-01")
        try:
            record = RemediationRecord(
                remediation_id=raw.get("remediation_id", f"REM-LEGACY-{action_id}"),
                incident_id=raw.get("incident_id", "UNKNOWN"),
                action_id=action_id,
                action_type=raw.get("action_type", RemediationActionType.DISABLE_PUBLIC_INGRESS),
                status=raw.get("status", RemediationStatus.APPROVED),
                target_resource_id=raw.get("target_resource_id", ""),
                approval=ApprovalDetails(
                    status=raw.get("status", "APPROVED"),
                    operator=raw.get("operator", "security-operator"),
                    timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    notes=raw.get("notes"),
                ),
            )
            return cls(actions={action_id: record})
        except Exception:
            return cls(actions={})

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "actions": {aid: rec.model_dump() for aid, rec in self.actions.items()}
        }
        if self.actions:
            latest_action = list(self.actions.values())[-1]
            res["action_id"] = latest_action.action_id
            res["status"] = latest_action.status.value
            res["operator"] = latest_action.approval.operator if latest_action.approval else None
            res["remediation_executed"] = bool(latest_action.execution and latest_action.execution.status == "SUCCESS")
            res["timestamp"] = latest_action.approval.timestamp if latest_action.approval else None
            res["notes"] = latest_action.approval.notes if latest_action.approval else None
        return res
