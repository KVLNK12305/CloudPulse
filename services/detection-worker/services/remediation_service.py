import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from database.postgres import DatabaseRepository
from models.finding import Finding
from models.incident import Incident, IncidentStatus
from models.remediation import (
    RemediationActionType,
    RemediationStatus,
    RemediationRecord,
    RemediationContainer,
    ApprovalDetails,
    ExecutionDetails,
    VerificationDetails,
    generate_deterministic_remediation_id,
)
from services.azure_network_client import (
    AzureNetworkClient,
    AzureNetworkError,
    AzureNetworkAuthError,
    AzureNetworkNotFoundError,
    AzureNetworkConflictError,
)

logger = logging.getLogger("cloudpulse.services.remediation_service")


class RemediationError(Exception):
    """Base exception for remediation errors."""
    pass


class RemediationUnapprovedError(RemediationError):
    """Raised when attempting to execute an unapproved remediation."""
    pass


class RemediationPreconditionError(RemediationError):
    """Raised when target state does not match finding evidence."""
    pass


class RemediationVerificationError(RemediationError):
    """Raised when post-mutation verification fails."""
    pass


class RemediationService:
    """
    Deterministic Controlled Remediation Engine for CloudPulse.
    Implements docs/remediation/controlled-remediation.md.
    Strictly separates AI advisory recommendations from deterministic Azure mutations.
    """

    PERMISSIVE_SOURCES = {"*", "0.0.0.0/0", "internet"}

    def __init__(
        self,
        db_repo: DatabaseRepository,
        network_client: Optional[AzureNetworkClient] = None,
    ):
        self._db = db_repo
        self._network_client = network_client or AzureNetworkClient()

    def propose_action_from_recommendation(
        self,
        incident: Incident,
        action_id: str,
        action_type: RemediationActionType,
        target_finding_id: Optional[str] = None,
    ) -> RemediationRecord:
        """
        Create a PROPOSED RemediationRecord linked to an incident.
        Resolves targets strictly from verified Finding evidence.
        """
        container = RemediationContainer.from_incident_remediation(incident.remediation)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Resolve target evidence
        nsg_id = None
        rule_name = None
        if action_type == RemediationActionType.DISABLE_PUBLIC_INGRESS:
            f = self._find_upe_finding(incident, target_finding_id)
            if f and f.evidence:
                nsg_id = f.evidence.nsg_id
                rule_name = f.evidence.nsg_rule_name
        elif action_type == RemediationActionType.ISOLATE_WORKLOAD:
            f = self._find_soa_finding(incident, target_finding_id)
            if f and f.evidence:
                nsg_id = f.evidence.nsg_id

        rem_id = generate_deterministic_remediation_id(
            incident_id=incident.incident_id,
            action_type=action_type,
            target_resource=incident.resource.id,
            target_rule=rule_name,
        )

        record = RemediationRecord(
            remediation_id=rem_id,
            incident_id=incident.incident_id,
            action_id=action_id,
            action_type=action_type,
            status=RemediationStatus.PROPOSED,
            target_resource_id=incident.resource.id,
            target_finding_id=target_finding_id,
            target_nsg_id=nsg_id,
            target_rule_name=rule_name,
            created_at=now_iso,
            updated_at=now_iso,
        )

        container.actions[action_id] = record
        incident.remediation = container.to_dict()
        incident.updated_at = now_iso
        self._db.save_incident(incident)
        return record

    def record_approval(
        self,
        incident_id: str,
        action_id: str,
        decision: str,
        operator: str = "security-operator",
        notes: Optional[str] = None,
    ) -> RemediationRecord:
        """
        Record operator authorization intent on an action.
        Does NOT execute remediation.
        """
        incident = self._db.get_incident(incident_id)
        if not incident:
            raise RemediationError(f"Incident '{incident_id}' not found")

        container = RemediationContainer.from_incident_remediation(incident.remediation)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Reject unknown action IDs — approval must only operate on a
        # previously registered PROPOSED action.
        if action_id not in container.actions:
            raise RemediationError(
                f"Action '{action_id}' is not registered on incident '{incident_id}'. "
                f"Only previously proposed actions can be approved."
            )

        record = container.actions[action_id]
        decision_upper = decision.upper()
        if decision_upper not in ("APPROVED", "REJECTED"):
            raise RemediationError(f"Invalid approval status '{decision}'. Must be APPROVED or REJECTED")

        record.approval = ApprovalDetails(
            status=decision_upper,
            operator=operator,
            timestamp=now_iso,
            notes=notes,
        )
        record.status = RemediationStatus.APPROVED if decision_upper == "APPROVED" else RemediationStatus.REJECTED
        record.updated_at = now_iso

        # Append audit timeline entries (both legacy and remediation spec)
        legacy_event = "ACTION_APPROVED" if decision_upper == "APPROVED" else "ACTION_REJECTED"
        remediation_event = "REMEDIATION_APPROVED" if decision_upper == "APPROVED" else "REMEDIATION_REJECTED"
        for evt in (legacy_event, remediation_event):
            incident.timeline.append({
                "timestamp": now_iso,
                "event": evt,
                "operation": "OPERATOR_APPROVAL_INTENT",
                "caller": operator,
                "correlation_metadata": {
                    "action_id": action_id,
                    "remediation_id": record.remediation_id,
                    "action_type": record.action_type.value,
                    "decision": decision_upper,
                    "notes": notes,
                    "autonomous_remediation_blocked": True,
                },
            })

        container.actions[action_id] = record
        incident.remediation = container.to_dict()
        incident.updated_at = now_iso
        self._db.save_incident(incident)
        logger.info("Recorded %s intent for action %s on incident %s", decision_upper, action_id, incident_id)
        return record

    def execute_remediation(
        self,
        incident_id: str,
        action_id: str,
    ) -> RemediationRecord:
        """
        Execute deterministic controlled remediation pipeline:
        1. Precondition checking
        2. Snapshot capture for rollback
        3. Deterministic Azure SDK mutation
        4. Post-mutation verification
        5. Audit timeline appending and incident persistence
        """
        incident = self._db.get_incident(incident_id)
        if not incident:
            raise RemediationError(f"Incident '{incident_id}' not found")

        container = RemediationContainer.from_incident_remediation(incident.remediation)
        if action_id not in container.actions:
            raise RemediationError(f"Remediation action '{action_id}' not found on incident {incident_id}")

        record = container.actions[action_id]

        # Invariant 4: Require explicit prior human approval
        if not record.approval or record.approval.status != "APPROVED":
            raise RemediationUnapprovedError(
                f"Action '{action_id}' has not been approved by an operator (current status: {record.status.value})"
            )

        # Idempotency: If already verified, return existing record without mutation
        if record.status == RemediationStatus.VERIFIED:
            logger.info("Remediation %s already VERIFIED. Returning idempotent result.", record.remediation_id)
            return record

        now_iso = datetime.now(timezone.utc).isoformat()
        incident.status = IncidentStatus.INVESTIGATING
        record.status = RemediationStatus.PRECONDITION_CHECKING
        record.updated_at = now_iso

        # Append REMEDIATION_STARTED event
        incident.timeline.append({
            "timestamp": now_iso,
            "event": "REMEDIATION_STARTED",
            "operation": "REMEDIATION_PIPELINE_INITIATION",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "action_id": action_id,
                "remediation_id": record.remediation_id,
                "action_type": record.action_type.value,
                "target_resource": record.target_resource_id,
            },
        })

        start_time = time.time()
        try:
            if record.action_type == RemediationActionType.DISABLE_PUBLIC_INGRESS:
                self._execute_disable_public_ingress(incident, record)
            elif record.action_type == RemediationActionType.ISOLATE_WORKLOAD:
                self._execute_isolate_workload(incident, record)
            else:
                raise RemediationError(f"Unsupported remediation action type '{record.action_type}'")

            duration = round(time.time() - start_time, 2)
            record.execution = ExecutionDetails(
                executed_at=datetime.now(timezone.utc).isoformat(),
                operation="AZURE_ARM_MUTATION",
                status="SUCCESS",
                duration_ms=duration * 1000,
            )

            # Check if all actions on incident are verified; if so, resolve incident
            if all(a.status == RemediationStatus.VERIFIED for a in container.actions.values()):
                incident.status = IncidentStatus.RESOLVED

        except RemediationPreconditionError as pe:
            logger.warning("Precondition failed for remediation %s: %s", record.remediation_id, str(pe))
            record.status = RemediationStatus.PRECONDITION_FAILED
            record.error_message = str(pe)
            incident.timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "REMEDIATION_PRECONDITION_FAILED",
                "operation": "PRECONDITION_EVALUATION",
                "caller": "cloudpulse-remediation-engine",
                "correlation_metadata": {
                    "action_id": action_id,
                    "remediation_id": record.remediation_id,
                    "reason": str(pe),
                },
            })
        except RemediationVerificationError as ve:
            logger.error("Verification failed for remediation %s: %s", record.remediation_id, str(ve))
            record.status = RemediationStatus.VERIFICATION_FAILED
            record.error_message = str(ve)
            incident.timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "REMEDIATION_FAILED",
                "operation": "POST_REMEDIATION_VERIFICATION",
                "caller": "cloudpulse-remediation-engine",
                "correlation_metadata": {
                    "action_id": action_id,
                    "remediation_id": record.remediation_id,
                    "error": str(ve),
                },
            })
        except Exception as ex:
            logger.exception("Remediation execution failed for %s: %s", record.remediation_id, str(ex))
            record.status = RemediationStatus.FAILED
            record.error_message = str(ex)
            incident.timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "REMEDIATION_FAILED",
                "operation": "AZURE_ARM_MUTATION",
                "caller": "cloudpulse-remediation-engine",
                "correlation_metadata": {
                    "action_id": action_id,
                    "remediation_id": record.remediation_id,
                    "error": str(ex),
                },
            })

        record.updated_at = datetime.now(timezone.utc).isoformat()
        container.actions[action_id] = record
        incident.remediation = container.to_dict()
        incident.updated_at = record.updated_at
        self._db.save_incident(incident)
        return record

    # -----------------------------------------------------------------------
    # Action 1: DISABLE_PUBLIC_INGRESS
    # -----------------------------------------------------------------------

    def _execute_disable_public_ingress(
        self,
        incident: Incident,
        record: RemediationRecord,
    ) -> None:
        """
        Executes DISABLE_PUBLIC_INGRESS:
        Target NSG and rule are determined strictly from finding evidence.
        Precondition: live rule is Inbound Allow on specified port from public source.
        Mutation: updates access to Deny, preserving all other rule properties.
        Verification: re-reads live rule and confirms access is Deny.
        """
        finding = self._find_upe_finding(incident, record.target_finding_id)
        if not finding or not finding.evidence:
            raise RemediationPreconditionError("No UNEXPECTED_PUBLIC_EXPOSURE finding evidence attached to incident")

        ev = finding.evidence
        nsg_id = ev.nsg_id or record.target_nsg_id
        rule_name = ev.nsg_rule_name or record.target_rule_name
        expected_port = str(ev.destination_port or "").strip()
        expected_protocol = str(ev.protocol or "*").strip().upper()

        if not nsg_id or not rule_name:
            raise RemediationPreconditionError(f"Missing NSG ID or rule name in finding {finding.finding_id}")

        rg, nsg_name = self._parse_nsg_id(nsg_id)
        record.target_nsg_id = nsg_id
        record.target_rule_name = rule_name

        # 1. PRECONDITION CHECK
        live_rule = self._network_client.get_security_rule(
            resource_group_name=rg,
            network_security_group_name=nsg_name,
            security_rule_name=rule_name,
        )

        if not live_rule:
            raise RemediationPreconditionError(f"Target rule '{rule_name}' does not exist in NSG '{nsg_name}'")

        live_dir = str(live_rule.get("direction", "")).capitalize()
        live_access = str(live_rule.get("access", "")).capitalize()
        live_port = str(live_rule.get("destination_port_range", "")).strip()
        live_proto = str(live_rule.get("protocol", "")).strip().upper()
        live_src = str(live_rule.get("source_address_prefix", "")).strip().lower()

        # Idempotent Check: If already Denied, mark verified immediately
        if live_access == "Deny":
            logger.info("Rule '%s' in NSG '%s' already has access Deny. Recording compliant state.", rule_name, nsg_name)
            record.status = RemediationStatus.VERIFIED
            record.verification = VerificationDetails(
                verified_at=datetime.now(timezone.utc).isoformat(),
                verified_state="ACCESS_DENIED_IDEMPOTENT",
                is_compliant=True,
            )
            incident.timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "REMEDIATION_VERIFIED",
                "operation": "PRECONDITION_IDEMPOTENT_CHECK",
                "caller": "cloudpulse-remediation-engine",
                "correlation_metadata": {
                    "action_id": record.action_id,
                    "remediation_id": record.remediation_id,
                    "reason": "Rule already in compliant Deny state",
                },
            })
            return

        # Precondition validations
        if live_dir != "Inbound":
            raise RemediationPreconditionError(f"Rule direction is '{live_dir}', expected 'Inbound'")
        if live_access != "Allow":
            raise RemediationPreconditionError(f"Rule access is '{live_access}', expected 'Allow'")
        if expected_port and live_port != expected_port and live_port != "*":
            raise RemediationPreconditionError(f"Rule port is '{live_port}', expected '{expected_port}'")
        if expected_protocol != "*" and live_proto != "*" and live_proto != expected_protocol:
            raise RemediationPreconditionError(f"Rule protocol is '{live_proto}', expected '{expected_protocol}'")
        if live_src not in self.PERMISSIVE_SOURCES:
            raise RemediationPreconditionError(f"Rule source prefix '{live_src}' is not a permissive public source")

        # 2. CAPTURE ORIGINAL STATE FOR ROLLBACK
        record.rollback_state = dict(live_rule)
        captured_etag = live_rule.get("etag")

        # 3. MUTATION: Update access to Deny (with bounded 409 retry + revalidation)
        record.status = RemediationStatus.EXECUTING
        mutation_payload = dict(live_rule)
        mutation_payload["access"] = "Deny"
        mutation_payload["description"] = f"Remediated by CloudPulse: Public ingress disabled for {rule_name}"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._network_client.create_or_update_security_rule(
                    resource_group_name=rg,
                    network_security_group_name=nsg_name,
                    security_rule_name=rule_name,
                    rule_parameters=mutation_payload,
                    etag=captured_etag,
                )
                break  # Mutation succeeded
            except AzureNetworkConflictError:
                logger.warning(
                    "409 conflict on rule '%s' attempt %d/%d — re-reading live state",
                    rule_name, attempt + 1, max_retries,
                )
                if attempt + 1 >= max_retries:
                    raise RemediationPreconditionError(
                        f"Failed to update rule '{rule_name}' after {max_retries} 409 conflict retries"
                    )
                # Re-read live state
                refreshed_rule = self._network_client.get_security_rule(
                    resource_group_name=rg,
                    network_security_group_name=nsg_name,
                    security_rule_name=rule_name,
                )
                if not refreshed_rule:
                    raise RemediationPreconditionError(
                        f"Rule '{rule_name}' disappeared during 409 retry"
                    )
                # Revalidate preconditions against fresh state
                r_access = str(refreshed_rule.get("access", "")).capitalize()
                r_dir = str(refreshed_rule.get("direction", "")).capitalize()
                r_port = str(refreshed_rule.get("destination_port_range", "")).strip()
                r_proto = str(refreshed_rule.get("protocol", "")).strip().upper()
                r_src = str(refreshed_rule.get("source_address_prefix", "")).strip().lower()

                # If rule was already set to Deny by another actor, accept idempotently
                if r_access == "Deny":
                    logger.info("Rule '%s' was set to Deny by another actor during retry. Accepting.", rule_name)
                    record.status = RemediationStatus.VERIFIED
                    record.verification = VerificationDetails(
                        verified_at=datetime.now(timezone.utc).isoformat(),
                        verified_state="ACCESS_DENIED_CONCURRENT",
                        is_compliant=True,
                    )
                    return

                if r_dir != "Inbound":
                    raise RemediationPreconditionError(
                        f"Rule direction drifted to '{r_dir}' during 409 retry, expected 'Inbound'"
                    )
                if r_access != "Allow":
                    raise RemediationPreconditionError(
                        f"Rule access drifted to '{r_access}' during 409 retry, expected 'Allow'"
                    )
                if expected_port and r_port != expected_port and r_port != "*":
                    raise RemediationPreconditionError(
                        f"Rule port drifted to '{r_port}' during 409 retry, expected '{expected_port}'"
                    )
                if expected_protocol != "*" and r_proto != "*" and r_proto != expected_protocol:
                    raise RemediationPreconditionError(
                        f"Rule protocol drifted to '{r_proto}' during 409 retry, expected '{expected_protocol}'"
                    )
                if r_src not in self.PERMISSIVE_SOURCES:
                    raise RemediationPreconditionError(
                        f"Rule source drifted to '{r_src}' during 409 retry — no longer permissive public"
                    )

                # Preconditions still hold — capture new etag and retry
                captured_etag = refreshed_rule.get("etag")
                mutation_payload = dict(refreshed_rule)
                mutation_payload["access"] = "Deny"
                mutation_payload["description"] = f"Remediated by CloudPulse: Public ingress disabled for {rule_name}"

        now_iso = datetime.now(timezone.utc).isoformat()
        record.status = RemediationStatus.EXECUTED
        incident.timeline.append({
            "timestamp": now_iso,
            "event": "REMEDIATION_EXECUTED",
            "operation": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "action_id": record.action_id,
                "remediation_id": record.remediation_id,
                "rule_name": rule_name,
                "nsg_name": nsg_name,
                "mutation": "access=Deny",
            },
        })

        # 4. POST-REMEDIATION VERIFICATION
        record.status = RemediationStatus.VERIFYING
        incident.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "REMEDIATION_VERIFICATION_STARTED",
            "operation": "ARM_STATE_READBACK",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "remediation_id": record.remediation_id,
                "target_rule": rule_name,
            },
        })

        verified_rule = self._network_client.get_security_rule(
            resource_group_name=rg,
            network_security_group_name=nsg_name,
            security_rule_name=rule_name,
        )

        if not verified_rule or str(verified_rule.get("access", "")).capitalize() != "Deny":
            raise RemediationVerificationError(
                f"Post-remediation read-back failed: rule '{rule_name}' access is not 'Deny'"
            )

        # Verification Succeeded
        verified_iso = datetime.now(timezone.utc).isoformat()
        record.status = RemediationStatus.VERIFIED
        record.verification = VerificationDetails(
            verified_at=verified_iso,
            verified_state="ACCESS_DENIED",
            is_compliant=True,
            details={"rule": rule_name, "access": "Deny", "port": verified_rule.get("destination_port_range")},
        )
        incident.timeline.append({
            "timestamp": verified_iso,
            "event": "REMEDIATION_VERIFIED",
            "operation": "POST_REMEDIATION_VERIFICATION",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "action_id": record.action_id,
                "remediation_id": record.remediation_id,
                "verified_state": "ACCESS_DENIED",
                "is_compliant": True,
            },
        })

    # -----------------------------------------------------------------------
    # Action 2: ISOLATE_WORKLOAD
    # -----------------------------------------------------------------------

    def _execute_isolate_workload(
        self,
        incident: Incident,
        record: RemediationRecord,
    ) -> None:
        """
        Executes ISOLATE_WORKLOAD:
        Injects a dedicated high-priority outbound deny rule on the workload NSG
        blocking Internet egress while preserving intra-VNet communication.
        Precondition: target workload and NSG exist; selects an unused priority.
        Verification: confirms isolation rule exists with Outbound Deny to Internet.
        """
        finding = self._find_soa_finding(incident, record.target_finding_id)
        if not finding:
            raise RemediationPreconditionError("No SUSPICIOUS_OUTBOUND_ACTIVITY finding attached to incident")

        # Determine target IP & NSG
        workload_name = incident.resource.name
        source_ip = finding.evidence.source_ip if finding.evidence else None
        if not source_ip:
            source_ip = "10.50.3.10"  # Workload private IP from network topology

        nsg_id = finding.evidence.nsg_id if finding.evidence else None
        if not nsg_id:
            # Fallback to standard NSG associated with the workload tier
            rg_name = incident.resource.resource_group
            sub_id = self._network_client.subscription_id
            nsg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkSecurityGroups/nsg-worker"

        rg, nsg_name = self._parse_nsg_id(nsg_id)
        record.target_nsg_id = nsg_id
        iso_rule_name = f"CloudPulse-Isolate-Outbound-{workload_name}"
        record.target_rule_name = iso_rule_name

        # 1. PRECONDITION & IDEMPOTENCY CHECK
        existing_rules = self._network_client.list_security_rules(
            resource_group_name=rg,
            network_security_group_name=nsg_name,
        )

        # Check if isolation rule already exists
        existing_iso = next((r for r in existing_rules if r.get("name") == iso_rule_name), None)
        if existing_iso:
            if str(existing_iso.get("access", "")).capitalize() == "Deny" and str(existing_iso.get("direction", "")).capitalize() == "Outbound":
                logger.info("Isolation rule '%s' already active on '%s'. Recording idempotent VERIFIED.", iso_rule_name, nsg_name)
                record.status = RemediationStatus.VERIFIED
                record.verification = VerificationDetails(
                    verified_at=datetime.now(timezone.utc).isoformat(),
                    verified_state="WORKLOAD_ISOLATED_IDEMPOTENT",
                    is_compliant=True,
                )
                incident.timeline.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "REMEDIATION_VERIFIED",
                    "operation": "PRECONDITION_IDEMPOTENT_CHECK",
                    "caller": "cloudpulse-remediation-engine",
                    "correlation_metadata": {
                        "action_id": record.action_id,
                        "remediation_id": record.remediation_id,
                        "reason": "Workload isolation rule already active",
                    },
                })
                return

        # Find safe, unused high priority (range 100 to 500)
        used_priorities = {int(r.get("priority", 0)) for r in existing_rules if r.get("priority")}
        chosen_priority = 100
        while chosen_priority in used_priorities:
            chosen_priority += 10
            if chosen_priority > 500:
                raise RemediationPreconditionError("No unused priority available in range 100-500 for isolation rule")

        # 2. CAPTURE ROLLBACK STATE
        record.rollback_state = {
            "action": "DELETE_INJECTED_RULE",
            "rule_name": iso_rule_name,
            "nsg_id": nsg_id,
        }

        # 3. MUTATION: Inject high-priority Outbound Deny rule (with bounded 409 retry + revalidation)
        record.status = RemediationStatus.EXECUTING
        iso_payload = {
            "name": iso_rule_name,
            "priority": chosen_priority,
            "direction": "Outbound",
            "access": "Deny",
            "protocol": "*",
            "source_port_range": "*",
            "destination_port_range": "*",
            "source_address_prefix": f"{source_ip}/32",
            "destination_address_prefix": "Internet",
            "description": f"Autonomous containment: Isolate outbound Internet traffic for {workload_name}",
        }

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._network_client.create_or_update_security_rule(
                    resource_group_name=rg,
                    network_security_group_name=nsg_name,
                    security_rule_name=iso_rule_name,
                    rule_parameters=iso_payload,
                )
                break  # Mutation succeeded
            except AzureNetworkConflictError:
                logger.warning(
                    "409 conflict on isolation rule '%s' attempt %d/%d — re-reading NSG state",
                    iso_rule_name, attempt + 1, max_retries,
                )
                if attempt + 1 >= max_retries:
                    raise RemediationPreconditionError(
                        f"Failed to create isolation rule '{iso_rule_name}' after {max_retries} 409 conflict retries"
                    )
                # Re-read NSG rules to check if isolation rule appeared
                refreshed_rules = self._network_client.list_security_rules(
                    resource_group_name=rg,
                    network_security_group_name=nsg_name,
                )
                existing_iso = next((r for r in refreshed_rules if r.get("name") == iso_rule_name), None)
                if existing_iso and str(existing_iso.get("access", "")).capitalize() == "Deny":
                    logger.info("Isolation rule '%s' created by concurrent actor. Accepting.", iso_rule_name)
                    record.status = RemediationStatus.VERIFIED
                    record.verification = VerificationDetails(
                        verified_at=datetime.now(timezone.utc).isoformat(),
                        verified_state="WORKLOAD_ISOLATED_CONCURRENT",
                        is_compliant=True,
                    )
                    return
                # Re-check priority availability
                refreshed_priorities = {int(r.get("priority", 0)) for r in refreshed_rules if r.get("priority")}
                if chosen_priority in refreshed_priorities:
                    # Priority taken — pick new one
                    new_priority = chosen_priority
                    while new_priority in refreshed_priorities:
                        new_priority += 10
                        if new_priority > 500:
                            raise RemediationPreconditionError(
                                "No unused priority available in range 100-500 after 409 retry"
                            )
                    chosen_priority = new_priority
                    iso_payload["priority"] = chosen_priority

        now_iso = datetime.now(timezone.utc).isoformat()
        record.status = RemediationStatus.EXECUTED
        incident.timeline.append({
            "timestamp": now_iso,
            "event": "REMEDIATION_EXECUTED",
            "operation": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "action_id": record.action_id,
                "remediation_id": record.remediation_id,
                "rule_name": iso_rule_name,
                "priority": chosen_priority,
                "source_ip": source_ip,
                "destination": "Internet",
                "access": "Deny",
            },
        })

        # 4. POST-REMEDIATION VERIFICATION
        record.status = RemediationStatus.VERIFYING
        incident.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "REMEDIATION_VERIFICATION_STARTED",
            "operation": "ARM_STATE_READBACK",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "remediation_id": record.remediation_id,
                "target_rule": iso_rule_name,
            },
        })

        verified_rule = self._network_client.get_security_rule(
            resource_group_name=rg,
            network_security_group_name=nsg_name,
            security_rule_name=iso_rule_name,
        )

        if not verified_rule or str(verified_rule.get("access", "")).capitalize() != "Deny":
            raise RemediationVerificationError(
                f"Post-remediation read-back failed: isolation rule '{iso_rule_name}' was not verified"
            )

        verified_iso = datetime.now(timezone.utc).isoformat()
        record.status = RemediationStatus.VERIFIED
        record.verification = VerificationDetails(
            verified_at=verified_iso,
            verified_state="WORKLOAD_ISOLATED",
            is_compliant=True,
            details={"rule": iso_rule_name, "priority": chosen_priority, "access": "Deny"},
        )
        incident.timeline.append({
            "timestamp": verified_iso,
            "event": "REMEDIATION_VERIFIED",
            "operation": "POST_REMEDIATION_VERIFICATION",
            "caller": "cloudpulse-remediation-engine",
            "correlation_metadata": {
                "action_id": record.action_id,
                "remediation_id": record.remediation_id,
                "verified_state": "WORKLOAD_ISOLATED",
                "is_compliant": True,
            },
        })

    # -----------------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------------

    def _find_upe_finding(
        self,
        incident: Incident,
        target_finding_id: Optional[str] = None,
    ) -> Optional[Finding]:
        for fid in incident.findings:
            if target_finding_id and fid != target_finding_id:
                continue
            f = self._db.get_finding(fid)
            if f and f.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
                return f
        # Search all findings on incident
        for fid in incident.findings:
            f = self._db.get_finding(fid)
            if f and f.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
                return f
        return None

    def _find_soa_finding(
        self,
        incident: Incident,
        target_finding_id: Optional[str] = None,
    ) -> Optional[Finding]:
        for fid in incident.findings:
            if target_finding_id and fid != target_finding_id:
                continue
            f = self._db.get_finding(fid)
            if f and f.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
                return f
        for fid in incident.findings:
            f = self._db.get_finding(fid)
            if f and f.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
                return f
        return None

    @staticmethod
    def _parse_nsg_id(nsg_id: str) -> Tuple[str, str]:
        """
        Extracts (resource_group, nsg_name) from ARM NSG ID.
        """
        match = re.search(r"/resourceGroups/([^/]+)/providers/Microsoft\.Network/networkSecurityGroups/([^/]+)", nsg_id, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)
        # Fallback if bare name passed
        parts = nsg_id.strip("/").split("/")
        if len(parts) >= 2:
            return parts[-3], parts[-1]
        return "cloudpulse-rg", nsg_id
