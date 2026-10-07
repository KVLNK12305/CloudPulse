# CloudPulse Detection Specification — Resource Creation

## Detection ID

RESOURCE_CREATION

## Objective

Detect security-relevant Azure resource creation events and generate a
structured CloudPulse Finding for further correlation and incident creation.

## Initial Resource Types

The MVP considers creation of the following resources security-relevant:

- Virtual Machines
- Public IP addresses
- Storage Accounts
- Network Security Groups
- Role Assignments
- Container Apps

## Source

Azure Activity Log exported to Log Analytics.

## Relevant Operation

Resource creation/write operations represented by Azure Activity Log events.

## Required Evidence

Each finding must contain:

- Azure Activity Log event ID
- Operation name
- Resource ID
- Resource type
- Resource name
- Resource group
- Timestamp
- Initiating identity
- Caller / principal information
- Subscription ID
- Correlation ID where available

## Finding Severity

Resource creation alone does not automatically imply malicious activity.

Initial severity:

- LOW — expected/known resource creation
- MEDIUM — unexpected resource creation
- HIGH — unexpected security-sensitive resource creation
- CRITICAL — resource creation combined with additional high-confidence
  suspicious activity

## Confidence

The detector must provide a confidence score between 0.0 and 1.0.

## Finding Schema

```json
{
  "finding_id": "F-0001",
  "finding_type": "RESOURCE_CREATION",
  "severity": "MEDIUM",
  "timestamp": "...",
  "resource": {
    "id": "...",
    "type": "...",
    "name": "...",
    "resource_group": "..."
  },
  "identity": {
    "principal_id": "...",
    "principal_type": "...",
    "caller": "..."
  },
  "evidence": {
    "operation": "...",
    "activity_log_event_id": "...",
    "correlation_id": "..."
  },
  "confidence": 0.85
}
