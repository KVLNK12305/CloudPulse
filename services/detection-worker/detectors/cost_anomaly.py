import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union

from config import config
from models.cost_record import CostObservation, extract_arm_metadata
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_cost_anomaly_finding_id,
)
from telemetry.cost_baseline import CostBaselineStore

logger = logging.getLogger("cloudpulse.detectors.cost_anomaly")


class CostAnomalyDetector:
    """
    Deterministic detector for COST_ANOMALY.
    Identifies statistically significant, unexpected, or uncharacteristic financial spikes
    across Azure workloads based on CostObservation bundles.
    Adheres strictly to docs/detection/cost-anomaly.md.
    """

    DETECTION_ID = "COST_ANOMALY"

    # Category Sensitivity Profiles (docs/detection/cost-anomaly.md Section 7)
    CATEGORY_SENSITIVITY: Dict[str, Dict[str, float]] = {
        "Network/Egress": {"floor": 5.0, "ratio": 1.5},
        "Compute": {"floor": 10.0, "ratio": 1.7},
        "Database": {"floor": 15.0, "ratio": 1.6},
        "Container": {"floor": 10.0, "ratio": 1.8},
        "Storage": {"floor": 15.0, "ratio": 2.0},
        "Other": {"floor": 10.0, "ratio": 1.5},
    }

    # Absolute Dollar Guardrail Floor (Section 3.1 & 13.1)
    MINIMUM_ABSOLUTE_FLOOR: float = 5.0

    def __init__(self, baseline_store: Optional[CostBaselineStore] = None):
        """
        Initialize detector. Optionally accepts a baseline store to pull observations.
        """
        self._baseline_store = baseline_store

    def detect(
        self,
        observations: Optional[List[Union[CostObservation, Dict[str, Any]]]] = None,
        evaluation_date: Optional[str] = None,
    ) -> List[Finding]:
        """
        Execute deterministic COST_ANOMALY detection over CostObservations.
        Adheres to 11-step execution sequence in Section 16 of specification.
        """
        obs_list: List[CostObservation] = []

        if observations is not None:
            for item in observations:
                if isinstance(item, CostObservation):
                    obs_list.append(item)
                elif isinstance(item, dict):
                    obs_list.append(CostObservation(**item))
        elif self._baseline_store is not None:
            obs_list = self._baseline_store.list_observations(evaluation_date=evaluation_date)

        findings: List[Finding] = []
        today_utc = datetime.now(timezone.utc).date().strftime("%Y-%m-%d")

        for obs in obs_list:
            finding = self.evaluate_observation(obs, today_utc=today_utc)
            if finding:
                findings.append(finding)

        logger.info("COST_ANOMALY detector generated %d findings from %d observations", len(findings), len(obs_list))
        return findings

    def evaluate_observation(
        self,
        obs: CostObservation,
        today_utc: Optional[str] = None,
    ) -> Optional[Finding]:
        """
        Evaluate a single CostObservation per Section 16 sequence.
        """
        # Step 2: Input Validity Check
        if not obs.resource_id or not obs.evaluation_date:
            logger.debug("Skipping invalid observation: missing resource_id or evaluation_date")
            return None

        clean_res_id = obs.resource_id.strip().lower()
        if clean_res_id in ("unallocated", "", "none") or "resourcegroups/unallocated" in clean_res_id:
            logger.debug("Skipping unallocated platform cost observation")
            return None

        # Step 3: Check Date Bounds (ignore current day T per Section 6 & 13.6)
        today_str = today_utc or datetime.now(timezone.utc).date().strftime("%Y-%m-%d")
        if obs.evaluation_date >= today_str:
            logger.debug("Skipping incomplete current calendar day %s (today is %s)", obs.evaluation_date, today_str)
            return None

        delta = obs.deviation_absolute
        ratio = obs.deviation_ratio

        # Step 4: Check Absolute Delta Floor ($5.00 floor & non-negative delta)
        # Billed refunds or cost decreases (delta <= 0) never trigger alerts (Section 13.5)
        if delta < self.MINIMUM_ABSOLUTE_FLOOR:
            logger.debug("Suppressed: delta $%.2f below $5.00 floor for %s", delta, obs.resource_id)
            return None

        # Step 5: Evaluate Cold-Start Guardrail (Section 4.A & 13.2)
        if obs.is_cold_start:
            if delta < 100.0:
                logger.debug("Suppressed cold-start workload %s (delta $%.2f < $100.00)", obs.resource_id, delta)
                return None
            # Catastrophic single-day surge on cold start: emit LOW with confidence 0.30
            severity = SeverityLevel.LOW
            confidence = 0.30
            return self._build_finding(obs, severity=severity, confidence=confidence)

        # Step 6: Evaluate High Volatility Guardrail (Section 4.C & 13.3)
        if obs.high_volatility:
            z_score = (delta / obs.std_dev) if obs.std_dev > 0.0 else 0.0
            if z_score < 3.5 or delta < 25.0:
                logger.debug("Suppressed volatile workload %s (z=%.2f < 3.5 or delta $%.2f < $25.00)", obs.resource_id, z_score, delta)
                return None

        # Step 7 & 8: Evaluate Category Thresholds & Determine Severity Level
        # 4.D: Zero-Cost Baseline
        if obs.baseline_cost == 0.0:
            if delta >= 50.0:
                severity = SeverityLevel.MEDIUM
            elif delta >= 15.0:
                severity = SeverityLevel.LOW
            else:
                logger.debug("Suppressed zero-baseline workload %s with delta $%.2f < $15.00", obs.resource_id, delta)
                return None
        else:
            # Check Category Floor & Ratio Thresholds (Section 7)
            cat_profile = self.CATEGORY_SENSITIVITY.get(
                obs.cost_category,
                {"floor": 10.0, "ratio": 1.5},
            )
            cat_floor = cat_profile["floor"]
            cat_ratio = cat_profile["ratio"]

            # Section 4.B: Low sample count (3 <= N < 7) applies +50% buffer to ratio thresholds
            if 3 <= obs.sample_days < 7:
                cat_ratio *= 1.5

            # Dual-criteria: Must meet category sensitivity OR Large Absolute Impact Override (Section 3.2 & Section 5)
            # Section 5 Decision Matrix: Any ratio if Delta >= $1,000, Delta >= $300, or Delta >= $75
            # Section 3.2: Delta >= $250 triggers if ratio >= 1.25
            is_large_override = (
                (delta >= 1000.0)
                or (delta >= 300.0)
                or (delta >= 250.0 and ratio >= 1.25)
                or (delta >= 75.0)
            )

            if not is_large_override:
                if delta < cat_floor or ratio < cat_ratio:
                    logger.debug(
                        "Suppressed below category threshold for %s (%s): delta $%.2f < $%.2f or ratio %.2f < %.2f",
                        obs.resource_id,
                        obs.cost_category,
                        delta,
                        cat_floor,
                        ratio,
                        cat_ratio,
                    )
                    return None

            # Section 5 Decision Matrix
            severity = self._determine_severity(delta=delta, ratio=ratio, sample_days=obs.sample_days)
            if severity is None:
                return None

        # Step 9: Compute Confidence Score (Section 6)
        confidence = self._compute_confidence(obs)

        # Step 10 & 11: Construct Finding
        return self._build_finding(obs, severity=severity, confidence=confidence)

    def _determine_severity(
        self,
        delta: float,
        ratio: float,
        sample_days: int,
    ) -> Optional[SeverityLevel]:
        """
        Deterministic Severity Model per Section 5 Decision Matrix.
        """
        # CRITICAL: Delta >= $500 and Ratio >= 3.00 OR Delta >= $1,000.00
        if delta >= 1000.0 or (delta >= 500.0 and ratio >= 3.00):
            return SeverityLevel.CRITICAL

        # HIGH: Delta >= $100 and Ratio >= 2.50 OR Delta >= $300.00
        if delta >= 300.0 or (delta >= 100.0 and ratio >= 2.50):
            return SeverityLevel.HIGH

        # MEDIUM: Delta >= $25 and Ratio >= 2.00 OR Delta >= $75.00
        if delta >= 75.0 or (delta >= 25.0 and ratio >= 2.00):
            return SeverityLevel.MEDIUM

        # LOW: Delta >= $5.00 and Ratio >= 1.50
        if delta >= 5.0 and ratio >= 1.50:
            return SeverityLevel.LOW

        # If it reached here via override (e.g. delta >= $250, ratio >= 1.25), classify at least MEDIUM
        if delta >= 250.0 and ratio >= 1.25:
            return SeverityLevel.MEDIUM

        return None

    def _compute_confidence(self, obs: CostObservation) -> float:
        """
        Additive Confidence Scoring Schedule per Section 6.
        """
        base = obs.confidence if (obs.confidence and obs.confidence > 0.0) else 0.85
        adjustment = 0.0

        # Baseline Maturity
        if obs.sample_days >= 14:
            adjustment += 0.05
        elif 3 <= obs.sample_days < 7:
            adjustment -= 0.15

        # Statistical Significance (z-score)
        if obs.std_dev > 0.0:
            z = obs.deviation_absolute / obs.std_dev
            if z >= 3.5:
                adjustment += 0.10

        # Financial Significance
        if obs.deviation_absolute >= 100.0:
            adjustment += 0.10
        elif obs.deviation_absolute < 10.0:
            adjustment -= 0.10

        # Workload Volatility
        if obs.high_volatility:
            adjustment -= 0.20

        # Cold Start
        if obs.is_cold_start:
            adjustment -= 0.40

        # Billing Reconciliation / Provisional Data
        is_prov = any(getattr(r, "is_provisional", False) for r in obs.records)
        if is_prov:
            adjustment -= 0.10

        score = base + adjustment
        # Clamp between 0.10 and 1.00
        clamped = max(0.10, min(1.00, score))

        # Enforce caps
        if 3 <= obs.sample_days < 7:
            clamped = min(0.70, clamped)
        if obs.is_cold_start:
            clamped = min(0.30, clamped)

        return round(clamped, 2)

    def _build_finding(
        self,
        obs: CostObservation,
        severity: SeverityLevel,
        confidence: float,
    ) -> Finding:
        """
        Construct normalized Finding domain model conforming to models/finding.py.
        """
        # Parse canonical ARM dimensions
        canon_id, name, res_type, rg, sub_id = extract_arm_metadata(
            raw_resource_id=obs.resource_id,
            default_sub_id=config.AZURE_SUBSCRIPTION_ID,
            default_rg=obs.resource_group or "",
        )

        display_name = obs.resource_name or name
        display_rg = obs.resource_group or rg

        # Extract record metadata if available
        service_name = obs.cost_category
        meter_name = f"{obs.cost_category} Meter"
        is_provisional = False

        if obs.records:
            first_rec = obs.records[0]
            service_name = first_rec.service_name or service_name
            meter_name = first_rec.meter_name or meter_name
            sub_id = first_rec.subscription_id or sub_id
            is_provisional = any(r.is_provisional for r in obs.records)

        # Step 10: Deterministic Finding ID
        finding_id = generate_cost_anomaly_finding_id(
            resource_id=canon_id,
            cost_category=obs.cost_category,
            evaluation_date=obs.evaluation_date,
        )

        date_clean = obs.evaluation_date.replace("-", "")
        event_id = f"cost-obs-{display_name}-{date_clean}"
        corr_id = f"corr-finops-{date_clean}"

        evidence = EvidenceInfo(
            operation="COST_ANOMALY_EVALUATION",
            activity_log_event_id=event_id,
            correlation_id=corr_id,
            subscription_id=sub_id,
            actual_cost=obs.current_cost,
            baseline_cost=obs.baseline_cost,
            deviation_absolute=obs.deviation_absolute,
            deviation_ratio=obs.deviation_ratio,
            percentage_increase=obs.percentage_increase,
            std_dev=obs.std_dev,
            currency=obs.currency,
            cost_category=obs.cost_category,
            service_name=service_name,
            meter_name=meter_name,
            evaluation_date=obs.evaluation_date,
            sample_days=obs.sample_days,
            is_cold_start=obs.is_cold_start,
            high_volatility=obs.high_volatility,
            is_provisional=is_provisional,
            raw_event=obs.model_dump(exclude={"records"}),
        )

        return Finding(
            finding_id=finding_id,
            finding_type=self.DETECTION_ID,
            severity=severity,
            timestamp=f"{obs.evaluation_date}T00:00:00Z",
            resource=ResourceInfo(
                id=canon_id,
                name=display_name,
                type=res_type,
                resource_group=display_rg,
            ),
            identity=IdentityInfo(
                principal_id=None,
                principal_type=None,
                caller="azure-cost-management",
            ),
            evidence=evidence,
            confidence=confidence,
        )
