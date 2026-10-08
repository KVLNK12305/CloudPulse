import logging
import math
from dataclasses import dataclass
from datetime import datetime, date
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple

from models.finding import Finding, SeverityLevel

logger = logging.getLogger("cloudpulse.services.correlation_service")


class CorrelationStrength(str, Enum):
    """
    Deterministic correlation strength levels per Section 5 of
    docs/correlation/security-finops.md.
    """
    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"


@dataclass
class CorrelationResult:
    """
    Result of evaluating correlation between a security finding and a FinOps finding.
    Preserves dimensions, strength, explainable confidence, and incident escalation guidance.
    """
    security_finding_id: str
    finops_finding_id: str
    strength: CorrelationStrength
    confidence: float
    correlation_type: str
    reason: str
    affected_resource: str
    cost_category: str
    actual_cost: float
    baseline_cost: float
    deviation_absolute: float
    percentage_increase: float
    currency: str
    evaluation_date: str
    escalate_severity: Optional[SeverityLevel] = None
    correlated_title: Optional[str] = None


class SecurityFinopsCorrelator:
    """
    Deterministic correlation engine bridging Security Findings and FinOps Findings.
    Authoritative specification: docs/correlation/security-finops.md.
    """

    SECURITY_TYPES = {
        "RESOURCE_CREATION",
        "UNEXPECTED_PUBLIC_EXPOSURE",
        "SUSPICIOUS_OUTBOUND_ACTIVITY",
    }
    FINOPS_TYPES = {"COST_ANOMALY"}

    def correlate(
        self,
        finding_a: Finding,
        finding_b: Finding,
        all_security_types: Optional[set] = None,
    ) -> CorrelationResult:
        """
        Evaluate correlation between two findings.
        Identifies security and FinOps finding roles, evaluates resource,
        temporal, and categorical dimensions, and returns a CorrelationResult.
        """
        # 1. Identify security finding vs FinOps finding
        sec_finding, cost_finding = self._identify_pair(finding_a, finding_b)
        if not sec_finding or not cost_finding:
            return CorrelationResult(
                security_finding_id=finding_a.finding_id,
                finops_finding_id=finding_b.finding_id,
                strength=CorrelationStrength.NONE,
                confidence=0.0,
                correlation_type="UNSUPPORTED_FINDING_PAIR",
                reason="Correlation requires exactly one Security finding and one FinOps finding.",
                affected_resource=finding_a.resource.id,
                cost_category="",
                actual_cost=0.0,
                baseline_cost=0.0,
                deviation_absolute=0.0,
                percentage_increase=0.0,
                currency="USD",
                evaluation_date="",
            )

        # 2. Resource Boundary Dimension
        sec_res = sec_finding.resource.id.strip().lower()
        cost_res = cost_finding.resource.id.strip().lower()
        exact_resource = (sec_res == cost_res)

        sec_rg = (sec_finding.resource.resource_group or "").strip().lower()
        cost_rg = (cost_finding.resource.resource_group or "").strip().lower()
        same_rg = bool(sec_rg and cost_rg and sec_rg == cost_rg)

        cost_cat = (cost_finding.evidence.cost_category or "FinOps").strip()
        actual_cost = float(cost_finding.evidence.actual_cost or 0.0)
        baseline_cost = float(cost_finding.evidence.baseline_cost or 0.0)
        deviation_abs = float(cost_finding.evidence.deviation_absolute or 0.0)
        pct_increase = float(cost_finding.evidence.percentage_increase or 0.0)
        currency = cost_finding.evidence.currency or "USD"
        eval_date_str = cost_finding.evidence.evaluation_date or cost_finding.timestamp[:10]

        # Non-matching resource handling
        if not exact_resource:
            if same_rg:
                base_score = math.sqrt(sec_finding.confidence * cost_finding.confidence)
                conf = self._calculate_confidence(
                    base_score=base_score,
                    resource_adj=-0.35,
                    category_adj=-0.10,
                    temporal_adj=-0.10,
                    stability_adj=0.0,
                )
                # Cap confidence for resource group only
                conf = min(conf, 0.40)
                return CorrelationResult(
                    security_finding_id=sec_finding.finding_id,
                    finops_finding_id=cost_finding.finding_id,
                    strength=CorrelationStrength.WEAK,
                    confidence=conf,
                    correlation_type="RESOURCE_GROUP_CO_LOCATION",
                    reason=(
                        f"Different resources ({sec_finding.resource.name} vs "
                        f"{cost_finding.resource.name}) in same resource group "
                        f"'{sec_finding.resource.resource_group}'; structural proximity only; "
                        "no incident escalation."
                    ),
                    affected_resource=sec_finding.resource.id,
                    cost_category=cost_cat,
                    actual_cost=actual_cost,
                    baseline_cost=baseline_cost,
                    deviation_absolute=deviation_abs,
                    percentage_increase=pct_increase,
                    currency=currency,
                    evaluation_date=eval_date_str,
                    escalate_severity=None,
                    correlated_title=None,
                )
            else:
                return CorrelationResult(
                    security_finding_id=sec_finding.finding_id,
                    finops_finding_id=cost_finding.finding_id,
                    strength=CorrelationStrength.NONE,
                    confidence=0.0,
                    correlation_type="UNRELATED_RESOURCES",
                    reason="Findings originate from different resources and resource groups; no correlation.",
                    affected_resource=sec_finding.resource.id,
                    cost_category=cost_cat,
                    actual_cost=actual_cost,
                    baseline_cost=baseline_cost,
                    deviation_absolute=deviation_abs,
                    percentage_increase=pct_increase,
                    currency=currency,
                    evaluation_date=eval_date_str,
                    escalate_severity=None,
                    correlated_title=None,
                )

        # 3. Temporal Alignment Dimension
        sec_date = self._parse_date(sec_finding.timestamp)
        eval_date = self._parse_date(cost_finding.evidence.evaluation_date) or self._parse_date(cost_finding.timestamp)

        if sec_date and eval_date:
            delta_days = (eval_date - sec_date).days
        else:
            delta_days = 0

        # Temporal boundaries: events separated by > 7 days or negative lag (security in future)
        if delta_days < 0 or delta_days > 7:
            return CorrelationResult(
                security_finding_id=sec_finding.finding_id,
                finops_finding_id=cost_finding.finding_id,
                strength=CorrelationStrength.NONE,
                confidence=0.0,
                correlation_type="TEMPORAL_DIVERGENCE",
                reason=(
                    f"Temporal divergence: security event ({sec_date}) and cost evaluation ({eval_date}) "
                    f"are separated by {delta_days} days (outside 7-day correlation window)."
                ),
                affected_resource=sec_finding.resource.id,
                cost_category=cost_cat,
                actual_cost=actual_cost,
                baseline_cost=baseline_cost,
                deviation_absolute=deviation_abs,
                percentage_increase=pct_increase,
                currency=currency,
                evaluation_date=eval_date_str,
                escalate_severity=None,
                correlated_title=None,
            )

        # 4. Categorical Compatibility & Matrix Evaluation
        cat_lower = cost_cat.lower()
        sec_type = sec_finding.finding_type
        soa_anomaly = (sec_finding.evidence.anomaly_type or "").strip().upper()

        strength = CorrelationStrength.MODERATE
        corr_type = "SECURITY_FINOPS_CORRELATION"
        reason = ""
        cat_adj = 0.0

        if sec_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
            if cat_lower == "network/egress":
                cat_adj = 0.15
                corr_type = "SECURITY_FINOPS_EGRESS_CONCURRENCE"
                if delta_days in (0, 1):
                    if sec_finding.confidence >= 0.85 and cost_finding.confidence >= 0.85:
                        strength = CorrelationStrength.VERY_STRONG
                    else:
                        strength = CorrelationStrength.STRONG
                    reason = (
                        f"High-volume outbound data transfer on {sec_date} concurred with an unexpected "
                        f"surge in Azure network egress billing on {eval_date}."
                    )
                else:
                    strength = CorrelationStrength.MODERATE
                    reason = (
                        f"Outbound data transfer on {sec_date} preceded Network/Egress billing surge "
                        f"on {eval_date} by {delta_days} days."
                    )
            elif cat_lower == "compute" and soa_anomaly == "MINING_PORT":
                cat_adj = 0.15
                corr_type = "SECURITY_FINOPS_COMPUTE_CONCURRENCE"
                if delta_days in (0, 1):
                    strength = CorrelationStrength.STRONG
                    reason = (
                        f"Outbound cryptomining traffic on {sec_date} concurred with an unexpected "
                        f"compute core cost surge on {eval_date}."
                    )
                else:
                    strength = CorrelationStrength.MODERATE
                    reason = (
                        f"Cryptomining traffic on {sec_date} preceded compute cost surge on "
                        f"{eval_date} by {delta_days} days."
                    )
            else:
                cat_adj = -0.25
                strength = CorrelationStrength.WEAK
                corr_type = "SECURITY_FINOPS_CATEGORICAL_MISMATCH"
                reason = (
                    f"Outbound traffic anomaly on {sec_date} coincides with unrelated cost category "
                    f"'{cost_cat}' on {eval_date}; categorical mismatch."
                )

        elif sec_type == "RESOURCE_CREATION":
            if cat_lower in ("compute", "database", "container"):
                cat_adj = 0.10
                strength = CorrelationStrength.STRONG
                corr_type = "SECURITY_FINOPS_PROVISIONING_COST_SURGE"
                reason = (
                    f"Newly provisioned resource created on {sec_date} generated immediate uncharacteristic "
                    f"financial run-rate in '{cost_cat}' on {eval_date}."
                )
            else:
                cat_adj = 0.0
                strength = CorrelationStrength.MODERATE
                corr_type = "SECURITY_FINOPS_PROVISIONING_COST_SURGE"
                reason = (
                    f"Resource created on {sec_date} experienced cost increase in '{cost_cat}' on {eval_date}."
                )

        elif sec_type == "UNEXPECTED_PUBLIC_EXPOSURE":
            if cat_lower in ("network/egress", "compute"):
                cat_adj = 0.10
                strength = CorrelationStrength.MODERATE
                corr_type = "SECURITY_FINOPS_EXPOSURE_COST_INCREASE"
                reason = (
                    f"Workload exposed to the Internet on {sec_date} experienced concurrent cost increases "
                    f"in '{cost_cat}' on {eval_date}."
                )
            else:
                cat_adj = -0.25
                strength = CorrelationStrength.WEAK
                corr_type = "SECURITY_FINOPS_CATEGORICAL_MISMATCH"
                reason = (
                    f"Public exposure on {sec_date} does not align with cost category '{cost_cat}' on {eval_date}."
                )

        # 5. Temporal Proximity Adjustment
        if delta_days == 0:
            temporal_adj = 0.10
        elif delta_days == 1:
            temporal_adj = 0.05
        else:
            temporal_adj = -0.10

        # 6. Baseline Stability Adjustment
        sample_days = cost_finding.evidence.sample_days or 0
        is_cold = cost_finding.evidence.is_cold_start or False
        is_volatile = cost_finding.evidence.high_volatility or False

        stability_adj = 0.0
        if sample_days >= 14 and not is_cold and not is_volatile:
            stability_adj += 0.05
        elif 3 <= sample_days < 7:
            stability_adj -= 0.15

        if is_volatile:
            stability_adj -= 0.20

        # Compute confidence
        base_score = math.sqrt(sec_finding.confidence * cost_finding.confidence)
        confidence = self._calculate_confidence(
            base_score=base_score,
            resource_adj=0.15,
            category_adj=cat_adj,
            temporal_adj=temporal_adj,
            stability_adj=stability_adj,
            is_cold_start=is_cold,
        )


        # 7. Escalated Severity & Correlated Title
        all_types = all_security_types or {sec_finding.finding_type}
        escalate_sev = self._determine_escalation(
            sec=sec_finding,
            cost=cost_finding,
            strength=strength,
            all_sec_types=all_types,
        )
        title = self._determine_title(
            sec=sec_finding,
            cost=cost_finding,
            all_sec_types=all_types,
        )

        return CorrelationResult(
            security_finding_id=sec_finding.finding_id,
            finops_finding_id=cost_finding.finding_id,
            strength=strength,
            confidence=confidence,
            correlation_type=corr_type,
            reason=reason,
            affected_resource=sec_finding.resource.id,
            cost_category=cost_cat,
            actual_cost=actual_cost,
            baseline_cost=baseline_cost,
            deviation_absolute=deviation_abs,
            percentage_increase=pct_increase,
            currency=currency,
            evaluation_date=eval_date_str,
            escalate_severity=escalate_sev,
            correlated_title=title,
        )

    def correlate_incident_findings(
        self,
        findings: List[Finding],
    ) -> Optional[CorrelationResult]:
        """
        Evaluate correlation across all findings attached to an incident.
        Selects the highest-strength, highest-confidence security ↔ FinOps pair.
        """
        sec_findings = [f for f in findings if f.finding_type in self.SECURITY_TYPES]
        cost_findings = [f for f in findings if f.finding_type in self.FINOPS_TYPES]

        if not sec_findings or not cost_findings:
            return None

        all_sec_types = {f.finding_type for f in sec_findings}

        best_result: Optional[CorrelationResult] = None
        strength_rank = {
            CorrelationStrength.VERY_STRONG: 4,
            CorrelationStrength.STRONG: 3,
            CorrelationStrength.MODERATE: 2,
            CorrelationStrength.WEAK: 1,
            CorrelationStrength.NONE: 0,
        }

        for cost_f in cost_findings:
            for sec_f in sec_findings:
                res = self.correlate(sec_f, cost_f, all_security_types=all_sec_types)
                if best_result is None:
                    best_result = res
                else:
                    current_rank = strength_rank.get(res.strength, 0)
                    best_rank = strength_rank.get(best_result.strength, 0)
                    if current_rank > best_rank:
                        best_result = res
                    elif current_rank == best_rank and res.confidence > best_result.confidence:
                        best_result = res

        return best_result

    # -----------------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------------

    def _identify_pair(
        self,
        fa: Finding,
        fb: Finding,
    ) -> Tuple[Optional[Finding], Optional[Finding]]:
        if fa.finding_type in self.SECURITY_TYPES and fb.finding_type in self.FINOPS_TYPES:
            return fa, fb
        if fb.finding_type in self.SECURITY_TYPES and fa.finding_type in self.FINOPS_TYPES:
            return fb, fa
        return None, None

    @staticmethod
    def _parse_date(d_val: Any) -> Optional[date]:
        if not d_val:
            return None
        s = str(d_val).strip()
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            try:
                return datetime.strptime(s[:10], "%Y-%m-%d").date()
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.date()
        except Exception:
            return None

    @staticmethod
    def _calculate_confidence(
        base_score: float,
        resource_adj: float,
        category_adj: float,
        temporal_adj: float,
        stability_adj: float,
        is_cold_start: bool = False,
    ) -> float:
        total = base_score + resource_adj + category_adj + temporal_adj + stability_adj
        if is_cold_start:
            clamped = min(0.30, max(0.10, total - 0.40))
        else:
            clamped = max(0.10, min(1.00, total))
        return round(clamped, 2)


    def _determine_escalation(
        self,
        sec: Finding,
        cost: Finding,
        strength: CorrelationStrength,
        all_sec_types: set,
    ) -> SeverityLevel:
        """
        Deterministic severity escalation schedule per Section 10 of
        docs/correlation/security-finops.md.
        """
        cost_cat = (cost.evidence.cost_category or "").strip().lower()
        delta = float(cost.evidence.deviation_absolute or 0.0)

        # 1. Multi-stage: UPE + SOA + COST on same workload -> CRITICAL
        if "UNEXPECTED_PUBLIC_EXPOSURE" in all_sec_types and "SUSPICIOUS_OUTBOUND_ACTIVITY" in all_sec_types:
            if strength in (
                CorrelationStrength.VERY_STRONG,
                CorrelationStrength.STRONG,
                CorrelationStrength.MODERATE,
            ) and self._severity_rank(cost.severity.value) >= self._severity_rank("MEDIUM"):
                return SeverityLevel.CRITICAL

        # 2. SOA (HIGH/CRITICAL) + COST (HIGH/CRITICAL) on Network/Egress with VERY_STRONG -> CRITICAL
        if (
            sec.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY"
            and self._severity_rank(sec.severity.value) >= self._severity_rank("HIGH")
            and self._severity_rank(cost.severity.value) >= self._severity_rank("HIGH")
            and strength == CorrelationStrength.VERY_STRONG
            and cost_cat == "network/egress"
        ):
            return SeverityLevel.CRITICAL

        # 3. SOA (HIGH/CRITICAL) + COST (HIGH/CRITICAL) on Compute with mining port -> CRITICAL
        if (
            sec.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY"
            and self._severity_rank(sec.severity.value) >= self._severity_rank("HIGH")
            and self._severity_rank(cost.severity.value) >= self._severity_rank("HIGH")
            and strength in (CorrelationStrength.STRONG, CorrelationStrength.VERY_STRONG)
            and cost_cat == "compute"
            and (sec.evidence.anomaly_type or "").upper() == "MINING_PORT"
        ):
            return SeverityLevel.CRITICAL

        # 4. RC (MEDIUM) + COST (CRITICAL) with catastrophic surge (Delta >= $1,000.00) -> CRITICAL
        if (
            sec.finding_type == "RESOURCE_CREATION"
            and cost.severity == SeverityLevel.CRITICAL
            and delta >= 1000.00
        ):
            return SeverityLevel.CRITICAL

        # 5. RC (LOW/MEDIUM) + COST (HIGH) with STRONG and Delta >= $100.00 -> HIGH
        if (
            sec.finding_type == "RESOURCE_CREATION"
            and self._severity_rank(cost.severity.value) >= self._severity_rank("HIGH")
            and strength == CorrelationStrength.STRONG
            and delta >= 100.00
        ):
            return SeverityLevel.HIGH

        # 6. RC (LOW) + COST (MEDIUM) with Delta < $100.00 -> MEDIUM
        if (
            sec.finding_type == "RESOURCE_CREATION"
            and sec.severity == SeverityLevel.LOW
            and cost.severity == SeverityLevel.MEDIUM
            and delta < 100.00
        ):
            return SeverityLevel.MEDIUM

        # 7. Weak correlation: do not escalate beyond max of individual severities
        if strength == CorrelationStrength.WEAK:
            return self._max_severity(sec.severity, cost.severity)

        # Default: max of individual severities
        return self._max_severity(sec.severity, cost.severity)

    def _determine_title(
        self,
        sec: Finding,
        cost: Finding,
        all_sec_types: set,
    ) -> str:
        """
        Deterministic title generation per Section 9 of
        docs/correlation/security-finops.md.
        """
        res_name = sec.resource.name
        cost_cat = cost.evidence.cost_category or "FinOps"
        delta = float(cost.evidence.deviation_absolute or 0.0)

        if "UNEXPECTED_PUBLIC_EXPOSURE" in all_sec_types and "SUSPICIOUS_OUTBOUND_ACTIVITY" in all_sec_types:
            return f"Critical Multi-Stage Incident: {res_name} (Public Exposure + Outbound Egress + Cost Surge)"

        if sec.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
            if cost_cat.lower() == "network/egress":
                return f"Correlated Security & FinOps: {res_name} (Outbound Egress + Network Cost Surge)"
            elif cost_cat.lower() == "compute" and (sec.evidence.anomaly_type or "").upper() == "MINING_PORT":
                return f"Correlated Security & FinOps: {res_name} (Mining Activity + Compute Cost Surge)"
            else:
                return f"Correlated Security & FinOps: {res_name} (Outbound Activity + {cost_cat} Cost Anomaly)"

        if sec.finding_type == "RESOURCE_CREATION":
            return f"Resource Creation Cost Surge: {res_name} ({cost_cat}) - +${delta:.2f}"

        if sec.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
            return f"Public Exposure with Cost Increase: {res_name} ({cost_cat})"

        return f"Correlated Incident: {res_name} ({cost_cat})"

    @staticmethod
    def _severity_rank(sev: str) -> int:
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(str(sev).upper(), 1)

    def _max_severity(self, s1: SeverityLevel, s2: SeverityLevel) -> SeverityLevel:
        return s1 if self._severity_rank(s1.value) >= self._severity_rank(s2.value) else s2
