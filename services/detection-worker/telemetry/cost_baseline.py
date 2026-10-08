import logging
import math
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from models.cost_record import CostRecord, CostObservation

logger = logging.getLogger("cloudpulse.telemetry.cost_baseline")


class CostBaselineStore(ABC):
    """
    Abstract interface for managing and calculating FinOps cost baselines.
    Docs: docs/finops/cost-telemetry.md Section 7 & 14.
    """

    @abstractmethod
    def record_costs(self, records: List[CostRecord]) -> int:
        """
        Persist or reconcile cost records with deterministic deduplication.
        Returns count of records inserted or updated.
        """
        pass

    @abstractmethod
    def get_records(
        self,
        resource_id: Optional[str] = None,
        cost_category: Optional[str] = None,
    ) -> List[CostRecord]:
        """Retrieve stored CostRecords matching optional filter criteria."""
        pass

    @abstractmethod
    def get_observation(
        self,
        resource_id: str,
        cost_category: str,
        evaluation_date: Optional[str] = None,
    ) -> Optional[CostObservation]:
        """
        Calculate baseline and return a single CostObservation for the specified workload and category.
        """
        pass

    @abstractmethod
    def list_observations(
        self,
        evaluation_date: Optional[str] = None,
    ) -> List[CostObservation]:
        """
        Generate CostObservations for all active (resource_id, cost_category) workloads.
        """
        pass


class InMemoryCostBaselineStore(CostBaselineStore):
    """
    In-memory baseline store implementing deterministic reconciliation,
    14-day statistical baseline modeling, cold-start guardrails,
    and CostObservation bundling.
    """

    def __init__(self, initial_records: Optional[List[CostRecord]] = None):
        # Keyed by deterministic record_id (CR-{SHA256})
        self._records: Dict[str, CostRecord] = {}
        if initial_records:
            self.record_costs(initial_records)

    def record_costs(self, records: List[CostRecord]) -> int:
        """
        Idempotent storage & reconciliation.
        If record_id already exists: updates actual_cost, usage_quantity, is_provisional.
        If not: inserts new record.
        Section 12.B of contract.
        """
        count = 0
        for r in records:
            self._records[r.record_id] = r
            count += 1
        return count

    def get_records(
        self,
        resource_id: Optional[str] = None,
        cost_category: Optional[str] = None,
    ) -> List[CostRecord]:
        results: List[CostRecord] = []
        clean_res = resource_id.strip().lower() if resource_id else None
        clean_cat = cost_category.strip().lower() if cost_category else None

        for rec in self._records.values():
            if clean_res and rec.resource_id != clean_res:
                continue
            if clean_cat and rec.cost_category.lower() != clean_cat:
                continue
            results.append(rec)
        return results

    def get_observation(
        self,
        resource_id: str,
        cost_category: str,
        evaluation_date: Optional[str] = None,
    ) -> Optional[CostObservation]:
        clean_res = resource_id.strip().lower()
        clean_cat = cost_category.strip()

        matching_records = [
            r for r in self._records.values()
            if r.resource_id == clean_res and r.cost_category.lower() == clean_cat.lower()
        ]
        if not matching_records:
            return None

        return self._compute_observation(matching_records, clean_res, clean_cat, evaluation_date)

    def list_observations(
        self,
        evaluation_date: Optional[str] = None,
    ) -> List[CostObservation]:
        # Group records by (resource_id, cost_category)
        workload_groups: Dict[Tuple[str, str], List[CostRecord]] = defaultdict(list)
        for r in self._records.values():
            workload_groups[(r.resource_id, r.cost_category)].append(r)

        observations: List[CostObservation] = []
        for (res_id, cost_cat), group_records in workload_groups.items():
            obs = self._compute_observation(group_records, res_id, cost_cat, evaluation_date)
            if obs:
                observations.append(obs)

        return observations

    @classmethod
    def calculate_observations_from_records(
        cls,
        records: List[CostRecord],
        evaluation_date: Optional[str] = None,
    ) -> List[CostObservation]:
        """
        Utility method to compute observations directly from a list of records without prior persistence.
        """
        store = cls(initial_records=records)
        return store.list_observations(evaluation_date=evaluation_date)

    def _compute_observation(
        self,
        records: List[CostRecord],
        resource_id: str,
        cost_category: str,
        evaluation_date: Optional[str] = None,
    ) -> Optional[CostObservation]:
        """
        Statistical formulation per Section 7 of docs/finops/cost-telemetry.md.
        """
        if not records:
            return None

        # Determine evaluation date: provided or latest date among records
        all_dates = sorted({r.timestamp for r in records})
        if evaluation_date:
            eval_date = evaluation_date.strip()
        else:
            eval_date = all_dates[-1]

        # Extract representative metadata from any record in group
        sample_rec = records[0]
        res_name = sample_rec.resource_name
        res_group = sample_rec.resource_group
        currency = sample_rec.currency

        # Separate evaluation day records from historical baseline records
        eval_records = [r for r in records if r.timestamp == eval_date]
        # Current cost on evaluation date
        current_cost = sum(r.actual_cost for r in eval_records)

        # Historical baseline days: days strictly prior to evaluation date
        historical_records = [r for r in records if r.timestamp < eval_date]
        daily_historical: Dict[str, float] = defaultdict(float)
        for r in historical_records:
            # Clamp negative cost adjustments to 0.0 for statistical variance calculation per Section 13.B.2
            clamped_cost = max(0.0, r.actual_cost)
            daily_historical[r.timestamp] += clamped_cost

        # Active baseline observation days
        historical_dates = sorted(daily_historical.keys())
        N = len(historical_dates)

        # 1. Cold-Start Handling (N < 3 days)
        if N < 3:
            baseline_cost = current_cost
            std_dev = 0.0
            deviation_abs = 0.0
            deviation_ratio = 1.0 if current_cost > 0 else 0.0
            pct_change = 0.0
            is_cold_start = True
            high_volatility = False
            confidence = 0.30

            return CostObservation(
                resource_id=resource_id,
                resource_name=res_name,
                resource_group=res_group,
                cost_category=cost_category,
                evaluation_date=eval_date,
                current_cost=round(current_cost, 4),
                baseline_cost=round(baseline_cost, 4),
                deviation_absolute=round(deviation_abs, 4),
                deviation_ratio=round(deviation_ratio, 4),
                percentage_increase=round(pct_change, 2),
                std_dev=round(std_dev, 4),
                currency=currency,
                sample_days=N,
                is_cold_start=is_cold_start,
                high_volatility=high_volatility,
                confidence=confidence,
                records=eval_records,
            )

        # 2. Normal Statistical Baseline (N >= 3 days)
        costs = [daily_historical[d] for d in historical_dates]
        mean_cost = sum(costs) / N

        # Sample standard deviation (N >= 2)
        variance = sum((c - mean_cost) ** 2 for c in costs) / (N - 1)
        std_dev = math.sqrt(variance)

        deviation_abs = current_cost - mean_cost

        # Deviation ratio and percentage increase
        if mean_cost > 0.0:
            deviation_ratio = current_cost / mean_cost
            pct_change = (deviation_ratio - 1.0) * 100.0
            # Coefficient of Variation (CV)
            cv = std_dev / mean_cost
            high_volatility = cv > 0.50
        else:
            deviation_ratio = 0.0
            pct_change = 0.0
            high_volatility = False

        # Confidence score based on sample completeness
        if N >= 14:
            confidence = 0.95
        elif N >= 7:
            confidence = 0.90
        else:
            confidence = 0.80

        return CostObservation(
            resource_id=resource_id,
            resource_name=res_name,
            resource_group=res_group,
            cost_category=cost_category,
            evaluation_date=eval_date,
            current_cost=round(current_cost, 4),
            baseline_cost=round(mean_cost, 4),
            deviation_absolute=round(deviation_abs, 4),
            deviation_ratio=round(deviation_ratio, 4),
            percentage_increase=round(pct_change, 2),
            std_dev=round(std_dev, 4),
            currency=currency,
            sample_days=N,
            is_cold_start=False,
            high_volatility=high_volatility,
            confidence=confidence,
            records=eval_records,
        )
