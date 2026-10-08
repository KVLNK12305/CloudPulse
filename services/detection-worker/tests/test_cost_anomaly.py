import hashlib
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from app import create_app
from database.postgres import InMemoryDatabase
from detectors.cost_anomaly import CostAnomalyDetector
from models.cost_record import CostObservation, CostRecord
from models.finding import (
    Finding,
    SeverityLevel,
    generate_cost_anomaly_finding_id,
)
from models.incident import Incident
from services.incident_orchestrator import IncidentOrchestrator


def make_observation(
    resource_id: str = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
    cost_category: str = "Compute",
    evaluation_date: str = "2026-10-07",
    current_cost: float = 180.0,
    baseline_cost: float = 15.0,
    deviation_absolute: float = 165.0,
    deviation_ratio: float = 12.0,
    percentage_increase: float = 1100.0,
    std_dev: float = 2.1,
    sample_days: int = 14,
    is_cold_start: bool = False,
    high_volatility: bool = False,
    confidence: float = 0.90,
    currency: str = "USD",
    resource_name: str = "vm-worker-01",
    resource_group: str = "cloudpulse-rg",
    records: list = None,
) -> CostObservation:
    """Helper to construct strongly-typed CostObservation bundles."""
    return CostObservation(
        resource_id=resource_id,
        resource_name=resource_name,
        resource_group=resource_group,
        cost_category=cost_category,
        evaluation_date=evaluation_date,
        current_cost=current_cost,
        baseline_cost=baseline_cost,
        deviation_absolute=deviation_absolute,
        deviation_ratio=deviation_ratio,
        percentage_increase=percentage_increase,
        std_dev=std_dev,
        sample_days=sample_days,
        is_cold_start=is_cold_start,
        high_volatility=high_volatility,
        confidence=confidence,
        currency=currency,
        records=records or [],
    )


# ---------------------------------------------------------------------------
# 1. Normal Cost -> No Finding
# ---------------------------------------------------------------------------

def test_normal_cost_no_finding():
    detector = CostAnomalyDetector()
    # Cost fluctuates by $1.00 on a $20.00 baseline (ratio 1.05, delta $1.00)
    obs = make_observation(
        current_cost=21.0,
        baseline_cost=20.0,
        deviation_absolute=1.0,
        deviation_ratio=1.05,
        percentage_increase=5.0,
        std_dev=0.8,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# 2. Genuine Cost Anomaly (Compute Surge & Database Surge)
# ---------------------------------------------------------------------------

def test_genuine_compute_surge_high():
    # Example A from specification: $15 baseline -> $180 actual (+1100%, +$165)
    detector = CostAnomalyDetector()
    obs = make_observation(
        cost_category="Compute",
        current_cost=180.0,
        baseline_cost=15.0,
        deviation_absolute=165.0,
        deviation_ratio=12.0,
        percentage_increase=1100.0,
        std_dev=2.1,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "COST_ANOMALY"
    assert f.severity == SeverityLevel.HIGH
    assert f.confidence >= 0.85
    assert f.evidence.cost_category == "Compute"
    assert f.evidence.actual_cost == 180.0
    assert f.evidence.baseline_cost == 15.0
    assert f.evidence.deviation_absolute == 165.0


def test_genuine_database_surge_critical():
    # Example C: $100 baseline -> $700 actual (+$600, +600%)
    detector = CostAnomalyDetector()
    obs = make_observation(
        cost_category="Database",
        current_cost=700.0,
        baseline_cost=100.0,
        deviation_absolute=600.0,
        deviation_ratio=7.0,
        percentage_increase=600.0,
        std_dev=8.5,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# 3. Tiny-Dollar Trap: Large % but Tiny Dollar Amount (Section 3.1)
# ---------------------------------------------------------------------------

def test_tiny_dollar_trap_suppressed():
    # Example B: $0.02 baseline -> $0.50 actual (+2400%, delta $0.48 < $5.00)
    detector = CostAnomalyDetector()
    obs = make_observation(
        cost_category="Storage",
        current_cost=0.50,
        baseline_cost=0.02,
        deviation_absolute=0.48,
        deviation_ratio=25.0,
        percentage_increase=2400.0,
        std_dev=0.005,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# 4. Large Absolute Surge Override (Section 3.2)
# ---------------------------------------------------------------------------

def test_large_absolute_surge_override():
    detector = CostAnomalyDetector()
    # Baseline $10,000 -> $11,200 (+12%, ratio 1.12), but delta = $1,200 >= $1,000
    obs = make_observation(
        current_cost=11200.0,
        baseline_cost=10000.0,
        deviation_absolute=1200.0,
        deviation_ratio=1.12,
        percentage_increase=12.0,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# 5. Cold-Start Workload (Section 4.A)
# ---------------------------------------------------------------------------

def test_cold_start_normal_provisioning_suppressed():
    # Example D: Single-day provision with $45.00 delta < $100.00
    detector = CostAnomalyDetector()
    obs = make_observation(
        current_cost=45.0,
        baseline_cost=45.0,
        deviation_absolute=45.0,
        sample_days=1,
        is_cold_start=True,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 0


def test_cold_start_catastrophic_provisioning_emits_low():
    # Catastrophic provisioning: Single-day bill $150.00 >= $100.00
    detector = CostAnomalyDetector()
    obs = make_observation(
        current_cost=150.0,
        baseline_cost=150.0,
        deviation_absolute=150.0,
        sample_days=1,
        is_cold_start=True,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.LOW
    assert f.confidence == 0.30
    assert f.evidence.is_cold_start is True


# ---------------------------------------------------------------------------
# 6. Low Sample Count (3 <= N < 7)
# ---------------------------------------------------------------------------

def test_low_sample_count_buffered_and_confidence_capped():
    detector = CostAnomalyDetector()
    # N = 4 days. Ratio buffer (+50%) requires ratio >= 1.7 * 1.5 = 2.55 for Compute
    obs_marginal = make_observation(
        cost_category="Compute",
        current_cost=30.0,
        baseline_cost=15.0,
        deviation_absolute=15.0,
        deviation_ratio=2.0,  # Below 2.55 buffered threshold
        sample_days=4,
    )
    assert len(detector.detect(observations=[obs_marginal])) == 0

    # Strong surge meeting buffered threshold
    obs_strong = make_observation(
        cost_category="Compute",
        current_cost=60.0,
        baseline_cost=15.0,
        deviation_absolute=45.0,
        deviation_ratio=4.0,  # Above 2.55
        sample_days=4,
    )
    findings = detector.detect(observations=[obs_strong])
    assert len(findings) == 1
    # Confidence must be capped at 0.70
    assert findings[0].confidence <= 0.70


# ---------------------------------------------------------------------------
# 7. High-Volatility Workload (Section 4.C)
# ---------------------------------------------------------------------------

def test_high_volatility_suppression_and_trigger():
    detector = CostAnomalyDetector()
    # Example E: Volatile ETL cluster with std_dev = $35.00, delta = $45.00 (z = 1.28 < 3.5)
    obs_volatile_normal = make_observation(
        current_cost=95.0,
        baseline_cost=50.0,
        deviation_absolute=45.0,
        std_dev=35.0,
        high_volatility=True,
    )
    assert len(detector.detect(observations=[obs_volatile_normal])) == 0

    # Extreme surge z = 150 / 35 = 4.28 >= 3.5 and delta >= $25
    obs_volatile_spike = make_observation(
        current_cost=200.0,
        baseline_cost=50.0,
        deviation_absolute=150.0,
        deviation_ratio=4.0,
        std_dev=35.0,
        high_volatility=True,
    )
    findings = detector.detect(observations=[obs_volatile_spike])
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# 8. Zero-Cost Baseline (Section 4.D)
# ---------------------------------------------------------------------------

def test_zero_cost_baseline_thresholds():
    detector = CostAnomalyDetector()
    # Under $15 -> Suppressed
    obs_low = make_observation(
        baseline_cost=0.0,
        current_cost=10.0,
        deviation_absolute=10.0,
        deviation_ratio=0.0,
    )
    assert len(detector.detect(observations=[obs_low])) == 0

    # $20 -> LOW (>= $15)
    obs_med_low = make_observation(
        baseline_cost=0.0,
        current_cost=20.0,
        deviation_absolute=20.0,
        deviation_ratio=0.0,
    )
    findings_low = detector.detect(observations=[obs_med_low])
    assert len(findings_low) == 1
    assert findings_low[0].severity == SeverityLevel.LOW

    # $60 -> MEDIUM (>= $50)
    obs_med = make_observation(
        baseline_cost=0.0,
        current_cost=60.0,
        deviation_absolute=60.0,
        deviation_ratio=0.0,
    )
    findings_med = detector.detect(observations=[obs_med])
    assert len(findings_med) == 1
    assert findings_med[0].severity == SeverityLevel.MEDIUM


# ---------------------------------------------------------------------------
# 9. Incomplete Day T & Input Validation
# ---------------------------------------------------------------------------

def test_incomplete_current_day_t_ignored():
    detector = CostAnomalyDetector()
    today_utc = datetime.now(timezone.utc).date().strftime("%Y-%m-%d")

    obs_today = make_observation(
        evaluation_date=today_utc,  # Day T is incomplete
        current_cost=500.0,
        baseline_cost=10.0,
        deviation_absolute=490.0,
    )
    # Must be ignored per Section 6 & 13.6
    findings = detector.detect(observations=[obs_today])
    assert len(findings) == 0


def test_invalid_resource_id_skipped():
    detector = CostAnomalyDetector()
    obs_unallocated = make_observation(resource_id="/subscriptions/sub-1/resourcegroups/unallocated")
    assert len(detector.detect(observations=[obs_unallocated])) == 0


# ---------------------------------------------------------------------------
# 10. Negative Billing Adjustments / Refunds
# ---------------------------------------------------------------------------

def test_negative_cost_delta_never_alerts():
    detector = CostAnomalyDetector()
    obs_credit = make_observation(
        current_cost=5.0,
        baseline_cost=20.0,
        deviation_absolute=-15.0,  # Negative adjustment
        deviation_ratio=0.25,
    )
    assert len(detector.detect(observations=[obs_credit])) == 0


# ---------------------------------------------------------------------------
# 11 & 12. Deterministic Finding ID & Deduplication Across Reconciliations
# ---------------------------------------------------------------------------

def test_deterministic_finding_id_stability():
    res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
    fid1 = generate_cost_anomaly_finding_id(res_id, "Network/Egress", "2026-10-07")
    fid2 = generate_cost_anomaly_finding_id(res_id.upper(), "network/egress", "2026-10-07")

    assert fid1 == fid2
    assert fid1.startswith("F-COST-")
    assert len(fid1) == 19  # "F-COST-" (7) + 12 = 19


def test_reconciliation_finding_id_does_not_change_when_cost_adjusted():
    """
    Section 9: Actual cost must NOT be part of the seed so that retroactive
    rating adjustments do not create duplicate findings.
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1"
    detector = CostAnomalyDetector()

    # Initial rating: $135.24
    obs1 = make_observation(
        resource_id=res_id,
        current_cost=135.24,
        baseline_cost=5.0,
        deviation_absolute=130.24,
        deviation_ratio=27.0,
    )
    findings1 = detector.detect(observations=[obs1])
    assert len(findings1) == 1

    # Reconciled rating 24 hours later: adjusted to $135.80
    obs2 = make_observation(
        resource_id=res_id,
        current_cost=135.80,
        baseline_cost=5.0,
        deviation_absolute=130.80,
        deviation_ratio=27.16,
    )
    findings2 = detector.detect(observations=[obs2])
    assert len(findings2) == 1

    # Finding ID must be strictly identical
    assert findings1[0].finding_id == findings2[0].finding_id


def test_database_deduplication_of_cost_anomaly():
    db = InMemoryDatabase()
    detector = CostAnomalyDetector()
    obs = make_observation()

    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    f = findings[0]

    is_new_1 = db.save_finding(f)
    assert is_new_1 is True

    # Re-saving identical finding deduplicates
    is_new_2 = db.save_finding(f)
    assert is_new_2 is False
    assert len(db.list_findings()) == 1


# ---------------------------------------------------------------------------
# 13. Severity Boundaries (Decision Matrix Section 5)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("delta,ratio,expected_sev", [
    (1100.0, 1.1, SeverityLevel.CRITICAL),
    (600.0, 3.5, SeverityLevel.CRITICAL),
    (350.0, 1.3, SeverityLevel.HIGH),
    (120.0, 2.6, SeverityLevel.HIGH),
    (80.0, 1.4, SeverityLevel.MEDIUM),
    (30.0, 2.1, SeverityLevel.MEDIUM),
    (10.0, 1.8, SeverityLevel.LOW),
])
def test_severity_matrix_boundaries(delta, ratio, expected_sev):
    detector = CostAnomalyDetector()
    obs = make_observation(
        cost_category="Network/Egress",
        current_cost=delta + 10.0,
        baseline_cost=10.0,
        deviation_absolute=delta,
        deviation_ratio=ratio,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    assert findings[0].severity == expected_sev


# ---------------------------------------------------------------------------
# 14. Confidence Behavior (Section 6)
# ---------------------------------------------------------------------------

def test_confidence_additive_scoring():
    detector = CostAnomalyDetector()
    # Mature 14-day (+0.05), large dollars (+$150, +0.10), high z-score (z=150/10=15, +0.10)
    obs_strong = make_observation(
        confidence=0.90,
        sample_days=14,
        deviation_absolute=150.0,
        std_dev=10.0,
    )
    findings = detector.detect(observations=[obs_strong])
    assert len(findings) == 1
    # 0.90 + 0.05 + 0.10 + 0.10 = 1.0 (clamped)
    assert findings[0].confidence == 1.0


# ---------------------------------------------------------------------------
# 15. Finding Evidence Completeness (Section 8 & 11)
# ---------------------------------------------------------------------------

def test_finding_evidence_completeness():
    detector = CostAnomalyDetector()
    obs = make_observation(
        cost_category="Network/Egress",
        current_cost=125.0,
        baseline_cost=4.0,
        deviation_absolute=121.0,
        deviation_ratio=31.25,
        percentage_increase=3025.0,
        std_dev=0.5,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    ev = findings[0].evidence

    assert ev.actual_cost == 125.0
    assert ev.baseline_cost == 4.0
    assert ev.deviation_absolute == 121.0
    assert ev.deviation_ratio == 31.25
    assert ev.percentage_increase == 3025.0
    assert ev.std_dev == 0.5
    assert ev.currency == "USD"
    assert ev.cost_category == "Network/Egress"
    assert ev.evaluation_date == "2026-10-07"
    assert ev.sample_days == 14
    assert ev.is_cold_start is False
    assert ev.high_volatility is False
    assert findings[0].identity.caller == "azure-cost-management"


# ---------------------------------------------------------------------------
# 16. Incident Orchestrator Integration (Section 10)
# ---------------------------------------------------------------------------

def test_incident_orchestration_cost_anomaly():
    db = InMemoryDatabase()
    orchestrator = IncidentOrchestrator(db)
    detector = CostAnomalyDetector()

    obs = make_observation(
        cost_category="Network/Egress",
        resource_name="vm-worker-01",
        current_cost=135.24,
        baseline_cost=4.20,
        deviation_absolute=131.04,
        deviation_ratio=32.20,
        percentage_increase=3120.0,
    )
    findings = detector.detect(observations=[obs])
    assert len(findings) == 1
    finding = findings[0]

    incident = orchestrator.process_finding(finding)

    # Title check per Section 10: "Cost Anomaly: vm-worker-01 (Network/Egress) - +$131.04 (+3120%)"
    assert "Cost Anomaly: vm-worker-01 (Network/Egress)" in incident.title
    assert "+$131.04 (+3120%)" in incident.title
    assert incident.severity == SeverityLevel.HIGH
    assert incident.status.value == "OPEN"

    # Timeline event check
    assert len(incident.timeline) == 1
    tl = incident.timeline[0]
    assert tl["event"] == "COST_ANOMALY_DETECTED"
    assert tl["finding_id"] == finding.finding_id
    assert tl["caller"] == "azure-cost-management"


# ---------------------------------------------------------------------------
# 17. Flask API Integration: /detect/cost-anomaly
# ---------------------------------------------------------------------------

def test_api_detect_cost_anomaly_replay():
    db = InMemoryDatabase()
    app = create_app(db_repo=db)
    client = app.test_client()

    obs_payload = make_observation(
        cost_category="Network/Egress",
        current_cost=150.0,
        baseline_cost=5.0,
        deviation_absolute=145.0,
        deviation_ratio=30.0,
        percentage_increase=2900.0,
    ).model_dump()

    resp = client.post(
        "/detect/cost-anomaly",
        json={"observations": [obs_payload], "evaluation_date": "2026-10-07"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["observations_evaluated"] == 1
    assert data["findings_detected"] == 1
    assert data["new_findings_persisted"] == 1
    assert data["incidents_created_or_updated"] == 1

    f = data["findings"][0]
    assert f["finding_type"] == "COST_ANOMALY"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["cost_category"] == "Network/Egress"

    inc = data["incidents"][0]
    assert "Cost Anomaly: vm-worker-01" in inc["title"]

    # Verify duplicate replay persists 0 new findings
    resp2 = client.post(
        "/detect/cost-anomaly",
        json={"observations": [obs_payload], "evaluation_date": "2026-10-07"},
    )
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["new_findings_persisted"] == 0
