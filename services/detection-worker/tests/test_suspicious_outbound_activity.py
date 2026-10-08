import pytest
from datetime import datetime, timezone
from typing import Set

from database.postgres import InMemoryDatabase
from detectors.suspicious_outbound_activity import (
    SuspiciousOutboundActivityDetector,
    VOLUME_SPIKE_RATIO,
    MIN_BASELINE_HOURLY_BYTES,
)
from models.finding import (
    Finding,
    SeverityLevel,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    generate_outbound_finding_id,
)
from models.network_flow import NetworkFlowEvent, WorkloadBaseline
from services.incident_orchestrator import IncidentOrchestrator
from telemetry.network_flow import InMemoryBaselineStore, NetworkFlowAdapter
from tests.fixtures.network_flow_fixtures import (
    WORKLOAD_VM_01,
    WORKLOAD_VM_DATA,
    SUBNET_WORKER,
    SUBNET_DATA,
    make_flow_record,
    mining_flow_fixture,
    volume_spike_fixture,
    massive_exfiltration_fixture,
    management_port_ssh_fixture,
    management_port_rdp_fixture,
    scanning_sweep_fixtures,
    subnet_violation_fixture,
    internal_traffic_fixture,
    standard_approved_dns_fixture,
    standard_approved_cloudflare_dns_fixture,
    normal_known_traffic_fixture,
)


@pytest.fixture
def baseline_store() -> InMemoryBaselineStore:
    """Established 7-day baseline for WORKLOAD_VM_01 with 168 historical hours."""
    store = InMemoryBaselineStore()
    store.set_baseline(
        WORKLOAD_VM_01,
        WorkloadBaseline(
            resource_id=WORKLOAD_VM_01,
            mean_hourly_bytes=50.0 * 1024 * 1024,  # 50 MB / hour
            std_hourly_bytes=10.0 * 1024 * 1024,
            known_destination_ips={"93.184.216.34", "151.101.1.69", "20.50.2.1"},
            historical_hours=168,
            flow_count=5000,
            is_cold_start=False,
        ),
    )
    store.set_baseline(
        WORKLOAD_VM_DATA,
        WorkloadBaseline(
            resource_id=WORKLOAD_VM_DATA,
            mean_hourly_bytes=20.0 * 1024 * 1024,
            std_hourly_bytes=5.0 * 1024 * 1024,
            known_destination_ips=set(),
            historical_hours=168,
            flow_count=1000,
            is_cold_start=False,
        ),
    )
    return store


@pytest.fixture
def soa_detector(mock_db, baseline_store) -> SuspiciousOutboundActivityDetector:
    return SuspiciousOutboundActivityDetector(
        db_repo=mock_db,
        baseline_store=baseline_store,
    )


# =========================================================================
# POSITIVE CASES
# =========================================================================

def test_cryptomining_port_critical(soa_detector):
    """
    Positive Case 1: Outbound connection to Stratum mining pool port 3333.
    Expected: CRITICAL severity, MINING_PORT anomaly type, F-SOA- ID.
    """
    event = mining_flow_fixture()
    findings = soa_detector.detect(flows=[event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.evidence.anomaly_type == "MINING_PORT"
    assert finding.evidence.destination_port == "3333"
    assert finding.finding_id.startswith("F-SOA-")
    assert finding.confidence >= 0.70


def test_outbound_volume_spike_high(soa_detector):
    """
    Positive Case 2: Outbound egress exceeds baseline by factor >= 5.0 and > 1 GB.
    Expected: HIGH severity, VOLUME_SPIKE anomaly type.
    """
    event = volume_spike_fixture(bytes_sent=1500 * 1024 * 1024)  # 1.5 GB vs 50 MB baseline (ratio ~30.0)
    findings = soa_detector.detect(flows=[event])

    volume_findings = [f for f in findings if f.evidence.anomaly_type == "VOLUME_SPIKE"]
    assert len(volume_findings) == 1
    vf = volume_findings[0]
    assert vf.severity == SeverityLevel.HIGH
    assert vf.evidence.bytes_sent == 1500 * 1024 * 1024
    assert vf.evidence.deviation_ratio >= 5.0
    assert vf.finding_id.startswith("F-SOA-")


def test_massive_exfiltration_critical(soa_detector):
    """
    Positive Case 3: Massive outbound egress (> 5 GB with ratio >= 10.0).
    Expected: CRITICAL severity.
    """
    event = massive_exfiltration_fixture()
    findings = soa_detector.detect(flows=[event])

    vol_findings = [f for f in findings if f.evidence.anomaly_type == "VOLUME_SPIKE"]
    assert len(vol_findings) == 1
    assert vol_findings[0].severity == SeverityLevel.CRITICAL


def test_novel_external_destination(soa_detector):
    """
    Positive Case 4: Communication to a novel external IP not in known baseline.
    Expected: NOVEL_DESTINATION anomaly type.
    """
    event = make_flow_record(
        dest_ip="203.0.113.199",  # Novel public IP
        dest_port=443,
        bytes_sent=100000,
        flow_count=2,
    )
    findings = soa_detector.detect(flows=[event])

    novel_findings = [f for f in findings if f.evidence.anomaly_type == "NOVEL_DESTINATION"]
    assert len(novel_findings) == 1
    assert novel_findings[0].evidence.destination_ip == "203.0.113.199"
    assert novel_findings[0].severity == SeverityLevel.MEDIUM


def test_internet_management_ports_medium(soa_detector):
    """
    Positive Case 5: Outbound SSH (22) or RDP (3389) over the Internet.
    Expected: MEDIUM severity, MANAGEMENT_PORT anomaly type.
    """
    ssh_event = management_port_ssh_fixture()
    rdp_event = management_port_rdp_fixture()

    findings = soa_detector.detect(flows=[ssh_event, rdp_event])
    mgmt_findings = [f for f in findings if f.evidence.anomaly_type == "MANAGEMENT_PORT"]

    assert len(mgmt_findings) == 2
    ports = {f.evidence.destination_port for f in mgmt_findings}
    assert "22" in ports
    assert "3389" in ports
    for f in mgmt_findings:
        assert f.severity == SeverityLevel.MEDIUM


def test_outbound_scanning_diversity_high(soa_detector):
    """
    Positive Case 6: Workload connects to > 50 distinct public IPs within observation window.
    Expected: HIGH severity, SCANNING anomaly type, dest_ip_count > 50.
    """
    scan_events = scanning_sweep_fixtures(num_targets=60)
    findings = soa_detector.detect(flows=scan_events)

    scan_findings = [f for f in findings if f.evidence.anomaly_type == "SCANNING"]
    assert len(scan_findings) == 1
    assert scan_findings[0].severity == SeverityLevel.HIGH
    assert scan_findings[0].evidence.dest_ip_count == 60


def test_subnet_role_violation_high(soa_detector):
    """
    Positive Case 7: Workload residing in snet-data initiates direct Internet egress.
    Expected: HIGH severity, SUBNET_VIOLATION anomaly type.
    """
    event = subnet_violation_fixture()
    findings = soa_detector.detect(flows=[event])

    sub_findings = [f for f in findings if f.evidence.anomaly_type == "SUBNET_VIOLATION"]
    assert len(sub_findings) == 1
    assert sub_findings[0].severity == SeverityLevel.HIGH


def test_security_context_escalates_to_critical_with_active_upe(mock_db, baseline_store):
    """
    Positive Case 8: When the workload already has an active UNEXPECTED_PUBLIC_EXPOSURE
    finding in PostgreSQL, an outbound anomaly escalates to CRITICAL and receives confidence boost.
    """
    # Seed active UPE finding for WORKLOAD_VM_01
    upe_finding = Finding(
        finding_id="F-UPE-7A39B21C4D10",
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=SeverityLevel.HIGH,
        timestamp=datetime.now(timezone.utc).isoformat(),
        resource=ResourceInfo(
            id=WORKLOAD_VM_01,
            type="Microsoft.Compute/virtualMachines",
            name="vm-worker-01",
            resource_group="cloudpulse-rg",
        ),
        identity=IdentityInfo(),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-upe-01",
            destination_port="22",
            exposure_type="MANAGEMENT_PORT",
        ),
        confidence=0.95,
    )
    mock_db.save_finding(upe_finding)

    detector = SuspiciousOutboundActivityDetector(db_repo=mock_db, baseline_store=baseline_store)

    # Moderate egress event (normally MEDIUM)
    event = management_port_ssh_fixture()
    findings = detector.detect(flows=[event])

    assert len(findings) == 1
    f = findings[0]
    # Escalated to CRITICAL due to active public exposure
    assert f.severity == SeverityLevel.CRITICAL
    assert "F-UPE-7A39B21C4D10" in f.evidence.related_finding_ids
    assert f.confidence >= 0.85  # boosted


# =========================================================================
# NEGATIVE CASES
# =========================================================================

def test_normal_known_traffic_no_finding(soa_detector):
    """
    Negative Case 1: Normal traffic to known destination within baseline volume.
    Expected: 0 findings.
    """
    event = normal_known_traffic_fixture()
    findings = soa_detector.detect(flows=[event])
    assert len(findings) == 0


def test_approved_infrastructure_dns_ntp_no_finding(soa_detector):
    """
    Negative Case 2: Standard DNS (port 53 UDP) or NTP (port 123 UDP).
    Expected: 0 findings.
    """
    dns_wire = standard_approved_dns_fixture()
    dns_cf = standard_approved_cloudflare_dns_fixture()
    ntp_event = make_flow_record(
        dest_ip="216.239.35.0",  # time.google.com
        dest_port=123,
        protocol="UDP",
        bytes_sent=480,
    )

    findings = soa_detector.detect(flows=[dns_wire, dns_cf, ntp_event])
    assert len(findings) == 0


def test_small_volume_deviation_no_finding(soa_detector):
    """
    Negative Case 3: Moderate transfer (e.g. 10 MB) below volume thresholds.
    Expected: 0 volume findings.
    """
    event = make_flow_record(
        dest_ip="93.184.216.34",  # In known baseline
        dest_port=443,
        bytes_sent=10 * 1024 * 1024,  # 10 MB vs 50 MB baseline (ratio 0.2)
        bytes_received=20 * 1024 * 1024,
    )
    findings = soa_detector.detect(flows=[event])
    assert len(findings) == 0


def test_cold_start_suppresses_volume_false_positives(mock_db):
    """
    Negative Case 4: Newly created resource (< 10 historical hours) emits a volume spike.
    Contract Section 6: Volume ratio checks are suppressed during cold start.
    Expected: 0 volume spike findings.
    """
    cold_store = InMemoryBaselineStore()
    cold_store.set_baseline(
        WORKLOAD_VM_01,
        WorkloadBaseline(
            resource_id=WORKLOAD_VM_01,
            mean_hourly_bytes=0.0,
            historical_hours=2,  # Cold start (< 10 hours)
            flow_count=5,
            is_cold_start=True,
        ),
    )
    detector = SuspiciousOutboundActivityDetector(db_repo=mock_db, baseline_store=cold_store)

    # 800 MB egress during initial deployment
    event = volume_spike_fixture(bytes_sent=800 * 1024 * 1024)
    findings = detector.detect(flows=[event])

    vol_findings = [f for f in findings if f.evidence.anomaly_type == "VOLUME_SPIKE"]
    assert len(vol_findings) == 0


def test_internal_rfc1918_traffic_no_finding(soa_detector):
    """
    Negative Case 5: Large internal VNet transfer between private RFC 1918 addresses.
    Contract: Internal/private traffic must not qualify as an Internet anomaly.
    Expected: 0 findings.
    """
    event = internal_traffic_fixture()
    findings = soa_detector.detect(flows=[event])
    assert len(findings) == 0


# =========================================================================
# EDGE CASES
# =========================================================================

def test_missing_optional_fields_handled_safely(soa_detector):
    """
    Edge Case 1: Missing optional fields (SourceIP_s, SrcSubnet_s, CallerIpAddress).
    Expected: Evaluates safely without raising exceptions.
    """
    minimal_event = {
        "TimeGenerated": "2026-10-08T14:15:00Z",
        "VM_s": WORKLOAD_VM_01,
        "DestPublicIPs_s": "198.51.100.77",
        "DestPort_d": 3333.0,
        "L4Protocol_s": "T",
        "TotalBytesSent": 1000,
        "TotalBytesReceived": 500,
    }
    findings = soa_detector.detect(flows=[minimal_event])
    assert len(findings) == 1
    assert findings[0].evidence.anomaly_type == "MINING_PORT"


def test_zero_baseline_safe_division(mock_db):
    """
    Edge Case 2: Zero historical baseline. The 10 MB floor must prevent division by zero.
    """
    store = InMemoryBaselineStore()
    store.set_baseline(
        WORKLOAD_VM_01,
        WorkloadBaseline(
            resource_id=WORKLOAD_VM_01,
            mean_hourly_bytes=0.0,
            historical_hours=100,  # mature workload with 0 historic egress
            flow_count=100,
            is_cold_start=False,
        ),
    )
    detector = SuspiciousOutboundActivityDetector(db_repo=mock_db, baseline_store=store)

    event = volume_spike_fixture(bytes_sent=600 * 1024 * 1024)  # 600 MB
    findings = detector.detect(flows=[event])

    vol_findings = [f for f in findings if f.evidence.anomaly_type == "VOLUME_SPIKE"]
    assert len(vol_findings) == 1
    # Denominator used 10 MB floor: 600 MB / 10 MB = 60.0
    assert vol_findings[0].evidence.deviation_ratio == 60.0


def test_cold_start_structural_checks_remain_active_and_confidence_capped(mock_db):
    """
    Edge Case 3: On a cold-start resource, structural checks (cryptomining ports)
    remain 100% active, and confidence is capped at 0.70.
    """
    store = InMemoryBaselineStore()
    store.set_baseline(
        WORKLOAD_VM_01,
        WorkloadBaseline(
            resource_id=WORKLOAD_VM_01,
            mean_hourly_bytes=0.0,
            historical_hours=1,
            flow_count=2,
            is_cold_start=True,
        ),
    )
    detector = SuspiciousOutboundActivityDetector(db_repo=mock_db, baseline_store=store)

    event = mining_flow_fixture()
    findings = detector.detect(flows=[event])

    assert len(findings) == 1
    assert findings[0].evidence.anomaly_type == "MINING_PORT"
    assert findings[0].severity == SeverityLevel.CRITICAL
    # Confidence capped at 0.70 during cold start (Section 6)
    assert findings[0].confidence <= 0.70


def test_deterministic_finding_id_stability():
    """
    Edge Case 4: Verify finding ID stability and F-SOA- format formula.
    """
    res_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
    dest_ip = "198.51.100.77"
    port = 3333
    anomaly = "MINING_PORT"
    timestamp = "2026-10-08T14:15:00Z"

    id1 = generate_outbound_finding_id(res_id, dest_ip, port, anomaly, epoch_timestamp=timestamp)
    id2 = generate_outbound_finding_id(res_id, dest_ip, port, anomaly, epoch_timestamp=timestamp)

    assert id1.startswith("F-SOA-")
    assert id1 == id2
    assert len(id1) == 18  # F-SOA- (6) + 12 hex chars


def test_repeated_evaluation_deduplication(soa_detector, mock_db):
    """
    Edge Case 5: Re-evaluating the identical anomaly within the same 4-hour window
    yields identical finding_id and is deduplicated in PostgreSQL/InMemoryDatabase.
    """
    event = mining_flow_fixture()

    findings_1 = soa_detector.detect(flows=[event])
    assert len(findings_1) == 1
    is_new_1 = mock_db.save_finding(findings_1[0])
    assert is_new_1 is True

    findings_2 = soa_detector.detect(flows=[event])
    assert len(findings_2) == 1
    assert findings_1[0].finding_id == findings_2[0].finding_id

    is_new_2 = mock_db.save_finding(findings_2[0])
    assert is_new_2 is False  # Deduplicated!


def test_incident_orchestrator_multi_detector_escalation(mock_db, soa_detector):
    """
    Incident Integration: Combining UNEXPECTED_PUBLIC_EXPOSURE with SUSPICIOUS_OUTBOUND_ACTIVITY
    on the same workload escalates the Incident to CRITICAL.
    """
    orchestrator = IncidentOrchestrator(db_repo=mock_db)

    # 1. First event: UNEXPECTED_PUBLIC_EXPOSURE (HIGH)
    upe_finding = Finding(
        finding_id="F-UPE-TEST01",
        finding_type="UNEXPECTED_PUBLIC_EXPOSURE",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(
            id=WORKLOAD_VM_01,
            type="Microsoft.Compute/virtualMachines",
            name="vm-worker-01",
            resource_group="cloudpulse-rg",
        ),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            activity_log_event_id="evt-upe-1",
            destination_port="22",
            exposure_type="MANAGEMENT_PORT",
        ),
        confidence=0.95,
    )
    mock_db.save_finding(upe_finding)
    incident_1 = orchestrator.process_finding(upe_finding)
    assert incident_1.severity == SeverityLevel.HIGH

    # 2. Second event: SUSPICIOUS_OUTBOUND_ACTIVITY
    soa_event = management_port_ssh_fixture()
    soa_findings = soa_detector.detect(flows=[soa_event])
    assert len(soa_findings) == 1

    mock_db.save_finding(soa_findings[0])
    incident_2 = orchestrator.process_finding(soa_findings[0])

    # Canonical incident correlation
    assert incident_2.incident_id == incident_1.incident_id
    assert len(incident_2.findings) == 2
    # Escalated to CRITICAL
    assert incident_2.severity == SeverityLevel.CRITICAL
    events = [e["event"] for e in incident_2.timeline]
    assert "UNEXPECTED_PUBLIC_EXPOSURE_DETECTED" in events
    assert "SUSPICIOUS_OUTBOUND_ACTIVITY_DETECTED" in events


def test_api_detect_suspicious_outbound_endpoint(client):
    """
    API Integration: POST /detect/suspicious-outbound with mocked flow events.
    """
    event = mining_flow_fixture()
    resp = client.post(
        "/detect/suspicious-outbound",
        json={"events": [event]},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["findings_detected"] >= 1
    assert data["findings"][0]["finding_type"] == "SUSPICIOUS_OUTBOUND_ACTIVITY"
    assert data["findings"][0]["severity"] == "CRITICAL"


def test_api_detect_live_dependency_unavailable_returns_503(client):
    """
    API Integration: POST /detect/suspicious-outbound without events when
    LogAnalyticsClient has no AzureNetworkAnalytics_CL table.
    Should report dependency rather than faking.
    """
    resp = client.post("/detect/suspicious-outbound", json={})
    # Since client fixture uses log_client=None, it should return 503
    assert resp.status_code == 503
    data = resp.get_json()
    assert data["status"] == "error"
