"""
Adversarial Detection Test Suite (Scenarios 1-7)
Tests hostiles edge-cases in rule shadowing, perimeter reachability, evasion prefixes,
effective multi-tier NSG evaluation, port coverage gaps, 90-day cost z-score, and telemetry blindness.
"""

import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
import pytest

from models.finding import Finding, SeverityLevel
from detectors.unexpected_public_exposure import UnexpectedPublicExposureDetector
from telemetry.cost_baseline import InMemoryCostBaselineStore, CostRecord, CostObservation
from detectors.cost_anomaly import CostAnomalyDetector
from app import create_app
from database.postgres import InMemoryDatabase


def build_base_topology(rules: List[Dict[str, Any]], pip_attached: bool = True, subnet_rules: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    pip_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-1"
    nic_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/nic-1"
    vm_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
    nic_nsg_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-nic"
    snet_nsg_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-snet"
    snet_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/snet-app"

    nsgs = {
        nic_nsg_id.lower(): {
            "id": nic_nsg_id,
            "name": "nsg-nic",
            "resource_group": "rg-1",
            "rules": rules,
        }
    }
    subnets = {
        snet_id.lower(): {
            "id": snet_id,
            "name": "snet-app",
            "resource_group": "rg-1",
            "nsg_id": snet_nsg_id if subnet_rules is not None else None,
        }
    }
    if subnet_rules is not None:
        nsgs[snet_nsg_id.lower()] = {
            "id": snet_nsg_id,
            "name": "nsg-snet",
            "resource_group": "rg-1",
            "rules": subnet_rules,
        }

    public_ips = {}
    if pip_attached:
        public_ips[pip_id.lower()] = {
            "id": pip_id,
            "name": "pip-1",
            "ip_address": "20.50.100.1",
            "ip_configuration_id": f"{nic_id}/ipConfigurations/ipconfig1",
        }

    return {
        "public_ips": public_ips,
        "nics": {
            nic_id.lower(): {
                "id": nic_id,
                "name": "nic-1",
                "vm_id": vm_id,
                "nsg_id": nic_nsg_id,
                "ip_configurations": [
                    {
                        "id": f"{nic_id}/ipConfigurations/ipconfig1",
                        "subnet_id": snet_id,
                        "private_ip": "10.0.1.4",
                    }
                ],
            }
        },
        "vms": {
            vm_id.lower(): {
                "id": vm_id,
                "name": "vm-1",
                "resource_group": "rg-1",
            }
        },
        "nsgs": nsgs,
        "subnets": subnets,
    }


class TestAdversarialDetection:

    def test_scenario_1_shadowed_rule_must_not_alert(self):
        """
        Scenario 1: Allow 22 from 0.0.0.0/0 at priority 400 shadowed by Deny 22 at priority 300.
        Requirement: Must NOT alert because lower-numbered rule (300 Deny) takes precedence in Azure.
        """
        rules = [
            {
                "name": "Deny-SSH-HigherPriority",
                "properties": {
                    "priority": 300,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
            },
            {
                "name": "Allow-SSH-Shadowed",
                "properties": {
                    "priority": 400,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "22",
                },
            },
        ]
        topology = build_base_topology(rules=rules)
        detector = UnexpectedPublicExposureDetector()
        findings = detector.detect(topology=topology)

        # Adversarial assertion: It MUST NOT alert on shadowed rules.
        # Flaw confirmation: If findings > 0, detector ignores rule priority and alerts on shadowed Allow rule.
        assert len(findings) == 0, (
            f"DETECTION BUG CONFIRMED: Shadowed Allow rule at priority 400 was alerted despite Deny rule at priority 300. "
            f"Findings generated: {len(findings)}"
        )

    def test_scenario_2_nsg_open_without_public_ip_must_not_be_critical(self):
        """
        Scenario 2: NSG open to Internet but no public IP attached → must NOT be Critical.
        """
        rules = [
            {
                "name": "Allow-All-Inbound",
                "properties": {
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
            }
        ]
        # PIP not attached
        topology = build_base_topology(rules=rules, pip_attached=False)
        detector = UnexpectedPublicExposureDetector()
        findings = detector.detect(topology=topology)

        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical_findings) == 0, "No public IP is attached; must NOT alert as Critical"

    def test_scenario_3_evasion_prefixes_and_tags(self):
        """
        Scenario 3: Evasions:
        - 0.0.0.0/1 + 128.0.0.0/1
        - "Internet" / "AzureCloud" tags
        - ::/0
        - multiple source prefixes
        - port ranges (20-25, 1-65535)
        - '*' ports
        - ASG sources
        Requirement: Must all be detected as public source.
        """
        detector = UnexpectedPublicExposureDetector()

        results = {
            "0.0.0.0/1": detector.is_public_source("0.0.0.0/1"),
            "128.0.0.0/1": detector.is_public_source("128.0.0.0/1"),
            "Internet": detector.is_public_source("Internet"),
            "::/0": detector.is_public_source("::/0"),
            "multiple_prefixes": detector.is_public_source(["10.0.0.0/8", "0.0.0.0/0"]),
            "AzureCloud": detector.is_public_source("AzureCloud"),
            "ASG_source": detector.is_public_source("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/applicationSecurityGroups/asg-web"),
        }

        port_res_20_25 = detector.analyze_port_exposure("20-25")
        port_res_all = detector.analyze_port_exposure("1-65535")
        port_res_star = detector.analyze_port_exposure("*")

        # Report exact coverage
        evasions_succeeded = [k for k, detected in results.items() if not detected]
        assert "AzureCloud" in evasions_succeeded, "Expected AzureCloud to evade is_public_source"
        assert "ASG_source" in evasions_succeeded, "Expected ASG_source to evade is_public_source"

        assert port_res_20_25[0] == SeverityLevel.CRITICAL  # Covers port 22
        assert port_res_all[0] == SeverityLevel.CRITICAL    # Covers 22/3389
        assert port_res_star[0] == SeverityLevel.HIGH       # Wildcard

        assert len(evasions_succeeded) == 0, (
            f"EVASION DETECTION FAILED: Following sources bypassed public classification: {evasions_succeeded}"
        )

    def test_scenario_4_combined_subnet_and_nic_nsg_evaluation(self):
        """
        Scenario 4: Subnet NSG has Deny 22, NIC NSG has Allow 22.
        In Azure, inbound traffic hits Subnet NSG first; packet is dropped.
        Requirement: Detector must evaluate effective combined path and NOT alert.
        """
        subnet_rules = [
            {
                "name": "Subnet-Deny-SSH",
                "properties": {
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                },
            }
        ]
        nic_rules = [
            {
                "name": "NIC-Allow-SSH",
                "properties": {
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationPortRange": "22",
                },
            }
        ]
        topology = build_base_topology(rules=nic_rules, subnet_rules=subnet_rules)
        detector = UnexpectedPublicExposureDetector()
        findings = detector.detect(topology=topology)

        # If it inspects NIC independently, it fires a false positive
        assert len(findings) == 0, (
            f"EFFECTIVE RULE EVALUATION BUG: Subnet NSG drops traffic, but detector evaluated NIC NSG in isolation "
            f"and generated {len(findings)} false positive alert(s)."
        )

    def test_scenario_5_port_coverage_gaps(self):
        """
        Scenario 5: Ports beyond standard management:
        23, 445, 5985, 6379, 9200, 27017, 2375, 10250.
        Report coverage gaps (ports categorized as MEDIUM UNPROTECTED_SERVICE instead of CRITICAL).
        """
        detector = UnexpectedPublicExposureDetector()
        test_ports = [23, 445, 5985, 6379, 9200, 27017, 2375, 10250]
        critical_ports = []
        medium_ports = []

        for p in test_ports:
            res = detector.analyze_port_exposure(str(p))
            if res and res[0] == SeverityLevel.CRITICAL:
                critical_ports.append(p)
            else:
                medium_ports.append(p)

        # 445 (SMB), 2375 (Docker daemon), 10250 (Kubelet API) are severe wormable/RCE ports
        # but CloudPulse treats them as MEDIUM UNPROTECTED_SERVICE
        assert 445 in medium_ports, "Port 445 expected to fall through to MEDIUM"
        assert 2375 in medium_ports, "Port 2375 expected to fall through to MEDIUM"
        assert 10250 in medium_ports, "Port 10250 expected to fall through to MEDIUM"

        # The test asserts comprehensive critical coverage
        assert len(medium_ports) == 0, (
            f"PORT COVERAGE GAP: High-risk administrative/container daemon ports misclassified as MEDIUM: {medium_ports}"
        )

    def test_scenario_6_cost_zscore_90_day_benign_and_slow_ramp(self):
        """
        Scenario 6:
        Part A: Feed 90 days of benign synthetic data (weekend dips $15 vs weekday $100, month-end spike $220).
                Measure and report false-positive rate.
        Part B: Feed a slow ramp attack (+15%/day for 14 days). Check if caught or suppressed.
        """
        base_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records: List[CostRecord] = []
        res_id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-cost"

        # Generate 90 days of benign records
        for day in range(90):
            d = base_date + timedelta(days=day)
            d_str = d.strftime("%Y-%m-%d")
            # Weekend dip: Saturday (5), Sunday (6)
            weekday = d.weekday()
            if weekday in (5, 6):
                cost = 15.0
            elif d.day in (28, 29, 30):  # Month-end batch job
                cost = 220.0
            else:
                cost = 100.0

            records.append(
                CostRecord(
                    record_id=f"CR-{day:04d}",
                    subscription_id="sub-1",
                    resource_id=res_id,
                    resource_name="vm-cost",
                    resource_type="Microsoft.Compute/virtualMachines",
                    resource_group="rg-1",
                    service_name="Virtual Machines",
                    meter_category="Compute",
                    meter_name="Standard D2s v3",
                    cost_category="Compute",
                    actual_cost=cost,
                    timestamp=d_str,
                )
            )

        detector = CostAnomalyDetector()
        benign_alerts = 0
        eval_days_count = 0

        # Evaluate days 14 through 89
        for day in range(14, 90):
            eval_date = (base_date + timedelta(days=day)).strftime("%Y-%m-%d")
            eval_days_count += 1
            # Filter historical records up to eval_date
            subset = [r for r in records if r.timestamp <= eval_date]
            obs_list = InMemoryCostBaselineStore.calculate_observations_from_records(
                records=subset,
                evaluation_date=eval_date,
            )
            for obs in obs_list:
                finding = detector.evaluate_observation(obs)
                if finding is not None:
                    benign_alerts += 1

        fp_rate = (benign_alerts / eval_days_count) * 100.0

        # Part B: Slow ramp attack (+15%/day)
        ramp_records: List[CostRecord] = []
        cur_cost = 50.0
        ramp_alerts = 0
        for day in range(14):
            d = base_date + timedelta(days=day)
            d_str = d.strftime("%Y-%m-%d")
            ramp_records.append(
                CostRecord(
                    record_id=f"CR-RAMP-{day:04d}",
                    subscription_id="sub-1",
                    resource_id=res_id,
                    resource_name="vm-cost",
                    resource_type="Microsoft.Compute/virtualMachines",
                    resource_group="rg-1",
                    service_name="Virtual Machines",
                    meter_category="Compute",
                    meter_name="Standard D2s v3",
                    cost_category="Compute",
                    actual_cost=round(cur_cost, 2),
                    timestamp=d_str,
                )
            )
            if day >= 7:
                obs_list = InMemoryCostBaselineStore.calculate_observations_from_records(
                    records=ramp_records,
                    evaluation_date=d_str,
                )
                for obs in obs_list:
                    finding = detector.evaluate_observation(obs)
                    if finding is not None:
                        ramp_alerts += 1
            cur_cost *= 1.15

        # Assertions
        assert ramp_alerts > 0, "Slow ramp attack (+15%/day) completely evaded detection due to rolling baseline inflation"
        assert fp_rate < 5.0, f"False-positive rate too high on benign data: {fp_rate:.1f}% ({benign_alerts}/{eval_days_count} days alerted)"

    def test_scenario_7_empty_telemetry_must_report_blind_not_healthy(self):
        """
        Scenario 7: Missing/empty/late telemetry (empty ARG, empty logs, 429s).
        Requirement: System must report 'blind' or 'degraded', NEVER 'healthy'.
        """
        app = create_app(db_repo=InMemoryDatabase())
        client = app.test_client()

        # Telemetry is empty (no ARG, no logs)
        resp = client.get("/health")
        data = resp.get_json()

        assert data["status"] != "healthy", (
            f"HEALTH BLINDNESS BUG: /health reported status '{data['status']}' despite empty telemetry and zero ingestion feeds."
        )
