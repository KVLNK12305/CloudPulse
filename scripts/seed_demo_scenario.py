#!/usr/bin/env python3
"""
CloudPulse Real-Life Demo Scenario Seeder
=========================================
This script seeds a high-fidelity, multi-stage cyber-incident into CloudPulse:

Stage 1: Unauthorized Resource Creation (vm-worker-01 provisioned)
Stage 2: Perimeter Misconfiguration (Unexpected Public Exposure: Port 22 SSH to 0.0.0.0/0)
Stage 3: Data Exfiltration (16.5 GB egress to novel external IP 198.51.100.77:443)
Stage 4: FinOps Cost Surge (Network/Egress cost spikes +$181.20 / +1276%)
Stage 5: Advisory AI Triage & 5-Dimension Cross-Correlation

Usage:
    python scripts/seed_demo_scenario.py [--host http://127.0.0.1:8080]
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

def post_json(url: str, data: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    parser = argparse.ArgumentParser(description="Seed CloudPulse Demo Data")
    parser.add_argument("--host", default="http://127.0.0.1:8080", help="Base URL for CloudPulse server")
    args = parser.parse_args()
    base_url = args.host.rstrip("/")

    print("=" * 70)
    print("🚀 CLOUDPULSE DEMO SCENARIO SEEDER: MULTI-STAGE BREACH & FINOPS SURGE")
    print("=" * 70)

    # Check health
    try:
        health = get_json(f"{base_url}/health")
        print(f"✅ CloudPulse Server is Healthy at {base_url} (status: {health.get('status')})")
    except Exception as e:
        print(f"❌ Failed to reach CloudPulse server at {base_url}: {e}")
        print("   Make sure the server is running (e.g., python services/detection-worker/app.py)")
        sys.exit(1)

    sub_id = "90b900ea-4273-4b40-a343-091aecfe2911"
    rg = "cloudpulse-rg"
    victim_res_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
    nic_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/nic-worker-01"
    pip_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/publicIPAddresses/pip-worker-01"
    nsg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/nsg-worker"
    ip_cfg_id = f"{nic_id}/ipConfigurations/ipconfig1"

    now = datetime.now(timezone.utc)

    # Stage 1: Resource Creation
    print("\n[Stage 1/5] Ingesting Initial Access Telemetry: Resource Creation...")
    rc_time = (now - timedelta(hours=4)).isoformat()
    rc_payload = {
        "events": [{
            "TimeGenerated": rc_time,
            "EventDataId": "evt-rc-demo-01",
            "CorrelationId": "corr-demo-01",
            "OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            "ActivityStatusValue": "Success",
            "ActivitySubstatusValue": "Created",
            "_ResourceId": victim_res_id,
            "ResourceGroup": rg,
            "SubscriptionId": sub_id,
            "Caller": "admin@cloudpulse.io",
            "CallerIpAddress": "198.51.100.10",
            "Properties_d": json.dumps({"statusCode": "Created", "activitySubstatusValue": "Created"})
        }]
    }
    rc_res = post_json(f"{base_url}/detect/resource-creation", rc_payload)
    print(f"   -> Resource Creation Finding Generated: {rc_res.get('new_findings_persisted')} new findings")

    # Stage 2: Unexpected Public Exposure
    print("\n[Stage 2/5] Ingesting Perimeter Exposure: Inbound SSH (Port 22) to 0.0.0.0/0...")
    upe_time = (now - timedelta(hours=3)).isoformat()
    upe_payload = {
        "events": [{
            "TimeGenerated": upe_time,
            "EventDataId": "evt-upe-demo-01",
            "OperationNameValue": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
            "ActivityStatusValue": "Success",
            "_ResourceId": nsg_id,
            "ResourceGroup": rg,
            "SubscriptionId": sub_id,
            "Caller": "admin@cloudpulse.io",
            "Properties_d": json.dumps({
                "securityRule": {
                    "access": "Allow",
                    "direction": "Inbound",
                    "protocol": "Tcp",
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "targetResourceId": victim_res_id
                }
            })
        }],
        "topology": {
            "public_ips": {
                pip_id.lower(): {
                    "id": pip_id,
                    "name": "pip-worker-01",
                    "ip_address": "20.198.51.10",
                    "ip_configuration_id": ip_cfg_id,
                    "resource_group": rg,
                    "subscription_id": sub_id
                }
            },
            "nics": {
                nic_id.lower(): {
                    "id": nic_id,
                    "name": "nic-worker-01",
                    "vm_id": victim_res_id,
                    "nsg_id": nsg_id,
                    "ip_configurations": [{
                        "id": ip_cfg_id,
                        "name": "ipconfig1",
                        "public_ip_id": pip_id,
                        "subnet_id": f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/vnet-cloudpulse/subnets/snet-worker"
                    }],
                    "resource_group": rg,
                    "subscription_id": sub_id
                }
            },
            "nsgs": {
                nsg_id.lower(): {
                    "id": nsg_id,
                    "name": "nsg-worker",
                    "resource_group": rg,
                    "subscription_id": sub_id,
                    "rules": [{
                        "name": "Allow-SSH-Internet",
                        "properties": {
                            "access": "Allow",
                            "direction": "Inbound",
                            "protocol": "Tcp",
                            "destinationPortRange": "22",
                            "sourceAddressPrefix": "0.0.0.0/0",
                            "priority": 100
                        }
                    }]
                }
            },
            "vms": {
                victim_res_id.lower(): {
                    "id": victim_res_id,
                    "name": "vm-worker-01",
                    "resourceGroup": rg,
                    "networkInterfaces": [nic_id]
                }
            }
        }
    }
    upe_res = post_json(f"{base_url}/detect/unexpected-public-exposure", upe_payload)
    print(f"   -> Unexpected Public Exposure Finding Generated: {upe_res.get('new_findings_persisted')} new findings")

    # Stage 3: Suspicious Outbound Activity
    print("\n[Stage 3/5] Ingesting Network Flow Telemetry: 16.5 GB Egress Spike to Untrusted IP...")
    soa_time = (now - timedelta(hours=2)).isoformat()
    soa_payload = {
        "events": [{
            "timestamp": soa_time,
            "resource_id": victim_res_id,
            "destination_ip": "198.51.100.77",
            "destination_port": 443,
            "bytes_sent": 16500000000,
            "bytes_received": 24000,
            "flow_direction": "O",
            "flow_status": "A"
        }],
        "baselines": {
            victim_res_id: {
                "mean_hourly_bytes": 50000000,
                "std_hourly_bytes": 10000000,
                "historical_hours": 24,
                "flow_count": 100,
                "known_destination_ips": ["168.63.129.16"]
            }
        }
    }
    soa_res = post_json(f"{base_url}/detect/suspicious-outbound", soa_payload)
    print(f"   -> Suspicious Outbound Findings Generated: {soa_res.get('new_findings_persisted')} new findings")

    # Stage 4: FinOps Cost Anomaly
    print("\n[Stage 4/5] Ingesting FinOps Cost Anomaly: Network/Egress Spike +$181.20 (+1276%)...")
    eval_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    cost_payload = {
        "evaluation_date": eval_date,
        "observations": [{
            "resource_id": victim_res_id,
            "resource_name": "vm-worker-01",
            "resource_group": rg,
            "cost_category": "Network/Egress",
            "evaluation_date": eval_date,
            "current_cost": 195.40,
            "baseline_cost": 14.20,
            "deviation_absolute": 181.20,
            "deviation_ratio": 13.76,
            "percentage_increase": 1276.0,
            "std_dev": 2.1,
            "sample_days": 14,
            "confidence": 0.90,
            "currency": "USD"
        }]
    }
    cost_res = post_json(f"{base_url}/detect/cost-anomaly", cost_payload)
    print(f"   -> Cost Anomaly Findings Generated: {cost_res.get('new_findings_persisted')} new findings")

    # Stage 5: Advisory AI Triage
    print("\n[Stage 5/5] Invoking Advisory AI Triage Engine...")
    incidents_data = get_json(f"{base_url}/api/incidents")
    incidents = incidents_data.get("incidents", [])
    if not incidents:
        print("❌ No incident found after seeding!")
        sys.exit(1)

    target_inc = incidents[0]
    inc_id = target_inc["incident_id"]

    triage_res = post_json(f"{base_url}/api/incidents/{inc_id}/ai-triage", {"force_refresh": True})
    ai_analysis = triage_res.get("ai_analysis", {})

    print("\n" + "=" * 70)
    print("🎯 REAL-LIFE DEMO DATA SEEDING COMPLETE!")
    print("=" * 70)
    print(f"Incident ID        : {inc_id}")
    print(f"Target Workload    : {target_inc.get('resource', {}).get('name')}")
    print(f"Severity           : {target_inc.get('severity')}")
    print(f"Correlated Findings: {len(target_inc.get('findings', []))} findings across SecOps & FinOps:")
    for fid in target_inc.get('findings', []):
        print(f"   • {fid}")
    print(f"\nAI Summary         : {ai_analysis.get('summary')}")
    print(f"Risk Assessment    : {ai_analysis.get('risk_assessment')}")
    print(f"\nAdvisory Actions   :")
    for act in ai_analysis.get("recommended_actions", []):
        approval_str = "Required" if act.get("requires_human_approval") else "Auto"
        print(f"   [{act.get('id')}] {act.get('title')} ({act.get('category')}, Risk: {act.get('risk')}, Human Approval: {approval_str})")

    print(f"\n🌐 Web UI Dashboard : {base_url}/dashboard")
    print("=" * 70)

if __name__ == "__main__":
    main()
