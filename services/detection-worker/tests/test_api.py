import pytest
import json


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["service"] == "cloudpulse-detection-worker"
    assert data["status"] == "healthy"
    assert data["detector"] == "RESOURCE_CREATION"


def test_home_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert "CloudPulse" in data["message"]


def test_detect_endpoint_with_mocked_telemetry(client, vm_creation_event, public_ip_creation_event):
    payload = {
        "lookback_minutes": 30,
        "events": [vm_creation_event, public_ip_creation_event],
    }

    response = client.post(
        "/detect/resource-creation",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["events_analyzed"] == 2
    assert data["findings_detected"] == 2
    assert data["new_findings_persisted"] == 2
    assert data["incidents_created_or_updated"] == 2

    # Check that findings list contains expected items conforming to contract
    findings = data["findings"]
    assert len(findings) == 2
    assert any(f["resource"]["type"] == "Microsoft.Compute/virtualMachines" for f in findings)
    assert any(f["resource"]["type"] == "Microsoft.Network/publicIPAddresses" for f in findings)

    # Check incidents
    incidents = data["incidents"]
    assert len(incidents) == 2


def test_detect_endpoint_deduplication(client, vm_creation_event):
    payload = {"events": [vm_creation_event]}

    # First run
    res1 = client.post("/detect/resource-creation", json=payload)
    assert res1.status_code == 200
    d1 = res1.get_json()
    assert d1["new_findings_persisted"] == 1

    # Second run with identical event
    res2 = client.post("/detect/resource-creation", json=payload)
    assert res2.status_code == 200
    d2 = res2.get_json()
    assert d2["findings_detected"] == 1
    assert d2["new_findings_persisted"] == 0  # Deduplicated!
    assert d2["incidents_created_or_updated"] == 1  # Updated existing, not duplicated


def test_get_findings_and_incidents(client, vm_creation_event):
    # Post event
    client.post("/detect/resource-creation", json={"events": [vm_creation_event]})

    # Fetch findings list
    res_f = client.get("/findings")
    assert res_f.status_code == 200
    findings_data = res_f.get_json()
    assert findings_data["count"] >= 1
    fid = findings_data["findings"][0]["finding_id"]

    # Fetch specific finding
    res_f_single = client.get(f"/findings/{fid}")
    assert res_f_single.status_code == 200
    assert res_f_single.get_json()["finding_id"] == fid

    # Fetch incidents list
    res_i = client.get("/incidents")
    assert res_i.status_code == 200
    incidents_data = res_i.get_json()
    assert incidents_data["count"] >= 1
    iid = incidents_data["incidents"][0]["incident_id"]

    # Fetch specific incident
    res_i_single = client.get(f"/incidents/{iid}")
    assert res_i_single.status_code == 200
    assert res_i_single.get_json()["incident_id"] == iid


def test_finding_not_found(client):
    res = client.get("/findings/non-existent-id")
    assert res.status_code == 404


def test_incident_not_found(client):
    res = client.get("/incidents/non-existent-id")
    assert res.status_code == 404
