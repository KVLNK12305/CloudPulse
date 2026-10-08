import hashlib
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import urllib.error

from config import config
from models.cost_record import (
    CostRecord,
    CostObservation,
    generate_cost_record_id,
    classify_cost_category,
    parse_usage_date,
    extract_arm_metadata,
)
from telemetry.cost_management import (
    CostManagementClient,
    CostManagementQueryError,
    CostManagementAuthenticationError,
    CostManagementRbacError,
    CostManagementRateLimitError,
    CostManagementBadRequestError,
    CostManagementNotFoundError,
)
from telemetry.cost_baseline import (
    CostBaselineStore,
    InMemoryCostBaselineStore,
)
from app import create_app
from database.postgres import InMemoryDatabase


# ---------------------------------------------------------------------------
# 1. Deterministic Cost Record ID & Identity Formula Tests (Section 12.A)
# ---------------------------------------------------------------------------

def test_deterministic_record_id_formula():
    sub_id = "90b900ea-4273-4b40-a343-091aecfe2911"
    res_id = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01"
    meter_name = "B2s vCPU"
    usage_date = "2026-10-07"
    cost_type = "ActualCost"

    seed = f"{sub_id.lower()}:{res_id.lower()}:{meter_name.lower()}:{usage_date}:{cost_type.lower()}"
    expected_digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    expected_id = f"CR-{expected_digest}"

    rec_id = generate_cost_record_id(sub_id, res_id, meter_name, usage_date, cost_type)
    assert rec_id == expected_id
    assert rec_id.startswith("CR-")
    assert len(rec_id) == 19  # "CR-" (3) + 16 chars = 19


def test_deterministic_record_id_case_insensitivity():
    id1 = generate_cost_record_id(
        "SUB-123",
        "/SUBSCRIPTIONS/SUB-123/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1",
        "STANDARD D2S V3",
        "2026-10-07",
        "ActualCost",
    )
    id2 = generate_cost_record_id(
        "sub-123",
        "/subscriptions/sub-123/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1",
        "standard d2s v3",
        "2026-10-07",
        "actualcost",
    )
    assert id1 == id2


# ---------------------------------------------------------------------------
# 2. Deterministic Cost Categorization Tests (Section 5)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("meter_cat,svc_name,expected_cat", [
    ("Bandwidth", "Unknown", "Network/Egress"),
    ("Data Transfer Out", "Networking", "Network/Egress"),
    ("Virtual Network", "Virtual Network", "Network/Egress"),
    ("Networking", "NAT Gateway", "Network/Egress"),
    ("General", "VPN Gateway", "Network/Egress"),
    ("General", "ExpressRoute", "Network/Egress"),
    ("IP", "Public IP Addresses", "Network/Egress"),
])
def test_category_network_egress(meter_cat, svc_name, expected_cat):
    cat = classify_cost_category("Microsoft.Network/networkInterfaces", svc_name, meter_cat)
    assert cat == expected_cat


@pytest.mark.parametrize("res_type,svc_name", [
    ("Microsoft.Compute/virtualMachines", "Virtual Machines"),
    ("Microsoft.Web/serverfarms", "Azure App Service"),
    ("Microsoft.Resources/resource", "Cloud Services"),
    ("Microsoft.Batch/batchAccounts", "Batch"),
])
def test_category_compute(res_type, svc_name):
    cat = classify_cost_category(res_type, svc_name, "Standard")
    assert cat == "Compute"


@pytest.mark.parametrize("res_type,svc_name", [
    ("Microsoft.DBforPostgreSQL/flexibleServers", "Azure Database for PostgreSQL Flexible Server"),
    ("Microsoft.Sql/servers/databases", "SQL Database"),
    ("Microsoft.DBforMySQL/flexibleServers", "Azure Database for MySQL"),
    ("Microsoft.DocumentDB/databaseAccounts", "Azure Cosmos DB"),
])
def test_category_database(res_type, svc_name):
    cat = classify_cost_category(res_type, svc_name, "General")
    assert cat == "Database"


@pytest.mark.parametrize("res_type,svc_name", [
    ("Microsoft.ContainerService/managedClusters", "Azure Kubernetes Service"),
    ("Microsoft.App/containerApps", "Container Apps"),
    ("Microsoft.ContainerRegistry/registries", "Container Registry"),
])
def test_category_container(res_type, svc_name):
    cat = classify_cost_category(res_type, svc_name, "Standard")
    assert cat == "Container"


@pytest.mark.parametrize("res_type,meter_cat,svc_name", [
    ("Microsoft.Storage/storageAccounts", "Standard Storage", "Storage"),
    ("Microsoft.Compute/disks", "Managed Disks", "Storage"),
    ("Microsoft.Resources/resource", "Disks", "Managed Disks"),
])
def test_category_storage(res_type, meter_cat, svc_name):
    cat = classify_cost_category(res_type, svc_name, meter_cat)
    assert cat == "Storage"


def test_category_other_fallback():
    cat = classify_cost_category(
        "Microsoft.KeyVault/vaults",
        "Key Vault",
        "Security",
    )
    assert cat == "Other"


# ---------------------------------------------------------------------------
# 3. Usage Date & ARM Path Normalization Tests (Section 4.C & 13.B)
# ---------------------------------------------------------------------------

def test_parse_usage_date():
    assert parse_usage_date(20261007) == "2026-10-07"
    assert parse_usage_date("20261007") == "2026-10-07"
    assert parse_usage_date("2026-10-07T00:00:00Z") == "2026-10-07"
    assert parse_usage_date("2026-10-07") == "2026-10-07"


def test_extract_arm_metadata_regular_resource():
    arm_id = "/subscriptions/sub-99/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-app-01"
    canon_id, name, res_type, rg, sub = extract_arm_metadata(arm_id)
    assert canon_id == arm_id.lower()
    assert name == "vm-app-01"
    assert res_type == "Microsoft.Compute/virtualMachines"
    assert rg == "rg-test"
    assert sub == "sub-99"


def test_extract_arm_metadata_unallocated():
    canon_id, name, res_type, rg, sub = extract_arm_metadata(None, default_sub_id="sub-default")
    assert canon_id == "/subscriptions/sub-default/resourcegroups/unallocated"
    assert name == "unallocated"
    assert res_type == "Microsoft.Resources/unallocated"
    assert rg == "unallocated"
    assert sub == "sub-default"


# ---------------------------------------------------------------------------
# 4. Raw Response Normalization Tests (Section 4.A & 4.C)
# ---------------------------------------------------------------------------

def test_normalize_query_response():
    client = CostManagementClient(credential=MagicMock())
    raw_response = {
        "properties": {
            "columns": [
                {"name": "PreTaxCost", "type": "Number"},
                {"name": "UsageDate", "type": "Number"},
                {"name": "ResourceId", "type": "String"},
                {"name": "ResourceGroupName", "type": "String"},
                {"name": "ServiceName", "type": "String"},
                {"name": "MeterCategory", "type": "String"},
                {"name": "MeterSubCategory", "type": "String"},
                {"name": "MeterName", "type": "String"},
                {"name": "UsageQuantity", "type": "Number"},
                {"name": "UnitOfMeasure", "type": "String"},
                {"name": "Currency", "type": "String"},
            ],
            "rows": [
                [
                    48.50,
                    20261007,
                    "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-worker-01",
                    "cloudpulse-rg",
                    "Bandwidth",
                    "Data Transfer Out",
                    "Data Transfer Out - Internet",
                    "Data Transfer Out - Internet",
                    1500.0,
                    "GB",
                    "USD",
                ],
                [
                    12.30,
                    20261007,
                    None,  # unallocated
                    "cloudpulse-rg",
                    "Log Analytics",
                    "Log Analytics",
                    "Ingestion",
                    "Standard Ingestion",
                    5.0,
                    "GB",
                    "USD",
                ],
            ],
        }
    }

    records = client.normalize_query_response(raw_response, default_sub_id="90b900ea-4273-4b40-a343-091aecfe2911")
    assert len(records) == 2

    # Record 1: Egress on VM
    r1 = records[0]
    assert r1.actual_cost == 48.50
    assert r1.timestamp == "2026-10-07"
    assert r1.resource_name == "vm-worker-01"
    assert r1.cost_category == "Network/Egress"
    assert r1.usage_quantity == 1500.0
    assert r1.usage_unit == "GB"
    assert r1.currency == "USD"
    assert r1.record_id.startswith("CR-")

    # Record 2: Unallocated platform cost
    r2 = records[1]
    assert r2.actual_cost == 12.30
    assert r2.resource_name == "unallocated"
    assert r2.cost_category == "Other"
    assert r2.record_id.startswith("CR-")


# ---------------------------------------------------------------------------
# 5. Baseline Engine Statistical Tests (Section 7 & 8)
# ---------------------------------------------------------------------------

def create_sample_cost_record(
    resource_id: str,
    cost_category: str,
    date_str: str,
    cost: float,
    meter: str = "Standard Meter",
) -> CostRecord:
    sub_id = "sub-test-01"
    rec_id = generate_cost_record_id(sub_id, resource_id, meter, date_str)
    return CostRecord(
        record_id=rec_id,
        timestamp=date_str,
        subscription_id=sub_id,
        resource_id=resource_id.lower(),
        resource_group="cloudpulse-rg",
        resource_name=resource_id.split("/")[-1],
        resource_type="Microsoft.Compute/virtualMachines",
        service_name="Virtual Machines",
        cost_category=cost_category,
        meter_category="Virtual Machines",
        meter_name=meter,
        actual_cost=cost,
        currency="USD",
    )


def test_baseline_14_day_statistical_modeling():
    """
    Test 14-day stable baseline calculation:
    Historical days T-14 to T-2: steady $10/day (std dev = 0).
    Evaluation day T-1: $50 (spike of $40, ratio 5.0, +400%).
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-app-01"
    records = []

    # 13 historical baseline days (2026-09-24 to 2026-10-06) at $10.00/day
    for day in range(24, 31):
        d_str = f"2026-09-{day:02d}"
        records.append(create_sample_cost_record(res_id, "Compute", d_str, 10.0))
    for day in range(1, 7):
        d_str = f"2026-10-{day:02d}"
        records.append(create_sample_cost_record(res_id, "Compute", d_str, 10.0))

    # Evaluation day (2026-10-07) spiked to $50.00
    records.append(create_sample_cost_record(res_id, "Compute", "2026-10-07", 50.0))

    store = InMemoryCostBaselineStore(records)
    obs = store.get_observation(res_id, "Compute", evaluation_date="2026-10-07")

    assert obs is not None
    assert obs.evaluation_date == "2026-10-07"
    assert obs.current_cost == 50.0
    assert obs.baseline_cost == 10.0
    assert obs.deviation_absolute == 40.0
    assert obs.deviation_ratio == 5.0
    assert obs.percentage_increase == 400.0
    assert obs.std_dev == 0.0
    assert obs.sample_days == 13
    assert obs.is_cold_start is False
    assert obs.high_volatility is False
    assert obs.confidence == 0.90


def test_baseline_cold_start_guardrail():
    """
    Test cold-start resource with N < 3 days of history:
    Must set is_cold_start = True, baseline = current, ratio = 1.0, confidence = 0.30.
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-new-01"
    records = [
        create_sample_cost_record(res_id, "Compute", "2026-10-06", 15.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-07", 20.0),
    ]

    store = InMemoryCostBaselineStore(records)
    obs = store.get_observation(res_id, "Compute", evaluation_date="2026-10-07")

    assert obs is not None
    assert obs.is_cold_start is True
    assert obs.sample_days == 1  # Only 1 historical day before 2026-10-07
    assert obs.current_cost == 20.0
    assert obs.baseline_cost == 20.0  # Cold-start defaults baseline to current
    assert obs.deviation_absolute == 0.0
    assert obs.percentage_increase == 0.0
    assert obs.confidence == 0.30


def test_baseline_zero_cost_baseline_safeguard():
    """
    Test resource with historical baseline of $0.00:
    Must avoid division by zero and set deviation_ratio = 0.0.
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/publicipaddresses/pip-01"
    records = [
        create_sample_cost_record(res_id, "Network/Egress", "2026-10-04", 0.0),
        create_sample_cost_record(res_id, "Network/Egress", "2026-10-05", 0.0),
        create_sample_cost_record(res_id, "Network/Egress", "2026-10-06", 0.0),
        create_sample_cost_record(res_id, "Network/Egress", "2026-10-07", 12.0),
    ]

    store = InMemoryCostBaselineStore(records)
    obs = store.get_observation(res_id, "Network/Egress", evaluation_date="2026-10-07")

    assert obs is not None
    assert obs.is_cold_start is False
    assert obs.baseline_cost == 0.0
    assert obs.current_cost == 12.0
    assert obs.deviation_absolute == 12.0
    assert obs.deviation_ratio == 0.0
    assert obs.percentage_increase == 0.0


def test_baseline_high_volatility_flag():
    """
    Test volatile workload with CV = std_dev / mean > 0.50.
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.batch/batchaccounts/batch-01"
    # Historical costs with extreme variance: [2.0, 50.0, 1.0, 45.0]
    records = [
        create_sample_cost_record(res_id, "Compute", "2026-10-03", 2.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-04", 50.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-05", 1.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-06", 45.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-07", 25.0),
    ]

    store = InMemoryCostBaselineStore(records)
    obs = store.get_observation(res_id, "Compute", evaluation_date="2026-10-07")

    assert obs is not None
    assert obs.is_cold_start is False
    assert obs.sample_days == 4
    assert obs.high_volatility is True  # High variance triggers flag


# ---------------------------------------------------------------------------
# 6. Idempotency & In-Memory Upsert Deduplication (Section 12.B)
# ---------------------------------------------------------------------------

def test_idempotent_cost_recording():
    store = InMemoryCostBaselineStore()
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-dedup-01"

    rec1 = create_sample_cost_record(res_id, "Compute", "2026-10-07", 10.0, "Meter A")
    rec2 = create_sample_cost_record(res_id, "Compute", "2026-10-07", 10.0, "Meter A")

    # Same record ID
    assert rec1.record_id == rec2.record_id

    store.record_costs([rec1])
    assert len(store.get_records()) == 1

    # Re-recording identical record does not duplicate
    store.record_costs([rec2])
    assert len(store.get_records()) == 1

    # Updating with reconciled adjusted cost updates in place
    rec_reconciled = create_sample_cost_record(res_id, "Compute", "2026-10-07", 14.50, "Meter A")
    store.record_costs([rec_reconciled])
    assert len(store.get_records()) == 1
    assert store.get_records()[0].actual_cost == 14.50


# ---------------------------------------------------------------------------
# 7. Resilience, Rate-Limiting & Error Handling (Section 13.A)
# ---------------------------------------------------------------------------

def test_rbac_403_non_retryable():
    client = CostManagementClient(credential=MagicMock())

    http_error = urllib.error.HTTPError(
        url="https://management.azure.com/query",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=MagicMock(read=MagicMock(return_value=b'{"error":{"code":"AuthorizationFailed"}}')),
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        with pytest.raises(CostManagementRbacError) as exc_info:
            client.query_cost(scope="/subscriptions/sub-1", query_payload={})
        assert "Cost Management Reader" in str(exc_info.value)


def test_bad_request_400_non_retryable():
    client = CostManagementClient(credential=MagicMock())

    http_error = urllib.error.HTTPError(
        url="https://management.azure.com/query",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=MagicMock(read=MagicMock(return_value=b'{"error":{"code":"InvalidQuerySyntax"}}')),
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        with pytest.raises(CostManagementBadRequestError):
            client.query_cost(scope="/subscriptions/sub-1", query_payload={})


def test_rate_limit_429_retry_success():
    client = CostManagementClient(credential=MagicMock())

    # First call returns 429, second call succeeds
    error_429 = urllib.error.HTTPError(
        url="https://management.azure.com/query",
        code=429,
        msg="Too Many Requests",
        hdrs={"Retry-After": "1"},
        fp=MagicMock(read=MagicMock(return_value=b'{"error":"QuotaExceeded"}')),
    )

    success_resp = MagicMock()
    success_resp.read.return_value = json.dumps({
        "properties": {
            "columns": [{"name": "PreTaxCost"}],
            "rows": [[10.5]],
        }
    }).encode("utf-8")
    success_resp.__enter__.return_value = success_resp
    success_resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", side_effect=[error_429, success_resp]), patch("time.sleep") as mock_sleep:
        resp = client.query_cost(scope="/subscriptions/sub-1", query_payload={})
        assert len(resp["properties"]["rows"]) == 1
        assert mock_sleep.called


def test_pagination_next_link_traversal():
    client = CostManagementClient(credential=MagicMock())

    # Page 1 returns 1 row and nextLink
    page1 = MagicMock()
    page1.read.return_value = json.dumps({
        "properties": {
            "columns": [{"name": "PreTaxCost"}],
            "rows": [[10.0]],
            "nextLink": "https://management.azure.com/query?$skipToken=page2",
        }
    }).encode("utf-8")
    page1.__enter__.return_value = page1
    page1.__exit__.return_value = None

    # Page 2 returns 1 row and no nextLink
    page2 = MagicMock()
    page2.read.return_value = json.dumps({
        "properties": {
            "columns": [{"name": "PreTaxCost"}],
            "rows": [[20.0]],
        }
    }).encode("utf-8")
    page2.__enter__.return_value = page2
    page2.__exit__.return_value = None

    with patch("urllib.request.urlopen", side_effect=[page1, page2]):
        result = client.query_cost(scope="/subscriptions/sub-1", query_payload={})
        assert len(result["properties"]["rows"]) == 2
        assert result["properties"]["rows"][0][0] == 10.0
        assert result["properties"]["rows"][1][0] == 20.0


# ---------------------------------------------------------------------------
# 8. Flask Route Integration Tests (/finops/cost-query, /finops/baseline)
# ---------------------------------------------------------------------------

def test_api_finops_cost_query_replay():
    db = InMemoryDatabase()
    cost_store = InMemoryCostBaselineStore()
    app = create_app(db_repo=db, cost_store=cost_store)
    client = app.test_client()

    # Replay with mock raw_response
    raw_response = {
        "properties": {
            "columns": [
                {"name": "PreTaxCost", "type": "Number"},
                {"name": "UsageDate", "type": "Number"},
                {"name": "ResourceId", "type": "String"},
                {"name": "ResourceGroupName", "type": "String"},
                {"name": "ServiceName", "type": "String"},
                {"name": "MeterCategory", "type": "String"},
                {"name": "MeterName", "type": "String"},
            ],
            "rows": [
                [
                    25.0,
                    20261005,
                    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1",
                    "rg",
                    "Virtual Machines",
                    "Compute",
                    "D2s v3",
                ],
                [
                    25.0,
                    20261006,
                    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1",
                    "rg",
                    "Virtual Machines",
                    "Compute",
                    "D2s v3",
                ],
                [
                    25.0,
                    20261007,
                    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1",
                    "rg",
                    "Virtual Machines",
                    "Compute",
                    "D2s v3",
                ],
                [
                    80.0,
                    20261008,
                    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1",
                    "rg",
                    "Virtual Machines",
                    "Compute",
                    "D2s v3",
                ],
            ],
        }
    }

    resp = client.post(
        "/finops/cost-query",
        json={"raw_response": raw_response, "evaluation_date": "2026-10-08"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["records_ingested"] == 4
    assert data["unique_workloads"] == 1
    assert data["observations_generated"] == 1

    obs = data["observations"][0]
    assert obs["current_cost"] == 80.0
    assert obs["baseline_cost"] == 25.0
    assert obs["deviation_absolute"] == 55.0
    assert obs["deviation_ratio"] == 3.2
    assert obs["sample_days"] == 3
    assert obs["is_cold_start"] is False

    # Check /finops/baseline GET endpoint
    bl_resp = client.get("/finops/baseline?evaluation_date=2026-10-08")
    assert bl_resp.status_code == 200
    bl_data = bl_resp.get_json()
    assert bl_data["count"] == 1


def test_validate_rbac_behavior():
    client = CostManagementClient(credential=MagicMock())

    # Success case
    with patch.object(client, "query_cost", return_value={"properties": {"columns": [], "rows": []}}):
        assert client.validate_rbac("/subscriptions/sub-1") is True

    # 403 case
    with patch.object(client, "query_cost", side_effect=CostManagementRbacError("403")):
        assert client.validate_rbac("/subscriptions/sub-1") is False


def test_negative_cost_clamping_in_baseline():
    """
    Azure credits or negative billing records should be clamped to 0.0
    for statistical variance calculations per Section 13.B.2.
    """
    res_id = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-refund-01"
    records = [
        create_sample_cost_record(res_id, "Compute", "2026-10-04", -15.0),  # credit/refund
        create_sample_cost_record(res_id, "Compute", "2026-10-05", 10.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-06", 10.0),
        create_sample_cost_record(res_id, "Compute", "2026-10-07", 20.0),
    ]

    store = InMemoryCostBaselineStore(records)
    obs = store.get_observation(res_id, "Compute", evaluation_date="2026-10-07")

    assert obs is not None
    # 2026-10-04 clamped to 0.0, so costs are [0.0, 10.0, 10.0] -> mean = 20.0 / 3 = 6.6667
    assert obs.baseline_cost == pytest.approx(6.6667, rel=1e-3)
    assert obs.current_cost == 20.0
    assert obs.is_cold_start is False


def test_api_finops_rbac_check_endpoint():
    db = InMemoryDatabase()
    mock_cost_client = MagicMock(spec=CostManagementClient)
    mock_cost_client.validate_rbac.return_value = True

    app = create_app(db_repo=db, cost_client=mock_cost_client)
    client = app.test_client()

    resp = client.get("/finops/rbac-check?scope=/subscriptions/sub-1")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["rbac_valid"] is True
    assert data["required_role"] == "Cost Management Reader"

    # Now test when RBAC fails (returns False -> HTTP 403)
    mock_cost_client.validate_rbac.return_value = False
    resp_fail = client.get("/finops/rbac-check?scope=/subscriptions/sub-1")
    assert resp_fail.status_code == 403
    data_fail = resp_fail.get_json()
    assert data_fail["rbac_valid"] is False
