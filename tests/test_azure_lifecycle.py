import json
import os
import re
import subprocess
import tempfile
import pytest

SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
COMMON_SCRIPT = os.path.join(SCRIPT_DIR, "lib", "cloudpulse-common.sh")
STATUS_SCRIPT = os.path.join(SCRIPT_DIR, "cloudpulse-status.sh")
OFF_SCRIPT = os.path.join(SCRIPT_DIR, "cloudpulse-off.sh")
ON_SCRIPT = os.path.join(SCRIPT_DIR, "cloudpulse-on.sh")

MOCK_AZ_TEMPLATE = r"""#!/usr/bin/env bash
set -e
STATE_FILE="${MOCK_STATE_FILE}"

# Read current mock state (case-insensitive string representation)
get_state() {
    python3 -c "import json, sys; d=json.load(open('$STATE_FILE')); val=d.get(sys.argv[1], ''); print(str(val).lower() if isinstance(val, bool) else str(val))" "$1"
}

cmd="$*"

# Record any mutating operations
if [[ "$cmd" =~ "update" || "$cmd" =~ "stop" || "$cmd" =~ "start" || "$cmd" =~ "delete" || "$cmd" =~ "destroy" ]]; then
    python3 -c "import json; d=json.load(open('$STATE_FILE')); d.setdefault('mutations', []).append('$cmd'); json.dump(d, open('$STATE_FILE', 'w'))"
fi

# Simulate command failure if configured
fail_match=$(get_state "fail_command")
if [[ -n "$fail_match" && "$cmd" =~ $fail_match ]]; then
    echo "Simulated Azure CLI error for command: $cmd" >&2
    exit 1
fi

if [[ "$cmd" =~ "account show" ]]; then
    sub_id=$(get_state "sub_id")
    if [[ -z "$sub_id" ]]; then sub_id="90b900ea-4273-4b40-a343-091aecfe2911"; fi
    if [[ "$cmd" =~ "--query id" ]]; then
        echo "$sub_id"
    elif [[ "$cmd" =~ "--query name" ]]; then
        echo "Azure for Students"
    else
        cat <<EOF
{
  "id": "$sub_id",
  "name": "Azure for Students",
  "state": "Enabled"
}
EOF
    fi
    exit 0
fi

if [[ "$cmd" =~ "group show" ]]; then
    cat <<EOF
{
  "id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg",
  "name": "cloudpulse-rg",
  "location": "centralindia"
}
EOF
    exit 0
fi

if [[ "$cmd" =~ "identity show" ]]; then
    cat <<EOF
{
  "id": "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/cloudpulse-identity",
  "name": "cloudpulse-identity"
}
EOF
    exit 0
fi

if [[ "$cmd" =~ "postgres flexible-server show" ]]; then
    pg_state=$(get_state "pg_state")
    if [[ -z "$pg_state" ]]; then pg_state="Stopped"; fi
    if [[ "$cmd" =~ "--query state" ]]; then
        echo "$pg_state"
    else
        cat <<EOF
{
  "state": "$pg_state",
  "fqdn": "cloudpulse-postgres01.postgres.database.azure.com",
  "sku": "Standard_B1ms",
  "version": "16"
}
EOF
    fi
    exit 0
fi

if [[ "$cmd" =~ "postgres flexible-server stop" ]]; then
    python3 -c "import json; d=json.load(open('$STATE_FILE')); d['pg_state']='Stopped'; json.dump(d, open('$STATE_FILE', 'w'))"
    echo '{"status": "Stopped"}'
    exit 0
fi

if [[ "$cmd" =~ "postgres flexible-server start" ]]; then
    pg_timeout=$(get_state "pg_timeout")
    if [[ "$pg_timeout" != "true" ]]; then
        python3 -c "import json; d=json.load(open('$STATE_FILE')); d['pg_state']='Ready'; json.dump(d, open('$STATE_FILE', 'w'))"
    else
        python3 -c "import json; d=json.load(open('$STATE_FILE')); d['pg_state']='Starting'; json.dump(d, open('$STATE_FILE', 'w'))"
    fi
    echo '{"status": "Starting"}'
    exit 0
fi

if [[ "$cmd" =~ "postgres flexible-server db show" ]]; then
    cat <<EOF
{
  "name": "cloudpulse",
  "charset": "UTF8"
}
EOF
    exit 0
fi

if [[ "$cmd" =~ "containerapp show" ]]; then
    ca_min=$(get_state "ca_min")
    ca_max=$(get_state "ca_max")
    ca_prov=$(get_state "ca_provisioning")
    if [[ -z "$ca_min" ]]; then ca_min=0; fi
    if [[ -z "$ca_max" ]]; then ca_max=1; fi
    if [[ -z "$ca_prov" ]]; then ca_prov="Succeeded"; fi
    cat <<EOF
{
  "provisioningState": "$ca_prov",
  "runningStatus": "Running",
  "fqdn": "cloudpulse-detection-worker.mock.centralindia.azurecontainerapps.io",
  "minReplicas": $ca_min,
  "maxReplicas": $ca_max,
  "latestRevisionName": "cloudpulse-detection-worker--0000004",
  "latestReadyRevisionName": "cloudpulse-detection-worker--0000004",
  "workloadProfileName": "Consumption",
  "environmentId": "/subscriptions/mock/resourceGroups/cloudpulse-rg/providers/Microsoft.App/managedEnvironments/cloudpulse-env"
}
EOF
    exit 0
fi

if [[ "$cmd" =~ "containerapp update" ]]; then
    new_min=$(get_state "ca_min")
    new_max=$(get_state "ca_max")
    if [[ -z "$new_min" ]]; then new_min=0; fi
    if [[ -z "$new_max" ]]; then new_max=1; fi
    if [[ "$cmd" =~ --min-replicas\ ([0-9]+) ]]; then
        new_min="${BASH_REMATCH[1]}"
    fi
    if [[ "$cmd" =~ --max-replicas\ ([0-9]+) ]]; then
        new_max="${BASH_REMATCH[1]}"
        if [[ "$new_max" -eq 0 ]]; then
            echo "ERROR: --max-replicas must be in the range [1,1000]" >&2
            exit 2
        fi
    fi
    python3 -c "import json; d=json.load(open('$STATE_FILE')); d['ca_min']=$new_min; d['ca_max']=$new_max; json.dump(d, open('$STATE_FILE', 'w'))"
    exit 0
fi

if [[ "$cmd" =~ "containerapp replica list" ]]; then
    rep_err=$(get_state "replica_list_error")
    if [[ "$rep_err" == "true" ]]; then
        echo "Simulated az containerapp replica list API failure" >&2
        exit 1
    fi
    python3 -c "import json; d=json.load(open('$STATE_FILE')); print(json.dumps(d.get('replicas', [])))"
    exit 0
fi

if [[ "$cmd" =~ "containerapp revision show" ]]; then
    rev_running=$(get_state "rev_running_state")
    if [[ -z "$rev_running" ]]; then rev_running="ScaledToZero"; fi
    cat <<EOF
{
  "active": true,
  "provisioningState": "Provisioned",
  "runningState": "$rev_running",
  "replicas": 0,
  "healthState": "Healthy"
}
EOF
    exit 0
fi

exit 0
"""

MOCK_CURL_TEMPLATE = r"""#!/usr/bin/env bash
STATE_FILE="${MOCK_STATE_FILE}"

cmd="$*"
if [[ "$cmd" =~ "/health" ]]; then
    act_timeout=$(python3 -c "import json, sys; d=json.load(open('$STATE_FILE')); val=d.get('activation_timeout', False); print(str(val).lower() if isinstance(val, bool) else str(val))")
    if [[ "$act_timeout" == "true" ]]; then
        echo "curl: (28) Operation timed out" >&2
        exit 28
    fi

    db_fallback=$(python3 -c "import json, sys; d=json.load(open('$STATE_FILE')); val=d.get('db_fallback', False); print(str(val).lower() if isinstance(val, bool) else str(val))")
    storage="postgres"
    if [[ "$db_fallback" == "true" ]]; then
        storage="in_memory"
    fi

    payload=$(cat <<EOF
{
  "service": "cloudpulse-detection-worker",
  "status": "healthy",
  "environment": "production",
  "storage": "$storage",
  "detectors": [
    "RESOURCE_CREATION",
    "UNEXPECTED_PUBLIC_EXPOSURE",
    "SUSPICIOUS_OUTBOUND_ACTIVITY",
    "COST_ANOMALY"
  ]
}
EOF
)
    if [[ "$cmd" =~ "-w" ]]; then
        echo "$payload"
        echo "200"
    else
        echo "$payload"
    fi
    exit 0
fi

exit 0
"""

MOCK_SLEEP_TEMPLATE = """#!/usr/bin/env bash
# Fast sleep mock for testing
exit 0
"""


@pytest.fixture
def mock_env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    state_file = tmp_path / "mock_state.json"
    initial_state = {
        "sub_id": "90b900ea-4273-4b40-a343-091aecfe2911",
        "pg_state": "Stopped",
        "ca_min": 0,
        "ca_max": 1,
        "ca_provisioning": "Succeeded",
        "rev_running_state": "ScaledToZero",
        "replicas": [],
        "replica_list_error": False,
        "activation_timeout": False,
        "pg_timeout": False,
        "fail_command": "",
        "mutations": [],
    }
    state_file.write_text(json.dumps(initial_state))

    az_script = bin_dir / "az"
    az_script.write_text(MOCK_AZ_TEMPLATE)
    az_script.chmod(0o755)

    curl_script = bin_dir / "curl"
    curl_script.write_text(MOCK_CURL_TEMPLATE)
    curl_script.chmod(0o755)

    sleep_script = bin_dir / "sleep"
    sleep_script.write_text(MOCK_SLEEP_TEMPLATE)
    sleep_script.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["MOCK_STATE_FILE"] = str(state_file)
    env["POSTGRES_TIMEOUT_SECONDS"] = "2"
    env["REPLICA_TIMEOUT_SECONDS"] = "2"
    env["ACTIVATION_TIMEOUT_SECONDS"] = "2"
    env["POLL_INTERVAL_SECONDS"] = "1"

    def update_state(**kwargs):
        data = json.loads(state_file.read_text())
        data.update(kwargs)
        state_file.write_text(json.dumps(data))

    def get_state():
        return json.loads(state_file.read_text())

    return env, update_state, get_state


def run_cmd(script, args=None, env=None):
    cmd = [script] + (args or [])
    res = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res


# ------------------------------------------------------------------------------
# Test 1: Status command makes NO changes and classifies accurately
# ------------------------------------------------------------------------------
def test_status_command_dormant_and_zero_mutations(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Stopped", ca_min=0, ca_max=1, replicas=[], rev_running_state="ScaledToZero")

    res = run_cmd(STATUS_SCRIPT, env=env)
    assert res.returncode == 0
    assert "DORMANT" in res.stdout
    state = get_state()
    assert len(state.get("mutations", [])) == 0


def test_status_command_active_classification(mock_env):
    env, update_state, get_state = mock_env
    update_state(
        pg_state="Ready",
        ca_min=0,
        ca_max=1,
        replicas=[{"name": "rep1", "properties": {"runningState": "Running"}}],
        rev_running_state="Running",
    )

    res = run_cmd(STATUS_SCRIPT, env=env)
    assert res.returncode == 0
    assert "ACTIVE" in res.stdout
    assert "HEALTHY" in res.stdout
    state = get_state()
    assert len(state.get("mutations", [])) == 0


def test_status_command_partial_classification(mock_env):
    env, update_state, get_state = mock_env
    # PG is Ready, but Container App has no active replicas
    update_state(pg_state="Ready", ca_min=0, ca_max=1, replicas=[], rev_running_state="ScaledToZero")

    res = run_cmd(STATUS_SCRIPT, env=env)
    assert res.returncode == 0
    assert "PARTIAL" in res.stdout


# ------------------------------------------------------------------------------
# Test 2: Already-stopped PostgreSQL during OFF
# ------------------------------------------------------------------------------
def test_off_already_stopped_postgres(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Stopped", ca_min=1, ca_max=1, replicas=[])

    res = run_cmd(OFF_SCRIPT, env=env)
    assert res.returncode == 0
    assert "already Stopped" in res.stdout
    state = get_state()
    # Postgres stop command was NOT called
    assert not any("postgres flexible-server stop" in m for m in state.get("mutations", []))
    # Container app scaling was updated to min=0
    assert state["ca_min"] == 0


# ------------------------------------------------------------------------------
# Test 3: Already-dormant Container App during OFF
# ------------------------------------------------------------------------------
def test_off_already_dormant_container_app(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Ready", ca_min=0, ca_max=1, replicas=[])

    res = run_cmd(OFF_SCRIPT, env=env)
    assert res.returncode == 0
    assert "already configured for scale-to-zero (min=0)" in res.stdout
    state = get_state()
    # Container app update was skipped because already min=0
    assert not any("containerapp update" in m for m in state.get("mutations", []))
    # But Postgres stop was issued
    assert any("postgres flexible-server stop" in m for m in state.get("mutations", []))
    assert state["pg_state"] == "Stopped"


# ------------------------------------------------------------------------------
# Test 4: Already-active PostgreSQL during ON
# ------------------------------------------------------------------------------
def test_on_already_active_postgres(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Ready", ca_min=0, ca_max=1, replicas=[])

    res = run_cmd(ON_SCRIPT, env=env)
    assert res.returncode == 0
    assert "already Ready" in res.stdout
    state = get_state()
    # Postgres start command was NOT called
    assert not any("postgres flexible-server start" in m for m in state.get("mutations", []))


# ------------------------------------------------------------------------------
# Test 5: PostgreSQL startup timeout during ON
# ------------------------------------------------------------------------------
def test_on_postgres_startup_timeout(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Stopped", pg_timeout=True)

    res = run_cmd(ON_SCRIPT, env=env)
    assert res.returncode != 0
    assert "Timeout" in res.stderr or "Timeout" in res.stdout
    assert "Recovery Instructions" in res.stdout
    state = get_state()
    # Container App scaling should NOT be touched if PostgreSQL failed
    assert not any("containerapp update" in m for m in state.get("mutations", []))


# ------------------------------------------------------------------------------
# Test 6: Container App activation timeout during ON
# ------------------------------------------------------------------------------
def test_on_container_app_activation_timeout(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Stopped", activation_timeout=True)

    res = run_cmd(ON_SCRIPT, env=env)
    assert res.returncode != 0
    assert "Timeout" in res.stderr or "Timeout" in res.stdout
    state = get_state()
    # PostgreSQL was started and left Ready
    assert state["pg_state"] == "Ready"
    # Notice instructions explaining partial state and recovery
    assert "PostgreSQL is RUNNING" in res.stdout


# ------------------------------------------------------------------------------
# Test 7: Azure CLI command failure handling
# ------------------------------------------------------------------------------
def test_azure_cli_command_failure_handling(mock_env):
    env, update_state, _ = mock_env
    update_state(ca_min=1, fail_command="containerapp update")

    res = run_cmd(OFF_SCRIPT, env=env)
    assert res.returncode != 0
    assert "Failed to update Container App scaling limits" in res.stderr or "Failed" in res.stdout


# ------------------------------------------------------------------------------
# Test 8: Subscription mismatch rejection
# ------------------------------------------------------------------------------
def test_subscription_mismatch_fails_safely(mock_env):
    env, update_state, get_state = mock_env
    update_state(sub_id="11111111-2222-3333-4444-555555555555")

    for script in [STATUS_SCRIPT, OFF_SCRIPT, ON_SCRIPT]:
        res = run_cmd(script, env=env)
        assert res.returncode != 0
        assert "Subscription context mismatch" in res.stderr or "Subscription context mismatch" in res.stdout
        # No mutations attempted
        state = get_state()
        assert len(state.get("mutations", [])) == 0


# ------------------------------------------------------------------------------
# Test 9: Replica-list command failure versus genuinely empty replica list
# ------------------------------------------------------------------------------
def test_replica_list_failure_vs_genuinely_empty(mock_env):
    env, update_state, _ = mock_env
    
    # 1. Genuine empty replica list succeeds
    update_state(pg_state="Stopped", ca_min=0, ca_max=1, replicas=[], replica_list_error=False)
    res_empty = run_cmd(OFF_SCRIPT, env=env)
    assert res_empty.returncode == 0
    assert "All active replicas terminated" in res_empty.stdout

    # 2. Command failure does NOT get treated as empty list; it errors out
    update_state(pg_state="Stopped", ca_min=0, ca_max=1, replica_list_error=True)
    res_err = run_cmd(OFF_SCRIPT, env=env)
    assert res_err.returncode != 0
    assert "Replica query failed" in res_err.stderr or "Replica query failed" in res_err.stdout


# ------------------------------------------------------------------------------
# Test 10: Partial failure reporting during OFF
# ------------------------------------------------------------------------------
def test_partial_failure_reporting_during_off(mock_env):
    env, update_state, _ = mock_env
    # Container App update succeeds, but PostgreSQL stop fails
    update_state(pg_state="Ready", ca_min=1, ca_max=1, fail_command="postgres flexible-server stop")

    res = run_cmd(OFF_SCRIPT, env=env)
    assert res.returncode != 0
    assert "Step 3: Container App Scaling (min=0)  : SUCCESS" in res.stdout
    assert "Step 5: PostgreSQL Stop Command       : FAILED" in res.stdout
    assert "Shutdown completed with one or more failures" in res.stderr or "failures" in res.stdout


# ------------------------------------------------------------------------------
# Test 11: Partial failure reporting during ON
# ------------------------------------------------------------------------------
def test_partial_failure_reporting_during_on(mock_env):
    env, update_state, _ = mock_env
    # PostgreSQL starts, but Container App scaling update fails
    update_state(pg_state="Stopped", ca_min=1, ca_max=1, fail_command="containerapp update")

    res = run_cmd(ON_SCRIPT, env=env)
    assert res.returncode != 0
    assert "Step 4: PostgreSQL Ready Verified     : SUCCESS" in res.stdout
    assert "Step 6: Scale Limits Restored (0/1)   : FAILED" in res.stdout
    assert "Partial State Notice" in res.stdout


# ------------------------------------------------------------------------------
# Test 12: Repeated ON and OFF executions (Idempotency)
# ------------------------------------------------------------------------------
def test_repeated_executions_idempotent(mock_env):
    env, update_state, _ = mock_env
    update_state(pg_state="Stopped", ca_min=1, ca_max=1, replicas=[])

    # First OFF run
    res_off1 = run_cmd(OFF_SCRIPT, env=env)
    assert res_off1.returncode == 0

    # Second OFF run (already stopped and scaled to zero)
    res_off2 = run_cmd(OFF_SCRIPT, env=env)
    assert res_off2.returncode == 0
    assert "already configured for scale-to-zero (min=0)" in res_off2.stdout
    assert "already Stopped" in res_off2.stdout

    # First ON run
    res_on1 = run_cmd(ON_SCRIPT, env=env)
    assert res_on1.returncode == 0

    # Second ON run (already running and active)
    res_on2 = run_cmd(ON_SCRIPT, env=env)
    assert res_on2.returncode == 0
    assert "already Ready" in res_on2.stdout


# ------------------------------------------------------------------------------
# Test 13: Dry-run mode makes zero mutations
# ------------------------------------------------------------------------------
def test_dry_run_mode_zero_mutations(mock_env):
    env, update_state, get_state = mock_env
    update_state(pg_state="Ready", ca_min=1, ca_max=1, replicas=[])

    # Dry run OFF
    res_off = run_cmd(OFF_SCRIPT, ["--dry-run"], env=env)
    assert res_off.returncode == 0
    assert "[DRY-RUN]" in res_off.stdout
    assert len(get_state().get("mutations", [])) == 0

    # Dry run ON
    update_state(pg_state="Stopped", ca_min=0, ca_max=1)
    res_on = run_cmd(ON_SCRIPT, ["--dry-run"], env=env)
    assert res_on.returncode == 0
    assert "[DRY-RUN]" in res_on.stdout
    assert len(get_state().get("mutations", [])) == 0


# ------------------------------------------------------------------------------
# Test 14: Absence of secrets in logs
# ------------------------------------------------------------------------------
def test_absence_of_secrets_in_logs(mock_env):
    env, update_state, _ = mock_env
    sensitive_patterns = [
        r"3VuaVvFn5zOhgiUVLaPfmMqx9wUEM3W2Yu4Jv2PbS2I=",  # actual pg password in tfvars
        r"password\s*[:=]\s*[^\s]+",
        r"Server=.*User Id=.*Password=.*",
        r"AccountKey=[A-Za-z0-9+/=]{20,}",
        r"bearer\s+[A-Za-z0-9\._\-]{20,}",
    ]

    for script in [STATUS_SCRIPT, OFF_SCRIPT, ON_SCRIPT]:
        res = run_cmd(script, ["--dry-run"], env=env)
        combined_logs = res.stdout + "\n" + res.stderr
        for pat in sensitive_patterns:
            matches = re.findall(pat, combined_logs, flags=re.IGNORECASE)
            assert not matches, f"Found sensitive leak matching '{pat}' in {script} output: {matches}"
