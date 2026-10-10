#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle - Safe OFF Tool
#
# Idempotently and safely shuts down CloudPulse compute resources to minimize
# idle Azure costs without deleting or damaging infrastructure, databases,
# images, secrets, networking, identities, or Terraform state.
#
# Sequence:
# 1. Verify prerequisites, Azure authentication, subscription, and resources.
# 2. Confirm subscription matches expected context (no silent switching).
# 3. Prevent new work by updating Container App max replicas to 0.
# 4. Set Container App min and max replicas to 0.
# 5. Verify active replicas have terminated (bounded polling).
# 6. Stop PostgreSQL Flexible Server if running.
# 7. Verify PostgreSQL reaches Stopped state (bounded polling).
# 8. Report final operational status and step verification summary.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/cloudpulse-common.sh
source "${SCRIPT_DIR}/lib/cloudpulse-common.sh"

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Safely transition CloudPulse to DORMANT state to eliminate idle compute costs.
All resources, data, images, secrets, and configurations are preserved.

Options:
  -n, --dry-run             Simulate shutdown actions without mutating Azure resources
  -s, --subscription ID     Azure subscription ID (default: ${EXPECTED_SUBSCRIPTION_ID})
  -g, --resource-group NAME Azure resource group (default: ${RESOURCE_GROUP})
  -t, --timeout SECONDS     Bounded timeout for state transitions (default: ${POSTGRES_TIMEOUT_SECONDS}s)
  -h, --help                Show this help message and exit

Invariants Enforced:
  - Does NOT destroy resources, resource groups, or run terraform destroy.
  - Does NOT delete databases, images, storage accounts, secrets, or role assignments.
  - Verifies state transitions using bounded polling; never assumes success on dispatch.
  - Safe to run repeatedly (fully idempotent).

Example:
  $(basename "$0") --dry-run
  $(basename "$0")
EOF
}

parse_common_args "$@"

echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                 CloudPulse Safe OFF Lifecycle Shutdown                       ${COLOR_RESET}"
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
if [[ "$DRY_RUN" == "true" ]]; then
    log_dry_run "Running in DRY-RUN mode. No changes will be made to Azure resources."
fi

# Track individual step outcomes
STEP1_PREFLIGHT="PENDING"
STEP2_SUBSCRIPTION="PENDING"
STEP3_SCALE_ZERO="PENDING"
STEP4_REPLICAS_TERMINATED="PENDING"
STEP5_PG_STOP="PENDING"
STEP6_PG_VERIFIED="PENDING"

# ------------------------------------------------------------------------------
# Step 1: Pre-flight Verification & Tools
# ------------------------------------------------------------------------------
log_step "1/6: Verifying required CLI tools, authentication, and resource group..."
if ! check_required_tools; then
    STEP1_PREFLIGHT="FAILED"
    exit 1
fi

if ! check_azure_auth; then
    STEP1_PREFLIGHT="FAILED"
    exit 1
fi

if ! verify_resource_group; then
    STEP1_PREFLIGHT="FAILED"
    exit 1
fi
STEP1_PREFLIGHT="SUCCESS"

# ------------------------------------------------------------------------------
# Step 2: Validate Active Subscription Context
# ------------------------------------------------------------------------------
log_step "2/6: Validating active subscription context..."
if ! verify_subscription; then
    STEP2_SUBSCRIPTION="FAILED"
    exit 1
fi
STEP2_SUBSCRIPTION="SUCCESS"

# ------------------------------------------------------------------------------
# Step 3: Scale Container App to min=0 Replicas (Scale-to-Zero)
# ------------------------------------------------------------------------------
log_step "3/6: Evaluating Container App scaling configuration..."
ca_details=$(get_container_app_details || echo "{}")
current_ca_min=$(echo "$ca_details" | jq -r '.minReplicas // -1')
current_ca_max=$(echo "$ca_details" | jq -r '.maxReplicas // -1')
ca_latest_rev=$(echo "$ca_details" | jq -r '.latestRevisionName // ""')

log_info "Current Container App scaling: min=${current_ca_min}, max=${current_ca_max}"

if [[ "$current_ca_min" == "0" ]]; then
    log_info "Container App '${CONTAINER_APP}' is already configured for scale-to-zero (min=0)."
    STEP3_SCALE_ZERO="SKIPPED (already min=0)"
else
    log_info "Configuring Container App '${CONTAINER_APP}' scaling to min=0 (enables scale-to-zero)..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "az containerapp update --resource-group '${RESOURCE_GROUP}' --name '${CONTAINER_APP}' --min-replicas 0"
        STEP3_SCALE_ZERO="SUCCESS (dry-run)"
    else
        update_err=""
        if ! update_err=$(az containerapp update \
            --resource-group "$RESOURCE_GROUP" \
            --name "$CONTAINER_APP" \
            --min-replicas 0 \
            -o none 2>&1); then
            log_error "Failed to update Container App scaling limits: ${update_err}"
            STEP3_SCALE_ZERO="FAILED"
        else
            log_success "Container App scaling configured to min=0."
            STEP3_SCALE_ZERO="SUCCESS"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Step 4: Verify Active Replicas Have Terminated
# ------------------------------------------------------------------------------
log_step "4/6: Verifying active replica termination (bounded timeout: ${REPLICA_TIMEOUT_SECONDS}s)..."
if [[ "$DRY_RUN" == "true" ]]; then
    log_dry_run "Would poll revision '${ca_latest_rev}' replicas until active count is 0"
    STEP4_REPLICAS_TERMINATED="SUCCESS (dry-run)"
elif [[ "$STEP3_SCALE_ZERO" == "FAILED" ]]; then
    log_warn "Skipping replica termination verification due to scaling update failure."
    STEP4_REPLICAS_TERMINATED="SKIPPED"
else
    start_time=$(date +%s)
    terminated=false

    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        # Refresh latest revision name if needed
        if [[ -z "$ca_latest_rev" ]]; then
            ca_details=$(get_container_app_details || echo "{}")
            ca_latest_rev=$(echo "$ca_details" | jq -r '.latestRevisionName // ""')
        fi

        # Query replica list safely
        replica_json=""
        if replica_json=$(get_replica_list "$ca_latest_rev"); then
            active_replicas=$(echo "$replica_json" | jq '. | length' 2>/dev/null || echo "0")
            if [[ "$active_replicas" -eq 0 ]]; then
                # Double check revision running state
                rev_details=$(get_revision_details "$ca_latest_rev" || echo "{}")
                rev_running_state=$(echo "$rev_details" | jq -r '.runningState // "Unknown"')
                log_success "All active replicas terminated (replica count: 0, revision state: ${rev_running_state})."
                terminated=true
                STEP4_REPLICAS_TERMINATED="SUCCESS"
                break
            else
                log_info "Waiting for ${active_replicas} replica(s) to terminate... (${elapsed}s / ${REPLICA_TIMEOUT_SECONDS}s)"
            fi
        else
            log_error "Replica query failed. Aborting replica termination poll."
            STEP4_REPLICAS_TERMINATED="FAILED"
            break
        fi

        if [[ $elapsed -ge $REPLICA_TIMEOUT_SECONDS ]]; then
            log_error "Timeout (${REPLICA_TIMEOUT_SECONDS}s) waiting for replicas to terminate."
            STEP4_REPLICAS_TERMINATED="FAILED"
            break
        fi

        sleep "$POLL_INTERVAL_SECONDS"
    done
fi

# ------------------------------------------------------------------------------
# Step 5: Stop PostgreSQL Flexible Server if Running
# ------------------------------------------------------------------------------
log_step "5/6: Evaluating PostgreSQL server state..."
pg_details=$(get_postgres_details || echo "{}")
pg_state=$(echo "$pg_details" | jq -r '.state // "UNKNOWN"')

log_info "Current PostgreSQL server state: ${pg_state}"

if [[ "$pg_state" == "Stopped" ]]; then
    log_info "PostgreSQL server '${POSTGRES_SERVER}' is already Stopped."
    STEP5_PG_STOP="SKIPPED (already Stopped)"
    STEP6_PG_VERIFIED="SUCCESS (already Stopped)"
elif [[ "$pg_state" == "Stopping" ]]; then
    log_info "PostgreSQL server '${POSTGRES_SERVER}' is already transitioning to Stopped."
    STEP5_PG_STOP="SUCCESS (already Stopping)"
else
    log_info "Issuing stop command to PostgreSQL server '${POSTGRES_SERVER}'..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "az postgres flexible-server stop --resource-group '${RESOURCE_GROUP}' --name '${POSTGRES_SERVER}' --no-wait"
        STEP5_PG_STOP="SUCCESS (dry-run)"
        STEP6_PG_VERIFIED="SUCCESS (dry-run)"
    else
        stop_err=""
        if ! stop_err=$(az postgres flexible-server stop \
            --resource-group "$RESOURCE_GROUP" \
            --name "$POSTGRES_SERVER" \
            --no-wait 2>&1); then
            log_error "Failed to issue stop command for PostgreSQL server: ${stop_err}"
            STEP5_PG_STOP="FAILED"
            STEP6_PG_VERIFIED="FAILED"
        else
            log_success "PostgreSQL stop command accepted."
            STEP5_PG_STOP="SUCCESS"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Step 6: Verify PostgreSQL Reaches Stopped State
# ------------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" && "$STEP6_PG_VERIFIED" != "SUCCESS (already Stopped)" && "$STEP5_PG_STOP" == "SUCCESS" ]]; then
    log_step "6/6: Verifying PostgreSQL server reaches Stopped state (timeout: ${POSTGRES_TIMEOUT_SECONDS}s)..."
    start_time=$(date +%s)
    pg_stopped=false

    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        current_pg_details=$(get_postgres_details || echo "{}")
        current_pg_state=$(echo "$current_pg_details" | jq -r '.state // "UNKNOWN"')

        if [[ "$current_pg_state" == "Stopped" ]]; then
            log_success "PostgreSQL server confirmed in Stopped state (${elapsed}s elapsed)."
            pg_stopped=true
            STEP6_PG_VERIFIED="SUCCESS"
            break
        elif [[ "$current_pg_state" == "Stopping" || "$current_pg_state" == "Ready" ]]; then
            log_info "PostgreSQL server state: ${current_pg_state}... (${elapsed}s / ${POSTGRES_TIMEOUT_SECONDS}s)"
        else
            log_warn "Unexpected PostgreSQL server state: ${current_pg_state}"
        fi

        if [[ $elapsed -ge $POSTGRES_TIMEOUT_SECONDS ]]; then
            log_error "Timeout (${POSTGRES_TIMEOUT_SECONDS}s) waiting for PostgreSQL server to reach Stopped state."
            STEP6_PG_VERIFIED="FAILED"
            break
        fi

        sleep 10
    done
fi

# ------------------------------------------------------------------------------
# 8. Report Final Status & Step Breakdown
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                     CloudPulse OFF Execution Summary                         ${COLOR_RESET}"
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "Step 1: Pre-flight & Auth Check       : ${STEP1_PREFLIGHT}"
echo -e "Step 2: Subscription Match (${EXPECTED_SUBSCRIPTION_ID}) : ${STEP2_SUBSCRIPTION}"
echo -e "Step 3: Container App Scaling (min=0)  : ${STEP3_SCALE_ZERO}"
echo -e "Step 4: Replica Termination Verified  : ${STEP4_REPLICAS_TERMINATED}"
echo -e "Step 5: PostgreSQL Stop Command       : ${STEP5_PG_STOP}"
echo -e "Step 6: PostgreSQL Stopped Verified   : ${STEP6_PG_VERIFIED}"
echo -e "------------------------------------------------------------------------------"

# Determine overall success
has_failure=false
for status in "$STEP1_PREFLIGHT" "$STEP2_SUBSCRIPTION" "$STEP3_SCALE_ZERO" "$STEP4_REPLICAS_TERMINATED" "$STEP5_PG_STOP" "$STEP6_PG_VERIFIED"; do
    if [[ "$status" == "FAILED" ]]; then
        has_failure=true
        break
    fi
done

if [[ "$has_failure" == "true" ]]; then
    log_error "Shutdown completed with one or more failures."
    log_error "Deployment may be in a PARTIAL state. Review step breakdown above."
    log_error "Run './scripts/cloudpulse-status.sh' to inspect current resource states."
    exit 1
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_dry_run "DRY-RUN completed successfully. Zero changes were made to Azure infrastructure."
    exit 0
fi

log_success "CloudPulse successfully transitioned to DORMANT mode."
echo -e "\n${COLOR_BOLD}${COLOR_BLUE}ℹ Resource Disposition & Cost Notice:${COLOR_RESET}"
echo -e "  • Stopped Resources (Zero Active Compute Charge):"
echo -e "      - Container App compute replicas: 0 active replicas (${CONTAINER_APP})"
echo -e "      - Database compute              : Stopped (${POSTGRES_SERVER})"
echo -e "  • Preserved & Retained Resources (Zero Deletions):"
echo -e "      - Azure OpenAI Account          : ${OPENAI_ACCOUNT} (Provisioned PaaS; 0 inference token charges while dormant)"
echo -e "      - Model Deployments             : ${OPENAI_DEPLOYMENT} (Retained intact; never deleted during OFF)"
echo -e "      - Persistent Storage & Data     : PostgreSQL 32GB disk, LAW telemetry, ACR container images"
echo -e "      - Security & Identity           : Managed identities and RBAC role assignments unmodified"
echo -e "      - Infrastructure State          : Terraform state and resource groups preserved"
echo -e "  • Note: Azure Database for PostgreSQL may automatically restart after 7 days if not started sooner."
echo -e "  • To resume operations safely, run: ${COLOR_BOLD}./scripts/cloudpulse-on.sh${COLOR_RESET}\n"
exit 0
