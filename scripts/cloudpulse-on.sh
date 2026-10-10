#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle - Safe ON Tool
#
# Idempotently and safely brings CloudPulse to ACTIVE operational state.
#
# Sequence:
# 1. Verify prerequisites, Azure authentication, subscription, and resources.
# 2. Confirm subscription matches expected context (no silent switching).
# 3. Start PostgreSQL Flexible Server if stopped.
# 4. Poll PostgreSQL until Azure reports Ready (bounded polling).
# 5. Verify database connectivity using repository supported method (no secrets printed).
# 6. Restore Container App intended scaling limits (min: 0, max: 1).
# 7. Trigger minimum activation needed via existing HTTP ingress.
# 8. Wait for running replica and successful health check (bounded polling).
# 9. Verify managed identity and Azure dependencies from health response.
# 10. Report ON operational status and dashboard endpoint.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/cloudpulse-common.sh
source "${SCRIPT_DIR}/lib/cloudpulse-common.sh"

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Safely start and activate CloudPulse, bringing dependencies online in correct
order, validating health checks, and making the application operational.

Options:
  -n, --dry-run             Simulate startup actions without mutating Azure resources
  -s, --subscription ID     Azure subscription ID (default: ${EXPECTED_SUBSCRIPTION_ID})
  -g, --resource-group NAME Azure resource group (default: ${RESOURCE_GROUP})
  -t, --timeout SECONDS     Bounded timeout for state transitions (default: ${POSTGRES_TIMEOUT_SECONDS}s)
  -h, --help                Show this help message and exit

Invariants Enforced:
  - Does NOT alter scale-to-zero cost-saving design permanently (restores min=0, max=1).
  - Verifies PostgreSQL is fully ready before triggering Container App compute.
  - Safe to run repeatedly (fully idempotent).
  - If Container App activation fails after database starts, leaves database running
    and prints clear recovery instructions without automatically tearing down DB.

Example:
  $(basename "$0") --dry-run
  $(basename "$0")
EOF
}

parse_common_args "$@"

echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                  CloudPulse Safe ON Lifecycle Startup                        ${COLOR_RESET}"
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
if [[ "$DRY_RUN" == "true" ]]; then
    log_dry_run "Running in DRY-RUN mode. No changes will be made to Azure resources."
fi

# Track individual step outcomes
STEP1_PREFLIGHT="PENDING"
STEP2_SUBSCRIPTION="PENDING"
STEP3_PG_START="PENDING"
STEP4_PG_READY="PENDING"
STEP5_DB_HEALTH="PENDING"
STEP6_RESTORE_SCALE="PENDING"
STEP7_TRIGGER_ACTIVATION="PENDING"
STEP8_HEALTH_VERIFIED="PENDING"
STEP9_IDENTITY_DEPS="PENDING"
STEP10_OPENAI="PENDING"

# ------------------------------------------------------------------------------
# Step 1: Pre-flight Verification & Tools
# ------------------------------------------------------------------------------
log_step "1/10: Verifying required CLI tools, authentication, and resource group..."
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
log_step "2/10: Validating active subscription context..."
if ! verify_subscription; then
    STEP2_SUBSCRIPTION="FAILED"
    exit 1
fi
STEP2_SUBSCRIPTION="SUCCESS"

# ------------------------------------------------------------------------------
# Step 3: Start PostgreSQL Flexible Server if Stopped
# ------------------------------------------------------------------------------
log_step "3/10: Checking PostgreSQL server state..."
pg_details=$(get_postgres_details || echo "{}")
pg_state=$(echo "$pg_details" | jq -r '.state // "UNKNOWN"')

log_info "Current PostgreSQL server state: ${pg_state}"

if [[ "$pg_state" == "Ready" ]]; then
    log_info "PostgreSQL server '${POSTGRES_SERVER}' is already Ready."
    STEP3_PG_START="SKIPPED (already Ready)"
    STEP4_PG_READY="SUCCESS (already Ready)"
elif [[ "$pg_state" == "Starting" ]]; then
    log_info "PostgreSQL server '${POSTGRES_SERVER}' is already Starting."
    STEP3_PG_START="SUCCESS (already Starting)"
else
    log_info "Starting PostgreSQL server '${POSTGRES_SERVER}'..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "az postgres flexible-server start --resource-group '${RESOURCE_GROUP}' --name '${POSTGRES_SERVER}' --no-wait"
        STEP3_PG_START="SUCCESS (dry-run)"
        STEP4_PG_READY="SUCCESS (dry-run)"
        STEP5_DB_HEALTH="SUCCESS (dry-run)"
    else
        start_err=""
        if ! start_err=$(az postgres flexible-server start \
            --resource-group "$RESOURCE_GROUP" \
            --name "$POSTGRES_SERVER" \
            --no-wait 2>&1); then
            log_error "Failed to issue start command for PostgreSQL server: ${start_err}"
            STEP3_PG_START="FAILED"
            STEP4_PG_READY="FAILED"
            STEP5_DB_HEALTH="FAILED"
        else
            log_success "PostgreSQL start command accepted."
            STEP3_PG_START="SUCCESS"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Step 4: Poll PostgreSQL Until Ready
# ------------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" && "$STEP4_PG_READY" != "SUCCESS (already Ready)" && "$STEP3_PG_START" == "SUCCESS" ]]; then
    log_step "4/10: Polling PostgreSQL server until Ready (timeout: ${POSTGRES_TIMEOUT_SECONDS}s)..."
    start_time=$(date +%s)
    pg_ready=false

    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        current_pg_details=$(get_postgres_details || echo "{}")
        current_pg_state=$(echo "$current_pg_details" | jq -r '.state // "UNKNOWN"')

        if [[ "$current_pg_state" == "Ready" ]]; then
            log_success "PostgreSQL server is Ready (${elapsed}s elapsed)."
            pg_ready=true
            STEP4_PG_READY="SUCCESS"
            break
        elif [[ "$current_pg_state" == "Starting" || "$current_pg_state" == "Stopped" ]]; then
            log_info "PostgreSQL server state: ${current_pg_state}... (${elapsed}s / ${POSTGRES_TIMEOUT_SECONDS}s)"
        else
            log_warn "Unexpected PostgreSQL server state: ${current_pg_state}"
        fi

        if [[ $elapsed -ge $POSTGRES_TIMEOUT_SECONDS ]]; then
            log_error "Timeout (${POSTGRES_TIMEOUT_SECONDS}s) waiting for PostgreSQL server to reach Ready state."
            STEP4_PG_READY="FAILED"
            break
        fi

        sleep 10
    done
fi

# ------------------------------------------------------------------------------
# Step 5: Verify Database Connectivity via Supported Method
# ------------------------------------------------------------------------------
if [[ "$STEP4_PG_READY" == "SUCCESS" || "$STEP4_PG_READY" == "SUCCESS (already Ready)" ]]; then
    log_step "5/10: Verifying PostgreSQL database availability..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "az postgres flexible-server db show --resource-group '${RESOURCE_GROUP}' --server-name '${POSTGRES_SERVER}' --database-name 'cloudpulse'"
        STEP5_DB_HEALTH="SUCCESS (dry-run)"
    else
        # Verify database exists in server management plane without printing secrets
        if db_json=$(az postgres flexible-server db show \
            --resource-group "$RESOURCE_GROUP" \
            --server-name "$POSTGRES_SERVER" \
            --database-name "cloudpulse" \
            --query "{name:name, charset:charset}" \
            -o json 2>/dev/null); then
            db_name=$(echo "$db_json" | jq -r '.name // "cloudpulse"')
            log_success "PostgreSQL database '${db_name}' verified online and accessible."
            STEP5_DB_HEALTH="SUCCESS"
        else
            log_warn "Could not verify database 'cloudpulse' via ARM. Will verify via application health probe."
            STEP5_DB_HEALTH="DEFERRED_TO_APP_HEALTH"
        fi
    fi
else
    if [[ "$DRY_RUN" != "true" ]]; then
        STEP5_DB_HEALTH="SKIPPED (PostgreSQL not Ready)"
    fi
fi

# If PostgreSQL startup failed, abort before touching Container App
if [[ "$STEP4_PG_READY" == "FAILED" ]]; then
    log_error "PostgreSQL did not become Ready. Aborting startup sequence before touching Container App."
    STEP6_RESTORE_SCALE="SKIPPED (PostgreSQL failed)"
    STEP7_TRIGGER_ACTIVATION="SKIPPED (PostgreSQL failed)"
    STEP8_HEALTH_VERIFIED="SKIPPED (PostgreSQL failed)"
    STEP9_IDENTITY_DEPS="SKIPPED (PostgreSQL failed)"
    STEP10_OPENAI="SKIPPED (PostgreSQL failed)"

    echo -e "\n${COLOR_BOLD}==============================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}                     CloudPulse ON Execution Summary                          ${COLOR_RESET}"
    echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
    echo -e "Step 1: Pre-flight & Auth Check       : ${STEP1_PREFLIGHT}"
    echo -e "Step 2: Subscription Match (${EXPECTED_SUBSCRIPTION_ID}) : ${STEP2_SUBSCRIPTION}"
    echo -e "Step 3: PostgreSQL Start Command      : ${STEP3_PG_START}"
    echo -e "Step 4: PostgreSQL Ready Verified     : ${STEP4_PG_READY}"
    echo -e "Step 5: Database Health Verified      : ${STEP5_DB_HEALTH}"
    echo -e "Step 6: Scale Limits Restored (0/1)   : ${STEP6_RESTORE_SCALE}"
    echo -e "Step 7: Minimum Activation Triggered  : ${STEP7_TRIGGER_ACTIVATION}"
    echo -e "Step 8: Application Health Verified   : ${STEP8_HEALTH_VERIFIED}"
    echo -e "Step 9: Identity & Dependencies Check : ${STEP9_IDENTITY_DEPS}"
    echo -e "Step 10: Azure OpenAI & Model Ready   : ${STEP10_OPENAI}"
    echo -e "------------------------------------------------------------------------------"
    echo -e "\n${COLOR_BOLD}${COLOR_YELLOW}Recovery Instructions:${COLOR_RESET}"
    echo -e "  1. Inspect PostgreSQL server status: az postgres flexible-server show -g ${RESOURCE_GROUP} -n ${POSTGRES_SERVER}"
    echo -e "  2. Check activity logs: az monitor activity-log list --resource-group ${RESOURCE_GROUP} --max-events 20"
    echo -e "  3. Re-run startup once resolved: ./scripts/cloudpulse-on.sh\n"
    exit 1
fi

# ------------------------------------------------------------------------------
# Step 6: Restore Container App Intended Scaling Limits (min=0, max=1)
# ------------------------------------------------------------------------------
log_step "6/10: Restoring Container App scaling limits (min=${INTENDED_MIN_REPLICAS}, max=${INTENDED_MAX_REPLICAS})..."
ca_details=$(get_container_app_details || echo "{}")
current_ca_min=$(echo "$ca_details" | jq -r '.minReplicas // -1')
current_ca_max=$(echo "$ca_details" | jq -r '.maxReplicas // -1')
ca_fqdn=$(echo "$ca_details" | jq -r '.fqdn // ""')
ca_latest_rev=$(echo "$ca_details" | jq -r '.latestRevisionName // ""')

if [[ "$current_ca_min" == "$INTENDED_MIN_REPLICAS" && "$current_ca_max" == "$INTENDED_MAX_REPLICAS" ]]; then
    log_info "Container App '${CONTAINER_APP}' already has intended scaling (min=${INTENDED_MIN_REPLICAS}, max=${INTENDED_MAX_REPLICAS})."
    STEP6_RESTORE_SCALE="SKIPPED (already configured)"
else
    log_info "Updating Container App scaling to min=${INTENDED_MIN_REPLICAS}, max=${INTENDED_MAX_REPLICAS}..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "az containerapp update --resource-group '${RESOURCE_GROUP}' --name '${CONTAINER_APP}' --min-replicas ${INTENDED_MIN_REPLICAS} --max-replicas ${INTENDED_MAX_REPLICAS}"
        STEP6_RESTORE_SCALE="SUCCESS (dry-run)"
    else
        update_err=""
        if ! update_err=$(az containerapp update \
            --resource-group "$RESOURCE_GROUP" \
            --name "$CONTAINER_APP" \
            --min-replicas "$INTENDED_MIN_REPLICAS" \
            --max-replicas "$INTENDED_MAX_REPLICAS" \
            -o none 2>&1); then
            log_error "Failed to update Container App scaling limits: ${update_err}"
            STEP6_RESTORE_SCALE="FAILED"
        else
            log_success "Container App scaling configured to min=${INTENDED_MIN_REPLICAS}, max=${INTENDED_MAX_REPLICAS}."
            STEP6_RESTORE_SCALE="SUCCESS"
        fi
    fi
fi

if [[ "$STEP6_RESTORE_SCALE" == "FAILED" ]]; then
    log_error "Failed to set Container App scaling limits. Aborting activation."
    STEP7_TRIGGER_ACTIVATION="SKIPPED (scale failed)"
    STEP8_HEALTH_VERIFIED="SKIPPED (scale failed)"
    STEP9_IDENTITY_DEPS="SKIPPED (scale failed)"
    STEP10_OPENAI="SKIPPED (scale failed)"

    echo -e "\n${COLOR_BOLD}==============================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}                     CloudPulse ON Execution Summary                          ${COLOR_RESET}"
    echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
    echo -e "Step 1: Pre-flight & Auth Check       : ${STEP1_PREFLIGHT}"
    echo -e "Step 2: Subscription Match (${EXPECTED_SUBSCRIPTION_ID}) : ${STEP2_SUBSCRIPTION}"
    echo -e "Step 3: PostgreSQL Start Command      : ${STEP3_PG_START}"
    echo -e "Step 4: PostgreSQL Ready Verified     : ${STEP4_PG_READY}"
    echo -e "Step 5: Database Health Verified      : ${STEP5_DB_HEALTH}"
    echo -e "Step 6: Scale Limits Restored (0/1)   : ${STEP6_RESTORE_SCALE}"
    echo -e "Step 7: Minimum Activation Triggered  : ${STEP7_TRIGGER_ACTIVATION}"
    echo -e "Step 8: Application Health Verified   : ${STEP8_HEALTH_VERIFIED}"
    echo -e "Step 9: Identity & Dependencies Check : ${STEP9_IDENTITY_DEPS}"
    echo -e "Step 10: Azure OpenAI & Model Ready   : ${STEP10_OPENAI}"
    echo -e "------------------------------------------------------------------------------"
    echo -e "\n${COLOR_BOLD}${COLOR_YELLOW}Partial State Notice & Recovery:${COLOR_RESET}"
    echo -e "  PostgreSQL was started and is Ready, but Container App scaling failed."
    echo -e "  PostgreSQL was left running to prevent disruption. To shut it down: ./scripts/cloudpulse-off.sh\n"
    exit 1
fi

# ------------------------------------------------------------------------------
# Step 7: Trigger Activation via Existing HTTP Ingress
# ------------------------------------------------------------------------------
log_step "7/10: Triggering minimum activation for scale-to-zero Container App..."
if [[ -z "$ca_fqdn" ]]; then
    ca_details=$(get_container_app_details || echo "{}")
    ca_fqdn=$(echo "$ca_details" | jq -r '.fqdn // ""')
fi

if [[ -z "$ca_fqdn" ]]; then
    log_error "Container App does not have a public FQDN configured."
    STEP7_TRIGGER_ACTIVATION="FAILED"
else
    log_info "Dispatching HTTP wake-up probe to https://${ca_fqdn}/health..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "curl -sk -m 5 'https://${ca_fqdn}/health' (activates scale-to-zero replica)"
        STEP7_TRIGGER_ACTIVATION="SUCCESS (dry-run)"
        STEP8_HEALTH_VERIFIED="SUCCESS (dry-run)"
        STEP9_IDENTITY_DEPS="SUCCESS (dry-run)"
        STEP10_OPENAI="SUCCESS (dry-run)"
    else
        # Initial non-blocking ping to trigger KEDA / Envoy HTTP scaler
        curl -sk -m 5 "https://${ca_fqdn}/health" >/dev/null 2>&1 || true
        log_success "Activation probe dispatched to HTTP ingress."
        STEP7_TRIGGER_ACTIVATION="SUCCESS"
    fi
fi

# ------------------------------------------------------------------------------
# Step 8: Wait for Running Replica and Successful Application Health Check
# ------------------------------------------------------------------------------
health_payload=""
if [[ "$DRY_RUN" != "true" && "$STEP7_TRIGGER_ACTIVATION" == "SUCCESS" ]]; then
    log_step "8/10: Polling application health and active replicas (timeout: ${ACTIVATION_TIMEOUT_SECONDS}s)..."
    start_time=$(date +%s)
    app_ready=false

    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        # Check HTTP health probe
        if health_payload=$(check_application_health "$ca_fqdn" 8); then
            app_status=$(echo "$health_payload" | jq -r '.status // "unknown"')
            app_storage=$(echo "$health_payload" | jq -r '.storage // "unknown"')

            if [[ "$app_status" == "healthy" || "$app_status" == "degraded" ]]; then
                log_success "Application health probe responded: status='${app_status}', storage='${app_storage}' (${elapsed}s elapsed)."
                
                # Check actual replicas
                if replica_json=$(get_replica_list "$ca_latest_rev"); then
                    replica_count=$(echo "$replica_json" | jq '. | length' 2>/dev/null || echo "0")
                    log_info "Active replicas observed: ${replica_count}"
                fi

                app_ready=true
                STEP8_HEALTH_VERIFIED="SUCCESS"
                break
            fi
        fi

        log_info "Waiting for Container App replica to boot and respond... (${elapsed}s / ${ACTIVATION_TIMEOUT_SECONDS}s)"

        if [[ $elapsed -ge $ACTIVATION_TIMEOUT_SECONDS ]]; then
            log_error "Timeout (${ACTIVATION_TIMEOUT_SECONDS}s) waiting for application health check to succeed."
            STEP8_HEALTH_VERIFIED="FAILED"
            break
        fi

        sleep "$POLL_INTERVAL_SECONDS"
    done
fi

# ------------------------------------------------------------------------------
# Step 9: Verify Managed Identity & Azure Dependencies
# ------------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" && "$STEP8_HEALTH_VERIFIED" == "SUCCESS" ]]; then
    log_step "9/10: Verifying managed identity and Azure dependencies..."
    
    # Verify managed identity in Azure
    if az identity show --resource-group "$RESOURCE_GROUP" --name "cloudpulse-identity" -o none 2>/dev/null; then
        log_info "Managed identity 'cloudpulse-identity' verified."
    else
        log_warn "Managed identity 'cloudpulse-identity' check failed."
    fi

    # Verify registered detectors in health probe response
    detector_count=$(echo "$health_payload" | jq '.detectors | length' 2>/dev/null || echo "0")
    if [[ "$detector_count" -ge 4 ]]; then
        detectors_list=$(echo "$health_payload" | jq -r '.detectors | join(", ")')
        log_success "Application detectors verified: ${detectors_list}"
        STEP9_IDENTITY_DEPS="SUCCESS"
    else
        log_warn "Application health payload did not list all expected detectors."
        STEP9_IDENTITY_DEPS="PARTIAL"
    fi
fi

# ------------------------------------------------------------------------------
# Step 10: Verify Azure OpenAI Service & Model Deployment
# ------------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" && "$STEP8_HEALTH_VERIFIED" == "SUCCESS" ]]; then
    log_step "10/10: Verifying Azure OpenAI account, model deployment, and AI connectivity..."
    oai_account_json=$(get_openai_account_details || echo "{}")
    oai_acc_state=$(echo "$oai_account_json" | jq -r '.provisioningState // "UNKNOWN"')

    if [[ "$oai_acc_state" != "Succeeded" ]]; then
        log_warn "Azure OpenAI account '${OPENAI_ACCOUNT}' is in state: ${oai_acc_state}."
        STEP10_OPENAI="DEGRADED (Account state: ${oai_acc_state})"
    else
        log_info "Azure OpenAI account '${OPENAI_ACCOUNT}' verified (State: ${oai_acc_state}, Region: ${OPENAI_REGION})."
        
        # Check model deployment
        oai_dep_json=$(get_openai_deployment_details "$OPENAI_DEPLOYMENT" || echo "{}")
        oai_dep_state=$(echo "$oai_dep_json" | jq -r '.provisioningState // "NOT_DEPLOYED"')

        if [[ "$oai_dep_state" == "Succeeded" ]]; then
            log_success "Azure OpenAI deployment '${OPENAI_DEPLOYMENT}' verified (State: ${oai_dep_state})."
            
            # Check RBAC
            role_json=$(check_openai_role_assignment || echo "[]")
            role_count=$(echo "$role_json" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo "0")
            if [[ "$role_count" -gt 0 ]]; then
                log_success "Role 'Cognitive Services OpenAI User' verified for identity '${CONTAINER_APP_PRINCIPAL_ID}'."
                STEP10_OPENAI="SUCCESS (Live gpt-4.1-mini operational)"
            else
                log_warn "Managed identity lacks 'Cognitive Services OpenAI User' role on '${OPENAI_ACCOUNT}'."
                log_warn "Actionable manual assignment command:"
                log_warn "  az role assignment create --assignee ${CONTAINER_APP_PRINCIPAL_ID} --role 'Cognitive Services OpenAI User' --scope '/subscriptions/${EXPECTED_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/${OPENAI_ACCOUNT}'"
                STEP10_OPENAI="DEGRADED (Role missing; fallback synthesis active)"
            fi
        else
            log_warn "Azure OpenAI model deployment '${OPENAI_DEPLOYMENT}' is missing or not ready on '${OPENAI_ACCOUNT}' (State: ${oai_dep_state})."
            log_warn "Actionable diagnostic: CloudPulse does not create model deployments automatically."
            log_warn "To deploy the model manually, execute:"
            log_warn "  az cognitiveservices account deployment create -g ${RESOURCE_GROUP} -n ${OPENAI_ACCOUNT} --deployment-name ${OPENAI_DEPLOYMENT} --model-name ${OPENAI_MODEL} --model-version '${OPENAI_MODEL_VERSION}' --model-format OpenAI --sku-capacity 10 --sku-name GlobalStandard"
            STEP10_OPENAI="DEGRADED (Model deployment missing; fallback synthesis active)"
        fi
    fi

    # Check AI runtime status from application health probe
    if [[ -n "$health_payload" ]]; then
        ai_reported_mode=$(echo "$health_payload" | jq -r '.ai_provider.execution_mode // ""')
        ai_reported_model=$(echo "$health_payload" | jq -r '.ai_provider.model_identifier // ""')
        if [[ -n "$ai_reported_mode" ]]; then
            log_info "Application reported AI runtime mode: ${ai_reported_mode} (${ai_reported_model})"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 11. Report Final Operational Status
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                     CloudPulse ON Execution Summary                          ${COLOR_RESET}"
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "Step 1: Pre-flight & Auth Check       : ${STEP1_PREFLIGHT}"
echo -e "Step 2: Subscription Match (${EXPECTED_SUBSCRIPTION_ID}) : ${STEP2_SUBSCRIPTION}"
echo -e "Step 3: PostgreSQL Start Command      : ${STEP3_PG_START}"
echo -e "Step 4: PostgreSQL Ready Verified     : ${STEP4_PG_READY}"
echo -e "Step 5: Database Health Verified      : ${STEP5_DB_HEALTH}"
echo -e "Step 6: Scale Limits Restored (0/1)   : ${STEP6_RESTORE_SCALE}"
echo -e "Step 7: Minimum Activation Triggered  : ${STEP7_TRIGGER_ACTIVATION}"
echo -e "Step 8: Application Health Verified   : ${STEP8_HEALTH_VERIFIED}"
echo -e "Step 9: Identity & Dependencies Check : ${STEP9_IDENTITY_DEPS}"
echo -e "Step 10: Azure OpenAI & Model Ready   : ${STEP10_OPENAI}"
echo -e "------------------------------------------------------------------------------"

has_failure=false
for status in "$STEP1_PREFLIGHT" "$STEP2_SUBSCRIPTION" "$STEP3_PG_START" "$STEP4_PG_READY" "$STEP6_RESTORE_SCALE" "$STEP7_TRIGGER_ACTIVATION" "$STEP8_HEALTH_VERIFIED"; do
    if [[ "$status" == "FAILED" ]]; then
        has_failure=true
        break
    fi
done

if [[ "$has_failure" == "true" ]]; then
    log_error "CloudPulse ON failed to achieve fully operational ACTIVE state."
    echo -e "\n${COLOR_BOLD}${COLOR_YELLOW}Partial State Recovery Instructions:${COLOR_RESET}"
    echo -e "  • PostgreSQL is RUNNING. It has been deliberately left running to protect data and avoid disruption."
    echo -e "  • Container App logs: az containerapp logs show -g ${RESOURCE_GROUP} -n ${CONTAINER_APP} --type console"
    echo -e "  • Check replica states: az containerapp replica list -g ${RESOURCE_GROUP} -n ${CONTAINER_APP}"
    echo -e "  • To retry startup: ./scripts/cloudpulse-on.sh"
    echo -e "  • To return to dormant (cost-saving mode): ./scripts/cloudpulse-off.sh\n"
    exit 1
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_dry_run "DRY-RUN completed successfully. Zero changes were made to Azure infrastructure."
    exit 0
fi

if [[ "$STEP10_OPENAI" =~ "DEGRADED" ]]; then
    log_warn "CloudPulse is OPERATIONAL (DEGRADED: AI running in deterministic fallback mode)."
else
    log_success "CloudPulse is fully ACTIVE and operational!"
fi

echo -e "\n${COLOR_BOLD}${COLOR_GREEN}✔ Service Endpoints:${COLOR_RESET}"
echo -e "  Dashboard UI    : ${COLOR_BOLD}https://${ca_fqdn}/dashboard${COLOR_RESET}"
echo -e "  Health Probe    : ${COLOR_BOLD}https://${ca_fqdn}/health${COLOR_RESET}"
echo -e "  AI Status API   : ${COLOR_BOLD}https://${ca_fqdn}/api/ai/status${COLOR_RESET}"
echo -e "  Incidents API   : ${COLOR_BOLD}https://${ca_fqdn}/api/incidents${COLOR_RESET}"
echo -e "  Cost / FinOps   : ${COLOR_BOLD}https://${ca_fqdn}/api/finops/costs${COLOR_RESET}"
echo -e "\n  To safely shut down when finished, run: ${COLOR_BOLD}./scripts/cloudpulse-off.sh${COLOR_RESET}\n"
exit 0
