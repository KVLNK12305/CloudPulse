#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle - Status Inspection Tool
#
# Strictly read-only command. Inspects and reports the deployment state of
# Azure Database for PostgreSQL Flexible Server, Azure Container Apps,
# active replicas, and application health without mutating any resources.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/cloudpulse-common.sh
source "${SCRIPT_DIR}/lib/cloudpulse-common.sh"

OUTPUT_JSON=false

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Inspect and report the current status of the CloudPulse Azure deployment.
This command is STRICTLY READ-ONLY and will never mutate any resources.

Options:
  -s, --subscription ID     Azure subscription ID (default: ${EXPECTED_SUBSCRIPTION_ID})
  -g, --resource-group NAME Azure resource group (default: ${RESOURCE_GROUP})
  -j, --json                Output summary as JSON
  -h, --help                Show this help message and exit

Classification States:
  ACTIVE   - Dependencies ready, active replicas present, application health checks pass.
  DORMANT  - PostgreSQL is stopped, Container App is scaled to zero, 0 active replicas.
  PARTIAL  - A known subset of components is active, but not fully ACTIVE or DORMANT.
  UNKNOWN  - Insufficient evidence to classify deployment safely.

Example:
  $(basename "$0")
EOF
}

# Parse custom and common arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json|-j)
            OUTPUT_JSON=true
            shift
            ;;
        --dry-run|-n)
            # Read-only command already does nothing mutable; accept flag gracefully
            shift
            ;;
        --subscription|-s)
            EXPECTED_SUBSCRIPTION_ID="${2:-}"
            shift 2
            ;;
        --resource-group|-g)
            RESOURCE_GROUP="${2:-}"
            shift 2
            ;;
        --openai-account)
            OPENAI_ACCOUNT="${2:-}"
            OPENAI_ENDPOINT="https://${OPENAI_ACCOUNT}.openai.azure.com/"
            shift 2
            ;;
        --deployment)
            OPENAI_DEPLOYMENT="${2:-}"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# 1. Verification of Prerequisites & Context
# ------------------------------------------------------------------------------
if ! check_required_tools; then
    exit 1
fi

if ! check_azure_auth; then
    exit 1
fi

if ! verify_subscription; then
    exit 1
fi

if ! verify_resource_group; then
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Inspect PostgreSQL Flexible Server
# ------------------------------------------------------------------------------
pg_json=$(get_postgres_details || echo "{}")
pg_state=$(echo "$pg_json" | jq -r '.state // "UNKNOWN"')
pg_fqdn=$(echo "$pg_json" | jq -r '.fqdn // "UNKNOWN"')
pg_sku=$(echo "$pg_json" | jq -r '.sku // "UNKNOWN"')
pg_version=$(echo "$pg_json" | jq -r '.version // "UNKNOWN"')

# ------------------------------------------------------------------------------
# 3. Inspect Container App & Revisions
# ------------------------------------------------------------------------------
ca_json=$(get_container_app_details || echo "{}")
ca_prov_state=$(echo "$ca_json" | jq -r '.provisioningState // "UNKNOWN"')
ca_run_status=$(echo "$ca_json" | jq -r '.runningStatus // "UNKNOWN"')
ca_fqdn=$(echo "$ca_json" | jq -r '.fqdn // "UNKNOWN"')
ca_min=$(echo "$ca_json" | jq -r '.minReplicas // "UNKNOWN"')
ca_max=$(echo "$ca_json" | jq -r '.maxReplicas // "UNKNOWN"')
ca_latest_rev=$(echo "$ca_json" | jq -r '.latestRevisionName // "UNKNOWN"')
ca_workload_profile=$(echo "$ca_json" | jq -r '.workloadProfileName // "UNKNOWN"')
ca_env_id=$(echo "$ca_json" | jq -r '.environmentId // "UNKNOWN"')
ca_env_name=$(basename "$ca_env_id" 2>/dev/null || echo "cloudpulse-env")

# ------------------------------------------------------------------------------
# 4. Inspect Actual Replicas & Revision Running State
# ------------------------------------------------------------------------------
replica_count=0
replica_states="None"
replica_list_raw=""
replica_query_ok=true

if [[ "$ca_latest_rev" != "UNKNOWN" && -n "$ca_latest_rev" ]]; then
    if replica_list_raw=$(get_replica_list "$ca_latest_rev"); then
        replica_count=$(echo "$replica_list_raw" | jq '. | length' 2>/dev/null || echo "0")
        if [[ "$replica_count" -gt 0 ]]; then
            replica_states=$(echo "$replica_list_raw" | jq -r '[.[].properties.runningState // .[].name] | join(", ")' 2>/dev/null || echo "Active")
        else
            replica_states="0 active replicas"
        fi
    else
        replica_query_ok=false
        replica_states="ERROR_QUERYING_REPLICAS"
    fi
else
    replica_states="No active revision identified"
fi

rev_running_state="Unknown"
rev_replicas="Unknown"
if [[ "$ca_latest_rev" != "UNKNOWN" && -n "$ca_latest_rev" ]]; then
    rev_json=$(get_revision_details "$ca_latest_rev" || echo "{}")
    rev_running_state=$(echo "$rev_json" | jq -r '.runningState // "Unknown"')
    rev_replicas=$(echo "$rev_json" | jq -r '.replicas // "Unknown"')
fi

# ------------------------------------------------------------------------------
# 5. Evaluate Safe Application Health Check
# ------------------------------------------------------------------------------
# Safe rule: If replicas == 0, curling the external ingress triggers the HTTP
# scale rule in Azure Container Apps, spinning up a replica. The status command
# must NEVER scale or modify resources. Only probe if active replicas > 0 and DB is Ready.
app_health_status="SKIPPED"
app_health_detail="Application is scaled to zero / dormant (HTTP probe skipped to avoid scaling)"
app_healthy=false
h_storage="unknown"
h_db_degraded=false
h_db_reason=""
ai_runtime_mode="UNKNOWN"
ai_runtime_model="UNKNOWN"
ai_provider_status="UNKNOWN"

if [[ "$pg_state" == "Ready" && "$replica_count" -gt 0 && "$ca_fqdn" != "UNKNOWN" ]]; then
    if health_json=$(check_application_health "$ca_fqdn" 10); then
        app_healthy=true
        h_status=$(echo "$health_json" | jq -r '.status // "unknown"')
        h_storage=$(echo "$health_json" | jq -r '.storage // "unknown"')
        h_db_degraded=$(echo "$health_json" | jq -r '.database.degraded // false')
        h_db_reason=$(echo "$health_json" | jq -r '.database.degraded_reason // ""')
        ai_runtime_mode=$(echo "$health_json" | jq -r '.ai_provider.execution_mode // "UNKNOWN"')
        ai_runtime_model=$(echo "$health_json" | jq -r '.ai_provider.model_identifier // "UNKNOWN"')
        ai_provider_status=$(echo "$health_json" | jq -r '.ai_provider.status // "UNKNOWN"')

        app_health_status="HEALTHY"
        if [[ "$h_status" == "degraded" || "$h_db_degraded" == "true" ]]; then
            app_health_status="DEGRADED"
        fi
        app_health_detail="Status: ${h_status}, Storage: ${h_storage}, AI Mode: ${ai_runtime_mode}"
    else
        app_health_status="UNHEALTHY"
        app_health_detail="HTTP probe to https://${ca_fqdn}/health timed out or returned non-200"
    fi
elif [[ "$pg_state" != "Ready" ]]; then
    app_health_status="UNAVAILABLE"
    app_health_detail="PostgreSQL is not Ready (state: ${pg_state})"
fi

# ------------------------------------------------------------------------------
# 6. Inspect Azure OpenAI Account & Model Deployment (Strictly Read-Only)
# ------------------------------------------------------------------------------
oai_json=$(get_openai_account_details || echo "{}")
oai_name=$(echo "$oai_json" | jq -r '.name // "'"$OPENAI_ACCOUNT"'"')
oai_state=$(echo "$oai_json" | jq -r '.provisioningState // "NOT_PROVISIONED"')
oai_endpoint=$(echo "$oai_json" | jq -r '.endpoint // "'"$OPENAI_ENDPOINT"'"')
oai_loc=$(echo "$oai_json" | jq -r '.location // "'"$OPENAI_REGION"'"')
oai_sku=$(echo "$oai_json" | jq -r 'if (.sku | type) == "object" then (.sku.name // "Standard") else (.sku // "Standard") end')

dep_json=$(get_openai_deployment_details "$OPENAI_DEPLOYMENT" || echo "{}")
dep_state=$(echo "$dep_json" | jq -r '.provisioningState // "NOT_DEPLOYED"')
dep_model=$(echo "$dep_json" | jq -r '.model // "'"$OPENAI_MODEL"'"')
dep_ver=$(echo "$dep_json" | jq -r '.version // "'"$OPENAI_MODEL_VERSION"'"')

role_json=$(check_openai_role_assignment || echo "[]")
role_count=$(echo "$role_json" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo "0")
if [[ "$role_count" -gt 0 ]]; then
    rbac_status="ASSIGNED"
    rbac_detail="Cognitive Services OpenAI User assigned"
else
    rbac_status="MISSING"
    rbac_detail="Role 'Cognitive Services OpenAI User' missing for identity 'cloudpulse-identity'"
fi

# Determine truthful AI execution state
ai_eval_mode="LIVE"
if [[ "$ai_runtime_mode" != "UNKNOWN" ]]; then
    ai_eval_mode="$ai_runtime_mode"
else
    if [[ "$dep_state" != "Succeeded" ]]; then
        ai_eval_mode="FALLBACK"
        ai_runtime_mode="FALLBACK (Deployment not created; local synthesis active)"
    elif [[ "$rbac_status" == "MISSING" ]]; then
        ai_eval_mode="FALLBACK"
        ai_runtime_mode="FALLBACK (Identity role missing; local synthesis active)"
    else
        ai_eval_mode="CONFIGURED"
        ai_runtime_mode="DORMANT (Configured and ready)"
    fi
fi

# ------------------------------------------------------------------------------
# 7. Deployment Classification
# ------------------------------------------------------------------------------
overall_status="UNKNOWN"
if [[ "$replica_query_ok" == "true" ]]; then
    overall_status=$(classify_deployment \
        "$pg_state" \
        "$ca_prov_state" \
        "$ca_min" \
        "$ca_max" \
        "$replica_count" \
        "$rev_running_state" \
        "$app_healthy" \
        "$ai_eval_mode")
fi

# ------------------------------------------------------------------------------
# 8. Output Presentation
# ------------------------------------------------------------------------------
if [[ "$OUTPUT_JSON" == "true" ]]; then
    cat <<EOF
{
  "subscription": {
    "id": "${EXPECTED_SUBSCRIPTION_ID}",
    "resource_group": "${RESOURCE_GROUP}"
  },
  "overall_status": "${overall_status}",
  "database": {
    "server": "${POSTGRES_SERVER}",
    "state": "${pg_state}",
    "sku": "${pg_sku}",
    "version": "${pg_version}",
    "fqdn": "${pg_fqdn}",
    "storage": "${h_storage}",
    "degraded": ${h_db_degraded:-false}
  },
  "container_app": {
    "name": "${CONTAINER_APP}",
    "environment": "${ca_env_name}",
    "workload_profile": "${ca_workload_profile}",
    "provisioning_state": "${ca_prov_state}",
    "running_status": "${ca_run_status}",
    "min_replicas": ${ca_min:-0},
    "max_replicas": ${ca_max:-0},
    "latest_revision": "${ca_latest_rev}",
    "revision_running_state": "${rev_running_state}",
    "revision_replicas": ${rev_replicas:-0},
    "actual_replica_count": ${replica_count:-0},
    "replica_states": "${replica_states}",
    "fqdn": "${ca_fqdn}"
  },
  "azure_openai": {
    "account": "${oai_name}",
    "endpoint": "${oai_endpoint}",
    "provisioning_state": "${oai_state}",
    "region": "${oai_loc}",
    "sku": "${oai_sku}",
    "deployment_name": "${OPENAI_DEPLOYMENT}",
    "deployment_state": "${dep_state}",
    "intended_model": "${dep_model}",
    "model_version": "${dep_ver}",
    "rbac_status": "${rbac_status}",
    "rbac_detail": "${rbac_detail}",
    "runtime_execution_mode": "${ai_runtime_mode}",
    "model_identifier": "${ai_runtime_model}"
  },
  "application_health": {
    "status": "${app_health_status}",
    "detail": "${app_health_detail}"
  }
}
EOF
    exit 0
fi

# Terminal Human-Readable Report
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                     CloudPulse Azure Deployment Status                       ${COLOR_RESET}"
echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
echo -e "Subscription     : ${COLOR_CYAN}${EXPECTED_SUBSCRIPTION_ID}${COLOR_RESET}"
echo -e "Resource Group   : ${COLOR_CYAN}${RESOURCE_GROUP}${COLOR_RESET}"
echo -e "Location         : ${COLOR_CYAN}${AZURE_REGION}${COLOR_RESET}"

case "$overall_status" in
    ACTIVE)
        echo -e "Overall Status   : ${COLOR_BOLD}${COLOR_GREEN}● ACTIVE${COLOR_RESET} (Operational, dependencies ready, AI live)"
        ;;
    ACTIVE_DEGRADED)
        echo -e "Overall Status   : ${COLOR_BOLD}${COLOR_YELLOW}◐ ACTIVE (DEGRADED)${COLOR_RESET} (Core operational, AI in deterministic fallback)"
        ;;
    DORMANT)
        echo -e "Overall Status   : ${COLOR_BOLD}${COLOR_BLUE}○ DORMANT${COLOR_RESET} (Compute minimized, DB stopped, scale-to-zero)"
        ;;
    PARTIAL)
        echo -e "Overall Status   : ${COLOR_BOLD}${COLOR_YELLOW}◐ PARTIAL${COLOR_RESET} (In transition or subset of components active)"
        ;;
    *)
        echo -e "Overall Status   : ${COLOR_BOLD}${COLOR_RED}? UNKNOWN${COLOR_RESET} (State could not be verified conclusively)"
        ;;
esac

echo -e "\n${COLOR_BOLD}Database (Azure Database for PostgreSQL Flexible Server):${COLOR_RESET}"
echo -e "  Server Name    : ${POSTGRES_SERVER}"
if [[ "$pg_state" == "Ready" ]]; then
    echo -e "  State          : ${COLOR_GREEN}${pg_state}${COLOR_RESET}"
elif [[ "$pg_state" == "Stopped" ]]; then
    echo -e "  State          : ${COLOR_BLUE}${pg_state}${COLOR_RESET} (Auto-restart after 7 days if not started)"
else
    echo -e "  State          : ${COLOR_YELLOW}${pg_state}${COLOR_RESET}"
fi
echo -e "  SKU / Engine   : ${pg_sku} / PostgreSQL v${pg_version}"
echo -e "  Endpoint FQDN  : ${pg_fqdn}"
echo -e "  Storage Engine : ${h_storage}"
if [[ "$h_storage" == "in_memory" || "$h_db_degraded" == "true" ]]; then
    echo -e "  ${COLOR_BOLD}${COLOR_RED}⚠ STORAGE WARNING: Database is operating in ephemeral in-memory fallback!${COLOR_RESET}"
    echo -e "  ${COLOR_RED}  Records will be lost on Container App restart. Persistent PostgreSQL is disconnected.${COLOR_RESET}"
fi

echo -e "\n${COLOR_BOLD}Compute (Azure Container Apps):${COLOR_RESET}"
echo -e "  App Name       : ${CONTAINER_APP}"
echo -e "  Environment    : ${ca_env_name} (Profile: ${ca_workload_profile})"
echo -e "  Provisioning   : ${ca_prov_state}"
echo -e "  Running Status : ${ca_run_status} ${COLOR_YELLOW}(Note: administrative status, not active replicas)${COLOR_RESET}"
echo -e "  Scaling Limits : min=${ca_min}, max=${ca_max}"
echo -e "  Latest Revision: ${ca_latest_rev} (State: ${rev_running_state}, Replicas: ${rev_replicas})"
echo -e "  Active Replicas: ${COLOR_BOLD}${replica_count}${COLOR_RESET} (${replica_states})"
echo -e "  Ingress FQDN   : https://${ca_fqdn}"

echo -e "\n${COLOR_BOLD}AI Service (Azure OpenAI):${COLOR_RESET}"
echo -e "  Account Name   : ${oai_name} (State: ${oai_state}, Region: ${oai_loc})"
echo -e "  Endpoint FQDN  : ${oai_endpoint}"
if [[ "$dep_state" == "Succeeded" ]]; then
    echo -e "  Deployment     : ${OPENAI_DEPLOYMENT} (State: ${COLOR_GREEN}${dep_state}${COLOR_RESET}, Model: ${dep_model} v${dep_ver})"
else
    echo -e "  Deployment     : ${OPENAI_DEPLOYMENT} (${COLOR_YELLOW}${dep_state}${COLOR_RESET} - Model not deployed)"
fi
if [[ "$rbac_status" == "ASSIGNED" ]]; then
    echo -e "  Managed RBAC   : ${COLOR_GREEN}${rbac_status}${COLOR_RESET} (${rbac_detail})"
else
    echo -e "  Managed RBAC   : ${COLOR_YELLOW}${rbac_status}${COLOR_RESET} (${rbac_detail})"
fi
echo -e "  Execution Mode : ${COLOR_BOLD}${ai_runtime_mode}${COLOR_RESET}"

echo -e "\n${COLOR_BOLD}Application Health:${COLOR_RESET}"
echo -e "  Probe Status   : ${app_health_status}"
echo -e "  Details        : ${app_health_detail}"

if [[ "$overall_status" == "DORMANT" ]]; then
    echo -e "\n${COLOR_BOLD}${COLOR_BLUE}ℹ Cost-Saving Mode Active:${COLOR_RESET}"
    echo -e "  • Idle compute costs are currently minimized (0 replicas, DB stopped)."
    echo -e "  • Residual charges continue for retained storage (PostgreSQL 32GB, LAW, ACR images)."
    echo -e "  • Azure OpenAI account remains provisioned but incurs zero token inference charges when dormant."
    echo -e "  • To resume service, run: ${COLOR_BOLD}./scripts/cloudpulse-on.sh${COLOR_RESET}"
elif [[ "$overall_status" =~ "ACTIVE" ]]; then
    echo -e "\n${COLOR_BOLD}${COLOR_GREEN}✔ Service Operational:${COLOR_RESET}"
    echo -e "  Dashboard URL  : ${COLOR_BOLD}https://${ca_fqdn}/dashboard${COLOR_RESET}"
    if [[ "$overall_status" == "ACTIVE_DEGRADED" ]]; then
        echo -e "  ${COLOR_YELLOW}Note: AI is operating in deterministic FALLBACK mode. Core detection remains operational.${COLOR_RESET}"
    fi
    echo -e "  To shut down cleanly, run: ${COLOR_BOLD}./scripts/cloudpulse-off.sh${COLOR_RESET}"
elif [[ "$overall_status" == "PARTIAL" ]]; then
    echo -e "\n${COLOR_BOLD}${COLOR_YELLOW}⚠ Partial Deployment:${COLOR_RESET}"
    echo -e "  Some components are running while others are stopped."
    echo -e "  To achieve ACTIVE state : ${COLOR_BOLD}./scripts/cloudpulse-on.sh${COLOR_RESET}"
    echo -e "  To return to DORMANT   : ${COLOR_BOLD}./scripts/cloudpulse-off.sh${COLOR_RESET}"
fi

echo -e "${COLOR_BOLD}==============================================================================${COLOR_RESET}"
