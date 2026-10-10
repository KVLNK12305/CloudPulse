#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle Management - Shared Common Library
#
# Provides strict shell settings, logging, prerequisite checks,
# Azure CLI wrapper utilities, status classification, and polling helpers.
# ==============================================================================

# Strict shell execution settings
set -euo pipefail

# ------------------------------------------------------------------------------
# Terminal Formatting & Colors
# ------------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
    COLOR_RESET='\033[0m'
    COLOR_BOLD='\033[1m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[1;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_MAGENTA='\033[0;35m'
    COLOR_CYAN='\033[0;36m'
else
    COLOR_RESET=''
    COLOR_BOLD=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_BLUE=''
    COLOR_MAGENTA=''
    COLOR_CYAN=''
fi

# ------------------------------------------------------------------------------
# Default Deployment Configuration
# ------------------------------------------------------------------------------
EXPECTED_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-90b900ea-4273-4b40-a343-091aecfe2911}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-cloudpulse-rg}"
AZURE_REGION="${AZURE_REGION:-centralindia}"
POSTGRES_SERVER="${POSTGRES_SERVER_NAME:-cloudpulse-postgres01}"
CONTAINER_APP="${CONTAINER_APP_NAME:-cloudpulse-detection-worker}"
INTENDED_MIN_REPLICAS="${INTENDED_MIN_REPLICAS:-0}"
INTENDED_MAX_REPLICAS="${INTENDED_MAX_REPLICAS:-1}"

# Azure OpenAI Resource Configuration
OPENAI_ACCOUNT="${OPENAI_ACCOUNT_NAME:-cloudpulse-openai01}"
OPENAI_DEPLOYMENT="${OPENAI_DEPLOYMENT_NAME:-cloudpulse-triage}"
OPENAI_REGION="${OPENAI_REGION:-southeastasia}"
OPENAI_ENDPOINT="${AZURE_OPENAI_ENDPOINT:-https://${OPENAI_ACCOUNT}.openai.azure.com/}"
OPENAI_MODEL="${OPENAI_MODEL_NAME:-gpt-4.1-mini}"
OPENAI_MODEL_VERSION="${OPENAI_MODEL_VERSION:-2025-04-14}"
CONTAINER_APP_CLIENT_ID="${AZURE_CLIENT_ID:-070f1ae7-4c94-4a4f-83a1-5b56a86b14aa}"
CONTAINER_APP_PRINCIPAL_ID="${AZURE_PRINCIPAL_ID:-e3d36ac0-8174-4213-8a00-896b18c66440}"

# Default timeouts and intervals (seconds)
POSTGRES_TIMEOUT_SECONDS="${POSTGRES_TIMEOUT_SECONDS:-300}"
REPLICA_TIMEOUT_SECONDS="${REPLICA_TIMEOUT_SECONDS:-180}"
ACTIVATION_TIMEOUT_SECONDS="${ACTIVATION_TIMEOUT_SECONDS:-180}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-5}"
DRY_RUN="${DRY_RUN:-false}"

# ------------------------------------------------------------------------------
# Structured Logging Utilities
# ------------------------------------------------------------------------------
_log_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log_info() {
    echo -e "${COLOR_BLUE}[$(_log_timestamp)] [INFO]${COLOR_RESET} $*"
}

log_step() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}[$(_log_timestamp)] [STEP]${COLOR_RESET} ${COLOR_BOLD}$*${COLOR_RESET}"
}

log_success() {
    echo -e "${COLOR_BOLD}${COLOR_GREEN}[$(_log_timestamp)] [SUCCESS]${COLOR_RESET} $*"
}

log_warn() {
    echo -e "${COLOR_BOLD}${COLOR_YELLOW}[$(_log_timestamp)] [WARN]${COLOR_RESET} $*" >&2
}

log_error() {
    echo -e "${COLOR_BOLD}${COLOR_RED}[$(_log_timestamp)] [ERROR]${COLOR_RESET} $*" >&2
}

log_dry_run() {
    echo -e "${COLOR_BOLD}${COLOR_MAGENTA}[$(_log_timestamp)] [DRY-RUN]${COLOR_RESET} $*"
}

# ------------------------------------------------------------------------------
# Argument Parsing Helper
# ------------------------------------------------------------------------------
parse_common_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run|-n)
                DRY_RUN="true"
                shift
                ;;
            --subscription|-s)
                if [[ -z "${2:-}" ]]; then
                    log_error "Missing value for --subscription"
                    return 1
                fi
                EXPECTED_SUBSCRIPTION_ID="$2"
                shift 2
                ;;
            --resource-group|-g)
                if [[ -z "${2:-}" ]]; then
                    log_error "Missing value for --resource-group"
                    return 1
                fi
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            --timeout|-t)
                if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
                    log_error "Invalid or missing value for --timeout (must be positive integer)"
                    return 1
                fi
                POSTGRES_TIMEOUT_SECONDS="$2"
                REPLICA_TIMEOUT_SECONDS="$2"
                ACTIVATION_TIMEOUT_SECONDS="$2"
                shift 2
                ;;
            --openai-account)
                if [[ -z "${2:-}" ]]; then
                    log_error "Missing value for --openai-account"
                    return 1
                fi
                OPENAI_ACCOUNT="$2"
                OPENAI_ENDPOINT="https://${OPENAI_ACCOUNT}.openai.azure.com/"
                shift 2
                ;;
            --deployment)
                if [[ -z "${2:-}" ]]; then
                    log_error "Missing value for --deployment"
                    return 1
                fi
                OPENAI_DEPLOYMENT="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Prerequisite Verification
# ------------------------------------------------------------------------------
check_required_tools() {
    local missing_tools=()
    for tool in az jq curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Required CLI tools missing: ${missing_tools[*]}."
        log_error "Please install the missing tools and ensure they are on PATH."
        return 1
    fi
    return 0
}

check_azure_auth() {
    local account_json
    if ! account_json=$(az account show -o json 2>&1); then
        log_error "Azure authentication failed. Not logged in to Azure CLI."
        log_error "Details: ${account_json}"
        log_error "Please run 'az login' to authenticate before executing lifecycle commands."
        return 1
    fi
    return 0
}

verify_subscription() {
    local active_sub_id
    active_sub_id=$(az account show --query "id" -o tsv 2>/dev/null || true)
    if [[ -z "$active_sub_id" ]]; then
        log_error "Failed to retrieve active Azure subscription ID."
        return 1
    fi

    if [[ "$active_sub_id" != "$EXPECTED_SUBSCRIPTION_ID" ]]; then
        log_error "Subscription context mismatch!"
        log_error "  Active subscription : '${active_sub_id}'"
        log_error "  Expected subscription: '${EXPECTED_SUBSCRIPTION_ID}'"
        log_error "To prevent unintended mutations, silent subscription switching is strictly forbidden."
        log_error "Switch explicitly using: az account set --subscription '${EXPECTED_SUBSCRIPTION_ID}'"
        return 1
    fi

    local active_sub_name
    active_sub_name=$(az account show --query "name" -o tsv 2>/dev/null || echo "Unknown")
    if [[ "${OUTPUT_JSON:-false}" != "true" ]]; then
        log_info "Verified subscription context: ${active_sub_name} (${active_sub_id})"
    fi
    return 0
}

verify_resource_group() {
    if ! az group show --name "$RESOURCE_GROUP" -o none 2>/dev/null; then
        log_error "Target resource group '${RESOURCE_GROUP}' does not exist in subscription '${EXPECTED_SUBSCRIPTION_ID}'."
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Resource Inspection Helpers (Read-Only)
# ------------------------------------------------------------------------------
get_postgres_details() {
    az postgres flexible-server show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$POSTGRES_SERVER" \
        --query "{state:state, fqdn:fullyQualifiedDomainName, version:version, sku:sku.name}" \
        -o json 2>/dev/null
}

get_container_app_details() {
    az containerapp show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_APP" \
        --query "{provisioningState:properties.provisioningState, runningStatus:properties.runningStatus, fqdn:properties.configuration.ingress.fqdn, minReplicas:properties.template.scale.minReplicas, maxReplicas:properties.template.scale.maxReplicas, latestRevisionName:properties.latestRevisionName, latestReadyRevisionName:properties.latestReadyRevisionName, workloadProfileName:properties.workloadProfileName, environmentId:properties.environmentId}" \
        -o json 2>/dev/null
}

# Safe replica listing distinguishing Azure CLI command failures from genuine empty lists
get_replica_list() {
    local revision="${1:-}"
    local cmd=(az containerapp replica list --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_APP" -o json)
    if [[ -n "$revision" ]]; then
        cmd+=(--revision "$revision")
    fi

    local output
    local exit_code=0
    output=$("${cmd[@]}" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_error "Failed to query replica list for Container App '${CONTAINER_APP}'."
        log_error "CLI output: ${output}"
        return $exit_code
    fi

    echo "$output"
}

get_revision_details() {
    local revision="$1"
    az containerapp revision show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CONTAINER_APP" \
        --revision "$revision" \
        --query "{active:properties.active, provisioningState:properties.provisioningState, runningState:properties.runningState, replicas:properties.replicas, healthState:properties.healthState}" \
        -o json 2>/dev/null
}

# Azure OpenAI Resource Inspection Helpers (Strictly Read-Only)
get_openai_account_details() {
    az cognitiveservices account show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$OPENAI_ACCOUNT" \
        --query "{name:name, provisioningState:properties.provisioningState, endpoint:properties.endpoint, location:location, kind:kind, sku:sku.name}" \
        -o json 2>/dev/null
}

get_openai_deployment_details() {
    local deployment_name="${1:-$OPENAI_DEPLOYMENT}"
    az cognitiveservices account deployment show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$OPENAI_ACCOUNT" \
        --deployment-name "$deployment_name" \
        --query "{name:name, provisioningState:properties.provisioningState, model:properties.model.name, version:properties.model.version, format:properties.model.format, sku:sku.name, capacity:sku.capacity}" \
        -o json 2>/dev/null
}

list_openai_deployments() {
    az cognitiveservices account deployment list \
        --resource-group "$RESOURCE_GROUP" \
        --name "$OPENAI_ACCOUNT" \
        --query "[].{name:name, provisioningState:properties.provisioningState, model:properties.model.name, version:properties.model.version}" \
        -o json 2>/dev/null
}

check_openai_role_assignment() {
    local principal_id="${1:-$CONTAINER_APP_PRINCIPAL_ID}"
    az role assignment list \
        --assignee "$principal_id" \
        --all \
        --query "[?roleDefinitionName=='Cognitive Services OpenAI User' || roleDefinitionName=='Cognitive Services OpenAI Contributor'].{role:roleDefinitionName, scope:scope}" \
        -o json 2>/dev/null
}

# ------------------------------------------------------------------------------
# Application Health Check Helper
# ------------------------------------------------------------------------------
check_application_health() {
    local fqdn="$1"
    local timeout="${2:-10}"
    local health_url="https://${fqdn}/health"

    local response
    local http_code=0
    response=$(curl -sk -w "\n%{http_code}" --connect-timeout 5 --max-time "$timeout" "$health_url" 2>/dev/null) || true
    
    http_code=$(echo "$response" | tail -n 1)
    local body
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "200" ]]; then
        echo "$body"
        return 0
    else
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Status Classification Logic
# ------------------------------------------------------------------------------
classify_deployment() {
    local pg_state="$1"
    local ca_provisioning="$2"
    local ca_min="$3"
    local ca_max="$4"
    local replica_count="$5"
    local rev_running_state="$6"
    local app_healthy="$7"
    local ai_mode="${8:-LIVE}"

    # ACTIVE: dependencies ready and application health check passes
    if [[ "$pg_state" == "Ready" && "$ca_provisioning" == "Succeeded" && "$app_healthy" == "true" ]]; then
        if [[ "$ai_mode" == "FALLBACK" || "$ai_mode" == "UNAVAILABLE" || "$ai_mode" == "DEGRADED" || "$ai_mode" == "NOT_DEPLOYED" ]]; then
            echo "ACTIVE_DEGRADED"
            return 0
        fi
        echo "ACTIVE"
        return 0
    fi

    # DORMANT: PostgreSQL stopped, Container App scale-to-zero configured, no active replicas
    if [[ "$pg_state" == "Stopped" && "$ca_min" == "0" && "$replica_count" == "0" ]]; then
        if [[ "$rev_running_state" == "ScaledToZero" || "$rev_running_state" == "Stopped" || "$ca_max" == "0" ]]; then
            echo "DORMANT"
            return 0
        fi
    fi

    # Check for known PARTIAL states
    if [[ "$pg_state" == "Ready" || "$pg_state" == "Stopped" || "$ca_provisioning" == "Succeeded" ]]; then
        echo "PARTIAL"
        return 0
    fi

    echo "UNKNOWN"
}
