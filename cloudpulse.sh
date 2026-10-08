#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Management Script
# Commands: start | stop | restart | status | reset | seed | logs | test
# ==============================================================================

set -eo pipefail

PORT=8080
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$BASE_DIR/services/detection-worker/.venv/bin/python"
APP_SCRIPT="$BASE_DIR/services/detection-worker/app.py"
PID_FILE="$BASE_DIR/.cloudpulse.pid"
LOG_FILE="$BASE_DIR/cloudpulse.log"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper: Find PID listening on PORT
find_port_pid() {
    lsof -ti :"$PORT" 2>/dev/null || ss -tulpn 2>/dev/null | grep ":$PORT " | awk -F'pid=' '{print $2}' | awk -F',' '{print $1}' || true
}

# ------------------------------------------------------------------------------
# STATUS
# ------------------------------------------------------------------------------
status() {
    echo -e "${BOLD}${CYAN}🔍 Checking CloudPulse Status...${NC}"
    local active_pid
    active_pid=$(find_port_pid)

    if [ -n "$active_pid" ]; then
        echo -e "   ${GREEN}● CloudPulse is RUNNING${NC} (PID: $active_pid on port $PORT)"
        if curl -s "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
            echo -e "   ${GREEN}✔ Health Check:${NC} Healthy"
            echo -e "   ${CYAN}🌐 Web Dashboard:${NC} http://127.0.0.1:$PORT/dashboard"
        else
            echo -e "   ${YELLOW}⚠ Process is listening, but /health is not responding yet.${NC}"
        fi
        return 0
    else
        echo -e "   ${RED}○ CloudPulse is STOPPED${NC} (No process on port $PORT)"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# STOP
# ------------------------------------------------------------------------------
stop() {
    echo -e "${BOLD}${YELLOW}🛑 Stopping CloudPulse...${NC}"
    local pids
    pids=$(find_port_pid)

    if [ -n "$pids" ]; then
        for pid in $pids; do
            echo -e "   Killing process $pid on port $PORT..."
            kill "$pid" 2>/dev/null || true
        done
        sleep 1

        # Force kill if still lingering
        local remaining
        remaining=$(find_port_pid)
        if [ -n "$remaining" ]; then
            echo -e "   Force stopping lingering processes: $remaining..."
            kill -9 $remaining 2>/dev/null || true
        fi
        echo -e "   ${GREEN}✔ Successfully stopped CloudPulse on port $PORT.${NC}"
    else
        echo -e "   ${YELLOW}CloudPulse was not running.${NC}"
    fi

    rm -f "$PID_FILE"
}

# ------------------------------------------------------------------------------
# START
# ------------------------------------------------------------------------------
start() {
    echo -e "${BOLD}${CYAN}🚀 Starting CloudPulse Backend Daemon...${NC}"

    local existing_pid
    existing_pid=$(find_port_pid)
    if [ -n "$existing_pid" ]; then
        echo -e "   ${YELLOW}⚠ Port $PORT is already in use by PID $existing_pid.${NC}"
        echo -e "   Run ${BOLD}./cloudpulse.sh restart${NC} to restart it."
        return 0
    fi

    if [ ! -f "$VENV_PYTHON" ]; then
        echo -e "   ${RED}❌ Virtual environment not found at $VENV_PYTHON${NC}"
        exit 1
    fi

    # Launch daemon in background
    cd "$BASE_DIR"
    nohup env PYTHONPATH="services/detection-worker" "$VENV_PYTHON" "$APP_SCRIPT" > "$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"

    echo -e "   Spawned CloudPulse process (PID: $new_pid). Waiting for health check..."

    # Poll health for up to 10 seconds
    local max_retries=20
    local count=0
    while [ $count -lt $max_retries ]; do
        if curl -s "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
            echo -e "   ${GREEN}✔ CloudPulse is LIVE and HEALTHY!${NC}"
            echo -e "   ${BOLD}${GREEN}🌐 Open in browser:${NC} ${BOLD}http://127.0.0.1:$PORT/dashboard${NC}"
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done

    echo -e "   ${RED}❌ Server did not respond within 10 seconds. Check logs:${NC}"
    tail -n 20 "$LOG_FILE"
    exit 1
}

# ------------------------------------------------------------------------------
# RESTART
# ------------------------------------------------------------------------------
restart() {
    echo -e "${BOLD}${CYAN}🔄 Restarting CloudPulse...${NC}"
    stop
    sleep 1
    start
}

# ------------------------------------------------------------------------------
# SEED
# ------------------------------------------------------------------------------
seed() {
    echo -e "${BOLD}${CYAN}⚡ Seeding Real-Life Breach & FinOps Data...${NC}"
    if ! find_port_pid >/dev/null 2>&1; then
        echo -e "   ${YELLOW}Server is not running. Starting server first...${NC}"
        start
    fi
    "$VENV_PYTHON" "$BASE_DIR/scripts/seed_demo_scenario.py"
}

# ------------------------------------------------------------------------------
# RESET
# ------------------------------------------------------------------------------
reset() {
    echo -e "${BOLD}${CYAN}♻ Resetting CloudPulse to Clean State & Seeding Fresh Data...${NC}"
    restart
    seed
    echo -e "\n${BOLD}${GREEN}✔ Complete Reset Done! Dashboard ready with fresh data:${NC}"
    echo -e "   ${BOLD}http://127.0.0.1:$PORT/dashboard${NC}"
}

# ------------------------------------------------------------------------------
# LOGS
# ------------------------------------------------------------------------------
logs() {
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    fi
    echo -e "${BOLD}${CYAN}📋 Streaming CloudPulse Logs (Ctrl+C to exit)...${NC}"
    tail -f "$LOG_FILE"
}

# ------------------------------------------------------------------------------
# TEST
# ------------------------------------------------------------------------------
test() {
    echo -e "${BOLD}${CYAN}🧪 Running 250 Test Suite Verification...${NC}"
    PYTHONPATH=services/detection-worker "$BASE_DIR/services/detection-worker/.venv/bin/pytest" services/detection-worker/tests/ -q
}

# ------------------------------------------------------------------------------
# MAIN DISPATCH
# ------------------------------------------------------------------------------
case "${1:-}" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    seed)
        seed
        ;;
    reset)
        reset
        ;;
    logs)
        logs
        ;;
    test)
        test
        ;;
    *)
        echo -e "${BOLD}CloudPulse Service Controller${NC}"
        echo -e "Usage: ${BOLD}./cloudpulse.sh [command]${NC}\n"
        echo -e "Commands:"
        echo -e "  ${GREEN}start${NC}    - Start CloudPulse daemon on port $PORT"
        echo -e "  ${YELLOW}stop${NC}     - Stop running CloudPulse process on port $PORT"
        echo -e "  ${CYAN}restart${NC}  - Stop and start fresh backend on port $PORT"
        echo -e "  ${GREEN}reset${NC}    - Restart backend and re-seed clean real-life demo data"
        echo -e "  ${CYAN}seed${NC}     - Ingest real-life breach & FinOps demo telemetry"
        echo -e "  ${BOLD}status${NC}   - Check process and HTTP health status"
        echo -e "  ${BOLD}logs${NC}     - Tail application log output ($LOG_FILE)"
        echo -e "  ${BOLD}test${NC}     - Run pytest suite (250/250 tests)"
        exit 1
        ;;
esac
