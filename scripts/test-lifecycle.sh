#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle - Test Suite Runner
#
# Executes the lifecycle unit test suite (23 tests) validating ON, OFF, and STATUS
# behavior against mocked Azure CLI responses with zero Azure cloud mutations.
# ==============================================================================

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTEST="${BASE_DIR}/services/detection-worker/.venv/bin/pytest"

if [[ -f "$VENV_PYTEST" ]]; then
    PYTEST_BIN="$VENV_PYTEST"
elif command -v pytest >/dev/null 2>&1; then
    PYTEST_BIN="pytest"
else
    echo "Error: pytest not found at ${VENV_PYTEST} or on PATH" >&2
    exit 1
fi

echo "=============================================================================="
echo "      Running CloudPulse Azure Lifecycle Test Suite (Mocked Azure CLI)        "
echo "=============================================================================="

PYTHONPATH="${BASE_DIR}" "$PYTEST_BIN" "${BASE_DIR}/tests/test_azure_lifecycle.py" -v "$@"
