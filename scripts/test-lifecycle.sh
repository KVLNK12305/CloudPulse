#!/usr/bin/env bash
# ==============================================================================
# CloudPulse Azure Lifecycle - Test Suite Runner
#
# Executes the lifecycle unit test suite (16 tests) validating ON, OFF, and STATUS
# behavior against mocked Azure CLI responses with zero Azure cloud mutations.
# ==============================================================================

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTEST="${BASE_DIR}/services/detection-worker/.venv/bin/pytest"

if [[ ! -f "$VENV_PYTEST" ]]; then
    echo "Error: Virtual environment pytest not found at ${VENV_PYTEST}" >&2
    exit 1
fi

echo "=============================================================================="
echo "      Running CloudPulse Azure Lifecycle Test Suite (Mocked Azure CLI)        "
echo "=============================================================================="

PYTHONPATH="${BASE_DIR}" "$VENV_PYTEST" "${BASE_DIR}/tests/test_azure_lifecycle.py" -v "$@"
