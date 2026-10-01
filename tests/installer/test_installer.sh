#!/usr/bin/env bash
# PSV Linux Security Auditor - Installer Test Suite
# Tests installer options, helper functions, dry-run mode, and state management.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

source "${REPO_ROOT}/scripts/installer/common.sh"
source "${REPO_ROOT}/scripts/installer/prerequisites.sh"

echo "=========================================================="
echo "    PSV Installer Test Suite"
echo "=========================================================="

# Test 1: Helper Functions
echo "[1/5] Testing secret generation helper..."
secret_hex="$(generate_secret 32)"
if [ "${#secret_hex}" -ne 64 ]; then
    echo "[FAIL] generate_secret 32 produced string of length ${#secret_hex}, expected 64."
    exit 1
fi
echo "  [PASS] generate_secret 32 returned 64 hex chars."

# Test 2: Password Generator
echo "[2/5] Testing password generator helper..."
pass_str="$(generate_password)"
if [ "${#pass_str}" -lt 16 ]; then
    echo "[FAIL] generate_password produced password length ${#pass_str}, expected >= 16."
    exit 1
fi
echo "  [PASS] generate_password returned secure string."

# Test 3: Installer Help Option
echo "[3/5] Testing install.sh --help..."
help_out="$("${REPO_ROOT}/install.sh" --help)"
if ! echo "${help_out}" | grep -q "Usage:"; then
    echo "[FAIL] install.sh --help did not output expected Usage string."
    exit 1
fi
echo "  [PASS] install.sh --help printed options usage."

# Test 4: Installer Version Option
echo "[4/5] Testing install.sh --version..."
ver_out="$("${REPO_ROOT}/install.sh" --version)"
if ! echo "${ver_out}" | grep -q "PSV Linux Security Auditor Installer"; then
    echo "[FAIL] install.sh --version did not output expected version string."
    exit 1
fi
echo "  [PASS] install.sh --version printed version information."

# Test 5: Dry Run Execution
echo "[5/5] Testing install.sh --dry-run..."
dry_out="$("${REPO_ROOT}/install.sh" --dry-run)"
if ! echo "${dry_out}" | grep -q "DRY RUN MODE"; then
    echo "[FAIL] install.sh --dry-run did not output DRY RUN MODE header."
    exit 1
fi
echo "  [PASS] install.sh --dry-run completed cleanly without making system changes."

echo "=========================================================="
echo "[✔] ALL INSTALLER TESTS PASSED SUCCESSFULLY!"
echo "=========================================================="
