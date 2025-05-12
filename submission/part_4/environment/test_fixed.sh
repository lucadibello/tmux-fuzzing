#!/bin/bash
set -euo pipefail

# Source the common test script
source ./run_tmux_cve_test.sh

# Run the test for the fixed version
run_tmux_test \
  "25cae5d8f01d0deb050243842ed5d967b3dc411" \
  "fixed version (3.1c)" \
  "Expecting NO crash for the fixed version." \
  20 # 20s timeout
