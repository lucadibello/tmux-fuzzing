#!/bin/bash
set -euo pipefail

# Source the common test script
source ./run_tmux_cve_test.sh

# Run the test for the fixed version
run_tmux_test \
  "a868bacb46e3c900530bed47a1c6f85b0fbe701c" \
  "fixed version (3.1c)" \
  "Expecting NO crash for the fixed version." \
  20 # 20s timeout
