#!/usr/bin/env bash
set -euo pipefail

# --- Core Fuzzing Logic ---
# This script expects all configuration variables to be set as environment variables
# before it is called.

# --- Validate Required Variables ---
# These are variables that MUST be set by the calling script or have sane defaults here.
PROJECT=${PROJECT:-"tmux"}
HARNESS=${HARNESS:?"HARNESS variable must be set (e.g., input-fuzzer, cmd-fuzzer)"}
ENGINE=${ENGINE:-"libfuzzer"}
SANITIZER=${SANITIZER:-"address"}
RUNTIME=${RUNTIME:-14400} # Default 4 hours
LABEL=${LABEL:?"LABEL variable must be set (e.g., w_corpus, wo_corpus, improve1_cmd-fuzzer)"}
# PATCH_FILE can be empty if no patch is needed for a specific run
PATCH_FILE=${PATCH_FILE:-""}
# APPLY_PATCH_TO can be "oss-fuzz" or "project" or ""
APPLY_PATCH_TO=${APPLY_PATCH_TO:-"oss-fuzz"}
# REMOVE_CORPUS_BEFORE_BUILD can be "true" (default) or "false"
REMOVE_CORPUS_BEFORE_BUILD=${REMOVE_CORPUS_BEFORE_BUILD:-"true"}
# OSS_FUZZ_PROJECT_DIR is the specific project directory within oss-fuzz, e.g., projects/tmux
OSS_FUZZ_PROJECT_DIR_NAME=${OSS_FUZZ_PROJECT_DIR_NAME:-"tmux"}

# --- Optional Variables with Defaults ---
REBUILD_IMAGE=${REBUILD_IMAGE:-"true"}
ROOT_DIR=${ROOT_DIR:-"$(pwd)"}
EXPORT_RESULTS=${EXPORT_RESULTS:-"true"}
CORPUS_EXPORT_DIR_BASE=${CORPUS_EXPORT_DIR_BASE:-"${ROOT_DIR}/experiments"}
COVERAGE_EXPORT_DIR_BASE=${COVERAGE_EXPORT_DIR_BASE:-"${ROOT_DIR}/submission"} # e.g. submission/part1 or submission/part3/improve1
# LIBFUZZER_FLAGS can be overridden by the caller if needed
DEFAULT_LIBFUZZER_FLAGS="\
  -max_total_time=$RUNTIME \
  -timeout=25 \
  -print_final_stats=1 \
  -ignore_crashes=1 \
  -artifact_prefix=./crashes/" # Note: ./crashes is relative to where the fuzzer runs
LIBFUZZER_FLAGS="${LIBFUZZER_FLAGS:-$DEFAULT_LIBFUZZER_FLAGS}"

# --- Derived Variables ---
OSS_FUZZ_DIR="${ROOT_DIR}/oss-fuzz" # where to store OSS-Fuzz repo
OSS_FUZZ_PROJECT_PATH="${OSS_FUZZ_DIR}/projects/${OSS_FUZZ_PROJECT_DIR_NAME}"
BUILD_WORK_CORPUS_DIR="${OSS_FUZZ_DIR}/build/work/${PROJECT}/fuzzing_corpus" # Used by helper.py run_fuzzer
ARTIFACT_DIR="${OSS_FUZZ_DIR}/build/out/${PROJECT}/crashes"

TS=$(date +%Y%m%d_%H%M%S)
FINAL_CORPUS_EXPORT_PATH="${CORPUS_EXPORT_DIR_BASE}/${TS}_${LABEL}_corpus"
FINAL_COVERAGE_EXPORT_PATH="${COVERAGE_EXPORT_DIR_BASE}/${TS}_${LABEL}_coverage"

# --- Script Body ---
echo "========================================================================"
echo "Starting Fuzzing Run: Project=${PROJECT}, Harness=${HARNESS}, Label=${LABEL}"
echo "Runtime: ${RUNTIME}s, Sanitizer: ${SANITIZER}"
echo "OSS-Fuzz Directory: ${OSS_FUZZ_DIR}"
echo "Patch File: ${PATCH_FILE:-"None"}, Apply Patch To: ${APPLY_PATCH_TO:-"None"}"
echo "========================================================================"

# 0. Clone OSS-Fuzz if it doesn't exist
if [ ! -d "$OSS_FUZZ_DIR" ]; then
  echo "Cloning OSS-Fuzz repository..."
  # Ensure you have SSH keys for git@github.com or change to https if preferred
  git clone https://github.com/google/oss-fuzz.git "$OSS_FUZZ_DIR"
else
  echo "OSS-Fuzz directory already exists."
fi

# Navigate to OSS-Fuzz directory for subsequent operations
cd "$OSS_FUZZ_DIR" || {
  echo "Failed to cd to $OSS_FUZZ_DIR"
  exit 1
}

# Reset OSS-Fuzz and project repos to a clean state before applying any patches for this run
echo "Resetting OSS-Fuzz git repository to HEAD..."
if [ -d "${OSS_FUZZ_PROJECT_PATH}/${PROJECT}" ]; then
  echo "Resetting project ${PROJECT} OSS-Fuzz project to HEAD..."
  (cd "${OSS_FUZZ_PROJECT_PATH}/${PROJECT}" && git reset --hard HEAD && git clean -fdx)
fi

# First, we need to apply the patch to oss-fuzz itself (in the same directory as the script we are currently running)
BASE_DIR=$(dirname "$0")
if [ -f "$BASE_DIR/oss-fuzz.diff" ]; then
  echo "Applying patch to OSS-Fuzz..."
  git apply "$BASE_DIR/oss-fuzz.diff" || {
    echo "Failed to apply patch to OSS-Fuzz"
    exit 1
  }
else
  echo "No patch file found for OSS-Fuzz. This step is required to prepare the environment. NOTE: if you don't want to apply a patch, please create an empty oss-fuzz.diff file."
  exit 1
fi

# Apply patch if specified
if [ -n "$PATCH_FILE" ] && [ -f "${ROOT_DIR}/${PATCH_FILE}" ]; then
  echo "Applying patch: ${PATCH_FILE}"
  if [ "$APPLY_PATCH_TO" == "oss-fuzz" ]; then
    git apply "${ROOT_DIR}/${PATCH_FILE}" || {
      echo "Failed to apply patch to OSS-Fuzz"
      exit 1
    }
  elif [ "$APPLY_PATCH_TO" == "project" ] && [ -d "${OSS_FUZZ_PROJECT_PATH}/${PROJECT}" ]; then
    (cd "${OSS_FUZZ_PROJECT_PATH}/${PROJECT}" && git apply "${ROOT_DIR}/${PATCH_FILE}") || {
      echo "Failed to apply patch to project ${PROJECT}"
      exit 1
    }
  elif [ -n "$APPLY_PATCH_TO" ]; then
    echo "Warning: Unknown APPLY_PATCH_TO value: ${APPLY_PATCH_TO}. Patch not applied."
  else
    echo "APPLY_PATCH_TO not set, applying patch to current directory (OSS-Fuzz root)."
    git apply "${ROOT_DIR}/${PATCH_FILE}" || {
      echo "Failed to apply patch to OSS-Fuzz (default)"
      exit 1
    }
  fi
  echo "Patch applied successfully."
elif [ -n "$PATCH_FILE" ]; then
  echo "Warning: Patch file ${ROOT_DIR}/${PATCH_FILE} not found. Skipping patch application."
fi

# 1. Build OSS-Fuzz Docker image (conditionally)
if [ "$REBUILD_IMAGE" == "true" ]; then
  echo "Rebuilding Docker image for project ${PROJECT}..."
  rm -rf "$OSS_FUZZ_DIR/build" # Clean previous full build to ensure image is new
  python3 infra/helper.py build_image "$PROJECT" --pull || {
    echo "Build image failed"
    exit 1
  }
fi

# ensure crashes directory is present
mkdir -p "${ARTIFACT_DIR}" # ensure artifact directory exists

# 2. Build fuzzers
echo "Building fuzzers for ${PROJECT} with sanitizer ${SANITIZER}..."
# Optionally remove specific corpus dir for this project before building fuzzers,
# if the build script populates it and you want it clean for "no seed" runs.
if [ "$REMOVE_CORPUS_BEFORE_BUILD" == "true" ]; then
  echo "Removing existing build-time corpus directory: ${BUILD_WORK_CORPUS_DIR}"
  rm -rf "${BUILD_WORK_CORPUS_DIR}"
fi
python3 infra/helper.py build_fuzzers "$PROJECT" --sanitizer "$SANITIZER" || {
  echo "Build fuzzers failed"
  exit 1
}
echo "Fuzzers built successfully."

# 3. Run the fuzzer
echo "Running fuzzer ${HARNESS} for project ${PROJECT}..."
echo "Fuzzer flags: ${LIBFUZZER_FLAGS}"
# Note: infra/helper.py run_fuzzer uses build/work/<project>/fuzzing_corpus as its working dir for corpus input/output
python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir "${BUILD_WORK_CORPUS_DIR}" \
  "$PROJECT" "$HARNESS" -- \
  "$LIBFUZZER_FLAGS" || echo "Fuzzer run completed (may have found crashes, or exited normally)."

# 4. Stop Docker (important before generating coverage with a potentially different sanitizer image)
if [ "$EXPORT_RESULTS" == "true" ]; then
  echo "Exporting generated corpus to ${FINAL_CORPUS_EXPORT_PATH}..."
  mkdir -p "$(dirname "${FINAL_CORPUS_EXPORT_PATH}")"
  # Copy the contents of the dynamic corpus directory, not the directory itself
  # The corpus is generated in BUILD_WORK_CORPUS_DIR by the fuzzer run
  if [ -d "${BUILD_WORK_CORPUS_DIR}" ]; then
    cp -r "${BUILD_WORK_CORPUS_DIR}" "${FINAL_CORPUS_EXPORT_PATH}"
    # Optional: Zip the exported corpus
    (cd "$(dirname "${FINAL_CORPUS_EXPORT_PATH}")" && zip -qr "${FINAL_CORPUS_EXPORT_PATH}.zip" "$(basename "${FINAL_CORPUS_EXPORT_PATH}")" && rm -rf "${FINAL_CORPUS_EXPORT_PATH}")
    echo "Corpus exported and zipped to ${FINAL_CORPUS_EXPORT_PATH}.zip"
  else
    echo "Warning: Corpus directory ${BUILD_WORK_CORPUS_DIR} not found for export."
  fi
fi

# 5. Generate HTML coverage report
echo "Rebuilding fuzzers for coverage for ${PROJECT} (Harness: ${HARNESS})..."
python3 infra/helper.py build_fuzzers "$PROJECT" --sanitizer coverage || {
  echo "Build fuzzers for coverage failed"
  exit 1
}

echo "Generating coverage report..."
# The corpus used for coverage should be the one generated by the preceding fuzz run
python3 infra/helper.py coverage \
  --corpus-dir "${BUILD_WORK_CORPUS_DIR}" \
  --fuzz-target "$HARNESS" \
  "$PROJECT" &
COVERAGE_PID=$!

# Wait for the coverage report to be generated by the background process
# (helper.py coverage starts a local web server and generates report files)
TIMEOUT_COVERAGE=300                                                       # 5 minutes
OSS_FUZZ_COVERAGE_REPORT_DIR="${OSS_FUZZ_DIR}/build/out/${PROJECT}/report" # Default location for HTML report
echo "Waiting up to ${TIMEOUT_COVERAGE}s for coverage report to be generated at ${OSS_FUZZ_COVERAGE_REPORT_DIR}..."
for ((i = 0; i < TIMEOUT_COVERAGE; i += 5)); do
  if [ -d "$OSS_FUZZ_COVERAGE_REPORT_DIR" ] && [ -n "$(ls -A "$OSS_FUZZ_COVERAGE_REPORT_DIR")" ]; then
    echo "Coverage report generated."
    break
  fi
  sleep 5
  echo "Still waiting for coverage report... ($((i + 5))s elapsed)"
done

if ! [ -d "$OSS_FUZZ_COVERAGE_REPORT_DIR" ] || [ -z "$(ls -A "$OSS_FUZZ_COVERAGE_REPORT_DIR")" ]; then
  echo "ERROR: Coverage report generation timed out or directory is empty."
  # Kill the coverage process if it's still running
  if kill -0 $COVERAGE_PID 2>/dev/null; then
    kill $COVERAGE_PID
  fi
fi

# Ensure the coverage server process is stopped. `helper.py coverage` might leave a server running.
if kill -0 $COVERAGE_PID 2>/dev/null; then
  echo "Stopping coverage helper process (PID: $COVERAGE_PID)..."
  kill $COVERAGE_PID
  wait $COVERAGE_PID 2>/dev/null || true
fi

# 6. Stop any Docker container created by oss-fuzz to generate the report
echo "Stopping any final Docker containers..."
docker ps -q | xargs -r docker stop || true

if [ "$EXPORT_RESULTS" == "true" ]; then
  echo "Exporting coverage report to ${FINAL_COVERAGE_EXPORT_PATH}..."
  if [ -d "$OSS_FUZZ_COVERAGE_REPORT_DIR" ]; then
    mkdir -p "$(dirname "${FINAL_COVERAGE_EXPORT_PATH}")"
    cp -r "$OSS_FUZZ_COVERAGE_REPORT_DIR" "${FINAL_COVERAGE_EXPORT_PATH}"
    # Optional: Zip the coverage report
    (cd "$(dirname "${FINAL_COVERAGE_EXPORT_PATH}")" && zip -qr "${FINAL_COVERAGE_EXPORT_PATH}.zip" "$(basename "${FINAL_COVERAGE_EXPORT_PATH}")" && rm -rf "${FINAL_COVERAGE_EXPORT_PATH}")
    echo "Coverage report exported and zipped to ${FINAL_COVERAGE_EXPORT_PATH}.zip"
  else
    echo "Warning: OSS-Fuzz coverage report directory ${OSS_FUZZ_COVERAGE_REPORT_DIR} not found for export."
  fi
fi

# Go back to original directory to avoid confusion
cd "$ROOT_DIR" || exit 1
echo "========================================================================"
echo "Fuzzing Run for Label: ${LABEL} COMPLETED."
echo "Corpus exported to: ${FINAL_CORPUS_EXPORT_PATH}.zip (if enabled)"
echo "Coverage exported to: ${FINAL_COVERAGE_EXPORT_PATH}.zip (if enabled)"
echo "========================================================================"
