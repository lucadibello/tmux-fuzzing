#!/usr/bin/env bash
set -euo pipefail

# Configuration
## general information
PROJECT=tmux
FUZZER=input-fuzzer
ENGINE=libfuzzer
## libfuzzer settings
JOBS=4
WORKERS=2
# RUNTIME=14400 # 4 hours in seconds
RUNTIME=60 # 4 hours in seconds
## corpus settings
ROOT=$(pwd)

# OSS Fuzz absolute path
OSS_FUZZ_DIR=$ROOT/forks/oss-fuzz

# 1) Pull changes from submodules and update the working directory
git submodule update --init --recursive

# 2) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py build_image "$PROJECT" --pull
python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT"

# 3) Prepare empty corpus
rm -rf "$OSS_FUZZ_DIR/work-corpus" || true
mkdir -p "$OSS_FUZZ_DIR/work-corpus"

# 4) Run the fuzzer for RUNTIME
cd "$OSS_FUZZ_DIR"
timeout "$RUNTIME" \
  python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir work-corpus \
  "$PROJECT" "$FUZZER" -- -jobs="$JOBS" -workers="$WORKERS" -max_total_time="$RUNTIME" || true

# 5) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

# 6) Zip and store the corpus in `experiments/{timestamp}_wo_corpus`
ts=$(date +%Y%m%d_%H%M%S)
mkdir -p "$ROOT/experiments"
cp -r "$OSS_FUZZ_DIR/work-corpus" "$ROOT/experiments/${ts}_wo_corpus"
(cd "$ROOT/experiments" && zip -qr "${ts}_wo_corpus.zip" "${ts}_wo_corpus")

# 7) Generate HTML coverage report
REPORT_DIR="build/out/$PROJECT/report"
cd "$OSS_FUZZ_DIR"
rm -rf REPORT_DIR || true
python3 infra/helper.py coverage \
  "$PROJECT" \
  --corpus-dir work-corpus \
  --fuzz-target "$FUZZER" &

# --- wait for the coverage report to be generated ---
TIMEOUT=300 # total wait time in seconds (300s = 5 minutes)
echo "Waiting for coverage report to be generated..."
for ((i = 0; i < TIMEOUT; i += 5)); do
  sleep 5 # sleep 5 seconds

  # if the report directory exists, break the loop
  if [[ -d "$REPORT_DIR" ]]; then
    break
  fi
  echo "Waiting... ($i seconds elapsed)"
done

# 8) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

# 9) Copy results to submission directory
DEST=$ROOT/submission/part_1/${ts}-coverage_wo_corpus
REPORT_ABS_PATH="$OSS_FUZZ_DIR/$REPORT_DIR"
mkdir -p "$DEST"
cp -r "$REPORT_ABS_PATH" "$DEST/"

echo "✅ Done: coverage WITHOUT corpus in $DEST"
