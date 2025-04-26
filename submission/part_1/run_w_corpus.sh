#!/usr/bin/env bash
set -euo pipefail

# Configuration
## general information
PROJECT=tmux
HARNESS=input-fuzzer
ENGINE=libfuzzer
REBUILD=true
## libfuzzer settings
# RUNTIME=14400 # 4 hours in seconds
RUNTIME=30 # 4 hours in seconds
FLAGS="\
  -max_total_time=$RUNTIME \
  -timeout=25 \
  -print_final_stats=1 \
  -artifact_prefix=./crashes \
  -jobs=$(nproc) \
  -workers=0"

## corpus settings
ROOT=$(pwd)
SEED_CORPUS=$ROOT/forks/tmux-fuzzing-corpus

# OSS Fuzz directory
OSS_FUZZ_DIR=$ROOT/forks/oss-fuzz

# 1) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
if [ "$REBUILD" = true ]; then
  rm -rf "$OSS_FUZZ_DIR/build" || true
  python3 infra/helper.py build_image "$PROJECT" --pull
  python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT"
fi

# 2) Prepare seed corpus
rm -rf "$OSS_FUZZ_DIR/work-corpus" || true
mkdir -p "$OSS_FUZZ_DIR/work-corpus"
mkdir -p "$OSS_FUZZ_DIR/work-corpus/crashes"
cp -r "$SEED_CORPUS"/* "$OSS_FUZZ_DIR/work-corpus/" || true

# 3) Run the fuzzer for RUNTIME
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir work-corpus \
  "$PROJECT" "$HARNESS" \
  "$FLAGS"

# 4) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

# 5) Zip and store the corpus in `experiments/{timestamp}_w_corpus`
ts=$(date +%Y%m%d_%H%M%S)
mkdir -p "$ROOT/experiments"
cp -r "$OSS_FUZZ_DIR/work-corpus" "$ROOT/experiments/${ts}_w_corpus"
(cd "$ROOT/experiments" && zip -qr "${ts}_w_corpus.zip" "${ts}_w_corpus")

# 6) Generate HTML coverage report
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py coverage \
  "$PROJECT" \
  --corpus-dir work-corpus \
  --fuzz-target "$HARNESS" &

# --- wait for the coverage report to be generated ---
TIMEOUT=300 # total wait time in seconds (300s = 5 minutes)
GLOBAL_REPORT_DIR="$OSS_FUZZ_DIR/build/out/$PROJECT/report"
echo "Waiting for coverage report to be generated..."
for ((i = 0; i < TIMEOUT; i += 5)); do
  sleep 5 # sleep 5 seconds

  # if the report directory exists, break the loop
  if [[ -d "$GLOBAL_REPORT_DIR" ]]; then
    break
  fi
  echo "Waiting... ($i seconds elapsed)"
done

# 7) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

# 8) Copy results to submission directory
DEST=$ROOT/submission/part_1/${ts}_coverage_w_corpus
mkdir -p "$DEST"
cp -r "$GLOBAL_REPORT_DIR" "$DEST/"

echo "✅ Done: coverage WITH corpus in $DEST"
