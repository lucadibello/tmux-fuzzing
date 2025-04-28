#!/usr/bin/env bash
set -euo pipefail

# Configuration
## general information
PROJECT=tmux
HARNESS=input-fuzzer
ENGINE=libfuzzer
REBUILD=false
## libfuzzer settings
RUNTIME=60 # 4 hours in seconds
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

# ---- reset to default build.sh file ----
# FIXME: Uncomment for final submission
# git reset --hard HEAD

# 1) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
if [ "$REBUILD" = true ]; then
  rm -rf "$OSS_FUZZ_DIR/build" || true
  python3 infra/helper.py build_image "$PROJECT" --pull
  python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT"
fi

# 2) Ensure crashes directory is present
CORPUS_DIR="$OSS_FUZZ_DIR/build/work/$PROJECT/fuzzing_corpus"
mkdir -p "$CORPUS_DIR/crashes"

# 3) Run the fuzzer for RUNTIME
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" "$PROJECT" \
  --corpus-dir "build/work/$PROJECT/fuzzing_corpus" \
  "$HARNESS" -- "$FLAGS"

# 4) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

# 5) Zip and store the corpus in `experiments/{timestamp}_w_corpus`
ts=$(date +%Y%m%d_%H%M%S)
mkdir -p "$ROOT/experiments"
cp -r "$CORPUS_DIR" "$ROOT/experiments/${ts}_w_corpus"
(cd "$ROOT/experiments" && zip -qr "${ts}_w_corpus.zip" "${ts}_w_corpus")

# 6) Generate HTML coverage report
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py coverage \
  "$PROJECT" \
  --corpus-dir "build/work/$PROJECT/fuzzing_corpus" \
  --fuzz-target "$HARNESS" &

# --- wait for the coverage report to be generated ---
TIMEOUT=300 # total wait time in seconds (300s = 5 minutes)
GLOBAL_REPORT_DIR="$OSS_FUZZ_DIR/build/out/$PROJECT/report"
echo "Waiting for coverage report to be generated..."
for ((i = 0; i < TIMEOUT; i += 1)); do
  sleep 1
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
