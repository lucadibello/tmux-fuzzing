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
RUNTIME=14400 # 4 hours in seconds
## corpus settings
ROOT=$(pwd)

# Temporary working directories
WORKDIR=$ROOT/part1_temp_wo
OSS_FUZZ_DIR=$ROOT/forks/oss-fuzz
mkdir -p "$WORKDIR"

# 1) Pull changes from submodules and update the working directory
git submodule update --init --recursive

# 2) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py build_image "$PROJECT" --pull
python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT"

# 3) Prepare empty corpus
mkdir -p work-corpus # (no seed corpus is copied here)

# 4) Run the fuzzer for RUNTIME
timeout "$RUNTIME" \
  python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir work-corpus \
  "$PROJECT" "$FUZZER" -- -jobs="$JOBS" -workers="$WORKERS" -max_total_time="$RUNTIME" || true

# 5) Stop any remaining Docker containers
docker stop "$(docker ps -q)" 2>/dev/null || true

# 6) Zip and store the corpus in `experiments/{timestamp}_wo_corpus`
ts=$(date +%Y%m%d_%H%M%S)
mkdir -p "$ROOT/experiments"
cp -r work-corpus "$ROOT/experiments/${ts}_wo_corpus"
(cd "$ROOT/experiments" && zip -qr "${ts}_wo_corpus.zip" "${ts}_wo_corpus")

# 7) Generate HTML coverage report
python3 infra/helper.py coverage \
  "$PROJECT" \
  --corpus-dir work-corpus \
  --fuzz-target "$FUZZER"

# 8) Copy results to submission directory
DEST=$ROOT/submission/part1/coverage_wo_corpus
mkdir -p "$DEST"
cp -r build/out/report "$DEST/"

# 9) Clean up
rm -rf "$WORKDIR"

echo "✅ Done: coverage WITHOUT corpus in $DEST"
