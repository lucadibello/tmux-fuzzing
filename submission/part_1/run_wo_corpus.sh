#!/usr/bin/env bash
set -euo pipefail

# Configuration
## general information
PROJECT=tmux
HARNESS="${HARNESS:-input-fuzzer}"
ENGINE=libfuzzer
SANITIZER=address # address or undefined
REBUILD=${REBUILD:-true}
OUTPUT=${OUTPUT:-submission/part_1}
## libfuzzer settings
RUNTIME=${RUNTIME:-14400} # 4 hours in seconds
FLAGS="\
  -max_total_time=$RUNTIME \
  -timeout=25 \
  -print_final_stats=1 \
  -ignore_crashes=1 \
  -artifact_prefix=./build/work/$PROJECT/fuzzing_corpus/crashes/"

## corpus settings
ROOT=$(pwd)

# OSS Fuzz directory
OSS_FUZZ_DIR=$ROOT/forks/oss-fuzz

# ---- apply git diff to remove the corpus from the build.sh file ----
git restore forks/oss-fuzz/projects/tmux/Dockerfile
git restore forks/oss-fuzz/projects/tmux/build.sh
git apply submission/part_1/remove_seed_corpus.patch

# 1) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
if [ "$REBUILD" = true ]; then
  rm -rf "$OSS_FUZZ_DIR/build" || true
  python3 infra/helper.py build_image "$PROJECT" --pull
fi
python3 infra/helper.py build_fuzzers --sanitizer "$SANITIZER" "$PROJECT"

# 2) Ensure the corpus directory is empty
CORPUS_DIR="$OSS_FUZZ_DIR/build/work/$PROJECT/fuzzing_corpus"
rm -rf "$CORPUS_DIR" || true
mkdir -p "$CORPUS_DIR/crashes"

# 3) Run the fuzzer for RUNTIME
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir "build/work/$PROJECT/fuzzing_corpus" \
  "$PROJECT" "$HARNESS" -- \
  "$FLAGS" || true

# 4) Stop any remaining Docker containers
docker stop "$(docker ps -q)" || true

echo "[!] Done: corpus generation complete. Exporting.."

# 5) Zip and store the corpus in `experiments/{timestamp}_wo_corpus`
ts=$(date +%Y%m%d_%H%M%S)
mkdir -p "$ROOT/experiments"
cp -r "$CORPUS_DIR" "$ROOT/experiments/${ts}_wo_corpus"
#(cd "$ROOT/experiments" && zip -qr "${ts}_wo_corpus.zip" "${ts}_wo_corpus")

# 6) Generate HTML coverage report
echo "Generating HTML coverage report..."
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT"
python3 infra/helper.py coverage \
  --corpus-dir "build/work/$PROJECT/fuzzing_corpus" \
  --fuzz-target "$HARNESS" \
  "$PROJECT" &

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

echo "[!] Done: coverage report generation complete. Exporting.."

# 8) Copy results to submission directory
DEST=$ROOT/$OUTPUT/${ts}_coverage_wo_corpus
mkdir -p "$DEST"
cp -r "$GLOBAL_REPORT_DIR" "$DEST/"

echo "[!] Done: coverage WITHOUT corpus in $DEST"
