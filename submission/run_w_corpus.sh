#!/usr/bin/env bash
set -euo pipefail

# Configuration
## general information
PROJECT=tmux                                               # OSS-Fuzz project name
HARNESS="${HARNESS:-input-fuzzer}"                         # harness name
ENGINE=libfuzzer                                           # engine to use
SANITIZER=address                                          # address or undefined
REBUILD=${REBUILD:-true}                                   # whether to rebuild the image
PATCH=${PATCH:-submission/part_1/remove_seed_corpus.patch} # patch to apply before building
ROOT=${ROOT:-$(pwd)}                                       # root directory, use the current directory if not set
RUNTIME=${RUNTIME:-14400}                                  # fuzzing time in seconds (4 hours by default)
## export settings
EXPORT=${EXPORT:-false}                               # whether to export the corpus and coverage report
LABEL=${LABEL:-"w_corpus"}                            # label for the exported files
CORPUS_OUTPUT=${CORPUS_OUTPUT:-experiments}           # directory to store the corpus
COVERAGE_OUTPUT=${COVERAGE_OUTPUT:-submission/part_1} # directory to store the coverage report
## additional settings to override default options
FLAGS="\
  -max_total_time=$RUNTIME \
  -timeout=25 \
  -print_final_stats=1 \
  -ignore_crashes=1 \
  -artifact_prefix=crash-"

## corpus settings
ROOT=$(pwd)

# OSS Fuzz directory
OSS_FUZZ_DIR=$ROOT/oss-fuzz
CORPUS_DIR="$OSS_FUZZ_DIR/build/work/$PROJECT/fuzzing_corpus"

# clone the OSS-Fuzz repository if it doesn't exist
if [ ! -d "$OSS_FUZZ_DIR" ]; then
  git clone git@github.com:google/oss-fuzz.git "$OSS_FUZZ_DIR"
fi

# restore the entire oss-fuzz repository to its original state
(cd "$OSS_FUZZ_DIR" && git reset --hard HEAD)

# 1) Build OSS-Fuzz image and fuzzers with coverage instrumentation
cd "$OSS_FUZZ_DIR"
if [ "$REBUILD" = true ]; then
  rm -rf "$OSS_FUZZ_DIR/build" || true
  python3 infra/helper.py build_image "$PROJECT" --pull
fi

# remove corpus dir to ensure a clean build
rm -rf "$CORPUS_DIR" || true
python3 infra/helper.py build_fuzzers --sanitizer "$SANITIZER" "$PROJECT"

# 3) Run the fuzzer for RUNTIME
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py run_fuzzer \
  --engine "$ENGINE" \
  --corpus-dir "build/work/$PROJECT/fuzzing_corpus" \
  "$PROJECT" "$HARNESS" -- \
  "$FLAGS" || true

echo "[!] Done: corpus generation complete. Exporting.."

# 5) Zip and store the corpus in `experiments/{timestamp}_w_corpus`
if [ "$EXPORT" = true ]; then
  echo "Exporting corpus..."
  # remove the existing corpus directory
  rm -rf "$CORPUS_DIR" || true
  # create a new empty directory
  mkdir -p "$CORPUS_DIR"
  # copy the corpus files to the new directory
  cp -r "$OSS_FUZZ_DIR/build/work/$PROJECT/fuzzing_corpus/"* "$CORPUS_DIR/"
  # zip the corpus directory to save space
  (cd "$ROOT/experiments" && zip -qr "${ts}_$LABEL.zip" "${ts}_$LABEL")
fi

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
echo "[!] Done: coverage report generation complete."

if [ "$EXPORT" = true ]; then
  # 8) Copy results to submission directory
  DEST=$COVERAGE_OUTPUT/${ts}_coverage_$LABEL
  mkdir -p "$DEST"
  cp -r "$GLOBAL_REPORT_DIR" "$DEST/"
  echo "[!] Done: coverage WITH corpus in $DEST"
fi
