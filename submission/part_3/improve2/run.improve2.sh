#!/usr/bin/env bash
set -euo pipefail

# --- Configuration for Part 1: Without Corpus ---
export PROJECT="tmux"
export HARNESS="cmd-fuzzer"
export ENGINE="libfuzzer"
export SANITIZER="address"
export RUNTIME=14400 # 4h in seconds
export LABEL="part3_cmd_fuzzer"
export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
export ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd)"

export PATCH_FILE="part_1/remove_seed_corpus.patch" # Patch that removed corpus from build scripts
export APPLY_PATCH_TO="oss-fuzz"                     # "oss-fuzz" or "project" or "" (no patch)

export EXPORT_RESULTS="true"                                    # Export corpus and coverage after run
export CORPUS_EXPORT_DIR_BASE="${ROOT_DIR:-$(pwd)}/experiments" # Dir where to store the corpus
export COVERAGE_EXPORT_DIR_BASE="${ROOT_DIR:-$(pwd)}/part_3/improve2"    # Dir where to store the coverage report

# --- Call the Core Script ---
bash "utils/_run_fuzz_core.sh"

