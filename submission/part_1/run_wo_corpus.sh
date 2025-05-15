#!/usr/bin/env bash
set -euo pipefail

# --- Configuration for Part 1: Without Corpus ---
export PROJECT="tmux"
export HARNESS="input-fuzzer"
export ENGINE="libfuzzer"
export SANITIZER="address"
export RUNTIME=$((4 * 60 * 60)) # 4 hours
export LABEL="part1_wo_corpus"

export PATCH_FILE="./part1/remove_seed_corpus.patch" # Patch to apply
export APPLY_PATCH_TO="project"                      # "oss-fuzz" or "project" or "" (no patch)

export EXPORT_RESULTS="true"                                    # Export corpus and coverage after run
export CORPUS_EXPORT_DIR_BASE="${ROOT_DIR:-$(pwd)}/experiments" # Dir where to store the corpus
export COVERAGE_EXPORT_DIR_BASE="${ROOT_DIR:-$(pwd)}/part_1"    # Dir where to store the coverage report

# --- Call the Core Script ---
bash "utils/_run_fuzz_core.sh"
