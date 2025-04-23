# Variables
PROJECT        = tmux
FUZZER         = input-fuzzer
OSS_FUZZ_DIR   = forks/oss-fuzz
CORPUS_DIR     = forks/tmux-fuzzing-corpus
EMPTY_CORPUS   = forks/empty-corpus
JOBS           = 4
WORKERS        = 4
RUNTIME        = 14400    # 4 hours in seconds
BUILD_DIR      = build/out

# NOTE: Allow overriding which corpus to use; defaults to the pre-populated one
CORPUS         ?= $(CORPUS_DIR)

# -----------------------------------------------------------------------------
# Target: prepare
#   Build the OSS-Fuzz image and fuzzers for tmux
# -----------------------------------------------------------------------------
prepare:
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py build_image $(PROJECT) && \
		python3 infra/helper.py build_fuzzers $(PROJECT)

# -----------------------------------------------------------------------------
# Target: run_w_corpus
#   Run libFuzzer with your pre-populated corpus
# -----------------------------------------------------------------------------
run_w_corpus:
	@mkdir -p $(CORPUS_DIR)
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py run_fuzzer $(PROJECT) $(FUZZER) \
			--corpus-dir ../$(CORPUS_DIR) \
			-- -jobs=$(JOBS) -workers=$(WORKERS) -max_total_time=$(RUNTIME)

# -----------------------------------------------------------------------------
# Target: run_wo_corpus
#   Run libFuzzer from scratch (empty-seed corpus)
# -----------------------------------------------------------------------------
run_wo_corpus:
	@rm -rf $(EMPTY_CORPUS)
	@mkdir -p $(EMPTY_CORPUS)
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py run_fuzzer $(PROJECT) $(FUZZER) \
			--corpus-dir ../$(EMPTY_CORPUS) \
			-- -jobs=$(JOBS) -workers=$(WORKERS) -max_total_time=$(RUNTIME)

# -----------------------------------------------------------------------------
# Target: coverage
#   Generate an HTML coverage report using $(CORPUS)
#   Usage:
#     make coverage
#     # or
#     make coverage CORPUS=$(EMPTY_CORPUS)
# -----------------------------------------------------------------------------
coverage:
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py coverage $(PROJECT) \
			--corpus-dir ../$(CORPUS) \
			--fuzz-target $(FUZZER)

# -----------------------------------------------------------------------------
# Target: clean
#   Remove any modified files from the pre-populated corpus or empty corpus
# -----------------------------------------------------------------------------
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaning generated fuzz inputs from pre-populated corpus..."
	@cd $(CORPUS_DIR) && git clean -fdx
	@echo "Removing empty corpus..."
	@rm -rf $(EMPTY_CORPUS)

# -----------------------------------------------------------------------------
# Targets: full runs
# -----------------------------------------------------------------------------
full_w_corpus: prepare run_w_corpus coverage
full_wo_corpus: prepare run_wo_corpus coverage

# -----------------------------------------------------------------------------
# Target: diff
#   Produce diff files for oss-fuzz and tmux forks
# -----------------------------------------------------------------------------
diff:
	@cd $(OSS_FUZZ_DIR) && git diff > ../../oss-fuzz.diff
	@cd forks/tmux            && git diff > ../../project.diff
