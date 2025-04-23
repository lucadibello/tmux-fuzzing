# general information
PROJECT       = tmux
FUZZER        = input-fuzzer
OSS_FUZZ_DIR  = forks/oss-fuzz
# corpus settings (with / without initial seeds)
SEED_CORPUS   = forks/tmux-fuzzing-corpus          # initial seeds
WORK_CORPUS   = $(OSS_FUZZ_DIR)/work-corpus        # scratch area inside oss-fuzz
EMPTY_LABEL   = wo_corpus
WITH_LABEL    = w_corpus
# libfuzzer settings (mutithreading and timeout)
JOBS          = 4
WORKERS       = 2
# RUNTIME       = 14400      # seconds (== 4 h)
RUNTIME       = 10
ENGINE        = libfuzzer

# NOTE: available options here: https://llvm.org/docs/LibFuzzer.html#options
# WARNING: the "max_total_time" does not seem to work with oss-fuzz. For this reason
# we still use the `timeout` utility to limit the runtime of the fuzzer.
LIBFUZZER_PARAMS = -jobs=$(JOBS) -workers=$(WORKERS) -max_total_time=$(RUNTIME)
# coverage settings (overridable from command line)
CORPUS        ?= $(WORK_CORPUS)

# declare all targets as PHONY (utility targets)
.PHONY: prepare run_w_corpus run_wo_corpus coverage clean \
        full_w_corpus full_wo_corpus diff

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
	@rm -rf $(WORK_CORPUS)
	@mkdir -p $(WORK_CORPUS)
	@cp -r $(SEED_CORPUS) $(WORK_CORPUS)
	@echo "== Running fuzzer on pre-populated corpus =="
	@cd $(OSS_FUZZ_DIR) && \
		timeout $(RUNTIME) python3 infra/helper.py run_fuzzer \
			--engine $(ENGINE) \
			--corpus-dir work-corpus \
			$(PROJECT) $(FUZZER) -- $(LIBFUZZER_PARAMS) || true
	@echo "== Finished fuzzer run =="
	@docker stop $$(docker ps -q) || true
	@mkdir -p experiments
	@ts=$$(date +%Y%m%d_%H%M%S); \
	  cp -r $(WORK_CORPUS) experiments/$$ts-$(WITH_LABEL); \
		echo "== Corpus stored in experiments/$$ts-$(WITH_LABEL) =="

# -----------------------------------------------------------------------------
# Target: run_wo_corpus
#   Run libFuzzer from scratch (empty-seed corpus)
# -----------------------------------------------------------------------------
run_wo_corpus:
	@rm -rf $(WORK_CORPUS)
	@mkdir -p $(WORK_CORPUS)
	@echo "== Running fuzzer on empty corpus =="
	@cd $(OSS_FUZZ_DIR) && \
		timeout $(RUNTIME) python3 infra/helper.py run_fuzzer \
			--engine $(ENGINE) \
			--corpus-dir work-corpus \
			$(PROJECT) $(FUZZER) -- $(LIBFUZZER_PARAMS) || true
	@echo "== Finished fuzzer run =="
	@docker stop $$(docker ps -q) || true
	@mkdir -p experiments
	@ts=$$(date +%Y%m%d_%H%M%S); \
	  cp -r $(WORK_CORPUS) experiments/$$ts-$(EMPTY_LABEL); \
		echo "== Corpus stored in experiments/$$ts-$(EMPTY_LABEL) =="

# -----------------------------------------------------------------------------
# Target: coverage
#   Generate an HTML coverage report using $(CORPUS).
#
#   NOTE: we can override the variable from the command line!
#   Example:
#     a) make coverage
#     b) make coverage CORPUS=$(EMPTY_CORPUS)
# -----------------------------------------------------------------------------
coverage:
	@python3 $(OSS_FUZZ_DIR)/infra/helper.py coverage $(PROJECT) \
	    --corpus-dir $(CORPUS) --fuzz-target $(FUZZER)

clean:
	rm -rf $(WORK_CORPUS)

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
