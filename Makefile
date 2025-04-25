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
RUNTIME       = 14400      # seconds (== 4 h)
ENGINE        = libfuzzer

# NOTE: available options here: https://llvm.org/docs/LibFuzzer.html#options
# WARNING: the "max_total_time" does not seem to work with oss-fuzz. For this reason
# we still use the `timeout` utility to limit the runtime of the fuzzer, and we kill
# any docker containers that are still running after the timeout.
LIBFUZZER_PARAMS = -jobs=$(JOBS) -workers=$(WORKERS) -max_total_time=$(RUNTIME)
# coverage settings (overridable from command line)
CORPUS        ?= $(WORK_CORPUS)

# declare all targets as PHONY (utility targets)
.PHONY: prepare prepare_image prepare_fuzzers prepare_fuzzers_coverage prepare_coverage \
        run_w_corpus run_wo_corpus coverage clean full_w_corpus full_wo_corpus diff

# ----------------------------------------------------------------------------- 
# Internal template:
#   $(1)  – human-readable description (“pre-populated”, “empty”)
#   $(2)  – label for the experiments zip
#   $(3)  – command that prepares the corpus directory (copy seeds or `:`)
#
# Reference: https://stackoverflow.com/questions/6783243/functions-in-makefiles
# ----------------------------------------------------------------------------- 
define RUN_TEMPLATE
	@rm -rf $(WORK_CORPUS)
	@mkdir -p $(WORK_CORPUS)
	@$(3)
	@echo "== Running fuzzer on $(1) corpus =="
	@cd $(OSS_FUZZ_DIR) && \
	  timeout $(RUNTIME) \
	    python3 infra/helper.py run_fuzzer \
	      --engine $(ENGINE) \
	      --corpus-dir work-corpus \
	      $(PROJECT) $(FUZZER) -- $(LIBFUZZER_PARAMS) || true
	@echo "== Finished fuzzer run =="
	@docker stop $$(docker ps -q) || true
	@mkdir -p experiments
	@ts=$$(date +%Y%m%d_%H%M%S); \
	  cp -r $(WORK_CORPUS) experiments/$${ts}-$(2); \
	  zip -r experiments/$${ts}-$(2).zip experiments/$${ts}-$(2); \
	  echo "== Corpus archived to experiments/$${ts}-$(2).zip =="
endef

# Target: prepare - build the OSS-Fuzz image for the project
prepare_image:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_image $(PROJECT)

# Target: prepare_fuzzers - build the fuzzers for the project
prepare_fuzzers:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_fuzzers $(PROJECT)

# Target: prepare_fuzzers_coverage - build the fuzzers for the project with coverage sanitizer
prepare_fuzzers_coverage:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_fuzzers --sanitizer coverage $(PROJECT)

# Target: prepare / prepare-coverage - build the OSS-Fuzz image and fuzzers for tmux
prepare: clean prepare_image prepare_fuzzers
prepare_coverage: clean prepare_image prepare_fuzzers_coverage

# Target: run_w_corpus - fuzz starting from 
run_w_corpus:
	$(call RUN_TEMPLATE,pre-populated,$(WITH_LABEL),cp -r $(SEED_CORPUS)/* $(WORK_CORPUS))

# Target: run_wo_corpus – fuzz from scratch (empty corpus)
run_wo_corpus:
	$(call RUN_TEMPLATE,empty,$(EMPTY_LABEL),:)

# Target: coverage - generate an HTML coverage report using $(CORPUS).
#
#   NOTE: we can override the variable from the command line!
#   Example:
#     a) make coverage
#     b) make coverage CORPUS=$(EMPTY_CORPUS)
coverage:
	@python3 $(OSS_FUZZ_DIR)/infra/helper.py coverage $(PROJECT) \
	    --corpus-dir $(CORPUS) --fuzz-target $(FUZZER)

# Target: clean - removes any artifact generated from the fuzzer
clean:
	@rm -rf $(WORK_CORPUS)
	@docker stop $$(docker ps -q) 2>/dev/null || true

# Targets: full_w_corpus - full run with pre-populated corpus
full_w_corpus: prepare_coverage run_w_corpus coverage

# Target: full_wo_corpus - full run with empty corpus
full_wo_corpus: prepare_coverage run_wo_corpus coverage

# Target: diff - produce diff files for oss-fuzz and tmux forks
diff:
	@cd $(OSS_FUZZ_DIR) && git diff > ../../oss-fuzz.diff
	@cd forks/tmux            && git diff > ../../project.diff
