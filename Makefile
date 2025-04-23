# Variables
PROJECT = tmux
FUZZER = input-fuzzer
OSS_FUZZ_DIR = forks/oss-fuzz
CORPUS_DIR = ../tmux-fuzzing-corpus  # relative to OSS_FUZZ_DIR
BUILD_DIR = build/out
TIME_LIMIT = 4h # Using 'h' for hours in the timeout command
WORKERS = 4

# Target to set up the OSS-Fuzz environment
prepare:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py build_image $(PROJECT)
	@cd $(OSS_FUZZ_DIR) && python3 /infra/helper.py build_fuzzers $(PROJECT)

# Target to run the fuzzer with a predefined corpus
run_w_corpus:
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py run_fuzzer $(PROJECT) $(FUZZER) \
		--corpus-dir $(CORPUS_DIR) \
		-- -workers=$(WORKERS) -jobs=$(WORKERS)

# Target to run the fuzzer without any initial corpus (libfuzzer mutation engine will find some valid inputs)
run_wo_corpus:
	@rm -rf forks/empty-corpus
	@mkdir -p forks/empty-corpus
	@cd $(OSS_FUZZ_DIR) && \
		python3 infra/helper.py run_fuzzer $(PROJECT) $(FUZZER) \
		--corpus-dir ../empty-corpus \
		-- -workers=$(WORKERS) -jobs=$(WORKERS)

# Target to generate coverage reports
coverage:
	@cd $(OSS_FUZZ_DIR) && python3 infra/helper.py coverage $(PROJECT) --corpus-dir $(CORPUS_DIR) --fuzz-target $(FUZZER)

# Clean build files
clean:
	@rm -rf $(BUILD_DIR)

# Full fuzzing setup and execution
full_run: prepare run_w_corpus coverage

# Run the fuzzer for a time limit (using GNU `timeout` to limit fuzzing time)
time_run:
	@cd $(OSS_FUZZ_DIR) && timeout $(TIME_LIMIT) python3 infra/helper.py run_fuzzer $(PROJECT) $(FUZZER) --corpus-dir $(CORPUS_DIR)

# Diff for changes in the repositories
diff:
	@cd $(OSS_FUZZ_DIR) && git diff > ../../submission/part1/oss-fuzz.diff
	@cd forks/tmux && git diff > ../../submission/part1/project.diff
