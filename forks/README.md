# Fork Folder

This folder contains forks of the public repos used.

## OSS-Fuzz

Creating the [oss-fuzz](/forks/oss-fuzz/) folder if it does not exists.
```bash
git clone https://github.com/google/oss-fuzz.git && cd oss-fuzz
```

Build docker image for the project:

```bash
python3 infra/helper.py build_image <project>
```

Build Project fuzzers:
```bash
python3 infra/helper.py build_fuzzers <project>
```

Run a fuzzer and store the result in a corpus directory:
```bash
mkdir -p build/out/corpus
python3 infra/helper.py run_fuzzer <project> <fuzz_target> --corpus-dir build/out/corpus
```

Build coverage-instrumented analysis:
```bash
python3 infra/helper.py build_fuzzers --sanitizer coverage <project>
```
The option `--sanitizer coverage` build binaries with code coverage instrumentation.

Generate a coverage report:
```bash
python3 infra/helper.py coverage <project> --corpus-dir build/out/corpus --fuzz-target <fuzz_target>
```
This uses the `llvm-cov` command.

## To Do: Project