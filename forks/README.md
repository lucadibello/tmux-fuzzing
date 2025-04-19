# Fork Folder

This folder contains forks of the public repos used.

## OSS-Fuzz

Creating the [oss-fuzz](/forks/oss-fuzz/) folder if it does not exist.
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

In each *project* of *OSS-Fuzz* (subdirectory in `oss-fuzz/projects`) there are the following files:
- `project.yaml`, containing the Project Configuration, so homepage, language, supported Fuzzing Engines, Repository, Sanitizers and other options.
- `Dockerfile`
- `build.sh` Build Script that fuzzes specific  

## To Do: Select Project

[*OSS-Fuzz Introspector*](https://introspector.oss-fuzz.com/project-profile?project=libssh), the basic dashboard with the useful links for both the project and the fuzzing data. There the number of fuzzers can be found (`Fuzzer count`), as well as `Lines of code`, `Lines covered` or `Code coverage` percentage.