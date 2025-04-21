# Fork Folder

This folder contains forks of the public repos used.

## OSS-Fuzz

### Starting with OSS-Fuzz

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

### OSS-Fuzz *Project* Files

In each *project* of *OSS-Fuzz* (subdirectory in `oss-fuzz/projects`) there are the following files:
- `project.yaml`, containing the Project Configuration, so homepage, language, supported Fuzzing Engines, Repository, Sanitizers and other options.
- `Dockerfile`
- `build.sh` Build Script that fuzzes specific

### OSS-Fuzzer Commands

- `build_image`: Creates a Docker image for your project, containing all dependencies needed to build the project and its fuzzers. Uses the Dockerfile in your project's directory.
- `build_fuzzers`: Compiles the fuzzers for your project using the previously built Docker image. Requires a build.sh script in your project directory to define how fuzzers are built.
- `run_fuzzer`: Executes a fuzzer locally to test the project or reproduce crashes. Specify a corpus directory (--corpus-dir) to store/reuse test inputs. Use --engine <libfuzzer|afl|coverage> to choose the fuzzing engine (default: libFuzzer).
- `coverage`: Generates a code coverage report for the fuzzers. Requires building fuzzers with `--sanitizer coverage` first. 
- `check_build`: Verifies that the project and fuzzers are built correctly. 
- `shell`: Starts an interactive shell inside the project's Docker container.


## **tmux**

[*OSS-Fuzz Introspector*](https://introspector.oss-fuzz.com/project-profile?project=libssh), the basic dashboard with the useful links for both the project and the fuzzing data. There the number of fuzzers can be found (`Fuzzer count`), as well as `Lines of code`, `Lines covered` or `Code coverage` percentage.

[*tmux* OSS-Fuzz Introspector](https://introspector.oss-fuzz.com/project-profile?project=tmux)

### Current Fuzzing files

- `input-fuzzer.c`
- `input-fuzzer.dict`
- `input-fuzzer.options`
- `tmux-fuzzing-corpus`, [github repo](https://github.com/tmux/tmux-fuzzing-corpus) containing an initial set of input files designed for the fuzz testing. Those files simulate various terminal behaviors. Some of the provided corpus include:
    - `alacritty`, input files derived from the *Alacritty* terminal emulator
    - `esctest`, testing escape sequences
    - `iterm2`, testing *iTerm2* terminal emulator.