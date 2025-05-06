# Fuzzing Lab - CS-412

## Part 0: Clone the repo

Clone the repo:

```bash
git clone --recurse-submodules git@github.com:federicovilla55/fuzzing-lab.git
```

A detailed explanation of OSS-Fuzz commands and other project related information can be found here.

## Part 1: Running Existing Fuzzing Harnesses

Clone the _OSS-Fuzz_ repo:

```bash
git clone https://github.com/google/oss-fuzz && cd oss-fuzz
```

A cloned version with changed project-specific files: `build.sh`, `Dockerfile`, `project.yaml` is needed. Otherwise use one of the forker versions in the subdirectory [fork](/forks/).

Build the selected project:

```bash
python3 infra/helper.py build_image <project>
python3 infra/helper.py build_fuzzers <project>
```

Run the tests with the default corpsus:

```bash
mkdir -p build/out/corpus
python3 infra/helper.py run_fuzzer <project> <harness_name> --corpus-dir build/out/corpus
```

To run the selected project without the defined corpsus or the seed first modify the `build.sh` of the project and then run:

```bash
rm -rf build/out/corpus
python3 infra/helper.py run_fuzzer <project> <harness_name>
```

To create Coverage Reports:

```bash
python3 infra/helper.py coverage <project> --corpus-dir build/out/corpus --fuzz-target <harness_name>
```

or without the `--corpus-dir` if no seed is provided.

Compare the coverage of the seeded and empty corpus fuzzing, for example check the coverage percentage in the HTML reports.

The deliverables for this first part are:

- [ ] Running scripts:
  - [ ] `run_w_corpus.sh`
  - [ ] `run_wo_corpus.sh`
- [ ] Coverage Reports:
  - [ ] `w_corpus/`
  - [ ] `w_o_corpus`
- [ ] Differences files:
  - [ ] `oss-fuzz.diff`
  - [ ] `project.diff`

## Part 2: Analyzing Existing Fuzzing Harnesses

Identify two code regions that are not covered and explain why the existing harness fails to cover them. First go to [OSS-Fuzz Introspector](https://introspector.oss-fuzz.com/), identify two code regions uncovered and determine why.

Deliverables for the second part:

- [ ] Include in the report a section detailing the two uncovered regions, their significance, and harness limitations.

## Part 3: Improving the Fuzzers

Enhance coverage for the two regions identified in _Part 2_.

Deliverables:

- [ ] Scripts enhancing the coverage:
  - [ ] `improve1/run_improve1.sh`
  - [ ] `improve2/run_improve2.sh`
- [ ] Coverage of such regions without improvements
  - [ ] `coverage_noimprove/`
- [ ] Coverage improved
  - [ ] `improve1/coverage_improve1/`
  - [ ] `improve2/coverage_improve2/`
- [ ] Diff files showing the changes in harness and build scripts:
  - [ ] `improve1/oss-fuzz.diff`
  - [ ] `improve1/project.diff`
  - [ ] `improve2/oss-fuzz.diff`
  - [ ] `improve1/project.diff`

## Part 4: Crash Analysis

Triage a crash found by the improved fuzzer.  
If a crash is found, describe the steps and commands to reproduce it, otherwise use a previous _CVE_ or an old bug (in this case provide a proof of concept that can be run to reproduce the crash.

Deliverables:

- [ ] Proof of Concept script that leads to the crash: `run_poc.sh`
- [ ] Find and describe in the report the cause of the crash
- [ ] Fix Crash cause
- [ ] Exploit analysis of the crash

# Repo Description

- [docs](/docs/): Documentation, notes, and analysis
- [experiments](/experiments/): Data for local tests, so the used corpus crashes and coverage reports.
- [forks](/forks/): Clones of the used repositories, so [oss-fuzz](https://github.com/google/oss-fuzz) and [project_to_select]().
- [submission](/submission/): Final submission files

## How to run _LibFuzzer_ (in _OSS-Fuzz_)?

Clone the Repo, build the project Docker image, create fuzzers (binary results in `build/out/NAME/`), create a directory for the data corpsus (`build/out/corpsus`) so the starting input for my fuzzer. Start then the fuzzer, using the provided `--corpus-dir` parameter.

