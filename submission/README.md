# Software Security: Fuzzing Lab - Final Submission

## General information

Please, run all the scripts from the root of this folder. The scripts are designed to be run in a Linux environment with Docker installed.

## Commands

```bash
./part_1/run.w_corpus.sh
./part_2/run.wo_corpus.sh
./part_3/run.improve1.sh
./part_3/run.improve2.sh
./part_4/run.poc.sh
```

## Directory structure

```text
submission/
├── README.md
├── part_1
│   ├── oss-fuzz.diff
│   ├── project.diff
│   ├── remove_seed_corpus.patch
│   ├── report
│   │   ├── w_corpus
│   │   └── wo_corpus
│   ├── run.w_corpus.sh
│   └── run.wo_corpus.sh
├── part_3
│   ├── coverage_noimprove
│   │   ├── linux
│   │   └── style.css
│   ├── improve1
│   │   ├── coverage_improve1
│   │   ├── oss-fuzz.diff
│   │   ├── project.diff
│   │   └── run.improve1.sh
│   └── improve2
│       ├── coverage_improve2
│       ├── oss-fuzz.diff
│       ├── project.diff
│       └── run.improve2.sh
├── part_4
│   ├── environment
│   │   ├── Dockerfile
│   │   ├── run_tmux_cve_test.sh
│   │   ├── test_fixed.sh
│   │   └── test_vulnerable.sh
│   └── run.poc.sh
└── report.pdf
```
