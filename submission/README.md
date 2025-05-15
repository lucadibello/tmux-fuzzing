# Software Security: Fuzzing Lab - Final Submission

## General information

Please, run all the scripts in the `submission` folder from the root of the repository. The scripts are designed to be run from the root directory, and running them from a different location may cause errors.

## Subdirectory structure

Subdirectory containing the files for the final submission.

```text
submission/
├── README.md
├── part_1
│   ├── oss-fuzz.diff.todo
│   ├── project.diff.todo
│   ├── remove_seed_corpus.patch
│   ├── report
│   │   ├── w_corpus
│   │   └── wo_corpus
│   ├── run_w_corpus.sh
│   └── run_wo_corpus.sh
├── part_3
│   ├── improve1
│   │   ├── coverage_improve1
│   │   ├── oss-fuzz.diff
│   │   ├── project.diff
│   │   └── run_improve1.sh
│   └── improve2
│       ├── coverage_improve2
│       ├── oss-fuzz.diff
│       ├── project.diff
│       └── run_improve2.sh
└── part_4
    ├── environment
    │   ├── Dockerfile
    │   ├── run_tmux_cve_test.sh
    │   ├── test_fixed.sh
    │   └── test_vulnerable.sh
    └── run_poc.sh
```

