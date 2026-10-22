# Allocation Pattern Analyzer

Bounded static analysis for allocation-reaching paths in trusted ELF x86-64 programs. The analyzer uses angr 9.2.207 to build a control-flow/call graph and symbolically execute a declared entry point. It reports allocator call-chain candidates separately from satisfiable path witnesses and unknown cases.

This repository retains the complete BSD-2-Clause angr source tree and Git history at released tag `v9.2.207` (`9037fb8c6ee4a2df61ba64b7a561373f5eb6b253`). The upstream license, copyright notices, and original README are preserved. The allocation analyzer, controlled fixtures, verification driver, and workflow are coursework additions; they do not replace or claim to reproduce the full angr project.

## Run

Use Python 3.11 and install the exact angr release with the dependencies in [`requirements-ci.txt`](requirements-ci.txt). On a clean Linux environment, install Rust toolchain `1.99.1`, then run:

```sh
python -m pip install pip==26.2.2
python -m pip install --constraint requirements-ci.txt --build-constraint requirements-ci.txt angr==9.2.207 unicorn==2.1.4
mkdir -p build
cc -nostdlib -Wl,-e,entry_direct -Wl,--build-id=none -fno-pie -no-pie -O0 fixtures/allocation_paths.c -o build/allocation_paths
python -I allocation_analyzer/cli.py analyze --config fixtures/direct.json
python -I allocation_analyzer/cli.py explore --config fixtures/conditional.json
python -I tests/test_config.py
python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All
```

`analyze` emits JSON with syntactic call-graph candidates, feasible symbolic witnesses, allocator category, concrete declared-input values, constraints, executed block traces, and function chains reconstructed from those traces. Static candidate chains remain separate from the witness trace. `explore` compares seed-first selective symbolic exploration, seeded random concrete simulation, and bounded symbolic exploration. Input symbols and all budgets are validated; the binary must be a trusted ELF no larger than 256 MiB. See [`docs/development.md`](docs/development.md) for setup and result semantics, and [`docs/dependency-provenance.md`](docs/dependency-provenance.md) for release and native-build hashes.

## Research adaptation and measured scope

The seed-first strategy borrows Driller's selective concolic idea: run declared concrete inputs, identify uncovered edges that can reach a declared allocator, and prioritize symbolic execution there. This is a small angr-based adaptation, not a Driller implementation. Its concrete stage symbolically models concrete arguments inside angr; it is not native fuzzing. Native execution is performed separately by the verifier against the owned harmless C fixture.

The course project that motivates allocator-path analysis distinguishes slab allocation from mapping-producing allocation and notes that bounded basic-block exploration can miss paths. This implementation follows that static-analysis framing on small trusted ELF programs; it does not analyze a Linux kernel, identify a vulnerability, establish safety, bypass LASS, exploit Spectre, or measure a side channel. A feasible symbolic witness is a path under the modeled binary and declared interface. `no_witness_observed` means only that the configured bounded run found no witness. Time, state, step, unsupported-call, and unconstrained-successor cases remain explicitly unresolved.

References: [Berkeley CS 262A project report](https://people.eecs.berkeley.edu/~kubitron/courses/cs262a-F25/projects/reports/project1002_paper_ver2_39629115792957488818.pdf) and [Driller: Augmenting Fuzzing Through Selective Symbolic Execution](https://www.ndss-symposium.org/wp-content/uploads/2017/09/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf).

## Verification

The maintained [`verify-allocation-pattern-analyzer` skill](.agents/skills/verify-allocation-pattern-analyzer/SKILL.md) drives Launch, Doctor, Drive, Evidence, and Cleanup on generated fixtures and retains evidence after cleanup. Windows can compile and analyze the Linux ELF but cannot execute it natively. The pinned, read-only [Ubuntu workflow](.github/workflows/allocation-pattern-checks.yml) runs native counter validation and retains run evidence as a workflow artifact. It can be started with `workflow_dispatch`.

The inherited upstream CI workflow files are preserved byte-for-byte in [`archive/upstream-github-workflows/`](archive/upstream-github-workflows/); this project uses its focused workflow rather than the upstream workflows that call external services and reusable workflows.

The [native Ubuntu verification](https://github.com/STEVVVU/allocation-pattern-analyzer/actions/runs/39721132277) passed all ten analyzer cases, exact native counters for seven positive entrypoints, the infeasible zero-counter control, and the post-evidence failure/cleanup control. [Retained summaries](docs/evidence/linux-39721132277/) include raw artifact hashes and representative concrete witnesses. This verifies the controlled ELF fixture; it does not establish Linux-kernel or speculative-execution coverage.
