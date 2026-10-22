# Development and verification

## Environment

The implementation is based on angr v9.2.207, commit `9037fb8c6ee4a2df61ba64b7a561373f5eb6b253`, Python 3.11, and Rust 1.99.1. Install the pinned Python environment with:

```sh
rustup toolchain install 1.99.1 --profile minimal
python -m pip install pip==26.2.2
python -m pip install --constraint requirements-ci.txt --build-constraint requirements-ci.txt angr==9.2.207 unicorn==2.1.4
```

The angr 9.2.207 source distribution builds its native extension on Python 3.11; PyPI does not publish a matching cp311 wheel for that release. The dependency constraint pins `bitstring==4.3.1` because 5.x removes `ConstBitStream`, which this angr release imports. Rust and a native C toolchain are required to build the exact source release. The generated local Windows wheel is not checked in. The analyzer imports the installed package, not this repository's source checkout.

## Analyzer configuration

The CLI consumes JSON with exactly these keys: `binary`, `entry`, `inputs`, `allocators`, `max_steps`, `max_states`, `timeout_seconds`, `seeds`, `random_seed`, and `random_trials`. The binary path is relative to the config file. Entry and allocator names are plain C symbols. Integer inputs support unsigned 8-, 16-, 32-, or 64-bit values. The analyzer accepts trusted ELF x86-64 binaries; it does not execute untrusted files in a sandbox. Budgets are hard caps for explored basic blocks, states, or seconds per symbolic/concrete strategy stage, subject to work already in progress.

Syntactic callgraph candidates are not proof of a feasible path. `feasible_witness` means the allocator state constraints were satisfiable and concrete declared-argument values were extracted. The candidate's static call chain is kept separate; a witness chain is reconstructed from that state's executed basic-block history and annotated with `call_chain_complete`. The witness also carries the executed block addresses. `no_witness_observed` does not mean unreachable. Unsupported execution, unconstrained successors, timeouts, or exhausted limits appear as unknown reasons. `solver_calls` counts explicit allocator-state feasibility checks only; internal angr solver operations are not instrumented.

`explore` compares three bounded strategies. `seed_first` simulates the supplied input values with angr, then prioritizes symbolic states on uncovered CFG edges that can reach an allocator. `seeded_random` performs the same concrete angr simulation with deterministic generated values. `bounded_symbolic` explores symbolic states without seed priority. These strategies share a maximum basic-block budget, state cap, and per-stage time cap; they are not equal-cost measurements. The concrete stage is not a native fuzzer. The verifier separately runs extracted witnesses against a harmless native fixture counter and independent per-case oracle on Linux. For multiple declared inputs, the CLI evaluates a single concatenation of their symbolic bitvectors and decodes that model, preserving correlations among inputs.

## Linux kernel ELF scan

Run `python -I allocation_analyzer/cli.py kernel-scan --binary /path/to/vmlinux --max-entries 5000` on a trusted, unstripped ELF x86-64 kernel image. The scanner discovers `__x64_sys_*` entries and known allocator symbols from the image symbol table, builds CFGFast once, and reports callgraph candidate chains per entry. The default categories include `kmalloc` and `kmem_cache_alloc` as slab allocation, and `vmalloc`, `vzalloc`, and `vmap` as mapping-producing allocation. A candidate is syntactic only. An entry without a candidate is marked unknown because CFG omissions do not prove unreachability. The ELF must fit the existing 256 MiB input limit. `max-entries` applies after CFGFast and limits output entry records, not CFG construction. The standalone CLI does not impose process-level time or memory limits; the hosted verifier applies a 900-second timeout and 8192 MiB address-space cap around the scan process.

An optional `--analyze-entry __x64_sys_name` invokes the existing bounded symbolic analyzer with one symbolic 64-bit placeholder. Kernel boot state, the `pt_regs` layout, syscall arguments, user memory, and kernel-specific SimProcedures are not modeled. The JSON marks this analysis `kernel_state: not_modeled`; any resulting path is exploratory output under that incomplete model, not a real syscall witness.

The hosted workflow builds the official Linux 6.6 tarball with `tinyconfig` and KALLSYMS, without booting or installing it. The archive SHA-256 is pinned to the value published in the [kernel.org checksum file](https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc). It retains the generated `.config`, source archive provenance, `vmlinux` hash, and scanner JSON with the workflow evidence. The exact local command, once a vmlinux is available, is `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All --run-id <run-id> --kernel-binary /path/to/vmlinux`.

## Verification driver

Run all phases with:

```sh
python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All
```

The driver compiles a minimal ELF fixture; checks Python, installed angr, and architecture; analyzes direct, wrapper, competing-route, correlated two-input, conditional, bounded-loop, known-indirect, infeasible, and unsupported paths; compares exploration strategies; drives symbol discovery, a syscall-to-allocator callgraph path, and optional bounded execution against the owned syscall-shaped fixture; and, on Linux, checks every reported witness against exact native counters and an independent per-case oracle. It also checks a one-step loop run reports `step_limit` and the infeasible case has zero allocation counters. Cleanup removes only run-owned scratch executables. JSON, transcript, actions, native outcomes, and cleanup status remain in `.agents/runs/<run-id>/`. Use `--inject-failure` to verify evidence retention and failure cleanup. On Windows, Linux ELF analysis is available, but native validation is marked not run; the read-only Ubuntu workflow builds and scans the official kernel image and provides the native fixture proof.

The five maintained config tests can also run independently:

```sh
python -I tests/test_config.py
```
