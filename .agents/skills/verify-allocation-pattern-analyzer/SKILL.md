---
name: verify-allocation-pattern-analyzer
description: Drive the allocation-pattern analyzer CLI against owned ELF fixtures and retain its JSON, native witness, and cleanup evidence.
---

# Verify the allocation pattern analyzer

The primary surface is the Python CLI in `allocation_analyzer/cli.py`. Use only the isolated Python 3.11 environment documented in `docs/development.md`. The vendored angr checkout is source provenance; the CLI imports the pinned installed release.

## Launch

Run `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase Launch`. The script writes run data beneath `.agents/runs/<run-id>/` and reports `ready` only after it compiles the fixture ELF. Launch starts no persistent service.

## Doctor

Run `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase Doctor --run-id <run-id>`. Doctor checks the isolated interpreter, installed angr version, fixture architecture, and available compiler or runner. It makes no changes to host configuration.

## Drive

Run `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase Drive --run-id <run-id>`. The driver invokes the CLI with generated JSON configurations and owned ELF fixtures. It captures analyzer output and runs the native fixture with each reported input on Linux. A witness passes only when its native allocation counters match the separate fixture oracle. It also drives syscall and allocator discovery and bounded symbolic analysis on an owned syscall-shaped ELF, asserting that this incomplete model remains labeled `kernel_state: not_modeled`. On Windows native fixture validation is recorded as not run.

## Evidence

The driver writes the command transcript, analyzer JSON, native outcomes, and a final evidence record under `.agents/runs/<run-id>/`. It drives direct, wrapper, competing-route, correlated two-argument, conditional, loop, known-indirect, infeasible, bounded-loop, and unsupported-indirect cases. On Linux, every reported fixture witness is checked against exact native counters and a separate per-case Python oracle; the infeasible case must produce zero counters. The correlated case verifies that the two extracted inputs jointly satisfy the target predicate. The competing-route case ensures a witness chain follows executed block history instead of reusing a shorter but infeasible callgraph path. The bounded-loop case must report its step limit. The JSON must distinguish feasible witnessed paths, syntactic candidates without a witness, and unresolved or bounded-out paths.

The hosted Ubuntu workflow also builds official Linux 6.6 with `tinyconfig` and KALLSYMS, then scans the resulting `vmlinux`. It requires all discovered x86-64 syscall entries to be scanned and at least one syscall-to-allocation callgraph candidate. It preserves per-entry output, source and config provenance, and image hash. This is static candidate evidence only; no-path results remain unknown and are not proof of feasibility or unreachability. The verifier imposes a 900-second subprocess timeout and an 8192 MiB address-space cap; the standalone CLI does not. `max-entries` is applied after CFGFast, so it caps result records rather than CFG construction. To scan another trusted image, run `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All --run-id <run-id> --kernel-binary /path/to/vmlinux`.

## Cleanup

Run `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase Cleanup --run-id <run-id>`. Cleanup removes only the run's owned scratch binaries and temporary configs. Evidence remains under `.agents/runs/<run-id>/`. The driver must also clean up after an injected failure.

## Helpers

The maintained driver is `.agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py`. Run it with `--phase Launch`, `Doctor`, `Drive`, `Evidence`, `Cleanup`, or `All`. Use `--inject-failure` to verify failure recording and cleanup. The Linux CI workflow runs the same product journey on an Ubuntu runner because local Windows can analyze Linux ELF files but cannot execute them natively.
