# Analyze allocation paths

## Sub-features

- Find syntactic call-graph candidates from declared entry points to allocator symbols.
- Symbolically execute bounded paths and report feasible witnesses separately from candidates.
- Classify declared allocator symbols and return concrete integer inputs for witnessed paths. Multiple inputs are extracted from one combined solver model so cross-argument constraints remain coherent.
- Compare a conditional, loop, known-indirect call, competing-route path, correlated two-argument predicate, infeasible candidate, and bounded-loop unknown against small controlled fixtures.
- Scan an x86-64 Linux kernel ELF for syscall entrypoints and slab or mapping allocator callgraph candidates; report no-candidate entries as unknown.

## How to get to it (user POV)

Run `python allocation_analyzer/cli.py analyze --config <json>` with a trusted ELF, declared symbols, and explicit state and time bounds.

For the kernel image path, run `python allocation_analyzer/cli.py kernel-scan --binary <vmlinux> --max-entries 5000`. The hosted verifier builds official Linux 6.6 and passes its image with `--kernel-binary`.

## Driving it with the verification script

Run the `Drive` phase. Inspect the JSON and confirm that each witnessed input reaches the expected allocation counter in the owned native fixture. The driver compares those counters with a separate, deterministic Python oracle for the known fixture conditions.

## Gotchas

Only ELF x86-64 inputs and declared integer inputs are supported. Timeout, unsupported calls, unresolved indirect calls, and symbolic-address ambiguity remain unresolved; they do not prove that a path is absent. Loop exploration is bounded, and a reported step limit is an unknown outcome rather than a negative result.

Kernel callgraph entries are syntactic candidates, not feasibility results. The optional symbolic mode uses a placeholder input and does not model `pt_regs`, kernel boot state, user memory, or kernel-specific SimProcedures. Its results are exploratory and cannot be presented as real syscall witnesses.
