# Analyze allocation paths

## Sub-features

- Find syntactic call-graph candidates from declared entry points to allocator symbols.
- Symbolically execute bounded paths and report feasible witnesses separately from candidates.
- Classify declared allocator symbols and return concrete integer inputs for witnessed paths. Multiple inputs are extracted from one combined solver model so cross-argument constraints remain coherent.
- Compare a conditional, loop, known-indirect call, competing-route path, correlated two-argument predicate, infeasible candidate, and bounded-loop unknown against small controlled fixtures.

## How to get to it (user POV)

Run `python allocation_analyzer/cli.py analyze --config <json>` with a trusted ELF, declared symbols, and explicit state and time bounds.

## Driving it with the verification script

Run the `Drive` phase. Inspect the JSON and confirm that each witnessed input reaches the expected allocation counter in the owned native fixture. The driver compares those counters with a separate, deterministic Python oracle for the known fixture conditions.

## Gotchas

Only ELF x86-64 inputs and declared integer inputs are supported. Timeout, unsupported calls, unresolved indirect calls, and symbolic-address ambiguity remain unresolved; they do not prove that a path is absent. Loop exploration is bounded, and a reported step limit is an unknown outcome rather than a negative result.
