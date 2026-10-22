# Find witnesses with seed-first exploration

## Sub-features

- Run a fixed set of concrete synthetic inputs before symbolic exploration.
- Select uncovered allocation-reaching branches for bounded constraint solving.
- Compare with equal-budget seeded random inputs and plain bounded symbolic exploration.
- Validate generated inputs against the harmless native fixture.

## How to get to it (user POV)

Run `python allocation_analyzer/cli.py explore --config <json>` with a trusted ELF, explicit seeds, deterministic random seed, and bounds.

## Driving it with the verification script

Run the `Drive` phase. Compare explored blocks, solver calls, witness validity, and unknown outcomes across all three strategies. Native fixture counters are checked against a separate deterministic oracle; Windows records that native execution was not run.

## Gotchas

This is a bounded adaptation of Driller's seed-first selective concolic idea. It does not implement AFL, coverage-guided mutation, or the paper's Cyber Grand Challenge evaluation.
